#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
#
# Adapted from scripts/gen_acvp_vectors.py of fips204-mldsa-esp32,
# Copyright (c) 2026 The fips204-mldsa-esp32 authors (Apache-2.0).
# Changes: the NIST repository is read at a pinned commit, and expected
# outputs can be emitted in full instead of as SHA-256 digests.
"""
Generate a C header with NIST ACVP ML-DSA (FIPS 204) test vectors.

The vectors come from the official NIST ACVP server repository, read at the
commit pinned in ACVP_COMMIT so that a change upstream cannot alter the tests
silently:
  https://github.com/usnistgov/ACVP-Server  gen-val/json-files
    ML-DSA-keyGen-FIPS204/{prompt,expectedResults}.json
    ML-DSA-sigGen-FIPS204/{prompt,expectedResults}.json
    ML-DSA-sigVer-FIPS204/{prompt,expectedResults}.json

Every sigGen / sigVer case is mapped to one of four modes:
  MODE_PURE      external interface, pure ML-DSA (message + context)
  MODE_PREHASH   external interface, HashML-DSA. The pre-hash PH(M) is
                 computed here with Python's hashlib and stored instead of the
                 message; the test then runs the ML-DSA part (domain
                 separation with the hash OID, then signing or verifying).
  MODE_INTERNAL  internal interface, M' = message (ML-DSA.Sign_internal)
  MODE_EXTMU     internal interface with an external mu (64 bytes)

Byte strings are emitted as hex string literals exactly as they appear in the
JSON files, so every case can be cross-checked by its tcId. Expected outputs
(pk/sk of keyGen, signatures of sigGen) are replaced by their SHA-256 digest,
or kept in full with --full-expected.

By default a subset is emitted, to keep firmware small: per test group, the
cases with the shortest messages, and for sigVer at least one valid and one
invalid signature. --all emits every case.

Usage:
  # the header shipped with the example sketch
  scripts/gen_acvp_vectors.py --out examples/mldsa_test_vectors/acvp_vectors.h
  # every case with full expected values, for the host tests
  scripts/gen_acvp_vectors.py --all --full-expected --out build/acvp_all.h
  # fail if the shipped header is out of date
  scripts/gen_acvp_vectors.py --check --out examples/mldsa_test_vectors/acvp_vectors.h

The JSON files are downloaded once into --acvp-dir (default: .acvp-data).
"""

import argparse
import hashlib
import json
import sys
import urllib.request
from pathlib import Path

ACVP_COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
RAW_BASE = ("https://raw.githubusercontent.com/usnistgov/ACVP-Server/"
            "{ref}/gen-val/json-files/")
NAMES = ["ML-DSA-keyGen-FIPS204", "ML-DSA-sigGen-FIPS204", "ML-DSA-sigVer-FIPS204"]
LEVELS = ("44", "65", "87")

# ACVP hashAlg -> (mldsa-native MLD_PREHASH_* constant, hash function)
PREHASH = {
    "SHA2-224": ("MLD_PREHASH_SHA2_224", lambda m: hashlib.sha224(m).digest()),
    "SHA2-256": ("MLD_PREHASH_SHA2_256", lambda m: hashlib.sha256(m).digest()),
    "SHA2-384": ("MLD_PREHASH_SHA2_384", lambda m: hashlib.sha384(m).digest()),
    "SHA2-512": ("MLD_PREHASH_SHA2_512", lambda m: hashlib.sha512(m).digest()),
    "SHA2-512/224": ("MLD_PREHASH_SHA2_512_224", lambda m: hashlib.new("sha512_224", m).digest()),
    "SHA2-512/256": ("MLD_PREHASH_SHA2_512_256", lambda m: hashlib.new("sha512_256", m).digest()),
    "SHA3-224": ("MLD_PREHASH_SHA3_224", lambda m: hashlib.sha3_224(m).digest()),
    "SHA3-256": ("MLD_PREHASH_SHA3_256", lambda m: hashlib.sha3_256(m).digest()),
    "SHA3-384": ("MLD_PREHASH_SHA3_384", lambda m: hashlib.sha3_384(m).digest()),
    "SHA3-512": ("MLD_PREHASH_SHA3_512", lambda m: hashlib.sha3_512(m).digest()),
    "SHAKE-128": ("MLD_PREHASH_SHAKE_128", lambda m: hashlib.shake_128(m).digest(32)),
    "SHAKE-256": ("MLD_PREHASH_SHAKE_256", lambda m: hashlib.shake_256(m).digest(64)),
}


def download(acvp_dir: Path, ref: str) -> Path:
    """Fetch the JSON files for `ref` unless already cached; return their directory."""
    base = acvp_dir / ref
    for name in NAMES:
        for f in ("prompt.json", "expectedResults.json"):
            dst = base / name / f
            if dst.exists():
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            url = RAW_BASE.format(ref=ref) + f"{name}/{f}"
            print(f"downloading {url}", file=sys.stderr)
            with urllib.request.urlopen(url, timeout=120) as r:
                data = r.read()
            tmp = dst.with_suffix(".part")
            tmp.write_bytes(data)
            tmp.rename(dst)
    return base


def load(base: Path, name: str):
    prompt = json.loads((base / name / "prompt.json").read_text())
    expected = json.loads((base / name / "expectedResults.json").read_text())
    exp = {t["tcId"]: t for g in expected["testGroups"] for t in g["tests"]}
    return prompt, exp


def q(s):
    return "NULL" if s is None else f'"{s}"'


def mode_of(group):
    if group["signatureInterface"] == "external":
        return "MODE_PREHASH" if group["preHash"] == "preHash" else "MODE_PURE"
    return "MODE_EXTMU" if group.get("externalMu") else "MODE_INTERNAL"


def payload(t, mode):
    """(data hex, hashalg constant) for a sigGen/sigVer case."""
    if mode == "MODE_EXTMU":
        return t["mu"], "MLD_PREHASH_NONE"
    if mode == "MODE_PREHASH":
        const, fn = PREHASH[t["hashAlg"]]
        return fn(bytes.fromhex(t["message"])).hex().upper(), const
    return t["message"], "MLD_PREHASH_NONE"


def cost(t):
    return len(t.get("message", t.get("mu", ""))) + len(t.get("context", ""))


def select(tests, n, valid_of=None):
    if n is None:
        return tests
    order = sorted(tests, key=cost)
    if valid_of is None:
        return sorted(order[:n], key=lambda t: t["tcId"])
    good = [t for t in order if valid_of(t)]
    bad = [t for t in order if not valid_of(t)]
    out = []
    while len(out) < n and (good or bad):
        for pool in (good, bad):
            if pool and len(out) < n:
                out.append(pool.pop(0))
    return sorted(out, key=lambda t: t["tcId"])


def render(a, base: Path) -> str:
    kg_p, kg_e = load(base, NAMES[0])
    sg_p, sg_e = load(base, NAMES[1])
    sv_p, sv_e = load(base, NAMES[2])

    def expect(hex_value: str) -> str:
        if a.full_expected:
            return hex_value
        return hashlib.sha256(bytes.fromhex(hex_value)).hexdigest().upper()

    rows = {lvl: {"keygen": [], "siggen": [], "sigver": []} for lvl in LEVELS}
    for g in kg_p["testGroups"]:
        lvl = g["parameterSet"].split("-")[-1]
        tests = g["tests"] if a.keygen is None else g["tests"][:a.keygen]
        for t in tests:
            e = kg_e[t["tcId"]]
            rows[lvl]["keygen"].append(
                [str(t["tcId"]), q(t["seed"]), q(expect(e["pk"])), q(expect(e["sk"]))])
    for g in sg_p["testGroups"]:
        lvl, mode = g["parameterSet"].split("-")[-1], mode_of(g)
        for t in select(g["tests"], a.siggen):
            data, ha = payload(t, mode)
            rnd = None if g["deterministic"] else t["rnd"]
            ctx = t.get("context") if mode in ("MODE_PURE", "MODE_PREHASH") else None
            rows[lvl]["siggen"].append(
                [str(t["tcId"]), mode, ha, q(data), q(ctx), q(rnd), q(t["sk"]),
                 q(expect(sg_e[t["tcId"]]["signature"]))])
    for g in sv_p["testGroups"]:
        lvl, mode = g["parameterSet"].split("-")[-1], mode_of(g)
        for t in select(g["tests"], a.sigver, lambda t: sv_e[t["tcId"]]["testPassed"]):
            data, ha = payload(t, mode)
            ctx = t.get("context") if mode in ("MODE_PURE", "MODE_PREHASH") else None
            valid = "true" if sv_e[t["tcId"]]["testPassed"] else "false"
            rows[lvl]["sigver"].append(
                [str(t["tcId"]), mode, ha, q(data), q(ctx), q(t["pk"]), q(t["signature"]), valid])

    options = (" --all" if a.all else "") + (" --full-expected" if a.full_expected else "")
    expected_note = ("full expected values" if a.full_expected else
                     "SHA-256 digests of the (large) expected values")
    L = ["/*",
         " * NIST ACVP ML-DSA (FIPS 204) test vectors -- AUTO-GENERATED, do not edit.",
         " *",
         " * Generator: scripts/gen_acvp_vectors.py" + options,
         " * Source:    https://github.com/usnistgov/ACVP-Server (gen-val/json-files)",
         f" *            commit {a.ref}",
         f" *            ML-DSA-keyGen-FIPS204 vsId={kg_p.get('vsId')}, "
         f"ML-DSA-sigGen-FIPS204 vsId={sg_p.get('vsId')}, "
         f"ML-DSA-sigVer-FIPS204 vsId={sv_p.get('vsId')}",
         " *",
         " * Hex strings are copied verbatim from the JSON files, except for",
         " * MODE_PREHASH cases, whose data is the pre-hash PH(M) computed by the",
         f" * generator. The *_expect fields hold {expected_note}.",
         " * rnd == NULL marks the deterministic variant (rnd = 0^256).",
         " */",
         "",
         "#ifndef ACVP_VECTORS_H",
         "#define ACVP_VECTORS_H",
         "",
         "#include <stdbool.h>",
         "#include <stdint.h>",
         "",
         "#include <mldsa_native.h> /* MLD_PREHASH_* */",
         "",
         "enum acvp_mode { MODE_PURE, MODE_PREHASH, MODE_INTERNAL, MODE_EXTMU };",
         "",
         "typedef struct { uint16_t tcId; const char *seed, *pk_expect, *sk_expect; } acvp_keygen_t;",
         "typedef struct {",
         "  uint16_t tcId; uint8_t mode; uint8_t hashalg;",
         "  const char *data, *ctx, *rnd, *sk, *sig_expect;",
         "} acvp_siggen_t;",
         "typedef struct {",
         "  uint16_t tcId; uint8_t mode; uint8_t hashalg;",
         "  const char *data, *ctx, *pk, *sig; bool valid;",
         "} acvp_sigver_t;",
         ""]
    for lvl in LEVELS:
        for kind, ctype in (("keygen", "acvp_keygen_t"), ("siggen", "acvp_siggen_t"),
                            ("sigver", "acvp_sigver_t")):
            L.append(f"static const {ctype} acvp_{kind}_{lvl}[] = {{")
            L += ["  {" + ", ".join(r) + "}," for r in rows[lvl][kind]]
            L += ["};", ""]
    L.append("#endif /* ACVP_VECTORS_H */")
    for lvl in LEVELS:
        print(f"ML-DSA-{lvl}: " + ", ".join(f"{k}={len(v)}" for k, v in rows[lvl].items()),
              file=sys.stderr)
    return "\n".join(L) + "\n"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--acvp-dir", type=Path,
                    default=Path(__file__).resolve().parent.parent / ".acvp-data",
                    help="cache directory for the JSON files")
    ap.add_argument("--ref", default=ACVP_COMMIT,
                    help="ACVP-Server commit (default: the pinned one)")
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--check", action="store_true",
                    help="compare with --out instead of writing it")
    ap.add_argument("--keygen", type=int, default=None, help="keyGen cases per level (default: all)")
    ap.add_argument("--siggen", type=int, default=1, help="sigGen cases per test group")
    ap.add_argument("--sigver", type=int, default=2, help="sigVer cases per test group")
    ap.add_argument("--all", action="store_true", help="include every test case")
    ap.add_argument("--full-expected", action="store_true",
                    help="emit expected outputs in full instead of SHA-256 digests")
    a = ap.parse_args()
    if a.all:
        a.keygen = a.siggen = a.sigver = None

    text = render(a, download(a.acvp_dir, a.ref))
    if a.check:
        if not a.out.exists() or a.out.read_text() != text:
            print(f"{a.out} does not match ACVP commit {a.ref}", file=sys.stderr)
            return 1
        print(f"{a.out} matches ACVP commit {a.ref}", file=sys.stderr)
        return 0
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(text)
    print(f"wrote {a.out} ({a.out.stat().st_size} bytes)", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
