/*
 * Host smoke test: ML-DSA-44, 65 and 87 through the Arduino wrapper classes.
 *
 * For each variant: generate a keypair, sign, verify, and check that a
 * tampered signature, a wrong message and a wrong context are rejected.
 * It is a link and sanity check, not a conformance test.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <cstdio>
#include <cstring>
#include <vector>

#include "MLDSA44.h"
#include "MLDSA65.h"
#include "MLDSA87.h"

static int failures = 0;

static void check(bool ok, const char *variant, const char *what) {
  std::printf("  [%s] %s: %s\n", ok ? "PASS" : "FAIL", variant, what);
  if (!ok) {
    failures++;
  }
}

template <typename Variant> static void roundTrip(const char *name) {
  std::vector<uint8_t> pk(Variant::PUBLIC_KEY_SIZE);
  std::vector<uint8_t> sk(Variant::SECRET_KEY_SIZE);
  std::vector<uint8_t> sig(Variant::SIGNATURE_SIZE);
  const uint8_t msg[] = "mldsa-esp32 host smoke test";
  const uint8_t other[] = "mldsa-esp32 host smoke tesT";
  const uint8_t ctx[] = "ctx-a";
  const uint8_t badCtx[] = "ctx-b";
  size_t siglen = 0;

  check(Variant::generateKeypair(pk.data(), sk.data()) == 0, name, "keygen");
  check(Variant::sign(sig.data(), &siglen, msg, sizeof(msg), sk.data()) == 0 &&
            siglen == Variant::SIGNATURE_SIZE,
        name, "sign");
  check(Variant::verify(sig.data(), siglen, msg, sizeof(msg), pk.data()) == 0,
        name, "verify");
  check(Variant::verify(sig.data(), siglen, other, sizeof(other), pk.data()) != 0,
        name, "wrong message rejected");

  sig[sig.size() / 2] ^= 0x01;
  check(Variant::verify(sig.data(), siglen, msg, sizeof(msg), pk.data()) != 0,
        name, "tampered signature rejected");

  check(Variant::sign(sig.data(), &siglen, msg, sizeof(msg), sk.data(), ctx,
                      sizeof(ctx) - 1) == 0,
        name, "sign with context");
  check(Variant::verify(sig.data(), siglen, msg, sizeof(msg), pk.data(), ctx,
                        sizeof(ctx) - 1) == 0,
        name, "verify with context");
  check(Variant::verify(sig.data(), siglen, msg, sizeof(msg), pk.data(), badCtx,
                        sizeof(badCtx) - 1) != 0,
        name, "wrong context rejected");
}

int main() {
  roundTrip<MLDSA44>("ML-DSA-44");
  roundTrip<MLDSA65>("ML-DSA-65");
  roundTrip<MLDSA87>("ML-DSA-87");
  std::printf("%s\n", failures == 0 ? "ALL PASSED" : "FAILED");
  return failures == 0 ? 0 : 1;
}
