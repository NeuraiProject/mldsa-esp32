/*
 * Tests of the NVS key storage helpers, run against the mock Preferences
 * class in mock/.
 *
 * What the helpers must guarantee:
 *   1. What is loaded is always a whole identity: the public key belongs to
 *      the secret key.
 *   2. A save, migration or erase that fails or is interrupted at any point
 *      leaves the previous identity or the new one loadable.
 *   3. Failures are reported, and secret outputs are wiped.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <cstdio>
#include <cstring>
#include <vector>

#include "MLDSA44_NVS.h"
#include "MLDSA65_NVS.h"
#include "MLDSA87_NVS.h"

using mldsa::NvsError;

static int failures = 0, checks = 0;

static void check(bool ok, const char *what) {
  checks++;
  if (!ok) {
    std::printf("  [FAIL] %s\n", what);
    failures++;
  }
}

static const char *NS = "id";

typedef std::vector<uint8_t> Bytes;

static bool allZero(const Bytes &v) {
  for (size_t i = 0; i < v.size(); i++) {
    if (v[i] != 0) return false;
  }
  return true;
}

template <typename K> struct Identity {
  Bytes pk, sk;
  Identity() : pk(K::PUBLIC_KEY_SIZE), sk(K::SECRET_KEY_SIZE) {
    if (K::generateKeypair(pk.data(), sk.data()) != 0) failures++;
  }
  bool is(const Bytes &p, const Bytes &s) const { return p == pk && s == sk; }
};

/* The 0.2.0 layout, written directly. */
static void putLegacy(const Bytes &pk, const Bytes &sk) {
  mocknvs::state().data[NS]["pk"] = pk;
  mocknvs::state().data[NS]["sk"] = sk;
}

static Bytes &record() { return mocknvs::state().data[NS]["mldsa_key"]; }
static bool hasEntry(const char *key) {
  return mocknvs::state().data[NS].count(key) == 1;
}

/* ---- basics, for every level -------------------------------------------- */

template <typename K, typename Store> static void basics(const char *level) {
  const Identity<K> a;
  Bytes pk(K::PUBLIC_KEY_SIZE), sk(K::SECRET_KEY_SIZE);
  NvsError error = NvsError::OK;
  char what[128];
#define WHAT(text) (std::snprintf(what, sizeof what, "%s: %s", level, text), what)

  mocknvs::state().reset();
  check(!Store::hasKeypair(NS) && !Store::loadKeypair(NS, pk.data(), sk.data(), &error) &&
            error == NvsError::NOT_FOUND && allZero(pk) && allZero(sk),
        WHAT("an empty namespace has no key"));
  check(Store::eraseKeypair(NS), WHAT("erasing where there is nothing succeeds"));

  /* secret-key record */
  check(Store::saveKeypair(NS, a.pk.data(), a.sk.data(), &error) && error == NvsError::OK,
        WHAT("saveKeypair succeeds"));
  check(record().size() == 10 + K::SECRET_KEY_SIZE + 4 && !hasEntry("pk") && !hasEntry("sk"),
        WHAT("saveKeypair writes one secret-key record and no public key"));
  check(Store::hasKeypair(NS) && Store::loadKeypair(NS, pk.data(), sk.data()) && a.is(pk, sk),
        WHAT("loadKeypair returns what saveKeypair stored"));
  std::fill(pk.begin(), pk.end(), 0xEE);
  check(Store::loadPublicKey(NS, pk.data()) && pk == a.pk, WHAT("loadPublicKey returns the public key"));

  /* a pair that does not belong together is refused */
  const Identity<K> b;
  check(!Store::saveKeypair(NS, b.pk.data(), a.sk.data(), &error) && error == NvsError::INVALID_KEY &&
            Store::loadKeypair(NS, pk.data(), sk.data()) && a.is(pk, sk),
        WHAT("saveKeypair refuses a public key of another secret key"));

  /* seed record */
  mocknvs::state().reset();
  Bytes gpk(K::PUBLIC_KEY_SIZE), gsk(K::SECRET_KEY_SIZE);
  check(Store::generateAndSave(NS, gpk.data(), gsk.data(), &error) == 0 && error == NvsError::OK,
        WHAT("generateAndSave succeeds"));
  check(record().size() == 46, WHAT("generateAndSave writes a 46-byte seed record"));
  check(Store::loadKeypair(NS, pk.data(), sk.data()) && pk == gpk && sk == gsk,
        WHAT("loadKeypair regenerates the keypair of generateAndSave"));
  size_t siglen = 0;
  Bytes sig(K::SIGNATURE_SIZE);
  check(K::sign(sig.data(), &siglen, pk.data(), 32, sk.data()) == 0 &&
            K::verify(sig.data(), siglen, pk.data(), 32, gpk.data()) == 0,
        WHAT("the loaded key signs and the generated public key verifies"));

  Bytes seed(K::SEED_SIZE, 0x31);
  K::generateKeypairFromSeed(gpk.data(), gsk.data(), seed.data());
  check(Store::saveSeed(NS, seed.data()) && Store::loadKeypair(NS, pk.data(), sk.data()) &&
            pk == gpk && sk == gsk,
        WHAT("saveSeed stores a key made from a seed"));

  /* damaged records */
  Bytes good = record();
  record()[12] ^= 0x01;
  check(!Store::loadKeypair(NS, pk.data(), sk.data(), &error) && error == NvsError::INVALID_RECORD &&
            allZero(pk) && allZero(sk),
        WHAT("a record with a flipped bit is rejected and the outputs wiped"));
  record() = good;
  record().resize(good.size() - 1);
  check(!Store::loadKeypair(NS, pk.data(), sk.data(), &error) && error == NvsError::INVALID_RECORD,
        WHAT("a truncated record is rejected"));
  record() = good;
  record()[4] = 2; /* unknown format version; CRC no longer matches either */
  check(!Store::loadKeypair(NS, pk.data(), sk.data(), &error) && error == NvsError::INVALID_RECORD,
        WHAT("a record of an unknown format version is rejected"));
  record() = Bytes(3, 0x55);
  check(!Store::loadKeypair(NS, pk.data(), sk.data(), &error) && error == NvsError::INVALID_RECORD,
        WHAT("garbage under the record key is rejected"));

  /* erase */
  record() = good;
  check(Store::eraseKeypair(NS) && !Store::hasKeypair(NS) && !hasEntry("mldsa_key"),
        WHAT("eraseKeypair removes the record"));
  record() = good;
  mocknvs::state().failRemove = true;
  check(!Store::eraseKeypair(NS, &error) && error == NvsError::ERASE_FAILED && Store::hasKeypair(NS),
        WHAT("an erase that cannot remove the entry reports failure"));
  mocknvs::state().clearFaults();

  /* the namespace cannot be opened */
  mocknvs::state().failBegin = true;
  std::fill(sk.begin(), sk.end(), 0xEE);
  check(!Store::loadKeypair(NS, pk.data(), sk.data()) && allZero(pk) && allZero(sk),
        WHAT("load fails and wipes the outputs when the namespace cannot be opened"));
  check(!Store::saveKeypair(NS, a.pk.data(), a.sk.data(), &error) && error == NvsError::CANNOT_OPEN,
        WHAT("save reports that the namespace cannot be opened"));
  mocknvs::state().clearFaults();

  /* a failing random source */
  mocknvs::state().reset();
  struct Fail { static int source(uint8_t *, size_t, void *) { return 1; } };
  mldsa::setRandomSource(Fail::source);
  std::fill(gsk.begin(), gsk.end(), 0xEE);
  check(Store::generateAndSave(NS, gpk.data(), gsk.data()) == MLD_ERR_RNG_FAIL && allZero(gsk) &&
            !Store::hasKeypair(NS),
        WHAT("generateAndSave with a failing random source stores nothing"));
  mldsa::setRandomSource(nullptr);
#undef WHAT
}

/* ---- a record written for another level --------------------------------- */

static void otherLevel() {
  const Identity<MLDSA44> a;
  Bytes pk(MLDSA65::PUBLIC_KEY_SIZE), sk(MLDSA65::SECRET_KEY_SIZE);
  NvsError error = NvsError::OK;
  mocknvs::state().reset();
  MLDSA44_NVS::saveKeypair(NS, a.pk.data(), a.sk.data());
  check(!MLDSA65_NVS::loadKeypair(NS, pk.data(), sk.data(), &error) &&
            error == NvsError::WRONG_PARAMETER_SET && allZero(sk),
        "a secret-key record of ML-DSA-44 is not loaded as ML-DSA-65");
  mocknvs::state().reset();
  Bytes gpk(MLDSA44::PUBLIC_KEY_SIZE), gsk(MLDSA44::SECRET_KEY_SIZE);
  MLDSA44_NVS::generateAndSave(NS, gpk.data(), gsk.data());
  Bytes pk87(MLDSA87::PUBLIC_KEY_SIZE), sk87(MLDSA87::SECRET_KEY_SIZE);
  check(!MLDSA87_NVS::loadKeypair(NS, pk87.data(), sk87.data(), &error) &&
            error == NvsError::WRONG_PARAMETER_SET,
        "a seed record of ML-DSA-44 is not loaded as ML-DSA-87");
}

/* ---- interrupted and failed replacements -------------------------------- */

/* Run `replace` on a namespace holding identity a, cut off after each of
 * its storage operations in turn. Afterwards the namespace must load as a
 * or as the identity `replace` was storing. */
template <typename Replace>
static void interruptedReplacement(const char *what, const Identity<MLDSA44> &a,
                                   bool legacyStart, Replace replace) {
  for (int cutAfter = 0; cutAfter < 8; cutAfter++) {
    mocknvs::state().reset();
    if (legacyStart) {
      putLegacy(a.pk, a.sk);
    } else {
      MLDSA44_NVS::saveKeypair(NS, a.pk.data(), a.sk.data());
    }
    mocknvs::state().clearFaults();
    mocknvs::state().dieAfterOperations = cutAfter;
    Bytes newPk(MLDSA44::PUBLIC_KEY_SIZE), newSk(MLDSA44::SECRET_KEY_SIZE);
    replace(newPk, newSk);
    int carriedOut = mocknvs::state().operations;
    mocknvs::state().clearFaults(); /* power is back */

    Bytes pk(MLDSA44::PUBLIC_KEY_SIZE), sk(MLDSA44::SECRET_KEY_SIZE);
    bool loaded = MLDSA44_NVS::loadKeypair(NS, pk.data(), sk.data());
    char text[160];
    std::snprintf(text, sizeof text, "%s, cut off after %d storage operations: a whole identity loads",
                  what, cutAfter);
    check(loaded && (a.is(pk, sk) || (pk == newPk && sk == newSk)), text);
    if (carriedOut < cutAfter) break; /* the operation completed */
  }
}

static void replacements() {
  const Identity<MLDSA44> a, b;
  Bytes pk(MLDSA44::PUBLIC_KEY_SIZE), sk(MLDSA44::SECRET_KEY_SIZE);
  NvsError error = NvsError::OK;

  interruptedReplacement("saveKeypair over a record", a, false, [&](Bytes &newPk, Bytes &newSk) {
    newPk = b.pk;
    newSk = b.sk;
    MLDSA44_NVS::saveKeypair(NS, b.pk.data(), b.sk.data());
  });
  interruptedReplacement("generateAndSave over a record", a, false, [&](Bytes &newPk, Bytes &newSk) {
    MLDSA44_NVS::generateAndSave(NS, newPk.data(), newSk.data());
  });
  interruptedReplacement("saveKeypair over a 0.2.0 key", a, true, [&](Bytes &newPk, Bytes &newSk) {
    newPk = b.pk;
    newSk = b.sk;
    MLDSA44_NVS::saveKeypair(NS, b.pk.data(), b.sk.data());
  });
  interruptedReplacement("migrate", a, true, [&](Bytes &newPk, Bytes &newSk) {
    newPk = a.pk;
    newSk = a.sk;
    MLDSA44_NVS::migrate(NS);
  });

  /* The write itself fails. */
  mocknvs::state().reset();
  MLDSA44_NVS::saveKeypair(NS, a.pk.data(), a.sk.data());
  mocknvs::state().clearFaults();
  mocknvs::state().failPutOnCall = 1;
  check(!MLDSA44_NVS::saveKeypair(NS, b.pk.data(), b.sk.data(), &error) && error == NvsError::WRITE_FAILED,
        "a refused write is reported");
  mocknvs::state().clearFaults();
  check(MLDSA44_NVS::loadKeypair(NS, pk.data(), sk.data()) && a.is(pk, sk),
        "after a refused write the previous identity loads");

  mocknvs::state().failPutOnCall = 1;
  Bytes gpk(MLDSA44::PUBLIC_KEY_SIZE), gsk(MLDSA44::SECRET_KEY_SIZE);
  check(MLDSA44_NVS::generateAndSave(NS, gpk.data(), gsk.data(), &error) == 1 && error == NvsError::WRITE_FAILED,
        "generateAndSave returns 1 when the key cannot be stored");
  mocknvs::state().clearFaults();

  /* Not enough room for the new record next to the old one: nothing is
   * attempted, so nothing can be damaged. */
  mocknvs::state().reset();
  MLDSA44_NVS::saveKeypair(NS, a.pk.data(), a.sk.data());
  mocknvs::state().otherEntries = 630 - 126 - mocknvs::state().usedEntries() - 50;
  mocknvs::state().clearFaults();
  check(!MLDSA44_NVS::saveKeypair(NS, b.pk.data(), b.sk.data(), &error) && error == NvsError::NO_SPACE &&
            mocknvs::state().putCalls == 0,
        "a record that does not fit is refused without attempting the write");
  check(MLDSA44_NVS::loadKeypair(NS, pk.data(), sk.data()) && a.is(pk, sk),
        "after a refusal for lack of space the previous identity loads");
  /* A seed record needs 4 entries, so it still fits. */
  check(MLDSA44_NVS::generateAndSave(NS, gpk.data(), gsk.data(), &error) == 0 &&
            mocknvs::state().refusedForSpace == 0,
        "a seed record fits where a secret-key record does not");
}

/* ---- keys stored by version 0.2.0 --------------------------------------- */

static void legacy() {
  const Identity<MLDSA44> a, b;
  Bytes pk(MLDSA44::PUBLIC_KEY_SIZE), sk(MLDSA44::SECRET_KEY_SIZE);
  NvsError error = NvsError::OK;

  mocknvs::state().reset();
  putLegacy(a.pk, a.sk);
  check(MLDSA44_NVS::hasKeypair(NS) && MLDSA44_NVS::loadKeypair(NS, pk.data(), sk.data()) && a.is(pk, sk),
        "a key stored by 0.2.0 is found and loaded");
  check(hasEntry("pk") && hasEntry("sk") && !hasEntry("mldsa_key"), "loading does not write");

  /* The defect of 0.2.0: an interrupted replacement left the public key of
   * one identity with the secret key of another, and it loaded as valid. */
  putLegacy(b.pk, a.sk);
  check(!MLDSA44_NVS::loadKeypair(NS, pk.data(), sk.data(), &error) && error == NvsError::INVALID_KEY &&
            allZero(pk) && allZero(sk),
        "a mixed 0.2.0 pair is rejected and the outputs wiped");
  check(!MLDSA44_NVS::migrate(NS, &error) && error == NvsError::INVALID_KEY && !hasEntry("mldsa_key"),
        "a mixed 0.2.0 pair is not migrated");

  putLegacy(a.pk, a.sk);
  check(MLDSA44_NVS::migrate(NS) && hasEntry("mldsa_key") && !hasEntry("pk") && !hasEntry("sk"),
        "migrate writes the record and removes the 0.2.0 entries");
  check(MLDSA44_NVS::loadKeypair(NS, pk.data(), sk.data()) && a.is(pk, sk),
        "the migrated key loads");
  check(MLDSA44_NVS::migrate(NS), "migrate on an already migrated namespace succeeds");

  /* Both layouts present, as after an interrupted migration: the record
   * wins; if the record is damaged, the old entries are used. */
  putLegacy(a.pk, a.sk);
  check(MLDSA44_NVS::loadKeypair(NS, pk.data(), sk.data()) && a.is(pk, sk),
        "with both layouts present the record is loaded");
  record()[20] ^= 0x40;
  check(MLDSA44_NVS::loadKeypair(NS, pk.data(), sk.data()) && a.is(pk, sk),
        "with a damaged record the 0.2.0 entries are loaded");

  check(MLDSA44_NVS::eraseKeypair(NS) && !hasEntry("mldsa_key") && !hasEntry("pk") && !hasEntry("sk") &&
            !MLDSA44_NVS::hasKeypair(NS),
        "eraseKeypair removes the record and the 0.2.0 entries");

  mocknvs::state().reset();
  check(!MLDSA44_NVS::migrate(NS, &error) && error == NvsError::NOT_FOUND,
        "migrate with nothing stored reports that there is no key");
}

int main() {
  basics<MLDSA44, MLDSA44_NVS>("ML-DSA-44");
  basics<MLDSA65, MLDSA65_NVS>("ML-DSA-65");
  basics<MLDSA87, MLDSA87_NVS>("ML-DSA-87");
  otherLevel();
  replacements();
  legacy();
  std::printf("NVS helpers: %d checks, %d failed\n", checks, failures);
  return failures == 0 ? 0 : 1;
}
