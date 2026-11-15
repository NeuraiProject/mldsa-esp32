/*
 * The random source: registration, failure, argument checks, and wiping.
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

static void check(bool ok, const char *what) {
  std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
  if (!ok) failures++;
}

static bool allZero(const std::vector<uint8_t> &v) {
  for (size_t i = 0; i < v.size(); i++) {
    if (v[i] != 0) return false;
  }
  return true;
}

struct Source {
  int calls;
  uint8_t fill;
  int failOnCall; /* this call fails (1 = the first); 0 = never */
};

/* Fills with a fixed byte, so its output is easy to recognise. */
static int fixedSource(uint8_t *out, size_t outlen, void *context) {
  Source *s = static_cast<Source *>(context);
  s->calls++;
  memset(out, s->fill, outlen);
  return s->failOnCall != 0 && s->calls == s->failOnCall ? 1 : 0;
}

static const uint8_t MSG[] = "random source test";

template <typename K> static void level(const char *name) {
  std::vector<uint8_t> pk(K::PUBLIC_KEY_SIZE), sk(K::SECRET_KEY_SIZE);
  std::vector<uint8_t> pk2(K::PUBLIC_KEY_SIZE), sk2(K::SECRET_KEY_SIZE);
  std::vector<uint8_t> sig(K::SIGNATURE_SIZE), seed(K::SEED_SIZE, 0x5A);
  size_t siglen = 99;
  char what[96];

  /* A registered source is the only one used: same bytes in, same keys out,
   * and equal to deriving the keys from those bytes as a seed. */
  Source fixed = {0, 0x5A, 0};
  mldsa::setRandomSource(fixedSource, &fixed);
  int a = K::generateKeypair(pk.data(), sk.data());
  int b = K::generateKeypair(pk2.data(), sk2.data());
  std::snprintf(what, sizeof what, "%s: the registered source is used for keygen", name);
  check(a == 0 && b == 0 && fixed.calls == 2 && pk == pk2 && sk == sk2, what);
  K::generateKeypairFromSeed(pk2.data(), sk2.data(), seed.data());
  std::snprintf(what, sizeof what, "%s: keygen draws exactly the seed from the source", name);
  check(pk == pk2 && sk == sk2, what);

  int before = fixed.calls;
  std::snprintf(what, sizeof what, "%s: the registered source is used for signing", name);
  check(K::sign(sig.data(), &siglen, MSG, sizeof MSG, sk.data()) == 0 &&
            fixed.calls == before + 1 &&
            K::verify(sig.data(), siglen, MSG, sizeof MSG, pk.data()) == 0,
        what);

  /* A source that fails: the error is reported and nothing usable is left. */
  Source failing = {0, 0xEE, 1};
  mldsa::setRandomSource(fixedSource, &failing);
  memset(pk2.data(), 0xA5, pk2.size());
  memset(sk2.data(), 0xA5, sk2.size());
  std::snprintf(what, sizeof what, "%s: keygen reports a failing source and wipes pk and sk", name);
  check(K::generateKeypair(pk2.data(), sk2.data()) == MLD_ERR_RNG_FAIL &&
            allZero(pk2) && allZero(sk2),
        what);

  failing.calls = 0;
  memset(sig.data(), 0xA5, sig.size());
  siglen = 99;
  std::snprintf(what, sizeof what, "%s: sign reports a failing source and wipes the signature", name);
  check(K::sign(sig.data(), &siglen, MSG, sizeof MSG, sk.data()) == MLD_ERR_RNG_FAIL &&
            siglen == 0 && allZero(sig),
        what);

  /* Back to the default source. */
  mldsa::setRandomSource(nullptr);
  std::snprintf(what, sizeof what, "%s: the default source works again after nullptr", name);
  check(K::generateKeypair(pk.data(), sk.data()) == 0 &&
            K::generateKeypair(pk2.data(), sk2.data()) == 0 && pk != pk2,
        what);
}

static void adapter() {
  uint8_t buf[16];
  Source fixed = {0, 0x11, 0};
  mldsa_esp32_set_rng(fixedSource, &fixed);

  check(mldsa_esp32_randombytes(buf, 0) == 0 && mldsa_esp32_randombytes(NULL, 0) == 0 &&
            fixed.calls == 0,
        "a request for zero bytes succeeds without calling the source");
  check(mldsa_esp32_randombytes(NULL, 16) != 0 && fixed.calls == 0,
        "a null buffer with a non-zero length is refused");

  /* The library does not judge the source: all zeros is the source's
   * responsibility, not an error the adapter invents. */
  fixed.fill = 0x00;
  check(mldsa_esp32_randombytes(buf, sizeof buf) == 0 && buf[0] == 0x00,
        "bytes are passed through as the source gave them");
  fixed.fill = 0xAA;
  check(mldsa_esp32_randombytes(buf, sizeof buf) == 0 && buf[0] == 0xAA && buf[15] == 0xAA,
        "a run of 0xAA from the source is not mistaken for a failure");

  Source failing = {0, 0x77, 1};
  mldsa_esp32_set_rng(fixedSource, &failing);
  memset(buf, 0xFF, sizeof buf);
  bool wiped = mldsa_esp32_randombytes(buf, sizeof buf) != 0;
  for (size_t i = 0; i < sizeof buf; i++) wiped = wiped && buf[i] == 0;
  check(wiped, "the output of a failed source is wiped");
  mldsa_esp32_set_rng(NULL, NULL);
}

static void wiping() {
  uint8_t secret[64];
  memset(secret, 0xC3, sizeof secret);
  MLDSA44::secureZero(secret, sizeof secret);
  bool zero = true;
  for (size_t i = 0; i < sizeof secret; i++) zero = zero && secret[i] == 0;
  check(zero, "secureZero clears the buffer");
  mldsa::secureZero(NULL, 16);
  mldsa::secureZero(secret, 0);
  check(true, "secureZero accepts a null pointer and a zero length");
}

int main() {
  level<MLDSA44>("ML-DSA-44");
  level<MLDSA65>("ML-DSA-65");
  level<MLDSA87>("ML-DSA-87");
  adapter();
  wiping();
  std::printf("%s\n", failures == 0 ? "ALL PASSED" : "FAILED");
  return failures == 0 ? 0 : 1;
}
