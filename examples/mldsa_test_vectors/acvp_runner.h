/*
 * acvp_runner.h - runs the NIST ACVP ML-DSA vectors of acvp_vectors.h
 *
 * Platform independent: used by the Arduino sketch in this folder and by the
 * host tests in test/host. The C functions it calls are declared by
 * mldsa_native_all.h, which the MLDSA headers include. The includer must define, before including this
 * file:
 *
 *   void acvp_sha256(const uint8_t *in, size_t len, uint8_t out[32]);
 *   void acvp_fail(const char *what, unsigned id);   // report a failure
 *
 * and may include a vector header of its own first (the host tests use one
 * with every ACVP case); otherwise acvp_vectors.h from this folder is used.
 *
 * The includer may also define ACVP_YIELD(), which the runner calls between
 * test cases. A sketch uses it to let other tasks run: a task that computes
 * for seconds without yielding trips the FreeRTOS task watchdog.
 *
 * Adapted from acvp_runner.h of fips204-mldsa-esp32,
 * Copyright (c) 2026 The fips204-mldsa-esp32 authors (Apache-2.0).
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ACVP_RUNNER_H
#define ACVP_RUNNER_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <MLDSA44.h>
#include <MLDSA65.h>
#include <MLDSA87.h>

#include "acvp_vectors.h"

#ifndef ACVP_YIELD
#define ACVP_YIELD() ((void)0)
#endif

namespace acvp {

/* Scratch buffers, sized for the largest parameter set and ACVP message. */
static uint8_t msg[8192];
static uint8_t ctx[256];
static uint8_t pk[MLDSA87::PUBLIC_KEY_SIZE];
static uint8_t sk[MLDSA87::SECRET_KEY_SIZE];
static uint8_t sig[MLDSA87::SIGNATURE_SIZE];
static uint8_t pk2[MLDSA87::PUBLIC_KEY_SIZE];
static uint8_t sk2[MLDSA87::SECRET_KEY_SIZE];
static uint8_t sig2[MLDSA87::SIGNATURE_SIZE];
static uint8_t pre[MLD_DOMAIN_SEPARATION_MAX_BYTES];
static const uint8_t zeroRnd[32] = {0};

struct Result {
  int pass;
  int fail;
  Result() : pass(0), fail(0) {}
  void check(bool ok, const char *what, unsigned id) {
    if (ok) {
      pass++;
    } else {
      fail++;
      acvp_fail(what, id);
    }
  }
};

static const size_t TOO_LONG = (size_t)-1;

/* Decode a hex string (NULL -> empty) into out, which holds cap bytes.
 * Returns the byte count, or TOO_LONG if the string does not fit. */
static size_t unhex(const char *hex, uint8_t *out, size_t cap) {
  size_t n = 0;
  if (hex == NULL) return 0;
  for (; hex[0] && hex[1]; hex += 2) {
    if (n == cap) return TOO_LONG;
    uint8_t hi = hex[0] <= '9' ? hex[0] - '0' : (hex[0] | 0x20) - 'a' + 10;
    uint8_t lo = hex[1] <= '9' ? hex[1] - '0' : (hex[1] | 0x20) - 'a' + 10;
    out[n++] = (uint8_t)((hi << 4) | lo);
  }
  return n;
}

/* Compare data with an expected value given in hex: either the value itself
 * or, when the string is 64 characters long, its SHA-256 digest. */
static bool matches(const uint8_t *data, size_t len, const char *hex) {
  size_t hexLen = strlen(hex);
  if (hexLen == 2 * len) {
    for (size_t i = 0; i < len; i++) {
      uint8_t byte;
      const char pair[3] = {hex[2 * i], hex[2 * i + 1], 0};
      if (unhex(pair, &byte, 1) != 1 || byte != data[i]) return false;
    }
    return true;
  }
  uint8_t digest[32], expect[32];
  if (hexLen != 64 || unhex(hex, expect, 32) != 32) return false;
  acvp_sha256(data, len, digest);
  return memcmp(digest, expect, 32) == 0;
}

/* Per-level access to the wrapper class and to the parts of the C API that
 * the wrapper does not cover. The C functions take a signature of exactly
 * SIG bytes; the tests also feed signatures of other lengths. */
template <unsigned L>
struct Api;

#define ACVP_VERIFY(call, ...) \
  return slen == SIG ? call(s, __VA_ARGS__) : MLD_ERR_INVALID_SIGNATURE

#define ACVP_API(L)                                                            \
  template <>                                                                  \
  struct Api<L> {                                                              \
    typedef MLDSA##L Wrapper;                                                  \
    enum : size_t {                                                            \
      PK = MLDSA##L::PUBLIC_KEY_SIZE,                                          \
      SK = MLDSA##L::SECRET_KEY_SIZE,                                          \
      SIG = MLDSA##L::SIGNATURE_SIZE                                           \
    };                                                                         \
    static int signInternal(uint8_t *s, const uint8_t *m, size_t mlen,         \
                            const uint8_t *p, size_t plen, const uint8_t *r,   \
                            const uint8_t *k, int extmu) {                     \
      return PQCP_MLDSA_NATIVE_MLDSA##L##_signature_internal(                  \
          s, m, mlen, p, plen, r, k, extmu);                                   \
    }                                                                          \
    static int signPrehash(uint8_t *s, const uint8_t *ph, size_t phlen,        \
                           const uint8_t *c, size_t clen, const uint8_t *r,    \
                           const uint8_t *k, int alg) {                        \
      return PQCP_MLDSA_NATIVE_MLDSA##L##_signature_pre_hash_internal(         \
          s, ph, phlen, c, clen, r, k, alg);                                   \
    }                                                                          \
    static int verifyInternal(const uint8_t *s, size_t slen, const uint8_t *m, \
                              size_t mlen, const uint8_t *k) {                 \
      ACVP_VERIFY(PQCP_MLDSA_NATIVE_MLDSA##L##_verify_internal, m, mlen, pre,  \
                  0, k, 0);                                                    \
    }                                                                          \
    static int verifyPrehash(const uint8_t *s, size_t slen, const uint8_t *ph, \
                             size_t phlen, const uint8_t *c, size_t clen,      \
                             const uint8_t *k, int alg) {                      \
      ACVP_VERIFY(PQCP_MLDSA_NATIVE_MLDSA##L##_verify_pre_hash_internal, ph,   \
                  phlen, c, clen, k, alg);                                     \
    }                                                                          \
    static int verifyExtmu(const uint8_t *s, size_t slen, const uint8_t *mu,   \
                           const uint8_t *k) {                                 \
      ACVP_VERIFY(PQCP_MLDSA_NATIVE_MLDSA##L##_verify_extmu, mu, k);           \
    }                                                                          \
    static size_t prefix(uint8_t *p, const uint8_t *c, size_t clen) {          \
      return PQCP_MLDSA_NATIVE_MLDSA##L##_prepare_domain_separation_prefix(    \
          p, NULL, 0, c, clen, MLD_PREHASH_NONE);                              \
    }                                                                          \
    /* Deterministic pure ML-DSA: the hedged signer with rnd = 0^256. */       \
    static int signDeterministic(uint8_t *s, const uint8_t *m, size_t mlen,    \
                                 const uint8_t *k, const uint8_t *c,           \
                                 size_t clen) {                                \
      size_t plen = prefix(pre, c, clen);                                      \
      return plen ? signInternal(s, m, mlen, pre, plen, zeroRnd, k, 0) : -1;   \
    }                                                                          \
  };
ACVP_API(44)
ACVP_API(65)
ACVP_API(87)
#undef ACVP_API
#undef ACVP_VERIFY

/* keyGen: seed -> (pk, sk) */
template <unsigned L>
void keyGen(Result &r, const acvp_keygen_t &t) {
  typedef Api<L> A;
  uint8_t seed[32];
  bool ok = unhex(t.seed, seed, sizeof seed) == sizeof seed &&
            A::Wrapper::generateKeypairFromSeed(pk, sk, seed) == 0 &&
            matches(pk, A::PK, t.pk_expect) && matches(sk, A::SK, t.sk_expect);
  r.check(ok, "keyGen", t.tcId);
  ACVP_YIELD();
}

/* sigGen: (sk, message/ph/mu, ctx, rnd) -> signature */
template <unsigned L>
void sigGen(Result &r, const acvp_siggen_t &t) {
  typedef Api<L> A;
  uint8_t rnd[32] = {0}; /* stays 0^256 for the deterministic variant */
  size_t mlen = unhex(t.data, msg, sizeof msg);
  size_t clen = unhex(t.ctx, ctx, sizeof ctx);
  bool inputsOk = unhex(t.sk, sk, sizeof sk) == A::SK && mlen != TOO_LONG &&
                  clen != TOO_LONG && unhex(t.rnd, rnd, sizeof rnd) != TOO_LONG;
  int ret = -1;
  if (inputsOk) {
    switch (t.mode) {
      case MODE_PURE: {
        size_t plen = A::prefix(pre, ctx, clen);
        ret = plen ? A::signInternal(sig, msg, mlen, pre, plen, rnd, sk, 0) : -1;
        break;
      }
      case MODE_PREHASH:
        ret = A::signPrehash(sig, msg, mlen, ctx, clen, rnd, sk, t.hashalg);
        break;
      case MODE_INTERNAL:
        ret = A::signInternal(sig, msg, mlen, pre, 0, rnd, sk, 0);
        break;
      case MODE_EXTMU:
        ret = A::signInternal(sig, msg, mlen, pre, 0, rnd, sk, 1);
        break;
    }
  }
  r.check(ret == 0 && matches(sig, A::SIG, t.sig_expect), "sigGen", t.tcId);
  ACVP_YIELD();
}

/* sigVer: (pk, message/ph/mu, ctx, signature) -> valid / invalid */
template <unsigned L>
void sigVer(Result &r, const acvp_sigver_t &t) {
  typedef Api<L> A;
  size_t slen = unhex(t.sig, sig, sizeof sig);
  size_t mlen = unhex(t.data, msg, sizeof msg);
  size_t clen = unhex(t.ctx, ctx, sizeof ctx);
  bool inputsOk = unhex(t.pk, pk, sizeof pk) == A::PK && slen != TOO_LONG &&
                  mlen != TOO_LONG && clen != TOO_LONG;
  int ret = -1;
  if (inputsOk) {
    switch (t.mode) {
      case MODE_PURE:
        ret = A::Wrapper::verify(sig, slen, msg, mlen, pk, ctx, clen);
        break;
      case MODE_PREHASH:
        ret = A::verifyPrehash(sig, slen, msg, mlen, ctx, clen, pk, t.hashalg);
        break;
      case MODE_INTERNAL:
        ret = A::verifyInternal(sig, slen, msg, mlen, pk);
        break;
      case MODE_EXTMU:
        ret = A::verifyExtmu(sig, slen, msg, pk);
        break;
    }
  }
  r.check((ret == 0) == t.valid, "sigVer", t.tcId);
  ACVP_YIELD();
}

/* Randomized round trips through the wrapper class, with the platform's
 * random source, plus negative checks. The id reported is the round. */
template <unsigned L>
void roundTrips(Result &r, int rounds) {
  typedef Api<L> A;
  typedef typename A::Wrapper K;
  static const uint8_t text[] = "ML-DSA round trip";
  static const uint8_t c1[] = "context-1";
  for (int i = 0; i < rounds; i++) {
    size_t slen = 0;
    bool ok = K::generateKeypair(pk, sk) == 0 &&
              K::sign(sig, &slen, text, sizeof text, sk, c1, sizeof c1) == 0 &&
              slen == A::SIG &&
              K::verify(sig, slen, text, sizeof text, pk, c1, sizeof c1) == 0;
    r.check(ok, "round trip", i);
    ACVP_YIELD();
    r.check(K::publicKeyFromSecretKey(pk2, sk) == 0 &&
                memcmp(pk, pk2, A::PK) == 0,
            "publicKeyFromSecretKey reproduces pk", i);
    r.check(K::verify(sig, slen, text, sizeof text, pk) != 0,
            "missing context rejected", i);
    memcpy(msg, text, sizeof text);
    msg[i % sizeof text] ^= 1;
    r.check(K::verify(sig, slen, msg, sizeof text, pk, c1, sizeof c1) != 0,
            "tampered message rejected", i);
    memcpy(sig2, sig, A::SIG);
    sig2[(i * 97) % A::SIG] ^= (uint8_t)(1 << (i % 8));
    r.check(K::verify(sig2, slen, text, sizeof text, pk, c1, sizeof c1) != 0,
            "tampered signature rejected", i);
    r.check(K::verify(sig, slen - 1, text, sizeof text, pk, c1, sizeof c1) != 0,
            "short signature rejected", i);
    /* hedged signing is randomized, deterministic signing is not */
    size_t s2 = 0;
    r.check(K::sign(sig2, &s2, text, sizeof text, sk, c1, sizeof c1) == 0 &&
                memcmp(sig, sig2, A::SIG) != 0,
            "hedged signatures differ", i);
    ACVP_YIELD();
    r.check(A::signDeterministic(sig, text, sizeof text, sk, NULL, 0) == 0 &&
                A::signDeterministic(sig2, text, sizeof text, sk, NULL, 0) == 0 &&
                memcmp(sig, sig2, A::SIG) == 0 &&
                K::verify(sig, A::SIG, text, sizeof text, pk) == 0,
            "deterministic signatures repeat", i);
    /* a corrupted secret key must be rejected by pk_from_sk */
    sk[64 + 64 + (i % 32)] ^= 0x10; /* inside s1 (after rho, K, tr) */
    r.check(K::publicKeyFromSecretKey(pk2, sk) == MLD_ERR_INVALID_KEY,
            "corrupted sk rejected", i);
    ACVP_YIELD();
  }
  mldsa::secureZero(sk, sizeof sk);
}

/* Boundary cases of the wrapper API. The id reported is the case number. */
template <unsigned L>
void edgeCases(Result &r) {
  typedef Api<L> A;
  typedef typename A::Wrapper K;
  static const uint8_t text[] = "ML-DSA edge cases";
  static uint8_t longCtx[256];
  size_t slen = 0;
  for (size_t i = 0; i < sizeof longCtx; i++) longCtx[i] = (uint8_t)i;

  r.check(K::generateKeypair(pk, sk) == 0, "edge: keygen", 0);
  r.check(K::generateKeypair(pk2, sk2) == 0, "edge: second keygen", 0);

  /* 1. empty context is the default */
  r.check(K::sign(sig, &slen, text, sizeof text, sk) == 0 && slen == A::SIG &&
              K::verify(sig, slen, text, sizeof text, pk, NULL, 0) == 0,
          "edge: empty context", 1);
  /* 2. a public key from another keypair does not verify it */
  r.check(K::verify(sig, slen, text, sizeof text, pk2) != 0,
          "edge: wrong public key rejected", 2);
  ACVP_YIELD();
  /* 3. signature lengths other than the exact size are rejected */
  r.check(K::verify(sig, 0, text, sizeof text, pk) != 0 &&
              K::verify(sig, A::SIG - 1, text, sizeof text, pk) != 0 &&
              K::verify(sig, A::SIG / 2, text, sizeof text, pk) != 0,
          "edge: truncated signature rejected", 3);
  /* 4. flipping one bit anywhere invalidates the signature */
  {
    bool allRejected = true;
    const size_t at[] = {0, 1, 31, 32, A::SIG / 2, A::SIG - 2, A::SIG - 1};
    for (size_t i = 0; i < sizeof at / sizeof at[0]; i++) {
      memcpy(sig2, sig, A::SIG);
      sig2[at[i]] ^= 0x80;
      if (K::verify(sig2, A::SIG, text, sizeof text, pk) == 0) allRejected = false;
    }
    r.check(allRejected, "edge: altered signature rejected", 4);
  }
  ACVP_YIELD();
  /* 5. empty message */
  r.check(K::sign(sig, &slen, text, 0, sk) == 0 && slen == A::SIG &&
              K::verify(sig, slen, text, 0, pk) == 0 &&
              K::verify(sig, slen, text, 1, pk) != 0,
          "edge: empty message", 5);
  ACVP_YIELD();
  /* 6. longest context allowed by FIPS 204: 255 bytes */
  r.check(K::sign(sig, &slen, text, sizeof text, sk, longCtx, 255) == 0 &&
              slen == A::SIG &&
              K::verify(sig, slen, text, sizeof text, pk, longCtx, 255) == 0,
          "edge: 255-byte context", 6);
  ACVP_YIELD();
  /* 7. a context that differs only in length is a different context */
  r.check(K::verify(sig, slen, text, sizeof text, pk, longCtx, 254) != 0,
          "edge: 254-byte prefix of the context rejected", 7);
  /* 8. 256 bytes is too long, for the verifier */
  r.check(K::verify(sig, slen, text, sizeof text, pk, longCtx, 256) != 0,
          "edge: 256-byte context rejected by verify", 8);
  /* 9. and for the signer, which must not leave a usable signature behind */
  memset(sig2, 0xA5, A::SIG);
  slen = 12345;
  r.check(K::sign(sig2, &slen, text, sizeof text, sk, longCtx, 256) != 0 &&
              K::verify(sig2, A::SIG, text, sizeof text, pk, longCtx, 255) != 0,
          "edge: 256-byte context rejected by sign", 9);
  mldsa::secureZero(sk, sizeof sk);
  mldsa::secureZero(sk2, sizeof sk2);
}

} /* namespace acvp */

#endif /* ACVP_RUNNER_H */
