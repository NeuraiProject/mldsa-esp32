/*
 * Source compatibility with version 0.2.0: the C functions called with the
 * argument lists that sketches used before the core moved to mldsa-native
 * v2, and the crypto_sign_* aliases. See src/mldsa_compat.h.
 *
 * It includes only mldsa_native.h first, as the 0.2.0 demo sketch did.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <mldsa_native.h>

#include <cstdio>
#include <cstring>
#include <vector>

#include <MLDSA65.h>
#include <MLDSA87.h>

static int failures = 0;

static void check(bool ok, const char *what) {
  std::printf("  [%s] %s\n", ok ? "PASS" : "FAIL", what);
  if (!ok) failures++;
}

static const uint8_t MSG[] = "0.2.0 call signatures";
static const uint8_t CTX[] = "ctx";
static const uint8_t ZERO_RND[32] = {0};

#define LEVEL_TEST(L)                                                          \
  static void level##L() {                                                     \
    std::vector<uint8_t> pk(MLDSA##L##_PUBLICKEYBYTES);                        \
    std::vector<uint8_t> sk(MLDSA##L##_SECRETKEYBYTES);                        \
    std::vector<uint8_t> sig(MLDSA##L##_BYTES);                                \
    std::vector<uint8_t> sm(MLDSA##L##_BYTES + sizeof MSG);                    \
    std::vector<uint8_t> opened(sm.size());                                    \
    uint8_t pre[MLD_DOMAIN_SEPARATION_MAX_BYTES];                              \
    uint8_t mu[MLDSA_CRHBYTES] = {7};                                          \
    size_t siglen = 0, smlen = 0, mlen = 0;                                    \
                                                                               \
    check(PQCP_MLDSA_NATIVE_MLDSA##L##_keypair(pk.data(), sk.data()) == 0,     \
          "ML-DSA-" #L " keypair");                                            \
    check(PQCP_MLDSA_NATIVE_MLDSA##L##_signature(sig.data(), &siglen, MSG,     \
                                                 sizeof MSG, CTX, 3,           \
                                                 sk.data()) == 0 &&            \
              siglen == MLDSA##L##_BYTES &&                                    \
              PQCP_MLDSA_NATIVE_MLDSA##L##_verify(sig.data(), siglen, MSG,     \
                                                  sizeof MSG, CTX, 3,          \
                                                  pk.data()) == 0,             \
          "ML-DSA-" #L " signature / verify with lengths");                    \
    check(PQCP_MLDSA_NATIVE_MLDSA##L##_verify(sig.data(), siglen - 1, MSG,     \
                                              sizeof MSG, CTX, 3,              \
                                              pk.data()) != 0,                 \
          "ML-DSA-" #L " verify rejects a short length");                      \
                                                                               \
    size_t prelen = PQCP_MLDSA_NATIVE_MLDSA##L##_prepare_domain_separation_prefix( \
        pre, NULL, 0, CTX, 3, MLD_PREHASH_NONE);                               \
    siglen = 0;                                                                \
    check(prelen != 0 &&                                                       \
              PQCP_MLDSA_NATIVE_MLDSA##L##_signature_internal(                 \
                  sig.data(), &siglen, MSG, sizeof MSG, pre, prelen, ZERO_RND, \
                  sk.data(), 0) == 0 &&                                        \
              siglen == MLDSA##L##_BYTES &&                                    \
              PQCP_MLDSA_NATIVE_MLDSA##L##_verify_internal(                    \
                  sig.data(), siglen, MSG, sizeof MSG, pre, prelen, pk.data(), \
                  0) == 0,                                                     \
          "ML-DSA-" #L " signature_internal / verify_internal");               \
                                                                               \
    siglen = 0;                                                                \
    check(PQCP_MLDSA_NATIVE_MLDSA##L##_signature_extmu(sig.data(), &siglen,    \
                                                       mu, sk.data()) == 0 &&  \
              siglen == MLDSA##L##_BYTES &&                                    \
              PQCP_MLDSA_NATIVE_MLDSA##L##_verify_extmu(sig.data(), siglen,    \
                                                        mu, pk.data()) == 0,   \
          "ML-DSA-" #L " signature_extmu / verify_extmu");                     \
                                                                               \
    siglen = 0;                                                                \
    check(PQCP_MLDSA_NATIVE_MLDSA##L##_signature_pre_hash_shake256(            \
              sig.data(), &siglen, MSG, sizeof MSG, CTX, 3, ZERO_RND,          \
              sk.data()) == 0 &&                                               \
              siglen == MLDSA##L##_BYTES &&                                    \
              PQCP_MLDSA_NATIVE_MLDSA##L##_verify_pre_hash_shake256(           \
                  sig.data(), siglen, MSG, sizeof MSG, CTX, 3, pk.data()) ==   \
                  0,                                                           \
          "ML-DSA-" #L " pre-hash SHAKE256 sign / verify");                    \
                                                                               \
    check(PQCP_MLDSA_NATIVE_MLDSA##L##_sign(sm.data(), &smlen, MSG,            \
                                            sizeof MSG, CTX, 3,                \
                                            sk.data()) == 0 &&                 \
              smlen == sm.size() &&                                            \
              PQCP_MLDSA_NATIVE_MLDSA##L##_open(opened.data(), &mlen,          \
                                                sm.data(), smlen, CTX, 3,      \
                                                pk.data()) == 0 &&             \
              mlen == sizeof MSG && memcmp(opened.data(), MSG, mlen) == 0,     \
          "ML-DSA-" #L " sign / open");                                        \
    sm[sm.size() - 1] ^= 1;                                                    \
    check(PQCP_MLDSA_NATIVE_MLDSA##L##_open(opened.data(), &mlen, sm.data(),   \
                                            smlen, CTX, 3, pk.data()) != 0 &&  \
              mlen == 0,                                                       \
          "ML-DSA-" #L " open rejects a tampered message");                    \
  }

LEVEL_TEST(44)
LEVEL_TEST(65)
LEVEL_TEST(87)

/* The SUPERCOP-style aliases refer to ML-DSA-44. */
static void aliases() {
  std::vector<uint8_t> pk(CRYPTO_PUBLICKEYBYTES), sk(CRYPTO_SECRETKEYBYTES);
  std::vector<uint8_t> sig(CRYPTO_BYTES), sm(CRYPTO_BYTES + sizeof MSG);
  std::vector<uint8_t> opened(sm.size());
  size_t siglen = 0, smlen = 0, mlen = 0;
  check(CRYPTO_BYTES == MLDSA44_BYTES && crypto_sign_keypair(pk.data(), sk.data()) == 0 &&
            crypto_sign_signature(sig.data(), &siglen, MSG, sizeof MSG, NULL, 0, sk.data()) == 0 &&
            crypto_sign_verify(sig.data(), siglen, MSG, sizeof MSG, NULL, 0, pk.data()) == 0,
        "crypto_sign_keypair / crypto_sign_signature / crypto_sign_verify");
  check(crypto_sign(sm.data(), &smlen, MSG, sizeof MSG, NULL, 0, sk.data()) == 0 &&
            crypto_sign_open(opened.data(), &mlen, sm.data(), smlen, NULL, 0, pk.data()) == 0 &&
            mlen == sizeof MSG,
        "crypto_sign / crypto_sign_open");
}

int main() {
  level44();
  level65();
  level87();
  aliases();
  std::printf("%s\n", failures == 0 ? "ALL PASSED" : "FAILED");
  return failures == 0 ? 0 : 1;
}
