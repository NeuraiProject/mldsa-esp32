/*
 * mldsa_compat.h - source compatibility with version 0.2.0 of this library
 *
 * mldsa-native v2 fixed the size of a signature, so its C functions lost
 * their signature-length arguments. It also dropped the "signed message"
 * functions (sign and open) and the crypto_sign_* aliases. Sketches written
 * for 0.2.0 use the older forms; this header keeps them compiling:
 *
 *   - C++ overloads of the level-specific functions, with the argument lists
 *     of 0.2.0. A sketch is C++, so a call that passes a signature length
 *     resolves to the overload, and one that does not resolves to
 *     mldsa-native.
 *   - The crypto_sign_* aliases, which refer to ML-DSA-44 as they did.
 *
 * C code gets the mldsa-native v2 functions only.
 *
 * This header is included by mldsa_native_config.h, so it is in effect
 * wherever mldsa_native.h is. New code should use the MLDSA44, MLDSA65 and
 * MLDSA87 classes instead of the C API.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLDSA_COMPAT_H
#define MLDSA_COMPAT_H

#if !defined(MLDSA44_BYTES)
#error "Include mldsa_native.h; mldsa_native_config.h is not meant to be included on its own."
#endif

/* SUPERCOP-style names, for ML-DSA-44. */
#define CRYPTO_SECRETKEYBYTES MLDSA44_SECRETKEYBYTES
#define CRYPTO_PUBLICKEYBYTES MLDSA44_PUBLICKEYBYTES
#define CRYPTO_BYTES MLDSA44_BYTES
#define crypto_sign_keypair PQCP_MLDSA_NATIVE_MLDSA44_keypair
#define crypto_sign_signature PQCP_MLDSA_NATIVE_MLDSA44_signature
#define crypto_sign_verify PQCP_MLDSA_NATIVE_MLDSA44_verify

#if defined(__cplusplus)

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define crypto_sign PQCP_MLDSA_NATIVE_MLDSA44_sign
#define crypto_sign_open PQCP_MLDSA_NATIVE_MLDSA44_open

/*
 * The mldsa-native v2 functions the overloads forward to. These repeat
 * declarations of mldsa_native.h; if upstream changes one, the compiler
 * reports the conflict.
 */
#define MLDSA_COMPAT_V2(L)                                                     \
  int PQCP_MLDSA_NATIVE_MLDSA##L##_signature_internal(                         \
      uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *pre,         \
      size_t prelen, const uint8_t *rnd, const uint8_t *sk, int externalmu);   \
  int PQCP_MLDSA_NATIVE_MLDSA##L##_signature(                                  \
      uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,         \
      size_t ctxlen, const uint8_t *sk);                                       \
  int PQCP_MLDSA_NATIVE_MLDSA##L##_signature_extmu(                            \
      uint8_t *sig, const uint8_t *mu, const uint8_t *sk);                     \
  int PQCP_MLDSA_NATIVE_MLDSA##L##_verify_internal(                            \
      const uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *pre,   \
      size_t prelen, const uint8_t *pk, int externalmu);                       \
  int PQCP_MLDSA_NATIVE_MLDSA##L##_verify(                                     \
      const uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,   \
      size_t ctxlen, const uint8_t *pk);                                       \
  int PQCP_MLDSA_NATIVE_MLDSA##L##_verify_extmu(                               \
      const uint8_t *sig, const uint8_t *mu, const uint8_t *pk);               \
  int PQCP_MLDSA_NATIVE_MLDSA##L##_signature_pre_hash_internal(                \
      uint8_t *sig, const uint8_t *ph, size_t phlen, const uint8_t *ctx,       \
      size_t ctxlen, const uint8_t *rnd, const uint8_t *sk, int hashalg);      \
  int PQCP_MLDSA_NATIVE_MLDSA##L##_verify_pre_hash_internal(                   \
      const uint8_t *sig, const uint8_t *ph, size_t phlen, const uint8_t *ctx, \
      size_t ctxlen, const uint8_t *pk, int hashalg);                          \
  int PQCP_MLDSA_NATIVE_MLDSA##L##_signature_pre_hash_shake256(                \
      uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,         \
      size_t ctxlen, const uint8_t *rnd, const uint8_t *sk);                   \
  int PQCP_MLDSA_NATIVE_MLDSA##L##_verify_pre_hash_shake256(                   \
      const uint8_t *sig, const uint8_t *m, size_t mlen, const uint8_t *ctx,   \
      size_t ctxlen, const uint8_t *pk);

extern "C" {
MLDSA_COMPAT_V2(44)
MLDSA_COMPAT_V2(65)
MLDSA_COMPAT_V2(87)
}
#undef MLDSA_COMPAT_V2

/* A signing overload: call v2, then report the length as 0.2.0 did. */
#define MLDSA_COMPAT_SIGN(L, name, params, args)                    \
  static inline int PQCP_MLDSA_NATIVE_MLDSA##L##_##name params {    \
    int ret = PQCP_MLDSA_NATIVE_MLDSA##L##_##name args;             \
    if (siglen != NULL) *siglen = ret == 0 ? MLDSA##L##_BYTES : 0;  \
    return ret;                                                     \
  }

/* A verifying overload: v2 takes exactly MLDSA<L>_BYTES bytes. */
#define MLDSA_COMPAT_VERIFY(L, name, params, args)                  \
  static inline int PQCP_MLDSA_NATIVE_MLDSA##L##_##name params {    \
    if (siglen != MLDSA##L##_BYTES) return MLD_ERR_INVALID_SIGNATURE; \
    return PQCP_MLDSA_NATIVE_MLDSA##L##_##name args;                \
  }

#define MLDSA_COMPAT(L)                                                        \
  MLDSA_COMPAT_SIGN(L, signature_internal,                                     \
                    (uint8_t *sig, size_t *siglen, const uint8_t *m,           \
                     size_t mlen, const uint8_t *pre, size_t prelen,           \
                     const uint8_t *rnd, const uint8_t *sk, int externalmu),   \
                    (sig, m, mlen, pre, prelen, rnd, sk, externalmu))          \
  MLDSA_COMPAT_SIGN(L, signature,                                              \
                    (uint8_t *sig, size_t *siglen, const uint8_t *m,           \
                     size_t mlen, const uint8_t *ctx, size_t ctxlen,           \
                     const uint8_t *sk),                                       \
                    (sig, m, mlen, ctx, ctxlen, sk))                           \
  MLDSA_COMPAT_SIGN(L, signature_extmu,                                        \
                    (uint8_t *sig, size_t *siglen, const uint8_t *mu,          \
                     const uint8_t *sk),                                       \
                    (sig, mu, sk))                                             \
  MLDSA_COMPAT_SIGN(L, signature_pre_hash_internal,                            \
                    (uint8_t *sig, size_t *siglen, const uint8_t *ph,          \
                     size_t phlen, const uint8_t *ctx, size_t ctxlen,          \
                     const uint8_t *rnd, const uint8_t *sk, int hashalg),      \
                    (sig, ph, phlen, ctx, ctxlen, rnd, sk, hashalg))           \
  MLDSA_COMPAT_SIGN(L, signature_pre_hash_shake256,                            \
                    (uint8_t *sig, size_t *siglen, const uint8_t *m,           \
                     size_t mlen, const uint8_t *ctx, size_t ctxlen,           \
                     const uint8_t *rnd, const uint8_t *sk),                   \
                    (sig, m, mlen, ctx, ctxlen, rnd, sk))                      \
  MLDSA_COMPAT_VERIFY(L, verify_internal,                                      \
                      (const uint8_t *sig, size_t siglen, const uint8_t *m,    \
                       size_t mlen, const uint8_t *pre, size_t prelen,         \
                       const uint8_t *pk, int externalmu),                     \
                      (sig, m, mlen, pre, prelen, pk, externalmu))             \
  MLDSA_COMPAT_VERIFY(L, verify,                                               \
                      (const uint8_t *sig, size_t siglen, const uint8_t *m,    \
                       size_t mlen, const uint8_t *ctx, size_t ctxlen,         \
                       const uint8_t *pk),                                     \
                      (sig, m, mlen, ctx, ctxlen, pk))                         \
  MLDSA_COMPAT_VERIFY(L, verify_extmu,                                         \
                      (const uint8_t *sig, size_t siglen, const uint8_t *mu,   \
                       const uint8_t *pk),                                     \
                      (sig, mu, pk))                                           \
  MLDSA_COMPAT_VERIFY(L, verify_pre_hash_internal,                             \
                      (const uint8_t *sig, size_t siglen, const uint8_t *ph,   \
                       size_t phlen, const uint8_t *ctx, size_t ctxlen,        \
                       const uint8_t *pk, int hashalg),                        \
                      (sig, ph, phlen, ctx, ctxlen, pk, hashalg))              \
  MLDSA_COMPAT_VERIFY(L, verify_pre_hash_shake256,                             \
                      (const uint8_t *sig, size_t siglen, const uint8_t *m,    \
                       size_t mlen, const uint8_t *ctx, size_t ctxlen,         \
                       const uint8_t *pk),                                     \
                      (sig, m, mlen, ctx, ctxlen, pk))                         \
                                                                               \
  /* Signed message sm = signature || message. sm may overlap m. */            \
  static inline int PQCP_MLDSA_NATIVE_MLDSA##L##_sign(                         \
      uint8_t *sm, size_t *smlen, const uint8_t *m, size_t mlen,               \
      const uint8_t *ctx, size_t ctxlen, const uint8_t *sk) {                  \
    memmove(sm + MLDSA##L##_BYTES, m, mlen);                                   \
    int ret = PQCP_MLDSA_NATIVE_MLDSA##L##_signature(                          \
        sm, sm + MLDSA##L##_BYTES, mlen, ctx, ctxlen, sk);                     \
    *smlen = ret == 0 ? MLDSA##L##_BYTES + mlen : 0;                           \
    return ret;                                                                \
  }                                                                            \
                                                                               \
  /* Verify a signed message and recover the message. m may overlap sm. */     \
  static inline int PQCP_MLDSA_NATIVE_MLDSA##L##_open(                         \
      uint8_t *m, size_t *mlen, const uint8_t *sm, size_t smlen,               \
      const uint8_t *ctx, size_t ctxlen, const uint8_t *pk) {                  \
    int ret = MLD_ERR_INVALID_SIGNATURE;                                       \
    if (smlen >= MLDSA##L##_BYTES) {                                           \
      ret = PQCP_MLDSA_NATIVE_MLDSA##L##_verify(                               \
          sm, sm + MLDSA##L##_BYTES, smlen - MLDSA##L##_BYTES, ctx, ctxlen,    \
          pk);                                                                 \
    }                                                                          \
    if (ret == 0) {                                                            \
      *mlen = smlen - MLDSA##L##_BYTES;                                        \
      memmove(m, sm + MLDSA##L##_BYTES, *mlen);                                \
    } else {                                                                   \
      *mlen = 0;                                                               \
      memset(m, 0, smlen);                                                     \
    }                                                                          \
    return ret;                                                                \
  }

MLDSA_COMPAT(44)
MLDSA_COMPAT(65)
MLDSA_COMPAT(87)

#undef MLDSA_COMPAT
#undef MLDSA_COMPAT_SIGN
#undef MLDSA_COMPAT_VERIFY

#endif /* __cplusplus */

#endif /* MLDSA_COMPAT_H */
