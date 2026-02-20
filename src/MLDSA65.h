/*
 * MLDSA65.h - Arduino-friendly C++ wrapper for ML-DSA-65
 *
 * ML-DSA-65: NIST Security Level 3 (~AES-192 equivalent)
 *   Public Key:  1,952 bytes
 *   Secret Key:  4,032 bytes
 *   Signature:   3,309 bytes
 *
 * NOTE: ML-DSA-65 requires ~46KB working memory for keygen and ~45KB for
 * signing (with REDUCE_RAM). Use a FreeRTOS task with at least 64KB stack.
 *
 * Copyright (c) Asimov / NeuraiProject
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLDSA65_WRAPPER_H
#define MLDSA65_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

/* ML-DSA-65 size constants (FIPS 204, fixed values) */
#define MLDSA65_PUBLICKEYBYTES 1952
#define MLDSA65_SECRETKEYBYTES 4032
#define MLDSA65_BYTES          3309

/* Forward-declare the level-65 C API (implemented in mldsa65_build.c) */
#ifdef __cplusplus
extern "C" {
#endif

int PQCP_MLDSA_NATIVE_MLDSA65_keypair(
    uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES]);

int PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal(
    uint8_t pk[MLDSA65_PUBLICKEYBYTES],
    uint8_t sk[MLDSA65_SECRETKEYBYTES],
    const uint8_t seed[32]);

int PQCP_MLDSA_NATIVE_MLDSA65_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t sk[MLDSA65_SECRETKEYBYTES]);

int PQCP_MLDSA_NATIVE_MLDSA65_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[MLDSA65_PUBLICKEYBYTES]);

#ifdef __cplusplus
}
#endif

class MLDSA65 {
public:
  static constexpr size_t PUBLIC_KEY_SIZE = MLDSA65_PUBLICKEYBYTES;
  static constexpr size_t SECRET_KEY_SIZE = MLDSA65_SECRETKEYBYTES;
  static constexpr size_t SIGNATURE_SIZE  = MLDSA65_BYTES;
  static constexpr size_t SEED_SIZE       = 32;

  /*
   * Generate a new ML-DSA-65 keypair.
   * Returns 0 on success, negative on error.
   */
  static int generateKeypair(uint8_t *pk, uint8_t *sk) {
    return PQCP_MLDSA_NATIVE_MLDSA65_keypair(pk, sk);
  }

  /*
   * Generate a keypair from a deterministic 32-byte seed.
   * Returns 0 on success, negative on error.
   */
  static int generateKeypairFromSeed(uint8_t *pk, uint8_t *sk,
                                     const uint8_t *seed) {
    return PQCP_MLDSA_NATIVE_MLDSA65_keypair_internal(pk, sk, seed);
  }

  /*
   * Sign a message. Optional context string (ctx/ctxlen).
   * Returns 0 on success, negative on error.
   */
  static int sign(uint8_t *sig, size_t *siglen,
                  const uint8_t *msg, size_t msglen,
                  const uint8_t *sk,
                  const uint8_t *ctx = nullptr, size_t ctxlen = 0) {
    return PQCP_MLDSA_NATIVE_MLDSA65_signature(
        sig, siglen, msg, msglen, ctx, ctxlen, sk);
  }

  /*
   * Verify a signature. Optional context string (ctx/ctxlen).
   * Returns 0 if valid, negative on failure.
   */
  static int verify(const uint8_t *sig, size_t siglen,
                    const uint8_t *msg, size_t msglen,
                    const uint8_t *pk,
                    const uint8_t *ctx = nullptr, size_t ctxlen = 0) {
    return PQCP_MLDSA_NATIVE_MLDSA65_verify(
        sig, siglen, msg, msglen, ctx, ctxlen, pk);
  }
};

#endif /* MLDSA65_WRAPPER_H */
