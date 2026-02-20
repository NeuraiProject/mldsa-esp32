/*
 * MLDSA87.h - Arduino-friendly C++ wrapper for ML-DSA-87
 *
 * ML-DSA-87: NIST Security Level 5 (~AES-256 equivalent)
 *   Public Key:  2,592 bytes
 *   Secret Key:  4,896 bytes
 *   Signature:   4,627 bytes
 *
 * NOTE: ML-DSA-87 requires ~63KB working memory for keygen and ~59KB for
 * signing (with REDUCE_RAM). Use a FreeRTOS task with at least 80KB stack.
 * On ESP32 with ~320KB RAM, ensure enough heap is free before use.
 *
 * Copyright (c) Asimov / NeuraiProject
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLDSA87_WRAPPER_H
#define MLDSA87_WRAPPER_H

#include <stdint.h>
#include <stddef.h>

/* ML-DSA-87 size constants (FIPS 204, fixed values) */
#define MLDSA87_PUBLICKEYBYTES 2592
#define MLDSA87_SECRETKEYBYTES 4896
#define MLDSA87_BYTES          4627

/* Forward-declare the level-87 C API (implemented in mldsa87_build.c) */
#ifdef __cplusplus
extern "C" {
#endif

int PQCP_MLDSA_NATIVE_MLDSA87_keypair(
    uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES]);

int PQCP_MLDSA_NATIVE_MLDSA87_keypair_internal(
    uint8_t pk[MLDSA87_PUBLICKEYBYTES],
    uint8_t sk[MLDSA87_SECRETKEYBYTES],
    const uint8_t seed[32]);

int PQCP_MLDSA_NATIVE_MLDSA87_signature(
    uint8_t *sig, size_t *siglen,
    const uint8_t *m, size_t mlen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t sk[MLDSA87_SECRETKEYBYTES]);

int PQCP_MLDSA_NATIVE_MLDSA87_verify(
    const uint8_t *sig, size_t siglen,
    const uint8_t *m, size_t mlen,
    const uint8_t *ctx, size_t ctxlen,
    const uint8_t pk[MLDSA87_PUBLICKEYBYTES]);

#ifdef __cplusplus
}
#endif

class MLDSA87 {
public:
  static constexpr size_t PUBLIC_KEY_SIZE = MLDSA87_PUBLICKEYBYTES;
  static constexpr size_t SECRET_KEY_SIZE = MLDSA87_SECRETKEYBYTES;
  static constexpr size_t SIGNATURE_SIZE  = MLDSA87_BYTES;
  static constexpr size_t SEED_SIZE       = 32;

  /*
   * Generate a new ML-DSA-87 keypair.
   * Returns 0 on success, negative on error.
   */
  static int generateKeypair(uint8_t *pk, uint8_t *sk) {
    return PQCP_MLDSA_NATIVE_MLDSA87_keypair(pk, sk);
  }

  /*
   * Generate a keypair from a deterministic 32-byte seed.
   * Returns 0 on success, negative on error.
   */
  static int generateKeypairFromSeed(uint8_t *pk, uint8_t *sk,
                                     const uint8_t *seed) {
    return PQCP_MLDSA_NATIVE_MLDSA87_keypair_internal(pk, sk, seed);
  }

  /*
   * Sign a message. Optional context string (ctx/ctxlen).
   * Returns 0 on success, negative on error.
   */
  static int sign(uint8_t *sig, size_t *siglen,
                  const uint8_t *msg, size_t msglen,
                  const uint8_t *sk,
                  const uint8_t *ctx = nullptr, size_t ctxlen = 0) {
    return PQCP_MLDSA_NATIVE_MLDSA87_signature(
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
    return PQCP_MLDSA_NATIVE_MLDSA87_verify(
        sig, siglen, msg, msglen, ctx, ctxlen, pk);
  }
};

#endif /* MLDSA87_WRAPPER_H */
