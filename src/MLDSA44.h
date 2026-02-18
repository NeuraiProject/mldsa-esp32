/*
 * MLDSA44.h - Arduino-friendly C++ wrapper for ML-DSA-44
 *
 * Copyright (c) Asimov / NeuraiProject
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLDSA44_WRAPPER_H
#define MLDSA44_WRAPPER_H

#include <stdint.h>
#include <stddef.h>
#include "mldsa_native.h"

class MLDSA44 {
public:
  static constexpr size_t PUBLIC_KEY_SIZE = MLDSA44_PUBLICKEYBYTES;
  static constexpr size_t SECRET_KEY_SIZE = MLDSA44_SECRETKEYBYTES;
  static constexpr size_t SIGNATURE_SIZE  = MLDSA44_BYTES;
  static constexpr size_t SEED_SIZE       = MLDSA_SEEDBYTES;

  /*
   * Generate a new ML-DSA-44 keypair.
   *
   * pk: output buffer of PUBLIC_KEY_SIZE bytes
   * sk: output buffer of SECRET_KEY_SIZE bytes
   *
   * Returns 0 on success, negative on error.
   */
  static int generateKeypair(uint8_t *pk, uint8_t *sk) {
    return PQCP_MLDSA_NATIVE_MLDSA44_keypair(pk, sk);
  }

  /*
   * Generate a keypair from a deterministic seed.
   *
   * pk:   output buffer of PUBLIC_KEY_SIZE bytes
   * sk:   output buffer of SECRET_KEY_SIZE bytes
   * seed: input buffer of SEED_SIZE bytes
   *
   * Returns 0 on success, negative on error.
   */
  static int generateKeypairFromSeed(uint8_t *pk, uint8_t *sk,
                                     const uint8_t *seed) {
    return PQCP_MLDSA_NATIVE_MLDSA44_keypair_internal(pk, sk, seed);
  }

  /*
   * Sign a message.
   *
   * sig:    output buffer of SIGNATURE_SIZE bytes
   * siglen: output, set to SIGNATURE_SIZE on success
   * msg:    message to sign
   * msglen: length of message
   * sk:     secret key (SECRET_KEY_SIZE bytes)
   * ctx:    optional context string (NULL if ctxlen == 0)
   * ctxlen: length of context string (0 for none, max 255)
   *
   * Returns 0 on success, negative on error.
   */
  static int sign(uint8_t *sig, size_t *siglen,
                  const uint8_t *msg, size_t msglen,
                  const uint8_t *sk,
                  const uint8_t *ctx = nullptr, size_t ctxlen = 0) {
    return PQCP_MLDSA_NATIVE_MLDSA44_signature(
        sig, siglen, msg, msglen, ctx, ctxlen, sk);
  }

  /*
   * Verify a signature.
   *
   * sig:    signature (SIGNATURE_SIZE bytes)
   * siglen: length of signature
   * msg:    signed message
   * msglen: length of message
   * pk:     public key (PUBLIC_KEY_SIZE bytes)
   * ctx:    optional context string (NULL if ctxlen == 0)
   * ctxlen: length of context string (0 for none, max 255)
   *
   * Returns 0 if valid, negative on failure.
   */
  static int verify(const uint8_t *sig, size_t siglen,
                    const uint8_t *msg, size_t msglen,
                    const uint8_t *pk,
                    const uint8_t *ctx = nullptr, size_t ctxlen = 0) {
    return PQCP_MLDSA_NATIVE_MLDSA44_verify(
        sig, siglen, msg, msglen, ctx, ctxlen, pk);
  }
};

#endif /* MLDSA44_WRAPPER_H */
