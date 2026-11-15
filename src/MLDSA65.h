/*
 * MLDSA65.h - Arduino-friendly C++ wrapper for ML-DSA-65
 *
 * ML-DSA-65: NIST security category 3 (~AES-192)
 *   Public key:  1,952 bytes
 *   Secret key:  4,032 bytes
 *   Signature:   3,309 bytes
 *
 * The operations are documented in MLDSA.h:
 *
 *   MLDSA65::generateKeypair(pk, sk)
 *   MLDSA65::generateKeypairFromSeed(pk, sk, seed)
 *   MLDSA65::sign(sig, &siglen, msg, msglen, sk, ctx, ctxlen)
 *   MLDSA65::verify(sig, siglen, msg, msglen, pk, ctx, ctxlen)
 *   MLDSA65::publicKeyFromSecretKey(pk, sk)
 *   MLDSA65::secureZero(ptr, len)
 *
 * and the sizes PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SIGNATURE_SIZE, SEED_SIZE.
 *
 * Copyright (c) Asimov / NeuraiProject
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLDSA65_WRAPPER_H
#define MLDSA65_WRAPPER_H

#include "MLDSA.h"

class MLDSA65 : public mldsa::Variant<65> {};

#endif /* MLDSA65_WRAPPER_H */
