/*
 * MLDSA87.h - Arduino-friendly C++ wrapper for ML-DSA-87
 *
 * ML-DSA-87: NIST security category 5 (~AES-256)
 *   Public key:  2,592 bytes
 *   Secret key:  4,896 bytes
 *   Signature:   4,627 bytes
 *
 * The operations are documented in MLDSA.h:
 *
 *   MLDSA87::generateKeypair(pk, sk)
 *   MLDSA87::generateKeypairFromSeed(pk, sk, seed)
 *   MLDSA87::sign(sig, &siglen, msg, msglen, sk, ctx, ctxlen)
 *   MLDSA87::verify(sig, siglen, msg, msglen, pk, ctx, ctxlen)
 *   MLDSA87::publicKeyFromSecretKey(pk, sk)
 *   MLDSA87::secureZero(ptr, len)
 *
 * and the sizes PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SIGNATURE_SIZE, SEED_SIZE.
 *
 * Copyright (c) Asimov / NeuraiProject
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLDSA87_WRAPPER_H
#define MLDSA87_WRAPPER_H

#include "MLDSA.h"

class MLDSA87 : public mldsa::Variant<87> {};

#endif /* MLDSA87_WRAPPER_H */
