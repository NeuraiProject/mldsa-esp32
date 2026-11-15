/*
 * MLDSA44.h - Arduino-friendly C++ wrapper for ML-DSA-44
 *
 * ML-DSA-44: NIST security category 2 (~AES-128)
 *   Public key:  1,312 bytes
 *   Secret key:  2,560 bytes
 *   Signature:   2,420 bytes
 *
 * The operations are documented in MLDSA.h:
 *
 *   MLDSA44::generateKeypair(pk, sk)
 *   MLDSA44::generateKeypairFromSeed(pk, sk, seed)
 *   MLDSA44::sign(sig, &siglen, msg, msglen, sk, ctx, ctxlen)
 *   MLDSA44::verify(sig, siglen, msg, msglen, pk, ctx, ctxlen)
 *   MLDSA44::publicKeyFromSecretKey(pk, sk)
 *   MLDSA44::secureZero(ptr, len)
 *
 * and the sizes PUBLIC_KEY_SIZE, SECRET_KEY_SIZE, SIGNATURE_SIZE, SEED_SIZE.
 *
 * Copyright (c) Asimov / NeuraiProject
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLDSA44_WRAPPER_H
#define MLDSA44_WRAPPER_H

#include "MLDSA.h"

class MLDSA44 : public mldsa::Variant<44> {};

#endif /* MLDSA44_WRAPPER_H */
