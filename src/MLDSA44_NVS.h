/*
 * MLDSA44_NVS.h - persistent storage of an ML-DSA-44 key in NVS
 *
 * Keys survive reboots and power cycles. The operations are documented in
 * MLDSA_NVS.h:
 *
 *   MLDSA44_NVS::generateAndSave(ns, pk, sk)
 *   MLDSA44_NVS::saveKeypair(ns, pk, sk)
 *   MLDSA44_NVS::saveSeed(ns, seed)
 *   MLDSA44_NVS::loadKeypair(ns, pk, sk)
 *   MLDSA44_NVS::loadPublicKey(ns, pk)
 *   MLDSA44_NVS::hasKeypair(ns)
 *   MLDSA44_NVS::eraseKeypair(ns)
 *   MLDSA44_NVS::migrate(ns)
 *
 * Each takes an optional last argument, mldsa::NvsError *, that receives
 * the reason for a failure.
 *
 * Requires: ESP32 Arduino core with Preferences library (included by default)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLDSA44_NVS_H
#define MLDSA44_NVS_H

#include "MLDSA44.h"
#include "MLDSA_NVS.h"

class MLDSA44_NVS : public mldsa::Nvs<44> {};

#endif /* MLDSA44_NVS_H */
