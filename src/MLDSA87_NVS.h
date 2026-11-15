/*
 * MLDSA87_NVS.h - persistent storage of an ML-DSA-87 key in NVS
 *
 * Keys survive reboots and power cycles. The operations are documented in
 * MLDSA_NVS.h:
 *
 *   MLDSA87_NVS::generateAndSave(ns, pk, sk)
 *   MLDSA87_NVS::saveKeypair(ns, pk, sk)
 *   MLDSA87_NVS::saveSeed(ns, seed)
 *   MLDSA87_NVS::loadKeypair(ns, pk, sk)
 *   MLDSA87_NVS::loadPublicKey(ns, pk)
 *   MLDSA87_NVS::hasKeypair(ns)
 *   MLDSA87_NVS::eraseKeypair(ns)
 *   MLDSA87_NVS::migrate(ns)
 *
 * Each takes an optional last argument, mldsa::NvsError *, that receives
 * the reason for a failure.
 *
 * Requires: ESP32 Arduino core with Preferences library (included by default)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLDSA87_NVS_H
#define MLDSA87_NVS_H

#include "MLDSA87.h"
#include "MLDSA_NVS.h"

class MLDSA87_NVS : public mldsa::Nvs<87> {};

#endif /* MLDSA87_NVS_H */
