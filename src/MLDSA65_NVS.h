/*
 * MLDSA65_NVS.h - persistent storage of an ML-DSA-65 key in NVS
 *
 * Keys survive reboots and power cycles. The operations are documented in
 * MLDSA_NVS.h:
 *
 *   MLDSA65_NVS::generateAndSave(ns, pk, sk)
 *   MLDSA65_NVS::saveKeypair(ns, pk, sk)
 *   MLDSA65_NVS::saveSeed(ns, seed)
 *   MLDSA65_NVS::loadKeypair(ns, pk, sk)
 *   MLDSA65_NVS::loadPublicKey(ns, pk)
 *   MLDSA65_NVS::hasKeypair(ns)
 *   MLDSA65_NVS::eraseKeypair(ns)
 *   MLDSA65_NVS::migrate(ns)
 *
 * Each takes an optional last argument, mldsa::NvsError *, that receives
 * the reason for a failure.
 *
 * Requires: ESP32 Arduino core with Preferences library (included by default)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLDSA65_NVS_H
#define MLDSA65_NVS_H

#include "MLDSA65.h"
#include "MLDSA_NVS.h"

class MLDSA65_NVS : public mldsa::Nvs<65> {};

#endif /* MLDSA65_NVS_H */
