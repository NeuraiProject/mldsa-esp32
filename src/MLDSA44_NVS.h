/*
 * MLDSA44_NVS.h - NVS (Non-Volatile Storage) helper for ML-DSA-44 keypairs
 *
 * Provides persistent storage for ML-DSA-44 keys using ESP32's NVS flash
 * partition. Keys survive reboots and power cycles, avoiding expensive
 * regeneration (~seconds on ESP32).
 *
 * Requires: ESP32 Arduino core with Preferences library (included by default)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLDSA44_NVS_H
#define MLDSA44_NVS_H

#include <Preferences.h>
#include <stdint.h>
#include <string.h>
#include "MLDSA44.h"

class MLDSA44_NVS {
public:
  /*
   * Save a keypair to NVS.
   *
   * ns:  NVS namespace (max 15 chars, e.g. "mldsa")
   * pk:  public key buffer (PUBLIC_KEY_SIZE bytes)
   * sk:  secret key buffer (SECRET_KEY_SIZE bytes)
   *
   * Returns true on success.
   */
  static bool saveKeypair(const char *ns,
                          const uint8_t *pk, const uint8_t *sk) {
    Preferences prefs;
    if (!prefs.begin(ns, false)) {
      return false;
    }
    size_t wrote_pk = prefs.putBytes("pk", pk, MLDSA44::PUBLIC_KEY_SIZE);
    size_t wrote_sk = prefs.putBytes("sk", sk, MLDSA44::SECRET_KEY_SIZE);
    prefs.end();
    return (wrote_pk == MLDSA44::PUBLIC_KEY_SIZE &&
            wrote_sk == MLDSA44::SECRET_KEY_SIZE);
  }

  /*
   * Load a keypair from NVS.
   *
   * ns:  NVS namespace used when saving
   * pk:  output buffer of PUBLIC_KEY_SIZE bytes
   * sk:  output buffer of SECRET_KEY_SIZE bytes
   *
   * Returns true if a valid keypair was loaded.
   */
  static bool loadKeypair(const char *ns,
                          uint8_t *pk, uint8_t *sk) {
    Preferences prefs;
    if (!prefs.begin(ns, true)) {
      return false;
    }
    size_t read_pk = prefs.getBytes("pk", pk, MLDSA44::PUBLIC_KEY_SIZE);
    size_t read_sk = prefs.getBytes("sk", sk, MLDSA44::SECRET_KEY_SIZE);
    prefs.end();
    return (read_pk == MLDSA44::PUBLIC_KEY_SIZE &&
            read_sk == MLDSA44::SECRET_KEY_SIZE);
  }

  /*
   * Load only the public key from NVS.
   *
   * ns:  NVS namespace used when saving
   * pk:  output buffer of PUBLIC_KEY_SIZE bytes
   *
   * Returns true if loaded successfully.
   */
  static bool loadPublicKey(const char *ns, uint8_t *pk) {
    Preferences prefs;
    if (!prefs.begin(ns, true)) {
      return false;
    }
    size_t read_pk = prefs.getBytes("pk", pk, MLDSA44::PUBLIC_KEY_SIZE);
    prefs.end();
    return (read_pk == MLDSA44::PUBLIC_KEY_SIZE);
  }

  /*
   * Check if a keypair exists in NVS.
   *
   * ns:  NVS namespace to check
   *
   * Returns true if both pk and sk exist.
   */
  static bool hasKeypair(const char *ns) {
    Preferences prefs;
    if (!prefs.begin(ns, true)) {
      return false;
    }
    bool has = prefs.isKey("pk") && prefs.isKey("sk");
    prefs.end();
    return has;
  }

  /*
   * Erase a keypair from NVS securely.
   * Removes both pk and sk entries from the namespace.
   *
   * ns:  NVS namespace to erase
   *
   * Returns true on success.
   */
  static bool eraseKeypair(const char *ns) {
    Preferences prefs;
    if (!prefs.begin(ns, false)) {
      return false;
    }
    prefs.remove("pk");
    prefs.remove("sk");
    prefs.end();
    return true;
  }

  /*
   * Generate a new keypair and save it to NVS in one step.
   *
   * ns:  NVS namespace (max 15 chars)
   * pk:  output buffer of PUBLIC_KEY_SIZE bytes
   * sk:  output buffer of SECRET_KEY_SIZE bytes
   *
   * Returns 0 on success, negative on keygen error, 1 on NVS save error.
   */
  static int generateAndSave(const char *ns,
                             uint8_t *pk, uint8_t *sk) {
    int ret = MLDSA44::generateKeypair(pk, sk);
    if (ret != 0) {
      return ret;
    }
    if (!saveKeypair(ns, pk, sk)) {
      return 1;
    }
    return 0;
  }
};

#endif /* MLDSA44_NVS_H */
