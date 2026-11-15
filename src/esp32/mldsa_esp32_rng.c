/*
 * mldsa_esp32_rng.c - the default random source: the ESP32 hardware RNG
 *
 * esp_fill_random() cannot report failure, and does not say whether an
 * entropy source is active. See mldsa_esp32.h and the README for what the
 * application has to guarantee before it generates keys.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <esp_random.h>

#include "../mldsa_esp32.h"

int mldsa_esp32_default_rng(uint8_t *out, size_t outlen, void *context) {
  (void)context;
  esp_fill_random(out, outlen);
  return 0;
}
