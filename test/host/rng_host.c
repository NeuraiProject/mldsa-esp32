/*
 * Test-only default random source for Linux builds of the library.
 *
 * Stands in for src/esp32/mldsa_esp32_rng.c, which needs the ESP32 SDK.
 * Never ship this file in firmware.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/random.h>

#include "mldsa_esp32.h"

int mldsa_esp32_default_rng(uint8_t *out, size_t outlen, void *context) {
  (void)context;
  while (outlen > 0) {
    ssize_t got = getrandom(out, outlen, 0);
    if (got < 0) {
      if (errno == EINTR) {
        continue;
      }
      return -1;
    }
    if (got == 0) {
      return -1;
    }
    out += got;
    outlen -= (size_t)got;
  }
  return 0;
}
