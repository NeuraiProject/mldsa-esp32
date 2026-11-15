/*
 * mldsa_esp32.c - random source dispatch and secure wiping
 *
 * Platform independent: the part that talks to the ESP32 is in src/esp32/.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "common.h" /* the core's configuration, needed by ct.h */
#include "ct.h"     /* mld_zeroize() */

#include "mldsa_esp32.h"

static mldsa_esp32_rng_t registered_rng;
static void *registered_context;

void mldsa_esp32_set_rng(mldsa_esp32_rng_t rng, void *context) {
  registered_rng = rng;
  registered_context = rng != NULL ? context : NULL;
}

int mldsa_esp32_randombytes(uint8_t *out, size_t outlen) {
  mldsa_esp32_rng_t rng = registered_rng;
  void *context = registered_context;

  if (outlen == 0) {
    return 0;
  }
  if (out == NULL) {
    return -1;
  }
  if (rng == NULL) {
    rng = mldsa_esp32_default_rng;
    context = NULL;
  }
  if (rng(out, outlen, context) != 0) {
    /* Whatever a failed source left behind must not be used. */
    mld_zeroize(out, outlen);
    return -1;
  }
  return 0;
}

void mldsa_esp32_secure_zero(void *ptr, size_t len) {
  if (ptr != NULL && len != 0) {
    mld_zeroize(ptr, len);
  }
}
