/*
 * Two functions that copy a secret into a local buffer, use it and wipe it,
 * one with memset() and one with secureZero().
 *
 * This file is compiled with optimization and its machine code inspected:
 * the wipe done with secureZero() must still be there. The memset() one is
 * usually gone, because the buffer is not read again; that is why the
 * library offers secureZero().
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <cstdint>
#include <cstring>

#include "MLDSA44.h"

extern "C" int wipe_with_memset(const uint8_t *in) {
  uint8_t secret[64];
  memcpy(secret, in, sizeof secret);
  int value = secret[5] ^ secret[40];
  memset(secret, 0, sizeof secret);
  return value;
}

extern "C" int wipe_with_secure_zero(const uint8_t *in) {
  uint8_t secret[64];
  memcpy(secret, in, sizeof secret);
  int value = secret[5] ^ secret[40];
  MLDSA44::secureZero(secret, sizeof secret);
  return value;
}
