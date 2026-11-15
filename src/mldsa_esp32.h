/*
 * mldsa_esp32.h - functions of the ESP32 port that are not part of ML-DSA
 *
 * The random source used for key generation and signing, and secure wiping
 * of secrets. Usable from C and C++; the MLDSA44, MLDSA65 and MLDSA87
 * classes offer the same through mldsa::setRandomSource() and secureZero().
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLDSA_ESP32_H
#define MLDSA_ESP32_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A random source: fill out[0..outlen) with random bytes.
 *
 * context is the pointer given to mldsa_esp32_set_rng().
 *
 * Returns 0 on success. Any other value makes the operation that asked for
 * randomness fail with MLD_ERR_RNG_FAIL.
 */
typedef int (*mldsa_esp32_rng_t)(uint8_t *out, size_t outlen, void *context);

/*
 * Use rng for every later key generation and signature. NULL restores the
 * default source.
 *
 * The library does not judge the quality of what the source returns: a
 * source that returns predictable bytes gives predictable keys. Key
 * generation is where this matters most; see the README.
 *
 * Call it before other tasks use the library: it is not synchronized with
 * operations in progress.
 */
void mldsa_esp32_set_rng(mldsa_esp32_rng_t rng, void *context);

/*
 * The default source: esp_fill_random(), which never fails. It is truly
 * random only while Wi-Fi or Bluetooth is enabled, or while the SAR ADC
 * entropy source is enabled with bootloader_random_enable(). context is
 * ignored. Exposed so that a source of your own can build on it.
 */
int mldsa_esp32_default_rng(uint8_t *out, size_t outlen, void *context);

/*
 * What the library calls to get randomness: the registered source, or the
 * default one.
 *
 * Returns 0 on success, and when outlen is 0. Returns -1 if out is NULL
 * with outlen > 0, or if the source fails; out is then wiped.
 */
int mldsa_esp32_randombytes(uint8_t *out, size_t outlen);

/*
 * Overwrite len bytes at ptr with zeros, in a way the compiler does not
 * remove. Use it instead of memset() to wipe secret keys and seeds: a
 * memset() of a buffer that is not read again can be optimized away.
 */
void mldsa_esp32_secure_zero(void *ptr, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* MLDSA_ESP32_H */
