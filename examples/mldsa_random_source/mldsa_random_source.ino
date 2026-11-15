/*
 * Choosing the random source for ML-DSA
 *
 * A key is only as unpredictable as the random numbers it was generated
 * from. By default this library takes them from the ESP32 hardware RNG,
 * which produces true random numbers only while Wi-Fi or Bluetooth is
 * enabled, or while the SAR ADC entropy source is enabled. Otherwise
 * ESP-IDF documents its output as pseudo-random only.
 *
 * This sketch shows two ways to generate a key with the radio off:
 *
 *   1. Enable the SAR ADC entropy source around key generation.
 *   2. Register a random source of your own. Here it is the CTR-DRBG of
 *      mbedTLS, seeded once while the entropy source is enabled, which then
 *      keeps working with the entropy source off.
 *
 * bootloader_random_enable() must not be used while Wi-Fi, Bluetooth, the
 * ADC or (on the ESP32) I2S are in use; disable it before starting them.
 *
 * https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/random.html
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <MLDSA44.h>
#include <bootloader_random.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>

static uint8_t pk[MLDSA44::PUBLIC_KEY_SIZE];
static uint8_t sk[MLDSA44::SECRET_KEY_SIZE];
static uint8_t sig[MLDSA44::SIGNATURE_SIZE];

static mbedtls_entropy_context entropy;
static mbedtls_ctr_drbg_context drbg;

/* A random source for the library: returns 0 on success. */
static int drbgSource(uint8_t *out, size_t outlen, void *context) {
  return mbedtls_ctr_drbg_random(context, out, outlen);
}

static bool signAndVerify() {
  const char *msg = "random source example";
  size_t siglen;
  return MLDSA44::sign(sig, &siglen, (const uint8_t *)msg, strlen(msg), sk) == 0 &&
         MLDSA44::verify(sig, siglen, (const uint8_t *)msg, strlen(msg), pk) == 0;
}

void setup() {
  Serial.begin(115200);
  delay(1000);

  // --- 1. Hardware RNG, with the entropy source enabled for the keygen ---
  bootloader_random_enable();
  int ret = MLDSA44::generateKeypair(pk, sk);
  bootloader_random_disable();
  Serial.printf("1. Keygen with the SAR ADC entropy source: %s\n",
                ret == 0 && signAndVerify() ? "OK" : "FAILED");

  // --- 2. A DRBG of your own as the random source ---
  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&drbg);
  bootloader_random_enable();
  ret = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *)"mldsa-esp32", 11);
  bootloader_random_disable();
  if (ret != 0) {
    Serial.printf("2. Could not seed the DRBG (mbedTLS error %d)\n", ret);
  } else {
    // From here on, key generation and signing draw from the DRBG.
    mldsa::setRandomSource(drbgSource, &drbg);
    ret = MLDSA44::generateKeypair(pk, sk);
    Serial.printf("2. Keygen with a registered CTR-DRBG: %s\n",
                  ret == 0 && signAndVerify() ? "OK" : "FAILED");
  }

  MLDSA44::secureZero(sk, sizeof(sk));
  Serial.println("Done.");
}

void loop() {
  delay(5000);
  Serial.println("Done.");
}
