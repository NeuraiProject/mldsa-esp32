/*
 * ML-DSA-44 Demo for ESP32
 *
 * Demonstrates post-quantum digital signature generation and verification
 * using the ML-DSA-44 (FIPS 204) algorithm on an ESP32 microcontroller.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <mldsa_native.h>

TaskHandle_t cryptoTaskHandle = NULL;

void printHex(const char *label, const uint8_t *data, size_t len) {
  Serial.printf("%s (%u bytes): ", label, (unsigned int)len);
  for (size_t i = 0; i < len && i < 32; i++) {
    Serial.printf("%02X", data[i]);
  }
  if (len > 32) {
    Serial.printf("... [truncated]");
  }
  Serial.println();
}

void printMemInfo(const char *phase) {
  Serial.printf("[%s] Free heap: %u bytes, largest block: %u bytes\n",
                phase,
                (unsigned int)ESP.getFreeHeap(),
                (unsigned int)ESP.getMaxAllocHeap());
}

void cryptoTask(void *pvParameters) {
  Serial.println();
  Serial.println("========================================");
  Serial.println("  ML-DSA-44 (FIPS 204) Demo for ESP32");
  Serial.println("========================================");
  Serial.println();

  Serial.printf("Key sizes: PK=%u bytes, SK=%u bytes, SIG=%u bytes\n",
                (unsigned int)MLDSA44_PUBLICKEYBYTES,
                (unsigned int)MLDSA44_SECRETKEYBYTES,
                (unsigned int)MLDSA44_BYTES);
  printMemInfo("Start");

  uint8_t pk[MLDSA44_PUBLICKEYBYTES];
  uint8_t sk[MLDSA44_SECRETKEYBYTES];
  uint8_t signature[MLDSA44_BYTES];
  size_t siglen;
  int ret;

  // --- 1. Key Generation ---
  Serial.println("\n--- Key Generation ---");
  printMemInfo("Before keygen");
  unsigned long start = millis();
  ret = PQCP_MLDSA_NATIVE_MLDSA44_keypair(pk, sk);
  unsigned long elapsed = millis() - start;

  if (ret != 0) {
    Serial.printf("ERROR: Keypair generation failed with code %d\n", ret);
    vTaskDelete(NULL);
    return;
  }
  Serial.printf("Keypair generated in %lu ms\n", elapsed);
  printHex("Public Key", pk, MLDSA44_PUBLICKEYBYTES);
  printMemInfo("After keygen");

  // --- 2. Signing ---
  const char *message = "Hello, post-quantum world!";
  size_t mlen = strlen(message);

  Serial.printf("\n--- Signing ---\n");
  Serial.printf("Message: \"%s\" (%u bytes)\n", message, (unsigned int)mlen);
  start = millis();
  ret = PQCP_MLDSA_NATIVE_MLDSA44_signature(
      signature, &siglen,
      (const uint8_t *)message, mlen,
      NULL, 0,  // No context string
      sk);
  elapsed = millis() - start;

  if (ret != 0) {
    Serial.printf("ERROR: Signing failed with code %d\n", ret);
    vTaskDelete(NULL);
    return;
  }
  Serial.printf("Signed in %lu ms (signature: %u bytes)\n", elapsed, (unsigned int)siglen);
  printHex("Signature", signature, siglen);

  // --- 3. Verification ---
  Serial.println("\n--- Verification ---");
  start = millis();
  ret = PQCP_MLDSA_NATIVE_MLDSA44_verify(
      signature, siglen,
      (const uint8_t *)message, mlen,
      NULL, 0,  // No context string
      pk);
  elapsed = millis() - start;

  if (ret == 0) {
    Serial.printf("Verification SUCCESS (%lu ms)\n", elapsed);
  } else {
    Serial.printf("Verification FAILED: code %d (%lu ms)\n", ret, elapsed);
  }

  // --- 4. Tamper test ---
  Serial.println("\n--- Tamper Test ---");
  signature[0] ^= 0x01;  // Flip one bit
  ret = PQCP_MLDSA_NATIVE_MLDSA44_verify(
      signature, siglen,
      (const uint8_t *)message, mlen,
      NULL, 0,
      pk);

  if (ret != 0) {
    Serial.println("Tampered signature correctly REJECTED");
  } else {
    Serial.println("WARNING: Tampered signature was accepted!");
  }

  // Zeroize sensitive material
  memset(sk, 0, sizeof(sk));

  Serial.println("\n========================================");
  printMemInfo("End");
  Serial.println("Demo complete.");
  Serial.println("========================================");

  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  while (!Serial) {
    ;
  }
  delay(1000);

  // ML-DSA-44 requires significant stack space for intermediate computations.
  // 64KB is sufficient for keygen + sign + verify.
  xTaskCreate(
      cryptoTask,
      "cryptoTask",
      65536,
      NULL,
      1,
      &cryptoTaskHandle);
}

void loop() {
  delay(1000);
}
