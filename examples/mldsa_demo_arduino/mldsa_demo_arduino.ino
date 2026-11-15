/*
 * ML-DSA-44 Demo for ESP32
 *
 * Demonstrates post-quantum digital signature generation and verification
 * using the ML-DSA-44 (FIPS 204) algorithm on an ESP32 microcontroller.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <MLDSA44.h>

/* The crypto task holds the key and signature buffers on its stack (6 KB
 * for ML-DSA-44); the library itself needs about 3 KB more. */
static const uint32_t TASK_STACK_BYTES = 16 * 1024;

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
                (unsigned int)MLDSA44::PUBLIC_KEY_SIZE,
                (unsigned int)MLDSA44::SECRET_KEY_SIZE,
                (unsigned int)MLDSA44::SIGNATURE_SIZE);
  printMemInfo("Start");

  uint8_t pk[MLDSA44::PUBLIC_KEY_SIZE];
  uint8_t sk[MLDSA44::SECRET_KEY_SIZE];
  uint8_t signature[MLDSA44::SIGNATURE_SIZE];
  size_t siglen;
  int ret;

  // --- 1. Key Generation ---
  Serial.println("\n--- Key Generation ---");
  printMemInfo("Before keygen");
  unsigned long start = millis();
  ret = MLDSA44::generateKeypair(pk, sk);
  unsigned long elapsed = millis() - start;

  if (ret != 0) {
    Serial.printf("ERROR: Keypair generation failed with code %d\n", ret);
    vTaskDelete(NULL);
    return;
  }
  Serial.printf("Keypair generated in %lu ms\n", elapsed);
  printHex("Public Key", pk, MLDSA44::PUBLIC_KEY_SIZE);
  printMemInfo("After keygen");

  // --- 2. Signing ---
  const char *message = "Hello, post-quantum world!";
  size_t mlen = strlen(message);

  Serial.printf("\n--- Signing ---\n");
  Serial.printf("Message: \"%s\" (%u bytes)\n", message, (unsigned int)mlen);
  start = millis();
  ret = MLDSA44::sign(signature, &siglen, (const uint8_t *)message, mlen, sk);
  elapsed = millis() - start;

  if (ret != 0) {
    Serial.printf("ERROR: Signing failed with code %d\n", ret);
    MLDSA44::secureZero(sk, sizeof(sk));
    vTaskDelete(NULL);
    return;
  }
  Serial.printf("Signed in %lu ms (signature: %u bytes)\n", elapsed, (unsigned int)siglen);
  printHex("Signature", signature, siglen);

  // --- 3. Verification ---
  Serial.println("\n--- Verification ---");
  start = millis();
  ret = MLDSA44::verify(signature, siglen, (const uint8_t *)message, mlen, pk);
  elapsed = millis() - start;

  if (ret == 0) {
    Serial.printf("Verification SUCCESS (%lu ms)\n", elapsed);
  } else {
    Serial.printf("Verification FAILED: code %d (%lu ms)\n", ret, elapsed);
  }

  // --- 4. Tamper test ---
  Serial.println("\n--- Tamper Test ---");
  signature[0] ^= 0x01;  // Flip one bit
  ret = MLDSA44::verify(signature, siglen, (const uint8_t *)message, mlen, pk);

  if (ret != 0) {
    Serial.println("Tampered signature correctly REJECTED");
  } else {
    Serial.println("WARNING: Tampered signature was accepted!");
  }

  // Zeroize sensitive material
  MLDSA44::secureZero(sk, sizeof(sk));

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

  // The library takes its working memory from the heap; the printMemInfo()
  // lines show how much is free before and after each step.
  if (xTaskCreate(cryptoTask, "cryptoTask", TASK_STACK_BYTES, NULL, 1,
                  &cryptoTaskHandle) != pdPASS) {
    Serial.println("ERROR: could not create the crypto task");
  }
}

void loop() {
  delay(1000);
}
