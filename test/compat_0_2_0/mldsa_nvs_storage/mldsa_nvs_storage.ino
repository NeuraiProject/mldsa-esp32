/*
 * ML-DSA-44 NVS Persistent Key Storage Example
 *
 * Demonstrates storing ML-DSA-44 keypairs in ESP32's Non-Volatile Storage (NVS)
 * so they survive reboots without expensive regeneration.
 *
 * First boot:  Generates a new keypair and stores it in NVS flash.
 * Next boots:  Loads the existing keypair from NVS instantly.
 *
 * The example then signs and verifies a message to prove the loaded keys work.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <MLDSA44.h>
#include <MLDSA44_NVS.h>

static const char *NVS_NAMESPACE = "mldsa";

void printHex(const char *label, const uint8_t *data, size_t len) {
  Serial.printf("%s (%u bytes): ", label, (unsigned)len);
  for (size_t i = 0; i < len && i < 16; i++) {
    Serial.printf("%02X", data[i]);
  }
  if (len > 16) Serial.print("...");
  Serial.println();
}

void cryptoTask(void *pvParameters) {
  uint8_t pk[MLDSA44::PUBLIC_KEY_SIZE];
  uint8_t sk[MLDSA44::SECRET_KEY_SIZE];

  Serial.println();
  Serial.println("=== ML-DSA-44 NVS Key Storage Demo ===");
  Serial.println();

  // Check if we already have a stored keypair
  if (MLDSA44_NVS::hasKeypair(NVS_NAMESPACE)) {
    Serial.println("Found existing keypair in NVS, loading...");
    unsigned long start = millis();

    if (!MLDSA44_NVS::loadKeypair(NVS_NAMESPACE, pk, sk)) {
      Serial.println("ERROR: Failed to load keypair from NVS!");
      vTaskDelete(NULL);
      return;
    }

    Serial.printf("Keypair loaded from NVS in %lu ms\n", millis() - start);
  } else {
    Serial.println("No keypair in NVS. Generating new one...");
    unsigned long start = millis();

    int ret = MLDSA44_NVS::generateAndSave(NVS_NAMESPACE, pk, sk);
    if (ret != 0) {
      Serial.printf("ERROR: generateAndSave failed (code %d)\n", ret);
      vTaskDelete(NULL);
      return;
    }

    Serial.printf("Keypair generated and saved to NVS in %lu ms\n",
                  millis() - start);
  }

  printHex("Public Key", pk, MLDSA44::PUBLIC_KEY_SIZE);

  // Sign a test message to verify the keys work
  const char *msg = "NVS stored key test";
  uint8_t sig[MLDSA44::SIGNATURE_SIZE];
  size_t siglen;

  Serial.printf("\nSigning: \"%s\"\n", msg);
  if (MLDSA44::sign(sig, &siglen, (const uint8_t *)msg, strlen(msg), sk) != 0) {
    Serial.println("ERROR: Signing failed!");
    goto cleanup;
  }
  Serial.printf("Signed (%u bytes)\n", (unsigned)siglen);

  if (MLDSA44::verify(sig, siglen, (const uint8_t *)msg, strlen(msg), pk) == 0) {
    Serial.println("Verification OK -- stored keys work correctly!");
  } else {
    Serial.println("Verification FAILED!");
  }

  /*
   * To erase stored keys (e.g. for key rotation), uncomment:
   * MLDSA44_NVS::eraseKeypair(NVS_NAMESPACE);
   * Serial.println("Keypair erased from NVS.");
   */

cleanup:
  memset(sk, 0, sizeof(sk));
  Serial.println("\n=== Demo complete. Reset to test NVS reload. ===");
  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  xTaskCreate(cryptoTask, "crypto", 65536, NULL, 1, NULL);
}

void loop() {
  delay(1000);
}
