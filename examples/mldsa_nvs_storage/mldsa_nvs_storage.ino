/*
 * ML-DSA-44 NVS Persistent Key Storage Example
 *
 * Demonstrates keeping an ML-DSA-44 key in ESP32's Non-Volatile Storage (NVS)
 * so that the device keeps its identity across reboots.
 *
 * First boot:  Generates a new keypair and stores it in NVS flash.
 * Next boots:  Loads the existing keypair from NVS.
 *
 * The example then signs and verifies a message to prove the loaded keys work.
 *
 * What is stored is the 32-byte seed of the key; the keypair is derived from
 * it again on every load. NVS is not encrypted unless you enable NVS
 * encryption: without it, anyone who can read the flash can read the key.
 * MLDSA65_NVS and MLDSA87_NVS work the same way.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <MLDSA44.h>
#include <MLDSA44_NVS.h>

static const char *NVS_NAMESPACE = "mldsa";

/* The crypto task holds the key and signature buffers on its stack (6 KB
 * for ML-DSA-44); the library itself needs about 3 KB more. */
static const uint32_t TASK_STACK_BYTES = 16 * 1024;

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

    mldsa::NvsError error;
    if (!MLDSA44_NVS::loadKeypair(NVS_NAMESPACE, pk, sk, &error)) {
      Serial.printf("ERROR: Failed to load keypair from NVS: %s\n",
                    mldsa::nvsErrorText(error));
      vTaskDelete(NULL);
      return;
    }

    Serial.printf("Keypair loaded from NVS in %lu ms\n", millis() - start);
  } else {
    Serial.println("No keypair in NVS. Generating new one...");
    unsigned long start = millis();

    mldsa::NvsError error;
    int ret = MLDSA44_NVS::generateAndSave(NVS_NAMESPACE, pk, sk, &error);
    if (ret != 0) {
      // 1: the key was generated but not stored; negative: keygen failed
      Serial.printf("ERROR: generateAndSave failed (code %d: %s)\n", ret,
                    ret == 1 ? mldsa::nvsErrorText(error) : "key generation");
      MLDSA44::secureZero(sk, sizeof(sk));
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
  MLDSA44::secureZero(sk, sizeof(sk));
  Serial.println("\n=== Demo complete. Reset to test NVS reload. ===");
  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  if (xTaskCreate(cryptoTask, "crypto", TASK_STACK_BYTES, NULL, 1, NULL) != pdPASS) {
    Serial.println("ERROR: could not create the crypto task");
  }
}

void loop() {
  delay(1000);
}
