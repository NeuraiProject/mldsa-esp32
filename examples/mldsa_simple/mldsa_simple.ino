/*
 * Simple ML-DSA-44 example using the MLDSA44 C++ wrapper.
 *
 * This example uses a FreeRTOS task with 64KB stack because
 * ML-DSA-44 needs ~32KB of working memory for signing.
 */

#include <Arduino.h>
#include <MLDSA44.h>

void cryptoTask(void *pvParameters) {
  uint8_t pk[MLDSA44::PUBLIC_KEY_SIZE];
  uint8_t sk[MLDSA44::SECRET_KEY_SIZE];
  uint8_t sig[MLDSA44::SIGNATURE_SIZE];
  size_t siglen;

  // Generate keypair
  if (MLDSA44::generateKeypair(pk, sk) != 0) {
    Serial.println("Keygen failed!");
    vTaskDelete(NULL);
    return;
  }
  Serial.println("Keypair generated.");

  // Sign a message
  const char *msg = "Hello, post-quantum world!";
  if (MLDSA44::sign(sig, &siglen, (const uint8_t *)msg, strlen(msg), sk) != 0) {
    Serial.println("Signing failed!");
    vTaskDelete(NULL);
    return;
  }
  Serial.printf("Signed (%u bytes)\n", (unsigned)siglen);

  // Verify
  if (MLDSA44::verify(sig, siglen, (const uint8_t *)msg, strlen(msg), pk) == 0) {
    Serial.println("Verification OK!");
  } else {
    Serial.println("Verification FAILED!");
  }

  // Clean up secret key
  memset(sk, 0, sizeof(sk));
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
