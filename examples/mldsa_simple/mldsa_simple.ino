/*
 * Simple ML-DSA-44 example using the MLDSA44 C++ wrapper.
 *
 * It runs in setup(), on the default Arduino stack: the library takes its
 * working memory (about 13 KB while signing) from the heap and needs about
 * 3 KB of stack.
 *
 * The key and signature buffers are static because together they take 6 KB,
 * most of that stack.
 */

#include <Arduino.h>
#include <MLDSA44.h>

static uint8_t pk[MLDSA44::PUBLIC_KEY_SIZE];
static uint8_t sk[MLDSA44::SECRET_KEY_SIZE];
static uint8_t sig[MLDSA44::SIGNATURE_SIZE];

void setup() {
  Serial.begin(115200);
  delay(1000);

  // Generate keypair
  if (MLDSA44::generateKeypair(pk, sk) != 0) {
    Serial.println("Keygen failed!");
    return;
  }
  Serial.println("Keypair generated.");

  // Sign a message
  const char *msg = "Hello, post-quantum world!";
  size_t siglen;
  if (MLDSA44::sign(sig, &siglen, (const uint8_t *)msg, strlen(msg), sk) != 0) {
    Serial.println("Signing failed!");
    MLDSA44::secureZero(sk, sizeof(sk));
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
  MLDSA44::secureZero(sk, sizeof(sk));
}

void loop() {
  delay(1000);
}
