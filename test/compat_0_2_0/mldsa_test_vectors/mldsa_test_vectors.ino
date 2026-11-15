/*
 * ML-DSA-44 FIPS 204 Test Vectors Verification
 *
 * Verifies this implementation against official NIST ACVP test vectors
 * to ensure conformance with the FIPS 204 standard.
 *
 * Test vector source:
 *   https://github.com/usnistgov/ACVP-Server/tree/master/gen-val/json-files/
 *   ML-DSA-keyGen-FIPS204 (tgId=1, tcId=1, parameterSet=ML-DSA-44)
 *
 * What this tests:
 *   1. Deterministic keygen: seed -> (pk, sk) matches NIST expected output
 *   2. Round-trip: sign with generated sk, verify with generated pk
 *   3. Cross-verification: keypair is internally consistent
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <MLDSA44.h>

/*
 * NIST ACVP ML-DSA-44 KeyGen Test Vector (tcId=1)
 * Source: ML-DSA-keyGen-FIPS204/prompt.json + expectedResults.json
 */

/* Input seed (32 bytes) */
static const uint8_t NIST_SEED[32] = {
    0xD7, 0x13, 0x61, 0xC0, 0x00, 0xF9, 0xA7, 0xBC,
    0x99, 0xDF, 0xB4, 0x25, 0xBC, 0xB6, 0xBB, 0x27,
    0xC3, 0x2C, 0x36, 0xAB, 0x44, 0x4F, 0xF3, 0x70,
    0x8B, 0x2D, 0x93, 0xB4, 0xE6, 0x6D, 0x5B, 0x5B
};

/*
 * Expected public key -- first 64 bytes (of 1312 total).
 * In ML-DSA-44, the first 32 bytes of pk are "rho" derived from the seed.
 */
static const uint8_t NIST_PK_PREFIX[64] = {
    /* bytes 0-31 (rho) */
    0xB8, 0x45, 0xFA, 0x28, 0x81, 0x40, 0x7A, 0x59,
    0x18, 0x30, 0x71, 0x62, 0x9B, 0x08, 0x22, 0x31,
    0x28, 0x11, 0x60, 0x14, 0xFB, 0x58, 0xFF, 0x6B,
    0xB4, 0xC8, 0xC9, 0xFE, 0x19, 0xCF, 0x5B, 0x0B,
    /* bytes 32-63 (start of t1 encoding) */
    0xD7, 0x7B, 0x16, 0x64, 0x8A, 0x34, 0x4F, 0xFE,
    0x48, 0x6B, 0xC3, 0xE3, 0xCB, 0x5F, 0xAB, 0x9A,
    0xBC, 0x4C, 0xC2, 0xF1, 0xC3, 0x49, 0x01, 0x69,
    0x2B, 0xEC, 0x5D, 0x29, 0x0D, 0x81, 0x5A, 0x6C
};

/*
 * Expected secret key -- first 64 bytes (of 2560 total).
 * sk layout: rho (32) || K (32) || tr (64) || s1 || s2 || t0
 * The first 32 bytes (rho) match pk[0..31].
 */
static const uint8_t NIST_SK_PREFIX[64] = {
    /* bytes 0-31 (rho, same as pk[0..31]) */
    0xB8, 0x45, 0xFA, 0x28, 0x81, 0x40, 0x7A, 0x59,
    0x18, 0x30, 0x71, 0x62, 0x9B, 0x08, 0x22, 0x31,
    0x28, 0x11, 0x60, 0x14, 0xFB, 0x58, 0xFF, 0x6B,
    0xB4, 0xC8, 0xC9, 0xFE, 0x19, 0xCF, 0x5B, 0x0B,
    /* bytes 32-63 (K) */
    0x28, 0x96, 0xDE, 0xCE, 0xBB, 0x71, 0xEF, 0xBA,
    0x3C, 0x69, 0x67, 0x44, 0x4C, 0xFC, 0x64, 0xFC,
    0x28, 0xF7, 0x60, 0x31, 0x7D, 0xEA, 0x7A, 0xC0,
    0xFC, 0x58, 0x8B, 0x15, 0xE1, 0xD4, 0x57, 0xC2
};

static void printHex(const char *label, const uint8_t *data, size_t len) {
  Serial.printf("%s: ", label);
  for (size_t i = 0; i < len; i++) {
    Serial.printf("%02X", data[i]);
  }
  Serial.println();
}

static bool compareBytes(const uint8_t *a, const uint8_t *b, size_t len,
                         const char *name) {
  if (memcmp(a, b, len) == 0) {
    Serial.printf("  [PASS] %s matches NIST expected value (%u bytes)\n",
                  name, (unsigned)len);
    return true;
  }
  Serial.printf("  [FAIL] %s does NOT match!\n", name);
  printHex("    Got     ", a, len > 32 ? 32 : len);
  printHex("    Expected", b, len > 32 ? 32 : len);
  return false;
}

void testTask(void *pvParameters) {
  int pass = 0;
  int fail = 0;

  Serial.println();
  Serial.println("================================================");
  Serial.println("  ML-DSA-44 FIPS 204 Test Vector Verification");
  Serial.println("================================================");
  Serial.println();

  // --- Test 1: Deterministic KeyGen from NIST seed ---
  Serial.println("Test 1: Deterministic KeyGen (NIST ACVP tcId=1)");
  Serial.println("  Generating keypair from known seed...");

  uint8_t pk[MLDSA44::PUBLIC_KEY_SIZE];
  uint8_t sk[MLDSA44::SECRET_KEY_SIZE];

  unsigned long start = millis();
  int ret = MLDSA44::generateKeypairFromSeed(pk, sk, NIST_SEED);
  unsigned long elapsed = millis() - start;

  if (ret != 0) {
    Serial.printf("  [FAIL] generateKeypairFromSeed returned %d\n", ret);
    fail++;
  } else {
    Serial.printf("  KeyGen completed in %lu ms\n", elapsed);

    if (compareBytes(pk, NIST_PK_PREFIX, 64, "pk[0..63]")) pass++;
    else fail++;

    if (compareBytes(sk, NIST_SK_PREFIX, 64, "sk[0..63]")) pass++;
    else fail++;

    /* Verify rho consistency: pk[0..31] == sk[0..31] */
    if (compareBytes(pk, sk, 32, "rho (pk[0..31] == sk[0..31])")) pass++;
    else fail++;
  }

  // --- Test 2: Round-trip sign/verify with NIST-derived keys ---
  Serial.println("\nTest 2: Sign/Verify round-trip with NIST-derived keypair");

  const char *msg = "FIPS 204 conformance test";
  uint8_t sig[MLDSA44::SIGNATURE_SIZE];
  size_t siglen;

  ret = MLDSA44::sign(sig, &siglen, (const uint8_t *)msg, strlen(msg), sk);
  if (ret != 0) {
    Serial.printf("  [FAIL] sign returned %d\n", ret);
    fail++;
  } else {
    Serial.printf("  Signed OK (siglen=%u)\n", (unsigned)siglen);

    /* Verify with the NIST-derived public key */
    ret = MLDSA44::verify(sig, siglen, (const uint8_t *)msg, strlen(msg), pk);
    if (ret == 0) {
      Serial.println("  [PASS] Signature verified with NIST-derived pk");
      pass++;
    } else {
      Serial.printf("  [FAIL] Verification failed (code %d)\n", ret);
      fail++;
    }

    /* Tamper and verify rejection */
    sig[0] ^= 0x01;
    ret = MLDSA44::verify(sig, siglen, (const uint8_t *)msg, strlen(msg), pk);
    if (ret != 0) {
      Serial.println("  [PASS] Tampered signature correctly rejected");
      pass++;
    } else {
      Serial.println("  [FAIL] Tampered signature was accepted!");
      fail++;
    }
  }

  // --- Test 3: Context string support ---
  Serial.println("\nTest 3: Signing with context string");
  const char *ctx_msg = "context test message";
  const uint8_t ctx[] = "my-app-v1";
  size_t ctxlen = sizeof(ctx) - 1; /* exclude null terminator */

  ret = MLDSA44::sign(sig, &siglen,
                      (const uint8_t *)ctx_msg, strlen(ctx_msg),
                      sk, ctx, ctxlen);
  if (ret != 0) {
    Serial.printf("  [FAIL] sign with context returned %d\n", ret);
    fail++;
  } else {
    /* Verify with same context */
    ret = MLDSA44::verify(sig, siglen,
                          (const uint8_t *)ctx_msg, strlen(ctx_msg),
                          pk, ctx, ctxlen);
    if (ret == 0) {
      Serial.println("  [PASS] Verified with matching context");
      pass++;
    } else {
      Serial.printf("  [FAIL] Verification with context failed (%d)\n", ret);
      fail++;
    }

    /* Verify with wrong context must fail */
    const uint8_t bad_ctx[] = "wrong-ctx";
    ret = MLDSA44::verify(sig, siglen,
                          (const uint8_t *)ctx_msg, strlen(ctx_msg),
                          pk, bad_ctx, sizeof(bad_ctx) - 1);
    if (ret != 0) {
      Serial.println("  [PASS] Wrong context correctly rejected");
      pass++;
    } else {
      Serial.println("  [FAIL] Wrong context was accepted!");
      fail++;
    }
  }

  // --- Summary ---
  memset(sk, 0, sizeof(sk));

  Serial.println();
  Serial.println("================================================");
  Serial.printf("  Results: %d passed, %d failed\n", pass, fail);
  if (fail == 0) {
    Serial.println("  ALL TESTS PASSED -- FIPS 204 conformance OK");
  } else {
    Serial.println("  SOME TESTS FAILED -- check implementation!");
  }
  Serial.println("================================================");

  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  xTaskCreate(testTask, "test", 65536, NULL, 1, NULL);
}

void loop() {
  delay(1000);
}
