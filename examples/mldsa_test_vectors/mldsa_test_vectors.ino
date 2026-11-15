/*
 * ML-DSA test vector check (NIST ACVP)
 *
 * Runs official NIST ACVP test cases for ML-DSA-44, 65 and 87 on the device.
 *
 * Test vector source:
 *   https://github.com/usnistgov/ACVP-Server  gen-val/json-files
 *   ML-DSA-keyGen-FIPS204, ML-DSA-sigGen-FIPS204, ML-DSA-sigVer-FIPS204
 * converted into acvp_vectors.h by scripts/gen_acvp_vectors.py, which reads
 * the NIST repository at a pinned commit. The header shipped here is a
 * subset that fits in the firmware; the host tests in test/host run every
 * case.
 *
 * What this tests, per parameter set:
 *   1. KeyGen:  seed -> (pk, sk) matches the NIST expected output
 *   2. SigGen:  deterministic and hedged signing through the FIPS 204
 *               interfaces: pure ML-DSA with context, HashML-DSA, the
 *               internal interface and external mu
 *   3. SigVer:  valid signatures accepted, invalid ones rejected
 *   4. Randomized round trips with the hardware RNG, negative checks and
 *      boundary cases (empty message, context of 0, 255 and 256 bytes)
 *
 * Passing this sketch is evidence that the build computes ML-DSA correctly.
 * It is not a FIPS 204 validation.
 *
 * The test logic is in acvp_runner.h.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <mbedtls/sha256.h>

static void acvp_sha256(const uint8_t *in, size_t len, uint8_t out[32]) {
  mbedtls_sha256(in, len, out, 0);
}

static void acvp_fail(const char *what, unsigned id) {
  Serial.printf("  [FAIL] %s (id %u)\n", what, id);
}

/* Let other tasks run between test cases; see acvp_runner.h. */
#define ACVP_YIELD() delay(1)

#include "acvp_runner.h"

/* The test buffers are static and the library takes its working memory from
 * the heap, so the task needs little stack. */
static const uint32_t TASK_STACK_BYTES = 16 * 1024;
static const int ROUNDS = 5;

static int totalPass = 0, totalFail = 0;
static volatile bool finished = false;

template <unsigned L, size_t NKG, size_t NSG, size_t NSV>
static void runLevel(const acvp_keygen_t (&keygen)[NKG],
                     const acvp_siggen_t (&siggen)[NSG],
                     const acvp_sigver_t (&sigver)[NSV]) {
  acvp::Result r;
  unsigned long t0 = millis();
  for (const acvp_keygen_t &t : keygen) acvp::keyGen<L>(r, t);
  for (const acvp_siggen_t &t : siggen) acvp::sigGen<L>(r, t);
  for (const acvp_sigver_t &t : sigver) acvp::sigVer<L>(r, t);
  acvp::roundTrips<L>(r, ROUNDS);
  acvp::edgeCases<L>(r);
  Serial.printf("ML-DSA-%u: keyGen %u, sigGen %u, sigVer %u, %d random rounds, "
                "edge cases -> %d passed, %d failed (%lu ms)\n",
                L, (unsigned)NKG, (unsigned)NSG, (unsigned)NSV, ROUNDS, r.pass,
                r.fail, millis() - t0);
  totalPass += r.pass;
  totalFail += r.fail;
}

static void printSummary() {
  Serial.printf("Results: %d passed, %d failed -- %s\n", totalPass, totalFail,
                totalFail == 0 ? "ALL TESTS PASSED" : "SOME TESTS FAILED");
}

static void testTask(void *) {
  Serial.println();
  Serial.println("ML-DSA NIST ACVP test vector check");
  runLevel<44>(acvp_keygen_44, acvp_siggen_44, acvp_sigver_44);
  runLevel<65>(acvp_keygen_65, acvp_siggen_65, acvp_sigver_65);
  runLevel<87>(acvp_keygen_87, acvp_siggen_87, acvp_sigver_87);
  printSummary();
  finished = true;
  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  if (xTaskCreate(testTask, "test", TASK_STACK_BYTES, NULL, 1, NULL) != pdPASS) {
    Serial.println("ERROR: could not create the test task");
  }
}

void loop() {
  /* Repeat the verdict, so it can be read whenever the monitor is opened. */
  delay(5000);
  if (finished) {
    printSummary();
  }
}
