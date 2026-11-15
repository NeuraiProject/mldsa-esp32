/*
 * Regression firmware: ML-DSA-44, 65 and 87 linked and exercised together.
 *
 * 1. For each variant: generate a keypair, sign, verify, and check that a
 *    tampered signature is rejected.
 * 2. Two tasks do the same at the same time, one with ML-DSA-44 and one with
 *    ML-DSA-87, to show that calls from different tasks do not interfere.
 *
 * Every task here has the stack of the default Arduino loop task, 8 KB: the
 * library takes its working memory from the heap.
 *
 * The report is printed once the run ends and repeated every few seconds, so
 * it can be read whenever the serial port is opened.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <MLDSA44.h>
#include <MLDSA65.h>
#include <MLDSA87.h>

static const uint32_t TASK_STACK_BYTES = 8 * 1024;
static const int CONCURRENT_ROUNDS = 10;

static const uint8_t MSG[] = "mldsa-esp32 variant regression";

static char report[1024];
static size_t reportLen = 0;
static volatile bool finished = false;

static void addLine(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  int n = vsnprintf(report + reportLen, sizeof(report) - reportLen, fmt, args);
  va_end(args);
  if (n > 0) {
    size_t room = sizeof(report) - reportLen - 1;
    reportLen += (size_t)n < room ? (size_t)n : room;
  }
}

/* Keygen, sign, verify and tamper check with the given buffers, which must
 * be large enough for Variant. Returns true if all four behave. */
template <typename Variant>
static bool roundTrip(uint8_t *pk, uint8_t *sk, uint8_t *sig, int *codes) {
  size_t siglen = 0;
  int keygen = Variant::generateKeypair(pk, sk);
  int sign = keygen == 0 ? Variant::sign(sig, &siglen, MSG, sizeof(MSG), sk) : -100;
  int verify = sign == 0 ? Variant::verify(sig, siglen, MSG, sizeof(MSG), pk) : -100;
  int tampered = 0;
  if (verify == 0) {
    sig[10] ^= 0x01;
    tampered = Variant::verify(sig, siglen, MSG, sizeof(MSG), pk);
  }
  if (codes != NULL) {
    codes[0] = keygen;
    codes[1] = sign;
    codes[2] = verify;
    codes[3] = tampered;
  }
  return keygen == 0 && sign == 0 && siglen == Variant::SIGNATURE_SIZE &&
         verify == 0 && tampered != 0;
}

/* ---- 1. the three variants, one after another --------------------------- */

static uint8_t pk[MLDSA87::PUBLIC_KEY_SIZE];
static uint8_t sk[MLDSA87::SECRET_KEY_SIZE];
static uint8_t sig[MLDSA87::SIGNATURE_SIZE];

template <typename Variant> static bool sequential(const char *name) {
  int codes[4];
  bool ok = roundTrip<Variant>(pk, sk, sig, codes);
  addLine("[%s] %s keygen=%d sign=%d verify=%d tampered=%d\n",
          ok ? "PASS" : "FAIL", name, codes[0], codes[1], codes[2], codes[3]);
  return ok;
}

/* ---- 2. two tasks at once ----------------------------------------------- */

struct Worker {
  bool (*run)();
  int failedRounds;
  uint32_t stackFree;
  TaskHandle_t parent;
};

static uint8_t pkA[MLDSA44::PUBLIC_KEY_SIZE], skA[MLDSA44::SECRET_KEY_SIZE],
    sigA[MLDSA44::SIGNATURE_SIZE];
static uint8_t pkB[MLDSA87::PUBLIC_KEY_SIZE], skB[MLDSA87::SECRET_KEY_SIZE],
    sigB[MLDSA87::SIGNATURE_SIZE];

static bool roundA() { return roundTrip<MLDSA44>(pkA, skA, sigA, NULL); }
static bool roundB() { return roundTrip<MLDSA87>(pkB, skB, sigB, NULL); }

static void workerTask(void *arg) {
  Worker *w = (Worker *)arg;
  for (int i = 0; i < CONCURRENT_ROUNDS; i++) {
    if (!w->run()) w->failedRounds++;
    delay(1); /* let other tasks run */
  }
  w->stackFree = uxTaskGetStackHighWaterMark(NULL);
  xTaskNotifyGive(w->parent);
  vTaskDelete(NULL);
}

static bool concurrent() {
  Worker a = {roundA, 0, 0, xTaskGetCurrentTaskHandle()};
  Worker b = {roundB, 0, 0, xTaskGetCurrentTaskHandle()};
  /* One task per core where there are two; time-sliced on one core otherwise. */
  BaseType_t coreB = portNUM_PROCESSORS > 1 ? 1 : 0;
  if (xTaskCreatePinnedToCore(workerTask, "mldsa44", TASK_STACK_BYTES, &a, 1, NULL, 0) != pdPASS ||
      xTaskCreatePinnedToCore(workerTask, "mldsa87", TASK_STACK_BYTES, &b, 1, NULL, coreB) != pdPASS) {
    addLine("[FAIL] concurrent: could not create the tasks\n");
    return false;
  }
  ulTaskNotifyTake(pdFALSE, portMAX_DELAY);
  ulTaskNotifyTake(pdFALSE, portMAX_DELAY);
  bool ok = a.failedRounds == 0 && b.failedRounds == 0;
  addLine("[%s] concurrent: ML-DSA-44 and ML-DSA-87 in two tasks, %d rounds each, "
          "failed rounds %d and %d, stack never used %u and %u of %u bytes\n",
          ok ? "PASS" : "FAIL", CONCURRENT_ROUNDS, a.failedRounds, b.failedRounds,
          (unsigned)a.stackFree, (unsigned)b.stackFree, (unsigned)TASK_STACK_BYTES);
  return ok;
}

/* ---- main ---------------------------------------------------------------- */

static void variantsTask(void *) {
  bool ok = sequential<MLDSA44>("ML-DSA-44");
  ok = sequential<MLDSA65>("ML-DSA-65") && ok;
  ok = sequential<MLDSA87>("ML-DSA-87") && ok;
  addLine("stack: %u of %u bytes never used\n",
          (unsigned)uxTaskGetStackHighWaterMark(NULL), (unsigned)TASK_STACK_BYTES);
  ok = concurrent() && ok;
  addLine("heap: %u bytes free at the lowest point\n", (unsigned)ESP.getMinFreeHeap());
  addLine("%s\n", ok ? "ALL VARIANTS PASSED" : "SOME VARIANTS FAILED");
  finished = true;
  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  if (xTaskCreate(variantsTask, "variants", TASK_STACK_BYTES, NULL, 1, NULL) != pdPASS) {
    addLine("[FAIL] could not create the %u-byte task\n", (unsigned)TASK_STACK_BYTES);
    finished = true;
  }
}

void loop() {
  if (finished) {
    Serial.println("--- mldsa-esp32 build_variants ---");
    Serial.print(report);
    Serial.println("--- end ---");
  }
  delay(3000);
}
