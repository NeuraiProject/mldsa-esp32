/*
 * Measurement firmware for mldsa-esp32 (not part of the library).
 *
 * 1. Time and stack use of keygen, sign and verify for ML-DSA-44/65/87.
 *    Each operation runs in its own task, so the stack figure is per
 *    operation. Heap use is reported as well.
 * 2. With -DBENCH_NVS: can a key record of each candidate size be written
 *    and then replaced in the default nvs partition, and what is left when a
 *    replacement does not fit?
 *
 * The report is repeated every few seconds once the run has finished, so it
 * can be read whenever the serial port is opened.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <nvs.h>
#include <nvs_flash.h>
#include <esp_system.h>
#ifdef BENCH_WIFI
#include <WiFi.h>
#endif
#include <MLDSA44.h>
#include <MLDSA65.h>
#include <MLDSA87.h>
#ifdef BENCH_NVS
#include <MLDSA44_NVS.h>
#include <MLDSA65_NVS.h>
#include <MLDSA87_NVS.h>
#endif

/* Stack given to each measured operation. It is a static buffer, and the
 * classic ESP32 has little room for static data, so keep it close to what
 * the largest operation needs. */
#ifndef BENCH_STACK_BYTES
#define BENCH_STACK_BYTES (80 * 1024)
#endif
static const uint32_t STACK_BYTES = BENCH_STACK_BYTES;
/* With the heap build, the library's own allocator reports its peak. */
#if defined(MLDSA_ESP32_ALLOC_STATS)
extern "C" {
size_t mldsa_esp32_alloc_peak(void);
void mldsa_esp32_alloc_reset_peak(void);
}
#endif

static const uint8_t MSG[] = "mldsa-esp32 device benchmark message";

static uint8_t pk[MLDSA87::PUBLIC_KEY_SIZE];
static uint8_t sk[MLDSA87::SECRET_KEY_SIZE];
static uint8_t sig[MLDSA87::SIGNATURE_SIZE];
static size_t siglen = 0;

static char report[6000];
static size_t reportLen = 0;
static volatile bool finished = false;
static TaskHandle_t mainTask = NULL;

/* The job stack is a static buffer scanned by hand: on this core,
 * uxTaskGetStackHighWaterMark() is truncated to 16 bits, so it wraps for
 * stacks with more than 64 KB free. */
static StackType_t jobStack[STACK_BYTES];
static StaticTask_t jobTcb;

static uint32_t stackUsed() {
  uint32_t untouched = 0;
  while (untouched < STACK_BYTES && jobStack[untouched] == 0xA5) untouched++;
  return STACK_BYTES - untouched;
}

static void out(const char *fmt, ...) {
  va_list args;
  va_start(args, fmt);
  int n = vsnprintf(report + reportLen, sizeof(report) - reportLen, fmt, args);
  va_end(args);
  if (n > 0) {
    size_t room = sizeof(report) - reportLen - 1;
    Serial.print(report + reportLen);
    reportLen += (size_t)n < room ? (size_t)n : room;
  }
}

struct Ops {
  const char *name;
  int (*keygen)(uint8_t *, uint8_t *);
  int (*keygenSeed)(uint8_t *, uint8_t *, const uint8_t *);
  int (*sign)(uint8_t *, size_t *, const uint8_t *, size_t, const uint8_t *,
              const uint8_t *, size_t);
  int (*verify)(const uint8_t *, size_t, const uint8_t *, size_t,
                const uint8_t *, const uint8_t *, size_t);
  size_t pkSize, skSize, sigSize;
};

static const Ops VARIANTS[] = {
    {"ML-DSA-44", MLDSA44::generateKeypair, MLDSA44::generateKeypairFromSeed,
     MLDSA44::sign, MLDSA44::verify, MLDSA44::PUBLIC_KEY_SIZE,
     MLDSA44::SECRET_KEY_SIZE, MLDSA44::SIGNATURE_SIZE},
    {"ML-DSA-65", MLDSA65::generateKeypair, MLDSA65::generateKeypairFromSeed,
     MLDSA65::sign, MLDSA65::verify, MLDSA65::PUBLIC_KEY_SIZE,
     MLDSA65::SECRET_KEY_SIZE, MLDSA65::SIGNATURE_SIZE},
    {"ML-DSA-87", MLDSA87::generateKeypair, MLDSA87::generateKeypairFromSeed,
     MLDSA87::sign, MLDSA87::verify, MLDSA87::PUBLIC_KEY_SIZE,
     MLDSA87::SECRET_KEY_SIZE, MLDSA87::SIGNATURE_SIZE},
};

enum Kind { KEYGEN, SIGN, VERIFY };
static const char *KIND_NAME[] = {"keygen", "sign", "verify"};

struct Job {
  const Ops *ops;
  Kind kind;
  int iterations;
  uint32_t minUs, maxUs;
  uint64_t sumUs;
  int errors;
  uint32_t stackBase, stackPeak, apiFree;
  bool tamperRejected;
  uint32_t heapBefore, heapLowBefore, heapLowAfter;
};

static void jobTask(void *arg) {
  Job *job = (Job *)arg;
  const Ops *v = job->ops;
  job->stackBase = stackUsed();
  job->minUs = UINT32_MAX;

  for (int i = 0; i < job->iterations; i++) {
    int ret = 0;
    uint32_t t = micros();
    switch (job->kind) {
      case KEYGEN:
        ret = v->keygen(pk, sk);
        break;
      case SIGN:
        ret = v->sign(sig, &siglen, MSG, sizeof(MSG), sk, NULL, 0);
        break;
      case VERIFY:
        ret = v->verify(sig, siglen, MSG, sizeof(MSG), pk, NULL, 0);
        break;
    }
    t = micros() - t;
    if (ret != 0) job->errors++;
    if (t < job->minUs) job->minUs = t;
    if (t > job->maxUs) job->maxUs = t;
    job->sumUs += t;
    vTaskDelay(1); /* let the idle task run */
  }

  if (job->kind == VERIFY) {
    sig[v->sigSize / 2] ^= 0x01;
    job->tamperRejected = v->verify(sig, siglen, MSG, sizeof(MSG), pk, NULL, 0) != 0;
    sig[v->sigSize / 2] ^= 0x01;
  }

  job->stackPeak = stackUsed();
  job->apiFree = uxTaskGetStackHighWaterMark(NULL);
  xTaskNotifyGive(mainTask);
  vTaskDelete(NULL);
}

static void run(const Ops *ops, Kind kind, int iterations) {
  Job job = {};
  job.ops = ops;
  job.kind = kind;
  job.iterations = iterations;
#if defined(MLDSA_ESP32_ALLOC_STATS)
  mldsa_esp32_alloc_reset_peak();
#endif
  job.heapBefore = ESP.getFreeHeap();
  job.heapLowBefore = ESP.getMinFreeHeap();
  if (xTaskCreateStaticPinnedToCore(jobTask, "job", STACK_BYTES, &job, 1, jobStack, &jobTcb, 1) == NULL) {
    out("BENCH %s %s: could not create task\n", ops->name, KIND_NAME[kind]);
    return;
  }
  ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
  job.heapLowAfter = ESP.getMinFreeHeap();
  vTaskDelay(pdMS_TO_TICKS(200)); /* let the idle task retire the job task */

  out("BENCH %s %-11s n=%d min=%.1f avg=%.1f max=%.1f ms errors=%d stack_peak=%u task_base=%u api_free=%u true_free=%u",
      ops->name, KIND_NAME[kind], iterations, job.minUs / 1000.0,
      job.sumUs / 1000.0 / iterations, job.maxUs / 1000.0, job.errors,
      (unsigned)job.stackPeak, (unsigned)job.stackBase, (unsigned)job.apiFree,
      (unsigned)(STACK_BYTES - job.stackPeak));
#if defined(MLDSA_ESP32_ALLOC_STATS)
  out(" lib_heap_peak=%u", (unsigned)mldsa_esp32_alloc_peak());
#endif
  /* The low-water mark is global: it only shows this job's heap peak when the
   * job set a new low. */
  if (job.heapLowAfter < job.heapLowBefore) {
    out(" heap_peak=%u", (unsigned)(job.heapBefore - job.heapLowAfter));
  } else {
    out(" heap_peak<=%u", (unsigned)(job.heapBefore - job.heapLowBefore));
  }
  if (kind == VERIFY) out(" tampered=%s", job.tamperRejected ? "rejected" : "ACCEPTED");
  out("\n");
}

#ifdef BENCH_NVS
/* ---- NVS sizing ---------------------------------------------------------- */

static uint8_t blob[8192];
static uint8_t readback[8192];
static const char *NS = "mldsa_sz";

static nvs_stats_t stats() {
  nvs_stats_t s = {};
  nvs_get_stats(NULL, &s);
  return s;
}

/* Same effect on NVS as a reboot: orphaned blob chunks are cleaned up. */
static void nvsReinit() {
  nvs_flash_deinit();
  nvs_flash_init();
}

static void fill(uint8_t *buf, size_t size, int generation) {
  memset(buf, 0x30 + generation, size);
}

/* What does `key` hold? "gen N" when it is a complete blob of one pattern. */
static void describe(nvs_handle_t h, const char *key, size_t size, char *text, size_t textLen) {
  size_t len = sizeof(readback);
  esp_err_t err = nvs_get_blob(h, key, readback, &len);
  if (err != ESP_OK) {
    snprintf(text, textLen, "unreadable (%s)", esp_err_to_name(err));
    return;
  }
  bool uniform = len == size;
  for (size_t i = 1; uniform && i < len; i++) uniform = readback[i] == readback[0];
  if (uniform) snprintf(text, textLen, "gen %d", readback[0] - 0x30);
  else snprintf(text, textLen, "corrupt (len %u)", (unsigned)len);
}

static void eraseTestKeys() {
  nvs_handle_t h;
  if (nvs_open(NS, NVS_READWRITE, &h) == ESP_OK) {
    nvs_erase_all(h);
    nvs_commit(h);
    nvs_close(h);
  }
  nvsReinit();
}

/* One record under one key, written once and then replaced. */
static void nvsBlobTest(const char *label, size_t size, int cycles) {
  eraseTestKeys();
  unsigned usedStart = stats().used_entries;
  nvs_handle_t h;
  if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return;

  int ok = 0, lastGood = -1, failedGen = -1;
  esp_err_t failure = ESP_OK;
  uint32_t slowest = 0;
  for (int gen = 0; gen <= cycles; gen++) {
    fill(blob, size, gen);
    uint32_t t = millis();
    esp_err_t err = nvs_set_blob(h, "kp", blob, size);
    if (err == ESP_OK) err = nvs_commit(h);
    t = millis() - t;
    if (t > slowest) slowest = t;
    if (err != ESP_OK) {
      failure = err;
      failedGen = gen;
      break;
    }
    ok++;
    lastGood = gen;
  }

  char now[48] = "-", afterReinit[48] = "-";
  unsigned usedFail = stats().used_entries, usedReinit = usedFail;
  if (failedGen >= 0) {
    describe(h, "kp", size, now, sizeof(now));
    nvs_close(h);
    nvsReinit();
    usedReinit = stats().used_entries;
    if (nvs_open(NS, NVS_READWRITE, &h) == ESP_OK) describe(h, "kp", size, afterReinit, sizeof(afterReinit));
  }
  nvs_close(h);

  out("NVS %-10s %5u B: writes ok %d/%d, slowest %u ms, entries used by record %u",
      label, (unsigned)size, ok, cycles + 1, (unsigned)slowest,
      ok > 0 && failedGen < 0 ? stats().used_entries - usedStart : 0);
  if (failedGen >= 0) {
    out(" | write %d failed: %s; last good gen %d; stored value right after: %s (used %u); after NVS re-init: %s (used %u)",
        failedGen, esp_err_to_name(failure), lastGood, now, usedFail, afterReinit, usedReinit);
  }
  out("\n");
}

/* Layout of MLDSA44_NVS today: separate "pk" and "sk" entries. */
static void nvsPairTest(const char *label, size_t pkSize, size_t skSize, int cycles) {
  eraseTestKeys();
  nvs_handle_t h;
  if (nvs_open(NS, NVS_READWRITE, &h) != ESP_OK) return;

  int ok = 0, failedGen = -1;
  const char *failedKey = "";
  esp_err_t failure = ESP_OK;
  for (int gen = 0; gen <= cycles && failedGen < 0; gen++) {
    fill(blob, skSize, gen);
    esp_err_t err = nvs_set_blob(h, "pk", blob, pkSize);
    if (err != ESP_OK) failedKey = "pk";
    if (err == ESP_OK) {
      err = nvs_set_blob(h, "sk", blob, skSize);
      if (err != ESP_OK) failedKey = "sk";
    }
    if (err == ESP_OK) err = nvs_commit(h);
    if (err != ESP_OK) {
      failure = err;
      failedGen = gen;
    } else {
      ok++;
    }
  }

  out("NVS %-10s %u+%u B: writes ok %d/%d", label, (unsigned)pkSize, (unsigned)skSize, ok, cycles + 1);
  if (failedGen >= 0) {
    char pkText[48], skText[48];
    describe(h, "pk", pkSize, pkText, sizeof(pkText));
    describe(h, "sk", skSize, skText, sizeof(skText));
    out(" | write %d failed on \"%s\": %s; stored pk: %s; stored sk: %s", failedGen,
        failedKey, esp_err_to_name(failure), pkText, skText);
    nvs_close(h);
    nvsReinit();
    if (nvs_open(NS, NVS_READWRITE, &h) == ESP_OK) {
      describe(h, "pk", pkSize, pkText, sizeof(pkText));
      describe(h, "sk", skSize, skText, sizeof(skText));
      out("; after NVS re-init: pk: %s; sk: %s", pkText, skText);
    }
  }
  out("\n");
  nvs_close(h);
}

/* Time and heap of storing and loading a key, for both record types. */
template <typename K, typename Store> static void nvsKeyCost(const char *name) {
  static const char *NAMESPACE = "bench_key";
  uint32_t t;
  size_t peak = 0;
  Store::eraseKeypair(NAMESPACE);

#if defined(MLDSA_ESP32_ALLOC_STATS)
#define PEAK_RESET() mldsa_esp32_alloc_reset_peak()
#define PEAK_READ() (peak = mldsa_esp32_alloc_peak())
#else
#define PEAK_RESET()
#define PEAK_READ()
#endif
  t = micros();
  int stored = Store::generateAndSave(NAMESPACE, pk, sk);
  uint32_t saveSeed = micros() - t;
  PEAK_RESET();
  t = micros();
  bool loaded = Store::loadKeypair(NAMESPACE, pk, sk);
  uint32_t loadSeed = micros() - t;
  PEAK_READ();
  out("NVSKEY %s seed record:       generateAndSave %.1f ms, loadKeypair %.1f ms, load lib_heap_peak=%u %s\n",
      name, saveSeed / 1000.0, loadSeed / 1000.0, (unsigned)peak,
      stored == 0 && loaded ? "ok" : "FAILED");

  K::generateKeypair(pk, sk);
  t = micros();
  bool saved = Store::saveKeypair(NAMESPACE, pk, sk);
  uint32_t saveSk = micros() - t;
  PEAK_RESET();
  t = micros();
  loaded = Store::loadKeypair(NAMESPACE, pk, sk);
  uint32_t loadSk = micros() - t;
  PEAK_READ();
  out("NVSKEY %s secret-key record: saveKeypair %.1f ms, loadKeypair %.1f ms, load lib_heap_peak=%u %s\n",
      name, saveSk / 1000.0, loadSk / 1000.0, (unsigned)peak, saved && loaded ? "ok" : "FAILED");
  Store::eraseKeypair(NAMESPACE);
#undef PEAK_RESET
#undef PEAK_READ
}

static void nvsSizing() {
  const size_t header = 16; /* allowance for a record header */
  const int cycles = 12;
  eraseTestKeys();
  nvs_stats_t s = stats();
  out("NVS partition: total=%u entries, used by other data=%u, namespaces=%u\n",
      (unsigned)s.total_entries, (unsigned)s.used_entries, (unsigned)s.namespace_count);
  nvsBlobTest("seed", 32 + header, cycles);
  nvsBlobTest("44 sk", 2560 + header, cycles);
  nvsBlobTest("44 sk+pk", 2560 + 1312 + header, cycles);
  nvsBlobTest("65 sk", 4032 + header, cycles);
  nvsBlobTest("65 sk+pk", 4032 + 1952 + header, cycles);
  nvsBlobTest("87 sk", 4896 + header, cycles);
  nvsBlobTest("87 sk+pk", 4896 + 2592 + header, cycles);
  nvsPairTest("44 pk,sk", 1312, 2560, cycles);
  nvsPairTest("65 pk,sk", 1952, 4032, cycles);
  nvsPairTest("87 pk,sk", 2592, 4896, cycles);
  eraseTestKeys();
  s = stats();
  out("NVS after cleanup: used=%u namespaces=%u\n", (unsigned)s.used_entries,
      (unsigned)s.namespace_count);
}

#endif /* BENCH_NVS */

/* ---- main ---------------------------------------------------------------- */

static void benchAll() {
  out("=== mldsa-esp32 device measurements ===\n");
#ifdef BENCH_WIFI
  out("wifi=softAP\n");
#endif
  out("chip=%s rev=%u cores=%u cpu=%u MHz flash=%u MB psram=%u KB\n",
      ESP.getChipModel(), (unsigned)ESP.getChipRevision(), (unsigned)ESP.getChipCores(),
      (unsigned)ESP.getCpuFreqMHz(), (unsigned)(ESP.getFlashChipSize() >> 20),
      (unsigned)(ESP.getPsramSize() >> 10));
  out("arduino-esp32=%d.%d.%d idf=%s free_heap=%u largest_block=%u\n",
      ESP_ARDUINO_VERSION_MAJOR, ESP_ARDUINO_VERSION_MINOR, ESP_ARDUINO_VERSION_PATCH,
      esp_get_idf_version(), (unsigned)ESP.getFreeHeap(), (unsigned)ESP.getMaxAllocHeap());

  for (const Ops &v : VARIANTS) {
    run(&v, KEYGEN, 5);
    run(&v, SIGN, 40);
    run(&v, VERIFY, 10);
  }
  out("min_free_heap=%u\n", (unsigned)ESP.getMinFreeHeap());
#ifdef BENCH_NVS
  nvsKeyCost<MLDSA44, MLDSA44_NVS>("ML-DSA-44");
  nvsKeyCost<MLDSA65, MLDSA65_NVS>("ML-DSA-65");
  nvsKeyCost<MLDSA87, MLDSA87_NVS>("ML-DSA-87");
  out("loop task stack never used: %u bytes\n", (unsigned)uxTaskGetStackHighWaterMark(NULL));
  nvsSizing();
#endif
  out("=== end ===\n");
  finished = true;
}

void setup() {
  Serial.begin(115200);
  delay(3000);
  mainTask = xTaskGetCurrentTaskHandle();
#ifdef BENCH_WIFI
  /* Radio on, as in a connected product: an open access point nobody uses. */
  WiFi.mode(WIFI_AP);
  WiFi.softAP("mldsa-bench");
  delay(500);
#endif
  benchAll();
}

void loop() {
  delay(5000);
  if (finished) {
    Serial.println();
    Serial.print(report);
  }
}
