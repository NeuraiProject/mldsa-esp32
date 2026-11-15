/*
 * On-device tests of the NVS key storage helpers; see platformio.ini.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <Arduino.h>
#include <Preferences.h>
#include <MLDSA44_NVS.h>
#include <MLDSA65_NVS.h>
#include <MLDSA87_NVS.h>

using mldsa::NvsError;

static uint8_t pk[MLDSA87::PUBLIC_KEY_SIZE], sk[MLDSA87::SECRET_KEY_SIZE];
static uint8_t pk2[MLDSA87::PUBLIC_KEY_SIZE], sk2[MLDSA87::SECRET_KEY_SIZE];
static uint8_t sig[MLDSA87::SIGNATURE_SIZE];
static const uint8_t MSG[] = "nvs device test";

template <typename K> static bool signsAndVerifies(const uint8_t *p, const uint8_t *s) {
  size_t siglen = 0;
  return K::sign(sig, &siglen, MSG, sizeof(MSG), s) == 0 &&
         K::verify(sig, siglen, MSG, sizeof(MSG), p) == 0;
}

#ifndef NVS_POWERCUT
/* ======================= functional test ================================= */

static char report[3000];
static size_t reportLen = 0;
static int failures = 0;
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

static void check(bool ok, const char *what) {
  addLine("[%s] %s\n", ok ? "PASS" : "FAIL", what);
  if (!ok) failures++;
}

template <typename K, typename Store> static void roundTrip(const char *ns, const char *level) {
  char what[96];
  NvsError error = NvsError::OK;
  Store::eraseKeypair(ns);
  int ret = Store::generateAndSave(ns, pk, sk, &error);
  bool loaded = Store::loadKeypair(ns, pk2, sk2, &error);
  snprintf(what, sizeof what, "%s: generateAndSave, then loadKeypair gives the same key", level);
  check(ret == 0 && loaded && memcmp(pk, pk2, K::PUBLIC_KEY_SIZE) == 0 &&
            memcmp(sk, sk2, K::SECRET_KEY_SIZE) == 0 && signsAndVerifies<K>(pk2, sk2),
        what);
  memset(pk2, 0, sizeof pk2);
  snprintf(what, sizeof what, "%s: loadPublicKey", level);
  check(Store::loadPublicKey(ns, pk2) && memcmp(pk, pk2, K::PUBLIC_KEY_SIZE) == 0, what);
}

static size_t freeEntries() {
  Preferences prefs;
  prefs.begin("t_stats", false);
  size_t n = prefs.freeEntries();
  prefs.end();
  return n;
}

/* The NVS partition is small: every step removes what it stored. */
static void functionalTask(void *) {
  NvsError error = NvsError::OK;
  Preferences prefs;
  char what[160];
  MLDSA44_NVS::eraseKeypair("t44");
  MLDSA65_NVS::eraseKeypair("t65");
  MLDSA87_NVS::eraseKeypair("t87");
  MLDSA44_NVS::eraseKeypair("tleg");
  /* Left behind by the power-cut test, if it ran on this board. */
  MLDSA44_NVS::eraseKeypair("pc44");
  MLDSA87_NVS::eraseKeypair("pc87");
  addLine("NVS free entries at start: %u\n", (unsigned)freeEntries());

  /* The largest step keeps two ML-DSA-87 secret-key records (158 entries
   * each) next to the page NVS reserves (126). */
  const size_t needed = 126 + 2 * 158 + 20;
  if (freeEntries() < needed) {
    addLine("[FAIL] this test needs %u free NVS entries. Other data in the nvs partition leaves too "
            "few; erase the flash (pio run -t erase) and run it again.\n", (unsigned)needed);
    addLine("NVS DEVICE TESTS FAILED\n");
    finished = true;
    vTaskDelete(NULL);
    return;
  }

  /* 1. seed records, every level */
  roundTrip<MLDSA44, MLDSA44_NVS>("t44", "ML-DSA-44");
  roundTrip<MLDSA65, MLDSA65_NVS>("t65", "ML-DSA-65");
  roundTrip<MLDSA87, MLDSA87_NVS>("t87", "ML-DSA-87");

  /* 2. a record of another level */
  check(!MLDSA65_NVS::loadKeypair("t44", pk2, sk2, &error) && error == NvsError::WRONG_PARAMETER_SET,
        "an ML-DSA-44 record is not loaded as ML-DSA-65");
  MLDSA44_NVS::eraseKeypair("t44");
  MLDSA65_NVS::eraseKeypair("t65");

  /* 3. secret-key records, the largest one, replaced several times */
  bool ok = true;
  for (int i = 0; i < 5 && ok; i++) {
    ok = MLDSA87::generateKeypair(pk, sk) == 0 && MLDSA87_NVS::saveKeypair("t87", pk, sk, &error) &&
         MLDSA87_NVS::loadKeypair("t87", pk2, sk2, &error) && memcmp(sk, sk2, MLDSA87::SECRET_KEY_SIZE) == 0 &&
         memcmp(pk, pk2, MLDSA87::PUBLIC_KEY_SIZE) == 0;
  }
  snprintf(what, sizeof what, "ML-DSA-87: saveKeypair replaced five times, each one loads back (%s)",
           mldsa::nvsErrorText(error));
  check(ok, what);
  MLDSA87_NVS::eraseKeypair("t87");

  /* 4. a key stored by version 0.2.0 */
  MLDSA44::generateKeypair(pk, sk);
  prefs.begin("tleg", false);
  prefs.putBytes("pk", pk, MLDSA44::PUBLIC_KEY_SIZE);
  prefs.putBytes("sk", sk, MLDSA44::SECRET_KEY_SIZE);
  prefs.end();
  check(MLDSA44_NVS::hasKeypair("tleg") && MLDSA44_NVS::loadKeypair("tleg", pk2, sk2) &&
            memcmp(sk, sk2, MLDSA44::SECRET_KEY_SIZE) == 0 && memcmp(pk, pk2, MLDSA44::PUBLIC_KEY_SIZE) == 0,
        "a key stored by 0.2.0 loads");
  bool migrated = MLDSA44_NVS::migrate("tleg", &error);
  prefs.begin("tleg", true);
  bool layout = prefs.isKey("mldsa_key") && !prefs.isKey("pk") && !prefs.isKey("sk");
  prefs.end();
  snprintf(what, sizeof what, "migrate converts it to one record, which loads (%s)", mldsa::nvsErrorText(error));
  check(migrated && layout && MLDSA44_NVS::loadKeypair("tleg", pk2, sk2) &&
            memcmp(sk, sk2, MLDSA44::SECRET_KEY_SIZE) == 0,
        what);
  MLDSA44_NVS::eraseKeypair("tleg");

  /* 5. the defect of 0.2.0: public key of one identity, secret key of another */
  MLDSA44::generateKeypair(pk2, sk2);
  prefs.begin("tleg", false);
  prefs.putBytes("pk", pk2, MLDSA44::PUBLIC_KEY_SIZE);
  prefs.putBytes("sk", sk, MLDSA44::SECRET_KEY_SIZE);
  prefs.end();
  check(!MLDSA44_NVS::loadKeypair("tleg", pk2, sk2, &error) && error == NvsError::INVALID_KEY,
        "a mixed 0.2.0 pair is rejected");
  MLDSA44_NVS::eraseKeypair("tleg");

  /* 6. not enough room to replace a record: the save is refused and the
   *    stored identity is untouched */
  MLDSA87::generateKeypair(pk, sk);
  bool stored = MLDSA87_NVS::saveKeypair("t87", pk, sk, &error);
  NvsError storeError = error;
  static uint8_t filler[1000];
  memset(filler, 0x5A, sizeof filler);
  prefs.begin("t_fill", false);
  int fillers = 0;
  char key[8];
  /* leave less room than a second ML-DSA-87 record needs, but enough for a seed */
  while (prefs.freeEntries() > 126 + 60 && fillers < 40) {
    snprintf(key, sizeof key, "f%d", fillers);
    if (prefs.putBytes(key, filler, sizeof filler) != sizeof filler) break;
    fillers++;
  }
  size_t freeWhenFull = prefs.freeEntries();
  prefs.end();
  MLDSA87::generateKeypair(pk2, sk2);
  bool refused = !MLDSA87_NVS::saveKeypair("t87", pk2, sk2, &error) && error == NvsError::NO_SPACE;
  NvsError refusal = error;
  bool intact = MLDSA87_NVS::loadKeypair("t87", pk2, sk2, &error) && memcmp(sk, sk2, MLDSA87::SECRET_KEY_SIZE) == 0 &&
                memcmp(pk, pk2, MLDSA87::PUBLIC_KEY_SIZE) == 0;
  addLine("NVS free entries with %d fillers: %u\n", fillers, (unsigned)freeWhenFull);
  snprintf(what, sizeof what, "the first ML-DSA-87 secret-key record is stored (%s)", mldsa::nvsErrorText(storeError));
  check(stored, what);
  snprintf(what, sizeof what, "with NVS nearly full, replacing it is refused (%s)", mldsa::nvsErrorText(refusal));
  check(refused, what);
  check(intact, "the stored identity is intact after the refusal");
  check(MLDSA87_NVS::generateAndSave("t87", pk, sk, &error) == 0 && MLDSA87_NVS::loadKeypair("t87", pk2, sk2) &&
            memcmp(sk, sk2, MLDSA87::SECRET_KEY_SIZE) == 0,
        "a seed record still fits and replaces it");

  /* clean up */
  prefs.begin("t_fill", false);
  for (int i = 0; i < fillers; i++) {
    snprintf(key, sizeof key, "f%d", i);
    prefs.remove(key);
  }
  prefs.end();
  check(MLDSA87_NVS::eraseKeypair("t87") && !MLDSA87_NVS::hasKeypair("t87"),
        "eraseKeypair removes the key");
  addLine("NVS free entries at end: %u\n", (unsigned)freeEntries());

  addLine("%s\n", failures == 0 ? "NVS DEVICE TESTS PASSED" : "NVS DEVICE TESTS FAILED");
  finished = true;
  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  if (xTaskCreate(functionalTask, "nvs", 16 * 1024, NULL, 1, NULL) != pdPASS) {
    addLine("[FAIL] could not create the test task\n");
    finished = true;
  }
}

void loop() {
  if (finished) {
    Serial.println("--- mldsa-esp32 nvs_device ---");
    Serial.print(report);
    Serial.println("--- end ---");
  }
  delay(3000);
}

#else
/* ======================= power-cut test ================================== */

/* What this boot found in NVS, before saving anything. */
static const char *status44 = "?", *status87 = "?";
static volatile uint32_t saves = 0;

template <typename K, typename Store> static const char *inspect(const char *ns) {
  NvsError error = NvsError::OK;
  if (Store::loadKeypair(ns, pk, sk, &error)) {
    return signsAndVerifies<K>(pk, sk) ? "VALID" : "BROKEN";
  }
  return error == NvsError::NOT_FOUND ? "NONE" : "LOST";
}

/* Replace both identities for as long as the board stays up. */
static void saveTask(void *) {
  for (;;) {
    MLDSA44_NVS::generateAndSave("pc44", pk, sk); /* seed record */
    saves++;
    if (MLDSA87::generateKeypair(pk, sk) == 0) {
      MLDSA87_NVS::saveKeypair("pc87", pk, sk); /* secret-key record, 157 entries */
      saves++;
    }
    delay(1);
  }
}

void setup() {
  Serial.begin(115200);
  status44 = inspect<MLDSA44, MLDSA44_NVS>("pc44");
  status87 = inspect<MLDSA87, MLDSA87_NVS>("pc87");
  xTaskCreate(saveTask, "save", 16 * 1024, NULL, 1, NULL);
}

void loop() {
  /* Repeated, so that the host reads it whenever it gets the port open. */
  Serial.printf("PC up=%lu ms seed44=%s sk87=%s saves=%u\n", millis(), status44, status87,
                (unsigned)saves);
  delay(100);
}
#endif
