/*
 * MLDSA_NVS.h - persistent key storage in NVS, shared by all levels
 *
 * mldsa::Nvs<L> stores one ML-DSA identity per NVS namespace. MLDSA44_NVS.h,
 * MLDSA65_NVS.h and MLDSA87_NVS.h name the three parameter sets; include
 * those in a sketch.
 *
 * What is stored is a single small record, described in docs/nvs-format.md:
 * the 32-byte seed for keys generated here, or the secret key for keys saved
 * with saveKeypair(). The public key is never stored; it is derived when the
 * key is loaded. A single record is what makes a replacement all-or-nothing:
 * after an interrupted or failed save, loading gives the previous identity
 * or the new one, never a mix.
 *
 * NVS is not encrypted unless you enable NVS encryption, and erasing a key
 * removes its entry without overwriting the flash that held it. See the
 * README.
 *
 * Requires: ESP32 Arduino core with the Preferences library.
 * Not synchronized: do not use the same namespace from two tasks at once.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLDSA_NVS_H
#define MLDSA_NVS_H

#include <Preferences.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "MLDSA.h"

namespace mldsa {

/* Why an NVS operation failed. */
enum class NvsError : uint8_t {
  OK = 0,
  CANNOT_OPEN,         /* the namespace could not be opened */
  NOT_FOUND,           /* no key is stored in the namespace */
  INVALID_RECORD,      /* the stored data is damaged or of an unknown format */
  WRONG_PARAMETER_SET, /* the stored key belongs to another ML-DSA level */
  INVALID_KEY,         /* the key is malformed, or pk and sk do not match */
  NO_SPACE,            /* not enough free NVS entries; nothing was written */
  WRITE_FAILED,        /* NVS refused the write, or read back something else */
  ERASE_FAILED,        /* an entry could not be removed */
  OUT_OF_MEMORY        /* not enough heap for the operation */
};

inline const char *nvsErrorText(NvsError error) {
  switch (error) {
    case NvsError::OK: return "ok";
    case NvsError::CANNOT_OPEN: return "cannot open the NVS namespace";
    case NvsError::NOT_FOUND: return "no key stored";
    case NvsError::INVALID_RECORD: return "stored record is damaged or unknown";
    case NvsError::WRONG_PARAMETER_SET: return "stored key is for another ML-DSA level";
    case NvsError::INVALID_KEY: return "key is malformed or pk and sk do not match";
    case NvsError::NO_SPACE: return "not enough free NVS entries";
    case NvsError::WRITE_FAILED: return "NVS write failed";
    case NvsError::ERASE_FAILED: return "NVS erase failed";
    case NvsError::OUT_OF_MEMORY: return "out of memory";
  }
  return "unknown";
}

namespace nvs_detail {

/* Record layout; see docs/nvs-format.md. */
static const char RECORD_KEY[] = "mldsa_key";
static const char LEGACY_PK_KEY[] = "pk"; /* layout of version 0.2.0 */
static const char LEGACY_SK_KEY[] = "sk";
static const uint8_t MAGIC[4] = {'M', 'L', 'D', 'K'};
static const uint8_t FORMAT_VERSION = 1;
static const uint8_t TYPE_SEED = 1;
static const uint8_t TYPE_SECRET_KEY = 2;
static const size_t HEADER_BYTES = 10;
static const size_t CRC_BYTES = 4;

/* NVS keeps one page of 126 entries free for itself. */
static const size_t NVS_RESERVED_ENTRIES = 126;

/* Upper bound of the 32-byte entries a blob of this size takes: its data,
 * one header per chunk (a chunk cannot cross a 4 KB page) and one index. */
inline size_t entriesFor(size_t bytes) {
  return (bytes + 31) / 32 + (bytes / 4000 + 2) + 1;
}

/* CRC-32 (IEEE 802.3), bit by bit: records are small and rarely written. */
inline uint32_t crc32(const uint8_t *data, size_t len) {
  uint32_t crc = 0xFFFFFFFFu;
  for (size_t i = 0; i < len; i++) {
    crc ^= data[i];
    for (int bit = 0; bit < 8; bit++) {
      crc = (crc >> 1) ^ (0xEDB88320u & (0u - (crc & 1u)));
    }
  }
  return ~crc;
}

/* A heap buffer that is wiped before it is released. */
class SecretBuffer {
 public:
  explicit SecretBuffer(size_t size)
      : data_(static_cast<uint8_t *>(malloc(size))), size_(size) {}
  ~SecretBuffer() {
    if (data_ != nullptr) {
      secureZero(data_, size_);
      free(data_);
    }
  }
  uint8_t *data() { return data_; }
  size_t size() const { return size_; }
  bool ok() const { return data_ != nullptr; }

 private:
  SecretBuffer(const SecretBuffer &);
  SecretBuffer &operator=(const SecretBuffer &);
  uint8_t *data_;
  size_t size_;
};

} /* namespace nvs_detail */

template <unsigned L>
class Nvs {
 public:
  typedef Variant<L> Key;

  /*
   * Store a keypair. Replaces whatever the namespace held.
   *
   * ns:  NVS namespace (max 15 chars, e.g. "mldsa")
   * pk:  public key (PUBLIC_KEY_SIZE bytes)
   * sk:  secret key (SECRET_KEY_SIZE bytes)
   *
   * pk must be the public key of sk; a pair that does not match is refused.
   * Only the secret key is written. If the write cannot be done, the
   * previous key stays in place.
   *
   * Returns true on success.
   */
  static bool saveKeypair(const char *ns, const uint8_t *pk, const uint8_t *sk,
                          NvsError *error = nullptr) {
    return report(saveSecretKey(ns, pk, sk), error);
  }

  /*
   * Store a key as its 32-byte seed, as generateAndSave() does. Use it for
   * keys made with generateKeypairFromSeed(). The seed is as secret as the
   * secret key.
   *
   * Returns true on success.
   */
  static bool saveSeed(const char *ns, const uint8_t *seed,
                       NvsError *error = nullptr) {
    Preferences prefs;
    if (!prefs.begin(ns, false)) {
      return report(NvsError::CANNOT_OPEN, error);
    }
    NvsError result =
        writeRecord(prefs, nvs_detail::TYPE_SEED, seed, Key::SEED_SIZE);
    if (result == NvsError::OK) {
      removeLegacy(prefs);
    }
    prefs.end();
    return report(result, error);
  }

  /*
   * Load the keypair stored in a namespace.
   *
   * pk:  output buffer of PUBLIC_KEY_SIZE bytes
   * sk:  output buffer of SECRET_KEY_SIZE bytes
   *
   * The stored record is checked, and the public key is derived from the
   * stored secret, so the two always belong together. Keys stored by
   * version 0.2.0 are read too; see migrate().
   *
   * Returns true if a valid keypair was loaded. Otherwise both buffers are
   * wiped.
   */
  static bool loadKeypair(const char *ns, uint8_t *pk, uint8_t *sk,
                          NvsError *error = nullptr) {
    NvsError result;
    Preferences prefs;
    /* A namespace that was never written cannot be opened read-only. */
    if (!prefs.begin(ns, true)) {
      result = NvsError::NOT_FOUND;
    } else {
      result = load(prefs, pk, sk);
      prefs.end();
    }
    if (result != NvsError::OK) {
      secureZero(pk, Key::PUBLIC_KEY_SIZE);
      secureZero(sk, Key::SECRET_KEY_SIZE);
    }
    return report(result, error);
  }

  /*
   * Load only the public key.
   *
   * pk:  output buffer of PUBLIC_KEY_SIZE bytes
   *
   * Returns true on success. Otherwise pk is wiped.
   */
  static bool loadPublicKey(const char *ns, uint8_t *pk,
                            NvsError *error = nullptr) {
    nvs_detail::SecretBuffer sk(Key::SECRET_KEY_SIZE);
    if (!sk.ok()) {
      secureZero(pk, Key::PUBLIC_KEY_SIZE);
      return report(NvsError::OUT_OF_MEMORY, error);
    }
    return loadKeypair(ns, pk, sk.data(), error);
  }

  /*
   * Check if a namespace holds a key. It does not validate it; loadKeypair()
   * does.
   */
  static bool hasKeypair(const char *ns) {
    Preferences prefs;
    if (!prefs.begin(ns, true)) {
      return false;
    }
    bool has = prefs.isKey(nvs_detail::RECORD_KEY) ||
               (prefs.isKey(nvs_detail::LEGACY_PK_KEY) &&
                prefs.isKey(nvs_detail::LEGACY_SK_KEY));
    prefs.end();
    return has;
  }

  /*
   * Remove the key from a namespace, including one stored by version 0.2.0.
   *
   * This removes the NVS entries. It does not overwrite the flash that held
   * them: the data stays there until NVS reuses the page.
   *
   * Returns true if no key is left in the namespace, which includes the case
   * where there was none.
   */
  static bool eraseKeypair(const char *ns, NvsError *error = nullptr) {
    Preferences prefs;
    if (!prefs.begin(ns, false)) {
      return report(NvsError::CANNOT_OPEN, error);
    }
    /* Secrets first. */
    const char *keys[] = {nvs_detail::RECORD_KEY, nvs_detail::LEGACY_SK_KEY,
                          nvs_detail::LEGACY_PK_KEY};
    bool removed = true;
    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
      if (prefs.isKey(keys[i]) && !prefs.remove(keys[i])) {
        removed = false;
      }
    }
    bool left = prefs.isKey(nvs_detail::RECORD_KEY) ||
                prefs.isKey(nvs_detail::LEGACY_SK_KEY) ||
                prefs.isKey(nvs_detail::LEGACY_PK_KEY);
    prefs.end();
    return report(removed && !left ? NvsError::OK : NvsError::ERASE_FAILED,
                  error);
  }

  /*
   * Generate a new keypair and store it, as its seed, in one step.
   *
   * pk:  output buffer of PUBLIC_KEY_SIZE bytes
   * sk:  output buffer of SECRET_KEY_SIZE bytes
   *
   * Returns 0 on success, negative on keygen error (the buffers are then
   * wiped), 1 if the key was generated but could not be stored. In that last
   * case the buffers hold the new key and the namespace still holds the
   * previous one, if there was one.
   */
  static int generateAndSave(const char *ns, uint8_t *pk, uint8_t *sk,
                             NvsError *error = nullptr) {
    uint8_t seed[MLDSA_SEEDBYTES];
    report(NvsError::OK, error);
    if (mldsa_esp32_randombytes(seed, sizeof(seed)) != 0) {
      secureZero(pk, Key::PUBLIC_KEY_SIZE);
      secureZero(sk, Key::SECRET_KEY_SIZE);
      return MLD_ERR_RNG_FAIL;
    }
    int ret = Key::generateKeypairFromSeed(pk, sk, seed);
    bool stored = ret == 0 && saveSeed(ns, seed, error);
    secureZero(seed, sizeof(seed));
    if (ret != 0) {
      return ret;
    }
    return stored ? 0 : 1;
  }

  /*
   * Convert a key stored by version 0.2.0 (separate "pk" and "sk" entries)
   * to the current record. The old entries are removed only after the new
   * record has been written and read back.
   *
   * Returns true if the namespace now holds a current record, which includes
   * the case where it already did.
   */
  static bool migrate(const char *ns, NvsError *error = nullptr) {
    Preferences prefs;
    if (!prefs.begin(ns, false)) {
      return report(NvsError::CANNOT_OPEN, error);
    }
    NvsError result = migrateOpen(prefs);
    prefs.end();
    return report(result, error);
  }

 private:
  static bool report(NvsError result, NvsError *error) {
    if (error != nullptr) {
      *error = result;
    }
    return result == NvsError::OK;
  }

  static size_t recordSize(size_t payloadLen) {
    return nvs_detail::HEADER_BYTES + payloadLen + nvs_detail::CRC_BYTES;
  }

  /* Read and check the record. On success the payload (seed or secret key)
   * is in payload, which must hold SECRET_KEY_SIZE bytes. */
  static NvsError readRecord(Preferences &prefs, uint8_t *type,
                             uint8_t *payload) {
    if (!prefs.isKey(nvs_detail::RECORD_KEY)) {
      return NvsError::NOT_FOUND;
    }
    /* Any size a record of any level can have, to tell "damaged" from
     * "written for another level". */
    size_t len = prefs.getBytesLength(nvs_detail::RECORD_KEY);
    if (len < recordSize(0) || len > recordSize(MLDSA87_SECRETKEYBYTES)) {
      return NvsError::INVALID_RECORD;
    }
    nvs_detail::SecretBuffer record(len);
    if (!record.ok()) {
      return NvsError::OUT_OF_MEMORY;
    }
    if (prefs.getBytes(nvs_detail::RECORD_KEY, record.data(), len) != len) {
      return NvsError::INVALID_RECORD;
    }
    const uint8_t *r = record.data();
    size_t payloadLen = len - nvs_detail::HEADER_BYTES - nvs_detail::CRC_BYTES;
    uint32_t stored = static_cast<uint32_t>(r[len - 4]) |
                      static_cast<uint32_t>(r[len - 3]) << 8 |
                      static_cast<uint32_t>(r[len - 2]) << 16 |
                      static_cast<uint32_t>(r[len - 1]) << 24;
    if (memcmp(r, nvs_detail::MAGIC, 4) != 0 ||
        r[4] != nvs_detail::FORMAT_VERSION ||
        stored != nvs_detail::crc32(r, len - nvs_detail::CRC_BYTES) ||
        (static_cast<size_t>(r[8]) | static_cast<size_t>(r[9]) << 8) !=
            payloadLen) {
      return NvsError::INVALID_RECORD;
    }
    if (r[5] != L) {
      return NvsError::WRONG_PARAMETER_SET;
    }
    bool seed = r[6] == nvs_detail::TYPE_SEED && payloadLen == Key::SEED_SIZE;
    bool secretKey = r[6] == nvs_detail::TYPE_SECRET_KEY &&
                     payloadLen == Key::SECRET_KEY_SIZE;
    if (!seed && !secretKey) {
      return NvsError::INVALID_RECORD;
    }
    *type = r[6];
    memcpy(payload, r + nvs_detail::HEADER_BYTES, payloadLen);
    return NvsError::OK;
  }

  /* Write a record, after checking that it fits next to the one it
   * replaces, and read it back. */
  static NvsError writeRecord(Preferences &prefs, uint8_t type,
                              const uint8_t *payload, size_t payloadLen) {
    size_t len = recordSize(payloadLen);
    nvs_detail::SecretBuffer record(len), check(len);
    if (!record.ok() || !check.ok()) {
      return NvsError::OUT_OF_MEMORY;
    }
    uint8_t *r = record.data();
    memcpy(r, nvs_detail::MAGIC, 4);
    r[4] = nvs_detail::FORMAT_VERSION;
    r[5] = static_cast<uint8_t>(L);
    r[6] = type;
    r[7] = 0;
    r[8] = static_cast<uint8_t>(payloadLen & 0xFF);
    r[9] = static_cast<uint8_t>(payloadLen >> 8);
    memcpy(r + nvs_detail::HEADER_BYTES, payload, payloadLen);
    uint32_t crc = nvs_detail::crc32(r, len - nvs_detail::CRC_BYTES);
    r[len - 4] = static_cast<uint8_t>(crc);
    r[len - 3] = static_cast<uint8_t>(crc >> 8);
    r[len - 2] = static_cast<uint8_t>(crc >> 16);
    r[len - 1] = static_cast<uint8_t>(crc >> 24);

    /* NVS writes the new value before it erases the old one. A write that
     * does not fit fails half way, leaves the partition full until NVS is
     * initialised again and can damage other entries, so it is not tried. */
    if (prefs.freeEntries() <
        nvs_detail::entriesFor(len) + nvs_detail::NVS_RESERVED_ENTRIES) {
      return NvsError::NO_SPACE;
    }
    if (prefs.putBytes(nvs_detail::RECORD_KEY, r, len) != len) {
      return NvsError::WRITE_FAILED;
    }
    if (prefs.getBytes(nvs_detail::RECORD_KEY, check.data(), len) != len ||
        memcmp(check.data(), r, len) != 0) {
      return NvsError::WRITE_FAILED;
    }
    return NvsError::OK;
  }

  /* Turn a record payload into a keypair. payload may be sk itself. */
  static NvsError materialize(uint8_t type, const uint8_t *payload,
                              uint8_t *pk, uint8_t *sk) {
    int ret;
    if (type == nvs_detail::TYPE_SEED) {
      uint8_t seed[MLDSA_SEEDBYTES];
      memcpy(seed, payload, sizeof(seed));
      ret = Key::generateKeypairFromSeed(pk, sk, seed);
      secureZero(seed, sizeof(seed));
    } else {
      if (payload != sk) {
        memcpy(sk, payload, Key::SECRET_KEY_SIZE);
      }
      ret = Key::publicKeyFromSecretKey(pk, sk);
    }
    if (ret == MLD_ERR_OUT_OF_MEMORY) {
      return NvsError::OUT_OF_MEMORY;
    }
    return ret == 0 ? NvsError::OK : NvsError::INVALID_KEY;
  }

  /* The layout of version 0.2.0: "pk" and "sk" as separate entries. The
   * pair is accepted only if pk is the public key of sk. */
  static NvsError loadLegacy(Preferences &prefs, uint8_t *pk, uint8_t *sk) {
    if (!prefs.isKey(nvs_detail::LEGACY_PK_KEY) ||
        !prefs.isKey(nvs_detail::LEGACY_SK_KEY)) {
      return NvsError::NOT_FOUND;
    }
    nvs_detail::SecretBuffer storedPk(Key::PUBLIC_KEY_SIZE);
    if (!storedPk.ok()) {
      return NvsError::OUT_OF_MEMORY;
    }
    if (prefs.getBytesLength(nvs_detail::LEGACY_PK_KEY) != Key::PUBLIC_KEY_SIZE ||
        prefs.getBytesLength(nvs_detail::LEGACY_SK_KEY) != Key::SECRET_KEY_SIZE ||
        prefs.getBytes(nvs_detail::LEGACY_PK_KEY, storedPk.data(),
                       Key::PUBLIC_KEY_SIZE) != Key::PUBLIC_KEY_SIZE ||
        prefs.getBytes(nvs_detail::LEGACY_SK_KEY, sk, Key::SECRET_KEY_SIZE) !=
            Key::SECRET_KEY_SIZE) {
      return NvsError::INVALID_RECORD;
    }
    NvsError result = materialize(nvs_detail::TYPE_SECRET_KEY, sk, pk, sk);
    if (result == NvsError::OK &&
        memcmp(pk, storedPk.data(), Key::PUBLIC_KEY_SIZE) != 0) {
      return NvsError::INVALID_KEY;
    }
    return result;
  }

  /* The current record if there is a good one, else the 0.2.0 layout. */
  static NvsError load(Preferences &prefs, uint8_t *pk, uint8_t *sk) {
    uint8_t type = 0;
    NvsError record = readRecord(prefs, &type, sk);
    if (record == NvsError::OK) {
      return materialize(type, sk, pk, sk);
    }
    if (record == NvsError::WRONG_PARAMETER_SET ||
        record == NvsError::OUT_OF_MEMORY) {
      return record;
    }
    /* No record, or a damaged one: a migration that was interrupted leaves
     * the old entries in place. */
    NvsError legacy = loadLegacy(prefs, pk, sk);
    return legacy == NvsError::NOT_FOUND ? record : legacy;
  }

  static void removeLegacy(Preferences &prefs) {
    if (prefs.isKey(nvs_detail::LEGACY_SK_KEY)) {
      prefs.remove(nvs_detail::LEGACY_SK_KEY);
    }
    if (prefs.isKey(nvs_detail::LEGACY_PK_KEY)) {
      prefs.remove(nvs_detail::LEGACY_PK_KEY);
    }
  }

  static NvsError saveSecretKey(const char *ns, const uint8_t *pk,
                                const uint8_t *sk) {
    nvs_detail::SecretBuffer derived(Key::PUBLIC_KEY_SIZE);
    if (!derived.ok()) {
      return NvsError::OUT_OF_MEMORY;
    }
    int ret = Key::publicKeyFromSecretKey(derived.data(), sk);
    if (ret == MLD_ERR_OUT_OF_MEMORY) {
      return NvsError::OUT_OF_MEMORY;
    }
    if (ret != 0 || memcmp(derived.data(), pk, Key::PUBLIC_KEY_SIZE) != 0) {
      return NvsError::INVALID_KEY;
    }
    Preferences prefs;
    if (!prefs.begin(ns, false)) {
      return NvsError::CANNOT_OPEN;
    }
    NvsError result = writeRecord(prefs, nvs_detail::TYPE_SECRET_KEY, sk,
                                  Key::SECRET_KEY_SIZE);
    if (result == NvsError::OK) {
      removeLegacy(prefs);
    }
    prefs.end();
    return result;
  }

  static NvsError migrateOpen(Preferences &prefs) {
    nvs_detail::SecretBuffer pk(Key::PUBLIC_KEY_SIZE), sk(Key::SECRET_KEY_SIZE);
    if (!pk.ok() || !sk.ok()) {
      return NvsError::OUT_OF_MEMORY;
    }
    uint8_t type = 0;
    NvsError record = readRecord(prefs, &type, sk.data());
    if (record == NvsError::OK) {
      removeLegacy(prefs); /* left over from an interrupted migration */
      return NvsError::OK;
    }
    if (record == NvsError::WRONG_PARAMETER_SET ||
        record == NvsError::OUT_OF_MEMORY) {
      return record;
    }
    NvsError legacy = loadLegacy(prefs, pk.data(), sk.data());
    if (legacy != NvsError::OK) {
      return legacy == NvsError::NOT_FOUND ? record : legacy;
    }
    NvsError written = writeRecord(prefs, nvs_detail::TYPE_SECRET_KEY,
                                   sk.data(), Key::SECRET_KEY_SIZE);
    if (written == NvsError::OK) {
      removeLegacy(prefs);
    }
    return written;
  }
};

} /* namespace mldsa */

#endif /* MLDSA_NVS_H */
