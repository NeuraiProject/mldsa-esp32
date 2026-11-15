/*
 * In-memory stand-in for the ESP32 Arduino Preferences library, for host
 * tests of the NVS helpers. It mimics the return values of the real class,
 * models how many NVS entries the stored data takes, and can be told to
 * fail, to exercise error paths.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MOCK_PREFERENCES_H
#define MOCK_PREFERENCES_H

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <map>
#include <string>
#include <vector>

namespace mocknvs {

typedef std::map<std::string, std::vector<uint8_t> > Namespace;

struct State {
  std::map<std::string, Namespace> data;

  /* Size model: the default 20 KB partition has 630 entries, and NVS keeps
   * one page of 126 free. otherEntries stands for data of other users. */
  size_t totalEntries;
  size_t otherEntries;

  int putCalls;           /* putBytes calls seen so far */
  int failPutOnCall;      /* this putBytes call fails (1 = the next); 0 = never */
  bool failRemove;        /* remove() fails and leaves the entry in place */
  bool failBegin;         /* begin() fails */
  int operations;         /* writes and removals carried out so far */
  int dieAfterOperations; /* after this many, every write and removal fails,
                             as if power had been lost; -1 = never */
  int refusedForSpace;    /* writes refused because they did not fit */

  State() { reset(); }

  void reset() {
    data.clear();
    totalEntries = 630;
    otherEntries = 0;
    clearFaults();
  }

  void clearFaults() {
    putCalls = 0;
    failPutOnCall = 0;
    failRemove = false;
    failBegin = false;
    operations = 0;
    dieAfterOperations = -1;
    refusedForSpace = 0;
  }

  /* Entries a blob takes: data, one header per chunk, one index. */
  static size_t entriesFor(size_t len) { return (len + 31) / 32 + len / 4032 + 2; }

  size_t usedEntries() const {
    size_t used = otherEntries;
    for (std::map<std::string, Namespace>::const_iterator ns = data.begin(); ns != data.end(); ++ns) {
      used += 1; /* the namespace itself */
      for (Namespace::const_iterator kv = ns->second.begin(); kv != ns->second.end(); ++kv) {
        used += entriesFor(kv->second.size());
      }
    }
    return used;
  }

  size_t freeEntries() const {
    size_t used = usedEntries();
    return used >= totalEntries ? 0 : totalEntries - used;
  }

  bool dead() const { return dieAfterOperations >= 0 && operations >= dieAfterOperations; }
};

inline State &state() {
  static State s;
  return s;
}

} /* namespace mocknvs */

class Preferences {
 public:
  Preferences() : open_(false), readOnly_(false) {}

  bool begin(const char *name, bool readOnly = false) {
    mocknvs::State &s = mocknvs::state();
    if (s.failBegin) return false;
    /* The real class cannot open a namespace read-only before it exists. */
    if (readOnly && s.data.find(name) == s.data.end()) return false;
    name_ = name;
    readOnly_ = readOnly;
    open_ = true;
    if (!readOnly) s.data[name_];
    return true;
  }

  void end() { open_ = false; }

  size_t putBytes(const char *key, const void *value, size_t len) {
    mocknvs::State &s = mocknvs::state();
    if (!open_ || readOnly_ || value == NULL || len == 0) return 0;
    s.putCalls++;
    if (s.dead() || (s.failPutOnCall != 0 && s.putCalls == s.failPutOnCall)) return 0;
    /* NVS writes the new value while the old one is still there, and keeps
     * a page of 126 entries free. */
    if (s.freeEntries() < mocknvs::State::entriesFor(len) + 126) {
      s.refusedForSpace++;
      return 0;
    }
    const uint8_t *bytes = static_cast<const uint8_t *>(value);
    s.data[name_][key].assign(bytes, bytes + len);
    s.operations++;
    return len;
  }

  size_t getBytesLength(const char *key) {
    const std::vector<uint8_t> *v = find(key);
    return v ? v->size() : 0;
  }

  size_t getBytes(const char *key, void *buf, size_t maxLen) {
    const std::vector<uint8_t> *v = find(key);
    if (v == NULL || buf == NULL || v->size() > maxLen) return 0;
    memcpy(buf, v->data(), v->size());
    return v->size();
  }

  bool isKey(const char *key) { return find(key) != NULL; }

  bool remove(const char *key) {
    mocknvs::State &s = mocknvs::state();
    if (!open_ || readOnly_ || s.failRemove || s.dead()) return false;
    if (s.data[name_].erase(key) != 1) return false;
    s.operations++;
    return true;
  }

  size_t freeEntries() { return mocknvs::state().freeEntries(); }

 private:
  const std::vector<uint8_t> *find(const char *key) {
    mocknvs::State &s = mocknvs::state();
    if (!open_) return NULL;
    std::map<std::string, mocknvs::Namespace>::iterator ns = s.data.find(name_);
    if (ns == s.data.end()) return NULL;
    mocknvs::Namespace::iterator it = ns->second.find(key);
    return it == ns->second.end() ? NULL : &it->second;
  }

  bool open_;
  bool readOnly_;
  std::string name_;
};

#endif /* MOCK_PREFERENCES_H */
