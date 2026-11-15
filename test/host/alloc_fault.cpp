/*
 * Out-of-memory behaviour of the default build, whose working memory comes
 * from the heap.
 *
 * For each parameter set and operation, every allocation is made to fail in
 * turn. The operation must then report MLD_ERR_OUT_OF_MEMORY, give back
 * every block it had taken, and work again on the next call.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <cstdio>
#include <cstring>
#include <functional>
#include <vector>

#include "MLDSA44.h"
#include "MLDSA65.h"
#include "MLDSA87.h"
#include "alloc_host.h"

static int failures = 0;

static void check(bool ok, const char *level, const char *op, const char *what) {
  if (!ok) {
    std::printf("  [FAIL] %s %s: %s\n", level, op, what);
    failures++;
  }
}

static void exercise(const char *level, const char *op, const std::function<int()> &run) {
  alloc_host_reset(0);
  int ret = run();
  int allocations = alloc_host_calls();
  size_t peak = alloc_host_peak();
  check(ret == 0, level, op, "succeeds with memory available");
  check(allocations > 0, level, op, "allocates from the heap");
  check(alloc_host_outstanding() == 0, level, op, "frees everything after success");

  for (int failing = 1; failing <= allocations; failing++) {
    alloc_host_reset(failing);
    ret = run();
    check(ret == MLD_ERR_OUT_OF_MEMORY, level, op, "reports out of memory");
    check(alloc_host_outstanding() == 0, level, op, "frees everything after a failed allocation");
    alloc_host_reset(0);
    check(run() == 0, level, op, "works again on the next call");
  }
  std::printf("  %s %-10s %2d allocations, peak %5zu bytes: every failure reported and recovered\n",
              level, op, allocations, peak);
}

/* Deterministic signing, so that every run makes the same allocations. */
#define SIGN_DETERMINISTIC(L)                                                  \
  static int signDeterministic##L(uint8_t *sig, const uint8_t *msg,            \
                                  size_t msglen, const uint8_t *sk) {          \
    static const uint8_t zeroRnd[MLDSA_RNDBYTES] = {0};                        \
    static const uint8_t pre[2] = {0, 0}; /* pure ML-DSA, empty context */     \
    return PQCP_MLDSA_NATIVE_MLDSA##L##_signature_internal(                    \
        sig, msg, msglen, pre, sizeof pre, zeroRnd, sk, 0);                    \
  }
SIGN_DETERMINISTIC(44)
SIGN_DETERMINISTIC(65)
SIGN_DETERMINISTIC(87)

template <typename K>
static void level(const char *name,
                  int (*signDeterministic)(uint8_t *, const uint8_t *, size_t, const uint8_t *)) {
  static const uint8_t msg[] = "out-of-memory test";
  std::vector<uint8_t> seed(K::SEED_SIZE, 0x42);
  std::vector<uint8_t> pk(K::PUBLIC_KEY_SIZE), sk(K::SECRET_KEY_SIZE);
  std::vector<uint8_t> sig(K::SIGNATURE_SIZE), pk2(K::PUBLIC_KEY_SIZE);

  exercise(name, "keygen", [&] { return K::generateKeypairFromSeed(pk.data(), sk.data(), seed.data()); });
  exercise(name, "sign", [&] { return signDeterministic(sig.data(), msg, sizeof msg, sk.data()); });
  exercise(name, "verify", [&] { return K::verify(sig.data(), sig.size(), msg, sizeof msg, pk.data()); });
  exercise(name, "pk_from_sk", [&] { return K::publicKeyFromSecretKey(pk2.data(), sk.data()); });
  check(pk == pk2, name, "pk_from_sk", "reproduces the public key");
}

int main() {
  level<MLDSA44>("ML-DSA-44", signDeterministic44);
  level<MLDSA65>("ML-DSA-65", signDeterministic65);
  level<MLDSA87>("ML-DSA-87", signDeterministic87);
  std::printf("%s\n", failures == 0 ? "ALL PASSED" : "FAILED");
  return failures == 0 ? 0 : 1;
}
