/*
 * Link check: a program that uses only the variants selected with
 * -DUSE_44, -DUSE_65 and -DUSE_87 must link against the whole library.
 * It is linked, not run.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <cstddef>
#include <cstdint>

#ifdef USE_44
#include "MLDSA44.h"
#endif
#ifdef USE_65
#include "MLDSA65.h"
#endif
#ifdef USE_87
#include "MLDSA87.h"
#endif

static uint8_t pk[2592], sk[4896], sig[4627];

template <typename Variant> static int use() {
  size_t siglen = 0;
  int ret = Variant::generateKeypair(pk, sk);
  ret |= Variant::sign(sig, &siglen, pk, 16, sk);
  ret |= Variant::verify(sig, siglen, pk, 16, pk);
  return ret;
}

int main() {
  int ret = 0;
#ifdef USE_44
  ret |= use<MLDSA44>();
#endif
#ifdef USE_65
  ret |= use<MLDSA65>();
#endif
#ifdef USE_87
  ret |= use<MLDSA87>();
#endif
  return ret;
}
