/*
 * MLDSA.h - Arduino-friendly C++ wrapper for ML-DSA, shared by all levels
 *
 * mldsa::Variant<L> implements the operations once. MLDSA44.h, MLDSA65.h and
 * MLDSA87.h name the three parameter sets; include those in a sketch.
 *
 * Copyright (c) Asimov / NeuraiProject
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLDSA_WRAPPER_H
#define MLDSA_WRAPPER_H

#include <stddef.h>
#include <stdint.h>

#include "mldsa_esp32.h"
#include "mldsa_native_all.h"

namespace mldsa {

/*
 * A random source: fills a buffer with random bytes and returns 0, or
 * returns non-zero to make the operation fail with MLD_ERR_RNG_FAIL.
 * See mldsa_esp32.h.
 */
typedef mldsa_esp32_rng_t RandomSource;

/*
 * Use source for every later key generation and signature, for all
 * parameter sets. nullptr restores the default, esp_fill_random().
 *
 * Call it before other tasks use the library.
 */
inline void setRandomSource(RandomSource source, void *context = nullptr) {
  mldsa_esp32_set_rng(source, context);
}

/*
 * Overwrite len bytes at ptr with zeros, in a way the compiler does not
 * remove. Use it to wipe secret keys and seeds; a memset() of a buffer that
 * is not read again can be optimized away.
 */
inline void secureZero(void *ptr, size_t len) {
  mldsa_esp32_secure_zero(ptr, len);
}

/* Binding<L>: the sizes and C functions of parameter set L, spelled out for
 * each one rather than computed, so that a missing level fails to compile. */
template <unsigned L>
struct Binding;

#define MLDSA_BINDING(L)                                                       \
  template <>                                                                  \
  struct Binding<L> {                                                          \
    enum : size_t {                                                            \
      PUBLIC_KEY_BYTES = MLDSA##L##_PUBLICKEYBYTES,                            \
      SECRET_KEY_BYTES = MLDSA##L##_SECRETKEYBYTES,                            \
      SIGNATURE_BYTES = MLDSA##L##_BYTES                                       \
    };                                                                         \
    static int keypair(uint8_t *pk, uint8_t *sk) {                             \
      return PQCP_MLDSA_NATIVE_MLDSA##L##_keypair(pk, sk);                     \
    }                                                                          \
    static int keypairFromSeed(uint8_t *pk, uint8_t *sk,                       \
                               const uint8_t *seed) {                          \
      return PQCP_MLDSA_NATIVE_MLDSA##L##_keypair_internal(pk, sk, seed);      \
    }                                                                          \
    static int signature(uint8_t *sig, const uint8_t *msg, size_t msglen,      \
                         const uint8_t *ctx, size_t ctxlen,                    \
                         const uint8_t *sk) {                                  \
      return PQCP_MLDSA_NATIVE_MLDSA##L##_signature(sig, msg, msglen, ctx,     \
                                                    ctxlen, sk);               \
    }                                                                          \
    static int verify(const uint8_t *sig, const uint8_t *msg, size_t msglen,   \
                      const uint8_t *ctx, size_t ctxlen, const uint8_t *pk) {  \
      return PQCP_MLDSA_NATIVE_MLDSA##L##_verify(sig, msg, msglen, ctx,        \
                                                 ctxlen, pk);                  \
    }                                                                          \
    static int publicKeyFromSecretKey(uint8_t *pk, const uint8_t *sk) {        \
      return PQCP_MLDSA_NATIVE_MLDSA##L##_pk_from_sk(pk, sk);                  \
    }                                                                          \
  };

MLDSA_BINDING(44)
MLDSA_BINDING(65)
MLDSA_BINDING(87)
#undef MLDSA_BINDING

template <unsigned L>
class Variant {
 public:
  static constexpr unsigned PARAMETER_SET = L;
  static constexpr size_t PUBLIC_KEY_SIZE = Binding<L>::PUBLIC_KEY_BYTES;
  static constexpr size_t SECRET_KEY_SIZE = Binding<L>::SECRET_KEY_BYTES;
  static constexpr size_t SIGNATURE_SIZE = Binding<L>::SIGNATURE_BYTES;
  static constexpr size_t SEED_SIZE = MLDSA_SEEDBYTES;

  /*
   * Generate a new keypair.
   *
   * pk: output buffer of PUBLIC_KEY_SIZE bytes
   * sk: output buffer of SECRET_KEY_SIZE bytes
   *
   * Returns 0 on success, negative on error. On error both buffers are
   * wiped.
   */
  static int generateKeypair(uint8_t *pk, uint8_t *sk) {
    return wipeKeypairOnError(Binding<L>::keypair(pk, sk), pk, sk);
  }

  /*
   * Generate a keypair from a seed. The same seed always gives the same
   * keypair, so the seed is as secret as the secret key.
   *
   * pk:   output buffer of PUBLIC_KEY_SIZE bytes
   * sk:   output buffer of SECRET_KEY_SIZE bytes
   * seed: input buffer of SEED_SIZE bytes
   *
   * Returns 0 on success, negative on error. On error both buffers are
   * wiped.
   */
  static int generateKeypairFromSeed(uint8_t *pk, uint8_t *sk,
                                     const uint8_t *seed) {
    return wipeKeypairOnError(Binding<L>::keypairFromSeed(pk, sk, seed), pk,
                              sk);
  }

  /*
   * Sign a message.
   *
   * sig:    output buffer of SIGNATURE_SIZE bytes
   * siglen: output, set to SIGNATURE_SIZE on success and to 0 on error.
   *         May be NULL: a signature always has SIGNATURE_SIZE bytes.
   * msg:    message to sign
   * msglen: length of message
   * sk:     secret key (SECRET_KEY_SIZE bytes)
   * ctx:    optional context string (NULL if ctxlen == 0)
   * ctxlen: length of context string (0 for none, max 255)
   *
   * Returns 0 on success, negative on error. On error sig is wiped.
   */
  static int sign(uint8_t *sig, size_t *siglen, const uint8_t *msg,
                  size_t msglen, const uint8_t *sk,
                  const uint8_t *ctx = nullptr, size_t ctxlen = 0) {
    int ret = Binding<L>::signature(sig, msg, msglen, ctx, ctxlen, sk);
    if (ret != 0) {
      secureZero(sig, SIGNATURE_SIZE);
    }
    if (siglen != nullptr) {
      *siglen = ret == 0 ? static_cast<size_t>(SIGNATURE_SIZE) : 0;
    }
    return ret;
  }

  /*
   * Verify a signature.
   *
   * sig:    signature
   * siglen: length of signature; anything but SIGNATURE_SIZE is rejected
   * msg:    signed message
   * msglen: length of message
   * pk:     public key (PUBLIC_KEY_SIZE bytes)
   * ctx:    optional context string (NULL if ctxlen == 0)
   * ctxlen: length of context string (0 for none, max 255)
   *
   * Returns 0 if valid, negative on failure.
   */
  static int verify(const uint8_t *sig, size_t siglen, const uint8_t *msg,
                    size_t msglen, const uint8_t *pk,
                    const uint8_t *ctx = nullptr, size_t ctxlen = 0) {
    if (siglen != SIGNATURE_SIZE) {
      return MLD_ERR_INVALID_SIGNATURE;
    }
    return Binding<L>::verify(sig, msg, msglen, ctx, ctxlen, pk);
  }

  /*
   * Check a secret key and derive its public key.
   *
   * pk: output buffer of PUBLIC_KEY_SIZE bytes
   * sk: secret key (SECRET_KEY_SIZE bytes)
   *
   * Returns 0 on success, negative if the secret key is not well formed;
   * pk is then wiped. The result and the time taken reveal whether the key
   * was valid.
   */
  static int publicKeyFromSecretKey(uint8_t *pk, const uint8_t *sk) {
    int ret = Binding<L>::publicKeyFromSecretKey(pk, sk);
    if (ret != 0) {
      secureZero(pk, PUBLIC_KEY_SIZE);
    }
    return ret;
  }

  /*
   * Overwrite len bytes at ptr with zeros, in a way the compiler does not
   * remove. Use it to wipe a secret key or a seed after use:
   *
   *   MLDSA44::secureZero(sk, sizeof(sk));
   */
  static void secureZero(void *ptr, size_t len) { mldsa::secureZero(ptr, len); }

 private:
  static int wipeKeypairOnError(int ret, uint8_t *pk, uint8_t *sk) {
    if (ret != 0) {
      secureZero(pk, PUBLIC_KEY_SIZE);
      secureZero(sk, SECRET_KEY_SIZE);
    }
    return ret;
  }
};

/* Definitions, for code that takes the address of a constant. */
template <unsigned L>
constexpr unsigned Variant<L>::PARAMETER_SET;
template <unsigned L>
constexpr size_t Variant<L>::PUBLIC_KEY_SIZE;
template <unsigned L>
constexpr size_t Variant<L>::SECRET_KEY_SIZE;
template <unsigned L>
constexpr size_t Variant<L>::SIGNATURE_SIZE;
template <unsigned L>
constexpr size_t Variant<L>::SEED_SIZE;

} /* namespace mldsa */

#endif /* MLDSA_WRAPPER_H */
