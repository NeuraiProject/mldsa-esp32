# MLDSA

Post-quantum digital signatures for ESP32 using **ML-DSA-44** (FIPS 204), formerly known as Dilithium.

> **Note:** This version supports ML-DSA-44 only. Support for ML-DSA-65 and ML-DSA-87 is planned for future releases.

Ported from the [mldsa-native](https://github.com/pq-code-package/mldsa-native) reference implementation (PQCP project) with ESP32 hardware RNG support and memory optimizations for embedded use.

## Features

- **FIPS 204 compliant** -- ML-DSA-44 (Module-Lattice-Based Digital Signature Algorithm)
- **Hardware RNG** -- Uses ESP32's true random number generator (`esp_fill_random`)
- **Memory optimized** -- Reduced RAM mode (~32KB working memory for signing)
- **Constant-time** -- Side-channel resistant operations with value barriers
- **NVS key storage** -- Persist keypairs in flash across reboots
- **Arduino-friendly** -- Simple C++ wrapper class (`MLDSA44`)
- **NIST test vectors** -- Verification against official ACVP test vectors included

## MLDSA44

ML-DSA-44 (Module-Lattice-Based Digital Signature Algorithm, parameter set 44) is a post-quantum digital signature scheme standardized by NIST as **FIPS 204** in August 2024. It is derived from the **CRYSTALS-Dilithium** submission to the NIST Post-Quantum Cryptography competition.

### How it works

ML-DSA is built on the hardness of the **Module Learning With Errors (MLWE)** and **Module Short Integer Solution (MSIS)** problems over polynomial rings. These problems are believed to be intractable even for large-scale quantum computers, unlike classical schemes (RSA, ECDSA) which are broken by Shor's algorithm.

The algorithm operates over the ring $\mathbb{Z}_q[X]/(X^n + 1)$ with $n = 256$ and $q = 8{,}380{,}417$. Key generation, signing, and verification all rely on structured lattice arithmetic — primarily polynomial multiplication via the **Number Theoretic Transform (NTT)**, which makes operations fast even on constrained hardware.

The signing process uses a **Fiat-Shamir with aborts** approach:
1. A random mask polynomial vector is sampled.
2. A challenge hash is derived from the message and a commitment.
3. A candidate signature is computed; if it leaks information about the secret key (checked via norm bounds), the attempt is **aborted and restarted** — this is what makes the scheme secure without a random oracle assumption on the signer's side.

### Benefits

- **Quantum-resistant**: security relies on lattice problems with no known efficient quantum algorithm.
- **Fast**: NTT-based polynomial arithmetic is efficient even on microcontrollers like ESP32.
- **Compact**: the smallest ML-DSA variant — 1,312-byte public key, 2,420-byte signature — versus RSA-3072 (~384-byte key but ~384-byte signature) or ECDSA P-256 (64-byte signature but classically broken by quantum).
- **Deterministic keygen**: keypairs can be derived from a 32-byte seed, enabling reproducible key generation and backup.
- **Standardized**: FIPS 204 compliance ensures interoperability and regulatory acceptance.
- **Side-channel resistant**: constant-time implementation using value barriers prevents timing and power analysis attacks.

### Parameter set comparison

| Variant | Security level | Public key | Secret key | Signature |
|---------|---------------|-----------|-----------|-----------|
| ML-DSA-44 | NIST Level 2 (~AES-128) | 1,312 B | 2,560 B | 2,420 B |
| ML-DSA-65 | NIST Level 3 (~AES-192) | 1,952 B | 4,032 B | 3,309 B |
| ML-DSA-87 | NIST Level 5 (~AES-256) | 2,592 B | 4,896 B | 4,627 B |

ML-DSA-44 is the recommended choice for ESP32 due to its lower memory footprint.

## Key Sizes

| Parameter | Size |
|-----------|------|
| Public Key | 1,312 bytes |
| Secret Key | 2,560 bytes |
| Signature | 2,420 bytes |
| Seed | 32 bytes |

## Requirements

- ESP32 board (ESP32, ESP32-S2, ESP32-S3, ESP32-C3, etc.)
- Arduino IDE 1.8+ or PlatformIO
- ~32KB free stack for signing operations (use FreeRTOS task with 64KB stack)
- ~320KB free RAM minimum

## Installation

### Arduino IDE

1. Download or clone this repository
2. Copy the `mldsa-arduino` folder to your Arduino libraries directory:
   - Linux: `~/Arduino/libraries/`
   - macOS: `~/Documents/Arduino/libraries/`
   - Windows: `Documents\Arduino\libraries\`
3. Restart Arduino IDE

### PlatformIO

Add to your `platformio.ini`:

```ini
lib_deps =
    https://github.com/NeuraiProject/mldsa-esp32
```

## Quick Start

```cpp
#include <Arduino.h>
#include <MLDSA44.h>

void cryptoTask(void *pvParameters) {
  uint8_t pk[MLDSA44::PUBLIC_KEY_SIZE];
  uint8_t sk[MLDSA44::SECRET_KEY_SIZE];
  uint8_t sig[MLDSA44::SIGNATURE_SIZE];
  size_t siglen;

  // Generate keypair
  MLDSA44::generateKeypair(pk, sk);

  // Sign a message
  const char *msg = "Hello, post-quantum world!";
  MLDSA44::sign(sig, &siglen, (const uint8_t *)msg, strlen(msg), sk);

  // Verify
  int result = MLDSA44::verify(sig, siglen,
                                (const uint8_t *)msg, strlen(msg), pk);
  // result == 0 means valid

  memset(sk, 0, sizeof(sk)); // Zeroize secret key
  vTaskDelete(NULL);
}

void setup() {
  Serial.begin(115200);
  // ML-DSA-44 needs ~32KB working memory, use 64KB FreeRTOS task stack
  xTaskCreate(cryptoTask, "crypto", 65536, NULL, 1, NULL);
}

void loop() { delay(1000); }
```

## API Reference

### MLDSA44 (core operations)

```cpp
#include <MLDSA44.h>

// Generate a random keypair
int MLDSA44::generateKeypair(uint8_t *pk, uint8_t *sk);

// Generate keypair from a deterministic 32-byte seed
int MLDSA44::generateKeypairFromSeed(uint8_t *pk, uint8_t *sk,
                                      const uint8_t *seed);

// Sign a message (optional context string)
int MLDSA44::sign(uint8_t *sig, size_t *siglen,
                   const uint8_t *msg, size_t msglen,
                   const uint8_t *sk,
                   const uint8_t *ctx = nullptr, size_t ctxlen = 0);

// Verify a signature (optional context string)
int MLDSA44::verify(const uint8_t *sig, size_t siglen,
                     const uint8_t *msg, size_t msglen,
                     const uint8_t *pk,
                     const uint8_t *ctx = nullptr, size_t ctxlen = 0);
```

All functions return `0` on success, negative on error.

### MLDSA44_NVS (persistent key storage)

```cpp
#include <MLDSA44_NVS.h>

// Save/load keypair to/from NVS flash
bool MLDSA44_NVS::saveKeypair(const char *ns, const uint8_t *pk, const uint8_t *sk);
bool MLDSA44_NVS::loadKeypair(const char *ns, uint8_t *pk, uint8_t *sk);
bool MLDSA44_NVS::loadPublicKey(const char *ns, uint8_t *pk);

// Check existence / erase
bool MLDSA44_NVS::hasKeypair(const char *ns);
bool MLDSA44_NVS::eraseKeypair(const char *ns);

// Generate and save in one step
int MLDSA44_NVS::generateAndSave(const char *ns, uint8_t *pk, uint8_t *sk);
```

The `ns` parameter is an NVS namespace string (max 15 characters).

## Examples

| Example | Description |
|---------|-------------|
| [mldsa_simple](examples/mldsa_simple/) | Minimal keygen + sign + verify using MLDSA44 wrapper |
| [mldsa_demo_arduino](examples/mldsa_demo_arduino/) | Full demo with timing, memory diagnostics, and tamper test |
| [mldsa_nvs_storage](examples/mldsa_nvs_storage/) | Persistent key storage in NVS flash (survives reboots) |
| [mldsa_test_vectors](examples/mldsa_test_vectors/) | FIPS 204 conformance test against NIST ACVP test vectors |

## Memory Usage

With `MLD_CONFIG_REDUCE_RAM` and `MLD_CONFIG_SERIAL_FIPS202_ONLY` enabled (default in this port):

| Operation | Stack allocation |
|-----------|-----------------|
| KeyGen | ~33 KB |
| Sign | ~32 KB |
| Verify | ~22 KB |

A FreeRTOS task with 64KB stack is recommended to provide sufficient headroom.

## Important Notes

- **FreeRTOS task required**: ML-DSA operations must run in a FreeRTOS task with sufficient stack (64KB recommended). The default Arduino `loop()` stack (8KB) is too small.
- **Blocking operations**: Keygen and signing take several seconds on ESP32. Run them in a dedicated task to avoid blocking other operations.
- **Secret key handling**: Always zeroize secret keys with `memset(sk, 0, sizeof(sk))` after use.
- **Hardware RNG**: The ESP32 TRNG provides full entropy when WiFi or Bluetooth is active. With both radios off, it falls back to a pseudo-random source seeded from hardware noise, which is still suitable for most applications.

## Security Level

ML-DSA-44 provides NIST Security Level 2 (roughly equivalent to AES-128). This is the lightest ML-DSA variant, optimized for constrained environments like ESP32.

Support for higher security levels (ML-DSA-65 / ML-DSA-87) is planned for future releases. The underlying `mldsa-native` engine already handles all three parameter sets; the Arduino wrapper classes and memory optimizations for those variants are still work in progress.

## License

Licensed under the **Apache License, Version 2.0**.

The cryptographic implementation is derived from [mldsa-native](https://github.com/pq-code-package/mldsa-native) (PQCP project), which is licensed under Apache-2.0 OR ISC OR MIT. The upstream source files retain their original triple-license headers.

## Links

- [FIPS 204 Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [mldsa-native (upstream)](https://github.com/pq-code-package/mldsa-native)
- [NeuraiProject](https://neurai.org)
