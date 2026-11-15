# MLDSA

Post-quantum digital signatures for ESP32 using **ML-DSA** (FIPS 204), formerly known as Dilithium. Supports all three NIST security levels: **ML-DSA-44**, **ML-DSA-65**, and **ML-DSA-87**.

Built on [mldsa-native](https://github.com/pq-code-package/mldsa-native) v2.0.0 (PQCP project), with ESP32 hardware RNG support and a configuration tuned for the memory of a microcontroller.

## Features

- **Implements FIPS 204** -- All three ML-DSA security levels (44, 65, 87). This library is not a FIPS-validated module
- **Hardware RNG, or your own** -- Uses the ESP32 hardware random number generator (`esp_fill_random`) by default and accepts a random source of yours; see [Random Numbers](#random-numbers) for when the hardware one is truly random
- **Small memory footprint** -- 9 to 22 KB of heap per operation and about 3 KB of stack, measured on an ESP32-S3
- **Constant-time code** -- Inherits the timing side-channel hardening of mldsa-native (no secret-dependent branches or memory access, value barriers against compiler optimizations); its timing has not been measured on ESP32 hardware. No protection against power or electromagnetic analysis, or fault injection
- **NVS key storage** -- Keep a key of any security level in flash across reboots, as one small record that survives interrupted writes
- **Arduino-friendly** -- Simple C++ wrapper classes (`MLDSA44`, `MLDSA65`, `MLDSA87`)
- **NIST test vectors** -- All 615 ACVP cases for key generation, signing and verification pass in the host tests; a subset runs on the device in an example sketch

## About ML-DSA

ML-DSA (Module-Lattice-Based Digital Signature Algorithm) is a post-quantum digital signature scheme standardized by NIST as **FIPS 204** in August 2024. It is derived from the **CRYSTALS-Dilithium** submission to the NIST Post-Quantum Cryptography competition. This library supports all three parameter sets: ML-DSA-44, ML-DSA-65, and ML-DSA-87.

### How it works

ML-DSA is built on the hardness of the **Module Learning With Errors (MLWE)** and **Module Short Integer Solution (MSIS)** problems over polynomial rings. These problems are believed to be intractable even for large-scale quantum computers, unlike classical schemes (RSA, ECDSA) which are broken by Shor's algorithm.

The algorithm operates over the ring $\mathbb{Z}_q[X]/(X^n + 1)$ with $n = 256$ and $q = 8{,}380{,}417$. Key generation, signing, and verification all rely on structured lattice arithmetic — primarily polynomial multiplication via the **Number Theoretic Transform (NTT)**, which makes operations fast even on constrained hardware.

The signing process uses a **Fiat-Shamir with aborts** approach:
1. A random mask polynomial vector is sampled.
2. A challenge hash is derived from the message and a commitment.
3. A candidate signature is computed; if it would leak information about the secret key (checked via norm bounds), the attempt is **aborted and restarted**. This is why signing time varies from one call to the next.

### Benefits

- **Quantum-resistant**: security relies on lattice problems with no known efficient quantum algorithm.
- **Fast**: NTT-based polynomial arithmetic is efficient even on microcontrollers like ESP32.
- **Compact**: ML-DSA-44 has a 1,312-byte public key and 2,420-byte signature; higher levels trade size for stronger security margins.
- **Deterministic keygen**: keypairs can be derived from a 32-byte seed, enabling reproducible key generation and backup.
- **Standardized**: ML-DSA is specified in FIPS 204, so independent implementations interoperate.
- **Constant-time friendly**: the scheme can be implemented without secret-dependent timing, as mldsa-native does. That hardening covers timing only, not power or electromagnetic analysis.

### Parameter set comparison

| Variant | Security level | Public key | Secret key | Signature |
|---------|---------------|-----------|-----------|-----------|
| ML-DSA-44 | NIST Level 2 (~AES-128) | 1,312 B | 2,560 B | 2,420 B |
| ML-DSA-65 | NIST Level 3 (~AES-192) | 1,952 B | 4,032 B | 3,309 B |
| ML-DSA-87 | NIST Level 5 (~AES-256) | 2,592 B | 4,896 B | 4,627 B |

ML-DSA-44 is the recommended choice for ESP32 due to its lower memory footprint. ML-DSA-65 and ML-DSA-87 are available when higher security margins are needed.

## Key Sizes

| Parameter | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|-----------|-----------|----------|
| Public Key | 1,312 B | 1,952 B | 2,592 B |
| Secret Key | 2,560 B | 4,032 B | 4,896 B |
| Signature | 2,420 B | 3,309 B | 4,627 B |
| Seed | 32 B | 32 B | 32 B |

## Requirements

- ESP32 board (ESP32, ESP32-S2, ESP32-S3, ESP32-C3, etc.)
- Arduino IDE 1.8+ or PlatformIO
- Per operation, 9 to 22 KB of free heap and about 3 KB of free stack, depending on the operation and the security level (see [Memory Usage](#memory-usage))
- Room for the keys and the signature: 6 KB for ML-DSA-44, 9 KB for ML-DSA-65, 12 KB for ML-DSA-87

## Installation

### Arduino IDE

1. Download or clone this repository
2. Copy the repository folder (`mldsa-esp32`) to your Arduino libraries directory:
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

All three variants share the same API. Just include the appropriate header and use the corresponding class:

```cpp
#include <Arduino.h>
#include <MLDSA44.h>  // or <MLDSA65.h> or <MLDSA87.h>

// Static: together they take 6 KB, most of the default 8 KB Arduino stack
static uint8_t pk[MLDSA44::PUBLIC_KEY_SIZE];
static uint8_t sk[MLDSA44::SECRET_KEY_SIZE];
static uint8_t sig[MLDSA44::SIGNATURE_SIZE];

void setup() {
  Serial.begin(115200);

  // Generate keypair
  if (MLDSA44::generateKeypair(pk, sk) != 0) return;

  // Sign a message
  const char *msg = "Hello, post-quantum world!";
  size_t siglen;
  if (MLDSA44::sign(sig, &siglen, (const uint8_t *)msg, strlen(msg), sk) != 0) return;

  // Verify: 0 means valid
  int result = MLDSA44::verify(sig, siglen, (const uint8_t *)msg, strlen(msg), pk);
  Serial.println(result == 0 ? "Signature valid" : "Signature invalid");

  MLDSA44::secureZero(sk, sizeof(sk)); // Wipe the secret key
}

void loop() { delay(1000); }
```

For ML-DSA-65 or ML-DSA-87, replace `MLDSA44` with `MLDSA65` or `MLDSA87`.

## API Reference

### Core operations (MLDSA44 / MLDSA65 / MLDSA87)

All three wrapper classes expose an identical API. Replace `MLDSAxx` with `MLDSA44`, `MLDSA65`, or `MLDSA87` as needed:

```cpp
#include <MLDSA44.h>  // or <MLDSA65.h> or <MLDSA87.h>

// Generate a random keypair
int MLDSAxx::generateKeypair(uint8_t *pk, uint8_t *sk);

// Generate keypair from a deterministic 32-byte seed
int MLDSAxx::generateKeypairFromSeed(uint8_t *pk, uint8_t *sk,
                                      const uint8_t *seed);

// Sign a message (optional context string)
int MLDSAxx::sign(uint8_t *sig, size_t *siglen,
                   const uint8_t *msg, size_t msglen,
                   const uint8_t *sk,
                   const uint8_t *ctx = nullptr, size_t ctxlen = 0);

// Verify a signature (optional context string)
int MLDSAxx::verify(const uint8_t *sig, size_t siglen,
                     const uint8_t *msg, size_t msglen,
                     const uint8_t *pk,
                     const uint8_t *ctx = nullptr, size_t ctxlen = 0);

// Check a secret key and derive its public key
int MLDSAxx::publicKeyFromSecretKey(uint8_t *pk, const uint8_t *sk);

// Wipe a secret key or a seed after use
void MLDSAxx::secureZero(void *ptr, size_t len);

// Use your own random source, for all parameter sets (see Random Numbers)
void mldsa::setRandomSource(mldsa::RandomSource source, void *context = nullptr);
```

Each class provides size constants: `PUBLIC_KEY_SIZE`, `SECRET_KEY_SIZE`, `SIGNATURE_SIZE`, `SEED_SIZE`.

All functions that return `int` return `0` on success and a negative value on error. When key generation or signing fails, the output buffers are wiped.

| Value | Name | Meaning |
|-------|------|---------|
| -2 | `MLD_ERR_OUT_OF_MEMORY` | Not enough free heap for the operation |
| -3 | `MLD_ERR_RNG_FAIL` | The random source failed |
| -6 | `MLD_ERR_INVALID_SIGNATURE` | The signature does not verify, or has the wrong length |
| -7 | `MLD_ERR_INVALID_KEY` | The secret key is not well formed |
| -9 | `MLD_ERR_INVALID_ARG` | Invalid argument, such as a context longer than 255 bytes |

### MLDSA44_NVS / MLDSA65_NVS / MLDSA87_NVS (persistent key storage)

One class per security level, with the same functions:

```cpp
#include <MLDSA44_NVS.h>  // or <MLDSA65_NVS.h> or <MLDSA87_NVS.h>

// Generate a key and store it in one step
// 0: ok, negative: keygen error, 1: generated but could not be stored
int MLDSA44_NVS::generateAndSave(const char *ns, uint8_t *pk, uint8_t *sk);

// Store a key you already have
bool MLDSA44_NVS::saveKeypair(const char *ns, const uint8_t *pk, const uint8_t *sk);
bool MLDSA44_NVS::saveSeed(const char *ns, const uint8_t *seed);

// Load
bool MLDSA44_NVS::loadKeypair(const char *ns, uint8_t *pk, uint8_t *sk);
bool MLDSA44_NVS::loadPublicKey(const char *ns, uint8_t *pk);

// Check existence / erase
bool MLDSA44_NVS::hasKeypair(const char *ns);
bool MLDSA44_NVS::eraseKeypair(const char *ns);

// Convert a key stored by version 0.2.0 to the current record
bool MLDSA44_NVS::migrate(const char *ns);
```

The `ns` parameter is an NVS namespace string (max 15 characters). A namespace holds one key. Every function takes an optional last argument, `mldsa::NvsError *error`, that receives the reason for a failure; `mldsa::nvsErrorText(error)` turns it into text.

See [Key Storage in NVS](#key-storage-in-nvs) for what is stored and what NVS does not protect.

## Examples

| Example | Description |
|---------|-------------|
| [mldsa_simple](examples/mldsa_simple/) | Minimal keygen + sign + verify using MLDSA44 wrapper |
| [mldsa_demo_arduino](examples/mldsa_demo_arduino/) | Full demo with timing, memory diagnostics, and tamper test |
| [mldsa_nvs_storage](examples/mldsa_nvs_storage/) | A key that survives reboots, stored in NVS flash |
| [mldsa_random_source](examples/mldsa_random_source/) | Generating keys with the radio off, and registering your own random source |
| [mldsa_test_vectors](examples/mldsa_test_vectors/) | NIST ACVP test cases for ML-DSA-44, 65 and 87, run on the device |

## Random Numbers

Key generation and signing need random numbers. Their quality matters most for key generation: a key generated from predictable numbers is predictable. Signing is "hedged" (FIPS 204, section 3.4): it mixes fresh randomness with a secret value stored in the key, so a weak random source at signing time does not expose the key.

By default the library uses the ESP32 hardware RNG, `esp_fill_random()`. According to the [ESP-IDF documentation](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/system/random.html), it produces true random numbers only while at least one of these holds:

- Wi-Fi or Bluetooth is enabled.
- The SAR ADC entropy source has been enabled with `bootloader_random_enable()` and not yet disabled.

Otherwise its output is pseudo-random only. The library cannot tell which is the case, and it never turns on the radio or the entropy source for you. **Before generating a key, make sure one of the two conditions holds.** With the radio off:

```cpp
#include <bootloader_random.h>

bootloader_random_enable();
int ret = MLDSA44::generateKeypair(pk, sk);
bootloader_random_disable();
```

Do not call `bootloader_random_enable()` while Wi-Fi, Bluetooth, the ADC or (on the ESP32) I2S are in use, and call `bootloader_random_disable()` before starting them.

To use another source, such as a DRBG or a secure element, register it. It applies to all three parameter sets:

```cpp
// Fill out[0..outlen) and return 0; return non-zero on failure
int mySource(uint8_t *out, size_t outlen, void *context);

mldsa::setRandomSource(mySource, context);
```

The library uses the bytes as the source returns them, without testing their quality. If the source fails, key generation and signing return `MLD_ERR_RNG_FAIL` (-3). Register the source before other tasks use the library. The [mldsa_random_source](examples/mldsa_random_source/) example shows both approaches, using the CTR-DRBG of mbedTLS as the registered source.

## Memory Usage

There are two kinds of memory to budget for: what the library needs while it works, and the buffers of your own that hold the keys and the signature.

**Working memory of the library.** Each call takes it from the heap for the duration of the call, and wipes it before releasing it. Measured on an ESP32-S3:

| Operation | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|-----------|-----------|-----------|----------|
| KeyGen | 11.6 KB | 14.6 KB | 18.7 KB |
| Sign | 13.0 KB | 17.1 KB | 21.2 KB |
| Verify | 9.1 KB | 10.2 KB | 12.5 KB |
| Stack of the calling task, any operation | 3 KB | 3 KB | 3 KB |

If the heap memory is not available, the call returns `MLD_ERR_OUT_OF_MEMORY` (-2) and leaves nothing allocated.

**Your buffers.** They are yours to place, and the small stack the library needs does not make them small:

| Buffer | ML-DSA-44 | ML-DSA-65 | ML-DSA-87 |
|--------|-----------|-----------|----------|
| Public key | 1.3 KB | 2.0 KB | 2.6 KB |
| Secret key | 2.6 KB | 4.0 KB | 4.9 KB |
| Signature | 2.4 KB | 3.3 KB | 4.6 KB |
| All three | 6.3 KB | 9.3 KB | 12.1 KB |

Declared as local variables in `setup()` or `loop()`, they would overflow the 8 KB stack of the Arduino loop task. Make them `static` or global, or run in a task whose stack has room for them plus the 3 KB above.

**Build options.** Two options change the trade-off. Set them with `build_flags` in `platformio.ini`:

| Option | Effect |
|--------|--------|
| `-DMLDSA_ESP32_USE_STACK` | Working memory comes from the stack of the calling task instead of the heap: 12 to 24 KB, nothing from the heap |
| `-DMLDSA_ESP32_NO_REDUCE_RAM` | Signing is about twice as fast on average and uses 3 to 5 times the memory |

All the figures, how they were measured, and the comparison with version 0.2.0 are in [docs/measurements.md](docs/measurements.md).

## Important Notes

- **No dedicated task needed**: Operations can be called from `setup()` or `loop()`. Keep the key and signature buffers off the stack of the default Arduino loop task (8 KB): make them `static` or global, or run in a task with a larger stack.
- **Blocking operations**: On an ESP32-S3, keygen and verify take 11 to 33 ms and signing 70 to 170 ms on average. Signing time varies from one call to the next, and an occasional signature takes several times the average. A task that computes for more than about five seconds without yielding trips the FreeRTOS task watchdog.
- **Secret key handling**: Wipe secret keys and seeds after use with `MLDSA44::secureZero(sk, sizeof(sk))`. Do not use `memset()` for this: the compiler may remove a `memset()` of a buffer that is not read again.
- **Random numbers**: Before generating a key, make sure the hardware RNG has an entropy source: Wi-Fi or Bluetooth enabled, or `bootloader_random_enable()`. See [Random Numbers](#random-numbers).
- **NVS storage**: NVS is not encrypted unless you enable NVS encryption, and erasing a key does not overwrite the flash that held it. See [Key Storage in NVS](#key-storage-in-nvs).

## Key Storage in NVS

`MLDSA44_NVS`, `MLDSA65_NVS` and `MLDSA87_NVS` keep one key per NVS namespace.

**What is stored.** A single record: the 32-byte seed for keys made by `generateAndSave()`, or the secret key for keys saved with `saveKeypair()`. The public key is not stored; it is derived when the key is loaded, so the two always belong together. The format is in [docs/nvs-format.md](docs/nvs-format.md).

**Replacing a key is all-or-nothing.** If a save fails or power is lost half way, the next load gives the previous key or the new one, never a mix. This was tested on a board by resetting it 100 times at random moments while it replaced keys.

**Space.** NVS writes the new value before it erases the old one, so replacing a record needs room for both. If there is not enough, the save is refused with `NvsError::NO_SPACE` and the previous key stays in place.

| Record | Size | Free NVS space needed to write it |
|--------|------|-----------------------------------|
| Seed, any level | 46 B | 0.2 KB |
| Secret key, ML-DSA-44 | 2.6 KB | 2.7 KB |
| Secret key, ML-DSA-65 | 4.0 KB | 4.2 KB |
| Secret key, ML-DSA-87 | 4.9 KB | 5.1 KB |

The default `nvs` partition of Arduino-ESP32 is 20 KB, 16 KB of them usable and shared with Wi-Fi and other libraries. Prefer `generateAndSave()`: its record is 50 to 100 times smaller.

**Time.** On an ESP32-S3, loading a key takes 14 to 47 ms and the same heap as a key generation, because the keypair is derived again.

**Not encrypted by default.** NVS is plain flash unless [NVS encryption](https://docs.espressif.com/projects/esp-idf/en/stable/esp32/api-reference/storage/nvs_encryption.html) is enabled. ESP32 flash encryption does not cover NVS; it has to be enabled separately. Without it, anyone who can read the flash can read the key.

**Erasing is not secure erase.** `eraseKeypair()` removes the NVS entry. The bytes stay in flash until NVS reuses the page.

**Keys stored by version 0.2.0** (ML-DSA-44, as separate public and secret key entries) are still loaded, after checking that the two belong together. `migrate()` converts them to the current record; saving a new key does so too.

## Coming from Version 0.2.0

Sketches written for 0.2.0 compile and run unchanged; the repository builds the 0.2.0 examples against every change to check it. What is different:

- **No large task is needed any more.** A sketch that creates a 64 KB task for the cryptography keeps working, but can drop it. See [Memory Usage](#memory-usage).
- **Check return values.** A call can now return `MLD_ERR_OUT_OF_MEMORY` (-2). A signature that does not verify returns -6 instead of -1; code that tests for `!= 0` is not affected.
- **Wipe secrets with `secureZero()`**, not `memset()`.
- **Signing takes 15% to 40% longer on average**, in exchange for 60% less memory. `-DMLDSA_ESP32_NO_REDUCE_RAM` reverses the trade.
- **Keys stored in NVS by 0.2.0 still load.** See [Key Storage in NVS](#key-storage-in-nvs).
- **The C API** (`PQCP_MLDSA_NATIVE_MLDSA44_*` in `mldsa_native.h`) follows mldsa-native v2, whose functions no longer take a signature length. C++ code, which includes every sketch, can keep passing it: `mldsa_compat.h` provides the 0.2.0 forms, and the `crypto_sign_*` names. C code has to adopt the v2 signatures. `mldsa_native_all.h` declares the C API of the three levels at once.

Deterministic signing is not offered by the classes. The hedged signing they use is what FIPS 204 recommends, particularly for devices that an attacker can handle. The C function `PQCP_MLDSA_NATIVE_MLDSA44_signature_internal()` gives the deterministic variant to code that needs it.

## Testing

| What | How | Needs |
|------|-----|-------|
| Every NIST ACVP case for the three levels (615), boundary cases, out-of-memory and random-source failures, NVS storage with every write cut off, 0.2.0 call forms; all under AddressSanitizer and UndefinedBehaviorSanitizer | `test/host/run.sh` | Linux, a C/C++ compiler, Python 3 |
| The test firmware, the examples and the 0.2.0 sketches compile for ESP32 and ESP32-C3 | `test/build_firmware.sh` | PlatformIO |
| The same on a real board | [docs/device-test.md](docs/device-test.md) | A board |

It has been run on an ESP32-S3 with Arduino-ESP32 2.0.17. For the classic ESP32 and the ESP32-C3 it is compiled but has not been run on a board.

## Security Levels

All three ML-DSA parameter sets are supported:

| Variant | NIST Level | Classical equivalent |
|---------|-----------|---------------------|
| ML-DSA-44 | Level 2 | ~AES-128 |
| ML-DSA-65 | Level 3 | ~AES-192 |
| ML-DSA-87 | Level 5 | ~AES-256 |

ML-DSA-44 is recommended for most ESP32 applications due to its lower memory footprint and faster signing. Use ML-DSA-65 or ML-DSA-87 when higher security margins are required.

## License

Licensed under the **Apache License, Version 2.0**.

The cryptographic implementation is [mldsa-native](https://github.com/pq-code-package/mldsa-native) v2.0.0 (PQCP project), vendored without modification and licensed under Apache-2.0 OR ISC OR MIT. The upstream source files retain their original triple-license headers. [UPSTREAM.md](UPSTREAM.md) records the exact revision and what belongs to this port.

The test vector generator (`scripts/gen_acvp_vectors.py`) and the test runner (`examples/mldsa_test_vectors/acvp_runner.h`) are adapted from [fips204-mldsa-esp32](https://github.com/samettonyali29/fips204-mldsa-esp32), also under Apache-2.0.

## Links

- [FIPS 204 Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [mldsa-native (upstream)](https://github.com/pq-code-package/mldsa-native)
- [Changelog](CHANGELOG.md)
- [NeuraiProject](https://neurai.org)
