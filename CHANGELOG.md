# Changelog

Changes to the mldsa library for ESP32, newest first.

## 0.3.0 - 2026-11-15

### Changed

- **The cryptographic core is now mldsa-native v2.0.0**, vendored without
  modification. Up to 0.2.0 it was an unreleased development snapshot.
  `UPSTREAM.md` records the exact revision, and `scripts/check_upstream.sh`
  verifies that the vendored files are untouched.
- **A dedicated FreeRTOS task with a 64 to 80 KB stack is no longer needed.**
  Each operation takes its working memory from the heap (9 to 22 KB,
  depending on the operation and security level) and about 3 KB of stack, so
  it can be called from `setup()` or `loop()`. Version 0.2.0 needed 25 to
  62 KB of stack. Sketches that still create a large task keep working.
- **Signing takes longer on average**: about 71, 113 and 168 ms for
  ML-DSA-44, 65 and 87 on an ESP32-S3, against 51, 97 and 141 ms in 0.2.0.
  Key generation and verification are unchanged. Building with
  `-DMLDSA_ESP32_NO_REDUCE_RAM` makes signing about twice as fast at 3 to 5
  times the memory. `docs/measurements.md` has all the figures.
- **An operation that cannot get its memory returns `MLD_ERR_OUT_OF_MEMORY`
  (-2).** Check return values; 0.2.0 overflowed the stack instead.
- **Error codes follow mldsa-native v2.** A signature that does not verify
  now gives -6 (`MLD_ERR_INVALID_SIGNATURE`) instead of -1, and an invalid
  argument such as a context longer than 255 bytes gives -9. Code that tests
  for `!= 0` or `< 0` is not affected.
- **The C API follows mldsa-native v2**: the functions no longer take a
  signature length, and `sign`, `open` and the `crypto_sign_*` aliases are
  gone upstream. C++ code, which includes every sketch, keeps compiling:
  `mldsa_compat.h` provides the 0.2.0 forms. C code has to adopt the v2
  signatures.
- **NVS key storage was redesigned.** A key is now one small record, the
  32-byte seed or the secret key, instead of separate public and secret key
  entries, and the public key is derived when the key is loaded. Keys stored
  by 0.2.0 are still read; `migrate()` converts them, and so does saving a
  new key. `saveKeypair()` now refuses a public key that does not belong to
  the secret key. `docs/nvs-format.md` describes the record.
- **The library no longer defines the generic symbol `randombytes()`**, which
  clashed with other libraries that define it. Its random source is
  `mldsa_esp32_randombytes()`.
- **`mldsa_test_vectors` now runs NIST ACVP test cases for the three
  parameter sets**: key generation, signing and verification through the pure,
  pre-hash, internal and external-mu interfaces, plus randomized round trips
  and boundary cases. The vectors are read from a pinned commit of the NIST
  repository.
- **The examples** no longer create 64 KB tasks; `mldsa_simple` runs in
  `setup()`. Sketches written for 0.2.0 compile and run unchanged; the
  0.2.0 examples are kept in `test/compat_0_2_0` and built on every change.
- **README and source comments** no longer claim FIPS validation, protection
  against power analysis, or sufficient entropy with both radios off. The
  hardware RNG note now states the conditions under which ESP-IDF documents
  its output as truly random. Memory and timing figures are measured ones.

### Fixed

- **An interrupted key replacement in NVS could leave the public key of one
  identity with the secret key of another, and it loaded as valid.** With a
  single record this cannot happen: the next load gives the previous key or
  the new one. Tested on a board with 100 resets at random moments.
- **A key replacement that did not fit in NVS could destroy the stored key.**
  On an ESP32-S3, a write that ran out of space left the partition full
  until reboot and made the old secret key unreadable. Saves now check the
  free space first and are refused, with the stored key intact, when it is
  not enough.
- **`eraseKeypair()` reported success when the entries could not be
  removed.** It now reports the failure. It also no longer claims to erase
  securely: it removes the NVS entry, not the bytes in flash.
- **Loading from NVS left key material in the output buffers on failure.**
  They are wiped.

- **Secrets were wiped with `memset()`, which the compiler removes.** The
  examples and the README told you to clear the secret key with `memset()`
  after use. With the ESP32 toolchains that call is optimized away when the
  buffer is not read again. Use `MLDSA44::secureZero()` instead; the examples
  now do.
- **The random source adapter had a bogus health check.** It treated output
  that started with `0xAA` bytes as a failure, would have accepted a source
  that returned only zeros, and reported success for a null buffer. It now
  passes the bytes through, refuses a null buffer, and reports the failure of
  a source as `MLD_ERR_RNG_FAIL`.
- **Output buffers are wiped when an operation fails.** After a failed key
  generation, the key buffers could hold whatever they had before.

- **ML-DSA-65 and ML-DSA-87 did not link.** A sketch that used `MLDSA65` or
  `MLDSA87` stopped at the linker with undefined references to
  `PQCP_MLDSA_NATIVE_MLDSA_*`. Sketches that only used `MLDSA44` were not
  affected. All three variants now build and run in the same firmware.
- **The `mldsa_test_vectors` example checked against a wrong vector.** Its
  seed was not a NIST test case and 32 of the expected secret-key bytes did
  not match the algorithm's output, so the sketch reported a failure on a
  correct build.

### Added

- `MLDSA65_NVS` and `MLDSA87_NVS`: NVS key storage for the other two levels.
- `saveSeed()` and `migrate()` in the NVS classes, and an optional
  `mldsa::NvsError *` argument in all their functions that gives the reason
  for a failure.
- `mldsa::setRandomSource()`: registers your own random source, such as a
  DRBG or a secure element, for key generation and signing. The README has a
  new "Random Numbers" section on what the application must guarantee before
  it generates a key, and `examples/mldsa_random_source` shows how.
- `MLDSA44::secureZero()` (and the same for 65 and 87): wipes a secret in a
  way the compiler does not remove.
- `MLDSA44::publicKeyFromSecretKey()` (and the same for 65 and 87): checks a
  secret key and derives its public key.
- `mldsa_esp32.h`: the same functions for C code.
- `PARAMETER_SET` constant in the three classes; `sign()` accepts a null
  `siglen`.
- Build options `-DMLDSA_ESP32_USE_STACK` (working memory on the stack) and
  `-DMLDSA_ESP32_NO_REDUCE_RAM` (faster signing, more memory).
- `mldsa_native_all.h`: declares the C API of the three parameter sets.
- `test/host`: test suite for Linux, built with AddressSanitizer and
  UndefinedBehaviorSanitizer. It runs every NIST ACVP keyGen, sigGen and
  sigVer case for ML-DSA-44, 65 and 87 (615 cases) with both memory models,
  makes every allocation fail in turn, and checks linking, the 0.2.0 call
  forms and the NVS helper.
- `test/build_variants`: firmware that runs the three variants together and
  two of them concurrently, in tasks with 8 KB of stack.
- `test/bench_device`: firmware that measures time, stack and heap.
- `test/nvs_device`: on-device tests of the NVS key storage, including resets
  at random moments while keys are replaced.
- `test/build_firmware.sh`: compiles the test firmware and the examples for
  ESP32 and ESP32-C3.
- `scripts/gen_acvp_vectors.py`, `scripts/update_mldsa_native.sh`,
  `scripts/check_upstream.sh`.
- `.github/workflows/ci.yml`: runs the host tests and the firmware builds.
- `docs/measurements.md`, `docs/nvs-format.md`, `docs/device-test.md`,
  `UPSTREAM.md`.
