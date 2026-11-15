# Upstream code

The ML-DSA implementation in `src/` is vendored, unmodified, from
[mldsa-native](https://github.com/pq-code-package/mldsa-native).

| | |
| --- | --- |
| Release | `v2.0.0` |
| Commit | `834a90d5e846ffa1e1611bd24e160bb2e9b86d35` |
| License | Apache-2.0 OR ISC OR MIT (`src/LICENSE.mldsa-native`) |
| Imported with | `scripts/update_mldsa_native.sh v2.0.0` |

## What is vendored

`UPSTREAM.sha256` lists every vendored file with its hash and its path
upstream:

- `mldsa/src/` → `src/`, without the native assembly backends
  (`native/aarch64`, `native/x86_64`, `fips202/native/*/`).
- `mldsa/mldsa_native.h` → `src/mldsa_native.h`.
- `LICENSE` → `src/LICENSE.mldsa-native`.

`scripts/check_upstream.sh` fails if any of those files differs from its
recorded hash, or if `src/` holds a file that is neither vendored nor one of
the port's. With `--online` it also compares against GitHub. CI runs it.

## What belongs to the port

| File | Purpose |
| --- | --- |
| `src/mldsa_native_config.h` | Build configuration. Starts from upstream's file of the same name; every change is marked `ESP32 port:`. |
| `src/mldsa65_build.c`, `src/mldsa87_build.c` | Compile the level-dependent sources again for ML-DSA-65 and 87. |
| `src/randombytes.c` | Random source: `esp_fill_random()`. |
| `src/esp32/mldsa_esp32_alloc.c` | Working memory from the internal heap. |
| `src/mldsa_native_all.h` | Declares the C API of the three levels. |
| `src/mldsa_compat.h` | Keeps sketches written for 0.2.0 compiling. |
| `src/MLDSA.h`, `src/MLDSA44.h`, `src/MLDSA65.h`, `src/MLDSA87.h` | Arduino C++ wrapper. |
| `src/MLDSA44_NVS.h` | Key storage in NVS. |

### Changes to the configuration

Compared with upstream's `mldsa/mldsa_native_config.h`:

- `MLD_CONFIG_MULTILEVEL_BUILD`, and `MLD_CONFIG_MULTILEVEL_WITH_SHARED`
  unless a build unit asks for `MLD_CONFIG_MULTILEVEL_NO_SHARED`: one
  library with ML-DSA-44, 65 and 87 and a single copy of the shared code.
- `MLD_CONFIG_SERIAL_FIPS202_ONLY`: no 4-way Keccak, which needs SIMD to pay
  off.
- `MLD_CONFIG_REDUCE_RAM`, unless built with `-DMLDSA_ESP32_NO_REDUCE_RAM`.
- `MLD_CONFIG_CUSTOM_ALLOC_FREE` with the port's allocator, unless built with
  `-DMLDSA_ESP32_USE_STACK`. Upstream marks this option as experimental: its
  macros may change in a later release.
- At the end, `mldsa_compat.h` is included for code outside the core.

## Upstream options evaluated and not adopted

- `MLD_CONFIG_MAX_SIGNING_ATTEMPTS`: bounds the number of signing attempts
  and makes signing fail when it is reached. Left at the upstream default,
  which never fails in practice. FIPS 204 requires at least 821 if it is
  set. Measured signing times are far from any watchdog limit.
- `MLD_CONFIG_NO_KEYPAIR_API`, `MLD_CONFIG_NO_SIGN_API`,
  `MLD_CONFIG_NO_VERIFY_API`: remove parts of the API to save flash. Not
  needed here: the ESP32 toolchains link with `--gc-sections`, so a sketch
  that only verifies does not carry the signing code.
- `MLD_CONFIG_KEYGEN_PCT`: pairwise consistency test after key generation,
  as FIPS 140-3 asks of validated modules. Off, as upstream ships it; it
  costs a signature and a verification per keypair.
- `MLD_CONFIG_SIGN_HOOK_*` (restartable signing): not needed at the measured
  signing times.

## History

Up to version 0.2.0 the core was a snapshot of mldsa-native `main` at commit
`0b1c5364` (13 February 2026, 24 commits before `v1.0.0-beta`), with no
record of where it came from.

## Updating

1. `scripts/update_mldsa_native.sh <tag-or-commit>`
2. Compare upstream's new `mldsa/mldsa_native_config.h` with
   `src/mldsa_native_config.h` and merge new options by hand.
3. If the script warns that the level-dependent sources changed, update
   `src/mldsa65_build.c` and `src/mldsa87_build.c`.
4. `test/host/run.sh` and `test/build_firmware.sh`, then the on-device
   procedure in `docs/device-test.md`.
5. Update this file and `CHANGELOG.md`.

The C API can change between upstream releases, as it did in v2.
`src/mldsa_compat.h` repeats a few upstream declarations, so the compiler
reports a mismatch.
