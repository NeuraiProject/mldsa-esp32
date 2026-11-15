# Measurements

Time and memory of each operation, measured on a real board with
`test/bench_device`. Nothing here is taken from another project's figures.

## Setup

- Board: LilyGo T-Display-S3 (ESP32-S3, two cores at 240 MHz).
- Arduino-ESP32 2.0.17 (ESP-IDF 4.4.7), PlatformIO default build options.
- Date: 15 November 2026.
- Each operation runs in its own task. Stack use is read from a static stack
  buffer filled with a known pattern; heap use is counted by the library's
  allocator (`-DMLDSA_ESP32_ALLOC_STATS`).
- Times are wall-clock milliseconds. Keygen is the mean of 5 runs, verify of
  10, signing of 80 to 120 signatures.

Signing time is not constant: ML-DSA retries until a candidate signature
passes its checks, 4 to 5 attempts on average, sometimes many more. The
tables give the fastest signature seen (one attempt), the mean, and the
slowest seen.

Only this board has been measured. A classic ESP32 or an ESP32-C3 will be
slower.

## Default build

Working memory comes from the heap; `MLD_CONFIG_REDUCE_RAM` is on.

| Variant | Keygen | Sign: fastest / mean / slowest | Verify |
| --- | --- | --- | --- |
| ML-DSA-44 | 11 ms | 19 / 71 / 232 ms | 12 ms |
| ML-DSA-65 | 19 ms | 29 / 113 / 422 ms | 20 ms |
| ML-DSA-87 | 32 ms | 46 / 168 / 872 ms | 33 ms |

| Variant | Heap: keygen | Heap: sign | Heap: verify | Stack, any operation |
| --- | --- | --- | --- | --- |
| ML-DSA-44 | 11.6 KB | 13.0 KB | 9.1 KB | 2.9 KB |
| ML-DSA-65 | 14.6 KB | 17.1 KB | 10.2 KB | 2.9 KB |
| ML-DSA-87 | 18.7 KB | 21.2 KB | 12.5 KB | 2.9 KB |

Deriving a public key from a secret key (`publicKeyFromSecretKey`) takes
13.2, 17.1 and 22.0 KB of heap; that figure comes from the host tests, which
count the bytes requested.

With the Wi-Fi radio on (a soft access point), times and memory were the
same; the board had 199 KB of heap free instead of 271 KB.

The memory is taken for the duration of one call and wiped before it is
released. The stack figure includes 0.7 KB that an empty task uses. It does
not include your own key and signature buffers.

## Build options

Set these with `build_flags` in `platformio.ini`. They apply to the whole
library.

### `-DMLDSA_ESP32_USE_STACK`: working memory on the stack

Nothing is taken from the heap; the calling task needs this much stack.
Times are the same as in the default build.

| Variant | Keygen | Sign | Verify |
| --- | --- | --- | --- |
| ML-DSA-44 | 14.1 KB | 15.6 KB | 11.9 KB |
| ML-DSA-65 | 17.1 KB | 19.8 KB | 13.0 KB |
| ML-DSA-87 | 21.2 KB | 23.9 KB | 15.3 KB |

A task with too little stack crashes instead of returning an error, so leave
a margin.

### `-DMLDSA_ESP32_NO_REDUCE_RAM`: faster signing, more memory

Keygen and verify take the same time. Signing is about twice as fast on
average, because each retry no longer recomputes the public matrix.

| Variant | Sign: fastest / mean / slowest | Memory: keygen | Memory: sign | Memory: verify |
| --- | --- | --- | --- | --- |
| ML-DSA-44 | 18 / 34 / 97 ms | 29.6 KB | 47.4 KB | 27.4 KB |
| ML-DSA-65 | 27 / 64 / 222 ms | 47.0 KB | 72.0 KB | 42.9 KB |
| ML-DSA-87 | 43 / 79 / 194 ms | 77.7 KB | 110.9 KB | 71.8 KB |

Measured together with `-DMLDSA_ESP32_USE_STACK`, so the memory columns are
stack. The combination with heap memory has not been measured.

## Version 0.2.0, for comparison

Version 0.2.0 used an earlier mldsa-native and took all working memory from
the stack.

| Variant | Stack: keygen | Stack: sign | Stack: verify | Sign: fastest / mean |
| --- | --- | --- | --- | --- |
| ML-DSA-44 | 31.5 KB | 35.0 KB | 25.3 KB | 17 / 51 ms |
| ML-DSA-65 | 42.8 KB | 47.3 KB | 33.6 KB | 27 / 97 ms |
| ML-DSA-87 | 57.1 KB | 61.7 KB | 44.1 KB | 43 / 141 ms |

Keygen and verify took the same time as now. The current default build uses
about 60% less memory for signing, and none of it is stack beyond 3 KB. In
exchange, the mean signing time is 15% to 40% longer;
`-DMLDSA_ESP32_NO_REDUCE_RAM` trades that back.

## Storing and loading a key in NVS

`MLDSA44_NVS` and its siblings, default build, called from the Arduino loop
task with its default 8 KB stack (5.6 KB of it stayed unused).

| Variant | Seed record: generate and save | Seed record: load | Secret-key record: save | Secret-key record: load |
| --- | --- | --- | --- | --- |
| ML-DSA-44 | 15 ms | 14 ms | 84 ms | 20 ms |
| ML-DSA-65 | 23 ms | 22 ms | 113 ms | 31 ms |
| ML-DSA-87 | 36 ms | 34 ms | 118 ms | 47 ms |

Loading a seed record generates the keypair again, and takes the heap of a
key generation: 11.5, 14.6 and 18.7 KB. Loading a secret-key record derives
and checks the public key: 13.2, 17.1 and 22.0 KB. Saving a secret-key record
is slower because it first checks that the public key belongs to the secret
key, and then writes 80 to 160 flash entries instead of 4.

## NVS: which key records fit

Default `nvs` partition of Arduino-ESP32: 20 KB, 630 entries of which 504
are usable. On the test board, other data already held 121 entries. Each
case writes a record and then replaces it 12 times, as a key rotation would.
Sizes include a 16-byte record header.

| Record | Size | Entries | First write | Replacement |
| --- | --- | --- | --- | --- |
| Seed | 48 B | 4 | yes | yes |
| ML-DSA-44 secret key | 2,576 B | 84 | yes | yes |
| ML-DSA-44 secret + public key | 3,888 B | 126 | yes | yes |
| ML-DSA-65 secret key | 4,048 B | 130 | yes | yes |
| ML-DSA-65 secret + public key | 6,000 B | 192 | yes | **no** |
| ML-DSA-87 secret key | 4,912 B | 157 | yes | yes |
| ML-DSA-87 secret + public key | 7,504 B | 239 | yes | **no** |
| ML-DSA-87 public and secret key as two entries | 2,592 + 4,896 B | — | yes | **no** |

NVS writes the new value before it erases the old one, so replacing a record
needs room for both.

The table above is raw NVS behaviour, measured to design the storage
helpers. The helpers store a seed or a secret key, never both keys, and check
the free space first: a save that does not fit is refused before anything is
written.

When a replacement does not fit and is attempted anyway
(`ESP_ERR_NVS_NOT_ENOUGH_SPACE`):

- With a single record, the old value stays readable. The partition stays
  full until NVS is initialised again, for example by a reboot.
- With the public and secret key in two entries, the new public key was
  written, the secret key write failed, and the old secret key could no
  longer be read, even after NVS was initialised again. No usable identity
  was left.

### Interrupted writes

`test/nvs_device` (environment `powercut`) replaces an ML-DSA-44 seed record
and an ML-DSA-87 secret-key record in a loop while a script on the host
resets the board at random moments. After 100 resets and about 440 saves, all
101 boots found both identities whole and valid.

## Reproducing

```sh
pio run -d test/bench_device -e lilygo-t-display-s3 -t upload   # default build
pio device monitor -d test/bench_device
```

Other environments in `test/bench_device/platformio.ini`: `-stack`, `-fast`
and `-nvs`. The `-nvs` one writes to the NVS partition of the board.

On Arduino-ESP32 2.0.x, do not use `uxTaskGetStackHighWaterMark()` for tasks
with more than 64 KB of stack: its result is truncated to 16 bits.
