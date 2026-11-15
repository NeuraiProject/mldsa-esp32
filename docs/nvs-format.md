# NVS key record format

`MLDSA44_NVS`, `MLDSA65_NVS` and `MLDSA87_NVS` store one ML-DSA identity per
NVS namespace, as a single blob under the key `mldsa_key`.

## Record

All multi-byte fields are little-endian.

| Offset | Size | Field | Value |
| --- | --- | --- | --- |
| 0 | 4 | Magic | `M` `L` `D` `K` |
| 4 | 1 | Format version | `1` |
| 5 | 1 | Parameter set | `44`, `65` or `87` |
| 6 | 1 | Content type | `1` = seed, `2` = secret key |
| 7 | 1 | Reserved | `0` |
| 8 | 2 | Payload length | `n` |
| 10 | `n` | Payload | see below |
| 10 + `n` | 4 | CRC-32 | IEEE 802.3, over bytes 0 to 9 + `n` |

| Content type | Payload | Record size | NVS entries |
| --- | --- | --- | --- |
| Seed | The 32-byte seed of FIPS 204 key generation | 46 bytes | 4 |
| Secret key, ML-DSA-44 | The 2,560-byte secret key | 2,574 bytes | 84 |
| Secret key, ML-DSA-65 | The 4,032-byte secret key | 4,046 bytes | 130 |
| Secret key, ML-DSA-87 | The 4,896-byte secret key | 4,910 bytes | 157 |

`generateAndSave()` and `saveSeed()` write a seed record; `saveKeypair()`
writes a secret-key record, because a key that already exists has no seed to
store.

The public key is not stored. Loading derives it: from a seed by generating
the keypair again, from a secret key with `publicKeyFromSecretKey()`, which
also checks that the secret key is well formed. A stored public key that
could disagree with the stored secret key does not exist.

## Why one record

NVS writes a new value before it erases the old one, and replaces one entry
at a time. With the key in one entry, a save that is interrupted or fails
leaves either the previous identity or the new one. With the public and
secret keys in two entries, as version 0.2.0 did, it could leave the public
key of one identity and the secret key of another.

## Loading

1. If `mldsa_key` exists, it is read and checked: magic, format version,
   CRC, lengths, parameter set, content type. A well-formed record of
   another parameter set is reported as such.
2. If there is no record, or it is damaged, the layout of version 0.2.0 is
   tried: entries `pk` and `sk`. They are accepted only if `pk` is the
   public key derived from `sk`.
3. On any failure the output buffers are wiped.

## Saving

1. `saveKeypair()` first checks that the public key given is the one derived
   from the secret key.
2. The number of free NVS entries is checked. Replacing a record needs room
   for the new one while the old one is still there, plus the page NVS
   keeps free (126 entries). If there is not enough, nothing is written and
   the previous key stays in place.

   This check matters: on Arduino-ESP32 2.0.17, a blob write that does not
   fit fails half way, leaves the partition full until NVS is initialised
   again, and was seen to make another entry unreadable. See
   `docs/measurements.md`.
3. The record is written and read back.
4. Entries left by version 0.2.0 are removed.

## Migration from version 0.2.0

Version 0.2.0 stored ML-DSA-44 keys as two entries, `pk` and `sk`. They are
still read. `migrate()` converts them: it validates the pair, writes a
secret-key record, reads it back, and only then removes `pk` and `sk`. If it
is interrupted, the next load finds either the old entries or the new
record. Saving a new key migrates implicitly.

## What NVS does not give you

- **Confidentiality.** NVS is plain flash unless NVS encryption is enabled.
  NVS is not covered by ESP32 flash encryption; it has its own, which must
  be enabled separately. Without it, anyone who can read the flash can read
  the key.
- **Secure erase.** `eraseKeypair()` removes the entry. The bytes stay in
  flash until NVS reuses the page.
