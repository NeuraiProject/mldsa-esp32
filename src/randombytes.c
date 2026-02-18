/*
 * randombytes.c - ESP32 hardware RNG implementation for mldsa-native
 *
 * Uses esp_fill_random() which sources entropy from the ESP32's
 * true random number generator (TRNG). Full entropy is available
 * when WiFi or Bluetooth is active; otherwise a pseudo-random
 * source seeded from hardware noise is used.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "randombytes.h"
#include <esp_system.h>
#include <esp_random.h>
#include <string.h>

int randombytes(uint8_t *out, size_t outlen) {
    if (out == NULL || outlen == 0) {
        return 0;
    }

    /* Pre-fill with a known pattern so we can detect if
     * esp_fill_random() did not write anything at all. */
    memset(out, 0xAA, outlen);

    esp_fill_random(out, outlen);

    /* Sanity check: verify the buffer was actually modified.
     * If it still matches the pre-fill pattern, the RNG likely
     * failed silently. Check the first few bytes as a heuristic. */
    size_t check_len = outlen < 4 ? outlen : 4;
    uint8_t pattern_match = 1;
    for (size_t i = 0; i < check_len; i++) {
        if (out[i] != 0xAA) {
            pattern_match = 0;
            break;
        }
    }

    if (pattern_match) {
        /* All checked bytes still 0xAA -- highly unlikely with a
         * working RNG (probability: 1/2^32 for 4 bytes).
         * Attempt a second fill as a retry. */
        esp_fill_random(out, outlen);

        pattern_match = 1;
        for (size_t i = 0; i < check_len; i++) {
            if (out[i] != 0xAA) {
                pattern_match = 0;
                break;
            }
        }

        if (pattern_match) {
            /* Two consecutive fills produced no change -- RNG failure. */
            memset(out, 0, outlen);
            return -1;
        }
    }

    return 0;
}
