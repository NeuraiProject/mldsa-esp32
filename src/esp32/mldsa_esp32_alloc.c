/*
 * mldsa_esp32_alloc.c - working memory from the ESP32 heap
 *
 * Used unless the library is built with MLDSA_ESP32_USE_STACK; see
 * mldsa_native_config.h. Blocks come from internal RAM: they hold secret
 * material, which should not sit in external PSRAM. The core wipes every
 * block before it calls mldsa_esp32_free().
 *
 * With MLDSA_ESP32_ALLOC_STATS the peak number of bytes in use is tracked,
 * for measurements. The counters are not safe to read while another task is
 * inside the library.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>

#include <esp_heap_caps.h>

/* The core aligns its buffers to MLD_DEFAULT_ALIGN (32). */
#define MLDSA_ESP32_ALIGN 32

#if defined(MLDSA_ESP32_ALLOC_STATS)
static size_t in_use, peak;

size_t mldsa_esp32_alloc_peak(void) { return peak; }
void mldsa_esp32_alloc_reset_peak(void) { peak = in_use; }
#endif

void *mldsa_esp32_alloc(size_t size) {
  void *ptr = heap_caps_aligned_alloc(MLDSA_ESP32_ALIGN, size,
                                      MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
#if defined(MLDSA_ESP32_ALLOC_STATS)
  if (ptr != NULL) {
    in_use += heap_caps_get_allocated_size(ptr);
    if (in_use > peak) {
      peak = in_use;
    }
  }
#endif
  return ptr;
}

void mldsa_esp32_free(void *ptr) {
#if defined(MLDSA_ESP32_ALLOC_STATS)
  if (ptr != NULL) {
    in_use -= heap_caps_get_allocated_size(ptr);
  }
#endif
  heap_caps_free(ptr);
}
