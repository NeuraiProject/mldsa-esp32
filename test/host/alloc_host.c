/*
 * Test-only allocator for Linux builds of the library.
 *
 * Stands in for src/esp32/mldsa_esp32_alloc.c. It counts allocations and
 * can be told to fail one of them, to test the out-of-memory paths.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stddef.h>
#include <stdlib.h>

#include "alloc_host.h"

static int calls;       /* allocations requested since the last reset */
static int fail_on;     /* this allocation fails (1 = the next one); 0 = never */
static int outstanding; /* blocks handed out and not yet freed */
static size_t in_use, peak;

void alloc_host_reset(int fail_on_call) {
  calls = 0;
  fail_on = fail_on_call;
  peak = in_use;
}

int alloc_host_calls(void) { return calls; }
int alloc_host_outstanding(void) { return outstanding; }
size_t alloc_host_peak(void) { return peak; }

/* Each block is preceded by its size, in a header as wide as the alignment. */
#define ALIGN 32

void *mldsa_esp32_alloc(size_t size) {
  size_t total = ALIGN + ((size + ALIGN - 1) / ALIGN) * ALIGN;
  size_t *block;
  calls++;
  if (fail_on != 0 && calls == fail_on) {
    return NULL;
  }
  block = (size_t *)aligned_alloc(ALIGN, total);
  if (block == NULL) {
    return NULL;
  }
  block[0] = size;
  outstanding++;
  in_use += size;
  if (in_use > peak) {
    peak = in_use;
  }
  return (unsigned char *)block + ALIGN;
}

void mldsa_esp32_free(void *ptr) {
  size_t *block;
  if (ptr == NULL) {
    return;
  }
  block = (size_t *)((unsigned char *)ptr - ALIGN);
  outstanding--;
  in_use -= block[0];
  free(block);
}
