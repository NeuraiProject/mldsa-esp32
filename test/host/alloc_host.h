/*
 * Controls of the test-only allocator in alloc_host.c.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ALLOC_HOST_H
#define ALLOC_HOST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Start counting again. fail_on_call = n makes the n-th allocation from now
 * fail; 0 lets all of them succeed. */
void alloc_host_reset(int fail_on_call);
/* Allocations requested since the last reset, failed one included. */
int alloc_host_calls(void);
/* Blocks handed out and not yet freed. */
int alloc_host_outstanding(void);
/* Most bytes in use at once since the last reset. */
size_t alloc_host_peak(void);

#ifdef __cplusplus
}
#endif

#endif /* ALLOC_HOST_H */
