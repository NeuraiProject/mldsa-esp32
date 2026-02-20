/*
 * mldsa87_build.c - ML-DSA-87 level-specific compilation unit
 *
 * This file compiles the ML-DSA-87 level-dependent code as a single
 * translation unit alongside the default level-44 and level-65 builds.
 *
 * Mechanism:
 *   - MLD_CONFIG_NAMESPACE_PREFIX=PQCP_MLDSA_NATIVE_MLDSA sets the base
 *     prefix without the level number. MLD_ADD_PARAM_SET() then appends "87",
 *     yielding PQCP_MLDSA_NATIVE_MLDSA87_keypair etc. (the expected API names).
 *     Without this override the default prefix already contains "MLDSA87",
 *     which would cause double-suffixing: PQCP_MLDSA_NATIVE_MLDSA8787_keypair.
 *   - MLD_CONFIG_PARAMETER_SET=87 selects the ML-DSA-87 parameter set
 *     (K=8, L=7, ETA=2, GAMMA1=2^19, PK=2592, SK=4896, SIG=4627 bytes)
 *   - MLD_CONFIG_MULTILEVEL_NO_SHARED activates MLD_ADD_PARAM_SET(), which
 *     renames all level-dependent symbols with the "87" suffix, avoiding
 *     conflicts with the level-44 and level-65 symbols.
 *   - Shared code (poly.c, fips202.c, ct.c, keccakf1600.c) is NOT included
 *     here; it is compiled once by Arduino from those individual files.
 *   - MLD_BUILD_INTERNAL exposes build-only config options (REDUCE_RAM, etc.)
 *
 * NOTE: ML-DSA-87 sign requires ~59KB of working memory with REDUCE_RAM.
 *       Use a FreeRTOS task with at least 80KB stack on ESP32.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define MLD_BUILD_INTERNAL
#define MLD_CONFIG_NAMESPACE_PREFIX PQCP_MLDSA_NATIVE_MLDSA
#define MLD_CONFIG_PARAMETER_SET 87
#define MLD_CONFIG_MULTILEVEL_NO_SHARED

/*
 * Include the level-dependent implementation files.
 * These use MLD_ADD_PARAM_SET() to suffix their exported symbols with "87".
 * Shared FIPS202 / polynomial arithmetic are already compiled separately.
 */
#include "sign.c"
#include "poly_kl.c"
#include "packing.c"
#include "polyvec.c"
