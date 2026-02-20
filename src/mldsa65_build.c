/*
 * mldsa65_build.c - ML-DSA-65 level-specific compilation unit
 *
 * This file compiles the ML-DSA-65 level-dependent code as a single
 * translation unit alongside the default level-44 and level-87 builds.
 *
 * Mechanism:
 *   - MLD_CONFIG_NAMESPACE_PREFIX=PQCP_MLDSA_NATIVE_MLDSA sets the base
 *     prefix without the level number. MLD_ADD_PARAM_SET() then appends "65",
 *     yielding PQCP_MLDSA_NATIVE_MLDSA65_keypair etc. (the expected API names).
 *     Without this override the default prefix already contains "MLDSA65",
 *     which would cause double-suffixing: PQCP_MLDSA_NATIVE_MLDSA6565_keypair.
 *   - MLD_CONFIG_PARAMETER_SET=65 selects the ML-DSA-65 parameter set
 *     (K=6, L=5, ETA=4, GAMMA1=2^19, PK=1952, SK=4032, SIG=3309 bytes)
 *   - MLD_CONFIG_MULTILEVEL_NO_SHARED activates MLD_ADD_PARAM_SET(), which
 *     renames all level-dependent symbols with the "65" suffix, avoiding
 *     conflicts with the level-44 symbols from the direct .c file compiles.
 *   - Shared code (poly.c, fips202.c, ct.c, keccakf1600.c) is NOT included
 *     here; it is compiled once by Arduino from those individual files.
 *   - MLD_BUILD_INTERNAL exposes build-only config options (REDUCE_RAM, etc.)
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define MLD_BUILD_INTERNAL
#define MLD_CONFIG_NAMESPACE_PREFIX PQCP_MLDSA_NATIVE_MLDSA
#define MLD_CONFIG_PARAMETER_SET 65
#define MLD_CONFIG_MULTILEVEL_NO_SHARED

/*
 * Include the level-dependent implementation files.
 * These use MLD_ADD_PARAM_SET() to suffix their exported symbols with "65".
 * Shared FIPS202 / polynomial arithmetic are already compiled separately.
 */
#include "sign.c"
#include "poly_kl.c"
#include "packing.c"
#include "polyvec.c"
