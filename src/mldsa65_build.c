/*
 * mldsa65_build.c - ML-DSA-65 level-specific compilation unit
 *
 * This file compiles the ML-DSA-65 level-dependent code as a single
 * translation unit alongside the default level-44 and level-87 builds.
 *
 * Mechanism:
 *   - mldsa_native_config.h configures a multi-level build. The namespace
 *     prefix is PQCP_MLDSA_NATIVE_MLDSA: level-dependent symbols get the
 *     parameter set appended (PQCP_MLDSA_NATIVE_MLDSA65_keypair) and shared
 *     symbols do not (PQCP_MLDSA_NATIVE_MLDSA_shake256_init).
 *   - MLD_CONFIG_PARAMETER_SET=65 selects the ML-DSA-65 parameter set
 *     (K=6, L=5, ETA=4, GAMMA1=2^19, PK=1952, SK=4032, SIG=3309 bytes)
 *   - MLD_CONFIG_MULTILEVEL_NO_SHARED leaves the shared code (polynomial
 *     arithmetic, FIPS 202) out of this unit. It is emitted once, by the
 *     default level-44 compilation of the individual source files, which
 *     builds with MLD_CONFIG_MULTILEVEL_WITH_SHARED.
 *
 * The files included below are the level-dependent ones: those that
 * upstream does not guard with MLD_CONFIG_MULTILEVEL_NO_SHARED.
 * scripts/update_mldsa_native.sh warns if that set changes.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#define MLD_CONFIG_PARAMETER_SET 65
#define MLD_CONFIG_MULTILEVEL_NO_SHARED

#include "packing.c"
#include "poly_kl.c"
#include "polyvec.c"
#include "polyvec_lazy.c"
#include "sign.c"
