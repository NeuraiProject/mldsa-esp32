/*
 * mldsa_native_all.h - the C API of ML-DSA-44, ML-DSA-65 and ML-DSA-87
 *
 * mldsa_native.h declares one parameter set per inclusion: the one named by
 * MLD_CONFIG_PARAMETER_SET, ML-DSA-44 by default. This header includes it
 * once for each parameter set, so that all of these are declared:
 *
 *   PQCP_MLDSA_NATIVE_MLDSA44_keypair, PQCP_MLDSA_NATIVE_MLDSA65_keypair,
 *   PQCP_MLDSA_NATIVE_MLDSA87_keypair, and so on for the rest of the API.
 *
 * Most sketches should use the MLDSA44, MLDSA65 and MLDSA87 classes instead.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef MLDSA_NATIVE_ALL_H
#define MLDSA_NATIVE_ALL_H

/* The value the includer had, if any, is restored at the end. */
#pragma push_macro("MLD_CONFIG_PARAMETER_SET")

#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H
#define MLD_CONFIG_PARAMETER_SET 44
#include "mldsa_native.h"

#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H
#define MLD_CONFIG_PARAMETER_SET 65
#include "mldsa_native.h"

#undef MLD_CONFIG_PARAMETER_SET
#undef MLD_H
#define MLD_CONFIG_PARAMETER_SET 87
#include "mldsa_native.h"

#undef MLD_CONFIG_PARAMETER_SET
#pragma pop_macro("MLD_CONFIG_PARAMETER_SET")

#endif /* MLDSA_NATIVE_ALL_H */
