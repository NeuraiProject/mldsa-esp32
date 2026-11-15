#!/bin/sh
# Host test suite for Linux.
#
# Builds the library sources with a test-only random source, under
# AddressSanitizer and UndefinedBehaviorSanitizer, and runs:
#
#   1. smoke         round trips through the three wrapper classes
#   2. link checks   each variant alone, and the three together
#   3. acvp          every NIST ACVP keyGen/sigGen/sigVer case, plus randomized
#                    round trips and boundary cases
#   4. compat        the C API as sketches written for 0.2.0 call it
#   5. rng           the random source: registration, failure, wiping; and
#                    the machine code of a wipe done with secureZero()
#   6. nvs           the NVS key storage helpers against a mock, with every
#                    save, migration and erase cut off at each step
#   7. symbols       the code shared by the parameter sets exists once, and
#                    the library does not define the generic randombytes()
#   8. alloc faults  every allocation made to fail in turn
#   9. stack build   the acvp run again with the working memory on the
#                    stack (MLDSA_ESP32_USE_STACK)
#  10. upstream      the vendored mldsa-native files are untouched
#
#   test/host/run.sh [build-dir]
#
# Step 3 needs python3 and, the first time, network access to download the
# NIST vectors at the commit pinned in scripts/gen_acvp_vectors.py.
#
# SPDX-License-Identifier: Apache-2.0

set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)

if [ $# -ge 1 ]; then
  out=$1
  mkdir -p "$out"
else
  out=$(mktemp -d)
  trap 'rm -rf "$out"' EXIT
fi

cc=${CC:-cc}
cxx=${CXX:-c++}
flags="-O2 -g -fsanitize=address,undefined -fno-sanitize-recover=undefined"
cxxflags="-std=gnu++11 $flags -I$root/src"

step() { printf '\n== %s\n' "$1"; }

# Compile the library into $1 with extra flags $2; the object list is left
# in $built. src/esp32/ needs the ESP32 SDK: rng_host.c and alloc_host.c
# replace it here.
build_library() {
  mkdir -p "$1"
  built=""
  for src in $(find "$root/src" -name '*.c' ! -path '*/esp32/*' | sort); do
    obj="$1/$(echo "${src#"$root"/}" | tr '/' '_').o"
    $cc $flags $2 -I"$root/src" -c "$src" -o "$obj"
    built="$built $obj"
  done
  for src in "$here/rng_host.c" "$here/alloc_host.c"; do
    obj="$1/$(basename "$src" .c).o"
    $cc $flags -I"$root/src" -c "$src" -o "$obj"
    built="$built $obj"
  done
}

step "build library"
build_library "$out/default" ""
objs=$built

step "smoke"
$cxx $cxxflags "$here/smoke.cpp" $objs -o "$out/smoke"
"$out/smoke"

step "link checks"
for combo in "44" "65" "87" "44 65 87"; do
  defs=""
  for level in $combo; do defs="$defs -DUSE_$level"; done
  $cxx $cxxflags $defs "$here/link_check.cpp" $objs -o "$out/link_check"
  echo "  [PASS] links with: $combo"
done

step "acvp"
python3 "$root/scripts/gen_acvp_vectors.py" --all --full-expected \
  --out "$out/acvp_all.h"
$cxx $cxxflags -I"$out" -I"$root/examples/mldsa_test_vectors" \
  "$here/acvp_main.cpp" $objs -o "$out/acvp"
"$out/acvp"

step "compat"
$cxx $cxxflags "$here/compat_test.cpp" $objs -o "$out/compat_test"
"$out/compat_test"

step "rng"
$cxx $cxxflags "$here/rng_test.cpp" $objs -o "$out/rng_test"
"$out/rng_test"

# Compiled like firmware, optimized and without sanitizers, then inspected.
${WIPE_CXX:-$cxx} -std=gnu++11 ${WIPE_FLAGS:--O2} -I"$root/src" -c "$here/wipe_check.cpp" -o "$out/wipe_check.o"
body() { ${WIPE_OBJDUMP:-objdump} -dr "$out/wipe_check.o" | awk "/<$1>:/{on=1;next} /^\$/{on=0} on"; }
if body wipe_with_secure_zero | grep -q mldsa_esp32_secure_zero; then
  echo "  [PASS] the secureZero() wipe is in the machine code"
else
  echo "  [FAIL] the secureZero() wipe was optimized away"
  exit 1
fi
if body wipe_with_memset | grep -q memset; then
  echo "  [note] this compiler kept the memset() wipe"
else
  echo "  [note] this compiler removed the memset() wipe, as expected"
fi

step "nvs"
$cxx $cxxflags -I"$here/mock" "$here/nvs_test.cpp" $objs -o "$out/nvs_test"
"$out/nvs_test"

step "symbols"
shared=$(nm "$out/smoke" | grep -c ' T PQCP_MLDSA_NATIVE_MLDSA_' || true)
suffixed=$(nm "$out/smoke" |
  grep -cE ' T PQCP_MLDSA_NATIVE_MLDSA(44|65|87)_(shake|sha3|keccak)' || true)
echo "shared symbols: $shared, level-suffixed copies of shared code: $suffixed"
if [ "$shared" -eq 0 ] || [ "$suffixed" -ne 0 ]; then
  echo "FAILED: shared code is not emitted exactly once"
  exit 1
fi
if nm "$out/smoke" | grep -q ' [TtWw] randombytes$'; then
  echo "FAILED: the library defines the generic symbol randombytes"
  exit 1
fi
echo "no generic randombytes symbol"

step "alloc faults"
$cxx $cxxflags "$here/alloc_fault.cpp" $objs -o "$out/alloc_fault"
"$out/alloc_fault"

step "stack build"
build_library "$out/stack" "-DMLDSA_ESP32_USE_STACK"
$cxx $cxxflags -DMLDSA_ESP32_USE_STACK -I"$out" -I"$root/examples/mldsa_test_vectors" \
  "$here/acvp_main.cpp" $built -o "$out/acvp_stack"
"$out/acvp_stack"

step "upstream"
"$root/scripts/check_upstream.sh"

printf '\nHOST TESTS PASSED\n'
