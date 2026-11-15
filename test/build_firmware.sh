#!/bin/sh
# Firmware build check: compiles the three-variant regression project, the
# example sketches, and the sketches of version 0.2.0 (unchanged, to check
# that old code keeps compiling) for ESP32 (Xtensa) and ESP32-C3 (RISC-V).
#
#   test/build_firmware.sh
#
# Needs PlatformIO (pip install platformio). Nothing is flashed.
#
# SPDX-License-Identifier: Apache-2.0

set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
boards="esp32dev esp32-c3-devkitm-1"
# lilygo-t-display-S3 is left out: it needs the TFT_eSPI library and a board
# specific display configuration.
examples="mldsa_simple mldsa_demo_arduino mldsa_nvs_storage mldsa_random_source mldsa_test_vectors"

log=$(mktemp)
trap 'rm -f "$log"' EXIT

# Run a build quietly; show its output only if it fails.
build() {
  echo "== $1"
  shift
  if ! "$@" > "$log" 2>&1; then
    tail -n 60 "$log"
    echo "FAILED"
    exit 1
  fi
}

for board in $boards; do
  build "test/build_variants for $board" \
    pio run -d "$root/test/build_variants" -e "$board"
done

for example in $examples; do
  for board in $boards; do
    build "examples/$example for $board" \
      pio ci "$root/examples/$example" --lib "$root/src" --board "$board"
  done
done

for sketch in "$root"/test/compat_0_2_0/*/; do
  for board in $boards; do
    build "0.2.0 sketch $(basename "$sketch") for $board" \
      pio ci "$sketch" --lib "$root/src" --board "$board"
  done
done

echo "FIRMWARE BUILDS PASSED"
