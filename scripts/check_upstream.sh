#!/bin/sh
# Check that the vendored mldsa-native code is untouched.
#
#   scripts/check_upstream.sh            every vendored file still has the hash
#                                        recorded in UPSTREAM.sha256, and src/
#                                        holds nothing but those files and the
#                                        port's own
#   scripts/check_upstream.sh --online   also fetch the recorded commit from
#                                        GitHub and compare with the real files
#
# SPDX-License-Identifier: Apache-2.0

set -eu

url=https://github.com/pq-code-package/mldsa-native
root=$(cd "$(dirname "$0")/.." && pwd)
manifest="$root/UPSTREAM.sha256"
commit=$(sed -n 's/^# commit: //p' "$manifest")
status=0

# Files in src/ that belong to the port, not to upstream.
port_files="
src/mldsa_native_config.h
src/mldsa65_build.c
src/mldsa87_build.c
src/mldsa_esp32.c
src/mldsa_esp32.h
src/esp32/mldsa_esp32_alloc.c
src/esp32/mldsa_esp32_rng.c
src/mldsa_compat.h
src/mldsa_native_all.h
src/MLDSA.h
src/MLDSA44.h
src/MLDSA65.h
src/MLDSA87.h
src/MLDSA_NVS.h
src/MLDSA44_NVS.h
src/MLDSA65_NVS.h
src/MLDSA87_NVS.h
"

up=""
if [ "${1:-}" = "--online" ]; then
  up=$(mktemp -d)
  trap 'rm -rf "$up"' EXIT
  git init -q "$up"
  git -C "$up" fetch -q --depth 1 "$url" "$commit"
  git -C "$up" checkout -q FETCH_HEAD
fi

grep -v '^#' "$manifest" > "$root/.upstream-check.tmp"
while read -r hash local upstream; do
  if [ ! -f "$root/$local" ]; then
    echo "MISSING   $local"
    status=1
  elif [ "$(sha256sum "$root/$local" | cut -d' ' -f1)" != "$hash" ]; then
    echo "MODIFIED  $local"
    status=1
  elif [ -n "$up" ] &&
    [ "$(sha256sum "$up/$upstream" | cut -d' ' -f1)" != "$hash" ]; then
    echo "DIFFERS FROM UPSTREAM  $local ($upstream at $commit)"
    status=1
  fi
done < "$root/.upstream-check.tmp"

for f in $(cd "$root" && find src -type f | sort); do
  grep -q "  $f  " "$root/.upstream-check.tmp" && continue
  echo "$port_files" | grep -qx "$f" && continue
  echo "UNLISTED  $f (neither vendored nor a known port file)"
  status=1
done
rm -f "$root/.upstream-check.tmp"

count=$(grep -vc '^#' "$manifest")
if [ $status -eq 0 ]; then
  echo "vendored code matches mldsa-native $commit ($count files${up:+, checked against GitHub})"
fi
exit $status
