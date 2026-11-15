#!/bin/sh
# Re-vendor the mldsa-native sources into src/.
#
#   scripts/update_mldsa_native.sh <ref>         fetch a tag or commit from GitHub
#   scripts/update_mldsa_native.sh <ref> <dir>   use an existing checkout of it
#
# Copies the portable C implementation (mldsa/src, without the native assembly
# backends), the public header mldsa_native.h and the license. Vendored files
# that upstream no longer has are removed. The result is recorded in
# UPSTREAM.sha256, which scripts/check_upstream.sh verifies.
#
# The port's own files are not touched. In particular
# src/mldsa_native_config.h is the port's configuration: after an update,
# compare it with the new upstream mldsa/mldsa_native_config.h and merge new
# options by hand. Then run test/host/run.sh and update UPSTREAM.md.
#
# The check of the level-dependent sources follows the one in the update
# script of fips204-mldsa-esp32 (Apache-2.0).
#
# SPDX-License-Identifier: Apache-2.0

set -eu

url=https://github.com/pq-code-package/mldsa-native
ref=${1:?usage: $0 <tag-or-commit> [path-to-checkout]}
root=$(cd "$(dirname "$0")/.." && pwd)
manifest="$root/UPSTREAM.sha256"

if [ $# -ge 2 ]; then
  up=$(cd "$2" && pwd)
else
  up=$(mktemp -d)
  trap 'rm -rf "$up"' EXIT
  git init -q "$up"
  git -C "$up" fetch -q --depth 1 "$url" "$ref"
  git -C "$up" checkout -q FETCH_HEAD
fi
[ -f "$up/mldsa/mldsa_native.h" ] || {
  echo "not an mldsa-native checkout: $up" >&2
  exit 1
}
commit=$(git -C "$up" rev-parse HEAD)

# "upstream-path local-path" for every vendored file.
files=$(
  cd "$up"
  for f in mldsa/src/*.c mldsa/src/*.h mldsa/src/*.inc; do
    echo "$f src/${f#mldsa/src/}"
  done
  for f in mldsa/src/fips202/*.c mldsa/src/fips202/*.h; do
    echo "$f src/fips202/${f#mldsa/src/fips202/}"
  done
  echo "mldsa/src/native/api.h src/native/api.h"
  echo "mldsa/src/native/meta.h src/native/meta.h"
  echo "mldsa/src/fips202/native/api.h src/fips202/native/api.h"
  echo "mldsa/src/fips202/native/auto.h src/fips202/native/auto.h"
  echo "mldsa/mldsa_native.h src/mldsa_native.h"
  echo "LICENSE src/LICENSE.mldsa-native"
)

# Drop what the previous import brought in and upstream no longer has.
if [ -f "$manifest" ]; then
  grep -v '^#' "$manifest" | while read -r _ local _; do
    echo "$files" | grep -q " $local\$" || {
      echo "removing $local (no longer upstream)"
      rm -f "$root/$local"
    }
  done
fi

{
  echo "# Files vendored from mldsa-native: sha256, local path, upstream path."
  echo "# Written by scripts/update_mldsa_native.sh; do not edit by hand."
  echo "# ref: $ref"
  echo "# commit: $commit"
  echo "$files" | while read -r upstream local; do
    mkdir -p "$(dirname "$root/$local")"
    cp "$up/$upstream" "$root/$local"
    echo "$(sha256sum "$root/$local" | cut -d' ' -f1)  $local  $upstream"
  done
} > "$manifest.new"
mv "$manifest.new" "$manifest"

# The level-dependent sources must be exactly the ones that mldsa65_build.c
# and mldsa87_build.c include.
dependent=$(grep -L 'MLD_CONFIG_MULTILEVEL_NO_SHARED' "$up"/mldsa/src/*.c |
  xargs -n1 basename | sort | tr '\n' ' ')
for unit in mldsa65_build.c mldsa87_build.c; do
  included=$(sed -n 's/^#include "\(.*\.c\)"$/\1/p' "$root/src/$unit" | sort | tr '\n' ' ')
  if [ "$included" != "$dependent" ]; then
    echo "WARNING: src/$unit includes: $included" >&2
    echo "         level-dependent upstream sources are: $dependent" >&2
  fi
done

echo "vendored mldsa-native $ref ($commit): $(echo "$files" | wc -l) files"
echo "now review: diff -u <upstream>/mldsa/mldsa_native_config.h src/mldsa_native_config.h"
