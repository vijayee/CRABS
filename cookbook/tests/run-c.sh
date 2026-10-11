#!/usr/bin/env bash
# Compiles and runs every cookbook C snippet against the built `crabs` library.
# Pass = the snippet compiles with -Werror and exits 0 at runtime.
set -euo pipefail
cd "$(dirname "$0")/../.."

BUILD_DIR=build
SNIPPETS=cookbook/snippets/c
OUT=cookbook/snippets/.c-out
mkdir -p "$OUT"

cmake -S . -B "$BUILD_DIR" >/dev/null
cmake --build "$BUILD_DIR" -j >/dev/null

for snippet in "$SNIPPETS"/*.c; do
  name=$(basename "$snippet" .c)
  cc -std=c11 -Wall -Werror \
    -I src -I deps/openabe-c/include \
    "$snippet" build/libcrabs.a \
    deps/openabe-c/build/liboabe_c.a \
    deps/openabe-c/deps/relic/build/lib/librelic_s.a \
    -lgmp -lpthread -lssl -lcrypto \
    -o "$OUT/$name"
  if ! "$OUT/$name"; then
    echo "FAILED: $snippet (runtime)"; exit 1
  fi
  echo "OK: $snippet"
done
echo 'All C snippets passed.'