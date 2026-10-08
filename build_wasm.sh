#!/bin/bash
#
# build_wasm.sh — Cross-compile CRABS to WebAssembly.
#
# Links against the WASM-built RELIC and OpenABE static libraries from
# the openabe-to-c project. Produces crabs.wasm + crabs.js.
#
# Usage:
#   source /home/victor/emsdk/emsdk_env.sh
#   ./build_wasm.sh
#
set -e

ROOT_DIR="$(cd "$(dirname "$0")" && pwd)"
OPENABE_DIR="${OPENABE_DIR:-/home/victor/Workspace/src/github.com/vijayee/openabe-to-c/openabe-c}"
RELIC_WASM="$OPENABE_DIR/deps/relic/build-wasm"
OPENABE_WASM="$OPENABE_DIR/build-wasm"
OPENSSL_SRC="${OPENSSL_SRC:-/tmp/openssl-3.4.0}"
OPENSSL_WASM_LIB="$OPENSSL_SRC"
BUILD_DIR="$ROOT_DIR/build-wasm"

echo "=== CRABS WASM Build ==="
echo "  Root: $ROOT_DIR"
echo "  OpenABE: $OPENABE_DIR"
echo ""

# Verify dependencies exist
if [ ! -f "$RELIC_WASM/lib/librelic_s.a" ]; then
  echo "ERROR: RELIC WASM build not found at $RELIC_WASM/lib/librelic_s.a"
  echo "Run the openabe-to-c build_wasm.sh first."
  exit 1
fi
if [ ! -f "$OPENABE_WASM/liboabe_c_wasm.a" ]; then
  echo "ERROR: OpenABE WASM build not found at $OPENABE_WASM/liboabe_c_wasm.a"
  echo "Run the openabe-to-c build_wasm.sh first."
  exit 1
fi

rm -rf "$BUILD_DIR" "$BUILD_DIR.dev"
mkdir -p "$BUILD_DIR"

CRABS_SRCS=$(find "$ROOT_DIR/src" -name '*.c' | sort)
INCLUDES="-I$ROOT_DIR/src -I$OPENABE_DIR/include -I$RELIC_WASM/include -I$OPENABE_DIR/deps/relic/include -I$OPENSSL_SRC/include"
CFLAGS="-std=c11 -O2 -DWITH_RELIC -DBP_WITH_OPENSSL -D_POSIX_C_SOURCE=200809L -include strings.h -D__GLIBC_PREREQ\(x,y\)=0 -fPIC"

BASE_EXPORTS='[
  "_crypto_ecdsa_generate",
  "_crypto_ecdsa_sign",
  "_crypto_ecdsa_verify",
  "_crypto_ecdsa_keypair_destroy",
  "_crypto_ecdsa_derive_public_key",
  "_crypto_ecdsa_validate_public_key",
  "_crypto_sha256",
  "_crypto_random_bytes",
  "_crypto_abe_setup",
  "_crypto_abe_master_key_destroy",
  "_crypto_abe_keygen",
  "_crypto_abe_user_key_destroy",
  "_crypto_abe_encrypt",
  "_crypto_abe_decrypt",
  "_crypto_abe_ciphertext_destroy",
  "_crypto_abe_ciphertext_get_policy",
  "_crypto_abe_ciphertext_get_data",
  "_crypto_abe_user_key_serialize",
  "_crypto_abe_user_key_deserialize",
  "_crypto_sign_operation",
  "_crypto_verify_operation",
  "_crypto_key_envelope_create",
  "_crypto_key_envelope_destroy",
  "_crypto_key_envelope_verify",
  "_crypto_key_envelope_serialize",
  "_crypto_key_envelope_deserialize",
  "_crypto_key_envelope_decrypt_sk",
  "_crypto_compute_attributes_hash",
  "_crypto_revoke_and_rotate",
  "_crypto_recovery_result_destroy",
  "_attribute_machine_create",
  "_attribute_machine_destroy",
  "_attribute_machine_register_user",
  "_attribute_machine_grant_role",
  "_attribute_machine_self_assert",
  "_attribute_machine_verify_identity",
  "_attribute_machine_revoke_role",
  "_attribute_machine_suspend_user",
  "_attribute_machine_revoke_user",
  "_attribute_machine_find_user",
  "_attribute_machine_user_has_role",
  "_attribute_machine_set_time",
  "_attribute_machine_prune_expired_temporary",
  "_attribute_machine_issue_temporary",
  "_state_create",
  "_state_destroy",
  "_state_add_item",
  "_state_find_item",
  "_state_add_policy",
  "_state_find_policy",
  "_state_set_node_key",
  "_state_machine_execute",
  "_operation_create",
  "_operation_destroy",
  "_crabs_serialize_for_signing",
  "_crabs_serialize_state",
  "_serialized_buffer_destroy",
  "_malloc",
  "_free",
  "_crabs_wasm_register_handler",
  "_crabs_wasm_unregister_handler",
  "_crabs_wasm_handler_get_am",
  "_crabs_wasm_handler_op_get_payload_str",
  "_crabs_wasm_schedule",
  "_crabs_wasm_schedule_recurring",
  "_crabs_wasm_cancel_schedule",
  "_crabs_wasm_process_schedules",
  "_crabs_wasm_schedule_count",
  "_crabs_wasm_schedule_first",
  "_crabs_wasm_schedule_next",
  "_crabs_wasm_schedule_id",
  "_crabs_wasm_set_change_trampoline",
  "_crabs_wasm_set_schedule_occurrence_budget",
  "_crabs_wasm_schedule_occurrence_budget",
  "_crabs_wasm_schedule_execute_at",
  "_crabs_wasm_schedule_submitter",
  "_crabs_wasm_schedule_interval",
  "_crabs_wasm_schedule_repeat_count",
  "_crabs_wasm_schedule_end_at",
  "_crabs_time_source_https_create",
  "_crabs_time_source_https_create_with_transport",
  "_crabs_time_source_destroy",
  "_crabs_wasm_set_time_source",
  "_crabs_wasm_time_source_attached",
  "_crabs_wasm_lineage_blueprint_new",
  "_crabs_wasm_lineage_blueprint_destroy",
  "_crabs_wasm_lineage_blueprint_add_item",
  "_crabs_wasm_lineage_blueprint_add_policy",
  "_crabs_wasm_lineage_blueprint_stamp_hash",
  "_crabs_wasm_lineage_blueprint_serialize",
  "_crabs_wasm_lineage_blueprint_deserialize",
  "_crabs_wasm_lineage_spawn",
  "_crabs_wasm_lineage_query_resident_child",
  "_crabs_wasm_lineage_children_count",
  "_crabs_wasm_lineage_children_get_id",
  "_crabs_wasm_lineage_children_get_mode",
  "_crabs_wasm_lineage_children_get_status",
  "_crabs_wasm_lineage_children_get_ttl_ms",
  "_crabs_wasm_lineage_children_get_spawned_at",
  "_crabs_wasm_lineage_attest",
  "_crabs_wasm_lineage_tombstone",
  "_crabs_wasm_lineage_find_manifest_entry",
  "_crabs_wasm_register_lineage_ops"
]'

DEVTOOLS_EXPORTS='[
  "_crabs_wasm_devtools_snapshot",
  "_crabs_wasm_devtools_drain_events",
  "_crabs_wasm_devtools_drain_events_for",
  "_crabs_wasm_devtools_string_destroy"
]'

build_variant() {
  VARIANT_SUFFIX="$1"   # "" for production, ".dev" for devtools build
  EXTRA_DEFINES="$2"    # "" or "-DCRABS_ENABLE_DEVTOOLS"
  EXPORT_NAME="$3"
  EXPORTS_JSON="$4"

  VARIANT_DIR="$BUILD_DIR$VARIANT_SUFFIX"
  mkdir -p "$VARIANT_DIR"

  echo "Compiling CRABS sources (variant: ${VARIANT_SUFFIX:-prod})..."
  OBJECTS=""
  for src in $CRABS_SRCS; do
    obj="$VARIANT_DIR/$(basename ${src%.c}).o"
    emcc $CFLAGS $EXTRA_DEFINES $INCLUDES -c "$src" -o "$obj" 2>&1
    OBJECTS="$OBJECTS $obj"
  done

  echo "Linking WASM module (${VARIANT_SUFFIX:-prod})..."
  emcc $CFLAGS $EXTRA_DEFINES \
    $OBJECTS \
    "$OPENABE_WASM/liboabe_c_wasm.a" \
    "$RELIC_WASM/lib/librelic_s.a" \
    "$OPENSSL_WASM_LIB/libcrypto.a" \
    "$OPENSSL_WASM_LIB/libssl.a" \
    -o "$VARIANT_DIR/crabs$VARIANT_SUFFIX.js" \
    -s WASM=1 \
    -s MODULARIZE=1 \
    -s EXPORT_NAME="$EXPORT_NAME" \
    -s ALLOW_TABLE_GROWTH=1 \
    -s ALLOW_MEMORY_GROWTH=1 \
    -s INITIAL_MEMORY=64MB \
    -s EXPORTED_FUNCTIONS="$EXPORTS_JSON" \
    -s EXPORTED_RUNTIME_METHODS='["ccall","cwrap","getValue","setValue","UTF8ToString","stringToUTF8","lengthBytesUTF8","addFunction","removeFunction","HEAP8","HEAPU8","HEAP16","HEAPU16","HEAP32","HEAPU32","HEAPF32","HEAPF64"]' \
    --js-library "$ROOT_DIR/src/TimeSource/wasm_time_library.js" \
    -O2 \
    2>&1
}

build_variant "" "" "createCRABSModule" "$BASE_EXPORTS"
# Merge the two JSON arrays into one (emcc's -s parser splits on commas and
# cannot handle a "],[" junction between the lists).
build_variant ".dev" "-DCRABS_ENABLE_DEVTOOLS" "createCRABSModuleDev" "${BASE_EXPORTS%]},${DEVTOOLS_EXPORTS#[}"

echo ""
echo "=== CRABS WASM Build Complete ==="
ls -lh "$BUILD_DIR"/crabs*.js "$BUILD_DIR"/crabs*.wasm \
       "$BUILD_DIR.dev"/crabs*.js "$BUILD_DIR.dev"/crabs*.wasm 2>/dev/null
