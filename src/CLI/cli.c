//
// Created by victor on 5/1/25.
//

#include "cli.h"
#include "../Util/allocator.h"
#include "../Serialization/serialization.h"
#include "../Compaction/compaction_engine.h"
#include "../Compaction/crdt_compaction.h"
#include <openssl/crypto.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// ============================================================
// Hex encode/decode utilities
// ============================================================

static int _hex_val(char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

cli_result_e cli_hex_to_bytes(const char* hex, uint8_t* out, size_t out_len) {
  if (hex == NULL || out == NULL) return CLI_ERR_ARGS;
  size_t hex_len = strlen(hex);
  if (hex_len != out_len * 2) return CLI_ERR_ARGS;
  for (size_t i = 0; i < out_len; i++) {
    int hi = _hex_val(hex[i * 2]);
    int lo = _hex_val(hex[i * 2 + 1]);
    if (hi < 0 || lo < 0) return CLI_ERR_ARGS;
    out[i] = (uint8_t)((hi << 4) | lo);
  }
  return CLI_OK;
}

void cli_bytes_to_hex(const uint8_t* bytes, size_t len, char* out) {
  static const char hex_chars[] = "0123456789abcdef";
  for (size_t i = 0; i < len; i++) {
    out[i * 2]     = hex_chars[(bytes[i] >> 4) & 0x0F];
    out[i * 2 + 1] = hex_chars[bytes[i] & 0x0F];
  }
  out[len * 2] = '\0';
}

// ============================================================
// Error and state string utilities
// ============================================================

const char* cli_error_string(crabs_error_e err) {
  switch (err) {
    case CRABS_SUCCESS:                    return "success";
    case CRABS_ERR_PROTOCOL_VIOLATION:     return "protocol_violation";
    case CRABS_ERR_LOCK_TOKEN_MISMATCH:    return "lock_token_mismatch";
    case CRABS_ERR_LOCK_OWNER_MISMATCH:    return "lock_owner_mismatch";
    case CRABS_ERR_LOCK_CONTENTION:        return "lock_contention";
    case CRABS_ERR_LOCK_NOT_EXPIRED:       return "lock_not_expired";
    case CRABS_ERR_MAX_EXTENSIONS_REACHED: return "max_extensions_reached";
    case CRABS_ERR_FORCE_UNLOCK_DISABLED:  return "force_unlock_disabled";
    case CRABS_ERR_UNAUTHORIZED:           return "unauthorized";
    case CRABS_ERR_KEY_STALE:             return "key_stale";
    case CRABS_ERR_USER_NOT_FOUND:        return "user_not_found";
    case CRABS_ERR_USER_SUSPENDED:        return "user_suspended";
    case CRABS_ERR_INVARIANT_VIOLATED:    return "invariant_violated";
    case CRABS_ERR_RESOURCE_NOT_FOUND:    return "resource_not_found";
    case CRABS_ERR_DUPLICATE_OPERATION:   return "duplicate_operation";
    case CRABS_ERR_TYPE_MISMATCH:        return "type_mismatch";
    case CRABS_ERR_ALREADY_PERFORMED:    return "already_performed";
    case CRABS_ERR_ALREADY_EXECUTED:     return "already_executed";
    case CRABS_ERR_CONDITION_NOT_MET:    return "condition_not_met";
    case CRABS_ERR_TRACKER_NOT_FOUND:    return "tracker_not_found";
    case CRABS_ERR_FLAG_NOT_FOUND:       return "flag_not_found";
    case CRABS_ERR_SERIALIZATION_ERROR:   return "serialization_error";
    case CRABS_ERR_CRYPTOGRAPHIC_ERROR:   return "cryptographic_error";
    case CRABS_ERR_INTERNAL:              return "internal_error";
    case CRABS_ERR_OOM:                   return "out_of_memory";
    case CRABS_ERR_INVALID_PARAM:         return "invalid_param";
    default:                              return "unknown";
  }
}

const char* cli_protocol_state_string(protocol_state_e state) {
  switch (state) {
    case PROTOCOL_IDLE:     return "idle";
    case PROTOCOL_LOCKED:   return "locked";
    case PROTOCOL_MODIFIED: return "modified";
    case PROTOCOL_VERIFIED: return "verified";
    case PROTOCOL_ERROR:    return "error";
    default:                return "unknown";
  }
}

// ============================================================
// Node Lifecycle
// ============================================================

cli_node_t* cli_node_create(void) {
  cli_node_t* node = get_clear_memory(sizeof(cli_node_t));
  node->state = NULL;
  node->attr_machine = NULL;
  node->abe_mk = NULL;
  node->node_key = NULL;
  node->initialized = false;
  return node;
}

void cli_node_destroy(cli_node_t* node) {
  if (node == NULL) return;
  if (node->state_sig_payload != NULL) {
    free(node->state_sig_payload);
    node->state_sig_payload = NULL;
    node->state_sig_payload_len = 0;
    node->state_sig_pending = false;
  }
  if (node->attr_machine != NULL) {
    attribute_machine_destroy(node->attr_machine);
  } else if (node->state != NULL) {
    state_destroy(node->state);
  }
  if (node->abe_mk != NULL) crypto_abe_master_key_destroy(node->abe_mk);
  // Free per-user custodied keys, skipping the admin key (node_key), which
  // is freed separately below (the admin keyring entry aliases node_key).
  for (uint32_t i = 0; i < node->keyring_count; i++) {
    if (node->keyring[i].key != NULL && node->keyring[i].key != node->node_key) {
      crypto_ecdsa_keypair_destroy(node->keyring[i].key);
    }
  }
  if (node->node_key != NULL) crypto_ecdsa_keypair_destroy(node->node_key);
  free(node);
}

cli_result_e cli_node_init(cli_node_t* node, const char* admin_id) {
  if (node == NULL || admin_id == NULL) return CLI_ERR_ARGS;
  if (node->initialized) return CLI_ERR_ARGS;

  // The node keeps NO second master key instance. attribute_machine_create
  // generates the one live ABE master key on base_state.abe_mk; keeping a
  // node-level copy would create a second, unrelated MSK domain (envelope
  // creation and op verification would disagree about the keyspace).
  // Generate node ECDSA keypair
  node->node_key = crypto_ecdsa_generate();
  if (node->node_key == NULL) return CLI_ERR_EXEC;

  // Create attribute machine with admin
  node->attr_machine = attribute_machine_create(admin_id, node->node_key->public_key);
  if (node->attr_machine == NULL) return CLI_ERR_EXEC;

  // Wire up back-pointer so state_machine_execute can find the attribute machine
  node->attr_machine->base_state.attr_machine = node->attr_machine;

  // Set node key on state for envelope signing
  crabs_error_e err = state_set_node_key(&node->attr_machine->base_state,
                                           node->node_key->private_key,
                                           node->node_key->public_key);
  if (err != CRABS_SUCCESS) return CLI_ERR_EXEC;

  node->initialized = true;
  // Custody the bootstrap admin's signing key under their user id so the CLI
  // signs admin operations with the admin's key (audit M-17).
  cli_node_add_user_key(node, admin_id, node->node_key);
  return CLI_OK;
}

// Per-user key custody (audit M-17).
cli_result_e cli_node_add_user_key(cli_node_t* node, const char* user_id,
                                     ecdsa_keypair_t* key) {
  if (node == NULL || user_id == NULL || key == NULL) return CLI_ERR_ARGS;
  for (uint32_t i = 0; i < node->keyring_count; i++) {
    if (strcmp(node->keyring[i].user_id, user_id) == 0) {
      // Audit H-F: never destroy an entry that aliases node->node_key — that
      // leaves a dangling pointer dereferenced by cli_cmd_key_revoke and
      // double-freed by cli_node_destroy. Only destroy a genuinely distinct
      // previous key.
      if (node->keyring[i].key != NULL &&
          node->keyring[i].key != key &&
          node->keyring[i].key != node->node_key) {
        crypto_ecdsa_keypair_destroy(node->keyring[i].key);
      }
      node->keyring[i].key = key;
      return CLI_OK;
    }
  }
  if (node->keyring_count >= CRABS_CLI_KEYRING_MAX) return CLI_ERR_EXEC;
  strncpy(node->keyring[node->keyring_count].user_id, user_id, CRABS_MAX_USER_ID - 1);
  node->keyring[node->keyring_count].user_id[CRABS_MAX_USER_ID - 1] = '\0';
  node->keyring[node->keyring_count].key = key;
  node->keyring_count++;
  return CLI_OK;
}

ecdsa_keypair_t* cli_node_get_user_key(cli_node_t* node, const char* user_id) {
  if (node == NULL || user_id == NULL) return NULL;
  for (uint32_t i = 0; i < node->keyring_count; i++) {
    if (strcmp(node->keyring[i].user_id, user_id) == 0) {
      return node->keyring[i].key;
    }
  }
  return NULL;
}

cli_result_e cli_node_load(cli_node_t* node, const char* path) {
  if (node == NULL || path == NULL) return CLI_ERR_ARGS;
  if (node->initialized) return CLI_ERR_ARGS;

  // A prior load attempt that failed after the signed parse would have left
  // pending signature data behind; release it before repopulating.
  if (node->state_sig_pending) {
    free(node->state_sig_payload);
    node->state_sig_payload = NULL;
    node->state_sig_payload_len = 0;
    memset(node->state_sig_signature, 0, CRABS_SIG_SIZE);
    node->state_sig_pending = false;
  }

  FILE* f = fopen(path, "rb");
  if (f == NULL) return CLI_ERR_IO;

  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  if (fsize <= 0) {
    fclose(f);
    return CLI_ERR_IO;
  }

  size_t file_len = (size_t)fsize;
  uint8_t* data = get_memory(file_len);
  if (fread(data, 1, file_len, f) != file_len) {
    free(data);
    fclose(f);
    return CLI_ERR_IO;
  }
  fclose(f);

  // Audit M-1: the SHA-256 inside a state blob is an integrity check, not
  // authentication — an attacker who can write the file can recompute it.
  // cli_node_save emits node-key-signed blobs (payload + ECDSA signature
  // trailer), so try the signed parse first and keep the pending signature
  // for cli_node_load_key to verify once the operator imports the trusted
  // private key. Legacy unsigned blobs are still accepted (back-compat) with
  // a loud warning, because the formats are distinguishable: an unsigned
  // blob fails the checksum when parsed with the trailer stripped, and a
  // signed blob fails it when parsed with the trailer included.
  state_t* loaded = NULL;
  // Audit: each load re-evaluates snapshot authenticity from scratch.
  node->loaded_unauthenticated = false;
  node->unauth_warning_shown = false;
  const uint8_t* load_seal_key =
      node->seal_key_valid ? node->seal_key : NULL;
  if (file_len > CRABS_SIG_SIZE) {
    size_t payload_len = file_len - CRABS_SIG_SIZE;
    loaded = crabs_deserialize_state_keys(data, payload_len, load_seal_key);
    if (loaded != NULL) {
      uint8_t* payload_copy = get_memory(payload_len);
      if (payload_copy == NULL) {
        state_destroy(loaded);
        free(data);
        return CLI_ERR_EXEC;
      }
      memcpy(payload_copy, data, payload_len);
      memcpy(node->state_sig_signature, data + payload_len, CRABS_SIG_SIZE);
      node->state_sig_payload = payload_copy;
      node->state_sig_payload_len = payload_len;
      node->state_sig_pending = true;
      fprintf(stderr,
              "WARNING: state file carries a node-key signature that has NOT "
              "been verified yet — run 'key import' with the node private key "
              "to authenticate this snapshot before trusting it\n");
    }
  }
  if (loaded == NULL) {
    loaded = crabs_deserialize_state_keys(data, file_len, load_seal_key);
    if (loaded != NULL) {
      // Audit: the fallback parsed an UNSIGNED blob. Its provenance is
      // unauthenticated — mark the node so cli_node_save refuses to re-sign
      // it until the operator acknowledges via 'state accept-unverified'.
      node->loaded_unauthenticated = true;
      fprintf(stderr,
              "WARNING: state file is unsigned — it carries no node-key "
              "signature and is NOT authenticated; verify its provenance "
              "before trusting it. Saving is disabled until you run "
              "'state accept-unverified'\n");
    }
  }
  free(data);

  if (loaded == NULL) return CLI_ERR_EXEC;

  node->node_key = crypto_ecdsa_generate();

  // v10: when the blob carried a user registry, the deserializer returns an
  // attribute-machine SHELL (base_state is the first member of
  // attribute_machine_t, so the returned state pointer IS the shell
  // allocation) with the registry already spliced in — adopt it directly,
  // no re-wiring. An identifiable shell has base_state.attr_machine
  // pointing back at its own allocation; a bare state (empty registry or a
  // pre-v10 blob) keeps attr_machine NULL and is wrapped the legacy way.
  if (loaded->attr_machine != NULL &&
      loaded->attr_machine == (attribute_machine_t*)loaded) {
    // Adopt the shell wholesale.
    node->attr_machine = (attribute_machine_t*)loaded;
    node->attr_machine->base_state.attr_machine = node->attr_machine;
  } else {
    // Bare state: build the wrapping attribute machine. The shallow copy
    // transfers ownership of items/policies/log/etc.; the source state
    // struct itself carries no embedded registry to leak.
    node->attr_machine = get_clear_memory(sizeof(attribute_machine_t));
    node->attr_machine->base_state = *loaded;
    node->attr_machine->base_state.attr_machine = node->attr_machine;
    node->attr_machine->users = NULL;
    node->attr_machine->user_count = 0;
    node->attr_machine->current_time_ms = 0;
    free(loaded);
  }

  node->abe_mk = NULL;   // the single live authority is base_state.abe_mk

  state_set_node_key(&node->attr_machine->base_state,
                     node->node_key->private_key,
                     node->node_key->public_key);

  node->initialized = true;
  return CLI_OK;
}

// Audit L-l: restore node-key custody after cli_node_load. The operator
// persists the node private key out-of-band and imports it here so the node
// can sign for the bootstrap admin again. If the loaded snapshot carried a
// node-key signature (audit M-1), the imported key must verify it before
// custody is granted; a verified signature also identifies the key as the
// snapshot's node key, so custody falls back to the bootstrap admin id when
// the deserialized state has no matching registered user.
cli_result_e cli_node_load_key(cli_node_t* node, const char* private_key_hex) {
  if (node == NULL || private_key_hex == NULL) return CLI_ERR_ARGS;
  if (!node->initialized || node->attr_machine == NULL) return CLI_ERR_NOT_INIT;

  uint8_t priv[32];
  if (cli_hex_to_bytes(private_key_hex, priv, 32) != CLI_OK) return CLI_ERR_ARGS;

  uint8_t pub[33];
  if (crypto_ecdsa_derive_public_key(priv, pub) != CRABS_SUCCESS) return CLI_ERR_EXEC;

  // Audit M-1: a loaded snapshot carrying a node-key signature is only
  // authenticated once the imported key verifies that signature. Fail closed
  // on mismatch and leave the pending verification in place so the operator
  // can retry with the correct key.
  bool signature_verified = false;
  if (node->state_sig_pending) {
    if (!crypto_ecdsa_verify(pub, node->state_sig_payload,
                             node->state_sig_payload_len,
                             node->state_sig_signature)) {
      OPENSSL_cleanse(priv, 32);
      fprintf(stderr,
              "ERROR: state snapshot signature verification FAILED — the "
              "imported key did not sign this snapshot; refusing custody\n");
      return CLI_ERR_EXEC;
    }
    signature_verified = true;
    free(node->state_sig_payload);
    node->state_sig_payload = NULL;
    node->state_sig_payload_len = 0;
    memset(node->state_sig_signature, 0, CRABS_SIG_SIZE);
    node->state_sig_pending = false;
    printf("State snapshot signature verified against the imported node key.\n");
  }

  // Find the registered user whose public key matches the derived key. A
  // freshly loaded node has no restored user registry (the state format does
  // not carry it), so for a snapshot whose signature the imported key just
  // verified, custody the key under the snapshot's bootstrap admin — the
  // signature proves the imported key is the node key that saved it.
  const char* custody_id = NULL;
  for (user_t* u = node->attr_machine->users; u != NULL; u = u->next) {
    if (memcmp(u->public_key, pub, 33) == 0) {
      custody_id = u->user_id;
      break;
    }
  }
  if (custody_id == NULL && signature_verified &&
      node->attr_machine->base_state.config.bootstrap_admin[0] != '\0') {
    custody_id = node->attr_machine->base_state.config.bootstrap_admin;
  }
  if (custody_id == NULL) return CLI_ERR_EXEC; // no matching user

  // Replace the node key with the imported one.
  if (node->node_key != NULL) crypto_ecdsa_keypair_destroy(node->node_key);
  node->node_key = get_clear_memory(sizeof(ecdsa_keypair_t));
  if (node->node_key == NULL) return CLI_ERR_EXEC;
  memcpy(node->node_key->private_key, priv, 32);
  memcpy(node->node_key->public_key, pub, 33);

  state_set_node_key(&node->attr_machine->base_state, priv, pub);
  // Custody the imported key under the matching user id.
  cli_node_add_user_key(node, custody_id, node->node_key);
  OPENSSL_cleanse(priv, 32);
  return CLI_OK;
}

// Durability (v10): import the operator's at-rest seal key. Stored in
// memory only; never serialized anywhere. Re-import replaces the key
// wholesale (the raw bytes are overwritten in place).
cli_result_e cli_node_set_seal_key(cli_node_t* node, const char* key_hex) {
  if (node == NULL || key_hex == NULL) return CLI_ERR_ARGS;
  if (strlen(key_hex) != 64) {
    fprintf(stderr, "ERROR: seal key must be 64 hex chars (32 bytes)\n");
    return CLI_ERR_ARGS;
  }
  if (cli_hex_to_bytes(key_hex, node->seal_key, 32) != CLI_OK) {
    return CLI_ERR_ARGS;
  }
  node->seal_key_valid = true;
  return CLI_OK;
}

cli_result_e cli_node_load_sealed(cli_node_t* node, const char* path,
                                    const char* key_hex) {
  if (node == NULL || path == NULL || key_hex == NULL) return CLI_ERR_ARGS;
  if (node->initialized) return CLI_ERR_ARGS;
  if (cli_node_set_seal_key(node, key_hex) != CLI_OK) return CLI_ERR_ARGS;

  cli_result_e result = cli_node_load(node, path);
  if (result != CLI_OK) {
    // Do not leave a half-imported seal key on a failed load.
    node->seal_key_valid = false;
    OPENSSL_cleanse(node->seal_key, sizeof(node->seal_key));
    return result;
  }
  // The seal key is KEPT in node storage after a successful load: the next
  // cli_node_save must seal the MSK under the same key.
  return CLI_OK;
}

cli_result_e cli_node_save(cli_node_t* node, const char* path) {
  if (node == NULL || path == NULL || !node->initialized) return CLI_ERR_ARGS;

  // Audit M-1: do not persist a snapshot whose provenance is unverified —
  // saving would re-sign it with the ephemeral load-time node key, which no
  // operator holds. Import the node key first (cli_node_load_key).
  if (node->state_sig_pending) {
    fprintf(stderr,
            "ERROR: refusing to save — the loaded state signature has not "
            "been verified yet; run 'key import' with the node private key "
            "first\n");
    return CLI_ERR_EXEC;
  }

  // Audit: do not re-sign an UNSIGNED snapshot either — the operator's node
  // key would end up authenticating attacker-supplied state (signature
  // laundering). Require an explicit acknowledgment first.
  if (node->loaded_unauthenticated) {
    fprintf(stderr,
            "ERROR: refusing to save — the loaded state is unauthenticated "
            "(unsigned snapshot); run 'state accept-unverified' to "
            "acknowledge it first\n");
    return CLI_ERR_EXEC;
  }

  // Durability: refuse to persist without a seal key — an unsealed snapshot
  // silently loses the machine's authority (fresh MSK on reload).
  if (!node->seal_key_valid) {
    fprintf(stderr,
            "ERROR: refusing to save — no at-rest seal key imported; the "
            "machine's ABE master key would be lost. Run 'seal-key import "
            "<keyfile>' first\n");
    return CLI_ERR_EXEC;
  }

  // Audit M-1: sign the state blob with the node private key. The bare
  // SHA-256 checksum written by the unsigned serializer is integrity only —
  // an attacker who can write the file can recompute it.
  // Durability (v10): seal the MSK under the at-rest key, then append the
  // node-key signature over the sealed payload (seal and sign compose;
  // this is crabs_serialize_state_sealed + the signed-trailer logic).
  if (!node->attr_machine->base_state.node_key_valid) return CLI_ERR_EXEC;
  serialized_buffer_t* sealed_payload =
      crabs_serialize_state_sealed(&node->attr_machine->base_state,
                                   node->seal_key);
  if (sealed_payload == NULL) return CLI_ERR_EXEC;
  serialized_buffer_t* buf =
      serialized_buffer_create(sealed_payload->len + CRABS_SIG_SIZE);
  if (buf == NULL) {
    serialized_buffer_destroy(sealed_payload);
    return CLI_ERR_EXEC;
  }
  memcpy(buf->data, sealed_payload->data, sealed_payload->len);
  buf->len = sealed_payload->len + CRABS_SIG_SIZE;
  if (crypto_ecdsa_sign(node->attr_machine->base_state.node_private_key,
                        sealed_payload->data, sealed_payload->len,
                        buf->data + sealed_payload->len) != CRABS_SUCCESS) {
    serialized_buffer_destroy(sealed_payload);
    serialized_buffer_destroy(buf);
    return CLI_ERR_EXEC;
  }
  serialized_buffer_destroy(sealed_payload);

  FILE* f = fopen(path, "wb");
  if (f == NULL) {
    serialized_buffer_destroy(buf);
    return CLI_ERR_IO;
  }

  size_t written = fwrite(buf->data, 1, buf->len, f);
  fclose(f);
  size_t total_len = buf->len;
  serialized_buffer_destroy(buf);

  if (written != total_len) return CLI_ERR_IO;
  return CLI_OK;
}

// ============================================================
// State Queries
// ============================================================

cli_result_e cli_cmd_state_show(cli_node_t* node) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  state_t* state = &node->attr_machine->base_state;

  printf("State Version: %llu\n", (unsigned long long)state->version);
  uint32_t item_count = 0;
  data_item_t* item = state->items;
  while (item != NULL) {
    item_count++;
    item = item->next;
  }
  printf("  Data Items: %u\n", item_count);
  printf("  Policies: %u\n", state->policy_count);
  printf("  Log Entries: %llu\n", (unsigned long long)state->log_count);
  printf("  Triggers: %u\n", state->trigger_count);
  printf("  Node Key: %s\n", state->node_key_valid ? "initialized" : "not set");
  printf("  Users: %u\n", node->attr_machine->user_count);

  return CLI_OK;
}

cli_result_e cli_cmd_state_items(cli_node_t* node) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  state_t* state = &node->attr_machine->base_state;

  data_item_t* item = state->items;
  if (item == NULL) {
    printf("No data items.\n");
    return CLI_OK;
  }

  printf("%-20s %-12s %-8s %s\n", "Name", "Type", "CRDT", "State");
  printf("%-20s %-12s %-8s %s\n", "----", "----", "----", "-----");
  while (item != NULL) {
    printf("%-20s 0x%02x        0x%02x      %s\n",
           item->name, item->type, item->crdt_type,
           cli_protocol_state_string(item->protocol_state));
    item = item->next;
  }
  return CLI_OK;
}

cli_result_e cli_cmd_state_policies(cli_node_t* node) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  state_t* state = &node->attr_machine->base_state;

  if (state->policy_count == 0) {
    printf("No policies.\n");
    return CLI_OK;
  }

  printf("%-24s %s\n", "Operation", "Expression");
  printf("%-24s %s\n", "---------", "----------");
  for (uint32_t i = 0; i < state->policy_count; i++) {
    printf("%-24s %s\n", state->policies[i].operation, state->policies[i].expression);
  }
  return CLI_OK;
}

cli_result_e cli_cmd_state_config(cli_node_t* node) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  machine_config_t* cfg = &node->attr_machine->base_state.config;

  printf("Machine Configuration:\n");
  printf("  max_lock_duration_ms: %llu\n", (unsigned long long)cfg->max_lock_duration_ms);
  printf("  max_lock_extensions:  %u\n", cfg->max_lock_extensions);
  printf("  allow_force_unlock:   %s\n", cfg->allow_force_unlock ? "true" : "false");
  printf("  bootstrap_admin:     %s\n", cfg->bootstrap_admin[0] ? cfg->bootstrap_admin : "(not set)");
  return CLI_OK;
}

// Audit: explicit operator acknowledgment of an unauthenticated (unsigned)
// snapshot. This is the gate release for cli_node_save — the operator
// accepts responsibility for the snapshot's provenance.
cli_result_e cli_cmd_state_accept_unverified(cli_node_t* node) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;

  if (!node->loaded_unauthenticated) {
    printf("State is authenticated; nothing to acknowledge.\n");
    return CLI_OK;
  }

  node->loaded_unauthenticated = false;
  node->unauth_warning_shown = true;
  printf("Acknowledged: the loaded state snapshot was UNSIGNED and its "
         "provenance is UNVERIFIED — accepting it at the operator's "
         "discretion; saving will now sign this state with the node key.\n");
  return CLI_OK;
}

// ============================================================
// User Management
// ============================================================

cli_result_e cli_cmd_user_register(cli_node_t* node, const char* user_id,
                                    const char* public_key_hex) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  if (user_id == NULL || public_key_hex == NULL) return CLI_ERR_ARGS;

  uint8_t pk[33];
  cli_result_e rc = cli_hex_to_bytes(public_key_hex, pk, 33);
  if (rc != CLI_OK) {
    printf("Error: Invalid public key hex (expected 66 hex chars).\n");
    return rc;
  }

  crabs_error_e err = attribute_machine_register_user(node->attr_machine, user_id,
                                                        pk, "");
  if (err != CRABS_SUCCESS) {
    printf("Error: %s\n", cli_error_string(err));
    return CLI_ERR_EXEC;
  }

  printf("User '%s' registered.\n", user_id);
  return CLI_OK;
}

cli_result_e cli_cmd_user_list(cli_node_t* node) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;

  user_t* user = node->attr_machine->users;
  if (user == NULL) {
    printf("No users registered.\n");
    return CLI_OK;
  }

  printf("%-20s %-12s %-12s %s\n", "User ID", "Status", "Key Version", "Attributes");
  printf("%-20s %-12s %-12s %s\n", "-------", "------", "------------", "----------");
  while (user != NULL) {
    char pk_hex[67];
    cli_bytes_to_hex(user->public_key, 33, pk_hex);
    printf("%-20s %-12s %-12lu %u attrs (pk: %.8s...)\n",
           user->user_id,
           user->status == USER_ACTIVE ? "active" :
           user->status == USER_SUSPENDED ? "suspended" : "revoked",
           user->key_version,
           user->attribute_count,
           pk_hex);
    user = user->next;
  }
  return CLI_OK;
}

cli_result_e cli_cmd_user_grant(cli_node_t* node, const char* user_id,
                                  const char* role, const char* value) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  if (user_id == NULL || role == NULL) return CLI_ERR_ARGS;

  // Audit R5-1: attribute_machine_grant_role validates the attribute NAME
  // charset ([A-Za-z0-9_-]) and constructs the token as "name:value". The
  // CLI historically accepted the full "role:admin" token as the role
  // parameter with an empty value, which produced "role:admin:" (trailing
  // colon) and is now rejected by the name charset check (colon not allowed).
  // Split the role parameter on the first colon: if present, the part before
  // is the name and the part after is the value (the value argument is
  // ignored). If no colon, use role as the name and value as the value.
  char name_buf[CRABS_MAX_POLICY_EXPR];
  const char* name = role;
  const char* val = value ? value : "";
  const char* colon = strchr(role, ':');
  if (colon != NULL) {
    size_t name_len = (size_t)(colon - role);
    if (name_len >= sizeof(name_buf)) name_len = sizeof(name_buf) - 1;
    memcpy(name_buf, role, name_len);
    name_buf[name_len] = '\0';
    name = name_buf;
    val = colon + 1;
  }

  // R8-A-2: the grant signer must hold role:admin. Resolve the signer as the
  // bootstrap admin (config.bootstrap_admin), NOT the head of the users list:
  // users are prepended on registration, so users->user_id is the most
  // recently registered user, who typically holds no privileges.
  const char* signer_id = node->attr_machine->base_state.config.bootstrap_admin;
  crabs_error_e err = attribute_machine_grant_role(node->attr_machine, user_id,
                                                     name, val, signer_id);
  if (err != CRABS_SUCCESS) {
    printf("Error: %s\n", cli_error_string(err));
    return CLI_ERR_EXEC;
  }

  printf("Role '%s:%s' granted to '%s'.\n", name, val, user_id);
  return CLI_OK;
}

cli_result_e cli_cmd_user_revoke(cli_node_t* node, const char* user_id,
                                   const char* role) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  if (user_id == NULL || role == NULL) return CLI_ERR_ARGS;

  // Match grant_role: the bootstrap admin is the administrative signer
  // (users are prepended, so users->user_id is the newest registered user).
  const char* signer_id = node->attr_machine->base_state.config.bootstrap_admin;
  crabs_error_e err = attribute_machine_revoke_role(node->attr_machine, user_id,
                                                      role, signer_id);
  if (err != CRABS_SUCCESS) {
    printf("Error: %s\n", cli_error_string(err));
    return CLI_ERR_EXEC;
  }

  printf("Role '%s' revoked from '%s'.\n", role, user_id);
  return CLI_OK;
}

cli_result_e cli_cmd_user_suspend(cli_node_t* node, const char* user_id) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  if (user_id == NULL) return CLI_ERR_ARGS;

  // The CLI acts as the bootstrap admin (same signer resolution as grant/
  // revoke_role): users may be prepended by later registrations, so the list
  // head is not necessarily an admin.
  crabs_error_e err = attribute_machine_suspend_user(
      node->attr_machine, user_id,
      node->attr_machine->base_state.config.bootstrap_admin);
  if (err != CRABS_SUCCESS) {
    printf("Error: %s\n", cli_error_string(err));
    return CLI_ERR_EXEC;
  }

  printf("User '%s' suspended.\n", user_id);
  return CLI_OK;
}

// ============================================================
// Data Item Management
// ============================================================

static data_type_e _parse_data_type(const char* str) {
  if (strcmp(str, "counter") == 0)      return DATA_TYPE_COUNTER;
  if (strcmp(str, "pn_counter") == 0)   return DATA_TYPE_PN_COUNTER;
  if (strcmp(str, "set") == 0)           return DATA_TYPE_SET;
  if (strcmp(str, "2p_set") == 0)        return DATA_TYPE_2P_SET;
  if (strcmp(str, "register") == 0)      return DATA_TYPE_REGISTER;
  if (strcmp(str, "document") == 0)      return DATA_TYPE_DOCUMENT;
  if (strcmp(str, "resource") == 0)      return DATA_TYPE_RESOURCE;
  if (strcmp(str, "one_shot_set") == 0)  return DATA_TYPE_ONE_SHOT_SET;
  if (strcmp(str, "one_shot_flag") == 0) return DATA_TYPE_ONE_SHOT_FLAG;
  return DATA_TYPE_CUSTOM;
}

static crdt_type_e _parse_crdt_type(const char* str) {
  if (strcmp(str, "g_counter") == 0)    return CRDT_G_COUNTER;
  if (strcmp(str, "pn_counter") == 0)   return CRDT_PN_COUNTER;
  if (strcmp(str, "or_set") == 0)       return CRDT_OR_SET;
  if (strcmp(str, "2p_set") == 0)       return CRDT_2P_SET;
  if (strcmp(str, "lww_reg") == 0)      return CRDT_LWW_REG;
  if (strcmp(str, "rga") == 0)          return CRDT_RGA;
  if (strcmp(str, "one_shot_set") == 0)  return CRDT_ONE_SHOT_SET;
  if (strcmp(str, "one_shot_flag") == 0) return CRDT_ONE_SHOT_FLAG;
  return CRDT_CUSTOM;
}

cli_result_e cli_cmd_item_add(cli_node_t* node, const char* name,
                                const char* type_str) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  if (name == NULL || type_str == NULL) return CLI_ERR_ARGS;

  data_type_e dtype = _parse_data_type(type_str);
  crdt_type_e crdt = _parse_crdt_type(type_str);

  data_item_t* item = data_item_create(name, dtype, crdt);
  if (item == NULL) return CLI_ERR_EXEC;

  crabs_error_e err = state_add_item(&node->attr_machine->base_state, item);
  if (err != CRABS_SUCCESS) {
    data_item_destroy(item);
    printf("Error: %s\n", cli_error_string(err));
    return CLI_ERR_EXEC;
  }

  printf("Data item '%s' added (type=0x%02x, crdt=0x%02x).\n", name, dtype, crdt);
  return CLI_OK;
}

cli_result_e cli_cmd_item_list(cli_node_t* node) {
  return cli_cmd_state_items(node);
}

// ============================================================
// Policy Management
// ============================================================

cli_result_e cli_cmd_policy_add(cli_node_t* node, const char* operation,
                                  const char* expression) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  if (operation == NULL || expression == NULL) return CLI_ERR_ARGS;

  crabs_error_e err = state_add_policy(&node->attr_machine->base_state, operation, expression);
  if (err != CRABS_SUCCESS) {
    printf("Error: %s\n", cli_error_string(err));
    return CLI_ERR_EXEC;
  }

  printf("Policy added: %s -> %s\n", operation, expression);
  return CLI_OK;
}

// ============================================================
// Key Management
// ============================================================

cli_result_e cli_cmd_key_generate(void) {
  ecdsa_keypair_t* keypair = crypto_ecdsa_generate();
  if (keypair == NULL) {
    printf("Error: Failed to generate ECDSA keypair.\n");
    return CLI_ERR_EXEC;
  }

  char priv_hex[65];
  char pub_hex[67];
  cli_bytes_to_hex(keypair->private_key, 32, priv_hex);
  cli_bytes_to_hex(keypair->public_key, 33, pub_hex);

  printf("ECDSA Keypair Generated:\n");
  printf("  Private Key: %s\n", priv_hex);
  printf("  Public Key:  %s\n", pub_hex);

  crypto_ecdsa_keypair_destroy(keypair);
  return CLI_OK;
}

cli_result_e cli_cmd_key_refresh(cli_node_t* node, const char* user_id) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  if (user_id == NULL) return CLI_ERR_ARGS;

  // Create and submit a refresh key operation
  operation_t* op = operation_create(CRABS_OP_REFRESH_KEY);
  if (op == NULL) return CLI_ERR_EXEC;

  strncpy(op->signer_id, user_id, CRABS_MAX_USER_ID - 1);

  refresh_key_response_t response;
  crabs_error_e err = state_machine_op_refresh_key(&node->attr_machine->base_state, op, &response);
  operation_destroy(op);

  if (err != CRABS_SUCCESS) {
    printf("Error: Key refresh failed: %s\n", cli_error_string(err));
    return CLI_ERR_EXEC;
  }

  printf("Key refreshed for user '%s'.\n", user_id);
  printf("  Envelope length: %u bytes\n", response.envelope_data_len);

  user_t* user = attribute_machine_find_user(node->attr_machine, user_id);
  if (user != NULL) {
    printf("  New key version: %llu\n", (unsigned long long)user->key_version);
  }

  return CLI_OK;
}

cli_result_e cli_cmd_key_revoke(cli_node_t* node, const char* user_id,
                                  const char* new_public_key_hex) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  if (user_id == NULL || new_public_key_hex == NULL) return CLI_ERR_ARGS;

  uint8_t new_pk[33];
  if (cli_hex_to_bytes(new_public_key_hex, new_pk, 33) != CLI_OK) {
    printf("Error: new public key must be 66 hex chars.\n");
    return CLI_ERR_ARGS;
  }

  // Audit H-B: node-blind rotation. The node records the user's new public
  // key and issues an envelope; it never generates or holds the private key.
  recovery_result_t* result = crypto_revoke_and_rotate(
      (const abe_master_key_t*)node->attr_machine->base_state.abe_mk,
      node->node_key->private_key,
      node->attr_machine,
      user_id,
      new_pk,
      node->attr_machine->base_state.version,
      0);

  if (result == NULL) {
    printf("Error: Key revocation failed.\n");
    return CLI_ERR_EXEC;
  }

  printf("Keys revoked and rotated for user '%s'.\n", user_id);
  char pub_hex[67];
  cli_bytes_to_hex(result->new_public_key, 33, pub_hex);
  printf("  New public key recorded: %s\n", pub_hex);
  printf("  (Private key is held by the user; the node does not know it.)\n");

  crypto_recovery_result_destroy(result);
  return CLI_OK;
}

// ============================================================
// Operation Submission
// ============================================================

cli_result_e cli_cmd_op_submit(cli_node_t* node, const char* type,
                                 const char* payload_hex, const char* signer_id) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  if (type == NULL) return CLI_ERR_ARGS;

  operation_t* op = operation_create(type);
  if (op == NULL) {
    printf("Error: Failed to create operation.\n");
    return CLI_ERR_EXEC;
  }

  // Set signer
  if (signer_id != NULL) {
    strncpy(op->signer_id, signer_id, CRABS_MAX_USER_ID - 1);
  }

  // Generate UUID for the operation
  crypto_random_bytes(op->uuid, CRABS_UUID_SIZE);

  // Set resources for lock/unlock/verify/rollback/force_unlock/extend operations
  // by finding all RESOURCE-type data items
  if (operation_is_builtin(type)) {
    data_item_t* item = node->attr_machine->base_state.items;
    uint32_t res_count = 0;
    // Count resource items for lock operations
    while (item != NULL) {
      if (item->type == DATA_TYPE_RESOURCE) res_count++;
      item = item->next;
    }
    if (res_count > 0) {
      op->resource_count = res_count;
      op->resources = get_clear_memory(res_count * CRABS_MAX_USER_ID);
      op->required_state = get_clear_memory(res_count * sizeof(protocol_state_e));
      op->next_state = get_clear_memory(res_count * sizeof(protocol_state_e));
      item = node->attr_machine->base_state.items;
      uint32_t idx = 0;
      while (item != NULL && idx < res_count) {
        if (item->type == DATA_TYPE_RESOURCE) {
          strncpy(op->resources[idx], item->name, CRABS_MAX_USER_ID - 1);
          // Set required state based on the operation type
          if (strcmp(type, CRABS_OP_LOCK) == 0) {
            op->required_state[idx] = PROTOCOL_IDLE;
          } else if (strcmp(type, CRABS_OP_UNLOCK) == 0) {
            op->required_state[idx] = PROTOCOL_VERIFIED;
          } else if (strcmp(type, CRABS_OP_VERIFY) == 0) {
            op->required_state[idx] = PROTOCOL_MODIFIED;
          } else if (strcmp(type, CRABS_OP_ROLLBACK) == 0) {
            op->required_state[idx] = PROTOCOL_MODIFIED;
          } else if (strcmp(type, CRABS_OP_EXTEND) == 0) {
            op->required_state[idx] = PROTOCOL_LOCKED;
          } else if (strcmp(type, CRABS_OP_FORCE_UNLOCK) == 0) {
            op->required_state[idx] = PROTOCOL_LOCKED;
          }
          idx++;
        }
        item = item->next;
      }
    }
  }

  // Set payload if provided
  if (payload_hex != NULL) {
    size_t hex_len = strlen(payload_hex);
    size_t payload_len = hex_len / 2;
    if (payload_len > 0) {
      op->payload = get_clear_memory(payload_len);
      cli_result_e rc = cli_hex_to_bytes(payload_hex, op->payload, payload_len);
      if (rc != CLI_OK) {
        operation_destroy(op);
        printf("Error: Invalid payload hex.\n");
        return rc;
      }
      op->payload_size = (uint32_t)payload_len;
    }
  }

  // Sign the operation with the signer's own custodied key (audit M-17:
  // previously every op was signed with the node key regardless of signer_id,
  // so the CLI could not actually act as a non-admin user and would forge
  // admin signatures for anyone). If the CLI holds no key for the signer, the
  // op is left unsigned and execution will reject it (fail-closed).
  if (op->signer_id[0] != '\0' && node->attr_machine->base_state.node_key_valid) {
    user_t* user = attribute_machine_find_user(node->attr_machine, op->signer_id);
    if (user != NULL) {
      ecdsa_keypair_t* signer_key = cli_node_get_user_key(node, op->signer_id);
      if (signer_key != NULL) {
        // signer_key_version is part of the signed canonical form, so it must
        // be set BEFORE serializing for signing.
        op->signer_key_version = user->key_version;
        serialized_buffer_t* sig_data = crabs_serialize_for_signing(op);
        if (sig_data != NULL) {
          crypto_ecdsa_sign(signer_key->private_key,
                            sig_data->data, sig_data->len, op->signature);
          serialized_buffer_destroy(sig_data);
        }
      }
    }
  }

  // Execute the operation
  crabs_error_e err = state_machine_execute(&node->attr_machine->base_state, op);
  if (err != CRABS_SUCCESS) {
    operation_destroy(op);
    printf("Error: Operation '%s' failed: %s\n", type, cli_error_string(err));
    return CLI_ERR_EXEC;
  }

  printf("Operation '%s' submitted successfully.\n", type);
  operation_destroy(op);
  return CLI_OK;
}

// ============================================================
// Dedup Commands
// ============================================================

static dedup_type_e _parse_dedup_type(const char* str, bool* valid) {
  if (strcmp(str, "none") == 0)      { *valid = true; return DEDUP_NONE; }
  if (strcmp(str, "per_user") == 0)  { *valid = true; return DEDUP_PER_USER; }
  if (strcmp(str, "global") == 0)    { *valid = true; return DEDUP_GLOBAL; }
  if (strcmp(str, "custom") == 0)    { *valid = true; return DEDUP_CUSTOM; }
  *valid = false;
  return DEDUP_NONE;
}

cli_result_e cli_cmd_op_define(cli_node_t* node, const char* op_type_name,
                                const char* dedup_type_str,
                                const char* tracker_path,
                                const char* flag_path,
                                const char* condition) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  if (op_type_name == NULL || dedup_type_str == NULL) return CLI_ERR_ARGS;

  bool dedup_valid = false;
  dedup_type_e dtype = _parse_dedup_type(dedup_type_str, &dedup_valid);
  if (!dedup_valid) {
    printf("Error: Invalid dedup type '%s'. Use none|per_user|global|custom.\n", dedup_type_str);
    return CLI_ERR_ARGS;
  }

  operation_t* op = operation_create(CRABS_OP_DEFINE_OPERATION);
  if (op == NULL) return CLI_ERR_EXEC;

  op->resource_count = 1;
  op->resources = get_clear_memory(CRABS_MAX_USER_ID);
  strncpy(op->resources[0], op_type_name, CRABS_MAX_USER_ID - 1);
  // Use the bootstrap admin as the signer (config.bootstrap_admin): users
  // are prepended on registration, so users->user_id is the newest
  // registered user. This path invokes the handler directly today (no
  // pipeline authorization), but if it ever routes through
  // state_machine_execute, only an admin would pass the
  // __define_operation_type__ policy check.
  strncpy(op->signer_id, node->attr_machine->base_state.config.bootstrap_admin,
          CRABS_MAX_USER_ID - 1);

  op->dedup.type = dtype;
  if (dtype == DEDUP_PER_USER) {
    if (tracker_path == NULL) {
      operation_destroy(op);
      printf("Error: PER_USER dedup requires a tracker_path.\n");
      return CLI_ERR_ARGS;
    }
    strncpy(op->dedup.tracker_path, tracker_path, CRABS_MAX_DEDUP_PATH - 1);
  } else if (dtype == DEDUP_GLOBAL) {
    if (flag_path == NULL) {
      operation_destroy(op);
      printf("Error: GLOBAL dedup requires a flag_path.\n");
      return CLI_ERR_ARGS;
    }
    strncpy(op->dedup.flag_path, flag_path, CRABS_MAX_DEDUP_PATH - 1);
  } else if (dtype == DEDUP_CUSTOM) {
    if (condition == NULL) {
      operation_destroy(op);
      printf("Error: CUSTOM dedup requires a condition expression.\n");
      return CLI_ERR_ARGS;
    }
    strncpy(op->dedup.condition, condition, CRABS_MAX_POLICY_EXPR - 1);
  }

  crabs_error_e err = state_machine_op_define_operation(&node->attr_machine->base_state, op);
  operation_destroy(op);

  if (err != CRABS_SUCCESS) {
    printf("Error: Define operation '%s' failed: %s\n", op_type_name, cli_error_string(err));
    return CLI_ERR_EXEC;
  }

  printf("Operation type '%s' defined with dedup=%s.\n", op_type_name, dedup_type_str);
  return CLI_OK;
}

cli_result_e cli_cmd_op_check_dedup(cli_node_t* node, const char* op_type_name,
                                      const char* signer_id) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  if (op_type_name == NULL) return CLI_ERR_ARGS;

  operation_t* op = operation_create(op_type_name);
  if (op == NULL) return CLI_ERR_EXEC;

  if (signer_id) {
    strncpy(op->signer_id, signer_id, CRABS_MAX_USER_ID - 1);
  }

  crabs_error_e err = state_machine_op_check_dedup(&node->attr_machine->base_state, op);
  operation_destroy(op);

  if (err == CRABS_SUCCESS) {
    printf("Dedup check passed for '%s'.\n", op_type_name);
    return CLI_OK;
  } else if (err == CRABS_ERR_ALREADY_PERFORMED) {
    printf("Dedup check rejected for '%s': already performed.\n", op_type_name);
    return CLI_ERR_EXEC;
  } else if (err == CRABS_ERR_ALREADY_EXECUTED) {
    printf("Dedup check rejected for '%s': already executed.\n", op_type_name);
    return CLI_ERR_EXEC;
  } else if (err == CRABS_ERR_CONDITION_NOT_MET) {
    printf("Dedup check rejected for '%s': condition not met.\n", op_type_name);
    return CLI_ERR_EXEC;
  } else {
    printf("Dedup check error for '%s': %s\n", op_type_name, cli_error_string(err));
    return CLI_ERR_EXEC;
  }
}

// ============================================================
// Compaction Command (v1.5.2 §4.3)
// ============================================================

cli_result_e cli_cmd_compact(cli_node_t* node) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;

  crabs_compaction_engine_t engine;
  crabs_compaction_engine_init(&engine, NULL);
  crabs_register_crdt_vtables(&engine.registry);

  crabs_error_e err = crabs_op_compact_now(&engine, node->state);

  if (err == CRABS_SUCCESS) {
    printf("Compaction completed. Items compacted: %llu, Skipped: %llu, Unsafe: %llu\n",
           (unsigned long long)engine.compaction_count,
           (unsigned long long)engine.skipped_count,
           (unsigned long long)engine.unsafe_count);
    crabs_compaction_engine_destroy(&engine);
    return CLI_OK;
  }
  printf("Compaction error: %s\n", cli_error_string(err));
  crabs_compaction_engine_destroy(&engine);
  return CLI_ERR_EXEC;
}

// ============================================================
// Command Dispatch
// ============================================================

static void _print_state_usage(void) {
  printf("  state show              Show node state summary\n");
  printf("  state items            List data items\n");
  printf("  state policies         List policies\n");
  printf("  state config           Show machine configuration\n");
  printf("  state accept-unverified  Acknowledge an unsigned (unauthenticated) snapshot\n");
}

// Audit: mutating an unauthenticated (unsigned) snapshot is risky but
// recoverable without signature laundering — the hard gate is at save time
// (cli_node_save refuses until 'state accept-unverified'). Warn once on the
// first mutating command so the operator cannot miss the provenance problem.
static void _warn_first_unauthenticated_mutation(cli_node_t* node, const char* cmd,
                                                 const char* sub) {
  if (node == NULL || !node->loaded_unauthenticated || node->unauth_warning_shown) {
    return;
  }

  bool mutating = false;
  if (strcmp(cmd, "item") == 0 && sub != NULL && strcmp(sub, "add") == 0) {
    mutating = true;
  } else if (strcmp(cmd, "policy") == 0 && sub != NULL && strcmp(sub, "add") == 0) {
    mutating = true;
  } else if (strcmp(cmd, "compact") == 0) {
    mutating = true;
  } else if (strcmp(cmd, "user") == 0 && sub != NULL && strcmp(sub, "list") != 0) {
    mutating = true;
  } else if (strcmp(cmd, "key") == 0 && sub != NULL &&
             (strcmp(sub, "refresh") == 0 || strcmp(sub, "revoke") == 0)) {
    mutating = true;
  } else if (strcmp(cmd, "op") == 0 && sub != NULL &&
             (strcmp(sub, "submit") == 0 || strcmp(sub, "define") == 0)) {
    mutating = true;
  }

  if (!mutating) return;
  node->unauth_warning_shown = true;
  fprintf(stderr,
          "WARNING: mutating state loaded from an UNSIGNED (unauthenticated) "
          "snapshot — run 'state accept-unverified' to acknowledge it\n");
}

static void _print_user_usage(void) {
  printf("  user register <id> <pubkey_hex>   Register a new user\n");
  printf("  user list                          List all users\n");
  printf("  user grant <id> <role> [value]     Grant role to user\n");
  printf("  user revoke <id> <role>            Revoke role from user\n");
  printf("  user suspend <id>                  Suspend a user\n");
}

static void _print_item_usage(void) {
  printf("  item add <name> <type>   Add a data item (counter|pn_counter|set|2p_set|register|document|resource|one_shot_set|one_shot_flag)\n");
  printf("  item list                 List data items\n");
}

static void _print_policy_usage(void) {
  printf("  policy add <operation> <expression>   Add a policy\n");
}

static void _print_key_usage(void) {
  printf("  key generate                Generate a new ECDSA keypair\n");
  printf("  key refresh <user_id>       Refresh ABE key for a user\n");
  printf("  key revoke <user_id>        Revoke and rotate keys for a user\n");
}

static void _print_op_usage(void) {
  printf("  op submit <type> [payload_hex] [signer_id]           Submit an operation\n");
  printf("  op define <op_type> <dedup_type> [tracker|flag|condition]  Define operation type with dedup\n");
  printf("  op check-dedup <op_type> [signer_id]                 Check dedup for operation type\n");
  printf("  compact                       Run compaction on all items\n");
}

void cli_print_usage(const char* prog) {
  printf("CRABS - Cryptographic Resource Authorization & Binding System\n\n");
  printf("Usage: %s <command> [subcommand] [args]\n\n", prog);
  printf("Commands:\n");
  printf("  init <admin_id>          Initialize a new CRABS node\n");
  printf("  load <path>              Load node state from file\n");
  printf("  load-sealed <path> <keyfile>  Load state and restore its sealed master key\n");
  printf("  save <path>              Save node state to file (requires an imported seal key)\n");
  printf("  seal-key import <keyfile>  Import the at-rest seal key (64 hex chars; in memory only)\n");
  _print_state_usage();
  _print_user_usage();
  _print_item_usage();
  _print_policy_usage();
  _print_key_usage();
  _print_op_usage();
  printf("  compact                 Run tombstone compaction on all items\n");
  printf("\n  help                     Show this help message\n");
}

cli_result_e cli_dispatch(cli_node_t* node, int argc, char** argv) {
  if (argc < 2) {
    cli_print_usage(argv[0]);
    return CLI_ERR_ARGS;
  }

  const char* cmd = argv[1];

  // Commands that don't need an initialized node
  if (strcmp(cmd, "help") == 0) {
    cli_print_usage(argv[0]);
    return CLI_OK;
  }

  if (strcmp(cmd, "key") == 0 && argc >= 3 && strcmp(argv[2], "generate") == 0) {
    return cli_cmd_key_generate();
  }

  // Commands that need an initialized node
  if (strcmp(cmd, "init") == 0) {
    if (argc < 3) {
      printf("Usage: %s init <admin_id>\n", argv[0]);
      return CLI_ERR_ARGS;
    }
    return cli_node_init(node, argv[2]);
  }

  if (strcmp(cmd, "load") == 0) {
    if (argc < 3) {
      printf("Usage: %s load <path>\n", argv[0]);
      return CLI_ERR_ARGS;
    }
    return cli_node_load(node, argv[2]);
  }

  if (strcmp(cmd, "save") == 0) {
    if (argc < 3) {
      printf("Usage: %s save <path>\n", argv[0]);
      return CLI_ERR_ARGS;
    }
    return cli_node_save(node, argv[2]);
  }

  if (strcmp(cmd, "seal-key") == 0) {
    if (argc >= 3 && strcmp(argv[2], "import") == 0) {
      if (argc < 4) {
        printf("Usage: %s seal-key import <keyfile with 64 hex chars>\n", argv[0]);
        return CLI_ERR_ARGS;
      }
      char hex[65] = {0};
      FILE* seal_file = fopen(argv[3], "r");
      if (seal_file == NULL) return CLI_ERR_IO;
      if (fread(hex, 1, 64, seal_file) != 64) {
        fclose(seal_file);
        return CLI_ERR_IO;
      }
      fclose(seal_file);
      cli_result_e result = cli_node_set_seal_key(node, hex);
      OPENSSL_cleanse(hex, sizeof(hex));
      if (result == CLI_OK) printf("Seal key imported (in memory only).\n");
      return result;
    }
    printf("Usage: %s seal-key import <keyfile>\n", argv[0]);
    return CLI_ERR_ARGS;
  }

  if (strcmp(cmd, "load-sealed") == 0) {
    if (argc < 4) {
      printf("Usage: %s load-sealed <path> <seal-key-file>\n", argv[0]);
      return CLI_ERR_ARGS;
    }
    char hex[65] = {0};
    FILE* seal_file = fopen(argv[3], "r");
    if (seal_file == NULL) return CLI_ERR_IO;
    if (fread(hex, 1, 64, seal_file) != 64) {
      fclose(seal_file);
      return CLI_ERR_IO;
    }
    fclose(seal_file);
    cli_result_e result = cli_node_load_sealed(node, argv[2], hex);
    OPENSSL_cleanse(hex, sizeof(hex));
    return result;
  }

  // Check for known commands before init gate
  if (strcmp(cmd, "state") != 0 && strcmp(cmd, "user") != 0 &&
      strcmp(cmd, "item") != 0 && strcmp(cmd, "policy") != 0 &&
      strcmp(cmd, "key") != 0 && strcmp(cmd, "op") != 0 &&
      strcmp(cmd, "seal-key") != 0 && strcmp(cmd, "load-sealed") != 0) {
    printf("Unknown command: %s\n", cmd);
    cli_print_usage(argv[0]);
    return CLI_ERR_ARGS;
  }

  // All remaining commands need an initialized node
  if (!node->initialized) {
    printf("Error: Node not initialized. Run '%s init <admin_id>' first.\n", argv[0]);
    return CLI_ERR_NOT_INIT;
  }

  // Audit: warn once before the first mutating command on an unauthenticated
  // snapshot (the hard gate is at save time).
  _warn_first_unauthenticated_mutation(node, cmd, argc >= 3 ? argv[2] : NULL);

  if (strcmp(cmd, "state") == 0) {
    if (argc < 3) {
      _print_state_usage();
      return CLI_ERR_ARGS;
    }
    const char* sub = argv[2];
    if (strcmp(sub, "show") == 0)      return cli_cmd_state_show(node);
    if (strcmp(sub, "items") == 0)     return cli_cmd_state_items(node);
    if (strcmp(sub, "policies") == 0)  return cli_cmd_state_policies(node);
    if (strcmp(sub, "config") == 0)    return cli_cmd_state_config(node);
    if (strcmp(sub, "accept-unverified") == 0)
      return cli_cmd_state_accept_unverified(node);
    printf("Unknown state subcommand: %s\n", sub);
    _print_state_usage();
    return CLI_ERR_ARGS;
  }

  if (strcmp(cmd, "user") == 0) {
    if (argc < 3) {
      _print_user_usage();
      return CLI_ERR_ARGS;
    }
    const char* sub = argv[2];
    if (strcmp(sub, "register") == 0) {
      if (argc < 5) {
        printf("Usage: user register <id> <pubkey_hex>\n");
        return CLI_ERR_ARGS;
      }
      return cli_cmd_user_register(node, argv[3], argv[4]);
    }
    if (strcmp(sub, "list") == 0)       return cli_cmd_user_list(node);
    if (strcmp(sub, "grant") == 0) {
      if (argc < 5) {
        printf("Usage: user grant <id> <role> [value]\n");
        return CLI_ERR_ARGS;
      }
      return cli_cmd_user_grant(node, argv[3], argv[4], argc > 5 ? argv[5] : NULL);
    }
    if (strcmp(sub, "revoke") == 0) {
      if (argc < 5) {
        printf("Usage: user revoke <id> <role>\n");
        return CLI_ERR_ARGS;
      }
      return cli_cmd_user_revoke(node, argv[3], argv[4]);
    }
    if (strcmp(sub, "suspend") == 0) {
      if (argc < 4) {
        printf("Usage: user suspend <id>\n");
        return CLI_ERR_ARGS;
      }
      return cli_cmd_user_suspend(node, argv[3]);
    }
    printf("Unknown user subcommand: %s\n", sub);
    _print_user_usage();
    return CLI_ERR_ARGS;
  }

  if (strcmp(cmd, "item") == 0) {
    if (argc < 3) {
      _print_item_usage();
      return CLI_ERR_ARGS;
    }
    const char* sub = argv[2];
    if (strcmp(sub, "add") == 0) {
      if (argc < 5) {
        printf("Usage: item add <name> <type>\n");
        return CLI_ERR_ARGS;
      }
      return cli_cmd_item_add(node, argv[3], argv[4]);
    }
    if (strcmp(sub, "list") == 0) return cli_cmd_item_list(node);
    printf("Unknown item subcommand: %s\n", sub);
    _print_item_usage();
    return CLI_ERR_ARGS;
  }

  if (strcmp(cmd, "policy") == 0) {
    if (argc < 3) {
      _print_policy_usage();
      return CLI_ERR_ARGS;
    }
    if (strcmp(argv[2], "add") == 0) {
      if (argc < 5) {
        printf("Usage: policy add <operation> <expression>\n");
        return CLI_ERR_ARGS;
      }
      return cli_cmd_policy_add(node, argv[3], argv[4]);
    }
    printf("Unknown policy subcommand: %s\n", argv[2]);
    _print_policy_usage();
    return CLI_ERR_ARGS;
  }

  if (strcmp(cmd, "key") == 0) {
    if (argc < 3) {
      _print_key_usage();
      return CLI_ERR_ARGS;
    }
    const char* sub = argv[2];
    if (strcmp(sub, "generate") == 0)   return cli_cmd_key_generate();
    if (strcmp(sub, "refresh") == 0) {
      if (argc < 4) {
        printf("Usage: key refresh <user_id>\n");
        return CLI_ERR_ARGS;
      }
      return cli_cmd_key_refresh(node, argv[3]);
    }
    if (strcmp(sub, "revoke") == 0) {
      if (argc < 5) {
        printf("Usage: key revoke <user_id> <new_public_key_hex>\n");
        return CLI_ERR_ARGS;
      }
      return cli_cmd_key_revoke(node, argv[3], argv[4]);
    }
    printf("Unknown key subcommand: %s\n", sub);
    _print_key_usage();
    return CLI_ERR_ARGS;
  }

  if (strcmp(cmd, "op") == 0) {
    if (argc < 3) {
      _print_op_usage();
      return CLI_ERR_ARGS;
    }
    const char* sub = argv[2];
    if (strcmp(sub, "submit") == 0) {
      if (argc < 4) {
        printf("Usage: op submit <type> [payload_hex] [signer_id]\n");
        return CLI_ERR_ARGS;
      }
      return cli_cmd_op_submit(node, argv[3],
                                argc > 4 ? argv[4] : NULL,
                                argc > 5 ? argv[5] : NULL);
    }
    if (strcmp(sub, "define") == 0) {
      if (argc < 5) {
        printf("Usage: op define <op_type> <dedup_type> [tracker_path|flag_path|condition]\n");
        printf("  dedup_type: none|per_user|global|custom\n");
        printf("  For per_user: op define <op_type> per_user <tracker_path>\n");
        printf("  For global: op define <op_type> global <flag_path>\n");
        printf("  For custom: op define <op_type> custom <condition>\n");
        printf("  For none: op define <op_type> none\n");
        return CLI_ERR_ARGS;
      }
      const char* path = argc > 5 ? argv[5] : NULL;
      bool dedup_valid = false;
      dedup_type_e dtype = _parse_dedup_type(argv[4], &dedup_valid);
      const char* tracker = NULL, *flag = NULL, *cond = NULL;
      if (dtype == DEDUP_PER_USER) tracker = path;
      else if (dtype == DEDUP_GLOBAL) flag = path;
      else if (dtype == DEDUP_CUSTOM) cond = path;
      return cli_cmd_op_define(node, argv[3], argv[4], tracker, flag, cond);
    }
    if (strcmp(sub, "check-dedup") == 0) {
      if (argc < 4) {
        printf("Usage: op check-dedup <op_type> [signer_id]\n");
        return CLI_ERR_ARGS;
      }
      return cli_cmd_op_check_dedup(node, argv[3],
                                      argc > 4 ? argv[4] : NULL);
    }
    printf("Unknown op subcommand: %s\n", sub);
    _print_op_usage();
    return CLI_ERR_ARGS;
  }

  if (strcmp(cmd, "compact") == 0) {
    return cli_cmd_compact(node);
  }

  // Unreachable if all commands are handled above
  return CLI_ERR_ARGS;
}