//
// Created by victor on 5/1/25.
//

#include "cli.h"
#include "../Util/allocator.h"
#include "../Serialization/serialization.h"
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
  if (node->attr_machine != NULL) {
    attribute_machine_destroy(node->attr_machine);
  } else if (node->state != NULL) {
    state_destroy(node->state);
  }
  if (node->abe_mk != NULL) crypto_abe_master_key_destroy(node->abe_mk);
  if (node->node_key != NULL) crypto_ecdsa_keypair_destroy(node->node_key);
  free(node);
}

cli_result_e cli_node_init(cli_node_t* node, const char* admin_id) {
  if (node == NULL || admin_id == NULL) return CLI_ERR_ARGS;
  if (node->initialized) return CLI_ERR_ARGS;

  // Generate ABE master key
  node->abe_mk = crypto_abe_setup();
  if (node->abe_mk == NULL) return CLI_ERR_EXEC;

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
  return CLI_OK;
}

cli_result_e cli_node_load(cli_node_t* node, const char* path) {
  if (node == NULL || path == NULL) return CLI_ERR_ARGS;
  if (node->initialized) return CLI_ERR_ARGS;

  FILE* f = fopen(path, "rb");
  if (f == NULL) return CLI_ERR_IO;

  fseek(f, 0, SEEK_END);
  long fsize = ftell(f);
  fseek(f, 0, SEEK_SET);

  if (fsize <= 0) {
    fclose(f);
    return CLI_ERR_IO;
  }

  uint8_t* data = get_memory((size_t)fsize);
  if (fread(data, 1, (size_t)fsize, f) != (size_t)fsize) {
    free(data);
    fclose(f);
    return CLI_ERR_IO;
  }
  fclose(f);

  state_t* loaded = crabs_deserialize_state(data, (size_t)fsize);
  free(data);

  if (loaded == NULL) return CLI_ERR_EXEC;

  // Create attribute machine wrapping loaded state
  node->abe_mk = crypto_abe_setup();
  node->node_key = crypto_ecdsa_generate();

  // Build attribute machine from loaded state
  node->attr_machine = get_clear_memory(sizeof(attribute_machine_t));
  node->attr_machine->base_state = *loaded;
  node->attr_machine->users = NULL;
  node->attr_machine->user_count = 0;
  node->attr_machine->current_time_ms = 0;
  node->attr_machine->base_state.attr_machine = node->attr_machine;
  free(loaded);

  state_set_node_key(&node->attr_machine->base_state,
                     node->node_key->private_key,
                     node->node_key->public_key);

  node->initialized = true;
  return CLI_OK;
}

cli_result_e cli_node_save(cli_node_t* node, const char* path) {
  if (node == NULL || path == NULL || !node->initialized) return CLI_ERR_ARGS;

  serialized_buffer_t* buf = crabs_serialize_state(&node->attr_machine->base_state);
  if (buf == NULL) return CLI_ERR_EXEC;

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

  printf("State Version: %lu\n", state->version);
  uint32_t item_count = 0;
  data_item_t* item = state->items;
  while (item != NULL) {
    item_count++;
    item = item->next;
  }
  printf("  Data Items: %u\n", item_count);
  printf("  Policies: %u\n", state->policy_count);
  printf("  Log Entries: %lu\n", state->log_count);
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
  printf("  max_lock_duration_ms: %lu\n", cfg->max_lock_duration_ms);
  printf("  max_lock_extensions:  %u\n", cfg->max_lock_extensions);
  printf("  allow_force_unlock:   %s\n", cfg->allow_force_unlock ? "true" : "false");
  printf("  bootstrap_admin:     %s\n", cfg->bootstrap_admin[0] ? cfg->bootstrap_admin : "(not set)");
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

  // Use admin as signer (first registered user)
  const char* signer_id = node->attr_machine->users ? node->attr_machine->users->user_id : user_id;
  crabs_error_e err = attribute_machine_grant_role(node->attr_machine, user_id,
                                                     role, value ? value : "", signer_id);
  if (err != CRABS_SUCCESS) {
    printf("Error: %s\n", cli_error_string(err));
    return CLI_ERR_EXEC;
  }

  printf("Role '%s' granted to '%s'.\n", role, user_id);
  return CLI_OK;
}

cli_result_e cli_cmd_user_revoke(cli_node_t* node, const char* user_id,
                                   const char* role) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  if (user_id == NULL || role == NULL) return CLI_ERR_ARGS;

  const char* signer_id = node->attr_machine->users ? node->attr_machine->users->user_id : user_id;
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

  crabs_error_e err = attribute_machine_suspend_user(node->attr_machine, user_id);
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
    printf("  New key version: %lu\n", user->key_version);
  }

  return CLI_OK;
}

cli_result_e cli_cmd_key_revoke(cli_node_t* node, const char* user_id) {
  if (node == NULL || !node->initialized) return CLI_ERR_NOT_INIT;
  if (user_id == NULL) return CLI_ERR_ARGS;

  recovery_result_t* result = crypto_revoke_and_rotate(
      node->abe_mk,
      node->node_key->private_key,
      node->attr_machine,
      user_id,
      node->attr_machine->base_state.version,
      0);

  if (result == NULL) {
    printf("Error: Key revocation failed.\n");
    return CLI_ERR_EXEC;
  }

  printf("Keys revoked and rotated for user '%s'.\n", user_id);

  if (result->new_ecdsa_key != NULL) {
    char pub_hex[67];
    cli_bytes_to_hex(result->new_ecdsa_key->public_key, 33, pub_hex);
    printf("  New public key: %s\n", pub_hex);
  }

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

  // Sign the operation if we have a signer and node key
  if (op->signer_id[0] != '\0' && node->attr_machine->base_state.node_key_valid) {
    user_t* user = attribute_machine_find_user(node->attr_machine, op->signer_id);
    if (user != NULL) {
      serialized_buffer_t* sig_data = crabs_serialize_for_signing(op);
      if (sig_data != NULL) {
        crypto_ecdsa_sign(node->node_key->private_key,
                          sig_data->data, sig_data->len, op->signature);
        op->signer_key_version = user->key_version;
        serialized_buffer_destroy(sig_data);
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
  strncpy(op->signer_id, node->attr_machine->users ? node->attr_machine->users->user_id : "admin",
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
// Command Dispatch
// ============================================================

static void _print_state_usage(void) {
  printf("  state show              Show node state summary\n");
  printf("  state items            List data items\n");
  printf("  state policies         List policies\n");
  printf("  state config           Show machine configuration\n");
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
}

void cli_print_usage(const char* prog) {
  printf("CRABS - Cryptographic Resource Authorization & Binding System\n\n");
  printf("Usage: %s <command> [subcommand] [args]\n\n", prog);
  printf("Commands:\n");
  printf("  init <admin_id>          Initialize a new CRABS node\n");
  printf("  load <path>              Load node state from file\n");
  printf("  save <path>              Save node state to file\n");
  _print_state_usage();
  _print_user_usage();
  _print_item_usage();
  _print_policy_usage();
  _print_key_usage();
  _print_op_usage();
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

  // Check for known commands before init gate
  if (strcmp(cmd, "state") != 0 && strcmp(cmd, "user") != 0 &&
      strcmp(cmd, "item") != 0 && strcmp(cmd, "policy") != 0 &&
      strcmp(cmd, "key") != 0 && strcmp(cmd, "op") != 0) {
    printf("Unknown command: %s\n", cmd);
    cli_print_usage(argv[0]);
    return CLI_ERR_ARGS;
  }

  // All remaining commands need an initialized node
  if (!node->initialized) {
    printf("Error: Node not initialized. Run '%s init <admin_id>' first.\n", argv[0]);
    return CLI_ERR_NOT_INIT;
  }

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
      if (argc < 4) {
        printf("Usage: key revoke <user_id>\n");
        return CLI_ERR_ARGS;
      }
      return cli_cmd_key_revoke(node, argv[3]);
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

  // Unreachable if all commands are handled above
  return CLI_ERR_ARGS;
}