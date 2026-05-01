//
// Created by victor on 5/1/25.
//

#ifndef CRABS_CLI_H
#define CRABS_CLI_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"
#include "../Attribute/attribute_machine.h"
#include "../StateMachine/state_machine.h"
#include "../Crypto/crypto.h"

// ============================================================
// CLI Node Context
// ============================================================
typedef struct {
  state_t*             state;
  attribute_machine_t*  attr_machine;
  abe_master_key_t*    abe_mk;
  ecdsa_keypair_t*     node_key;
  bool                 initialized;
} cli_node_t;

// ============================================================
// CLI Result Codes
// ============================================================
typedef enum {
  CLI_OK            = 0,
  CLI_ERR_ARGS      = 1,
  CLI_ERR_NOT_INIT  = 2,
  CLI_ERR_EXEC      = 3,
  CLI_ERR_IO        = 4,
  CLI_ERR_NOT_FOUND = 5
} cli_result_e;

// ============================================================
// Node Lifecycle
// ============================================================
cli_node_t* cli_node_create(void);
void        cli_node_destroy(cli_node_t* node);
cli_result_e cli_node_init(cli_node_t* node, const char* admin_id);
cli_result_e cli_node_load(cli_node_t* node, const char* path);
cli_result_e cli_node_save(cli_node_t* node, const char* path);

// ============================================================
// State Queries
// ============================================================
cli_result_e cli_cmd_state_show(cli_node_t* node);
cli_result_e cli_cmd_state_items(cli_node_t* node);
cli_result_e cli_cmd_state_policies(cli_node_t* node);
cli_result_e cli_cmd_state_config(cli_node_t* node);

// ============================================================
// User Management
// ============================================================
cli_result_e cli_cmd_user_register(cli_node_t* node, const char* user_id,
                                    const char* public_key_hex);
cli_result_e cli_cmd_user_list(cli_node_t* node);
cli_result_e cli_cmd_user_grant(cli_node_t* node, const char* user_id,
                                  const char* role, const char* value);
cli_result_e cli_cmd_user_revoke(cli_node_t* node, const char* user_id,
                                   const char* role);
cli_result_e cli_cmd_user_suspend(cli_node_t* node, const char* user_id);

// ============================================================
// Data Item Management
// ============================================================
cli_result_e cli_cmd_item_add(cli_node_t* node, const char* name,
                                const char* type_str);
cli_result_e cli_cmd_item_list(cli_node_t* node);

// ============================================================
// Policy Management
// ============================================================
cli_result_e cli_cmd_policy_add(cli_node_t* node, const char* operation,
                                  const char* expression);

// ============================================================
// Key Management
// ============================================================
cli_result_e cli_cmd_key_generate(void);
cli_result_e cli_cmd_key_refresh(cli_node_t* node, const char* user_id);
cli_result_e cli_cmd_key_revoke(cli_node_t* node, const char* user_id);

// ============================================================
// Operation Submission
// ============================================================
cli_result_e cli_cmd_op_submit(cli_node_t* node, const char* type,
                                 const char* payload_hex, const char* signer_id);

// ============================================================
// Dedup Commands
// ============================================================
cli_result_e cli_cmd_op_define(cli_node_t* node, const char* op_type_name,
                                const char* dedup_type_str,
                                const char* tracker_path,
                                const char* flag_path,
                                const char* condition);
cli_result_e cli_cmd_op_check_dedup(cli_node_t* node, const char* op_type_name,
                                      const char* signer_id);

// ============================================================
// Command Dispatch
// ============================================================
cli_result_e cli_dispatch(cli_node_t* node, int argc, char** argv);
void          cli_print_usage(const char* prog);

// ============================================================
// Utility Functions
// ============================================================
cli_result_e cli_hex_to_bytes(const char* hex, uint8_t* out, size_t out_len);
void         cli_bytes_to_hex(const uint8_t* bytes, size_t len, char* out);
const char*  cli_error_string(crabs_error_e err);
const char*  cli_protocol_state_string(protocol_state_e state);

#endif // CRABS_CLI_H