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
#include "../Lineage/lineage.h"
#include "../TimeSource/time_source.h"

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
// CLI Node Context
// ============================================================
#define CRABS_CLI_KEYRING_MAX 32

// Session-scoped time-source selection (cli_node_t.time_source_mode).
typedef enum {
  CLI_TIME_SOURCE_SYSTEM = 0,  // local system clock (the default)
  CLI_TIME_SOURCE_HTTPS  = 1   // authenticated HTTPS time source
} cli_time_source_mode_e;

typedef struct {
  char             user_id[CRABS_MAX_USER_ID];
  ecdsa_keypair_t* key;
} cli_user_key_t;

typedef struct {
  state_t*             state;
  attribute_machine_t*  attr_machine;
  // Always NULL since v10: the single live ABE authority lives on
  // attr_machine->base_state.abe_mk. Kept as a field so destroy paths and
  // bindings signatures don't churn until Plan 2 (lineage) reshapes them.
  abe_master_key_t*    abe_mk;
  ecdsa_keypair_t*     node_key;
  // Per-user ECDSA key custody (audit M-17): operations are signed with the
  // key matching op->signer_id, not the node key. The bootstrap admin's key
  // is node_key; other users' keys are added via cli_node_add_user_key.
  cli_user_key_t       keyring[CRABS_CLI_KEYRING_MAX];
  uint32_t             keyring_count;
  // Audit M-1: pending state-blob signature verification. A loaded snapshot
  // signed by the saving node's key cannot be verified at load time (no
  // trusted public key exists until the operator imports the persisted
  // private key), so cli_node_load keeps the signed payload + signature here
  // and cli_node_load_key enforces the signature before granting custody.
  // Saving is refused while verification is pending.
  uint8_t*             state_sig_payload;   // owned copy of the signed payload
  size_t               state_sig_payload_len;
  uint8_t              state_sig_signature[CRABS_SIG_SIZE];
  bool                 state_sig_pending;
  // Audit: an UNSIGNED snapshot carries no node-key signature, so its
  // provenance is unauthenticated. cli_node_save refuses to re-sign it (the
  // operator's key would end up on attacker-supplied state) until the
  // operator runs 'state accept-unverified'.
  bool                 loaded_unauthenticated;
  bool                 unauth_warning_shown;
  bool                 initialized;
  // Durability (v10): the operator's at-rest seal key for the machine MSK.
  // 32 raw bytes imported from a keyfile; never serialized anywhere.
  uint8_t              seal_key[32];
  bool                 seal_key_valid;
  // Lineage (v1.7): the node-resident machine blueprint draft — NULL until
  // 'machine blueprint new' starts authoring, replaced by each later 'new',
  // destroyed by 'machine blueprint drop' and by cli_node_destroy.
  machine_blueprint_t* blueprint_draft;
  // Authenticated time-source selection (A10-L9 wiring, 'time-source'
  // command). Session-scoped runtime config — NOT serialized anywhere:
  // implementations are code + endpoint, not machine state. Re-applied to
  // whichever state_t the node currently carries whenever init/load recreates
  // that state (otherwise a configured source would silently drop back to the
  // system clock). R7-02: a configured HTTPS source that cannot fetch never
  // falls back to the local clock — time reports invalid and window checks
  // fail closed.
  int                      time_source_mode;  // cli_time_source_mode_e
  char                     https_url[256];    // "" = default endpoint
  crabs_time_source_ops_t* https_source;      // owned ops, NULL otherwise
} cli_node_t;

// Add (or replace) a per-user signing key the CLI can use to sign operations
// on that user's behalf. The CLI takes ownership of `key`.
cli_result_e cli_node_add_user_key(cli_node_t* node, const char* user_id,
                                     ecdsa_keypair_t* key);
// Look up a user's custodied signing key (NULL if none).
ecdsa_keypair_t* cli_node_get_user_key(cli_node_t* node, const char* user_id);

// ============================================================
// Node Lifecycle
// ============================================================
cli_node_t* cli_node_create(void);
void        cli_node_destroy(cli_node_t* node);
cli_result_e cli_node_init(cli_node_t* node, const char* admin_id);
cli_result_e cli_node_load(cli_node_t* node, const char* path);
// Audit L-l: restore node-key custody after a load. cli_node_load generates a
// fresh, unrelated node key, so the node cannot sign for the bootstrap admin
// until the operator imports the persisted private key (64 hex chars). The
// derived public key must match a registered user; that user's id is used as
// the custody alias.
// Audit L5: pass "-" as private_key_hex to read the 64-char hex line from
// stdin instead of argv, keeping the private key out of the process list and
// shell history.
cli_result_e cli_node_load_key(cli_node_t* node, const char* private_key_hex);
// Import the at-rest seal key (64 hex chars, decoded to 32 raw bytes). Once
// set, cli_node_save persists the ABE MSK sealed under it and cli_node_load
// unseals a saved MSK with it. Re-import replaces the key wholesale. Stored
// in memory only — it is never serialized to any file.
cli_result_e cli_node_set_seal_key(cli_node_t* node, const char* key_hex);
// Load a state file whose MSK section is sealed: sets the seal key BEFORE
// loading so the machine's authority (the MSK) is restored during the
// parse. key_hex is the 64-hex-char seal key.
cli_result_e cli_node_load_sealed(cli_node_t* node, const char* path,
                                    const char* key_hex);
cli_result_e cli_node_save(cli_node_t* node, const char* path);

// ============================================================
// State Queries
// ============================================================
cli_result_e cli_cmd_state_show(cli_node_t* node);
cli_result_e cli_cmd_state_items(cli_node_t* node);
cli_result_e cli_cmd_state_policies(cli_node_t* node);
cli_result_e cli_cmd_state_config(cli_node_t* node);
// Audit: acknowledge an unauthenticated (unsigned) snapshot after load so
// cli_node_save will accept it. No-op (with a notice) when the state is
// already authenticated.
cli_result_e cli_cmd_state_accept_unverified(cli_node_t* node);

// Durability (v10): re-enroll the snapshot's recorded bootstrap admin on a
// legacy (pre-v10) load, where no user registry was serialized. No-op
// (with a notice) when the machine already carries users.
cli_result_e cli_cmd_machine_migrate(cli_node_t* node);

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
// Write-domains v1: domain pill word, writer, chain seq, ordering module,
// and quarantined writers for one item.
cli_result_e cli_cmd_item_info(cli_node_t* node, const char* name);

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
// Audit H-B: revoke + rotate is node-blind. The operator supplies the user's
// new public key (66 hex chars, compressed secp256k1); the node records it
// and issues a new ABE envelope. The user generates their own private key
// out-of-band; the node never learns it.
cli_result_e cli_cmd_key_revoke(cli_node_t* node, const char* user_id,
                                  const char* new_public_key_hex);

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
// Compaction Command (v1.5.2 §4.3)
// ============================================================
cli_result_e cli_cmd_compact(cli_node_t* node);

// ============================================================
// Time Source Selection (A10-L9 wiring)
// ============================================================
// Select the machine's physical clock for this session. 'https' creates and
// applies the authenticated HTTPS time source (url NULL/"" = default
// endpoint); 'system' clears any configured source; 'show' prints the
// current selection. The node's owned ops object is destroyed on switch,
// clear, and cli_node_destroy. R7-02: a configured source that fails to
// fetch never falls back to the local clock — time reports invalid.
cli_result_e cli_cmd_time_source_https(cli_node_t* node, const char* url);
cli_result_e cli_cmd_time_source_system(cli_node_t* node);
cli_result_e cli_cmd_time_source_show(cli_node_t* node);

// ============================================================
// Command Dispatch
// ============================================================
cli_result_e cli_dispatch(cli_node_t* node, int argc, char** argv);
void          cli_print_usage(const char* prog);

// Audit A10-7b: shell mode. The single-shot argv path (main: create node →
// dispatch → destroy node) discards everything a command sets up — a loaded
// snapshot's custody, an imported seal key, a 'state accept-unverified'
// acknowledgment all die with the process — so load → import → mutate → save
// was unusable in the shipped binary. The shell dispatches each entered line
// against the SAME persistent node instead.
//
// Tokenizes one input line and dispatches it against `node`. `line` is
// modified in place. Tokenizer grammar (audit 11 A11-2 — quote-aware):
//   - Whitespace (space/tab/CR/LF) separates tokens OUTSIDE a quote span.
//   - '"' or '\'' opens a no-split span ending at the MATCHING quote char;
//     the quote chars are stripped from the token, the other quote kind
//     inside a span is an ordinary byte, and a span concatenates with
//     adjacent text into one token ("ab"cd → abcd).
//   - There are NO escape sequences: backslash is an ordinary byte.
//   - An unbalanced quote at end of line REFUSES the line (CLI_ERR_ARGS),
//     as does a token consisting of an empty quoted span ("").
//   - Lines with more than the fixed token limit are REFUSED with
//     CLI_ERR_ARGS rather than silently truncated: truncation could quietly
//     drop an argument from a destructive command and retarget it (and, per
//     A11-2, silently weaken an installed policy expression).
// Blank lines are no-ops and return CLI_OK. A line whose first token is
// "exit" or "quit" is handled here, never reaches cli_dispatch, and sets
// `*should_exit` so the caller's loop stops; on entry `*should_exit` is
// always cleared first, so the caller can reuse one flag across iterations.
// All other lines go to cli_dispatch and its result is returned
// (CLI_OK on success).
cli_result_e cli_shell_execute_line(cli_node_t* node, char* line,
                                     bool* should_exit);

// ============================================================
// Utility Functions
// ============================================================
cli_result_e cli_hex_to_bytes(const char* hex, uint8_t* out, size_t out_len);
void         cli_bytes_to_hex(const uint8_t* bytes, size_t len, char* out);
const char*  cli_error_string(crabs_error_e err);
const char*  cli_protocol_state_string(protocol_state_e state);

#endif // CRABS_CLI_H