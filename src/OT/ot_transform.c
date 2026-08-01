//
// Created by victor on 5/1/25.
//
// OT Transform Functions & Matrix (v1.5 §4)
// Implements the 5x5 operational transform matrix and all transform functions.
//

#include "ot_transform.h"
#include "../Compaction/compact_op.h"
#include <string.h>

// ============================================================
// Causal Ordering (v1.5 §4.1)
// ============================================================

bool crabs_causally_before(const crabs_ot_op_id_t* a, const crabs_ot_op_id_t* b) {
  if (a == NULL || b == NULL) return false;
  // Same node: the per-node sequence number is a sound happens-before order.
  if (strncmp(a->node_id, b->node_id, CRABS_MAX_USER_ID) == 0) {
    return a->sequence_num < b->sequence_num;
  }
  // Cross-node: an ID alone carries no causal information. The prior code
  // compared wall-clock timestamps, which is unsound (clocks skew and an
  // attacker can forge timestamps to reorder history). Cross-node causality
  // is decided by the dependency set (deps[]) — see crabs_op_depends_on.
  return false;
}

// True if `op` declares a causal dependency on `predecessor` (i.e. predecessor
// happens-before op). This is the sound, dependency-based replacement for the
// wall-clock comparison that previously decided cross-node causality.
bool crabs_op_depends_on(const crabs_ot_operation_t* op,
                          const crabs_ot_op_id_t* predecessor) {
  if (op == NULL || predecessor == NULL) return false;
  for (uint32_t i = 0; i < op->dep_count && i < CRABS_OT_MAX_DEPS; i++) {
    if (strncmp(op->deps[i].node_id, predecessor->node_id, CRABS_MAX_USER_ID) == 0 &&
        op->deps[i].sequence_num == predecessor->sequence_num) {
      return true;
    }
  }
  // Same-node lower sequence is also happens-before.
  if (op->id.node_id[0] != '\0' &&
      strncmp(op->id.node_id, predecessor->node_id, CRABS_MAX_USER_ID) == 0) {
    return op->id.sequence_num > predecessor->sequence_num;
  }
  return false;
}

// ============================================================
// Core Transform Functions (v1.5 §4.2)
// ============================================================

// T1: INSERT vs INSERT
// op1 is the local operation being transformed against op2 (remote).
// If both insert at the same position, the one with lower priority shifts right.
crabs_ot_operation_t* crabs_transform_insert_insert(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  if (op1->visible_pos > op2->visible_pos) {
    op1->visible_pos += 1;
  } else if (op1->visible_pos == op2->visible_pos) {
    // Audit F-4: tie-break must be a STRICT total order (antisymmetric) so
    // both replicas agree on which op shifts. The prior `op1->priority >=
    // op2->priority` rule shifted BOTH ops when priorities were equal (TP2
    // violation → divergent documents). Now the op with the lexicographically
    // larger (priority, node_id) shifts right; the other stays. Exactly one
    // replica shifts, so both converge.
    bool shift;
    if (op1->priority != op2->priority) {
      shift = (op1->priority > op2->priority);
    } else {
      int cmp = strncmp(op1->id.node_id, op2->id.node_id, CRABS_MAX_USER_ID);
      shift = (cmp > 0);
      // If node_id is also equal (same node, same priority), the per-node
      // sequence number is the final tiebreaker — but same-node same-priority
      // should not happen (sequence_num is unique per node). Default to no
      // shift to avoid symmetric behavior.
      if (cmp == 0) shift = false;
    }
    if (shift) op1->visible_pos += 1;
  }
  return op1;
}

// T2: DELETE vs INSERT
// If remote insert is before or at the delete position, shift delete right
crabs_ot_operation_t* crabs_transform_delete_insert(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  if (op2->visible_pos <= op1->visible_pos) {
    op1->visible_pos += 1;
  }
  return op1;
}

// T3: INSERT vs DELETE
// If remote delete is before or at the insert position, shift insert left
crabs_ot_operation_t* crabs_transform_insert_delete(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  if (op2->visible_pos < op1->visible_pos) {
    op1->visible_pos -= 1;
  }
  return op1;
}

// T4: DELETE vs DELETE
// If same position, second delete becomes no-op; otherwise shift if needed
crabs_ot_operation_t* crabs_transform_delete_delete(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  if (op1->visible_pos == op2->visible_pos) {
    // Same position: already deleted, mark as no-op
    op1->op_type = 0;
    return op1;
  }
  if (op2->visible_pos < op1->visible_pos) {
    op1->visible_pos -= 1;
  }
  return op1;
}

// T5: MOVE vs MOVE
// MOVE(pos1, pos2) = DELETE(pos1) + INSERT(pos2)
// Transform composite: first transform delete part, then insert part
crabs_ot_operation_t* crabs_transform_move_move(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  // op1: move from visible_pos to visible_pos_2
  // op2: move from visible_pos to visible_pos_2
  // Transform op1's source and destination against op2

  // Transform source (delete) against op2's source (delete)
  if (op1->visible_pos == op2->visible_pos) {
    // Same source: no-op
    op1->op_type = 0;
    return op1;
  }
  // Adjust source position for op2's delete
  if (op2->visible_pos < op1->visible_pos) {
    op1->visible_pos -= 1;
  }
  // Adjust destination position for op2's insert
  if (op2->visible_pos_2 <= op1->visible_pos_2) {
    op1->visible_pos_2 += 1;
  }
  return op1;
}

// T6: SWAP vs INSERT
// Insert before swap positions shifts both swap positions right
crabs_ot_operation_t* crabs_transform_swap_insert(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  if (op2->visible_pos <= op1->visible_pos) {
    op1->visible_pos += 1;
  }
  if (op2->visible_pos <= op1->visible_pos_2) {
    op1->visible_pos_2 += 1;
  }
  return op1;
}

// T7: SWAP vs DELETE
// Delete before swap positions shifts both swap positions left
crabs_ot_operation_t* crabs_transform_swap_delete(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  if (op2->visible_pos < op1->visible_pos) {
    op1->visible_pos -= 1;
  }
  if (op2->visible_pos < op1->visible_pos_2) {
    op1->visible_pos_2 -= 1;
  }
  return op1;
}

// MOVE vs INSERT
crabs_ot_operation_t* crabs_transform_move_insert(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  if (op2->visible_pos <= op1->visible_pos) {
    op1->visible_pos += 1;
  }
  if (op2->visible_pos <= op1->visible_pos_2) {
    op1->visible_pos_2 += 1;
  }
  return op1;
}

// MOVE vs DELETE
crabs_ot_operation_t* crabs_transform_move_delete(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  if (op2->visible_pos < op1->visible_pos) {
    op1->visible_pos -= 1;
  }
  if (op2->visible_pos < op1->visible_pos_2) {
    op1->visible_pos_2 -= 1;
  }
  return op1;
}

// INSERT vs MOVE
crabs_ot_operation_t* crabs_transform_insert_move(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  // MOVE removes from src, inserts at dst
  if (op2->visible_pos < op1->visible_pos) {
    op1->visible_pos -= 1;
  }
  if (op2->visible_pos_2 <= op1->visible_pos) {
    op1->visible_pos += 1;
  }
  return op1;
}

// DELETE vs MOVE
crabs_ot_operation_t* crabs_transform_delete_move(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  if (op2->visible_pos < op1->visible_pos) {
    op1->visible_pos -= 1;
  }
  if (op2->visible_pos_2 <= op1->visible_pos) {
    op1->visible_pos += 1;
  }
  return op1;
}

// SWAP vs SWAP
crabs_ot_operation_t* crabs_transform_swap_swap(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  // If both swaps touch the same positions, lower priority yields
  if (op1->visible_pos == op2->visible_pos &&
      op1->visible_pos_2 == op2->visible_pos_2) {
    if (op1->priority >= op2->priority) {
      // Reverse the swap direction for tie-breaking
      uint64_t tmp = op1->visible_pos;
      op1->visible_pos = op1->visible_pos_2;
      op1->visible_pos_2 = tmp;
    }
  }
  return op1;
}

// SWAP vs MOVE
crabs_ot_operation_t* crabs_transform_swap_move(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  if (op2->visible_pos < op1->visible_pos) {
    op1->visible_pos -= 1;
  }
  if (op2->visible_pos_2 <= op1->visible_pos) {
    op1->visible_pos += 1;
  }
  if (op2->visible_pos < op1->visible_pos_2) {
    op1->visible_pos_2 -= 1;
  }
  if (op2->visible_pos_2 <= op1->visible_pos_2) {
    op1->visible_pos_2 += 1;
  }
  return op1;
}

// MOVE vs SWAP
crabs_ot_operation_t* crabs_transform_move_swap(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  if (op2->visible_pos <= op1->visible_pos) {
    op1->visible_pos += 1;
  }
  if (op2->visible_pos <= op1->visible_pos_2) {
    op1->visible_pos_2 += 1;
  }
  return op1;
}

// DELETE vs SWAP
crabs_ot_operation_t* crabs_transform_delete_swap(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  if (op2->visible_pos <= op1->visible_pos) {
    op1->visible_pos += 1;
  }
  if (op2->visible_pos_2 <= op1->visible_pos) {
    op1->visible_pos += 1;
  }
  return op1;
}

// INSERT vs SWAP
crabs_ot_operation_t* crabs_transform_insert_swap(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  if (op1 == NULL || op2 == NULL) return op1;
  if (op2->visible_pos < op1->visible_pos) {
    op1->visible_pos -= 1;
  }
  if (op2->visible_pos_2 < op1->visible_pos) {
    op1->visible_pos -= 1;
  }
  return op1;
}

// Identity: no transformation
crabs_ot_operation_t* crabs_transform_identity(
    crabs_ot_operation_t* op1, crabs_ot_operation_t* op2) {
  (void)op2;
  return op1;
}

// ============================================================
// Transform Matrix Initialization (v1.5 §4)
// ============================================================

void crabs_transform_matrix_init(crabs_ot_data_item_t* item) {
  if (item == NULL) return;

  // Row INSERT (0): vs INSERT, DELETE, UPDATE, MOVE, SWAP
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_INSERT, CRABS_OT_OP_INSERT,
                                    crabs_transform_insert_insert);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_INSERT, CRABS_OT_OP_DELETE,
                                    crabs_transform_insert_delete);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_INSERT, CRABS_OT_OP_UPDATE,
                                    crabs_transform_identity);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_INSERT, CRABS_OT_OP_MOVE,
                                    crabs_transform_insert_move);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_INSERT, CRABS_OT_OP_SWAP,
                                    crabs_transform_insert_swap);

  // Row DELETE (1): vs INSERT, DELETE, UPDATE, MOVE, SWAP
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_DELETE, CRABS_OT_OP_INSERT,
                                    crabs_transform_delete_insert);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_DELETE, CRABS_OT_OP_DELETE,
                                    crabs_transform_delete_delete);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_DELETE, CRABS_OT_OP_UPDATE,
                                    crabs_transform_identity);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_DELETE, CRABS_OT_OP_MOVE,
                                    crabs_transform_delete_move);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_DELETE, CRABS_OT_OP_SWAP,
                                    crabs_transform_delete_swap);

  // Row UPDATE (2): vs all — identity (updates don't affect positions)
  for (int i = 1; i <= CRABS_OT_OP_TYPE_COUNT; i++) {
    crabs_ot_data_item_set_transform(item, CRABS_OT_OP_UPDATE, (crabs_ot_op_type_e)i,
                                      crabs_transform_identity);
  }

  // Row MOVE (3): vs INSERT, DELETE, UPDATE, MOVE, SWAP
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_MOVE, CRABS_OT_OP_INSERT,
                                    crabs_transform_move_insert);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_MOVE, CRABS_OT_OP_DELETE,
                                    crabs_transform_move_delete);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_MOVE, CRABS_OT_OP_UPDATE,
                                    crabs_transform_identity);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_MOVE, CRABS_OT_OP_MOVE,
                                    crabs_transform_move_move);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_MOVE, CRABS_OT_OP_SWAP,
                                    crabs_transform_move_swap);

  // Row SWAP (4): vs INSERT, DELETE, UPDATE, MOVE, SWAP
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_SWAP, CRABS_OT_OP_INSERT,
                                    crabs_transform_swap_insert);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_SWAP, CRABS_OT_OP_DELETE,
                                    crabs_transform_swap_delete);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_SWAP, CRABS_OT_OP_UPDATE,
                                    crabs_transform_identity);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_SWAP, CRABS_OT_OP_MOVE,
                                    crabs_transform_swap_move);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_SWAP, CRABS_OT_OP_SWAP,
                                    crabs_transform_swap_swap);

  // Row COMPACT (5): vs INSERT, DELETE, UPDATE, MOVE, SWAP, COMPACT
  // COMPACT absorbs all preceding ops (they're part of the compacted state)
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_COMPACT, CRABS_OT_OP_INSERT,
                                    crabs_transform_compact_insert);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_COMPACT, CRABS_OT_OP_DELETE,
                                    crabs_transform_compact_delete);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_COMPACT, CRABS_OT_OP_UPDATE,
                                    crabs_transform_compact_update);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_COMPACT, CRABS_OT_OP_MOVE,
                                    crabs_transform_compact_move);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_COMPACT, CRABS_OT_OP_SWAP,
                                    crabs_transform_compact_swap);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_COMPACT, CRABS_OT_OP_COMPACT,
                                    crabs_transform_compact_compact);

  // Column COMPACT: preceding ops vs COMPACT are absorbed (become no-ops)
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_INSERT, CRABS_OT_OP_COMPACT,
                                    crabs_transform_insert_compact);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_DELETE, CRABS_OT_OP_COMPACT,
                                    crabs_transform_delete_compact);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_UPDATE, CRABS_OT_OP_COMPACT,
                                    crabs_transform_update_compact);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_MOVE, CRABS_OT_OP_COMPACT,
                                    crabs_transform_move_compact);
  crabs_ot_data_item_set_transform(item, CRABS_OT_OP_SWAP, CRABS_OT_OP_COMPACT,
                                    crabs_transform_swap_compact);
}

// ============================================================
// Transform Matrix Entry Lookup
// ============================================================

static const char* _transform_descriptions[CRABS_OT_TRANSFORM_MATRIX_SIZE]
                                           [CRABS_OT_TRANSFORM_MATRIX_SIZE] = {
  {"T1: INS vs INS", "T3: INS vs DEL", "INS vs UPD", "INS vs MOV", "INS vs SWP", "INS vs CMP"},
  {"T2: DEL vs INS", "T4: DEL vs DEL", "DEL vs UPD", "DEL vs MOV", "DEL vs SWP", "DEL vs CMP"},
  {"UPD vs INS",     "UPD vs DEL",     "UPD vs UPD", "UPD vs MOV", "UPD vs SWP", "UPD vs CMP"},
  {"MOV vs INS",     "MOV vs DEL",     "MOV vs UPD", "T5: MOV vs MOV", "MOV vs SWP", "MOV vs CMP"},
  {"T6: SWP vs INS", "T7: SWP vs DEL", "SWP vs UPD", "SWP vs MOV", "SWP vs SWP", "SWP vs CMP"},
  {"CMP vs INS",     "CMP vs DEL",     "CMP vs UPD", "CMP vs MOV", "CMP vs SWP", "CMP vs CMP"},
};

static crabs_transform_entry_t _entry_result;

crabs_transform_entry_t* crabs_transform_matrix_get_entry(
    crabs_ot_data_item_t* item, crabs_ot_op_type_e type1, crabs_ot_op_type_e type2) {
  if (item == NULL) return NULL;
  if (type1 < 1 || type1 > CRABS_OT_OP_TYPE_COUNT) return NULL;
  if (type2 < 1 || type2 > CRABS_OT_OP_TYPE_COUNT) return NULL;
  _entry_result.fn = item->transform_matrix[type1 - 1][type2 - 1];
  memset(_entry_result.description, 0, CRABS_TRANSFORM_DESC_MAX);
  // _transform_descriptions only initializes the first 6 rows/cols; the
  // remaining entries are NULL. Guard against strncpy(NULL) crashing.
  const char* desc = NULL;
  if ((uint32_t)type1 - 1 < CRABS_OT_TRANSFORM_MATRIX_SIZE &&
      (uint32_t)type2 - 1 < CRABS_OT_TRANSFORM_MATRIX_SIZE) {
    desc = _transform_descriptions[type1 - 1][type2 - 1];
  }
  if (desc != NULL) {
    strncpy(_entry_result.description, desc, CRABS_TRANSFORM_DESC_MAX - 1);
  } else {
    strncpy(_entry_result.description, "(none)", CRABS_TRANSFORM_DESC_MAX - 1);
  }
  return &_entry_result;
}