//
// Created by victor on 4/30/25.
//

#include "serialization.h"
#include "../Util/platform.h"
#include "../Util/allocator.h"
#include "../Crypto/crypto.h"
#include "../OT/ot_ordered_set.h"
#include "../OT/ot_document.h"
#include "../OT/ot_tree.h"
#include "../OT/ot_transform.h"
#include "../Trigger/trigger.h"
#include "../Condition/condition.h"
#include "../Lineage/lineage.h"
#include <string.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>

// Upper bounds on attacker-controlled counts read from the wire. Without
// these, a tiny crafted blob declaring log_count = 2^32 would force a
// multi-GB allocation (and the allocator aborts on OOM → DoS, audit M-2).
#define CRABS_DESER_MAX_ITEMS   100000
#define CRABS_DESER_MAX_POLICIES 10000
#define CRABS_DESER_MAX_LOG     1000000
// Audit A-3: bound the trigger array read from the wire the same way as the
// other attacker-controlled counts.
#define CRABS_DESER_MAX_TRIGGERS 100000
// Minimum wire size of one trigger: nine string16s (empty = 2 bytes each),
// the effect type byte, two bool8s, and five u64 timestamps. Used to bound
// the trigger count against the remaining buffer.
#define CRABS_DESER_MIN_TRIGGER_WIRE_BYTES 61
// R8-SER-2/3: bound the OT tree node count so the O(n²) duplicate-id and
// parent-lookup scans cannot be driven to a multi-minute CPU DoS by a crafted
// blob (CRABS_DESER_MAX_LOG allows 1M nodes → ~10¹² strcmp calls).
#define CRABS_DESER_MAX_TREE_NODES 10000
// A10-M7: bound ordered-set elements like the OT tree so the per-element
// duplicate-id scan cannot be driven to a multi-minute CPU DoS by a crafted
// blob, and bound the count by the bytes actually remaining.
#define CRABS_DESER_MAX_SET_ELEMENTS 10000
// Bound on a single scheduled operation's serialized payload read from the
// wire; blocks a tiny crafted blob from driving a huge allocation (audit M-2).
#define CRABS_DESER_MAX_SCHEDULE_OP_BYTES (1024u * 1024u)
// v10: bound the user-registry count read from the wire the same way as the
// other attacker-controlled counts.
#define CRABS_DESER_MAX_USERS 4096
// Minimum wire size of one user entry: user_id/status (2+1), three u64
// timestamps (24), attribute count (4), 33-byte legacy public key,
// default_key_id (2), key_count (4), temp count (4) = 74 bytes. User entries
// in a blob are bounded against the remaining buffer with this.
#define CRABS_DESER_MIN_USER_WIRE_BYTES 74
// v10: a sealed MSK blob is bounded to the same ceiling the writer uses
// (16 KiB master-key buffer + seal overhead).
#define CRABS_DESER_MAX_SEALED_MSK_BYTES (16384u + CRABS_SEAL_OVERHEAD)
// v11: bound the lineage child-manifest count against the remaining buffer the
// same way as the other attacker-controlled counts.
#define CRABS_DESER_MAX_CHILDREN CRABS_MAX_CHILD_MACHINES
// Minimum wire size of one child-manifest entry: empty string16 id (2), mode
// (1), 32-byte genesis hash, 64-byte attestation signature, two u64s (16),
// status (1) = 116 bytes.
#define CRABS_DESER_MIN_CHILD_ENTRY_WIRE_BYTES 116

// ============================================================
// Write buffer helper
// ============================================================
typedef struct {
  uint8_t* data;
  size_t   len;
  size_t   offset;
} write_buf_t;

static write_buf_t* _write_buf_create(size_t initial_cap) {
  write_buf_t* buf = get_clear_memory(sizeof(write_buf_t));
  buf->data = get_memory(initial_cap);
  buf->len = initial_cap;
  buf->offset = 0;
  return buf;
}

static void _write_buf_ensure(write_buf_t* buf, size_t additional) {
  if (buf->offset + additional <= buf->len) return;
  size_t new_len = buf->len * 2;
  while (new_len < buf->offset + additional) {
    new_len *= 2;
  }
  uint8_t* new_data = get_memory(new_len);
  memcpy(new_data, buf->data, buf->offset);
  free(buf->data);
  buf->data = new_data;
  buf->len = new_len;
}

static void _write_uint8(write_buf_t* buf, uint8_t val) {
  _write_buf_ensure(buf, 1);
  buf->data[buf->offset++] = val;
}

static void _write_uint16_le(write_buf_t* buf, uint16_t val) {
  _write_buf_ensure(buf, 2);
  buf->data[buf->offset++] = (uint8_t)(val & 0xFF);
  buf->data[buf->offset++] = (uint8_t)((val >> 8) & 0xFF);
}

static void _write_uint32_le(write_buf_t* buf, uint32_t val) {
  _write_buf_ensure(buf, 4);
  buf->data[buf->offset++] = (uint8_t)(val & 0xFF);
  buf->data[buf->offset++] = (uint8_t)((val >> 8) & 0xFF);
  buf->data[buf->offset++] = (uint8_t)((val >> 16) & 0xFF);
  buf->data[buf->offset++] = (uint8_t)((val >> 24) & 0xFF);
}

static void _write_uint64_le(write_buf_t* buf, uint64_t val) {
  _write_buf_ensure(buf, 8);
  for (int i = 0; i < 8; i++) {
    buf->data[buf->offset++] = (uint8_t)((val >> (i * 8)) & 0xFF);
  }
}

static void _write_int64_le(write_buf_t* buf, int64_t val) {
  _write_uint64_le(buf, (uint64_t)val);
}

static void _write_bytes(write_buf_t* buf, const uint8_t* data, size_t len) {
  if (data == NULL || len == 0) return;
  _write_buf_ensure(buf, len);
  memcpy(buf->data + buf->offset, data, len);
  buf->offset += len;
}

static void _write_string16(write_buf_t* buf, const char* str) {
  if (str == NULL) {
    _write_uint16_le(buf, 0);
    return;
  }
  uint16_t slen = (uint16_t)strlen(str);
  _write_uint16_le(buf, slen);
  _write_bytes(buf, (const uint8_t*)str, slen);
}

static void _write_bytes32(write_buf_t* buf, const uint8_t* data, uint32_t len) {
  _write_uint32_le(buf, len);
  if (data != NULL && len > 0) {
    _write_bytes(buf, data, len);
  }
}

static void _write_bool8(write_buf_t* buf, bool val) {
  _write_uint8(buf, val ? 1 : 0);
}

// ============================================================
// Read buffer helper
// ============================================================
typedef struct {
  const uint8_t* data;
  size_t         len;
  size_t         offset;
} read_buf_t;

static bool _read_uint8(read_buf_t* buf, uint8_t* out) {
  if (buf->offset + 1 > buf->len) return false;
  *out = buf->data[buf->offset++];
  return true;
}

static bool _read_uint16_le(read_buf_t* buf, uint16_t* out) {
  if (buf->offset + 2 > buf->len) return false;
  *out = (uint16_t)(buf->data[buf->offset] |
                    (buf->data[buf->offset + 1] << 8));
  buf->offset += 2;
  return true;
}

static bool _read_uint32_le(read_buf_t* buf, uint32_t* out) {
  if (buf->offset + 4 > buf->len) return false;
  *out = (uint32_t)(buf->data[buf->offset] |
                     ((uint32_t)buf->data[buf->offset + 1] << 8) |
                     ((uint32_t)buf->data[buf->offset + 2] << 16) |
                     ((uint32_t)buf->data[buf->offset + 3] << 24));
  buf->offset += 4;
  return true;
}

static bool _read_uint64_le(read_buf_t* buf, uint64_t* out) {
  if (buf->offset + 8 > buf->len) return false;
  *out = 0;
  for (int i = 0; i < 8; i++) {
    *out |= ((uint64_t)buf->data[buf->offset + i]) << (i * 8);
  }
  buf->offset += 8;
  return true;
}

static bool _read_int64_le(read_buf_t* buf, int64_t* out) {
  return _read_uint64_le(buf, (uint64_t*)out);
}

static bool _read_bytes(read_buf_t* buf, uint8_t* out, size_t len) {
  if (buf->offset + len > buf->len) return false;
  memcpy(out, buf->data + buf->offset, len);
  buf->offset += len;
  return true;
}

static bool _read_string16(read_buf_t* buf, char* out, size_t max_len) {
  uint16_t slen;
  if (!_read_uint16_le(buf, &slen)) return false;
  if (slen > buf->len - buf->offset) return false;
  // R7-L-5: reject over-long strings instead of truncating. A truncated string
  // could alias a different legitimate value (e.g. "role:admi" matching a
  // truncated "role:admin").
  if (slen >= max_len) return false;
  if (slen > 0) {
    memcpy(out, buf->data + buf->offset, slen);
    buf->offset += slen;
  }
  out[slen] = '\0';
  return true;
}

static bool _read_bytes32(read_buf_t* buf, uint8_t** out, uint32_t* out_len) {
  uint32_t len;
  if (!_read_uint32_le(buf, &len)) return false;
  if (len > buf->len - buf->offset) return false;
  *out_len = len;
  if (len > 0) {
    *out = get_memory(len);
    memcpy(*out, buf->data + buf->offset, len);
    buf->offset += len;
  } else {
    *out = NULL;
  }
  return true;
}

// ============================================================
// Serialized buffer helpers
// ============================================================
serialized_buffer_t* serialized_buffer_create(size_t len) {
  serialized_buffer_t* buf = get_clear_memory(sizeof(serialized_buffer_t));
  buf->data = get_clear_memory(len);
  buf->len = len;
  return buf;
}

void serialized_buffer_destroy(serialized_buffer_t* buf) {
  if (buf == NULL) return;
  if (buf->data != NULL) free(buf->data);
  free(buf);
}

// ============================================================
// OT Operation Serialization (v1.5 §9)
// ============================================================

// Wire size of one serialized op id: node_id[CRABS_MAX_USER_ID] + sequence_num
// (u64) + timestamp (u64). Used to bound attacker-controlled element counts
// against the remaining buffer (A10-M7).
#define CRABS_OT_OP_ID_WIRE_SIZE (CRABS_MAX_USER_ID + 2 * sizeof(uint64_t))

static void _serialize_ot_op_id(write_buf_t* buf, const crabs_ot_op_id_t* id) {
  _write_bytes(buf, (const uint8_t*)id->node_id, CRABS_MAX_USER_ID);
  _write_uint64_le(buf, id->sequence_num);
  _write_uint64_le(buf, id->timestamp);
}

static bool _deserialize_ot_op_id(read_buf_t* buf, crabs_ot_op_id_t* id) {
  if (!_read_bytes(buf, (uint8_t*)id->node_id, CRABS_MAX_USER_ID)) return false;
  id->node_id[CRABS_MAX_USER_ID - 1] = '\0';
  if (!_read_uint64_le(buf, &id->sequence_num)) return false;
  if (!_read_uint64_le(buf, &id->timestamp)) return false;
  return true;
}

static void _serialize_ot_op(write_buf_t* buf, const crabs_ot_operation_t* op) {
  _serialize_ot_op_id(buf, &op->id);
  _write_uint32_le(buf, (uint32_t)op->op_type);
  _write_uint64_le(buf, op->visible_pos);
  _write_uint64_le(buf, op->visible_pos_2);
  _write_uint64_le(buf, op->priority);
  _write_bytes32(buf, op->payload, op->payload_size);
  uint32_t dep_write_count = op->dep_count < CRABS_OT_MAX_DEPS ? op->dep_count : CRABS_OT_MAX_DEPS;
  _write_uint32_le(buf, dep_write_count);
  for (uint32_t i = 0; i < dep_write_count; i++) {
    _serialize_ot_op_id(buf, &op->deps[i]);
  }
  _write_uint32_le(buf, op->transform_fn_id);
}

static bool _deserialize_ot_op(read_buf_t* buf, crabs_ot_operation_t* op) {
  crabs_ot_operation_init(op);
  if (!_deserialize_ot_op_id(buf, &op->id)) return false;
  uint32_t op_type;
  if (!_read_uint32_le(buf, &op_type)) return false;
  op->op_type = (crabs_ot_op_type_e)op_type;
  if (!_read_uint64_le(buf, &op->visible_pos)) return false;
  if (!_read_uint64_le(buf, &op->visible_pos_2)) return false;
  if (!_read_uint64_le(buf, &op->priority)) return false;

  uint8_t* payload = NULL;
  uint32_t payload_size = 0;
  if (!_read_bytes32(buf, &payload, &payload_size)) return false;
  op->payload = payload;
  op->payload_size = payload_size;

  if (!_read_uint32_le(buf, &op->dep_count)) goto fail;
  // Audit M-E: reject (do not clamp) oversized dep_count. Clamping desynced
  // the parse — the writer emitted `dep_count` deps but we'd only consume
  // CRABS_OT_MAX_DEPS, leaving subsequent ops misaligned.
  if (op->dep_count > CRABS_OT_MAX_DEPS) goto fail;
  for (uint32_t i = 0; i < op->dep_count; i++) {
    if (!_deserialize_ot_op_id(buf, &op->deps[i])) goto fail;
  }
  if (!_read_uint32_le(buf, &op->transform_fn_id)) goto fail;
  return true;

fail:
  // R7-L-14: free the payload allocated above so a malformed op does not leak.
  if (op->payload != NULL) free(op->payload);
  op->payload = NULL;
  return false;
}

// ============================================================
// BST Position Map Serialization
// ============================================================

// BST serialization uses level-order traversal with explicit NULL markers
// Format: node_count(4) [value(8) deleted(1) has_left(1) has_right(1)]...

static void _serialize_bst_node(write_buf_t* buf, const crabs_bst_node_t* node) {
  if (node == NULL) return;
  _write_uint64_le(buf, node->value);
  _write_uint8(buf, node->deleted ? 1 : 0);
  _write_uint8(buf, (node->left != NULL) ? 1 : 0);
  _write_uint8(buf, (node->right != NULL) ? 1 : 0);
}

static uint32_t _count_bst_nodes(const crabs_bst_node_t* root) {
  if (root == NULL) return 0;
  return 1 + _count_bst_nodes(root->left) + _count_bst_nodes(root->right);
}

static void _serialize_bst_recursive(write_buf_t* buf, const crabs_bst_node_t* root) {
  if (root == NULL) return;
  _serialize_bst_node(buf, root);
  _serialize_bst_recursive(buf, root->left);
  _serialize_bst_recursive(buf, root->right);
}

// Maximum BST depth accepted during deserialization. A degenerate left-linked
// tree of depth ~100k+ would otherwise overflow the stack; reject deeper
// trees. 256 levels comfortably holds any balanced tree of >2^256 nodes.
#define CRABS_BST_MAX_DESERIALIZE_DEPTH 256

static crabs_bst_node_t* _deserialize_bst_recursive(read_buf_t* buf, uint32_t depth) {
  if (depth > CRABS_BST_MAX_DESERIALIZE_DEPTH) return NULL;
  uint64_t value;
  if (!_read_uint64_le(buf, &value)) return NULL;
  uint8_t deleted;
  if (!_read_uint8(buf, &deleted)) return NULL;
  uint8_t has_left;
  if (!_read_uint8(buf, &has_left)) return NULL;
  uint8_t has_right;
  if (!_read_uint8(buf, &has_right)) return NULL;

  crabs_bst_node_t* node = crabs_bst_create(value);
  if (node == NULL) return NULL;
  node->deleted = (deleted != 0);

  if (has_left) {
    node->left = _deserialize_bst_recursive(buf, depth + 1);
    if (node->left == NULL) {
      crabs_bst_destroy(node);
      return NULL;
    }
  }
  if (has_right) {
    node->right = _deserialize_bst_recursive(buf, depth + 1);
    if (node->right == NULL) {
      crabs_bst_destroy(node);
      return NULL;
    }
  }

  // Recompute size and height from children
  uint32_t left_size = (node->left != NULL) ? crabs_bst_size(node->left) : 0;
  uint32_t right_size = (node->right != NULL) ? crabs_bst_size(node->right) : 0;
  node->size = 1 + left_size + right_size;
  uint32_t left_h = (node->left != NULL) ? node->left->height : 0;
  uint32_t right_h = (node->right != NULL) ? node->right->height : 0;
  node->height = 1 + (left_h > right_h ? left_h : right_h);

  return node;
}

// ============================================================
// OT Data Item Serialization
// ============================================================

static void _serialize_ot_type_state(write_buf_t* buf, const data_item_t* item) {
  switch (item->type) {
    case DATA_TYPE_OT_ORDERED_SET: {
      crabs_ot_ordered_set_t* set = (crabs_ot_ordered_set_t*)item->value;
      // Serialize elements as linked list
      uint32_t count = (set != NULL) ? set->count : 0;
      _write_uint32_le(buf, count);
      crabs_ordered_element_t* elem = (set != NULL) ? set->head : NULL;
      while (elem != NULL) {
        _serialize_ot_op_id(buf, &elem->id);
        _write_bytes32(buf, elem->value, elem->value_size);
        _write_uint8(buf, elem->deleted ? 1 : 0);
        _write_uint8(buf, elem->has_anchor ? 1 : 0);
        if (elem->has_anchor) _serialize_ot_op_id(buf, &elem->anchor_id);
        _serialize_ot_op_id(buf, &elem->placement_id);
        elem = elem->next;
      }
      break;
    }
    case DATA_TYPE_OT_DOCUMENT: {
      crabs_ot_document_t* doc = (crabs_ot_document_t*)item->value;
      // Serialize spans as linked list
      uint32_t span_count = (doc != NULL) ? doc->span_count : 0;
      _write_uint32_le(buf, span_count);
      crabs_span_t* span = (doc != NULL) ? doc->head : NULL;
      while (span != NULL) {
        _serialize_ot_op_id(buf, &span->id);
        _write_bytes32(buf, span->text, span->text_size);
        uint32_t style_write_count = span->style_count < CRABS_SPAN_MAX_STYLES ?
                                      span->style_count : CRABS_SPAN_MAX_STYLES;
        _write_uint32_le(buf, style_write_count);
        for (uint32_t s = 0; s < style_write_count; s++) {
          _write_string16(buf, span->styles[s].name);
          _write_string16(buf, span->styles[s].value);
        }
        _write_uint8(buf, span->deleted ? 1 : 0);
        span = span->next;
      }
      break;
    }
    case DATA_TYPE_OT_TREE: {
      crabs_ot_tree_t* tree = (crabs_ot_tree_t*)item->value;
      // Serialize tree nodes from pool
      uint32_t node_count = (tree != NULL) ? tree->node_count : 0;
      _write_uint32_le(buf, node_count);
      crabs_tree_node_t* node = (tree != NULL) ? tree->node_pool : NULL;
      while (node != NULL) {
        _write_string16(buf, node->id);
        _write_string16(buf, node->parent_id);
        _write_bytes32(buf, node->value, node->value_size);
        _write_uint8(buf, node->deleted ? 1 : 0);
        // Serialize the child position map
        uint32_t bst_count = _count_bst_nodes(node->child_position_map);
        _write_uint32_le(buf, bst_count);
        _serialize_bst_recursive(buf, node->child_position_map);
        node = node->pool_next;
      }
      // Root node id
      _write_string16(buf, (tree != NULL && tree->root != NULL) ? tree->root->id : "");
      break;
    }
    default:
      // No type-specific state for unimplemented OT types
      break;
  }
}

static bool _deserialize_ot_type_state(read_buf_t* buf, data_item_t* item,
                                       uint32_t version) {
  switch (item->type) {
    case DATA_TYPE_OT_ORDERED_SET: {
      crabs_ot_ordered_set_t* set = (crabs_ot_ordered_set_t*)item->value;
      if (set == NULL) return false;

      uint32_t count;
      if (!_read_uint32_le(buf, &count)) return false;
      if (count > CRABS_DESER_MAX_SET_ELEMENTS) return false;
      // A10-M7: each element carries at least one op id on the wire, so a
      // count above remaining/op-id-size cannot be satisfied by the blob —
      // reject before the per-element duplicate-id scan runs.
      if (count > (buf->len - buf->offset) / CRABS_OT_OP_ID_WIRE_SIZE) return false;

      crabs_ordered_element_t* tail = NULL;
      for (uint32_t i = 0; i < count; i++) {
        crabs_ot_op_id_t id;
        if (!_deserialize_ot_op_id(buf, &id)) return false;

        // Audit finding: reject duplicate element ids, matching the OT tree
        // path. Id-keyed lookups (crabs_ot_ordered_set_find and the merges)
        // become ambiguous when two elements share an id, and a crafted blob
        // could alias one element onto another.
        for (crabs_ordered_element_t* seen_element = set->head; seen_element != NULL;
             seen_element = seen_element->next) {
          if (crabs_ot_op_id_equal(&seen_element->id, &id)) return false;
        }

        uint8_t* value = NULL;
        uint32_t value_size = 0;
        if (!_read_bytes32(buf, &value, &value_size)) return false;

        uint8_t deleted;
        if (!_read_uint8(buf, &deleted)) { free(value); return false; }

        crabs_ordered_element_t* elem = crabs_ordered_element_create(&id, value, value_size);
        if (value != NULL) free(value);
        if (elem == NULL) return false;

        elem->deleted = (deleted != 0);

        if (version >= 8) {
          uint8_t has_anchor;
          if (!_read_uint8(buf, &has_anchor)) {
            crabs_ordered_element_destroy(elem);
            return false;
          }
          elem->has_anchor = has_anchor != 0;
          if (elem->has_anchor && !_deserialize_ot_op_id(buf, &elem->anchor_id)) {
            crabs_ordered_element_destroy(elem);
            return false;
          }
          if (!_deserialize_ot_op_id(buf, &elem->placement_id)) {
            crabs_ordered_element_destroy(elem);
            return false;
          }
        } else {
          elem->has_anchor = tail != NULL;
          if (tail != NULL) elem->anchor_id = tail->id;
          elem->placement_id = elem->id;
        }

        if (set->head == NULL) {
          set->head = elem;
          tail = elem;
        } else {
          tail->next = elem;
          elem->prev = tail;
          tail = elem;
        }
        set->count++;
        if (!elem->deleted) set->visible_count++;
      }
      set->tail = tail;
      break;
    }
    case DATA_TYPE_OT_DOCUMENT: {
      crabs_ot_document_t* doc = (crabs_ot_document_t*)item->value;
      if (doc == NULL) return false;

      uint32_t span_count;
      if (!_read_uint32_le(buf, &span_count)) return false;
      if (span_count > CRABS_DESER_MAX_LOG) return false;

      crabs_span_t* tail = NULL;
      for (uint32_t i = 0; i < span_count; i++) {
        crabs_ot_op_id_t id;
        if (!_deserialize_ot_op_id(buf, &id)) return false;

        uint8_t* text = NULL;
        uint32_t text_size = 0;
        if (!_read_bytes32(buf, &text, &text_size)) return false;

        crabs_span_t* span = crabs_span_create(&id, text, text_size);
        if (text != NULL) free(text);
        if (span == NULL) return false;

        uint32_t style_count;
        if (!_read_uint32_le(buf, &style_count)) return false;
        // Audit M-E: reject (do not clamp) oversized style_count. Clamping
        // desynced the parse.
        if (style_count > CRABS_SPAN_MAX_STYLES) return false;
        span->style_count = style_count;
        for (uint32_t s = 0; s < span->style_count; s++) {
          if (!_read_string16(buf, span->styles[s].name, CRABS_STYLE_NAME_MAX)) return false;
          if (!_read_string16(buf, span->styles[s].value, CRABS_STYLE_VALUE_MAX)) return false;
        }

        uint8_t deleted;
        if (!_read_uint8(buf, &deleted)) return false;
        span->deleted = (deleted != 0);

        if (doc->head == NULL) {
          doc->head = span;
          tail = span;
        } else {
          tail->next = span;
          span->prev = tail;
          tail = span;
        }
        doc->span_count++;
        if (!span->deleted) doc->visible_char_count += span->text_size;
      }
      doc->tail = tail;
      break;
    }
    case DATA_TYPE_OT_TREE: {
      crabs_ot_tree_t* tree = (crabs_ot_tree_t*)item->value;
      if (tree == NULL) return false;

      uint32_t node_count;
      if (!_read_uint32_le(buf, &node_count)) return false;
      if (node_count > CRABS_DESER_MAX_TREE_NODES) return false;

      crabs_tree_node_t* first_node = NULL;
      crabs_tree_node_t* prev_node = NULL;

      for (uint32_t i = 0; i < node_count; i++) {
        char id[CRABS_TREE_NODE_ID_MAX] = {0};
        char parent_id[CRABS_TREE_NODE_ID_MAX] = {0};
        if (!_read_string16(buf, id, CRABS_TREE_NODE_ID_MAX)) return false;
        if (!_read_string16(buf, parent_id, CRABS_TREE_NODE_ID_MAX)) return false;

        // Audit M-D: reject malformed trees. A self-parent (parent_id == id)
        // creates an immediate cycle, and a duplicate id would make the
        // later parent lookup ambiguous. Both can hang or overflow recursive
        // walkers downstream.
        if (parent_id[0] != '\0' && strcmp(parent_id, id) == 0) return false;
        for (crabs_tree_node_t* scan = first_node; scan != NULL; scan = scan->pool_next) {
          if (strcmp(scan->id, id) == 0) return false;
        }

        uint8_t* value = NULL;
        uint32_t value_size = 0;
        if (!_read_bytes32(buf, &value, &value_size)) return false;

        uint8_t deleted;
        if (!_read_uint8(buf, &deleted)) { free(value); return false; }

        crabs_tree_node_t* node = crabs_tree_node_create(id, parent_id[0] ? parent_id : NULL,
                                                           value, value_size);
        if (value != NULL) free(value);
        if (node == NULL) return false;
        node->deleted = (deleted != 0);

        // Deserialize child position map
        uint32_t bst_count;
        if (!_read_uint32_le(buf, &bst_count)) { crabs_tree_node_destroy(node); return false; }
        if (bst_count > 0) {
          node->child_position_map = _deserialize_bst_recursive(buf, 0);
          if (node->child_position_map == NULL) { crabs_tree_node_destroy(node); return false; }
        }

        // Build pool linkage
        if (first_node == NULL) {
          first_node = node;
        }
        if (prev_node != NULL) {
          prev_node->pool_next = node;
        }
        prev_node = node;
        tree->node_count++;
        if (!node->deleted) tree->visible_count++;
        // Assign pool incrementally so early returns don't leak nodes
        tree->node_pool = first_node;
      }

      // Read root node id and link up tree structure
      char root_id[CRABS_TREE_NODE_ID_MAX] = {0};
      if (!_read_string16(buf, root_id, CRABS_TREE_NODE_ID_MAX)) return false;

      // Rebuild parent/child links
      if (root_id[0] != '\0') {
        // Find root and rebuild tree structure
        crabs_tree_node_t* node = tree->node_pool;
        while (node != NULL) {
          if (strcmp(node->id, root_id) == 0) {
            tree->root = node;
            // Root has no parent
            break;
          }
          node = node->pool_next;
        }

        // R8-SER-4: a non-empty root_id that matches no node leaves tree->root
        // NULL, which skips the cycle-detection walk below. Reject it so a
        // crafted blob with a parent cycle cannot pass deserialization.
        if (tree->root == NULL) return false;
      }

      // Link parent-child relationships. Audit finding: nodes with an
      // empty parent_id are legal additional roots (empty-parent insert,
      // reparent-to-root, merge cycle-break). Link them into the root
      // sibling chain exactly as crabs_ot_tree_insert_node and
      // ot_tree.c:_rebuild_links do, instead of leaving them unlinked and
      // failing the connectivity check below (which made the state
      // permanently unloadable). When the blob declared no root_id, the
      // first empty-parent node becomes the root.
      crabs_tree_node_t* node = tree->node_pool;
      while (node != NULL) {
        if (node->parent_id[0] == '\0') {
          if (tree->root == NULL) {
            tree->root = node;
          } else if (node != tree->root) {
            // Additional root: append to the root sibling chain.
            crabs_tree_node_t* last_root_sibling = tree->root;
            while (last_root_sibling->next_sibling != NULL) {
              last_root_sibling = last_root_sibling->next_sibling;
            }
            last_root_sibling->next_sibling = node;
            node->prev_sibling = last_root_sibling;
          }
        } else {
          // Find parent
          crabs_tree_node_t* parent = tree->node_pool;
          while (parent != NULL) {
            if (strcmp(parent->id, node->parent_id) == 0) {
              node->parent = parent;
              // Add to parent's children (as last child)
              if (parent->first_child == NULL) {
                parent->first_child = node;
              } else {
                crabs_tree_node_t* sibling = parent->first_child;
                while (sibling->next_sibling != NULL) {
                  sibling = sibling->next_sibling;
                }
                sibling->next_sibling = node;
                node->prev_sibling = sibling;
              }
              break;
            }
            parent = parent->pool_next;
          }
        }
        node = node->pool_next;
      }

      // Audit M-D: detect cycles and disconnected nodes from the parent links
      // (e.g. A→B and B→A from a crafted blob). Walk each declared-parent
      // node's parent chain bounded by node_count+1; it must reach root, else
      // the blob is cyclic or disconnected and downstream recursive walkers
      // would hang or overflow the stack. Empty-parent_id nodes were linked
      // as sibling roots above, so they have no parent chain to check.
      if (tree->root != NULL) {
        crabs_tree_node_t* walk_node = tree->node_pool;
        while (walk_node != NULL) {
          if (walk_node->parent_id[0] != '\0') {
            uint32_t steps = 0;
            crabs_tree_node_t* ancestor = walk_node->parent;
            while (ancestor != NULL && ancestor != tree->root && steps <= node_count) {
              ancestor = ancestor->parent;
              steps++;
            }
            if (ancestor != tree->root) return false; // cyclic or disconnected
          }
          walk_node = walk_node->pool_next;
        }
      } else if (node_count > 0) {
        // No root and no empty-parent_id node: every node declares a parent.
        // This is reachable legitimately (a tree whose nodes are all deleted
        // merges back with cleared links and no root), so it must load — but
        // the reachability check above is skipped without a root. Bound-walk
        // each declared-parent chain here and require it to terminate, so a
        // crafted parent cycle (A→B, B→A) cannot pass deserialization.
        crabs_tree_node_t* forest_node = tree->node_pool;
        while (forest_node != NULL) {
          if (forest_node->parent_id[0] != '\0') {
            uint32_t steps = 0;
            crabs_tree_node_t* ancestor = forest_node->parent;
            while (ancestor != NULL && steps <= node_count) {
              ancestor = ancestor->parent;
              steps++;
            }
            if (ancestor != NULL) return false; // parent cycle
          }
          forest_node = forest_node->pool_next;
        }
      }
      break;
    }
    default:
      break;
  }
  return true;
}

// ============================================================
// CRDT value serialization (audit M-5): sets/flags previously lost their
// contents on round-trip (the serializer wrote a 0-length value). These
// helpers serialize or_set / two_p_set / one_shot_set / one_shot_flag into
// a length-prefixed blob that the deserializer reconstructs.
// ============================================================
#include "../CRDT/crdt_merge.h"
#include "../CRDT/one_shot.h"

static void _serialize_crdt_value(write_buf_t* buf, data_type_e type, const void* value) {
  if (value == NULL) { _write_bytes32(buf, NULL, 0); return; }
  write_buf_t* cb = _write_buf_create(64);
  switch (type) {
    case DATA_TYPE_SET: {
      const or_set_t* s = (const or_set_t*)value;
      _write_uint32_le(cb, s->element_count);
      for (uint32_t i = 0; i < s->element_count; i++) {
        _write_string16(cb, s->elements[i].element);
        _write_string16(cb, s->elements[i].tag);
      }
      _write_uint32_le(cb, s->tombstone_count);
      for (uint32_t i = 0; i < s->tombstone_count; i++) {
        _write_string16(cb, s->tombstones[i].element);
        _write_string16(cb, s->tombstones[i].tag);
      }
      break;
    }
    case DATA_TYPE_2P_SET: {
      const two_p_set_t* s = (const two_p_set_t*)value;
      _write_uint32_le(cb, s->add_count);
      for (uint32_t i = 0; i < s->add_count; i++) _write_string16(cb, s->add_set[i]);
      _write_uint32_le(cb, s->remove_count);
      for (uint32_t i = 0; i < s->remove_count; i++) _write_string16(cb, s->remove_set[i]);
      break;
    }
    case DATA_TYPE_ONE_SHOT_SET: {
      const one_shot_set_t* s = (const one_shot_set_t*)value;
      _write_uint32_le(cb, s->element_count);
      for (uint32_t i = 0; i < s->element_count; i++) _write_string16(cb, s->elements[i]);
      break;
    }
    case DATA_TYPE_ONE_SHOT_FLAG: {
      const one_shot_flag_t* f = (const one_shot_flag_t*)value;
      _write_bool8(cb, f->value);
      _write_string16(cb, f->set_by);
      _write_uint64_le(cb, f->set_at);
      break;
    }
    default:
      break;
  }
  _write_bytes32(buf, cb->data, (uint32_t)cb->offset);
  free(cb->data); free(cb);
}

static void* _deserialize_crdt_value(const uint8_t* data, uint32_t len, data_type_e type) {
  if (data == NULL || len == 0) return NULL;
  read_buf_t rb;
  rb.data = data; rb.len = len; rb.offset = 0;
  switch (type) {
    case DATA_TYPE_SET: {
      or_set_t* s = or_set_create();
      if (!s) return NULL;
      uint32_t ec;
      if (!_read_uint32_le(&rb, &ec)) { or_set_destroy(s); return NULL; }
      for (uint32_t i = 0; i < ec; i++) {
        char elem[CRABS_MAX_USER_ID]; char tag[CRABS_MAX_USER_ID];
        if (!_read_string16(&rb, elem, sizeof(elem)) || !_read_string16(&rb, tag, sizeof(tag))) { or_set_destroy(s); return NULL; }
        or_set_add(s, elem, tag);
      }
      uint32_t tc;
      if (!_read_uint32_le(&rb, &tc)) { or_set_destroy(s); return NULL; }
      for (uint32_t i = 0; i < tc; i++) {
        char elem[CRABS_MAX_USER_ID]; char tag[CRABS_MAX_USER_ID];
        if (!_read_string16(&rb, elem, sizeof(elem)) || !_read_string16(&rb, tag, sizeof(tag))) { or_set_destroy(s); return NULL; }
        // Reconstruct tombstone directly (or_set_remove would consume by element only)
        uint32_t idx = s->tombstone_count;
        s->tombstones = realloc(s->tombstones, (idx + 1) * sizeof(or_set_entry_t));
        if (!s->tombstones) { or_set_destroy(s); return NULL; }
        s->tombstones[idx].element = platform_strdup(elem);
        s->tombstones[idx].tag = platform_strdup(tag);
        s->tombstone_count = idx + 1;
      }
      return s;
    }
    case DATA_TYPE_2P_SET: {
      two_p_set_t* s = two_p_set_create();
      if (!s) return NULL;
      uint32_t ac;
      if (!_read_uint32_le(&rb, &ac)) { two_p_set_destroy(s); return NULL; }
      for (uint32_t i = 0; i < ac; i++) {
        char e[CRABS_MAX_USER_ID];
        if (!_read_string16(&rb, e, sizeof(e))) { two_p_set_destroy(s); return NULL; }
        two_p_set_add(s, e);
      }
      uint32_t rc2;
      if (!_read_uint32_le(&rb, &rc2)) { two_p_set_destroy(s); return NULL; }
      for (uint32_t i = 0; i < rc2; i++) {
        char e[CRABS_MAX_USER_ID];
        if (!_read_string16(&rb, e, sizeof(e))) { two_p_set_destroy(s); return NULL; }
        two_p_set_remove(s, e);
      }
      return s;
    }
    case DATA_TYPE_ONE_SHOT_SET: {
      one_shot_set_t* s = one_shot_set_create();
      if (!s) return NULL;
      uint32_t ec;
      if (!_read_uint32_le(&rb, &ec)) { one_shot_set_destroy(s); return NULL; }
      for (uint32_t i = 0; i < ec; i++) {
        char e[CRABS_MAX_USER_ID];
        if (!_read_string16(&rb, e, sizeof(e))) { one_shot_set_destroy(s); return NULL; }
        one_shot_set_add(s, e);
      }
      return s;
    }
    case DATA_TYPE_ONE_SHOT_FLAG: {
      one_shot_flag_t* f = one_shot_flag_create();
      if (!f) return NULL;
      uint8_t v; char setby[CRABS_MAX_USER_ID]; uint64_t at;
      if (!_read_uint8(&rb, &v) || !_read_string16(&rb, setby, sizeof(setby)) || !_read_uint64_le(&rb, &at)) {
        one_shot_flag_destroy(f); return NULL;
      }
      if (v) one_shot_flag_set(f, setby, at);
      return f;
    }
    default:
      return NULL;
  }
}

// ============================================================
// Data item serialization (§13.2)
// ============================================================
static void _serialize_data_item(write_buf_t* buf, const data_item_t* item) {
  // name_length + name
  _write_string16(buf, item->name);

  // type_id
  _write_uint8(buf, (uint8_t)item->type);

  // crdt_type_id
  _write_uint8(buf, (uint8_t)item->crdt_type);

  // protocol_state
  _write_uint8(buf, (uint8_t)item->protocol_state);

  // value: For simple types, serialize the value as bytes
  // For OT types, serialize the full OT data item (op_log, position_map, etc.)
  if (item->value != NULL) {
    if (item->type == DATA_TYPE_COUNTER || item->type == DATA_TYPE_PN_COUNTER ||
        item->type == DATA_TYPE_RESOURCE) {
      // int64_t value
      uint8_t val_bytes[sizeof(int64_t)];
      int64_t val = *(int64_t*)item->value;
      for (int i = 0; i < 8; i++) {
        val_bytes[i] = (uint8_t)((val >> (i * 8)) & 0xFF);
      }
      _write_bytes32(buf, val_bytes, sizeof(int64_t));
    } else if (item->type == DATA_TYPE_REGISTER) {
      // int64_t value
      uint8_t val_bytes[sizeof(int64_t)];
      int64_t val = *(int64_t*)item->value;
      for (int i = 0; i < 8; i++) {
        val_bytes[i] = (uint8_t)((val >> (i * 8)) & 0xFF);
      }
      _write_bytes32(buf, val_bytes, sizeof(int64_t));
    } else if (item->type >= DATA_TYPE_OT_ORDERED_SET && item->type <= DATA_TYPE_OT_ORDERED_MAP) {
      // OT type: serialize the ot_data (op_log + position_map + priority_counters)
      // followed by type-specific state (elements, spans, tree nodes)
      if (item->ot_data != NULL) {
        serialized_buffer_t* ot_buf = crabs_serialize_ot_data(
          (crabs_ot_data_item_t*)item->ot_data);
        if (ot_buf != NULL) {
          _write_bytes32(buf, ot_buf->data, (uint32_t)ot_buf->len);
          serialized_buffer_destroy(ot_buf);
        } else {
          _write_bytes32(buf, NULL, 0);
        }
      } else {
        _write_bytes32(buf, NULL, 0);
      }

      // Type-specific state
      _serialize_ot_type_state(buf, item);
    } else if (item->type == DATA_TYPE_SET || item->type == DATA_TYPE_2P_SET ||
               item->type == DATA_TYPE_ONE_SHOT_SET || item->type == DATA_TYPE_ONE_SHOT_FLAG) {
      // CRDT sets/flags: serialize their full contents (audit M-5).
      _serialize_crdt_value(buf, item->type, item->value);
    } else {
      // Generic: just write 0 length for unsupported types
      _write_bytes32(buf, NULL, 0);
    }
  } else {
    _write_bytes32(buf, NULL, 0);
  }

  // invariant_count
  _write_uint8(buf, (uint8_t)item->invariant_count);

  // invariants
  for (uint32_t i = 0; i < item->invariant_count; i++) {
    _write_uint8(buf, (uint8_t)item->invariants[i].type);
    _write_uint64_le(buf, (uint64_t)item->invariants[i].param);
    _write_string16(buf, item->invariants[i].error_message);
  }

  // last_compaction_time (v5: v1.5.2 §7)
  _write_uint64_le(buf, item->last_compaction_time);
}

static bool _deserialize_data_item(read_buf_t* buf, data_item_t* item, uint32_t version) {
  // name
  if (!_read_string16(buf, item->name, CRABS_MAX_USER_ID)) return false;

  // type_id
  uint8_t type_id;
  if (!_read_uint8(buf, &type_id)) return false;
  item->type = (data_type_e)type_id;

  // crdt_type_id
  uint8_t crdt_type_id;
  if (!_read_uint8(buf, &crdt_type_id)) return false;
  item->crdt_type = (crdt_type_e)crdt_type_id;

  // protocol_state
  uint8_t ps;
  if (!_read_uint8(buf, &ps)) return false;
  item->protocol_state = (protocol_state_e)ps;

  // value
  uint8_t* val_data = NULL;
  uint32_t val_len = 0;
  if (!_read_bytes32(buf, &val_data, &val_len)) return false;

  if (val_data != NULL && val_len > 0) {
    if (item->type == DATA_TYPE_COUNTER || item->type == DATA_TYPE_PN_COUNTER ||
        item->type == DATA_TYPE_RESOURCE) {
      int64_t* val = get_memory(sizeof(int64_t));
      *val = 0;
      for (int i = 0; i < 8 && i < (int)val_len; i++) {
        *val |= ((int64_t)val_data[i]) << (i * 8);
      }
      item->value = val;
      free(val_data);
    } else if (item->type == DATA_TYPE_REGISTER) {
      int64_t* val = get_memory(sizeof(int64_t));
      *val = 0;
      for (int i = 0; i < 8 && i < (int)val_len; i++) {
        *val |= ((int64_t)val_data[i]) << (i * 8);
      }
      item->value = val;
      free(val_data);
    } else if (item->type >= DATA_TYPE_OT_ORDERED_SET && item->type <= DATA_TYPE_OT_ORDERED_MAP) {
      // OT type: deserialize ot_data
      crabs_ot_data_item_t* ot_data = crabs_deserialize_ot_data(val_data, val_len, item->type);
      free(val_data);
      if (ot_data == NULL) return false;
      item->ot_data = ot_data;

      // Create the type-specific value and link ot_data
      switch (item->type) {
        case DATA_TYPE_OT_ORDERED_SET: {
          crabs_ot_ordered_set_t* set = crabs_ot_ordered_set_create();
          if (set == NULL) return false;
          // Replace the set's ot_data with the deserialized one
          if (set->ot_data != NULL) crabs_ot_data_item_destroy(set->ot_data);
          set->ot_data = ot_data;
          item->value = set;
          item->ot_data = ot_data;
          break;
        }
        case DATA_TYPE_OT_DOCUMENT: {
          crabs_ot_document_t* doc = crabs_ot_document_create();
          if (doc == NULL) return false;
          if (doc->ot_data != NULL) crabs_ot_data_item_destroy(doc->ot_data);
          doc->ot_data = ot_data;
          item->value = doc;
          item->ot_data = ot_data;
          break;
        }
        case DATA_TYPE_OT_TREE: {
          crabs_ot_tree_t* tree = crabs_ot_tree_create();
          if (tree == NULL) return false;
          if (tree->ot_data != NULL) crabs_ot_data_item_destroy(tree->ot_data);
          tree->ot_data = ot_data;
          item->value = tree;
          item->ot_data = ot_data;
          break;
        }
        default:
          item->value = NULL;
          break;
      }
    } else if (item->type == DATA_TYPE_SET || item->type == DATA_TYPE_2P_SET ||
               item->type == DATA_TYPE_ONE_SHOT_SET || item->type == DATA_TYPE_ONE_SHOT_FLAG) {
      // CRDT sets/flags: reconstruct the struct (audit M-5).
      void* v = _deserialize_crdt_value(val_data, val_len, item->type);
      free(val_data);
      item->value = v;
    } else {
      // Store as raw bytes for unknown types
      item->value = get_memory(val_len);
      memcpy(item->value, val_data, val_len);
      free(val_data);
    }
  } else {
    item->value = NULL;
  }

  // For OT types, deserialize type-specific state (elements, spans, tree nodes)
  if (item->type >= DATA_TYPE_OT_ORDERED_SET && item->type <= DATA_TYPE_OT_ORDERED_MAP) {
    if (!_deserialize_ot_type_state(buf, item, version)) return false;
  }

  // invariant_count
  uint8_t inv_count;
  if (!_read_uint8(buf, &inv_count)) return false;
  item->invariant_count = inv_count;

  // invariants - allocate invariants array with enough extra space
  // to embed the error_message strings inline after the array, so that
  // free(item->invariants) also frees the string data
  if (inv_count > 0) {
    // First pass: compute total string space needed
    size_t str_space = 0;
    size_t saved_offset = buf->offset;
    uint8_t* msg_lens = get_clear_memory(inv_count * sizeof(uint8_t) + inv_count * sizeof(uint16_t));
    uint16_t* msg_lens_arr = (uint16_t*)(msg_lens + inv_count);
    for (uint8_t i = 0; i < inv_count; i++) {
      uint8_t inv_type;
      if (!_read_uint8(buf, &inv_type)) { free(msg_lens); return false; }
      uint64_t param;
      if (!_read_uint64_le(buf, &param)) { free(msg_lens); return false; }
      uint16_t msg_len;
      if (!_read_uint16_le(buf, &msg_len)) { free(msg_lens); return false; }
      msg_lens_arr[i] = msg_len;
      // R7-12: only accumulate str_space for in-bounds messages, mirroring
      // the second pass. The prior code added msg_len+1 unconditionally, so a
      // crafted msg_len of 0xFFFF with a nearly-empty buffer forced a ~16.7 MB
      // allocation per item (get_clear_memory aborts on OOM → remote crash).
      if (msg_len > 0 && msg_len <= buf->len - buf->offset) {
        str_space += msg_len + 1; // +1 for null terminator
        buf->offset += msg_len;
      }
    }
    buf->offset = saved_offset;

    // Allocate invariants array + string space
    item->invariants = get_clear_memory(inv_count * sizeof(invariant_t) + str_space);
    char* str_pool = (char*)(item->invariants + inv_count);

    // Second pass: deserialize
    for (uint8_t i = 0; i < inv_count; i++) {
      uint8_t inv_type;
      if (!_read_uint8(buf, &inv_type)) { free(msg_lens); return false; }
      item->invariants[i].type = (invariant_type_e)inv_type;

      uint64_t param;
      if (!_read_uint64_le(buf, &param)) { free(msg_lens); return false; }
      item->invariants[i].param = (int64_t)param;

      uint16_t msg_len;
      if (!_read_uint16_le(buf, &msg_len)) { free(msg_lens); return false; }
      if (msg_len > 0 && msg_len <= buf->len - buf->offset) {
        memcpy(str_pool, buf->data + buf->offset, msg_len);
        str_pool[msg_len] = '\0';
        item->invariants[i].error_message = str_pool;
        str_pool += msg_len + 1;
        buf->offset += msg_len;
      } else {
        item->invariants[i].error_message = NULL;
      }
    }
    free(msg_lens);
  } else {
    item->invariants = NULL;
  }

  // Initialize lock_state
  memset(&item->lock_state, 0, sizeof(lock_state_t));
  item->next = NULL;

  // last_compaction_time (v5+: v1.5.2 §7)
  // Backward compat: older versions default to 0
  if (version >= 5) {
    uint64_t lct;
    if (!_read_uint64_le(buf, &lct)) return false;
    item->last_compaction_time = lct;
  } else {
    item->last_compaction_time = 0;
  }

  return true;
}

// ============================================================
// Policy serialization
// ============================================================
static void _serialize_policy(write_buf_t* buf, const policy_t* policy) {
  _write_string16(buf, policy->operation);
  _write_string16(buf, policy->expression);

  // v1.3: scheme constraints (clamp to MAX_ALLOWED_SCHEMES)
  uint32_t scheme_count = policy->allowed_scheme_count < CRABS_MAX_ALLOWED_SCHEMES ?
                          policy->allowed_scheme_count : CRABS_MAX_ALLOWED_SCHEMES;
  _write_uint32_le(buf, scheme_count);
  for (uint32_t i = 0; i < scheme_count; i++) {
    _write_uint8(buf, (uint8_t)policy->allowed_schemes[i]);
  }
  _write_uint64_le(buf, policy->min_key_version);
}

static bool _deserialize_policy(read_buf_t* buf, policy_t* policy, uint32_t serial_version) {
  if (!_read_string16(buf, policy->operation, CRABS_MAX_OP_NAME)) return false;
  if (!_read_string16(buf, policy->expression, CRABS_MAX_POLICY_EXPR)) return false;

  if (serial_version >= 2) {
    // v1.3: scheme constraints
    uint32_t scheme_count;
    if (!_read_uint32_le(buf, &scheme_count)) return false;
    // Audit M-E: reject (do not clamp) oversized scheme_count. Clamping
    // desynced the parse.
    if (scheme_count > CRABS_MAX_ALLOWED_SCHEMES) return false;
    policy->allowed_scheme_count = scheme_count;
    for (uint32_t i = 0; i < policy->allowed_scheme_count; i++) {
      uint8_t scheme;
      if (!_read_uint8(buf, &scheme)) return false;
      policy->allowed_schemes[i] = (signature_scheme_e)scheme;
    }
    if (!_read_uint64_le(buf, &policy->min_key_version)) return false;
  }
  // v1: allowed_schemes and min_key_version remain zero-initialized (defaults)

  return true;
}

// ============================================================
// Config serialization
// ============================================================
static void _serialize_config(write_buf_t* buf, const machine_config_t* config) {
  _write_uint64_le(buf, config->max_lock_duration_ms);
  _write_uint32_le(buf, config->max_lock_extensions);
  _write_bool8(buf, config->allow_force_unlock);
  _write_string16(buf, config->bootstrap_admin);

  // v1.3: sig_config
  _write_uint8(buf, (uint8_t)config->sig_config.default_scheme);
  _write_uint32_le(buf, config->sig_config.max_keys_per_user);
  _write_bool8(buf, config->sig_config.key_rotation_enabled);
  _write_uint32_le(buf, config->sig_config.co_sign_threshold);
  _write_bool8(buf, config->sig_config.key_expiry_enabled);
  _write_uint64_le(buf, config->sig_config.default_key_ttl_ms);
  _write_uint64_le(buf, config->sig_config.max_key_age_ms);

  // v1.3: vault_config
  _write_uint8(buf, (uint8_t)config->vault_config.provider);
  _write_string16(buf, config->vault_config.address);
  _write_string16(buf, config->vault_config.auth_token);
  _write_bool8(buf, config->vault_config.signing_delegated);
  _write_bool8(buf, config->vault_config.rotation_delegated);
}

static bool _deserialize_config(read_buf_t* buf, machine_config_t* config, uint32_t serial_version) {
  if (!_read_uint64_le(buf, &config->max_lock_duration_ms)) return false;
  uint32_t max_ext;
  if (!_read_uint32_le(buf, &max_ext)) return false;
  config->max_lock_extensions = max_ext;
  uint8_t allow;
  if (!_read_uint8(buf, &allow)) return false;
  config->allow_force_unlock = (allow != 0);
  if (!_read_string16(buf, config->bootstrap_admin, CRABS_MAX_USER_ID)) return false;

  // v2 fields: sig_config and vault_config
  if (serial_version >= 2) {
    // sig_config
    uint8_t scheme;
    if (!_read_uint8(buf, &scheme)) return false;
    config->sig_config.default_scheme = (signature_scheme_e)scheme;
    uint32_t max_keys;
    if (!_read_uint32_le(buf, &max_keys)) return false;
    config->sig_config.max_keys_per_user = max_keys;
    uint8_t rot_enabled;
    if (!_read_uint8(buf, &rot_enabled)) return false;
    config->sig_config.key_rotation_enabled = (rot_enabled != 0);
    uint32_t co_sign;
    if (!_read_uint32_le(buf, &co_sign)) return false;
    config->sig_config.co_sign_threshold = co_sign;
    uint8_t expiry_en;
    if (!_read_uint8(buf, &expiry_en)) return false;
    config->sig_config.key_expiry_enabled = (expiry_en != 0);
    if (!_read_uint64_le(buf, &config->sig_config.default_key_ttl_ms)) return false;
    if (!_read_uint64_le(buf, &config->sig_config.max_key_age_ms)) return false;

    // vault_config
    uint8_t provider;
    if (!_read_uint8(buf, &provider)) return false;
    config->vault_config.provider = (vault_provider_e)provider;
    if (!_read_string16(buf, config->vault_config.address, CRABS_VAULT_ADDRESS_MAX)) return false;
    if (!_read_string16(buf, config->vault_config.auth_token, CRABS_VAULT_TOKEN_MAX)) return false;
    uint8_t sig_del;
    if (!_read_uint8(buf, &sig_del)) return false;
    config->vault_config.signing_delegated = (sig_del != 0);
    uint8_t rot_del;
    if (!_read_uint8(buf, &rot_del)) return false;
    config->vault_config.rotation_delegated = (rot_del != 0);
  }
  // v1: sig_config and vault_config remain zero-initialized (defaults)

  return true;
}

// ============================================================
// Log entry serialization
// ============================================================
static void _serialize_log_entry(write_buf_t* buf, const log_entry_t* entry) {
  _write_uint64_le(buf, entry->version);
  _write_bytes(buf, entry->uuid, CRABS_UUID_SIZE);
  _write_string16(buf, entry->type);
  _write_string16(buf, entry->signer_id);
  _write_uint64_le(buf, entry->lamport_time);
  _write_string16(buf, entry->node_id);
  _write_bytes(buf, entry->state_hash, CRABS_HASH_SIZE);
  // v1.6 Amd6: ordering fields
  _write_uint8(buf, (uint8_t)entry->ordering_system);
  if (entry->ordering_system == CRABS_ORDERING_HLC) {
    _write_uint64_le(buf, entry->hlc.physical_seconds);
    _write_uint64_le(buf, entry->hlc.physical_nanos);
    _write_uint64_le(buf, entry->hlc.logical_counter);
    _write_string16(buf, entry->hlc.node_id);
  }
}

static bool _deserialize_log_entry(read_buf_t* buf, log_entry_t* entry) {
  if (!_read_uint64_le(buf, &entry->version)) return false;
  if (!_read_bytes(buf, entry->uuid, CRABS_UUID_SIZE)) return false;
  if (!_read_string16(buf, entry->type, CRABS_MAX_OP_NAME)) return false;
  if (!_read_string16(buf, entry->signer_id, CRABS_MAX_USER_ID)) return false;
  if (!_read_uint64_le(buf, &entry->lamport_time)) return false;
  if (!_read_string16(buf, entry->node_id, CRABS_MAX_USER_ID)) return false;
  if (!_read_bytes(buf, entry->state_hash, CRABS_HASH_SIZE)) return false;
  // v1.6 Amd6: ordering fields (backward compatible — defaults to LAMPORT if absent)
  entry->ordering_system = CRABS_ORDERING_LAMPORT;
  memset(&entry->hlc, 0, sizeof(crabs_hlc_t));
  if (buf->offset < buf->len) {
    if (!_read_uint8(buf, (uint8_t*)&entry->ordering_system)) return false;
    if (entry->ordering_system == CRABS_ORDERING_HLC) {
      if (!_read_uint64_le(buf, &entry->hlc.physical_seconds)) return false;
      if (!_read_uint64_le(buf, &entry->hlc.physical_nanos)) return false;
      // Audit A-4: enforce the same nanos bound crabs_hlc_deserialize does.
      // A log entry with nanos >= 1e9 would poison the R7-11 replay backstop
      // and the chain hash comparisons once HLC receive is wired.
      if (entry->hlc.physical_nanos >= 1000000000ULL) return false;
      if (!_read_uint64_le(buf, &entry->hlc.logical_counter)) return false;
      if (!_read_string16(buf, entry->hlc.node_id, CRABS_HLC_NODE_ID_SIZE)) return false;
    }
  }
  return true;
}

// ============================================================
// State serialization (§13.1)
// ============================================================

// Audit A-3: triggers were never serialized, so save/load silently dropped
// every trigger definition. v9 persists all trigger_t fields (the condition
// AST is runtime state re-derived from the condition string on load).
static void _serialize_trigger(write_buf_t* buf, const trigger_t* trigger) {
  _write_string16(buf, trigger->trigger_id);
  _write_string16(buf, trigger->description);
  _write_string16(buf, trigger->condition);
  _write_uint8(buf, (uint8_t)trigger->effect.type);
  _write_string16(buf, trigger->effect.issue_attribute);
  _write_string16(buf, trigger->effect.target_role);
  _write_uint64_le(buf, trigger->effect.duration_ms);
  _write_string16(buf, trigger->effect.attribute_value);
  _write_string16(buf, trigger->effect.policy_operation);
  _write_string16(buf, trigger->effect.policy_expression);
  _write_uint64_le(buf, trigger->cooldown_ms);
  _write_uint64_le(buf, trigger->last_triggered_at);
  _write_bool8(buf, trigger->one_shot);
  _write_bool8(buf, trigger->enabled);
  _write_uint64_le(buf, trigger->expires_at);
  _write_uint64_le(buf, trigger->created_at);
  _write_string16(buf, trigger->created_by);
}

static bool _deserialize_trigger(read_buf_t* buf, trigger_t* trigger) {
  if (!_read_string16(buf, trigger->trigger_id, CRABS_MAX_USER_ID)) return false;
  if (!_read_string16(buf, trigger->description, CRABS_MAX_POLICY_EXPR)) return false;
  if (!_read_string16(buf, trigger->condition, CRABS_MAX_POLICY_EXPR)) return false;
  uint8_t effect_type;
  if (!_read_uint8(buf, &effect_type)) return false;
  trigger->effect.type = (trigger_effect_type_e)effect_type;
  if (!_read_string16(buf, trigger->effect.issue_attribute, CRABS_MAX_POLICY_EXPR)) return false;
  if (!_read_string16(buf, trigger->effect.target_role, CRABS_MAX_USER_ID)) return false;
  if (!_read_uint64_le(buf, &trigger->effect.duration_ms)) return false;
  if (!_read_string16(buf, trigger->effect.attribute_value, CRABS_MAX_POLICY_EXPR)) return false;
  if (!_read_string16(buf, trigger->effect.policy_operation, CRABS_MAX_OP_NAME)) return false;
  if (!_read_string16(buf, trigger->effect.policy_expression, CRABS_MAX_POLICY_EXPR)) return false;
  if (!_read_uint64_le(buf, &trigger->cooldown_ms)) return false;
  if (!_read_uint64_le(buf, &trigger->last_triggered_at)) return false;
  uint8_t one_shot;
  if (!_read_uint8(buf, &one_shot)) return false;
  trigger->one_shot = (one_shot != 0);
  uint8_t enabled;
  if (!_read_uint8(buf, &enabled)) return false;
  trigger->enabled = (enabled != 0);
  if (!_read_uint64_le(buf, &trigger->expires_at)) return false;
  if (!_read_uint64_le(buf, &trigger->created_at)) return false;
  if (!_read_string16(buf, trigger->created_by, CRABS_MAX_USER_ID)) return false;
  // Re-derive the AST so the restored trigger can fire. Fail closed when the
  // condition does not parse — state_machine_op_create_trigger never stores
  // such a trigger, so a blob carrying one is malformed.
  trigger->condition_ast = condition_parse(trigger->condition);
  if (trigger->condition_ast == NULL) return false;
  return true;
}

// ============================================================
// v10: op_type_def (dedup registry) and user-registry writers
// ============================================================

static void _serialize_dedup_spec(write_buf_t* buf, const dedup_spec_t* spec) {
  _write_uint8(buf, (uint8_t)spec->type);
  _write_string16(buf, spec->tracker_path);
  _write_string16(buf, spec->flag_path);
  _write_string16(buf, spec->condition);
  _write_uint8(buf, (uint8_t)spec->update.type);
  _write_string16(buf, spec->update.set_path);
  _write_string16(buf, spec->update.element_value);
  _write_string16(buf, spec->update.flag_path);
  _write_string16(buf, spec->update.counter_path);
  _write_uint64_le(buf, (uint64_t)spec->update.delta);
  _write_string16(buf, spec->update.target_path);
  _write_string16(buf, spec->update.value);
  _write_string16(buf, spec->rejection_message);
}

static void _serialize_user(write_buf_t* buf, const user_t* user) {
  _write_string16(buf, user->user_id);
  _write_uint8(buf, (uint8_t)user->status);
  _write_uint64_le(buf, user->key_version);
  _write_uint64_le(buf, user->created_at);
  _write_uint64_le(buf, user->updated_at);
  _write_uint32_le(buf, user->attribute_count);
  // Attributes persist verbatim: attribute_value_t stores the whole
  // "name:value" pair in value (the attribute machine's lookup convention,
  // _attribute_matches_name / _extract_name), so there is no separate name
  // field to write — value round-trips byte-for-byte.
  for (uint32_t attribute_index = 0; attribute_index < user->attribute_count;
       attribute_index++) {
    const attribute_value_t* attribute = &user->attributes[attribute_index];
    _write_string16(buf, attribute->value);
    _write_string16(buf, attribute->verified_by);
    _write_uint64_le(buf, attribute->verified_at);
    _write_uint64_le(buf, attribute->expires_at);
  }
  _write_bytes(buf, user->public_key, 33);
  _write_string16(buf, user->default_key_id);
  // The key count is derived by walking the list (same derivation as the
  // user-registry and temp-attr counts): a stale in-memory key_count would
  // disagree with the entries actually written and corrupt round-trips.
  uint32_t wire_key_count = 0;
  for (const user_key_t* key = user->keys; key != NULL; key = key->next)
    wire_key_count++;
  _write_uint32_le(buf, wire_key_count);
  for (const user_key_t* key = user->keys; key != NULL; key = key->next) {
    _write_string16(buf, key->key_id);
    _write_uint8(buf, (uint8_t)key->scheme);
    _write_uint32_le(buf, key->public_key_len);
    _write_bytes(buf, key->public_key, key->public_key_len);
    _write_string16(buf, key->label);
    _write_uint64_le(buf, key->registered_at);
    _write_uint64_le(buf, key->last_used_at);
    _write_uint8(buf, (uint8_t)key->status);
    _write_uint64_le(buf, key->expires_at);
    _write_uint64_le(buf, key->suspended_at);
    _write_uint64_le(buf, key->revoked_at);
    _write_string16(buf, key->predecessor_key_id);
  }
  // temp attrs: the linked list has no count field — count first.
  uint32_t temp_count = 0;
  for (const temp_attr_list_t* temp = user->temp_attrs; temp != NULL; temp = temp->next)
    temp_count++;
  _write_uint32_le(buf, temp_count);
  for (const temp_attr_list_t* temp = user->temp_attrs; temp != NULL; temp = temp->next) {
    _write_string16(buf, temp->name);
    _write_string16(buf, temp->value);
    _write_uint64_le(buf, temp->issued_at);
    _write_uint64_le(buf, temp->expires_at);
  }
}

// Core state writer. seal_key selects the v10 MSK section behavior:
//  - seal_key == NULL (unkeyed, crabs_serialize_state): the MSK section is
//    written with flag 0 — v9 semantics, substrate only.
//  - seal_key != NULL (crabs_serialize_state_sealed): the ABE master key is
//    sealed and written (flag 1). A sealed write whose blob carries no
//    sealable master key fails the whole serialize.
static serialized_buffer_t* _serialize_state_internal(const state_t* state,
                                                      const uint8_t seal_key[32]) {
  if (state == NULL) return NULL;

  write_buf_t* buf = _write_buf_create(4096);

  // Magic bytes: "CRAB" = 0x43, 0x52, 0x41, 0x42
  _write_uint8(buf, 0x43);
  _write_uint8(buf, 0x52);
  _write_uint8(buf, 0x41);
  _write_uint8(buf, 0x42);

  // Version
  _write_uint32_le(buf, CRABS_SERIAL_VERSION);

  // state_version
  _write_uint64_le(buf, state->version);

  // Count items
  uint32_t item_count = 0;
  data_item_t* item = state->items;
  while (item != NULL) {
    item_count++;
    item = item->next;
  }

  // item_count
  _write_uint32_le(buf, item_count);

  // policy_count
  _write_uint32_le(buf, state->policy_count);

  // log_count
  _write_uint32_le(buf, (uint32_t)state->log_count);

  // items
  item = state->items;
  while (item != NULL) {
    _serialize_data_item(buf, item);
    item = item->next;
  }

  // policies
  for (uint32_t i = 0; i < state->policy_count; i++) {
    _serialize_policy(buf, &state->policies[i]);
  }

  // config
  _serialize_config(buf, &state->config);

  // log entries
  for (uint64_t i = 0; i < state->log_count; i++) {
    _serialize_log_entry(buf, &state->log[i]);
  }

  // schedules (v6): pending timed transactions
  _write_uint64_le(buf, state->schedule_seq);
  uint32_t schedule_count = 0;
  for (const scheduled_operation_t* schedule_entry = state->scheduled_operations;
       schedule_entry != NULL; schedule_entry = schedule_entry->next) {
    schedule_count++;
  }
  _write_uint32_le(buf, schedule_count);
  for (const scheduled_operation_t* schedule_entry = state->scheduled_operations;
       schedule_entry != NULL; schedule_entry = schedule_entry->next) {
    _write_uint64_le(buf, schedule_entry->schedule_id);
    _write_uint64_le(buf, schedule_entry->execute_at_ms);
    _write_uint64_le(buf, schedule_entry->interval_ms);
    _write_uint64_le(buf, schedule_entry->repeat_count);
    _write_uint64_le(buf, schedule_entry->end_at_ms);
    _write_bytes(buf, (const uint8_t*)schedule_entry->submitter, CRABS_MAX_USER_ID);
    _write_uint32_le(buf, schedule_entry->op_len);
    _write_bytes(buf, schedule_entry->op_bytes, schedule_entry->op_len);
  }

  // triggers (v9): persisted trigger definitions
  _write_uint32_le(buf, state->trigger_count);
  for (uint32_t trigger_index = 0; trigger_index < state->trigger_count; trigger_index++) {
    _serialize_trigger(buf, &state->triggers[trigger_index]);
  }

  // op_type_defs (v10): the dedup registry — it was previously not persisted.
  // The section order from here to the checksum is contractual (sequential
  // blob).
  _write_uint32_le(buf, state->op_type_def_count);
  for (uint32_t def_index = 0; def_index < state->op_type_def_count; def_index++) {
    _write_string16(buf, state->op_type_defs[def_index].op_type);
    _serialize_dedup_spec(buf, &state->op_type_defs[def_index].dedup);
  }

  // user registry (v10): users live on the linked attribute machine. The
  // count is derived by walking the list (same as items above) so the wire
  // count can never disagree with the entries actually written, even if the
  // machine's cached user_count were ever out of sync.
  uint32_t user_count = 0;
  if (state->attr_machine != NULL) {
    const user_t* user = state->attr_machine->users;
    while (user != NULL) {
      user_count++;
      user = user->next;
    }
  }
  _write_uint32_le(buf, user_count);
  if (state->attr_machine != NULL) {
    for (const user_t* user = state->attr_machine->users; user != NULL; user = user->next) {
      _serialize_user(buf, user);
    }
  }

  // child manifest (v11): the position v10 booked as a strictly-zero u32
  // count now carries the count plus one fixed-order entry per spawned child.
  // Entries are written from the state's heap array in index order with
  // fixed-width fields, so re-serializing a restored state is byte-identical
  // (canonical wire). The writer derives nothing from the entries — the count
  // is state->child_count, matching the state-owned array invariant (children
  // non-NULL iff child_count > 0; state_destroy frees the array wholesale).
  _write_uint32_le(buf, state->child_count);
  for (uint32_t child_index = 0; child_index < state->child_count; child_index++) {
    const child_manifest_entry_t* manifest_entry = &state->children[child_index];
    _write_string16(buf, manifest_entry->child_id);
    _write_uint8(buf, (uint8_t)manifest_entry->mode);
    _write_bytes(buf, manifest_entry->genesis_snapshot_hash, CRABS_HASH_SIZE);
    _write_bytes(buf, manifest_entry->genesis_attestation_signature, CRABS_SIG_SIZE);
    _write_uint64_le(buf, manifest_entry->attestation_ttl_ms);
    _write_uint64_le(buf, manifest_entry->spawned_at);
    _write_uint8(buf, (uint8_t)manifest_entry->status);
  }

  // parent binding (v11): present only for spawned children. lineage_self_id
  // travels WITH the binding (required) — it is the child_id the machine's
  // genesis attestation names, so endorsement checks survive restart.
  _write_uint8(buf, state->lineage_parent_bound ? 1 : 0);
  if (state->lineage_parent_bound) {
    _write_string16(buf, state->lineage_parent_id);
    _write_bytes(buf, state->lineage_parent_public_key, 33);
    _write_string16(buf, state->lineage_self_id);
    // v12: the dissolve tombstone flag rides at the END of the binding block
    // (v11 tail position). A v11 reader stops before this byte and leaves the
    // runtime default — the flag is additive, not a layout change.
    _write_uint8(buf, state->lineage_parent_dissolved ? 1 : 0);
  }

  // MSK (v10): sealed under seal_key when both the machine's authority and a
  // seal key are present. The unkeyed serializer omits the MSK (flag 0) —
  // persisting an UNSEALED master key is never valid, and losing it (v9
  // behavior) is the substrate-only compat path.
  if (state->abe_mk != NULL && seal_key != NULL) {
    uint8_t msk_blob[16384];
    size_t msk_len = crypto_master_key_serialize(
        (const abe_master_key_t*)state->abe_mk, msk_blob, sizeof(msk_blob));
    uint8_t sealed_msk[sizeof(msk_blob) + CRABS_SEAL_OVERHEAD];
    size_t sealed_len = sizeof(sealed_msk);
    if (msk_len == 0 ||
        crypto_seal(seal_key, msk_blob, msk_len, sealed_msk, &sealed_len) != CRABS_SUCCESS) {
      // Fail loud: cannot persist authority. The caller sees a NULL buffer.
      OPENSSL_cleanse(sealed_msk, sizeof(sealed_msk));
      OPENSSL_cleanse(msk_blob, sizeof(msk_blob));
      free(buf->data);
      free(buf);
      return NULL;
    }
    OPENSSL_cleanse(msk_blob, sizeof(msk_blob));
    _write_uint8(buf, 1);
    _write_uint32_le(buf, (uint32_t)sealed_len);
    _write_bytes(buf, sealed_msk, sealed_len);
    OPENSSL_cleanse(sealed_msk, sizeof(sealed_msk));
  } else {
    _write_uint8(buf, 0);
  }

  // Checksum: SHA-256 of all preceding bytes.
  // NOTE: this is an INTEGRITY/CORRUPTION check, NOT authentication. An
  // attacker who can modify the blob can recompute this hash. Loading state
  // blobs from untrusted sources requires an external signature (e.g. by the
  // node key) over the whole blob — the load API does not currently accept a
  // key, so adding HMAC would require an API change (audit M-1 follow-up).
  uint8_t hash[CRABS_HASH_SIZE];
  SHA256(buf->data, buf->offset, hash);
  _write_bytes(buf, hash, CRABS_HASH_SIZE);

  // Create output
  serialized_buffer_t* result = serialized_buffer_create(buf->offset);
  memcpy(result->data, buf->data, buf->offset);
  result->len = buf->offset;

  free(buf->data);
  free(buf);
  return result;
}

serialized_buffer_t* crabs_serialize_state(const state_t* state) {
  return _serialize_state_internal(state, NULL);
}

serialized_buffer_t* crabs_serialize_state_sealed(const state_t* state,
                                                    const uint8_t seal_key[32]) {
  if (state == NULL || seal_key == NULL) return NULL;
  // Fail loud: a "sealed" write without the machine's authority is not the
  // sealed format at all.
  if (state->abe_mk == NULL) return NULL;
  return _serialize_state_internal(state, seal_key);
}

// v10: read one user entry from the wire into the attribute machine's user
// list (the attribute machine owns the registry; see state_destroy and
// attribute_machine_destroy's ownership contract). Returns false and frees
// the partially built record on any malformed field.
static bool _deserialize_user(read_buf_t* buf, attribute_machine_t* machine) {
  user_t* user = get_clear_memory(sizeof(user_t));
  if (user == NULL) return false;

  if (!_read_string16(buf, user->user_id, CRABS_MAX_USER_ID)) goto fail;
  uint8_t user_status;
  if (!_read_uint8(buf, &user_status)) goto fail;
  user->status = (user_status_e)user_status;
  if (!_read_uint64_le(buf, &user->key_version)) goto fail;
  if (!_read_uint64_le(buf, &user->created_at)) goto fail;
  if (!_read_uint64_le(buf, &user->updated_at)) goto fail;
  if (!_read_uint32_le(buf, &user->attribute_count)) goto fail;
  if (user->attribute_count > CRABS_MAX_ATTRIBUTES) goto fail;
  for (uint32_t attribute_index = 0; attribute_index < user->attribute_count;
       attribute_index++) {
    attribute_value_t* attribute = &user->attributes[attribute_index];
    // Attributes persist verbatim as "name:value" pairs: the attribute name
    // precedes the first ':' in the stored value (the attribute machine's
    // lookup convention — _extract_name). There is no separate name field
    // in attribute_value_t, so nothing else needs reconstructing.
    if (!_read_string16(buf, attribute->value, CRABS_MAX_POLICY_EXPR)) goto fail;
    if (!_read_string16(buf, attribute->verified_by, CRABS_MAX_USER_ID)) goto fail;
    if (!_read_uint64_le(buf, &attribute->verified_at)) goto fail;
    if (!_read_uint64_le(buf, &attribute->expires_at)) goto fail;
  }
  if (!_read_bytes(buf, user->public_key, 33)) goto fail;
  if (!_read_string16(buf, user->default_key_id, CRABS_MAX_KEY_ID)) goto fail;
  if (!_read_uint32_le(buf, &user->key_count)) goto fail;
  if (user->key_count > CRABS_MAX_KEYS_PER_USER) goto fail;
  user_key_t** key_tail = &user->keys;
  for (uint32_t key_index = 0; key_index < user->key_count; key_index++) {
    user_key_t* key = get_clear_memory(sizeof(user_key_t));
    if (key == NULL) goto fail;
    // A partially read key is NOT in the list yet, so the shared cleanup
    // below cannot free it — release it at every malformed-field exit.
    if (!_read_string16(buf, key->key_id, CRABS_MAX_KEY_ID)) { free(key); goto fail; }
    uint8_t key_scheme;
    if (!_read_uint8(buf, &key_scheme)) { free(key); goto fail; }
    key->scheme = (signature_scheme_e)key_scheme;
    if (!_read_uint32_le(buf, &key->public_key_len)) { free(key); goto fail; }
    if (key->public_key_len > CRABS_MAX_PUBLIC_KEY) { free(key); goto fail; }
    if (!_read_bytes(buf, key->public_key, key->public_key_len)) { free(key); goto fail; }
    if (!_read_string16(buf, key->label, CRABS_MAX_KEY_LABEL)) { free(key); goto fail; }
    if (!_read_uint64_le(buf, &key->registered_at)) { free(key); goto fail; }
    if (!_read_uint64_le(buf, &key->last_used_at)) { free(key); goto fail; }
    uint8_t key_status;
    if (!_read_uint8(buf, &key_status)) { free(key); goto fail; }
    key->status = (key_status_e)key_status;
    if (!_read_uint64_le(buf, &key->expires_at)) { free(key); goto fail; }
    if (!_read_uint64_le(buf, &key->suspended_at)) { free(key); goto fail; }
    if (!_read_uint64_le(buf, &key->revoked_at)) { free(key); goto fail; }
    if (!_read_string16(buf, key->predecessor_key_id, CRABS_MAX_KEY_ID)) { free(key); goto fail; }
    *key_tail = key;
    key_tail = &key->next;
  }
  uint32_t temp_count;
  if (!_read_uint32_le(buf, &temp_count)) goto fail;
  // Each temp entry is at least two string16s (4 bytes); a larger count
  // cannot be satisfied by the remaining buffer.
  if (temp_count > (buf->len - buf->offset) / 4) goto fail;
  temp_attr_list_t** temp_tail = &user->temp_attrs;
  for (uint32_t temp_index = 0; temp_index < temp_count; temp_index++) {
    temp_attr_list_t* temp = get_clear_memory(sizeof(temp_attr_list_t));
    if (temp == NULL) goto fail;
    if (!_read_string16(buf, temp->name, CRABS_MAX_POLICY_EXPR) ||
        !_read_string16(buf, temp->value, CRABS_MAX_POLICY_EXPR) ||
        !_read_uint64_le(buf, &temp->issued_at) ||
        !_read_uint64_le(buf, &temp->expires_at)) {
      free(temp);
      goto fail;
    }
    *temp_tail = temp;
    temp_tail = &temp->next;
  }
  // Splice into the machine's list (the attribute machine is the owner).
  user_t** user_tail = &machine->users;
  while (*user_tail != NULL) user_tail = &(*user_tail)->next;
  *user_tail = user;
  user->next = NULL;
  machine->user_count++;
  return true;
fail:
  // Same teardown the registry uses on destroy — the entry is NOT spliced
  // into the machine's list yet on this path, so release it in isolation.
  user_destroy(user);
  return false;
}

// authority_restored is set true only when a sealed MSK section unsealed and
// deserialized with the provided key; msk_section_present reports whether the
// sealed authority section existed at all. Both are nullable.
static state_t* _deserialize_state_internal(const uint8_t* data, size_t len,
                                            const uint8_t seal_key[32],
                                            bool* authority_restored,
                                            bool* msk_section_present) {
  // Reporters default false; the sealed path below sets them true.
  if (authority_restored != NULL) *authority_restored = false;
  if (msk_section_present != NULL) *msk_section_present = false;
  if (data == NULL || len < CRABS_HASH_SIZE + 4 + 4 + 8 + 4 + 4 + 4) {
    return NULL;
  }

  read_buf_t buf;
  buf.data = data;
  buf.len = len;
  buf.offset = 0;

  // Verify checksum first
  uint8_t computed_hash[CRABS_HASH_SIZE];
  SHA256(data, len - CRABS_HASH_SIZE, computed_hash);
  if (memcmp(computed_hash, data + len - CRABS_HASH_SIZE, CRABS_HASH_SIZE) != 0) {
    return NULL;
  }

  // Magic bytes
  uint8_t magic[4];
  for (int i = 0; i < 4; i++) {
    if (!_read_uint8(&buf, &magic[i])) return NULL;
  }
  if (magic[0] != 0x43 || magic[1] != 0x52 || magic[2] != 0x41 || magic[3] != 0x42) {
    return NULL;
  }

  // Version
  uint32_t version;
  if (!_read_uint32_le(&buf, &version)) return NULL;
  if (version < 1 || version > CRABS_SERIAL_VERSION) return NULL;

  state_t* state = state_create();

  // state_version
  if (!_read_uint64_le(&buf, &state->version)) goto fail;

  // item_count
  uint32_t item_count;
  if (!_read_uint32_le(&buf, &item_count)) goto fail;
  if (item_count > CRABS_DESER_MAX_ITEMS) goto fail;

  // policy_count
  uint32_t policy_count;
  if (!_read_uint32_le(&buf, &policy_count)) goto fail;
  if (policy_count > CRABS_DESER_MAX_POLICIES) goto fail;

  // log_count
  uint32_t log_count;
  if (!_read_uint32_le(&buf, &log_count)) goto fail;
  // Audit A-5: bound the allocation to the remaining buffer like the other
  // counters (see pc_count below). A log entry occupies at least 64 wire
  // bytes, so a count above remaining/64 cannot be satisfied by the blob;
  // without this a few-byte blob could drive a multi-GB allocation (the
  // aborting allocator turns it into a DoS).
  if (log_count > CRABS_DESER_MAX_LOG ||
      log_count > (buf.len - buf.offset) / 64) {
    goto fail;
  }

  // items
  data_item_t* tail = NULL;
  for (uint32_t i = 0; i < item_count; i++) {
    data_item_t* item = get_clear_memory(sizeof(data_item_t));
    if (!_deserialize_data_item(&buf, item, version)) {
      data_item_destroy(item);
      goto fail;
    }
    if (state->items == NULL) {
      state->items = item;
      tail = item;
    } else {
      tail->next = item;
      tail = item;
    }
  }

  // policies
  if (policy_count > 0) {
    state->policies = get_clear_memory(policy_count * sizeof(policy_t));
    state->policy_count = policy_count;
    for (uint32_t i = 0; i < policy_count; i++) {
      if (!_deserialize_policy(&buf, &state->policies[i], version)) goto fail;
    }
  }

  // config
  if (!_deserialize_config(&buf, &state->config, version)) goto fail;

  // log entries
  if (log_count > 0) {
    state->log = get_clear_memory(log_count * sizeof(log_entry_t));
    state->log_count = log_count;
    for (uint32_t i = 0; i < log_count; i++) {
      if (!_deserialize_log_entry(&buf, &state->log[i])) goto fail;
    }
  }

  // schedules (v6+): pending timed transactions
  if (version >= 6) {
    if (!_read_uint64_le(&buf, &state->schedule_seq)) goto fail;
    uint32_t schedule_count;
    if (!_read_uint32_le(&buf, &schedule_count)) goto fail;
    if (schedule_count > CRABS_DESER_MAX_ITEMS) goto fail;
    for (uint32_t schedule_index = 0; schedule_index < schedule_count; schedule_index++) {
      scheduled_operation_t* entry =
          (scheduled_operation_t*)get_clear_memory(sizeof(scheduled_operation_t));
      if (!_read_uint64_le(&buf, &entry->schedule_id) ||
          !_read_uint64_le(&buf, &entry->execute_at_ms)) {
        free(entry);
        goto fail;
      }
      // v7: recurring cadence fields, written right after execute_at_ms (a
      // v6 blob does not contain them).
      if (version >= 7) {
        if (!_read_uint64_le(&buf, &entry->interval_ms) ||
            !_read_uint64_le(&buf, &entry->repeat_count) ||
            !_read_uint64_le(&buf, &entry->end_at_ms)) {
          free(entry);
          goto fail;
        }
      }
      if (!_read_bytes(&buf, (uint8_t*)entry->submitter, CRABS_MAX_USER_ID)) {
        free(entry);
        goto fail;
      }
      if (!_read_uint32_le(&buf, &entry->op_len) || entry->op_len == 0 ||
          entry->op_len > CRABS_DESER_MAX_SCHEDULE_OP_BYTES) {
        free(entry);
        goto fail;
      }
      entry->op_bytes = (uint8_t*)get_clear_memory(entry->op_len);
      if (!_read_bytes(&buf, entry->op_bytes, entry->op_len)) {
        free(entry->op_bytes);
        free(entry);
        goto fail;
      }
      // Append at the tail so the restored list follows submission order,
      // matching scheduler_schedule's insertion order.
      if (state->scheduled_operations == NULL) {
        state->scheduled_operations = entry;
      } else {
        scheduled_operation_t* tail = state->scheduled_operations;
        while (tail->next != NULL) tail = tail->next;
        tail->next = entry;
      }
    }
    // Defense against a hostile blob carrying a low schedule_seq alongside
    // high entry ids: the next scheduled id must not collide with any
    // restored entry. Blobs require external authentication (M-1), so this
    // is hardening, not a trust boundary.
    for (const scheduled_operation_t* schedule_entry = state->scheduled_operations;
         schedule_entry != NULL; schedule_entry = schedule_entry->next) {
      if (state->schedule_seq < schedule_entry->schedule_id) {
        state->schedule_seq = schedule_entry->schedule_id;
      }
    }
  }

  // triggers (v9+): persisted trigger definitions. The section is absent in
  // pre-v9 blobs, which restore with zero triggers.
  if (version >= 9) {
    uint32_t trigger_count;
    if (!_read_uint32_le(&buf, &trigger_count)) goto fail;
    // Audit A-3: bound the allocation to the remaining buffer. Each trigger
    // occupies at least CRABS_DESER_MIN_TRIGGER_WIRE_BYTES wire bytes, so a
    // count above remaining/min cannot be satisfied by the blob.
    if (trigger_count > CRABS_DESER_MAX_TRIGGERS ||
        trigger_count > (buf.len - buf.offset) / CRABS_DESER_MIN_TRIGGER_WIRE_BYTES) {
      goto fail;
    }
    if (trigger_count > 0) {
      state->triggers = get_clear_memory(trigger_count * sizeof(trigger_t));
      state->trigger_count = trigger_count;
      for (uint32_t trigger_index = 0; trigger_index < trigger_count; trigger_index++) {
        if (!_deserialize_trigger(&buf, &state->triggers[trigger_index])) goto fail;
      }
    }
  }

  // v10 sections: op_type_defs, user registry, child manifest space, MSK.
  // The section order is contractual (the blob is sequential).
  if (version >= 10) {
    // op_type_defs (v10): the dedup registry — previously not persisted.
    uint32_t def_count;
    if (!_read_uint32_le(&buf, &def_count)) goto fail;
    if (def_count > CRABS_MAX_OP_TYPE_DEFS) goto fail;
    if (def_count > 0) {
      state->op_type_defs = get_clear_memory(def_count * sizeof(op_type_def_t));
      if (state->op_type_defs == NULL) goto fail;
      state->op_type_def_count = def_count;
      for (uint32_t def_index = 0; def_index < def_count; def_index++) {
        op_type_def_t* def = &state->op_type_defs[def_index];
        if (!_read_string16(&buf, def->op_type, CRABS_MAX_OP_NAME)) goto fail;
        uint8_t dedup_type;
        if (!_read_uint8(&buf, &dedup_type)) goto fail;
        def->dedup.type = (dedup_type_e)dedup_type;
        if (!_read_string16(&buf, def->dedup.tracker_path, CRABS_MAX_DEDUP_PATH)) goto fail;
        if (!_read_string16(&buf, def->dedup.flag_path, CRABS_MAX_DEDUP_PATH)) goto fail;
        if (!_read_string16(&buf, def->dedup.condition, CRABS_MAX_POLICY_EXPR)) goto fail;
        uint8_t mutation_type;
        if (!_read_uint8(&buf, &mutation_type)) goto fail;
        def->dedup.update.type = (mutation_type_e)mutation_type;
        if (!_read_string16(&buf, def->dedup.update.set_path, CRABS_MAX_DEDUP_PATH)) goto fail;
        if (!_read_string16(&buf, def->dedup.update.element_value, CRABS_MAX_USER_ID)) goto fail;
        if (!_read_string16(&buf, def->dedup.update.flag_path, CRABS_MAX_DEDUP_PATH)) goto fail;
        if (!_read_string16(&buf, def->dedup.update.counter_path, CRABS_MAX_DEDUP_PATH)) goto fail;
        uint64_t dedup_delta;
        if (!_read_uint64_le(&buf, &dedup_delta)) goto fail;
        def->dedup.update.delta = (int64_t)dedup_delta;
        if (!_read_string16(&buf, def->dedup.update.target_path, CRABS_MAX_DEDUP_PATH)) goto fail;
        if (!_read_string16(&buf, def->dedup.update.value, CRABS_MAX_DEDUP_PATH)) goto fail;
        if (!_read_string16(&buf, def->dedup.rejection_message, CRABS_MAX_DEDUP_MESSAGE)) goto fail;
      }
    }

    // user registry (v10): users live on the linked attribute machine. The
    // registry is non-empty in the blob only when the source machine had
    // users, so a shell attribute machine is built here (base_state is the
    // FIRST member of attribute_machine_t — the returned state pointer is
    // also the shell allocation, so state_destroy releases it). Bare states
    // (empty registry) keep attr_machine NULL.
    uint32_t user_count;
    if (!_read_uint32_le(&buf, &user_count)) goto fail;
    if (user_count > CRABS_DESER_MAX_USERS ||
        user_count > (buf.len - buf.offset) / CRABS_DESER_MIN_USER_WIRE_BYTES) {
      goto fail;
    }
    if (user_count > 0) {
      attribute_machine_t* shell = get_clear_memory(sizeof(attribute_machine_t));
      if (shell == NULL) goto fail;
      shell->base_state = *state;
      shell->base_state.attr_machine = shell;
      free(state);
      state = &shell->base_state;
    }
    for (uint32_t user_index = 0; user_index < user_count; user_index++) {
      if (!_deserialize_user(&buf, state->attr_machine)) goto fail;
    }

    // child manifest: v10 booked a strictly-zero u32 count at this position;
    // v11 fills it with the count plus one entry per spawned child, followed
    // by the parent-binding block. The count is ALWAYS consumed here so v10
    // and v11 blobs stay byte-aligned through this section.
    uint32_t child_manifest_count;
    if (!_read_uint32_le(&buf, &child_manifest_count)) goto fail;
    if (version < 11) {
      // v10: the manifest section is count-only — it must be empty.
      if (child_manifest_count != 0) goto fail;
    } else {
      // v11: entries + parent binding. Both counts above are bounded by the
      // cap and by the remaining buffer (audit A-3/A-5 pattern).
      if (child_manifest_count > CRABS_DESER_MAX_CHILDREN ||
          child_manifest_count >
              (buf.len - buf.offset) / CRABS_DESER_MIN_CHILD_ENTRY_WIRE_BYTES) {
        goto fail;
      }
      if (child_manifest_count > 0) {
        state->children =
            get_clear_memory(child_manifest_count * sizeof(child_manifest_entry_t));
        if (state->children == NULL) goto fail;
        state->child_count = child_manifest_count;
        for (uint32_t child_index = 0; child_index < child_manifest_count;
             child_index++) {
          child_manifest_entry_t* manifest_entry = &state->children[child_index];
          if (!_read_string16(&buf, manifest_entry->child_id, CRABS_MAX_USER_ID)) {
            goto fail;
          }
          uint8_t entry_mode;
          if (!_read_uint8(&buf, &entry_mode)) goto fail;
          if (entry_mode < (uint8_t)LINEAGE_SHARED_ROOT ||
              entry_mode > (uint8_t)LINEAGE_SOVEREIGN) {
            goto fail;
          }
          manifest_entry->mode = (lineage_trust_mode_e)entry_mode;
          if (!_read_bytes(&buf, manifest_entry->genesis_snapshot_hash,
                           CRABS_HASH_SIZE)) {
            goto fail;
          }
          if (!_read_bytes(&buf, manifest_entry->genesis_attestation_signature,
                           CRABS_SIG_SIZE)) {
            goto fail;
          }
          if (!_read_uint64_le(&buf, &manifest_entry->attestation_ttl_ms)) goto fail;
          if (!_read_uint64_le(&buf, &manifest_entry->spawned_at)) goto fail;
          uint8_t entry_status;
          if (!_read_uint8(&buf, &entry_status)) goto fail;
          // Wire-compatible enum extension: 0..3 (ATTESTATION_REVOKED added
          // without a format bump — the status stays a u8).
          if (entry_status > (uint8_t)LINEAGE_ATTESTATION_REVOKED) goto fail;
          manifest_entry->status = (lineage_status_e)entry_status;
        }
      }

      // parent binding (v11): the flag is boolean on the wire — strictly
      // 0 or 1. When set, all three binding fields are required: parent id,
      // the parent's 33-byte public key, and THIS machine's id. It is read
      // even when the manifest is empty — a spawned child may have no
      // children of its own but still carry its binding.
      uint8_t parent_bound;
      if (!_read_uint8(&buf, &parent_bound)) goto fail;
      if (parent_bound > 1) goto fail;
      if (parent_bound == 1) {
        if (!_read_string16(&buf, state->lineage_parent_id,
                            CRABS_MAX_USER_ID)) {
          goto fail;
        }
        if (!_read_bytes(&buf, state->lineage_parent_public_key, 33)) goto fail;
        if (!_read_string16(&buf, state->lineage_self_id,
                            CRABS_MAX_USER_ID)) {
          goto fail;
        }
        // v12: the dissolve tombstone flag closes the binding block. v11 and
        // older blobs end the block at the self id — the flag byte does not
        // exist there, so the read is gated on version >= 12 and older files
        // keep the fresh-state default (dissolved false).
        if (version >= 12) {
          uint8_t parent_dissolved;
          if (!_read_uint8(&buf, &parent_dissolved)) goto fail;
          if (parent_dissolved > 1) goto fail;
          state->lineage_parent_dissolved = (parent_dissolved == 1);
        }
        state->lineage_parent_bound = true;
      }
    }

    // MSK (v10): u8 flag; when 1, u32 sealed_len + sealed bytes. A wrong or
    // absent seal key keeps the FRESH master key from state_create (the
    // substrate-only compat path) — never NULL.
    uint8_t msk_present;
    if (!_read_uint8(&buf, &msk_present)) goto fail;
    if (msk_present > 1) goto fail;   // the flag is boolean on the wire
    if (msk_present != 0) {
      if (msk_section_present != NULL) *msk_section_present = true;
      uint32_t sealed_len;
      if (!_read_uint32_le(&buf, &sealed_len)) goto fail;
      if (sealed_len == 0 || sealed_len > CRABS_DESER_MAX_SEALED_MSK_BYTES) goto fail;
      uint8_t* sealed_blob = get_memory(sealed_len);
      if (sealed_blob == NULL) goto fail;
      if (!_read_bytes(&buf, sealed_blob, sealed_len)) {
        free(sealed_blob);
        goto fail;
      }
      if (seal_key != NULL) {
        uint8_t msk_plain[16384];
        size_t msk_plain_len = 0;
        if (crypto_unseal(seal_key, sealed_blob, sealed_len,
                          msk_plain, sizeof(msk_plain), &msk_plain_len) == CRABS_SUCCESS) {
          abe_master_key_t* restored_master_key =
              crypto_master_key_deserialize(msk_plain, msk_plain_len);
          if (restored_master_key != NULL) {
            crypto_abe_master_key_destroy(state->abe_mk);   // discard fresh key
            state->abe_mk = restored_master_key;
            if (authority_restored != NULL) *authority_restored = true;
          }
        }
        // Cleanse the recovered plaintext whether or not the unseal or the
        // deserialize succeeded — plaintext key material never lingers.
        OPENSSL_cleanse(msk_plain, sizeof(msk_plain));
      }
      OPENSSL_cleanse(sealed_blob, sealed_len);
      free(sealed_blob);
    }
  }

  // A10-L6: require the payload to be fully consumed — every section must end
  // exactly where the checksum begins (the op deserializer precedent, R7-L-6).
  // Trailing bytes mean corruption or a crafted dual-parse blob. All version-
  // gated sections are consumed to the same end for every accepted version, and
  // the sealed path consumes the MSK section identically with or without a seal
  // key, so this invariant holds for every legitimate blob.
  if (buf.offset != buf.len - CRABS_HASH_SIZE) goto fail;

  return state;

fail:
  state_destroy(state);
  return NULL;
}

state_t* crabs_deserialize_state(const uint8_t* data, size_t len) {
  return _deserialize_state_internal(data, len, NULL, NULL, NULL);
}

state_t* crabs_deserialize_state_keys(const uint8_t* data, size_t len,
                                      const uint8_t seal_key[32]) {
  return _deserialize_state_internal(data, len, seal_key, NULL, NULL);
}

state_t* crabs_deserialize_state_keys_reported(const uint8_t* data, size_t len,
                                               const uint8_t seal_key[32],
                                               bool* authority_restored,
                                               bool* msk_section_present) {
  return _deserialize_state_internal(data, len, seal_key, authority_restored,
                                     msk_section_present);
}

// R7-03: append the node-key ECDSA trailer over the whole blob. The bare
// SHA-256 is not authentication — an attacker who can write the state file can
// recompute it. Returns NULL without touching the blob when the state has no
// valid node key.
static serialized_buffer_t* _append_state_signature(
    serialized_buffer_t* blob, const state_t* state) {
  if (blob == NULL || state == NULL) return NULL;
  if (!state->node_key_valid) return NULL;

  serialized_buffer_t* result =
      serialized_buffer_create(blob->len + CRABS_SIG_SIZE);
  if (result == NULL) return NULL;
  memcpy(result->data, blob->data, blob->len);
  result->len = blob->len + CRABS_SIG_SIZE;

  if (crypto_ecdsa_sign(state->node_private_key, blob->data, blob->len,
                        result->data + blob->len) != CRABS_SUCCESS) {
    serialized_buffer_destroy(result);
    return NULL;
  }
  return result;
}

// R7-03: authenticated state snapshot. Serializes the state (with its SHA-256
// corruption checksum) and appends an ECDSA signature over the whole blob from
// the node's private key.
serialized_buffer_t* crabs_serialize_state_signed(const state_t* state) {
  if (state == NULL) return NULL;
  if (!state->node_key_valid) return NULL;

  serialized_buffer_t* payload = crabs_serialize_state(state);
  if (payload == NULL) return NULL;

  serialized_buffer_t* result = _append_state_signature(payload, state);
  if (result == NULL) {
    serialized_buffer_destroy(payload);
    return NULL;
  }
  serialized_buffer_destroy(payload);
  return result;
}

// Sealed + signed: the full snapshot seals the MSK under seal_key, then the
// node-key trailer covers the WHOLE sealed payload. cli_node_save is the
// canonical caller; the CLI's durability path keeps both at-rest guarantees
// (authority persistence + snapshot authentication) in one serialized form.
serialized_buffer_t* crabs_serialize_state_sealed_signed(
    const state_t* state, const uint8_t seal_key[32]) {
  if (state == NULL || seal_key == NULL) return NULL;
  if (!state->node_key_valid) return NULL;

  serialized_buffer_t* sealed_payload =
      crabs_serialize_state_sealed(state, seal_key);
  if (sealed_payload == NULL) return NULL;

  serialized_buffer_t* result = _append_state_signature(sealed_payload, state);
  if (result == NULL) {
    serialized_buffer_destroy(sealed_payload);
    return NULL;
  }
  serialized_buffer_destroy(sealed_payload);
  return result;
}

// R7-03: verify the node-key signature over the blob BEFORE parsing, then
// delegate to the plain deserializer (which checks the SHA-256 corruption
// checksum). Returns NULL on any verification or parse failure.
state_t* crabs_deserialize_state_signed(const uint8_t* data, size_t len,
                                         const uint8_t node_public_key[33]) {
  if (data == NULL || node_public_key == NULL) return NULL;
  if (len <= CRABS_SIG_SIZE) return NULL;

  size_t payload_len = len - CRABS_SIG_SIZE;
  if (!crypto_ecdsa_verify(node_public_key, data, payload_len,
                           data + payload_len)) {
    return NULL;
  }
  return crabs_deserialize_state(data, payload_len);
}

// ============================================================
// Operation serialization
// ============================================================
serialized_buffer_t* crabs_serialize_operation(const operation_t* op) {
  if (op == NULL) return NULL;

  write_buf_t* buf = _write_buf_create(1024);

  // Operation format version
  _write_uint32_le(buf, 5);
  // v3: adds dedup_spec; v4: adds ordering_system + HLC;
  // v5: adds the parent-attestation section

  // type (length-prefixed string)
  _write_string16(buf, op->type);

  // uuid (16 bytes raw)
  _write_bytes(buf, op->uuid, CRABS_UUID_SIZE);

  // payload (length-prefixed bytes)
  _write_bytes32(buf, op->payload, op->payload_size);

  // resource_count
  _write_uint32_le(buf, op->resource_count);

  // resources (array of length-prefixed strings)
  for (uint32_t i = 0; i < op->resource_count; i++) {
    _write_string16(buf, op->resources[i]);
  }

  // required_state (array of uint8)
  _write_uint32_le(buf, op->resource_count);
  for (uint32_t i = 0; i < op->resource_count; i++) {
    _write_uint8(buf, (uint8_t)op->required_state[i]);
  }

  // next_state (array of uint8)
  _write_uint32_le(buf, op->resource_count);
  for (uint32_t i = 0; i < op->resource_count; i++) {
    _write_uint8(buf, (uint8_t)op->next_state[i]);
  }

  // lock_claim_count
  _write_uint32_le(buf, op->lock_claim_count);

  // lock_claims (for each: resource string + lock_token 32 bytes)
  for (uint32_t i = 0; i < op->lock_claim_count; i++) {
    _write_string16(buf, op->lock_claims[i].resource);
    _write_bytes(buf, op->lock_claims[i].lock_token, CRABS_LOCK_TOKEN_SIZE);
  }

  // policy (length-prefixed string)
  _write_string16(buf, op->policy);

  // signature (64 bytes raw)
  _write_bytes(buf, op->signature, CRABS_SIG_SIZE);

  // signer_id (length-prefixed string)
  _write_string16(buf, op->signer_id);

  // signer_key_version
  _write_uint64_le(buf, op->signer_key_version);

  // lamport_time
  _write_uint64_le(buf, op->lamport_time);

  // node_id (length-prefixed string)
  _write_string16(buf, op->node_id);

  // payload_format
  _write_uint8(buf, op->payload_format);

  // v1.3: sig_scheme
  _write_uint8(buf, (uint8_t)op->sig_scheme);

  // v1.3: key_id (length-prefixed string)
  _write_string16(buf, op->key_id);

  // v1.3: co_signer_count + co_signers
  _write_uint32_le(buf, op->co_signer_count);
  for (uint32_t i = 0; i < op->co_signer_count; i++) {
    _write_string16(buf, op->co_signers[i].signer_id);
    _write_string16(buf, op->co_signers[i].key_id);
    _write_uint8(buf, (uint8_t)op->co_signers[i].sig_scheme);
    _write_bytes32(buf, op->co_signers[i].signature, op->co_signers[i].signature_len);
  }

  // v1.4: dedup_spec
  _write_uint8(buf, (uint8_t)op->dedup.type);
  if (op->dedup.type != DEDUP_NONE) {
    _write_string16(buf, op->dedup.tracker_path);
    _write_string16(buf, op->dedup.flag_path);
    _write_string16(buf, op->dedup.condition);
    _write_string16(buf, op->dedup.rejection_message);
    // state_mutation
    _write_uint8(buf, (uint8_t)op->dedup.update.type);
    // R7-L-15: always write all 7 mutation fields, matching the canonical
    // signing form. The prior conditional dropped them for MUTATION_CUSTOM, so
    // an op carrying such fields failed verification after gossip.
    _write_string16(buf, op->dedup.update.set_path);
    _write_string16(buf, op->dedup.update.element_value);
    _write_string16(buf, op->dedup.update.flag_path);
    _write_string16(buf, op->dedup.update.counter_path);
    _write_int64_le(buf, op->dedup.update.delta);
    _write_string16(buf, op->dedup.update.target_path);
    _write_string16(buf, op->dedup.update.value);
  }

  // v4: ordering_system + HLC fields (v1.6 Amd6 §6.2). R7-15: the wire format
  // must cover the same field set as the canonical signing form, otherwise an
  // HLC-ordered op cannot verify after gossip (the deserialized op re-serializes
  // to different bytes).
  _write_uint8(buf, (uint8_t)op->ordering_system);
  if (op->ordering_system == CRABS_ORDERING_HLC) {
    _write_uint64_le(buf, op->hlc.physical_seconds);
    _write_uint64_le(buf, op->hlc.physical_nanos);
    _write_uint64_le(buf, op->hlc.logical_counter);
    _write_string16(buf, op->hlc.node_id);
  }

  // v5 (v1.7 §attestation bridge): parent attestations carried by the op.
  // Each entry reuses the attestation wire format verbatim (u32le total
  // length + canonical body + signature, lineage.h), prefixed here by its
  // own u32le length so the transport can never drift from the format
  // attestation_verify consumes. Attestations are NOT part of the canonical
  // signing form: each carries the parent's signature over its own body.
  // Symmetric with the reader's count cap: an over-cap op would serialize
  // into wire the deserializer fail-closes on, so refuse it here instead.
  if (op->attestation_count > CRABS_MAX_OP_ATTESTATIONS) {
    free(buf->data);
    free(buf);
    return NULL;
  }
  _write_uint32_le(buf, op->attestation_count);
  for (uint32_t attestation_index = 0;
       attestation_index < op->attestation_count; attestation_index++) {
    uint8_t attestation_wire[CRABS_ATTESTATION_WIRE_MAX];
    size_t attestation_wire_len = attestation_serialize(
        &op->attestations[attestation_index],
        attestation_wire, sizeof(attestation_wire));
    if (attestation_wire_len == 0) {
      // A structurally broken attestation (unterminated field) cannot be
      // faithfully transported — refuse the op instead of truncating it.
      free(buf->data);
      free(buf);
      return NULL;
    }
    _write_uint32_le(buf, (uint32_t)attestation_wire_len);
    _write_bytes(buf, attestation_wire, attestation_wire_len);
  }

  // Create output
  serialized_buffer_t* result = serialized_buffer_create(buf->offset);
  memcpy(result->data, buf->data, buf->offset);
  result->len = buf->offset;

  free(buf->data);
  free(buf);
  return result;
}

operation_t* crabs_deserialize_operation(const uint8_t* data, size_t len) {
  if (data == NULL || len == 0) return NULL;

  read_buf_t buf;
  buf.data = data;
  buf.len = len;
  buf.offset = 0;

  operation_t* op = operation_create("");
  if (op == NULL) return NULL;

  // Operation format version
  uint32_t op_version;
  if (!_read_uint32_le(&buf, &op_version)) goto fail;
  if (op_version < 1 || op_version > 5) goto fail;

  // type
  if (!_read_string16(&buf, op->type, CRABS_MAX_OP_NAME)) goto fail;

  // uuid
  if (!_read_bytes(&buf, op->uuid, CRABS_UUID_SIZE)) goto fail;

  // payload
  uint8_t* payload = NULL;
  uint32_t payload_size = 0;
  if (!_read_bytes32(&buf, &payload, &payload_size)) goto fail;
  op->payload = payload;
  op->payload_size = payload_size;

  // resource_count
  uint32_t resource_count;
  if (!_read_uint32_le(&buf, &resource_count)) goto fail;
  if (resource_count > CRABS_MAX_RESOURCES) goto fail;
  op->resource_count = resource_count;

  // resources
  if (resource_count > 0) {
    op->resources = get_clear_memory(resource_count * CRABS_MAX_USER_ID);
    for (uint32_t i = 0; i < resource_count; i++) {
      if (!_read_string16(&buf, op->resources[i], CRABS_MAX_USER_ID)) goto fail;
    }
  }

  // required_state
  uint32_t rs_count;
  if (!_read_uint32_le(&buf, &rs_count)) goto fail;
  if (rs_count > CRABS_MAX_RESOURCES) goto fail;
  // The executor indexes op->required_state[i] for i < resource_count, so the
  // counts must match to avoid an out-of-bounds read on a malformed op.
  if (rs_count != resource_count) goto fail;
  if (rs_count > 0) {
    op->required_state = get_clear_memory(rs_count * sizeof(protocol_state_e));
    for (uint32_t i = 0; i < rs_count; i++) {
      uint8_t ps;
      if (!_read_uint8(&buf, &ps)) goto fail;
      op->required_state[i] = (protocol_state_e)ps;
    }
  }

  // next_state
  uint32_t ns_count;
  if (!_read_uint32_le(&buf, &ns_count)) goto fail;
  if (ns_count > CRABS_MAX_RESOURCES) goto fail;
  if (ns_count != resource_count) goto fail;
  if (ns_count > 0) {
    op->next_state = get_clear_memory(ns_count * sizeof(protocol_state_e));
    for (uint32_t i = 0; i < ns_count; i++) {
      uint8_t ps;
      if (!_read_uint8(&buf, &ps)) goto fail;
      op->next_state[i] = (protocol_state_e)ps;
    }
  }

  // lock_claim_count
  uint32_t lc_count;
  if (!_read_uint32_le(&buf, &lc_count)) goto fail;
  if (lc_count > CRABS_MAX_RESOURCES) goto fail;
  op->lock_claim_count = lc_count;

  // lock_claims
  if (lc_count > 0) {
    op->lock_claims = get_clear_memory(lc_count * sizeof(lock_claim_t));
    for (uint32_t i = 0; i < lc_count; i++) {
      if (!_read_string16(&buf, op->lock_claims[i].resource, CRABS_MAX_USER_ID)) goto fail;
      if (!_read_bytes(&buf, op->lock_claims[i].lock_token, CRABS_LOCK_TOKEN_SIZE)) goto fail;
    }
  }

  // policy
  if (!_read_string16(&buf, op->policy, CRABS_MAX_POLICY_EXPR)) goto fail;

  // signature
  if (!_read_bytes(&buf, op->signature, CRABS_SIG_SIZE)) goto fail;

  // signer_id
  if (!_read_string16(&buf, op->signer_id, CRABS_MAX_USER_ID)) goto fail;

  // signer_key_version
  if (!_read_uint64_le(&buf, &op->signer_key_version)) goto fail;

  // lamport_time
  if (!_read_uint64_le(&buf, &op->lamport_time)) goto fail;

  // node_id
  if (!_read_string16(&buf, op->node_id, CRABS_MAX_USER_ID)) goto fail;

  // payload_format
  uint8_t pf;
  if (!_read_uint8(&buf, &pf)) goto fail;
  op->payload_format = pf;

  // v1.3: sig_scheme
  uint8_t scheme;
  if (!_read_uint8(&buf, &scheme)) goto fail;
  op->sig_scheme = (signature_scheme_e)scheme;

  // v1.3: key_id (length-prefixed string)
  if (!_read_string16(&buf, op->key_id, CRABS_MAX_KEY_ID)) goto fail;

  // v1.3: co_signer_count + co_signers
  uint32_t cs_count;
  if (!_read_uint32_le(&buf, &cs_count)) goto fail;
  op->co_signer_count = cs_count;
  if (cs_count > 0) {
    if (cs_count > CRABS_MAX_CO_SIGNERS) goto fail;
    op->co_signers = get_clear_memory(cs_count * sizeof(co_signature_t));
    for (uint32_t i = 0; i < cs_count; i++) {
      if (!_read_string16(&buf, op->co_signers[i].signer_id, CRABS_MAX_USER_ID)) goto fail;
      if (!_read_string16(&buf, op->co_signers[i].key_id, CRABS_MAX_KEY_ID)) goto fail;
      uint8_t cs_scheme;
      if (!_read_uint8(&buf, &cs_scheme)) goto fail;
      op->co_signers[i].sig_scheme = (signature_scheme_e)cs_scheme;
      uint8_t* cs_sig = NULL;
      uint32_t cs_sig_len = 0;
      if (!_read_bytes32(&buf, &cs_sig, &cs_sig_len)) goto fail;
      if (cs_sig != NULL && cs_sig_len <= CRABS_SIG_SIZE) {
        memcpy(op->co_signers[i].signature, cs_sig, cs_sig_len);
        op->co_signers[i].signature_len = cs_sig_len;
        free(cs_sig);
      } else if (cs_sig != NULL) {
        free(cs_sig);
        goto fail;
      }
    }
  }

  // v3: dedup_spec (only for version >= 3)
  if (op_version >= 3) {
    uint8_t dedup_type;
    if (!_read_uint8(&buf, &dedup_type)) goto fail;
    op->dedup.type = (dedup_type_e)dedup_type;

    if (op->dedup.type != DEDUP_NONE) {
      if (!_read_string16(&buf, op->dedup.tracker_path, CRABS_MAX_DEDUP_PATH)) goto fail;
      if (!_read_string16(&buf, op->dedup.flag_path, CRABS_MAX_DEDUP_PATH)) goto fail;
      if (!_read_string16(&buf, op->dedup.condition, CRABS_MAX_POLICY_EXPR)) goto fail;
      if (!_read_string16(&buf, op->dedup.rejection_message, CRABS_MAX_DEDUP_MESSAGE)) goto fail;

      // state_mutation
      uint8_t mut_type;
      if (!_read_uint8(&buf, &mut_type)) goto fail;
      op->dedup.update.type = (mutation_type_e)mut_type;

      // R7-L-15: always read all 7 mutation fields, matching the canonical
      // signing form (the writer now always emits them).
      if (!_read_string16(&buf, op->dedup.update.set_path, CRABS_MAX_DEDUP_PATH)) goto fail;
      if (!_read_string16(&buf, op->dedup.update.element_value, CRABS_MAX_USER_ID)) goto fail;
      if (!_read_string16(&buf, op->dedup.update.flag_path, CRABS_MAX_DEDUP_PATH)) goto fail;
      if (!_read_string16(&buf, op->dedup.update.counter_path, CRABS_MAX_DEDUP_PATH)) goto fail;
      if (!_read_int64_le(&buf, &op->dedup.update.delta)) goto fail;
      if (!_read_string16(&buf, op->dedup.update.target_path, CRABS_MAX_DEDUP_PATH)) goto fail;
      if (!_read_string16(&buf, op->dedup.update.value, CRABS_MAX_DEDUP_PATH)) goto fail;
    }
  }

  // v4: ordering_system + HLC fields (v1.6 Amd6 §6.2). Older versions default
  // to LAMPORT (zero-init) with no HLC fields.
  if (op_version >= 4) {
    uint8_t ordering;
    if (!_read_uint8(&buf, &ordering)) goto fail;
    op->ordering_system = (crabs_ordering_system_e)ordering;
    if (op->ordering_system == CRABS_ORDERING_HLC) {
      if (!_read_uint64_le(&buf, &op->hlc.physical_seconds)) goto fail;
      if (!_read_uint64_le(&buf, &op->hlc.physical_nanos)) goto fail;
      // Audit A-4: fail closed on nanos >= 1e9, matching
      // crabs_hlc_deserialize. A nanos overflow on the wire would freeze
      // crabs_hlc_next (the normalize carry never terminates in one step and
      // the comparisons misorder) if the received HLC were ever adopted.
      if (op->hlc.physical_nanos >= 1000000000ULL) goto fail;
      if (!_read_uint64_le(&buf, &op->hlc.logical_counter)) goto fail;
      if (!_read_string16(&buf, op->hlc.node_id, CRABS_HLC_NODE_ID_SIZE)) goto fail;
    }
  }

  // v5 (v1.7 §attestation bridge): parent attestations. Older versions
  // default to none (zero-init).
  if (op_version >= 5) {
    uint32_t attestation_count;
    if (!_read_uint32_le(&buf, &attestation_count)) goto fail;
    if (attestation_count > CRABS_MAX_OP_ATTESTATIONS) goto fail;
    op->attestation_count = attestation_count;
    if (attestation_count > 0) {
      op->attestations = get_clear_memory(attestation_count * sizeof(attestation_t));
      for (uint32_t attestation_index = 0;
           attestation_index < attestation_count; attestation_index++) {
        uint32_t attestation_wire_len;
        if (!_read_uint32_le(&buf, &attestation_wire_len)) goto fail;
        if (attestation_wire_len > CRABS_ATTESTATION_WIRE_MAX ||
            buf.offset + attestation_wire_len > buf.len) {
          goto fail;
        }
        attestation_t* parsed = attestation_deserialize(
            buf.data + buf.offset, attestation_wire_len);
        if (parsed == NULL) goto fail;
        op->attestations[attestation_index] = *parsed;
        free(parsed);
        buf.offset += attestation_wire_len;
      }
    }
  }

  // R7-L-6: require full consumption of the buffer. Trailing bytes would let
  // arbitrary data be appended to a signed op without invalidating it.
  if (buf.offset != buf.len) goto fail;

  return op;

fail:
  operation_destroy(op);
  return NULL;
}

// ============================================================
// ============================================================
// Public OT Serialization Functions
// ============================================================

serialized_buffer_t* crabs_serialize_ot_op(const crabs_ot_operation_t* op) {
  if (op == NULL) return NULL;
  write_buf_t* buf = _write_buf_create(256);
  _serialize_ot_op(buf, op);

  serialized_buffer_t* result = serialized_buffer_create(buf->offset);
  memcpy(result->data, buf->data, buf->offset);
  result->len = buf->offset;
  free(buf->data);
  free(buf);
  return result;
}

crabs_ot_operation_t* crabs_deserialize_ot_op(const uint8_t* data, size_t len) {
  if (data == NULL || len == 0) return NULL;
  read_buf_t buf;
  buf.data = data;
  buf.len = len;
  buf.offset = 0;

  crabs_ot_operation_t* op = crabs_ot_operation_create();
  if (op == NULL) return NULL;
  if (!_deserialize_ot_op(&buf, op)) {
    crabs_ot_operation_destroy(op);
    return NULL;
  }
  return op;
}

serialized_buffer_t* crabs_serialize_ot_op_log(const crabs_ot_operation_t* ops, uint32_t count) {
  if (ops == NULL || count == 0) return NULL;
  write_buf_t* buf = _write_buf_create(64 + count * 256);

  _write_uint32_le(buf, count);
  for (uint32_t i = 0; i < count; i++) {
    _serialize_ot_op(buf, &ops[i]);
  }

  serialized_buffer_t* result = serialized_buffer_create(buf->offset);
  memcpy(result->data, buf->data, buf->offset);
  result->len = buf->offset;
  free(buf->data);
  free(buf);
  return result;
}

uint32_t crabs_deserialize_ot_op_log(const uint8_t* data, size_t len,
                                      crabs_ot_operation_t** ops_out) {
  if (data == NULL || len < 4 || ops_out == NULL) return 0;

  read_buf_t buf;
  buf.data = data;
  buf.len = len;
  buf.offset = 0;

  uint32_t count;
  if (!_read_uint32_le(&buf, &count)) return 0;
  if (count == 0 || count > 1024) return 0;

  crabs_ot_operation_t* ops = get_clear_memory(sizeof(crabs_ot_operation_t) * count);
  if (ops == NULL) return 0;

  for (uint32_t i = 0; i < count; i++) {
    crabs_ot_operation_init(&ops[i]);
    if (!_deserialize_ot_op(&buf, &ops[i])) {
      // Free already-parsed ops
      for (uint32_t j = 0; j < i; j++) {
        if (ops[j].payload != NULL) free(ops[j].payload);
      }
      free(ops);
      *ops_out = NULL;
      return 0;
    }
  }

  *ops_out = ops;
  return count;
}

serialized_buffer_t* crabs_serialize_bst(const crabs_bst_node_t* root) {
  write_buf_t* buf = _write_buf_create(128);

  uint32_t node_count = _count_bst_nodes(root);
  _write_uint32_le(buf, node_count);
  _serialize_bst_recursive(buf, root);

  serialized_buffer_t* result = serialized_buffer_create(buf->offset);
  memcpy(result->data, buf->data, buf->offset);
  result->len = buf->offset;
  free(buf->data);
  free(buf);
  return result;
}

crabs_bst_node_t* crabs_deserialize_bst(const uint8_t* data, size_t len) {
  if (data == NULL || len < 4) return NULL;

  read_buf_t buf;
  buf.data = data;
  buf.len = len;
  buf.offset = 0;

  uint32_t node_count;
  if (!_read_uint32_le(&buf, &node_count)) return NULL;
  if (node_count == 0) return NULL;

  return _deserialize_bst_recursive(&buf, 0);
}

serialized_buffer_t* crabs_serialize_ot_data(const crabs_ot_data_item_t* item) {
  if (item == NULL) return NULL;

  write_buf_t* buf = _write_buf_create(512);

  // ot_type_id
  _write_uint32_le(buf, item->ot_type_id);

  // op_log
  _write_uint32_le(buf, item->op_log_count);
  for (uint32_t i = 0; i < item->op_log_count; i++) {
    _serialize_ot_op(buf, &item->op_log[i]);
  }

  // position_map (BST)
  uint32_t bst_count = _count_bst_nodes(item->position_map);
  _write_uint32_le(buf, bst_count);
  _serialize_bst_recursive(buf, item->position_map);

  // priority_counters
  _write_uint32_le(buf, item->priority_counter_count);
  for (uint32_t i = 0; i < item->priority_counter_count; i++) {
    _write_uint64_le(buf, item->priority_counters[i]);
  }

  serialized_buffer_t* result = serialized_buffer_create(buf->offset);
  memcpy(result->data, buf->data, buf->offset);
  result->len = buf->offset;
  free(buf->data);
  free(buf);
  return result;
}

crabs_ot_data_item_t* crabs_deserialize_ot_data(const uint8_t* data, size_t len,
                                                  uint32_t ot_type_id) {
  if (data == NULL || len == 0) return NULL;

  read_buf_t buf;
  buf.data = data;
  buf.len = len;
  buf.offset = 0;

  crabs_ot_data_item_t* item = crabs_ot_data_item_create(ot_type_id);
  if (item == NULL) return NULL;

  // ot_type_id
  uint32_t type_id;
  if (!_read_uint32_le(&buf, &type_id)) goto fail;

  // op_log
  uint32_t op_count;
  if (!_read_uint32_le(&buf, &op_count)) goto fail;
  if (op_count > CRABS_OT_OP_LOG_MAX) goto fail;
  // Audit H-G: bound the allocation to remaining buffer. Each op is at least
  // a few bytes on the wire; if op_count exceeds the remaining buffer, the
  // requested allocation (op_count * ~1.4KB) would be far larger than the
  // input and the aborting allocator turns a few-byte packet into a DoS.
  if (op_count > (buf.len - buf.offset)) goto fail;
  if (op_count > 0) {
    free(item->op_log);
    item->op_log = get_clear_memory(sizeof(crabs_ot_operation_t) * op_count);
    if (item->op_log == NULL) goto fail;
    item->op_log_capacity = op_count;
    for (uint32_t i = 0; i < op_count; i++) {
      crabs_ot_operation_init(&item->op_log[i]);
      if (!_deserialize_ot_op(&buf, &item->op_log[i])) {
        item->op_log_count = i; // Free payloads of already-parsed ops
        goto fail;
      }
    }
    item->op_log_count = op_count;
  }

  // position_map (BST)
  uint32_t bst_count;
  if (!_read_uint32_le(&buf, &bst_count)) goto fail;
  if (bst_count > 0) {
    item->position_map = _deserialize_bst_recursive(&buf, 0);
    if (item->position_map == NULL) goto fail;
  }

  // priority_counters
  uint32_t pc_count;
  if (!_read_uint32_le(&buf, &pc_count)) goto fail;
  // Audit H-G: bound the allocation to remaining buffer. 4 wire bytes could
  // request ~34 GiB; the aborting allocator turns a tiny packet into a DoS.
  if (pc_count > (buf.len - buf.offset) / sizeof(uint64_t)) goto fail;
  if (pc_count > 0) {
    item->priority_counters = get_clear_memory(sizeof(uint64_t) * pc_count);
    if (item->priority_counters == NULL) goto fail;
    item->priority_counter_count = pc_count;
    for (uint32_t i = 0; i < pc_count; i++) {
      if (!_read_uint64_le(&buf, &item->priority_counters[i])) goto fail;
    }
  }

  // Initialize transform matrix for this type
  crabs_transform_matrix_init(item);

  return item;

fail:
  crabs_ot_data_item_destroy(item);
  return NULL;
}

// ============================================================
// Canonical encoding for signing (§7.5)
// ============================================================
serialized_buffer_t* crabs_serialize_for_signing(const operation_t* op) {
  if (op == NULL) return NULL;

  write_buf_t* buf = _write_buf_create(1024);

  // 0. Domain-separation tag + canonical-form version. This MUST change
  // whenever the signed field set changes, so that signatures from one
  // version do not verify against another.
  _write_uint8(buf, 0x43); // 'C'
  _write_uint8(buf, 0x52); // 'R'
  _write_uint8(buf, 0x41); // 'A'
  _write_uint8(buf, 0x42); // 'B'
  _write_uint8(buf, 0x02); // signing-format version 2 (full dedup + payload_format + domain tag)

  // 1. op.type (length-prefixed string)
  _write_string16(buf, op->type);

  // 2. op.uuid (16 bytes raw)
  _write_bytes(buf, op->uuid, CRABS_UUID_SIZE);

  // 3. op.payload_format (uint8) — included so the format byte cannot be
  // flipped after signing without invalidating the signature.
  _write_uint8(buf, op->payload_format);

  // 4. op.payload (length-prefixed bytes)
  _write_bytes32(buf, op->payload, op->payload_size);

  // 5. op.resources (length-prefixed array of length-prefixed strings)
  _write_uint32_le(buf, op->resource_count);
  for (uint32_t i = 0; i < op->resource_count; i++) {
    _write_string16(buf, op->resources[i]);
  }

  // 6. op.required_state (array of uint8)
  _write_uint32_le(buf, op->resource_count);
  for (uint32_t i = 0; i < op->resource_count; i++) {
    _write_uint8(buf, (uint8_t)op->required_state[i]);
  }

  // 7. op.next_state (array of uint8)
  _write_uint32_le(buf, op->resource_count);
  for (uint32_t i = 0; i < op->resource_count; i++) {
    _write_uint8(buf, (uint8_t)op->next_state[i]);
  }

  // 8. op.lock_claims (for each: resource length-prefixed string, then 32 bytes lock_token)
  _write_uint32_le(buf, op->lock_claim_count);
  for (uint32_t i = 0; i < op->lock_claim_count; i++) {
    _write_string16(buf, op->lock_claims[i].resource);
    _write_bytes(buf, op->lock_claims[i].lock_token, CRABS_LOCK_TOKEN_SIZE);
  }

  // 9. op.policy (length-prefixed string)
  _write_string16(buf, op->policy);

  // 10. op.signer_id (length-prefixed string)
  _write_string16(buf, op->signer_id);

  // 11. op.signer_key_version (uint64)
  _write_uint64_le(buf, op->signer_key_version);

  // 12. op.lamport_time (uint64)
  _write_uint64_le(buf, op->lamport_time);

  // 13. op.node_id (length-prefixed string)
  _write_string16(buf, op->node_id);

  // 14. op.sig_scheme (uint8)
  _write_uint8(buf, (uint8_t)op->sig_scheme);

  // 15. op.key_id (length-prefixed string)
  _write_string16(buf, op->key_id);

  // 16. op.dedup (v1.4 — full spec included in canonical form per §7.5).
  // The state_mutation and rejection_message MUST be signed, otherwise a
  // relay could tamper with the mutation (e.g., change a counter delta)
  // without invalidating the signature.
  _write_uint8(buf, (uint8_t)op->dedup.type);
  _write_string16(buf, op->dedup.tracker_path);
  _write_string16(buf, op->dedup.flag_path);
  _write_string16(buf, op->dedup.condition);
  _write_string16(buf, op->dedup.rejection_message);
  // state_mutation
  _write_uint8(buf, (uint8_t)op->dedup.update.type);
  _write_string16(buf, op->dedup.update.set_path);
  _write_string16(buf, op->dedup.update.element_value);
  _write_string16(buf, op->dedup.update.flag_path);
  _write_string16(buf, op->dedup.update.counter_path);
  _write_int64_le(buf, op->dedup.update.delta);
  _write_string16(buf, op->dedup.update.target_path);
  _write_string16(buf, op->dedup.update.value);

  // 17. op.ordering_system (v1.6 Amd6 §6.2: uint8 discriminator)
  _write_uint8(buf, (uint8_t)op->ordering_system);

  // 18. Ordering fields (v1.6 Amd6 §6.2: conditional on ordering_system)
  if (op->ordering_system == CRABS_ORDERING_HLC) {
    // HLC: physical_seconds, physical_nanos, logical_counter, node_id
    _write_uint64_le(buf, op->hlc.physical_seconds);
    _write_uint64_le(buf, op->hlc.physical_nanos);
    _write_uint64_le(buf, op->hlc.logical_counter);
    _write_string16(buf, op->hlc.node_id);
  }
  // Lamport: lamport_time is already included at position 12

  // Create output
  serialized_buffer_t* result = serialized_buffer_create(buf->offset);
  memcpy(result->data, buf->data, buf->offset);
  result->len = buf->offset;

  free(buf->data);
  free(buf);
  return result;
}
