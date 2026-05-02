//
// Created by victor on 5/1/25.
//
// OT_DOCUMENT Data Type (v1.5 §6)
// Rich text document with spans and styles.
// Type ID: 0x11
//

#ifndef CRABS_OT_DOCUMENT_H
#define CRABS_OT_DOCUMENT_H

#include <stdint.h>
#include <stdbool.h>
#include "ot_ordered_set.h"

// ============================================================
// Type ID
// ============================================================

#define DATA_TYPE_OT_DOCUMENT 0x11
#define CRABS_OT_DOCUMENT     0x11

// ============================================================
// Document Operation Types (extends crabs_ot_op_type_e)
// ============================================================

#define CRABS_OT_OP_INSERT_TEXT  0x10
#define CRABS_OT_OP_DELETE_RANGE 0x11
#define CRABS_OT_OP_STYLE        0x12
#define CRABS_OT_OP_MERGE_SPANS  0x13
#define CRABS_OT_OP_SPLIT_SPAN   0x14

// ============================================================
// Style (v1.5 §6.1)
// ============================================================

#define CRABS_STYLE_NAME_MAX 32
#define CRABS_STYLE_VALUE_MAX 64

typedef struct {
  char name[CRABS_STYLE_NAME_MAX];
  char value[CRABS_STYLE_VALUE_MAX];
} crabs_style_t;

// ============================================================
// Span (v1.5 §6.1)
// ============================================================

#define CRABS_SPAN_MAX_STYLES 8

typedef struct crabs_span {
  crabs_ot_op_id_t  id;
  uint8_t*          text;
  uint32_t          text_size;
  crabs_style_t     styles[CRABS_SPAN_MAX_STYLES];
  uint32_t          style_count;
  bool              deleted;
  struct crabs_span* next;
  struct crabs_span* prev;
} crabs_span_t;

// ============================================================
// OT Document (v1.5 §6)
// ============================================================

typedef struct {
  crabs_span_t*       head;
  crabs_span_t*       tail;
  uint32_t            span_count;
  uint32_t            visible_char_count;
  crabs_ot_data_item_t* ot_data;
} crabs_ot_document_t;

// ============================================================
// Span Lifecycle
// ============================================================

crabs_span_t* crabs_span_create(const crabs_ot_op_id_t* id,
                                  const uint8_t* text, uint32_t text_size);
void crabs_span_destroy(crabs_span_t* span);

// ============================================================
// Document Lifecycle
// ============================================================

crabs_ot_document_t* crabs_ot_document_create(void);
void crabs_ot_document_destroy(crabs_ot_document_t* doc);
uint32_t crabs_ot_document_span_count(const crabs_ot_document_t* doc);
uint32_t crabs_ot_document_char_count(const crabs_ot_document_t* doc);

// ============================================================
// Document Operations (v1.5 §6.2)
// ============================================================

crabs_span_t* crabs_ot_document_insert_text(
  crabs_ot_document_t* doc, uint64_t pos,
  const uint8_t* text, uint32_t text_size,
  const crabs_ot_op_id_t* id);

crabs_span_t* crabs_ot_document_delete_range(
  crabs_ot_document_t* doc, uint64_t pos, uint64_t len);

crabs_span_t* crabs_ot_document_apply_style(
  crabs_ot_document_t* doc, uint64_t pos, uint64_t len,
  const crabs_style_t* style);

crabs_span_t* crabs_ot_document_merge_spans(
  crabs_ot_document_t* doc, uint64_t pos1, uint64_t pos2);

crabs_span_t* crabs_ot_document_split_span(
  crabs_ot_document_t* doc, uint64_t pos);

// ============================================================
// Document Access
// ============================================================

crabs_span_t* crabs_ot_document_head(const crabs_ot_document_t* doc);
crabs_span_t* crabs_ot_document_tail(const crabs_ot_document_t* doc);

#endif // CRABS_OT_DOCUMENT_H