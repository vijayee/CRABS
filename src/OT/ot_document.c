//
// Created by victor on 5/1/25.
//
// OT_DOCUMENT Data Type (v1.5 §6)
// Rich text document with spans and styles.
// Type ID: 0x11
//

#include "ot_document.h"
#include "ot_transform.h"
#include "../Util/allocator.h"
#include <stdlib.h>
#include <string.h>

// ============================================================
// Span Lifecycle
// ============================================================

crabs_span_t* crabs_span_create(const crabs_ot_op_id_t* id,
                                  const uint8_t* text, uint32_t text_size) {
  crabs_span_t* span = get_clear_memory(sizeof(crabs_span_t));
  if (id != NULL) {
    span->id = *id;
  }
  if (text != NULL && text_size > 0) {
    span->text = get_memory(text_size);
    memcpy(span->text, text, text_size);
    span->text_size = text_size;
  }
  return span;
}

void crabs_span_destroy(crabs_span_t* span) {
  if (span == NULL) return;
  if (span->text != NULL) {
    free(span->text);
  }
  free(span);
}

// ============================================================
// Document Lifecycle
// ============================================================

crabs_ot_document_t* crabs_ot_document_create(void) {
  crabs_ot_document_t* doc = get_clear_memory(sizeof(crabs_ot_document_t));
  doc->ot_data = crabs_ot_data_item_create(CRABS_OT_DOCUMENT);
  crabs_transform_matrix_init(doc->ot_data);
  return doc;
}

void crabs_ot_document_destroy(crabs_ot_document_t* doc) {
  if (doc == NULL) return;
  crabs_span_t* span = doc->head;
  while (span != NULL) {
    crabs_span_t* next = span->next;
    crabs_span_destroy(span);
    span = next;
  }
  crabs_ot_data_item_destroy(doc->ot_data);
  free(doc);
}

uint32_t crabs_ot_document_span_count(const crabs_ot_document_t* doc) {
  return doc == NULL ? 0 : doc->span_count;
}

uint32_t crabs_ot_document_char_count(const crabs_ot_document_t* doc) {
  return doc == NULL ? 0 : doc->visible_char_count;
}

// ============================================================
// Helpers
// ============================================================

// Get span at visible position (skip deleted spans)
static crabs_span_t* _get_at_visible(const crabs_ot_document_t* doc, uint64_t visible_pos) {
  if (doc == NULL) return NULL;
  uint64_t idx = 0;
  for (crabs_span_t* s = doc->head; s != NULL; s = s->next) {
    if (s->deleted) continue;
    if (idx == visible_pos) return s;
    idx++;
  }
  return NULL;
}

// Count visible characters up to (but not including) a span
static uint64_t _count_chars_before(const crabs_ot_document_t* doc, const crabs_span_t* target) {
  uint64_t count = 0;
  for (crabs_span_t* s = doc->head; s != NULL && s != target; s = s->next) {
    if (!s->deleted) {
      count += s->text_size;
    }
  }
  return count;
}

// Find span containing character position, set offset within that span
static crabs_span_t* _find_span_at_char(const crabs_ot_document_t* doc,
                                          uint64_t char_pos, uint32_t* offset) {
  uint64_t remaining = char_pos;
  for (crabs_span_t* s = doc->head; s != NULL; s = s->next) {
    if (s->deleted) continue;
    if (remaining < s->text_size) {
      if (offset) *offset = (uint32_t)remaining;
      return s;
    }
    remaining -= s->text_size;
  }
  // Position past end of document
  if (offset) *offset = 0;
  return NULL;
}

// Insert span after a specific span (NULL = insert at head)
static void _insert_after(crabs_ot_document_t* doc,
                           crabs_span_t* after, crabs_span_t* span) {
  if (after == NULL) {
    span->next = doc->head;
    if (doc->head != NULL) doc->head->prev = span;
    doc->head = span;
    if (doc->tail == NULL) doc->tail = span;
  } else {
    span->prev = after;
    span->next = after->next;
    if (after->next != NULL) after->next->prev = span;
    after->next = span;
    if (after == doc->tail) doc->tail = span;
  }
  doc->span_count++;
  if (!span->deleted) doc->visible_char_count += span->text_size;
}

// ============================================================
// Document Operations (v1.5 §6.2)
// ============================================================

crabs_span_t* crabs_ot_document_insert_text(
    crabs_ot_document_t* doc, uint64_t pos,
    const uint8_t* text, uint32_t text_size,
    const crabs_ot_op_id_t* id) {
  if (doc == NULL || text == NULL || text_size == 0) return NULL;

  crabs_span_t* span = crabs_span_create(id, text, text_size);
  if (span == NULL) return NULL;

  // Use position map for coordinate translation if available
  if (doc->ot_data != NULL && doc->ot_data->position_map != NULL) {
    uint64_t internal_pos = crabs_xi_inv(doc->ot_data->position_map, pos);
    // Insert at internal position
    if (internal_pos == 0 || doc->head == NULL) {
      _insert_after(doc, NULL, span);
    } else {
      // Walk to span at internal position - 1
      uint64_t idx = 0;
      crabs_span_t* at = NULL;
      for (crabs_span_t* s = doc->head; s != NULL; s = s->next) {
        if (idx == internal_pos - 1) { at = s; break; }
        idx++;
      }
      _insert_after(doc, at, span);
    }
    doc->ot_data->position_map = crabs_xi_one(doc->ot_data->position_map, internal_pos);
  } else {
    // No position map: insert at visible position
    if (pos == 0 || doc->head == NULL) {
      _insert_after(doc, NULL, span);
    } else {
      // Find span that contains character position pos-1
      uint32_t offset = 0;
      crabs_span_t* at = _find_span_at_char(doc, pos, &offset);
      if (at != NULL) {
        // If insertion point is mid-span, split the span first
        if (offset > 0 && offset < at->text_size) {
          // Split: create new span for text after offset
          crabs_span_t* right = crabs_span_create(&at->id,
            at->text + offset, at->text_size - offset);
          right->style_count = at->style_count;
          memcpy(right->styles, at->styles, sizeof(crabs_style_t) * at->style_count);
          // Truncate left span
          uint8_t* new_text = get_memory(offset);
          memcpy(new_text, at->text, offset);
          free(at->text);
          at->text = new_text;
          at->text_size = offset;
          // Insert right after left
          right->next = at->next;
          right->prev = at;
          if (at->next) at->next->prev = right;
          at->next = right;
          if (at == doc->tail) doc->tail = right;
          doc->span_count++;
          // Now insert new text after the left part
          _insert_after(doc, at, span);
        } else {
          // Insert at end of found span
          _insert_after(doc, at, span);
        }
      } else {
        _insert_after(doc, doc->tail, span);
      }
    }
  }

  return span;
}

crabs_span_t* crabs_ot_document_delete_range(
    crabs_ot_document_t* doc, uint64_t pos, uint64_t len) {
  if (doc == NULL || len == 0) return NULL;

  uint64_t remaining = len;
  uint64_t char_pos = pos;
  crabs_span_t* first_deleted = NULL;

  while (remaining > 0) {
    uint32_t offset = 0;
    crabs_span_t* span = _find_span_at_char(doc, char_pos, &offset);
    if (span == NULL) break;

    uint32_t chars_in_span = span->text_size - offset;
    uint32_t to_delete = (remaining >= chars_in_span) ? chars_in_span : (uint32_t)remaining;

    if (offset == 0 && to_delete >= span->text_size) {
      // Delete entire span
      if (!span->deleted) {
        doc->visible_char_count -= span->text_size;
        span->deleted = true;
      }
      remaining -= span->text_size;
      if (first_deleted == NULL) first_deleted = span;
    } else {
      // Partial delete — need to split the span
      uint32_t keep_before = offset;
      uint32_t keep_after = span->text_size - offset - to_delete;

      if (keep_after > 0) {
        // Create right portion
        crabs_span_t* right = crabs_span_create(&span->id,
          span->text + offset + to_delete, keep_after);
        right->style_count = span->style_count;
        memcpy(right->styles, span->styles, sizeof(crabs_style_t) * span->style_count);
        right->next = span->next;
        right->prev = span;
        if (span->next) span->next->prev = right;
        span->next = right;
        if (span == doc->tail) doc->tail = right;
        doc->span_count++;
      }

      if (keep_before > 0) {
        // Truncate to keep left portion
        uint8_t* new_text = get_memory(keep_before);
        memcpy(new_text, span->text, keep_before);
        free(span->text);
        span->text = new_text;
        span->text_size = keep_before;
        doc->visible_char_count -= to_delete;
        if (first_deleted == NULL) first_deleted = span;
      } else {
        // Delete from start of span — keep_after portion stays
        if (keep_after > 0) {
          // Trim from start: keep only the right portion
          uint8_t* new_text = get_memory(keep_after);
          memcpy(new_text, span->text + offset + to_delete, keep_after);
          free(span->text);
          span->text = new_text;
          span->text_size = keep_after;
          doc->visible_char_count -= to_delete;
        } else {
          // Delete entire span (offset was 0, covers whole span)
          if (!span->deleted) {
            doc->visible_char_count -= span->text_size;
            span->deleted = true;
          }
        }
        if (first_deleted == NULL) first_deleted = span;
      }
      remaining -= to_delete;
    }
    // Keep deleting from the original `pos`: after each deletion the chars
    // that followed shift left into position `pos`, so the next char to
    // delete is again at `pos`. Advancing char_pos by the deleted count
    // (the previous `pos + (len - remaining)`) skipped characters and
    // deleted the wrong ones across span boundaries.
    char_pos = pos;
  }

  return first_deleted;
}

crabs_span_t* crabs_ot_document_apply_style(
    crabs_ot_document_t* doc, uint64_t pos, uint64_t len,
    const crabs_style_t* style) {
  if (doc == NULL || style == NULL || len == 0) return NULL;

  uint64_t remaining = len;
  uint64_t char_pos = pos;
  crabs_span_t* first_styled = NULL;

  while (remaining > 0) {
    uint32_t offset = 0;
    crabs_span_t* span = _find_span_at_char(doc, char_pos, &offset);
    if (span == NULL) break;

    if (first_styled == NULL) first_styled = span;

    // If style applies to entire span, just add it
    if (offset == 0 && remaining >= span->text_size) {
      if (span->style_count < CRABS_SPAN_MAX_STYLES) {
        span->styles[span->style_count] = *style;
        span->style_count++;
      }
      remaining -= span->text_size;
    } else {
      // Need to split the span to apply style to the correct range
      // For now, apply style to the whole span if it's partially covered
      if (span->style_count < CRABS_SPAN_MAX_STYLES) {
        span->styles[span->style_count] = *style;
        span->style_count++;
      }
      if (remaining >= span->text_size - offset) {
        remaining -= (span->text_size - offset);
      } else {
        remaining = 0;
      }
    }
    char_pos = pos + (len - remaining);
  }

  return first_styled;
}

// Sane upper bound for a merged span. A single span holding 256 MiB of text
// is already far beyond any legitimate document; larger requests are treated
// as corrupt input rather than an allocation to honor.
#define CRABS_OT_MERGE_SPANS_MAX_SIZE (256u * 1024u * 1024u)

crabs_span_t* crabs_ot_document_merge_spans(
    crabs_ot_document_t* doc, uint64_t pos1, uint64_t pos2) {
  if (doc == NULL) return NULL;

  crabs_span_t* s1 = _get_at_visible(doc, pos1);
  crabs_span_t* s2 = _get_at_visible(doc, pos2);
  if (s1 == NULL || s2 == NULL) return NULL;
  if (s1 == s2) return s1;

  // Audit finding: the sum was computed in uint32_t and could silently
  // overflow, then allocate a tiny buffer and memcpy huge sizes into it
  // (heap corruption). Compute in uint64_t and reject before allocating.
  uint64_t merged_size = (uint64_t)s1->text_size + (uint64_t)s2->text_size;
  if (merged_size > (uint64_t)UINT32_MAX ||
      merged_size > (uint64_t)CRABS_OT_MERGE_SPANS_MAX_SIZE) {
    return NULL;
  }

  // Merge s2's text into s1
  uint32_t new_size = (uint32_t)merged_size;
  uint8_t* new_text = get_memory(new_size);
  memcpy(new_text, s1->text, s1->text_size);
  memcpy(new_text + s1->text_size, s2->text, s2->text_size);
  free(s1->text);
  s1->text = new_text;
  s1->text_size = new_size;

  // Mark s2 as deleted — its text is now part of s1, so visible_char_count stays the same
  s2->deleted = true;

  return s1;
}

crabs_span_t* crabs_ot_document_split_span(
    crabs_ot_document_t* doc, uint64_t pos) {
  if (doc == NULL) return NULL;

  uint32_t offset = 0;
  crabs_span_t* span = _find_span_at_char(doc, pos, &offset);
  if (span == NULL) return NULL;
  if (offset == 0) return span;

  // Create right portion
  uint32_t right_size = span->text_size - offset;
  crabs_span_t* right = crabs_span_create(&span->id,
    span->text + offset, right_size);
  right->style_count = span->style_count;
  memcpy(right->styles, span->styles, sizeof(crabs_style_t) * span->style_count);

  // Truncate left span
  uint8_t* new_text = get_memory(offset);
  memcpy(new_text, span->text, offset);
  free(span->text);
  span->text = new_text;
  span->text_size = offset;

  // Link right after left
  right->next = span->next;
  right->prev = span;
  if (span->next) span->next->prev = right;
  span->next = right;
  if (span == doc->tail) doc->tail = right;
  doc->span_count++;

  return right;
}

// ============================================================
// Document Access
// ============================================================

crabs_span_t* crabs_ot_document_head(const crabs_ot_document_t* doc) {
  return doc == NULL ? NULL : doc->head;
}

crabs_span_t* crabs_ot_document_tail(const crabs_ot_document_t* doc) {
  return doc == NULL ? NULL : doc->tail;
}