//
// Created by victor on 5/1/25.
//
// Tests for OT_DOCUMENT Data Type (v1.5 §6)
//

#include <gtest/gtest.h>
#include <cstdlib>
extern "C" {
#include "../src/OT/ot_document.h"
}

static crabs_ot_op_id_t make_id(const char* node, uint64_t seq, uint64_t ts) {
  crabs_ot_op_id_t id;
  crabs_ot_op_id_init(&id, node, seq, ts);
  return id;
}

// ============================================================
// Span Lifecycle Tests
// ============================================================

TEST(OTDocument, SpanCreateDestroy) {
  crabs_ot_op_id_t id = make_id("n1", 1, 100);
  const uint8_t text[] = {'H', 'e', 'l', 'l', 'o'};
  crabs_span_t* span = crabs_span_create(&id, text, 5);
  ASSERT_NE(span, nullptr);
  EXPECT_TRUE(crabs_ot_op_id_equal(&span->id, &id));
  ASSERT_NE(span->text, nullptr);
  EXPECT_EQ(span->text_size, 5u);
  EXPECT_EQ(span->text[0], 'H');
  EXPECT_EQ(span->style_count, 0u);
  EXPECT_FALSE(span->deleted);
  crabs_span_destroy(span);
}

TEST(OTDocument, SpanCreateNull) {
  crabs_span_t* span = crabs_span_create(NULL, NULL, 0);
  ASSERT_NE(span, nullptr);
  EXPECT_EQ(span->text, nullptr);
  EXPECT_EQ(span->text_size, 0u);
  crabs_span_destroy(span);
  crabs_span_destroy(NULL);
}

// ============================================================
// Document Lifecycle Tests
// ============================================================

TEST(OTDocument, CreateDestroy) {
  crabs_ot_document_t* doc = crabs_ot_document_create();
  ASSERT_NE(doc, nullptr);
  EXPECT_EQ(crabs_ot_document_span_count(doc), 0u);
  EXPECT_EQ(crabs_ot_document_char_count(doc), 0u);
  EXPECT_NE(doc->ot_data, nullptr);
  crabs_ot_document_destroy(doc);
}

TEST(OTDocument, DestroyNull) {
  crabs_ot_document_destroy(NULL);
}

// ============================================================
// Insert Text Tests
// ============================================================

TEST(OTDocument, InsertSingleSpan) {
  crabs_ot_document_t* doc = crabs_ot_document_create();
  crabs_ot_op_id_t id = make_id("n1", 1, 100);
  const uint8_t text[] = {'H', 'i'};
  crabs_span_t* span = crabs_ot_document_insert_text(doc, 0, text, 2, &id);
  ASSERT_NE(span, nullptr);
  EXPECT_EQ(crabs_ot_document_span_count(doc), 1u);
  EXPECT_EQ(crabs_ot_document_char_count(doc), 2u);
  crabs_ot_document_destroy(doc);
}

TEST(OTDocument, InsertMultipleSpans) {
  crabs_ot_document_t* doc = crabs_ot_document_create();
  crabs_ot_op_id_t id1 = make_id("n1", 1, 100);
  crabs_ot_op_id_t id2 = make_id("n1", 2, 101);
  crabs_ot_op_id_t id3 = make_id("n1", 3, 102);
  const uint8_t t1[] = {'A'}, t2[] = {'B'}, t3[] = {'C'};

  crabs_ot_document_insert_text(doc, 0, t1, 1, &id1);
  crabs_ot_document_insert_text(doc, 1, t2, 1, &id2);
  crabs_ot_document_insert_text(doc, 2, t3, 1, &id3);

  EXPECT_EQ(crabs_ot_document_span_count(doc), 3u);
  EXPECT_EQ(crabs_ot_document_char_count(doc), 3u);

  crabs_span_t* head = crabs_ot_document_head(doc);
  ASSERT_NE(head, nullptr);
  EXPECT_EQ(head->text[0], 'A');

  crabs_span_t* tail = crabs_ot_document_tail(doc);
  ASSERT_NE(tail, nullptr);
  EXPECT_EQ(tail->text[0], 'C');

  crabs_ot_document_destroy(doc);
}

TEST(OTDocument, InsertNullDoc) {
  crabs_ot_op_id_t id = make_id("n1", 1, 100);
  const uint8_t text[] = {'X'};
  EXPECT_EQ(crabs_ot_document_insert_text(NULL, 0, text, 1, &id), nullptr);
}

// ============================================================
// Delete Range Tests
// ============================================================

TEST(OTDocument, DeleteFullSpan) {
  crabs_ot_document_t* doc = crabs_ot_document_create();
  crabs_ot_op_id_t id = make_id("n1", 1, 100);
  const uint8_t text[] = {'H', 'i'};
  crabs_ot_document_insert_text(doc, 0, text, 2, &id);

  crabs_span_t* deleted = crabs_ot_document_delete_range(doc, 0, 2);
  ASSERT_NE(deleted, nullptr);
  EXPECT_TRUE(deleted->deleted);
  EXPECT_EQ(crabs_ot_document_char_count(doc), 0u);
  // Span count stays the same (tombstone)
  EXPECT_EQ(crabs_ot_document_span_count(doc), 1u);

  crabs_ot_document_destroy(doc);
}

TEST(OTDocument, DeletePartialSpan) {
  crabs_ot_document_t* doc = crabs_ot_document_create();
  crabs_ot_op_id_t id = make_id("n1", 1, 100);
  const uint8_t text[] = {'H', 'e', 'l', 'l', 'o'};
  crabs_ot_document_insert_text(doc, 0, text, 5, &id);

  // Delete "ell" (positions 1-3)
  crabs_span_t* span = crabs_ot_document_delete_range(doc, 1, 3);
  ASSERT_NE(span, nullptr);
  // Remaining characters should be "Ho" = 2
  EXPECT_EQ(crabs_ot_document_char_count(doc), 2u);

  crabs_ot_document_destroy(doc);
}

TEST(OTDocument, DeleteFromStartOfSpan) {
  crabs_ot_document_t* doc = crabs_ot_document_create();
  crabs_ot_op_id_t id = make_id("n1", 1, 100);
  const uint8_t text[] = {'H', 'e', 'l', 'l', 'o'};
  crabs_ot_document_insert_text(doc, 0, text, 5, &id);

  // Delete "Hel" (positions 0-2)
  crabs_span_t* span = crabs_ot_document_delete_range(doc, 0, 3);
  ASSERT_NE(span, nullptr);
  // Remaining characters should be "lo" = 2
  EXPECT_EQ(crabs_ot_document_char_count(doc), 2u);

  crabs_ot_document_destroy(doc);
}

TEST(OTDocument, DeleteAcrossSpans) {
  crabs_ot_document_t* doc = crabs_ot_document_create();
  crabs_ot_op_id_t id1 = make_id("n1", 1, 100);
  crabs_ot_op_id_t id2 = make_id("n1", 2, 101);
  crabs_ot_op_id_t id3 = make_id("n1", 3, 102);
  const uint8_t t1[] = {'A', 'B'}, t2[] = {'C'}, t3[] = {'D', 'E'};

  crabs_ot_document_insert_text(doc, 0, t1, 2, &id1);
  crabs_ot_document_insert_text(doc, 2, t2, 1, &id2);
  crabs_ot_document_insert_text(doc, 3, t3, 2, &id3);

  EXPECT_EQ(crabs_ot_document_char_count(doc), 5u); // "ABCDE"

  // Delete "BCD" (positions 1-3)
  crabs_span_t* span = crabs_ot_document_delete_range(doc, 1, 3);
  EXPECT_NE(span, nullptr);
  // "AE" remaining = 2 chars
  EXPECT_EQ(crabs_ot_document_char_count(doc), 2u);

  crabs_ot_document_destroy(doc);
}

TEST(OTDocument, DeleteNullDoc) {
  EXPECT_EQ(crabs_ot_document_delete_range(NULL, 0, 1), nullptr);
}

// ============================================================
// Style Tests
// ============================================================

TEST(OTDocument, ApplyStyle) {
  crabs_ot_document_t* doc = crabs_ot_document_create();
  crabs_ot_op_id_t id = make_id("n1", 1, 100);
  const uint8_t text[] = {'H', 'e', 'l', 'l', 'o'};
  crabs_ot_document_insert_text(doc, 0, text, 5, &id);

  crabs_style_t style;
  memset(&style, 0, sizeof(style));
  strncpy(style.name, "bold", CRABS_STYLE_NAME_MAX - 1);
  strncpy(style.value, "true", CRABS_STYLE_VALUE_MAX - 1);

  crabs_span_t* styled = crabs_ot_document_apply_style(doc, 0, 5, &style);
  ASSERT_NE(styled, nullptr);
  EXPECT_EQ(styled->style_count, 1u);
  EXPECT_STREQ(styled->styles[0].name, "bold");

  crabs_ot_document_destroy(doc);
}

TEST(OTDocument, ApplyStyleNull) {
  EXPECT_EQ(crabs_ot_document_apply_style(NULL, 0, 1, NULL), nullptr);
}

// ============================================================
// Merge Spans Tests
// ============================================================

TEST(OTDocument, MergeSpans) {
  crabs_ot_document_t* doc = crabs_ot_document_create();
  crabs_ot_op_id_t id1 = make_id("n1", 1, 100);
  crabs_ot_op_id_t id2 = make_id("n1", 2, 101);
  const uint8_t t1[] = {'H', 'e'}, t2[] = {'l', 'l', 'o'};

  crabs_ot_document_insert_text(doc, 0, t1, 2, &id1);
  crabs_ot_document_insert_text(doc, 2, t2, 3, &id2);

  EXPECT_EQ(crabs_ot_document_span_count(doc), 2u);
  EXPECT_EQ(crabs_ot_document_char_count(doc), 5u);

  // Merge span 0 and span 1
  crabs_span_t* merged = crabs_ot_document_merge_spans(doc, 0, 1);
  ASSERT_NE(merged, nullptr);
  EXPECT_EQ(merged->text_size, 5u);  // "Hello"
  // Second span is now deleted, but visible char count stays the same
  // (merged span contains all 5 visible chars)
  EXPECT_EQ(crabs_ot_document_char_count(doc), 5u);

  crabs_ot_document_destroy(doc);
}

TEST(OTDocument, MergeSpansNull) {
  EXPECT_EQ(crabs_ot_document_merge_spans(NULL, 0, 1), nullptr);
}

// Audit finding: `new_size = s1->text_size + s2->text_size` was computed in
// uint32_t and could silently overflow, then allocate a tiny buffer and
// memcpy huge sizes into it (heap corruption). The guard must fire before
// any allocation. Sizes are poked directly on real spans with small actual
// buffers — nothing may be read or written once the guard rejects.
TEST(OTDocument, MergeSpansUint32OverflowRejected) {
  crabs_ot_document_t* doc = crabs_ot_document_create();
  crabs_ot_op_id_t id1 = make_id("n1", 1, 100);
  crabs_ot_op_id_t id2 = make_id("n1", 2, 101);
  const uint8_t t1[] = {'A'}, t2[] = {'B'};

  crabs_ot_document_insert_text(doc, 0, t1, 1, &id1);
  crabs_ot_document_insert_text(doc, 1, t2, 1, &id2);

  crabs_span_t* s1 = crabs_ot_document_head(doc);
  crabs_span_t* s2 = crabs_ot_document_head(doc)->next;
  ASSERT_NE(s1, nullptr);
  ASSERT_NE(s2, nullptr);

  // Two sizes that individually fit but sum to UINT32_MAX + 1.
  const uint32_t huge_size = 0x80000000u;  // 2 GiB
  s1->text_size = huge_size;
  s2->text_size = huge_size;

  uint8_t* text_before = s1->text;
  EXPECT_EQ(crabs_ot_document_merge_spans(doc, 0, 1), nullptr);
  // Guard fired before any allocation/free: buffers and links untouched.
  EXPECT_EQ(s1->text, text_before);
  EXPECT_EQ(s1->text[0], 'A');
  EXPECT_EQ(s1->text_size, huge_size);
  EXPECT_FALSE(s2->deleted);

  crabs_ot_document_destroy(doc);
}

// A sum that fits in uint32_t but exceeds the sane merge cap is rejected too.
TEST(OTDocument, MergeSpansOverCapRejected) {
  crabs_ot_document_t* doc = crabs_ot_document_create();
  crabs_ot_op_id_t id1 = make_id("n1", 1, 100);
  crabs_ot_op_id_t id2 = make_id("n1", 2, 101);
  const uint8_t t1[] = {'A'}, t2[] = {'B'};

  crabs_ot_document_insert_text(doc, 0, t1, 1, &id1);
  crabs_ot_document_insert_text(doc, 1, t2, 1, &id2);

  crabs_span_t* s1 = crabs_ot_document_head(doc);
  crabs_span_t* s2 = crabs_ot_document_head(doc)->next;
  ASSERT_NE(s1, nullptr);
  ASSERT_NE(s2, nullptr);

  // 128 MiB + 1 each: sum is 256 MiB + 2, above the merge cap.
  const uint32_t over_cap_size = (256u * 1024u * 1024u) / 2u + 1u;
  s1->text_size = over_cap_size;
  s2->text_size = over_cap_size;

  uint8_t* text_before = s1->text;
  EXPECT_EQ(crabs_ot_document_merge_spans(doc, 0, 1), nullptr);
  EXPECT_EQ(s1->text, text_before);
  EXPECT_EQ(s1->text[0], 'A');
  EXPECT_FALSE(s2->deleted);

  crabs_ot_document_destroy(doc);
}

// ============================================================
// Split Span Tests
// ============================================================

TEST(OTDocument, SplitSpan) {
  crabs_ot_document_t* doc = crabs_ot_document_create();
  crabs_ot_op_id_t id = make_id("n1", 1, 100);
  const uint8_t text[] = {'H', 'e', 'l', 'l', 'o'};
  crabs_ot_document_insert_text(doc, 0, text, 5, &id);

  EXPECT_EQ(crabs_ot_document_span_count(doc), 1u);

  // Split at position 2 (after "He")
  crabs_span_t* right = crabs_ot_document_split_span(doc, 2);
  ASSERT_NE(right, nullptr);
  EXPECT_EQ(crabs_ot_document_span_count(doc), 2u);

  // Left span should be "He"
  crabs_span_t* left = crabs_ot_document_head(doc);
  ASSERT_NE(left, nullptr);
  EXPECT_EQ(left->text_size, 2u);

  // Right span should be "llo"
  EXPECT_EQ(right->text_size, 3u);

  crabs_ot_document_destroy(doc);
}

TEST(OTDocument, SplitSpanNullDoc) {
  EXPECT_EQ(crabs_ot_document_split_span(NULL, 0), nullptr);
}

// ============================================================
// Access Tests
// ============================================================

TEST(OTDocument, HeadTail) {
  crabs_ot_document_t* doc = crabs_ot_document_create();
  EXPECT_EQ(crabs_ot_document_head(doc), nullptr);
  EXPECT_EQ(crabs_ot_document_tail(doc), nullptr);
  EXPECT_EQ(crabs_ot_document_head(NULL), nullptr);
  EXPECT_EQ(crabs_ot_document_tail(NULL), nullptr);
  crabs_ot_document_destroy(doc);
}