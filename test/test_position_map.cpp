//
// Created by victor on 5/1/25.
//
// Tests for Position Map BST & Coordinate Mapping (v1.5 §3.3, §12.1)
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/OT/position_map.h"
}

// ============================================================
// BST Lifecycle Tests
// ============================================================

TEST(PositionMap, CreateDestroy) {
  crabs_bst_node_t* node = crabs_bst_create(5);
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->value, 5u);
  EXPECT_EQ(node->size, 1u);
  EXPECT_EQ(node->height, 1u);
  EXPECT_FALSE(node->deleted);
  crabs_bst_destroy(node);
}

TEST(PositionMap, CreateDestroyNull) {
  crabs_bst_destroy(NULL);
}

// ============================================================
// BST Insert Tests
// ============================================================

TEST(PositionMap, InsertSingle) {
  crabs_bst_node_t* root = crabs_bst_insert(NULL, 10);
  ASSERT_NE(root, nullptr);
  EXPECT_EQ(root->value, 10u);
  EXPECT_EQ(crabs_bst_size(root), 1u);
  crabs_bst_destroy(root);
}

TEST(PositionMap, InsertMultiple) {
  crabs_bst_node_t* root = NULL;
  root = crabs_bst_insert(root, 5);
  root = crabs_bst_insert(root, 3);
  root = crabs_bst_insert(root, 7);
  root = crabs_bst_insert(root, 1);
  root = crabs_bst_insert(root, 9);

  EXPECT_EQ(crabs_bst_size(root), 5u);
  EXPECT_TRUE(crabs_bst_contains(root, 5));
  EXPECT_TRUE(crabs_bst_contains(root, 3));
  EXPECT_TRUE(crabs_bst_contains(root, 7));
  EXPECT_TRUE(crabs_bst_contains(root, 1));
  EXPECT_TRUE(crabs_bst_contains(root, 9));
  EXPECT_FALSE(crabs_bst_contains(root, 4));

  crabs_bst_destroy(root);
}

TEST(PositionMap, InsertDuplicate) {
  crabs_bst_node_t* root = NULL;
  root = crabs_bst_insert(root, 5);
  root = crabs_bst_insert(root, 5);
  EXPECT_EQ(crabs_bst_size(root), 1u);
  crabs_bst_destroy(root);
}

// ============================================================
// BST Delete Tests
// ============================================================

TEST(PositionMap, DeleteNode) {
  crabs_bst_node_t* root = NULL;
  root = crabs_bst_insert(root, 5);
  root = crabs_bst_insert(root, 3);
  root = crabs_bst_insert(root, 7);

  EXPECT_EQ(crabs_bst_size(root), 3u);

  root = crabs_bst_delete_node(root, 3);
  EXPECT_EQ(crabs_bst_size(root), 2u);
  EXPECT_FALSE(crabs_bst_contains(root, 3));
  EXPECT_TRUE(crabs_bst_contains(root, 5));
  EXPECT_TRUE(crabs_bst_contains(root, 7));

  crabs_bst_destroy(root);
}

TEST(PositionMap, DeleteRoot) {
  crabs_bst_node_t* root = NULL;
  root = crabs_bst_insert(root, 5);
  root = crabs_bst_insert(root, 3);
  root = crabs_bst_insert(root, 7);

  root = crabs_bst_delete_node(root, 5);
  EXPECT_EQ(crabs_bst_size(root), 2u);
  EXPECT_FALSE(crabs_bst_contains(root, 5));

  crabs_bst_destroy(root);
}

TEST(PositionMap, DeleteNonExistent) {
  crabs_bst_node_t* root = NULL;
  root = crabs_bst_insert(root, 5);

  root = crabs_bst_delete_node(root, 99);
  EXPECT_EQ(crabs_bst_size(root), 1u);

  crabs_bst_destroy(root);
}

// ============================================================
// BST Find & Contains Tests
// ============================================================

TEST(PositionMap, FindExisting) {
  crabs_bst_node_t* root = NULL;
  root = crabs_bst_insert(root, 10);
  root = crabs_bst_insert(root, 5);
  root = crabs_bst_insert(root, 15);

  crabs_bst_node_t* found = crabs_bst_find(root, 5);
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->value, 5u);
  crabs_bst_destroy(root);
}

TEST(PositionMap, FindNonExistent) {
  crabs_bst_node_t* root = NULL;
  root = crabs_bst_insert(root, 10);

  crabs_bst_node_t* found = crabs_bst_find(root, 99);
  EXPECT_EQ(found, nullptr);
  crabs_bst_destroy(root);
}

// Helper to check BST height from outside the module
static uint32_t tree_height(const crabs_bst_node_t* node) {
  return node ? node->height : 0;
}

// ============================================================
// AVL Balancing Tests
// ============================================================

TEST(PositionMap, AVLBalanceRightHeavy) {
  // Insert in ascending order (right-heavy without balancing)
  crabs_bst_node_t* root = NULL;
  root = crabs_bst_insert(root, 1);
  root = crabs_bst_insert(root, 2);
  root = crabs_bst_insert(root, 3);
  root = crabs_bst_insert(root, 4);
  root = crabs_bst_insert(root, 5);

  EXPECT_EQ(crabs_bst_size(root), 5u);
  // Height should be <= log2(5) + 1 = ~3 for balanced AVL
  EXPECT_LE(tree_height(root), 3u);

  crabs_bst_destroy(root);
}

TEST(PositionMap, AVLBalanceLeftHeavy) {
  // Insert in descending order (left-heavy without balancing)
  crabs_bst_node_t* root = NULL;
  root = crabs_bst_insert(root, 5);
  root = crabs_bst_insert(root, 4);
  root = crabs_bst_insert(root, 3);
  root = crabs_bst_insert(root, 2);
  root = crabs_bst_insert(root, 1);

  EXPECT_EQ(crabs_bst_size(root), 5u);
  EXPECT_LE(tree_height(root), 3u);

  crabs_bst_destroy(root);
}

// ============================================================
// Mark Deleted Tests
// ============================================================

TEST(PositionMap, MarkDeleted) {
  crabs_bst_node_t* root = NULL;
  root = crabs_bst_insert(root, 5);
  root = crabs_bst_insert(root, 3);
  root = crabs_bst_insert(root, 7);

  crabs_bst_mark_deleted(root, 5);

  crabs_bst_node_t* node = crabs_bst_find(root, 5);
  ASSERT_NE(node, nullptr);
  EXPECT_TRUE(node->deleted);

  crabs_bst_node_t* node3 = crabs_bst_find(root, 3);
  ASSERT_NE(node3, nullptr);
  EXPECT_FALSE(node3->deleted);

  crabs_bst_destroy(root);
}

TEST(PositionMap, MarkDeletedNonExistent) {
  crabs_bst_node_t* root = NULL;
  root = crabs_bst_insert(root, 5);

  // Should not crash
  crabs_bst_mark_deleted(root, 99);
  crabs_bst_destroy(root);
}

// ============================================================
// Coordinate Mapping: xi() Tests
// ============================================================

TEST(PositionMap, XiEmptyTree) {
  // Empty tree: internal_pos maps to itself
  EXPECT_EQ(crabs_xi(NULL, 0), 0u);
  EXPECT_EQ(crabs_xi(NULL, 5), 5u);
}

TEST(PositionMap, XiNoDeleted) {
  // Empty tree: xi is identity
  for (uint64_t i = 0; i < 10; i++) {
    EXPECT_EQ(crabs_xi(NULL, i), i);
  }
}

TEST(PositionMap, XiWithDeletedPositions) {
  // Position 2 deleted: internal→visible mapping shifts after the deletion
  crabs_bst_node_t* root = NULL;
  root = crabs_union_one(root, 2);

  EXPECT_EQ(crabs_xi(root, 0), 0u);
  EXPECT_EQ(crabs_xi(root, 1), 1u);
  EXPECT_EQ(crabs_xi(root, 3), 2u);
  EXPECT_EQ(crabs_xi(root, 4), 3u);

  crabs_bst_destroy(root);
}

// ============================================================
// Coordinate Mapping: xi_inv() Tests
// ============================================================

TEST(PositionMap, XiInvEmptyTree) {
  // Empty tree: visible_pos maps to itself
  EXPECT_EQ(crabs_xi_inv(NULL, 0), 0u);
  EXPECT_EQ(crabs_xi_inv(NULL, 5), 5u);
}

TEST(PositionMap, XiInvWithDeletedPositions) {
  // Position 2 deleted: visible→internal mapping
  crabs_bst_node_t* root = NULL;
  root = crabs_union_one(root, 2);

  EXPECT_EQ(crabs_xi_inv(root, 0), 0u);
  EXPECT_EQ(crabs_xi_inv(root, 1), 1u);
  EXPECT_EQ(crabs_xi_inv(root, 2), 3u);
  EXPECT_EQ(crabs_xi_inv(root, 3), 4u);

  crabs_bst_destroy(root);
}

// ============================================================
// Coordinate Mapping Round-Trip Tests
// ============================================================

TEST(PositionMap, XiXiInvRoundTripEmpty) {
  // With empty tree, xi and xi_inv are both identity
  for (uint64_t i = 0; i < 10; i++) {
    EXPECT_EQ(crabs_xi_inv(NULL, crabs_xi(NULL, i)), i);
    EXPECT_EQ(crabs_xi(NULL, crabs_xi_inv(NULL, i)), i);
  }
}

TEST(PositionMap, XiXiInvRoundTripWithDeletions) {
  // Deletions at 3 and 7
  crabs_bst_node_t* root = NULL;
  root = crabs_union_one(root, 3);
  root = crabs_union_one(root, 7);

  // Positions before first deletion: identity
  for (uint64_t i = 0; i < 3; i++) {
    uint64_t visible = crabs_xi(root, i);
    EXPECT_EQ(visible, i);
    uint64_t internal_back = crabs_xi_inv(root, visible);
    EXPECT_EQ(internal_back, i);
  }

  // Positions between deletions (4-6): shift by 1
  for (uint64_t i = 4; i < 7; i++) {
    uint64_t visible = crabs_xi(root, i);
    EXPECT_EQ(visible, i - 1);
    uint64_t internal_back = crabs_xi_inv(root, visible);
    EXPECT_EQ(internal_back, i);
  }

  // Positions after both deletions (8+): shift by 2
  for (uint64_t i = 8; i < 12; i++) {
    uint64_t visible = crabs_xi(root, i);
    EXPECT_EQ(visible, i - 2);
    uint64_t internal_back = crabs_xi_inv(root, visible);
    EXPECT_EQ(internal_back, i);
  }

  crabs_bst_destroy(root);
}

// ============================================================
// union_one Tests
// ============================================================

TEST(PositionMap, UnionOneInsertNew) {
  crabs_bst_node_t* root = NULL;
  root = crabs_union_one(root, 5);

  crabs_bst_node_t* found = crabs_bst_find(root, 5);
  ASSERT_NE(found, nullptr);
  EXPECT_EQ(found->value, 5u);
  EXPECT_TRUE(found->deleted);

  crabs_bst_destroy(root);
}

TEST(PositionMap, UnionOneMarkExisting) {
  crabs_bst_node_t* root = NULL;
  root = crabs_bst_insert(root, 5);
  EXPECT_FALSE(crabs_bst_find(root, 5)->deleted);

  root = crabs_union_one(root, 5);
  EXPECT_TRUE(crabs_bst_find(root, 5)->deleted);
  EXPECT_EQ(crabs_bst_size(root), 1u);

  crabs_bst_destroy(root);
}

TEST(PositionMap, UnionOneMultiple) {
  crabs_bst_node_t* root = NULL;
  root = crabs_union_one(root, 1);
  root = crabs_union_one(root, 3);
  root = crabs_union_one(root, 5);

  EXPECT_EQ(crabs_bst_size(root), 3u);
  EXPECT_TRUE(crabs_bst_find(root, 1)->deleted);
  EXPECT_TRUE(crabs_bst_find(root, 3)->deleted);
  EXPECT_TRUE(crabs_bst_find(root, 5)->deleted);

  crabs_bst_destroy(root);
}

// ============================================================
// xi_one Tests
// ============================================================

TEST(PositionMap, XiOneShiftValues) {
  crabs_bst_node_t* root = NULL;
  root = crabs_bst_insert(root, 3);
  root = crabs_bst_insert(root, 5);
  root = crabs_bst_insert(root, 7);

  // Shift all positions >= 5 by +1
  root = crabs_xi_one(root, 5);

  // Position 5 should become 6, position 7 should become 8
  EXPECT_TRUE(crabs_bst_contains(root, 3));
  EXPECT_TRUE(crabs_bst_contains(root, 6));  // was 5
  EXPECT_TRUE(crabs_bst_contains(root, 8));  // was 7

  crabs_bst_destroy(root);
}

TEST(PositionMap, XiOneShiftAllValues) {
  crabs_bst_node_t* root = NULL;
  root = crabs_bst_insert(root, 2);
  root = crabs_bst_insert(root, 4);

  // Shift all positions >= 1 by +1
  root = crabs_xi_one(root, 1);

  // All values >= 1 shift by +1: 2->3, 4->5
  EXPECT_TRUE(crabs_bst_contains(root, 3));
  EXPECT_TRUE(crabs_bst_contains(root, 5));

  crabs_bst_destroy(root);
}

// ============================================================
// BST Merge Tests
// ============================================================

TEST(PositionMap, MergeDeletedEntries) {
  crabs_bst_node_t* dest = NULL;
  dest = crabs_bst_insert(dest, 2);
  dest = crabs_bst_insert(dest, 5);

  crabs_bst_node_t* src = NULL;
  src = crabs_union_one(src, 7);  // 7 is deleted

  dest = crabs_bst_merge(dest, src);

  // Dest should now contain 7 as deleted
  EXPECT_TRUE(crabs_bst_contains(dest, 7));
  EXPECT_TRUE(crabs_bst_find(dest, 7)->deleted);

  // Original entries should still be present
  EXPECT_TRUE(crabs_bst_contains(dest, 2));
  EXPECT_TRUE(crabs_bst_contains(dest, 5));

  crabs_bst_destroy(dest);
  crabs_bst_destroy(src);
}

TEST(PositionMap, MergeEmptySource) {
  crabs_bst_node_t* dest = NULL;
  dest = crabs_bst_insert(dest, 5);

  dest = crabs_bst_merge(dest, NULL);
  EXPECT_EQ(crabs_bst_size(dest), 1u);
  EXPECT_TRUE(crabs_bst_contains(dest, 5));

  crabs_bst_destroy(dest);
}

TEST(PositionMap, MergeEmptyDest) {
  crabs_bst_node_t* src = NULL;
  src = crabs_union_one(src, 3);

  crabs_bst_node_t* dest = crabs_bst_merge(NULL, src);
  ASSERT_NE(dest, nullptr);
  EXPECT_TRUE(crabs_bst_contains(dest, 3));
  EXPECT_TRUE(crabs_bst_find(dest, 3)->deleted);

  crabs_bst_destroy(dest);
  crabs_bst_destroy(src);
}