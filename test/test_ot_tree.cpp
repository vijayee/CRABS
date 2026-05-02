//
// Created by victor on 5/1/25.
//
// Tests for OT_TREE Data Type (v1.5 §7)
//

#include <gtest/gtest.h>
#include <cstdlib>
extern "C" {
#include "../src/OT/ot_tree.h"
}

// ============================================================
// Tree Node Lifecycle Tests
// ============================================================

TEST(OTTree, NodeCreateDestroy) {
  const uint8_t data[] = {0x01, 0x02};
  crabs_tree_node_t* node = crabs_tree_node_create("n1", "root", data, 2);
  ASSERT_NE(node, nullptr);
  EXPECT_STREQ(node->id, "n1");
  EXPECT_STREQ(node->parent_id, "root");
  ASSERT_NE(node->value, nullptr);
  EXPECT_EQ(node->value_size, 2u);
  EXPECT_EQ(node->value[0], 0x01);
  EXPECT_FALSE(node->deleted);
  crabs_tree_node_destroy(node);
}

TEST(OTTree, NodeCreateNull) {
  crabs_tree_node_t* node = crabs_tree_node_create(NULL, NULL, NULL, 0);
  ASSERT_NE(node, nullptr);
  EXPECT_EQ(node->value, nullptr);
  EXPECT_EQ(node->value_size, 0u);
  crabs_tree_node_destroy(node);
  crabs_tree_node_destroy(NULL);
}

// ============================================================
// Tree Lifecycle Tests
// ============================================================

TEST(OTTree, CreateDestroy) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  ASSERT_NE(tree, nullptr);
  EXPECT_EQ(crabs_ot_tree_node_count(tree), 0u);
  EXPECT_EQ(crabs_ot_tree_visible_count(tree), 0u);
  EXPECT_NE(tree->ot_data, nullptr);
  crabs_ot_tree_destroy(tree);
}

TEST(OTTree, DestroyNull) {
  crabs_ot_tree_destroy(NULL);
}

// ============================================================
// Insert Node Tests
// ============================================================

TEST(OTTree, InsertRootNode) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  const uint8_t data[] = {0x01};

  crabs_tree_node_t* root = crabs_ot_tree_insert_node(tree, NULL, 0, "root", data, 1);
  ASSERT_NE(root, nullptr);
  EXPECT_STREQ(root->id, "root");
  EXPECT_EQ(crabs_ot_tree_node_count(tree), 1u);
  EXPECT_EQ(crabs_ot_tree_visible_count(tree), 1u);

  crabs_tree_node_t* found_root = crabs_ot_tree_root(tree);
  EXPECT_EQ(found_root, root);

  crabs_ot_tree_destroy(tree);
}

TEST(OTTree, InsertChildNodes) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  const uint8_t data[] = {0x01};

  crabs_tree_node_t* root = crabs_ot_tree_insert_node(tree, NULL, 0, "root", data, 1);
  crabs_tree_node_t* c1 = crabs_ot_tree_insert_node(tree, "root", 0, "child1", data, 1);
  crabs_tree_node_t* c2 = crabs_ot_tree_insert_node(tree, "root", 1, "child2", data, 1);

  ASSERT_NE(c1, nullptr);
  ASSERT_NE(c2, nullptr);
  EXPECT_EQ(crabs_ot_tree_node_count(tree), 3u);
  EXPECT_EQ(crabs_ot_tree_visible_count(tree), 3u);
  EXPECT_EQ(crabs_ot_tree_child_count(root), 2u);

  // Children should be linked
  EXPECT_EQ(root->first_child, c1);
  EXPECT_EQ(c1->next_sibling, c2);
  EXPECT_EQ(c2->prev_sibling, c1);

  crabs_ot_tree_destroy(tree);
}

TEST(OTTree, InsertNullTree) {
  const uint8_t data[] = {0x01};
  EXPECT_EQ(crabs_ot_tree_insert_node(NULL, NULL, 0, "root", data, 1), nullptr);
}

TEST(OTTree, InsertNullId) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  const uint8_t data[] = {0x01};
  EXPECT_EQ(crabs_ot_tree_insert_node(tree, NULL, 0, NULL, data, 1), nullptr);
  crabs_ot_tree_destroy(tree);
}

TEST(OTTree, InsertMissingParent) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  const uint8_t data[] = {0x01};
  // Parent "nonexistent" doesn't exist — should return NULL
  crabs_tree_node_t* node = crabs_ot_tree_insert_node(tree, "nonexistent", 0, "child", data, 1);
  EXPECT_EQ(node, nullptr);
  EXPECT_EQ(crabs_ot_tree_node_count(tree), 0u);
  crabs_ot_tree_destroy(tree);
}

// ============================================================
// Delete Node Tests
// ============================================================

TEST(OTTree, DeleteNode) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  const uint8_t data[] = {0x01};

  crabs_tree_node_t* root = crabs_ot_tree_insert_node(tree, NULL, 0, "root", data, 1);
  crabs_tree_node_t* c1 = crabs_ot_tree_insert_node(tree, "root", 0, "child1", data, 1);

  crabs_tree_node_t* deleted = crabs_ot_tree_delete_node(tree, "child1");
  ASSERT_NE(deleted, nullptr);
  EXPECT_TRUE(deleted->deleted);
  EXPECT_EQ(crabs_ot_tree_visible_count(tree), 1u); // Only root visible
  EXPECT_EQ(crabs_ot_tree_node_count(tree), 2u);     // Still 2 nodes (tombstone)

  crabs_ot_tree_destroy(tree);
}

TEST(OTTree, DeleteNodeWithChildren) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  const uint8_t data[] = {0x01};

  crabs_ot_tree_insert_node(tree, NULL, 0, "root", data, 1);
  crabs_tree_node_t* parent = crabs_ot_tree_insert_node(tree, "root", 0, "parent", data, 1);
  crabs_tree_node_t* child = crabs_ot_tree_insert_node(tree, "parent", 0, "child", data, 1);
  crabs_tree_node_t* grandchild = crabs_ot_tree_insert_node(tree, "child", 0, "grandchild", data, 1);

  // Deleting parent should also mark children and grandchildren as deleted
  crabs_tree_node_t* deleted = crabs_ot_tree_delete_node(tree, "parent");
  EXPECT_TRUE(deleted->deleted);
  EXPECT_TRUE(child->deleted);
  EXPECT_TRUE(grandchild->deleted);
  EXPECT_EQ(crabs_ot_tree_visible_count(tree), 1u); // Only root visible

  crabs_ot_tree_destroy(tree);
}

TEST(OTTree, DeleteNonexistent) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  EXPECT_EQ(crabs_ot_tree_delete_node(tree, "nobody"), nullptr);
  crabs_ot_tree_destroy(tree);
}

TEST(OTTree, DeleteNullTree) {
  EXPECT_EQ(crabs_ot_tree_delete_node(NULL, "root"), nullptr);
}

// ============================================================
// Reparent Tests
// ============================================================

TEST(OTTree, ReparentNode) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  const uint8_t data[] = {0x01};

  crabs_ot_tree_insert_node(tree, NULL, 0, "root", data, 1);
  crabs_ot_tree_insert_node(tree, "root", 0, "A", data, 1);
  crabs_ot_tree_insert_node(tree, "root", 1, "B", data, 1);
  crabs_tree_node_t* c = crabs_ot_tree_insert_node(tree, "A", 0, "child", data, 1);

  // Move "child" from A to B at position 0
  crabs_tree_node_t* moved = crabs_ot_tree_reparent(tree, "child", "B", 0);
  ASSERT_NE(moved, nullptr);
  EXPECT_STREQ(moved->parent_id, "B");
  EXPECT_EQ(moved->parent, crabs_ot_tree_find(tree, "B"));
  EXPECT_EQ(crabs_ot_tree_child_count(crabs_ot_tree_find(tree, "A")), 0u);
  EXPECT_EQ(crabs_ot_tree_child_count(crabs_ot_tree_find(tree, "B")), 1u);

  crabs_ot_tree_destroy(tree);
}

TEST(OTTree, ReparentToRoot) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  const uint8_t data[] = {0x01};

  crabs_ot_tree_insert_node(tree, NULL, 0, "root", data, 1);
  crabs_ot_tree_insert_node(tree, "root", 0, "A", data, 1);

  // Move A to root (parent_id = "")
  crabs_tree_node_t* moved = crabs_ot_tree_reparent(tree, "A", "", 0);
  ASSERT_NE(moved, nullptr);
  EXPECT_STREQ(moved->parent_id, "");

  crabs_ot_tree_destroy(tree);
}

TEST(OTTree, ReparentNullTree) {
  EXPECT_EQ(crabs_ot_tree_reparent(NULL, "A", "B", 0), nullptr);
}

// ============================================================
// Reorder Tests
// ============================================================

TEST(OTTree, ReorderChild) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  const uint8_t data[] = {0x01};

  crabs_ot_tree_insert_node(tree, NULL, 0, "root", data, 1);
  crabs_ot_tree_insert_node(tree, "root", 0, "A", data, 1);
  crabs_ot_tree_insert_node(tree, "root", 1, "B", data, 1);
  crabs_ot_tree_insert_node(tree, "root", 2, "C", data, 1);

  // Move A from position 0 to position 2
  crabs_tree_node_t* moved = crabs_ot_tree_reorder(tree, "A", 2);
  ASSERT_NE(moved, nullptr);

  crabs_tree_node_t* root = crabs_ot_tree_find(tree, "root");
  crabs_tree_node_t* first = root->first_child;
  ASSERT_NE(first, nullptr);
  EXPECT_STREQ(first->id, "B");

  crabs_ot_tree_destroy(tree);
}

TEST(OTTree, ReorderSamePosition) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  const uint8_t data[] = {0x01};

  crabs_ot_tree_insert_node(tree, NULL, 0, "root", data, 1);
  crabs_ot_tree_insert_node(tree, "root", 0, "A", data, 1);
  crabs_ot_tree_insert_node(tree, "root", 1, "B", data, 1);

  // Reorder to same position should be a no-op
  crabs_tree_node_t* result = crabs_ot_tree_reorder(tree, "A", 0);
  ASSERT_NE(result, nullptr);
  EXPECT_STREQ(result->id, "A");

  crabs_ot_tree_destroy(tree);
}

TEST(OTTree, ReorderRootNode) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  const uint8_t data[] = {0x01};
  crabs_ot_tree_insert_node(tree, NULL, 0, "root", data, 1);

  // Root has no parent — reorder should return NULL
  EXPECT_EQ(crabs_ot_tree_reorder(tree, "root", 1), nullptr);

  crabs_ot_tree_destroy(tree);
}

TEST(OTTree, ReorderNullTree) {
  EXPECT_EQ(crabs_ot_tree_reorder(NULL, "A", 1), nullptr);
}

// ============================================================
// Access Tests
// ============================================================

TEST(OTTree, FindNode) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  const uint8_t data[] = {0x01};

  crabs_ot_tree_insert_node(tree, NULL, 0, "root", data, 1);
  crabs_ot_tree_insert_node(tree, "root", 0, "child", data, 1);

  crabs_tree_node_t* found = crabs_ot_tree_find(tree, "child");
  ASSERT_NE(found, nullptr);
  EXPECT_STREQ(found->id, "child");

  EXPECT_EQ(crabs_ot_tree_find(tree, "nonexistent"), nullptr);
  EXPECT_EQ(crabs_ot_tree_find(NULL, "root"), nullptr);
  EXPECT_EQ(crabs_ot_tree_find(tree, NULL), nullptr);

  crabs_ot_tree_destroy(tree);
}

TEST(OTTree, RootAccess) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  EXPECT_EQ(crabs_ot_tree_root(tree), nullptr);
  EXPECT_EQ(crabs_ot_tree_root(NULL), nullptr);

  const uint8_t data[] = {0x01};
  crabs_tree_node_t* root = crabs_ot_tree_insert_node(tree, NULL, 0, "root", data, 1);
  EXPECT_EQ(crabs_ot_tree_root(tree), root);

  crabs_ot_tree_destroy(tree);
}

TEST(OTTree, ChildCount) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  const uint8_t data[] = {0x01};

  crabs_tree_node_t* root = crabs_ot_tree_insert_node(tree, NULL, 0, "root", data, 1);
  EXPECT_EQ(crabs_ot_tree_child_count(root), 0u);

  crabs_ot_tree_insert_node(tree, "root", 0, "A", data, 1);
  crabs_ot_tree_insert_node(tree, "root", 1, "B", data, 1);
  EXPECT_EQ(crabs_ot_tree_child_count(root), 2u);

  // Delete one child — visible count decreases
  crabs_ot_tree_delete_node(tree, "A");
  EXPECT_EQ(crabs_ot_tree_child_count(root), 1u);

  crabs_ot_tree_destroy(tree);
}

TEST(OTTree, ChildCountNull) {
  EXPECT_EQ(crabs_ot_tree_child_count(NULL), 0u);
}

// ============================================================
// Merge Tests
// ============================================================

TEST(OTTree, MergeAddsNodes) {
  crabs_ot_tree_t* dest = crabs_ot_tree_create();
  crabs_ot_tree_t* src = crabs_ot_tree_create();
  const uint8_t data[] = {0x01};

  crabs_ot_tree_insert_node(dest, NULL, 0, "root", data, 1);
  crabs_ot_tree_insert_node(src, NULL, 0, "root", data, 1);
  crabs_ot_tree_insert_node(src, "root", 0, "childA", data, 1);

  crabs_ot_tree_merge(dest, src);
  // "root" exists in both, so not duplicated. "childA" is new, so added.
  EXPECT_EQ(crabs_ot_tree_node_count(dest), 2u);

  crabs_tree_node_t* found = crabs_ot_tree_find(dest, "childA");
  ASSERT_NE(found, nullptr);
  EXPECT_STREQ(found->id, "childA");

  crabs_ot_tree_destroy(dest);
  crabs_ot_tree_destroy(src);
}

TEST(OTTree, MergeDeletionWins) {
  crabs_ot_tree_t* dest = crabs_ot_tree_create();
  crabs_ot_tree_t* src = crabs_ot_tree_create();
  const uint8_t data[] = {0x01};

  crabs_ot_tree_insert_node(dest, NULL, 0, "root", data, 1);
  crabs_ot_tree_insert_node(dest, "root", 0, "child", data, 1);

  crabs_ot_tree_insert_node(src, NULL, 0, "root", data, 1);
  crabs_ot_tree_insert_node(src, "root", 0, "child", data, 1);

  // Delete child in src
  crabs_ot_tree_delete_node(src, "child");

  crabs_ot_tree_merge(dest, src);
  crabs_tree_node_t* child = crabs_ot_tree_find(dest, "child");
  ASSERT_NE(child, nullptr);
  EXPECT_TRUE(child->deleted);

  crabs_ot_tree_destroy(dest);
  crabs_ot_tree_destroy(src);
}

TEST(OTTree, MergeNull) {
  crabs_ot_tree_t* tree = crabs_ot_tree_create();
  EXPECT_EQ(crabs_ot_tree_merge(tree, NULL), tree);
  EXPECT_EQ(crabs_ot_tree_merge(NULL, tree), nullptr);
  crabs_ot_tree_destroy(tree);
}