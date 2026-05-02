//
// Created by victor on 5/2/25.
//
// Tests for OR-Set & 2P-Set Compaction VTables (CRABS-75)
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/Compaction/crdt_compaction.h"
#include "../src/Compaction/compaction.h"
#include "../src/CRDT/crdt_merge.h"
#include "../src/CRABS/data_model.h"
}

// ============================================================
// OR-Set Compaction Tests
// ============================================================

class ORSetCompaction : public ::testing::Test {
protected:
  crabs_compaction_registry_t registry;
  const crabs_compaction_vtable_t* vtable;

  void SetUp() override {
    crabs_compaction_registry_init(&registry);
    crabs_register_or_set_vtable(&registry);
    vtable = crabs_compaction_get_vtable(&registry, DATA_TYPE_SET);
    ASSERT_NE(vtable, nullptr);
  }
};

TEST_F(ORSetCompaction, CountTombstones) {
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_add(set, "b", "n1:2");
  or_set_remove(set, "a");

  EXPECT_EQ(vtable->count_tombstones(set), 1u);
  or_set_destroy(set);
}

TEST_F(ORSetCompaction, CountTombstonesEmpty) {
  or_set_t* set = or_set_create();
  EXPECT_EQ(vtable->count_tombstones(set), 0u);
  or_set_destroy(set);
}

TEST_F(ORSetCompaction, CountTombstonesNull) {
  EXPECT_EQ(vtable->count_tombstones(nullptr), 0u);
}

TEST_F(ORSetCompaction, CountVisible) {
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_add(set, "b", "n1:2");
  or_set_add(set, "c", "n1:3");
  or_set_remove(set, "a");

  // a is tombstoned, b and c are visible
  EXPECT_EQ(vtable->count_visible(set), 2u);
  or_set_destroy(set);
}

TEST_F(ORSetCompaction, CountVisibleNoTombstones) {
  or_set_t* set = or_set_create();
  or_set_add(set, "x", "n1:1");
  or_set_add(set, "y", "n1:2");

  EXPECT_EQ(vtable->count_visible(set), 2u);
  or_set_destroy(set);
}

TEST_F(ORSetCompaction, CountVisibleNull) {
  EXPECT_EQ(vtable->count_visible(nullptr), 0u);
}

TEST_F(ORSetCompaction, ExtractVisible) {
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_add(set, "b", "n1:2");
  or_set_add(set, "c", "n1:3");
  or_set_remove(set, "b");

  or_set_t* visible = (or_set_t*)vtable->extract_visible(set);
  ASSERT_NE(visible, nullptr);
  EXPECT_EQ(visible->element_count, 2u);
  EXPECT_EQ(visible->tombstone_count, 0u);

  EXPECT_TRUE(or_set_contains(visible, "a"));
  EXPECT_TRUE(or_set_contains(visible, "c"));
  EXPECT_FALSE(or_set_contains(visible, "b"));

  or_set_destroy(visible);
  or_set_destroy(set);
}

TEST_F(ORSetCompaction, ExtractVisibleNoTombstones) {
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");

  or_set_t* visible = (or_set_t*)vtable->extract_visible(set);
  ASSERT_NE(visible, nullptr);
  EXPECT_EQ(visible->element_count, 1u);
  EXPECT_EQ(visible->tombstone_count, 0u);

  or_set_destroy(visible);
  or_set_destroy(set);
}

TEST_F(ORSetCompaction, ExtractVisibleNull) {
  EXPECT_EQ(vtable->extract_visible(nullptr), nullptr);
}

TEST_F(ORSetCompaction, RebuildFromVisible) {
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_add(set, "b", "n1:2");

  or_set_t* rebuilt = (or_set_t*)vtable->rebuild_from_visible(set);
  ASSERT_NE(rebuilt, nullptr);
  EXPECT_EQ(rebuilt->element_count, 2u);
  EXPECT_EQ(rebuilt->tombstone_count, 0u);

  or_set_destroy(rebuilt);
  or_set_destroy(set);
}

TEST_F(ORSetCompaction, RebuildFromVisibleNull) {
  EXPECT_EQ(vtable->rebuild_from_visible(nullptr), nullptr);
}

TEST_F(ORSetCompaction, CompactionSafe) {
  or_set_t set = {};
  EXPECT_TRUE(vtable->compaction_safe(&set, nullptr));
}

TEST_F(ORSetCompaction, CompactionSafeNull) {
  EXPECT_FALSE(vtable->compaction_safe(nullptr, nullptr));
}

TEST_F(ORSetCompaction, EstimatedSavings) {
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_add(set, "b", "n1:2");
  or_set_remove(set, "a");

  // 1 tombstone / (2 elements + 1 tombstone) = 1/3 ≈ 0.333
  double savings = vtable->estimated_savings(set);
  EXPECT_NEAR(savings, 0.333, 0.01);
  or_set_destroy(set);
}

TEST_F(ORSetCompaction, EstimatedSavingsEmpty) {
  or_set_t* set = or_set_create();
  EXPECT_DOUBLE_EQ(vtable->estimated_savings(set), 0.0);
  or_set_destroy(set);
}

TEST_F(ORSetCompaction, EstimatedSavingsNull) {
  EXPECT_DOUBLE_EQ(vtable->estimated_savings(nullptr), 0.0);
}

TEST_F(ORSetCompaction, DescribeTombstones) {
  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_remove(set, "a");

  char buf[128];
  vtable->describe_tombstones(set, buf, sizeof(buf));
  EXPECT_NE(buf[0], '\0');
  EXPECT_TRUE(strstr(buf, "OR-Set") != nullptr);
  or_set_destroy(set);
}

TEST_F(ORSetCompaction, DescribeTombstonesNull) {
  char buf[128];
  vtable->describe_tombstones(nullptr, buf, sizeof(buf));
  EXPECT_STREQ(buf, "null or-set");
}

TEST_F(ORSetCompaction, DescribeTombstonesNullBuffer) {
  or_set_t* set = or_set_create();
  vtable->describe_tombstones(set, nullptr, 0);
  // Should not crash
  or_set_destroy(set);
}

// ============================================================
// 2P-Set Compaction Tests
// ============================================================

class TwoPSetCompaction : public ::testing::Test {
protected:
  crabs_compaction_registry_t registry;
  const crabs_compaction_vtable_t* vtable;

  void SetUp() override {
    crabs_compaction_registry_init(&registry);
    crabs_register_two_p_set_vtable(&registry);
    vtable = crabs_compaction_get_vtable(&registry, DATA_TYPE_2P_SET);
    ASSERT_NE(vtable, nullptr);
  }
};

TEST_F(TwoPSetCompaction, CountTombstones) {
  two_p_set_t* set = two_p_set_create();
  two_p_set_add(set, "a");
  two_p_set_add(set, "b");
  two_p_set_remove(set, "a");

  EXPECT_EQ(vtable->count_tombstones(set), 1u);
  two_p_set_destroy(set);
}

TEST_F(TwoPSetCompaction, CountTombstonesEmpty) {
  two_p_set_t* set = two_p_set_create();
  EXPECT_EQ(vtable->count_tombstones(set), 0u);
  two_p_set_destroy(set);
}

TEST_F(TwoPSetCompaction, CountTombstonesNull) {
  EXPECT_EQ(vtable->count_tombstones(nullptr), 0u);
}

TEST_F(TwoPSetCompaction, CountVisible) {
  two_p_set_t* set = two_p_set_create();
  two_p_set_add(set, "a");
  two_p_set_add(set, "b");
  two_p_set_add(set, "c");
  two_p_set_remove(set, "a");

  // Only b and c are visible (a is removed)
  EXPECT_EQ(vtable->count_visible(set), 2u);
  two_p_set_destroy(set);
}

TEST_F(TwoPSetCompaction, CountVisibleNoRemoves) {
  two_p_set_t* set = two_p_set_create();
  two_p_set_add(set, "x");
  two_p_set_add(set, "y");

  EXPECT_EQ(vtable->count_visible(set), 2u);
  two_p_set_destroy(set);
}

TEST_F(TwoPSetCompaction, CountVisibleNull) {
  EXPECT_EQ(vtable->count_visible(nullptr), 0u);
}

TEST_F(TwoPSetCompaction, ExtractVisible) {
  two_p_set_t* set = two_p_set_create();
  two_p_set_add(set, "a");
  two_p_set_add(set, "b");
  two_p_set_add(set, "c");
  two_p_set_remove(set, "b");

  two_p_set_t* visible = (two_p_set_t*)vtable->extract_visible(set);
  ASSERT_NE(visible, nullptr);
  EXPECT_EQ(visible->add_count, 2u);   // a and c
  EXPECT_EQ(visible->remove_count, 0u); // remove_set cleared

  EXPECT_TRUE(two_p_set_contains(visible, "a"));
  EXPECT_TRUE(two_p_set_contains(visible, "c"));
  // After compaction, "b" can be re-added (semantic change!)
  EXPECT_FALSE(two_p_set_contains(visible, "b"));

  two_p_set_destroy(visible);
  two_p_set_destroy(set);
}

TEST_F(TwoPSetCompaction, ExtractVisibleNoRemoves) {
  two_p_set_t* set = two_p_set_create();
  two_p_set_add(set, "a");

  two_p_set_t* visible = (two_p_set_t*)vtable->extract_visible(set);
  ASSERT_NE(visible, nullptr);
  EXPECT_EQ(visible->add_count, 1u);
  EXPECT_EQ(visible->remove_count, 0u);

  two_p_set_destroy(visible);
  two_p_set_destroy(set);
}

TEST_F(TwoPSetCompaction, ExtractVisibleNull) {
  EXPECT_EQ(vtable->extract_visible(nullptr), nullptr);
}

TEST_F(TwoPSetCompaction, RebuildFromVisible) {
  two_p_set_t* set = two_p_set_create();
  two_p_set_add(set, "a");
  two_p_set_add(set, "b");

  two_p_set_t* rebuilt = (two_p_set_t*)vtable->rebuild_from_visible(set);
  ASSERT_NE(rebuilt, nullptr);
  EXPECT_EQ(rebuilt->add_count, 2u);
  EXPECT_EQ(rebuilt->remove_count, 0u);

  two_p_set_destroy(rebuilt);
  two_p_set_destroy(set);
}

TEST_F(TwoPSetCompaction, RebuildFromVisibleNull) {
  EXPECT_EQ(vtable->rebuild_from_visible(nullptr), nullptr);
}

TEST_F(TwoPSetCompaction, CompactionSafe) {
  two_p_set_t set = {};
  EXPECT_TRUE(vtable->compaction_safe(&set, nullptr));
}

TEST_F(TwoPSetCompaction, CompactionSafeNull) {
  EXPECT_FALSE(vtable->compaction_safe(nullptr, nullptr));
}

TEST_F(TwoPSetCompaction, EstimatedSavings) {
  two_p_set_t* set = two_p_set_create();
  two_p_set_add(set, "a");
  two_p_set_add(set, "b");
  two_p_set_add(set, "c");
  two_p_set_remove(set, "a");
  two_p_set_remove(set, "b");

  // remove_count=2, tombstoned_in_add=2 (a,b), total=5
  // savings = (2 + 2) / 5 = 0.8
  double savings = vtable->estimated_savings(set);
  EXPECT_NEAR(savings, 0.8, 0.01);
  two_p_set_destroy(set);
}

TEST_F(TwoPSetCompaction, EstimatedSavingsEmpty) {
  two_p_set_t* set = two_p_set_create();
  EXPECT_DOUBLE_EQ(vtable->estimated_savings(set), 0.0);
  two_p_set_destroy(set);
}

TEST_F(TwoPSetCompaction, EstimatedSavingsNull) {
  EXPECT_DOUBLE_EQ(vtable->estimated_savings(nullptr), 0.0);
}

TEST_F(TwoPSetCompaction, DescribeTombstones) {
  two_p_set_t* set = two_p_set_create();
  two_p_set_add(set, "a");
  two_p_set_remove(set, "a");

  char buf[128];
  vtable->describe_tombstones(set, buf, sizeof(buf));
  EXPECT_NE(buf[0], '\0');
  EXPECT_TRUE(strstr(buf, "2P-Set") != nullptr);
  two_p_set_destroy(set);
}

TEST_F(TwoPSetCompaction, DescribeTombstonesNull) {
  char buf[128];
  vtable->describe_tombstones(nullptr, buf, sizeof(buf));
  EXPECT_STREQ(buf, "null 2p-set");
}

// ============================================================
// Registration Tests
// ============================================================

TEST(CRDTCompaction, RegisterORSetVtable) {
  crabs_compaction_registry_t registry;
  crabs_compaction_registry_init(&registry);

  crabs_error_e err = crabs_register_or_set_vtable(&registry);
  EXPECT_EQ(err, CRABS_SUCCESS);

  const crabs_compaction_vtable_t* vtable =
    crabs_compaction_get_vtable(&registry, DATA_TYPE_SET);
  ASSERT_NE(vtable, nullptr);
  EXPECT_NE(vtable->count_tombstones, nullptr);
  EXPECT_NE(vtable->count_visible, nullptr);
  EXPECT_NE(vtable->extract_visible, nullptr);
  EXPECT_NE(vtable->rebuild_from_visible, nullptr);
  EXPECT_NE(vtable->compaction_safe, nullptr);
}

TEST(CRDTCompaction, RegisterTwoPSetVtable) {
  crabs_compaction_registry_t registry;
  crabs_compaction_registry_init(&registry);

  crabs_error_e err = crabs_register_two_p_set_vtable(&registry);
  EXPECT_EQ(err, CRABS_SUCCESS);

  const crabs_compaction_vtable_t* vtable =
    crabs_compaction_get_vtable(&registry, DATA_TYPE_2P_SET);
  ASSERT_NE(vtable, nullptr);
  EXPECT_NE(vtable->count_tombstones, nullptr);
  EXPECT_NE(vtable->count_visible, nullptr);
  EXPECT_NE(vtable->extract_visible, nullptr);
  EXPECT_NE(vtable->rebuild_from_visible, nullptr);
  EXPECT_NE(vtable->compaction_safe, nullptr);
}

TEST(CRDTCompaction, RegisterAllVtables) {
  crabs_compaction_registry_t registry;
  crabs_compaction_registry_init(&registry);

  crabs_error_e err = crabs_register_crdt_vtables(&registry);
  EXPECT_EQ(err, CRABS_SUCCESS);

  EXPECT_NE(crabs_compaction_get_vtable(&registry, DATA_TYPE_SET), nullptr);
  EXPECT_NE(crabs_compaction_get_vtable(&registry, DATA_TYPE_2P_SET), nullptr);
  EXPECT_EQ(registry.count, 2u);
}

TEST(CRDTCompaction, RegisterNull) {
  EXPECT_EQ(crabs_register_or_set_vtable(nullptr), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(crabs_register_two_p_set_vtable(nullptr), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(crabs_register_crdt_vtables(nullptr), CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Integration: Needs Compaction with OR-Set
// ============================================================

TEST(CRDTCompaction, NeedsCompactionORSet) {
  crabs_compaction_registry_t registry;
  crabs_compaction_registry_init(&registry);
  crabs_register_or_set_vtable(&registry);

  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.max_tombstone_ratio = 0.6;

  or_set_t* set = or_set_create();
  or_set_add(set, "a", "n1:1");
  or_set_add(set, "b", "n1:2");
  or_set_add(set, "c", "n1:3");
  or_set_remove(set, "a");

  data_item_t* item = data_item_create("test_set", DATA_TYPE_SET, CRDT_OR_SET);
  item->value = set;

  // tombstones=1, visible=2, total=3, ratio=1/3=0.33 < 0.6
  EXPECT_FALSE(crabs_needs_compaction(&config, &registry, item));

  or_set_remove(set, "b");
  // tombstones=2, visible=1, total=3, ratio=2/3=0.67 >= 0.6
  EXPECT_TRUE(crabs_needs_compaction(&config, &registry, item));

  or_set_destroy(set);
  item->value = nullptr;
  data_item_destroy(item);
}

TEST(CRDTCompaction, NeedsCompaction2PSet) {
  crabs_compaction_registry_t registry;
  crabs_compaction_registry_init(&registry);
  crabs_register_two_p_set_vtable(&registry);

  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.max_tombstone_ratio = 0.6;

  two_p_set_t* set = two_p_set_create();
  two_p_set_add(set, "a");
  two_p_set_add(set, "b");
  two_p_set_add(set, "c");
  two_p_set_remove(set, "a");

  data_item_t* item = data_item_create("test_set", DATA_TYPE_2P_SET, CRDT_2P_SET);
  item->value = set;

  // remove_count=1, visible=2, total=3, ratio=1/3=0.33 < 0.6
  EXPECT_FALSE(crabs_needs_compaction(&config, &registry, item));

  two_p_set_remove(set, "b");
  // remove_count=2, visible=1, total=3, ratio=2/3=0.67 >= 0.6
  EXPECT_TRUE(crabs_needs_compaction(&config, &registry, item));

  two_p_set_destroy(set);
  item->value = nullptr;
  data_item_destroy(item);
}