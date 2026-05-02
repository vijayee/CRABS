//
// Created by victor on 5/1/25.
//
// Tests for Vector Clock & Compaction Safety (CRABS-70)
//

#include <gtest/gtest.h>
extern "C" {
#include "../src/Compaction/vector_clock.h"
#include "../src/Compaction/compaction.h"
#include "../src/CRABS/data_model.h"
}

// ============================================================
// Vector Clock Init Tests
// ============================================================

TEST(VectorClock, InitDefaults) {
  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);
  EXPECT_EQ(vc.count, 0u);
}

TEST(VectorClock, InitNull) {
  crabs_vector_clock_init(nullptr);
  // Should not crash
}

// ============================================================
// Get / Set Tests
// ============================================================

TEST(VectorClock, GetNonExistent) {
  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);
  EXPECT_EQ(crabs_vector_clock_get(&vc, "node1"), 0u);
}

TEST(VectorClock, GetNullParams) {
  EXPECT_EQ(crabs_vector_clock_get(nullptr, "node1"), 0u);
  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);
  EXPECT_EQ(crabs_vector_clock_get(&vc, nullptr), 0u);
}

TEST(VectorClock, SetAndGet) {
  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);

  crabs_error_e err = crabs_vector_clock_set(&vc, "node1", 5);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(vc.count, 1u);
  EXPECT_EQ(crabs_vector_clock_get(&vc, "node1"), 5u);
}

TEST(VectorClock, SetUpdatesExisting) {
  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);

  crabs_vector_clock_set(&vc, "node1", 5);
  crabs_error_e err = crabs_vector_clock_set(&vc, "node1", 10);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(vc.count, 1u);  // Not duplicated
  EXPECT_EQ(crabs_vector_clock_get(&vc, "node1"), 10u);
}

TEST(VectorClock, SetMultipleNodes) {
  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);

  crabs_vector_clock_set(&vc, "node1", 1);
  crabs_vector_clock_set(&vc, "node2", 2);
  crabs_vector_clock_set(&vc, "node3", 3);

  EXPECT_EQ(vc.count, 3u);
  EXPECT_EQ(crabs_vector_clock_get(&vc, "node1"), 1u);
  EXPECT_EQ(crabs_vector_clock_get(&vc, "node2"), 2u);
  EXPECT_EQ(crabs_vector_clock_get(&vc, "node3"), 3u);
}

TEST(VectorClock, SetNullParams) {
  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);
  EXPECT_EQ(crabs_vector_clock_set(nullptr, "node1", 5), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(crabs_vector_clock_set(&vc, nullptr, 5), CRABS_ERR_INVALID_PARAM);
}

TEST(VectorClock, SetExceedsMax) {
  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);

  // Fill to max
  for (uint32_t i = 0; i < CRABS_VC_MAX_NODES; i++) {
    char node_id[CRABS_MAX_USER_ID];
    snprintf(node_id, sizeof(node_id), "node%u", i);
    crabs_error_e err = crabs_vector_clock_set(&vc, node_id, i);
    EXPECT_EQ(err, CRABS_SUCCESS);
  }

  // One more should fail
  crabs_error_e err = crabs_vector_clock_set(&vc, "overflow", 999);
  EXPECT_EQ(err, CRABS_ERR_OOM);
}

// ============================================================
// Increment Tests
// ============================================================

TEST(VectorClock, IncrementNewNode) {
  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);

  crabs_error_e err = crabs_vector_clock_increment(&vc, "node1");
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(crabs_vector_clock_get(&vc, "node1"), 1u);
}

TEST(VectorClock, IncrementExistingNode) {
  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);

  crabs_vector_clock_set(&vc, "node1", 5);
  crabs_error_e err = crabs_vector_clock_increment(&vc, "node1");
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(crabs_vector_clock_get(&vc, "node1"), 6u);
}

TEST(VectorClock, IncrementMultiple) {
  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);

  crabs_vector_clock_increment(&vc, "node1");
  crabs_vector_clock_increment(&vc, "node1");
  crabs_vector_clock_increment(&vc, "node1");

  EXPECT_EQ(crabs_vector_clock_get(&vc, "node1"), 3u);
}

TEST(VectorClock, IncrementNullParams) {
  EXPECT_EQ(crabs_vector_clock_increment(nullptr, "node1"), CRABS_ERR_INVALID_PARAM);

  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);
  EXPECT_EQ(crabs_vector_clock_increment(&vc, nullptr), CRABS_ERR_INVALID_PARAM);
}

// ============================================================
// Merge Tests
// ============================================================

TEST(VectorClock, MergeBasic) {
  crabs_vector_clock_t vc1;
  crabs_vector_clock_init(&vc1);
  crabs_vector_clock_set(&vc1, "node1", 3);
  crabs_vector_clock_set(&vc1, "node2", 5);

  crabs_vector_clock_t vc2;
  crabs_vector_clock_init(&vc2);
  crabs_vector_clock_set(&vc2, "node1", 5);
  crabs_vector_clock_set(&vc2, "node3", 7);

  crabs_vector_clock_merge(&vc1, &vc2);

  // node1: max(3, 5) = 5
  EXPECT_EQ(crabs_vector_clock_get(&vc1, "node1"), 5u);
  // node2: only in vc1, stays 5
  EXPECT_EQ(crabs_vector_clock_get(&vc1, "node2"), 5u);
  // node3: only in vc2, added with 7
  EXPECT_EQ(crabs_vector_clock_get(&vc1, "node3"), 7u);
  EXPECT_EQ(vc1.count, 3u);
}

TEST(VectorClock, MergeNullParams) {
  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);
  EXPECT_EQ(crabs_vector_clock_merge(nullptr, &vc), CRABS_ERR_INVALID_PARAM);
  EXPECT_EQ(crabs_vector_clock_merge(&vc, nullptr), CRABS_ERR_INVALID_PARAM);
}

TEST(VectorClock, MergeEmpty) {
  crabs_vector_clock_t vc1;
  crabs_vector_clock_init(&vc1);
  crabs_vector_clock_set(&vc1, "node1", 3);

  crabs_vector_clock_t vc2;
  crabs_vector_clock_init(&vc2);

  crabs_vector_clock_merge(&vc1, &vc2);
  EXPECT_EQ(vc1.count, 1u);
  EXPECT_EQ(crabs_vector_clock_get(&vc1, "node1"), 3u);
}

TEST(VectorClock, MergeIntoEmpty) {
  crabs_vector_clock_t vc1;
  crabs_vector_clock_init(&vc1);

  crabs_vector_clock_t vc2;
  crabs_vector_clock_init(&vc2);
  crabs_vector_clock_set(&vc2, "node1", 3);

  crabs_error_e err = crabs_vector_clock_merge(&vc1, &vc2);
  EXPECT_EQ(err, CRABS_SUCCESS);
  EXPECT_EQ(vc1.count, 1u);
  EXPECT_EQ(crabs_vector_clock_get(&vc1, "node1"), 3u);
}

TEST(VectorClock, MergeOom) {
  crabs_vector_clock_t vc1;
  crabs_vector_clock_init(&vc1);

  // Fill vc1 to max
  for (uint32_t i = 0; i < CRABS_VC_MAX_NODES; i++) {
    char node_id[CRABS_MAX_USER_ID];
    snprintf(node_id, sizeof(node_id), "n%u", i);
    crabs_vector_clock_set(&vc1, node_id, i);
  }

  // vc2 has a node not in vc1 — merge should fail with OOM
  crabs_vector_clock_t vc2;
  crabs_vector_clock_init(&vc2);
  crabs_vector_clock_set(&vc2, "newnode", 1);

  crabs_error_e err = crabs_vector_clock_merge(&vc1, &vc2);
  EXPECT_EQ(err, CRABS_ERR_OOM);
}

// ============================================================
// Copy Tests
// ============================================================

TEST(VectorClock, Copy) {
  crabs_vector_clock_t vc1;
  crabs_vector_clock_init(&vc1);
  crabs_vector_clock_set(&vc1, "node1", 5);
  crabs_vector_clock_set(&vc1, "node2", 10);

  crabs_vector_clock_t vc2;
  crabs_vector_clock_copy(&vc2, &vc1);

  EXPECT_EQ(vc2.count, 2u);
  EXPECT_EQ(crabs_vector_clock_get(&vc2, "node1"), 5u);
  EXPECT_EQ(crabs_vector_clock_get(&vc2, "node2"), 10u);
}

TEST(VectorClock, CopyNullParams) {
  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);
  crabs_vector_clock_copy(nullptr, &vc);
  crabs_vector_clock_copy(&vc, nullptr);
  // Should not crash
}

// ============================================================
// Dominates Tests
// ============================================================

TEST(VectorClock, DominatesEqual) {
  crabs_vector_clock_t vc1;
  crabs_vector_clock_init(&vc1);
  crabs_vector_clock_set(&vc1, "node1", 5);

  crabs_vector_clock_t vc2;
  crabs_vector_clock_init(&vc2);
  crabs_vector_clock_set(&vc2, "node1", 5);

  EXPECT_TRUE(crabs_vector_clock_dominates(&vc1, &vc2));
}

TEST(VectorClock, DominatesGreater) {
  crabs_vector_clock_t vc1;
  crabs_vector_clock_init(&vc1);
  crabs_vector_clock_set(&vc1, "node1", 10);

  crabs_vector_clock_t vc2;
  crabs_vector_clock_init(&vc2);
  crabs_vector_clock_set(&vc2, "node1", 5);

  EXPECT_TRUE(crabs_vector_clock_dominates(&vc1, &vc2));
}

TEST(VectorClock, DominatesLess) {
  crabs_vector_clock_t vc1;
  crabs_vector_clock_init(&vc1);
  crabs_vector_clock_set(&vc1, "node1", 3);

  crabs_vector_clock_t vc2;
  crabs_vector_clock_init(&vc2);
  crabs_vector_clock_set(&vc2, "node1", 5);

  EXPECT_FALSE(crabs_vector_clock_dominates(&vc1, &vc2));
}

TEST(VectorClock, DominatesConcurrent) {
  crabs_vector_clock_t vc1;
  crabs_vector_clock_init(&vc1);
  crabs_vector_clock_set(&vc1, "node1", 10);
  crabs_vector_clock_set(&vc1, "node2", 3);

  crabs_vector_clock_t vc2;
  crabs_vector_clock_init(&vc2);
  crabs_vector_clock_set(&vc2, "node1", 5);
  crabs_vector_clock_set(&vc2, "node2", 7);

  // Neither dominates: node1 > but node2 <
  EXPECT_FALSE(crabs_vector_clock_dominates(&vc1, &vc2));
  EXPECT_FALSE(crabs_vector_clock_dominates(&vc2, &vc1));
}

TEST(VectorClock, DominatesSuperset) {
  crabs_vector_clock_t vc1;
  crabs_vector_clock_init(&vc1);
  crabs_vector_clock_set(&vc1, "node1", 5);
  crabs_vector_clock_set(&vc1, "node2", 3);

  crabs_vector_clock_t vc2;
  crabs_vector_clock_init(&vc2);
  crabs_vector_clock_set(&vc2, "node1", 5);

  // vc1 has all entries vc2 has, and they're >=
  EXPECT_TRUE(crabs_vector_clock_dominates(&vc1, &vc2));
}

TEST(VectorClock, DominatesNullParams) {
  EXPECT_FALSE(crabs_vector_clock_dominates(nullptr, nullptr));

  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);
  EXPECT_FALSE(crabs_vector_clock_dominates(&vc, nullptr));
  EXPECT_FALSE(crabs_vector_clock_dominates(nullptr, &vc));
}

// ============================================================
// Count Tests
// ============================================================

TEST(VectorClock, Count) {
  crabs_vector_clock_t vc;
  crabs_vector_clock_init(&vc);
  EXPECT_EQ(crabs_vector_clock_count(&vc), 0u);

  crabs_vector_clock_set(&vc, "node1", 1);
  EXPECT_EQ(crabs_vector_clock_count(&vc), 1u);

  crabs_vector_clock_set(&vc, "node2", 2);
  EXPECT_EQ(crabs_vector_clock_count(&vc), 2u);
}

TEST(VectorClock, CountNull) {
  EXPECT_EQ(crabs_vector_clock_count(nullptr), 0u);
}

// ============================================================
// Compaction Safety Tests
// ============================================================

TEST(CompactionSafety, ForceAlwaysSafe) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init_strategy(&config, CRABS_COMPACT_NONE);
  // NONE strategy sets safety_level to FORCE
  EXPECT_EQ(config.safety_level, CRABS_SAFETY_FORCE);

  EXPECT_TRUE(crabs_check_compaction_safety(&config, nullptr, nullptr, nullptr, nullptr));
}

TEST(CompactionSafety, StrongAllAcknowledged) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.safety_level = CRABS_SAFETY_STRONG;

  crabs_vector_clock_t local;
  crabs_vector_clock_init(&local);
  crabs_vector_clock_set(&local, "node1", 5);
  crabs_vector_clock_set(&local, "node2", 3);

  crabs_vector_clock_t peer;
  crabs_vector_clock_init(&peer);
  crabs_vector_clock_set(&peer, "node1", 5);
  crabs_vector_clock_set(&peer, "node2", 3);

  state_t* state = state_create();
  data_item_t* item = data_item_create("test", DATA_TYPE_COUNTER, CRDT_G_COUNTER);

  EXPECT_TRUE(crabs_check_compaction_safety(&config, state, item, &local, &peer));

  state_destroy(state);
  data_item_destroy(item);
}

TEST(CompactionSafety, StrongNotAllAcknowledged) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.safety_level = CRABS_SAFETY_STRONG;

  crabs_vector_clock_t local;
  crabs_vector_clock_init(&local);
  crabs_vector_clock_set(&local, "node1", 3);

  crabs_vector_clock_t peer;
  crabs_vector_clock_init(&peer);
  crabs_vector_clock_set(&peer, "node1", 5);

  state_t* state = state_create();
  data_item_t* item = data_item_create("test", DATA_TYPE_COUNTER, CRDT_G_COUNTER);

  EXPECT_FALSE(crabs_check_compaction_safety(&config, state, item, &local, &peer));

  state_destroy(state);
  data_item_destroy(item);
}

TEST(CompactionSafety, StrongNullClocks) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.safety_level = CRABS_SAFETY_STRONG;

  EXPECT_FALSE(crabs_check_compaction_safety(&config, nullptr, nullptr, nullptr, nullptr));
}

TEST(CompactionSafety, QuorumMet) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.safety_level = CRABS_SAFETY_QUORUM;
  config.quorum_threshold = 2;

  crabs_vector_clock_t local;
  crabs_vector_clock_init(&local);
  crabs_vector_clock_set(&local, "node1", 5);
  crabs_vector_clock_set(&local, "node2", 3);
  crabs_vector_clock_set(&local, "node3", 7);

  crabs_vector_clock_t peer;
  crabs_vector_clock_init(&peer);
  crabs_vector_clock_set(&peer, "node1", 5);
  crabs_vector_clock_set(&peer, "node2", 3);
  crabs_vector_clock_set(&peer, "node3", 10);

  state_t* state = state_create();
  data_item_t* item = data_item_create("test", DATA_TYPE_COUNTER, CRDT_G_COUNTER);

  // node1: 5 >= 5 ✓, node2: 3 >= 3 ✓, node3: 7 < 10 ✗ → 2/3 acknowledged
  EXPECT_TRUE(crabs_check_compaction_safety(&config, state, item, &local, &peer));

  state_destroy(state);
  data_item_destroy(item);
}

TEST(CompactionSafety, QuorumNotMet) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.safety_level = CRABS_SAFETY_QUORUM;
  config.quorum_threshold = 3;

  crabs_vector_clock_t local;
  crabs_vector_clock_init(&local);
  crabs_vector_clock_set(&local, "node1", 5);
  crabs_vector_clock_set(&local, "node2", 3);

  crabs_vector_clock_t peer;
  crabs_vector_clock_init(&peer);
  crabs_vector_clock_set(&peer, "node1", 5);
  crabs_vector_clock_set(&peer, "node2", 10);
  crabs_vector_clock_set(&peer, "node3", 7);

  state_t* state = state_create();
  data_item_t* item = data_item_create("test", DATA_TYPE_COUNTER, CRDT_G_COUNTER);

  // node1: 5 >= 5 ✓, node2: 3 < 10 ✗, node3: 0 < 7 ✗ → 1/3 acknowledged
  EXPECT_FALSE(crabs_check_compaction_safety(&config, state, item, &local, &peer));

  state_destroy(state);
  data_item_destroy(item);
}

TEST(CompactionSafety, QuorumNoPeers) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init(&config);
  config.safety_level = CRABS_SAFETY_QUORUM;
  config.quorum_threshold = 2;

  crabs_vector_clock_t local;
  crabs_vector_clock_init(&local);

  crabs_vector_clock_t peer;
  crabs_vector_clock_init(&peer);

  state_t* state = state_create();
  data_item_t* item = data_item_create("test", DATA_TYPE_COUNTER, CRDT_G_COUNTER);

  // No peers to wait for — always safe
  EXPECT_TRUE(crabs_check_compaction_safety(&config, state, item, &local, &peer));

  state_destroy(state);
  data_item_destroy(item);
}

TEST(CompactionSafety, TimestampSafe) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init_strategy(&config, CRABS_COMPACT_TIME_BASED);
  EXPECT_EQ(config.safety_level, CRABS_SAFETY_TIMESTAMP);

  crabs_vector_clock_t local;
  crabs_vector_clock_init(&local);
  crabs_vector_clock_t peer;
  crabs_vector_clock_init(&peer);

  state_t* state = state_create();
  state->version = 10;
  data_item_t* item = data_item_create("test", DATA_TYPE_COUNTER, CRDT_G_COUNTER);

  EXPECT_TRUE(crabs_check_compaction_safety(&config, state, item, &local, &peer));

  state_destroy(state);
  data_item_destroy(item);
}

TEST(CompactionSafety, TimestampNullState) {
  crabs_tombstone_config_t config;
  crabs_tombstone_config_init_strategy(&config, CRABS_COMPACT_TIME_BASED);

  EXPECT_FALSE(crabs_check_compaction_safety(&config, nullptr, nullptr, nullptr, nullptr));
}

TEST(CompactionSafety, NullConfig) {
  EXPECT_FALSE(crabs_check_compaction_safety(nullptr, nullptr, nullptr, nullptr, nullptr));
}