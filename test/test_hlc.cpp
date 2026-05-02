//
// Created by victor on 5/2/25.
//
// HLC Core Types & Comparison Tests (v1.6 Amd6 §2-3)
//

#include <gtest/gtest.h>
#include <cstring>
#include <cstdio>

extern "C" {
#include "HLC/hlc.h"
}

// ============================================================
// HLC Initialization Tests
// ============================================================

TEST(HLCCore, StateInitDefaults) {
  crabs_hlc_state_t state;
  crabs_hlc_state_init(&state, "alice");

  EXPECT_EQ(state.last.physical_seconds, 0u);
  EXPECT_EQ(state.last.physical_nanos, 0u);
  EXPECT_EQ(state.last.logical_counter, 0u);
  EXPECT_STREQ(state.last.node_id, "alice");
  EXPECT_EQ(state.time_source, CRABS_TIME_SOURCE_SYSTEM_CLOCK);
  EXPECT_EQ(state.receive_strategy, HLC_STRATEGY_BOUNDED);
  EXPECT_EQ(state.max_skew_ms, CRABS_HLC_DEFAULT_MAX_SKEW_MS);
  EXPECT_EQ(state.quorum_size, CRABS_HLC_DEFAULT_QUORUM_SIZE);
  EXPECT_EQ(state.quorum_timeout_ms, CRABS_HLC_DEFAULT_QUORUM_TIMEOUT_MS);
  EXPECT_EQ(state.trusted_resync_ms, CRABS_HLC_DEFAULT_TRUSTED_RESYNC_MS);
  EXPECT_FALSE(state.strict_mode);
  EXPECT_EQ(state.clock_regressions_detected, 0u);
  EXPECT_EQ(state.time_travel_attempts_rejected, 0u);
  EXPECT_EQ(state.quorum_failures, 0u);
}

TEST(HLCCore, StateInitNullNodeId) {
  crabs_hlc_state_t state;
  crabs_hlc_state_init(&state, NULL);

  EXPECT_EQ(state.last.node_id[0], '\0');
}

TEST(HLCCore, StateInitNullPointer) {
  // Should not crash
  crabs_hlc_state_init(NULL, "alice");
}

TEST(HLCCore, StateInitLongNodeId) {
  crabs_hlc_state_t state;
  char long_id[128];
  memset(long_id, 'A', 127);
  long_id[127] = '\0';

  crabs_hlc_state_init(&state, long_id);

  // Should be truncated to CRABS_HLC_NODE_ID_SIZE-1 chars + null
  EXPECT_EQ(state.last.node_id[CRABS_HLC_NODE_ID_SIZE - 1], '\0');
}

TEST(HLCCore, StateInitStrategyNaive) {
  crabs_hlc_state_t state;
  crabs_hlc_state_init_strategy(&state, "bob", HLC_STRATEGY_NAIVE);

  EXPECT_EQ(state.receive_strategy, HLC_STRATEGY_NAIVE);
  EXPECT_EQ(state.max_skew_ms, CRABS_HLC_DEFAULT_MAX_SKEW_MS);
  EXPECT_FALSE(state.strict_mode);
}

TEST(HLCCore, StateInitStrategyStrict) {
  crabs_hlc_state_t state;
  crabs_hlc_state_init_strategy(&state, "charlie", HLC_STRATEGY_STRICT);

  EXPECT_EQ(state.receive_strategy, HLC_STRATEGY_STRICT);
  EXPECT_TRUE(state.strict_mode);
}

TEST(HLCCore, StateInitStrategyQuorum) {
  crabs_hlc_state_t state;
  crabs_hlc_state_init_strategy(&state, "dave", HLC_STRATEGY_QUORUM);

  EXPECT_EQ(state.receive_strategy, HLC_STRATEGY_QUORUM);
  EXPECT_EQ(state.quorum_size, CRABS_HLC_DEFAULT_QUORUM_SIZE);
  EXPECT_EQ(state.quorum_timeout_ms, CRABS_HLC_DEFAULT_QUORUM_TIMEOUT_MS);
}

TEST(HLCCore, StateInitStrategyTrusted) {
  crabs_hlc_state_t state;
  crabs_hlc_state_init_strategy(&state, "eve", HLC_STRATEGY_TRUSTED);

  EXPECT_EQ(state.receive_strategy, HLC_STRATEGY_TRUSTED);
  EXPECT_EQ(state.trusted_resync_ms, CRABS_HLC_DEFAULT_TRUSTED_RESYNC_MS);
}

// ============================================================
// Ordering Config Tests
// ============================================================

TEST(HLCCore, OrderingConfigInitLamport) {
  crabs_ordering_config_t config;
  crabs_ordering_config_init(&config);

  EXPECT_EQ(config.ordering_system, CRABS_ORDERING_LAMPORT);
}

TEST(HLCCore, OrderingConfigInitHLC) {
  crabs_ordering_config_t config;
  crabs_ordering_config_init_hlc(&config, HLC_STRATEGY_BOUNDED);

  EXPECT_EQ(config.ordering_system, CRABS_ORDERING_HLC);
  EXPECT_EQ(config.hlc.receive_strategy, HLC_STRATEGY_BOUNDED);
  EXPECT_EQ(config.hlc.max_skew_ms, CRABS_HLC_DEFAULT_MAX_SKEW_MS);
  EXPECT_EQ(config.hlc.quorum_size, CRABS_HLC_DEFAULT_QUORUM_SIZE);
  EXPECT_FALSE(config.hlc.strict_mode);
}

TEST(HLCCore, OrderingConfigInitHLCStrict) {
  crabs_ordering_config_t config;
  crabs_ordering_config_init_hlc(&config, HLC_STRATEGY_STRICT);

  EXPECT_EQ(config.ordering_system, CRABS_ORDERING_HLC);
  EXPECT_TRUE(config.hlc.strict_mode);
}

TEST(HLCCore, OrderingConfigInitHLCTrusted) {
  crabs_ordering_config_t config;
  crabs_ordering_config_init_hlc(&config, HLC_STRATEGY_TRUSTED);

  EXPECT_TRUE(config.hlc.trusted_time_source);
}

// ============================================================
// HLC Comparison Tests (§2.2)
// ============================================================

TEST(HLCCore, CompareEqual) {
  crabs_hlc_t a = {36000, 500000000, 0, "alice"};
  crabs_hlc_t b = {36000, 500000000, 0, "alice"};
  EXPECT_EQ(crabs_hlc_compare(&a, &b), 0);
}

TEST(HLCCore, CompareByPhysicalSeconds) {
  crabs_hlc_t a = {36000, 0, 0, "alice"};
  crabs_hlc_t b = {36001, 0, 0, "alice"};
  EXPECT_LT(crabs_hlc_compare(&a, &b), 0);
  EXPECT_GT(crabs_hlc_compare(&b, &a), 0);
}

TEST(HLCCore, CompareByNanos) {
  crabs_hlc_t a = {36000, 400000000, 0, "alice"};
  crabs_hlc_t b = {36000, 500000000, 0, "alice"};
  EXPECT_LT(crabs_hlc_compare(&a, &b), 0);
  EXPECT_GT(crabs_hlc_compare(&b, &a), 0);
}

TEST(HLCCore, CompareByLogicalCounter) {
  crabs_hlc_t a = {36000, 500000000, 5, "alice"};
  crabs_hlc_t b = {36000, 500000000, 10, "alice"};
  EXPECT_LT(crabs_hlc_compare(&a, &b), 0);
  EXPECT_GT(crabs_hlc_compare(&b, &a), 0);
}

TEST(HLCCore, CompareByNodeId) {
  crabs_hlc_t a = {36000, 500000000, 0, "alice"};
  crabs_hlc_t b = {36000, 500000000, 0, "bob"};
  EXPECT_LT(crabs_hlc_compare(&a, &b), 0);
  EXPECT_GT(crabs_hlc_compare(&b, &a), 0);
}

TEST(HLCCore, CompareNullPointers) {
  crabs_hlc_t a = {36000, 0, 0, "alice"};
  EXPECT_EQ(crabs_hlc_compare(NULL, NULL), 0);
  EXPECT_LT(crabs_hlc_compare(NULL, &a), 0);
  EXPECT_GT(crabs_hlc_compare(&a, NULL), 0);
}

TEST(HLCCore, ComparePhysicalSecondsOverridesCounter) {
  // Earlier physical time with higher counter still comes first
  crabs_hlc_t a = {35999, 999999999, 100, "alice"};
  crabs_hlc_t b = {36000, 0, 0, "alice"};
  EXPECT_LT(crabs_hlc_compare(&a, &b), 0);
}

// ============================================================
// HLC Formatting Tests (§2.3)
// ============================================================

TEST(HLCCore, FormatBasic) {
  crabs_hlc_t hlc = {36000, 500123456, 42, "alice"};
  char buf[128];
  int written = crabs_hlc_format(&hlc, buf, sizeof(buf));

  EXPECT_GT(written, 0);
  // 36000 seconds from epoch = 1970-01-01T10:00:00
  EXPECT_NE(strstr(buf, "1970-01-01T10:00:00"), nullptr);
  EXPECT_NE(strstr(buf, "500123456"), nullptr);
  EXPECT_NE(strstr(buf, "#42"), nullptr);
  EXPECT_NE(strstr(buf, "@alice"), nullptr);
}

TEST(HLCCore, FormatNullPointers) {
  crabs_hlc_t hlc = {36000, 0, 0, "alice"};
  char buf[128];
  EXPECT_LT(crabs_hlc_format(NULL, buf, sizeof(buf)), 0);
  EXPECT_LT(crabs_hlc_format(&hlc, NULL, sizeof(buf)), 0);
  EXPECT_LT(crabs_hlc_format(&hlc, buf, 0), 0);
}

TEST(HLCCore, FormatBufferTooSmall) {
  crabs_hlc_t hlc = {36000, 0, 0, "alice"};
  char buf[5];
  EXPECT_LT(crabs_hlc_format(&hlc, buf, sizeof(buf)), 0);
}

// ============================================================
// HLC Normalization Tests (§8.2)
// ============================================================

TEST(HLCCore, NormalizeNoOverflow) {
  crabs_hlc_t hlc = {36000, 500000000, 5, "alice"};
  crabs_hlc_normalize(&hlc);

  EXPECT_EQ(hlc.physical_seconds, 36000u);
  EXPECT_EQ(hlc.physical_nanos, 500000000u);
  EXPECT_EQ(hlc.logical_counter, 5u);
}

TEST(HLCCore, NormalizeSingleOverflow) {
  crabs_hlc_t hlc = {36000, 1000000000, 5, "alice"};
  crabs_hlc_normalize(&hlc);

  EXPECT_EQ(hlc.physical_seconds, 36001u);
  EXPECT_EQ(hlc.physical_nanos, 0u);
  EXPECT_EQ(hlc.logical_counter, 5u);
}

TEST(HLCCore, NormalizeDoubleOverflow) {
  crabs_hlc_t hlc = {36000, 2500000000, 5, "alice"};
  crabs_hlc_normalize(&hlc);

  EXPECT_EQ(hlc.physical_seconds, 36002u);
  EXPECT_EQ(hlc.physical_nanos, 500000000u);
  EXPECT_EQ(hlc.logical_counter, 5u);
}

TEST(HLCCore, NormalizeNullPointer) {
  // Should not crash
  crabs_hlc_normalize(NULL);
}

// ============================================================
// HLC Difference Tests (§4.2)
// ============================================================

TEST(HLCCore, DiffMsAhead) {
  crabs_hlc_t hlc = {36002, 0, 0, "bob"};
  int64_t diff = crabs_hlc_diff_ms(&hlc, 36000, 0);
  EXPECT_EQ(diff, 2000);  // 2 seconds = 2000ms
}

TEST(HLCCore, DiffMsBehind) {
  crabs_hlc_t hlc = {36000, 0, 0, "bob"};
  int64_t diff = crabs_hlc_diff_ms(&hlc, 36002, 0);
  EXPECT_EQ(diff, -2000);  // 2 seconds behind
}

TEST(HLCCore, DiffMsSameTime) {
  crabs_hlc_t hlc = {36000, 500000000, 0, "alice"};
  int64_t diff = crabs_hlc_diff_ms(&hlc, 36000, 500000000);
  EXPECT_EQ(diff, 0);
}

TEST(HLCCore, DiffMsNanosecondPrecision) {
  crabs_hlc_t hlc = {36000, 600000000, 0, "alice"};
  int64_t diff = crabs_hlc_diff_ms(&hlc, 36000, 100000000);
  // 500ms difference
  EXPECT_EQ(diff, 500);
}

// ============================================================
// Enum Values Tests
// ============================================================

TEST(HLCCore, OrderingSystemValues) {
  EXPECT_EQ(CRABS_ORDERING_LAMPORT, 0);
  EXPECT_EQ(CRABS_ORDERING_HLC, 1);
}

TEST(HLCCore, StrategyValues) {
  EXPECT_EQ(HLC_STRATEGY_NAIVE, 0x00);
  EXPECT_EQ(HLC_STRATEGY_BOUNDED, 0x01);
  EXPECT_EQ(HLC_STRATEGY_QUORUM, 0x02);
  EXPECT_EQ(HLC_STRATEGY_STRICT, 0x03);
  EXPECT_EQ(HLC_STRATEGY_TRUSTED, 0x04);
}

TEST(HLCCore, TimeSourceValues) {
  EXPECT_EQ(CRABS_TIME_SOURCE_SYSTEM_CLOCK, 0x00);
  EXPECT_EQ(CRABS_TIME_SOURCE_NTP_AUTH, 0x01);
  EXPECT_EQ(CRABS_TIME_SOURCE_TPM, 0x02);
  EXPECT_EQ(CRABS_TIME_SOURCE_CONSENSUS, 0x03);
}

TEST(HLCCore, ReceiveResultValues) {
  EXPECT_EQ(CRABS_HLC_ACCEPTED, 0);
  EXPECT_EQ(CRABS_HLC_REJECTED_SKEW, 1);
  EXPECT_EQ(CRABS_HLC_REJECTED_QUORUM, 2);
  EXPECT_EQ(CRABS_HLC_REJECTED_TRUST, 3);
  EXPECT_EQ(CRABS_HLC_ACCEPTED_STRICT, 4);
}

// ============================================================
// Defaults Tests
// ============================================================

TEST(HLCCore, DefaultConstants) {
  EXPECT_EQ(CRABS_HLC_DEFAULT_MAX_SKEW_MS, 5000u);
  EXPECT_EQ(CRABS_HLC_DEFAULT_QUORUM_SIZE, 3u);
  EXPECT_EQ(CRABS_HLC_DEFAULT_QUORUM_TIMEOUT_MS, 1000u);
  EXPECT_EQ(CRABS_HLC_DEFAULT_TRUSTED_RESYNC_MS, 30000u);
}