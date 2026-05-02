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

// ============================================================
// Mock Time Source for Deterministic Testing
// ============================================================

static crabs_physical_time_t g_mock_time = {0, 0, false};

static crabs_physical_time_t mock_get_time(void* ctx) {
  (void)ctx;
  return g_mock_time;
}

static bool mock_is_available(void* ctx) {
  (void)ctx;
  return g_mock_time.valid;
}

static crabs_time_source_ops_t g_mock_ops = {
  mock_get_time,
  mock_is_available,
  NULL
};

// Helper: create state with mock time source
static crabs_hlc_state_t make_mock_state(const char* node_id,
                                          uint64_t sec, uint64_t nanos) {
  g_mock_time.seconds = sec;
  g_mock_time.nanos = nanos;
  g_mock_time.valid = true;

  crabs_hlc_state_t state;
  crabs_hlc_state_init(&state, node_id);
  state.time_source_ops = &g_mock_ops;
  return state;
}

// ============================================================
// HLC Generation Tests (§4.1, §12.1-12.3)
// ============================================================

TEST(HLCGeneration, NullState) {
  crabs_hlc_t hlc = crabs_hlc_next(NULL);
  EXPECT_EQ(hlc.physical_seconds, 0u);
  EXPECT_EQ(hlc.physical_nanos, 0u);
  EXPECT_EQ(hlc.logical_counter, 0u);
  EXPECT_STREQ(hlc.node_id, "");
}

// §12.1: Basic HLC Generation
TEST(HLCGeneration, InitialTimestamp) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 500000000);

  crabs_hlc_t hlc = crabs_hlc_next(&state);

  EXPECT_EQ(hlc.physical_seconds, 36000u);
  EXPECT_EQ(hlc.physical_nanos, 500000000u);
  EXPECT_EQ(hlc.logical_counter, 0u);
  EXPECT_STREQ(hlc.node_id, "alice");

  // State should be updated
  EXPECT_EQ(state.last.physical_seconds, 36000u);
  EXPECT_EQ(state.last.physical_nanos, 500000000u);
  EXPECT_EQ(state.last.logical_counter, 0u);
}

// §12.2: Same-Nanosecond Events
TEST(HLCGeneration, SameNanosecondEvents) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 500000000);

  crabs_hlc_t hlc1 = crabs_hlc_next(&state);
  EXPECT_EQ(hlc1.physical_seconds, 36000u);
  EXPECT_EQ(hlc1.physical_nanos, 500000000u);
  EXPECT_EQ(hlc1.logical_counter, 0u);

  // Time doesn't change — same nanosecond
  g_mock_time.seconds = 36000;
  g_mock_time.nanos = 500000000;

  crabs_hlc_t hlc2 = crabs_hlc_next(&state);
  EXPECT_EQ(hlc2.physical_seconds, 36000u);
  EXPECT_EQ(hlc2.physical_nanos, 500000000u);
  EXPECT_EQ(hlc2.logical_counter, 1u);

  // Still same nanosecond
  crabs_hlc_t hlc3 = crabs_hlc_next(&state);
  EXPECT_EQ(hlc3.physical_seconds, 36000u);
  EXPECT_EQ(hlc3.physical_nanos, 500000000u);
  EXPECT_EQ(hlc3.logical_counter, 2u);
}

// §12.2: Events are properly ordered
TEST(HLCGeneration, SameNanosecondOrdering) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 500000000);

  crabs_hlc_t hlc1 = crabs_hlc_next(&state);
  g_mock_time.seconds = 36000;
  g_mock_time.nanos = 500000000;
  crabs_hlc_t hlc2 = crabs_hlc_next(&state);
  crabs_hlc_t hlc3 = crabs_hlc_next(&state);

  EXPECT_LT(crabs_hlc_compare(&hlc1, &hlc2), 0);
  EXPECT_LT(crabs_hlc_compare(&hlc2, &hlc3), 0);
}

// §12.3: Clock Regression
TEST(HLCGeneration, ClockRegression) {
  // Set up initial state with a known timestamp
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 500000000);
  crabs_hlc_next(&state);  // Establish baseline: (36000, 500000000, 0)

  // Now physical clock regresses (jumps backward 600ms)
  g_mock_time.seconds = 35999;
  g_mock_time.nanos = 900000000;

  uint64_t regressions_before = state.clock_regressions_detected;
  crabs_hlc_t hlc = crabs_hlc_next(&state);

  // Should use last known physical time + increment counter
  EXPECT_EQ(hlc.physical_seconds, 36000u);
  EXPECT_EQ(hlc.physical_nanos, 500000000u);
  EXPECT_EQ(hlc.logical_counter, 1u);
  EXPECT_EQ(state.clock_regressions_detected, regressions_before + 1);
}

// Clock regression with same-second but lower nanos
TEST(HLCGeneration, ClockRegressionNanos) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 500000000);
  crabs_hlc_next(&state);

  // Clock regresses within the same second
  g_mock_time.seconds = 36000;
  g_mock_time.nanos = 400000000;  // 100ms before last timestamp

  uint64_t regressions_before = state.clock_regressions_detected;
  crabs_hlc_t hlc = crabs_hlc_next(&state);

  EXPECT_EQ(hlc.physical_seconds, 36000u);
  EXPECT_EQ(hlc.physical_nanos, 500000000u);
  EXPECT_EQ(hlc.logical_counter, 1u);
  EXPECT_EQ(state.clock_regressions_detected, regressions_before + 1);
}

// Time source unavailable
TEST(HLCGeneration, TimeSourceUnavailable) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 500000000);
  crabs_hlc_next(&state);

  // Time source becomes unavailable
  g_mock_time.valid = false;

  crabs_hlc_t hlc = crabs_hlc_next(&state);

  // Should use last known time + increment counter
  EXPECT_EQ(hlc.physical_seconds, 36000u);
  EXPECT_EQ(hlc.physical_nanos, 500000000u);
  EXPECT_EQ(hlc.logical_counter, 1u);
}

// Normal time advance resets counter
TEST(HLCGeneration, NormalAdvanceResetsCounter) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 500000000);

  // Generate same-nanosecond events to build up counter
  crabs_hlc_next(&state);  // counter=0
  crabs_hlc_next(&state);  // counter=1
  crabs_hlc_next(&state);  // counter=2

  // Time advances
  g_mock_time.seconds = 36001;
  g_mock_time.nanos = 0;
  g_mock_time.valid = true;

  crabs_hlc_t hlc = crabs_hlc_next(&state);
  EXPECT_EQ(hlc.physical_seconds, 36001u);
  EXPECT_EQ(hlc.physical_nanos, 0u);
  EXPECT_EQ(hlc.logical_counter, 0u);  // Reset!
}

// Monotonicity guarantee
TEST(HLCGeneration, Monotonicity) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  crabs_hlc_t prev = crabs_hlc_next(&state);

  // Generate 100 events with varying time behavior
  for (int i = 0; i < 100; i++) {
    // Alternate between time advance, same time, and regression
    if (i % 3 == 0) {
      g_mock_time.seconds = 36000 + (i / 3) + 1;
      g_mock_time.nanos = 0;
      g_mock_time.valid = true;
    } else if (i % 3 == 1) {
      // Same nanosecond (no time change)
    } else {
      // Regression
      g_mock_time.seconds = 35999;
      g_mock_time.nanos = 0;
      g_mock_time.valid = true;
    }

    crabs_hlc_t curr = crabs_hlc_next(&state);
    EXPECT_LT(crabs_hlc_compare(&prev, &curr), 0)
      << "Monotonicity violated at iteration " << i;
    prev = curr;
  }
}

// Node ID preserved in generated timestamps
TEST(HLCGeneration, NodeIdPreserved) {
  crabs_hlc_state_t state = make_mock_state("testnode", 36000, 0);
  crabs_hlc_t hlc = crabs_hlc_next(&state);
  EXPECT_STREQ(hlc.node_id, "testnode");
}

// ============================================================
// Physical Time Source Tests (§7)
// ============================================================

TEST(HLCGeneration, SystemTimeSource) {
  crabs_physical_time_t t = crabs_hlc_get_system_time(NULL);
  // System clock should return valid time (epoch > 1700000000 for 2023+)
  EXPECT_TRUE(t.valid);
  EXPECT_GT(t.seconds, 1700000000u);
}

TEST(HLCGeneration, MockTimeSource) {
  g_mock_time.seconds = 36000;
  g_mock_time.nanos = 500000000;
  g_mock_time.valid = true;

  crabs_hlc_state_t state;
  crabs_hlc_state_init(&state, "test");
  state.time_source_ops = &g_mock_ops;

  crabs_physical_time_t t = crabs_hlc_get_physical_time(&state);
  EXPECT_TRUE(t.valid);
  EXPECT_EQ(t.seconds, 36000u);
  EXPECT_EQ(t.nanos, 500000000u);
}

TEST(HLCGeneration, MockTimeSourceUnavailable) {
  g_mock_time.valid = false;

  crabs_hlc_state_t state;
  crabs_hlc_state_init(&state, "test");
  state.time_source_ops = &g_mock_ops;

  crabs_physical_time_t t = crabs_hlc_get_physical_time(&state);
  EXPECT_FALSE(t.valid);
}

TEST(HLCGeneration, DefaultTimeSourceFallsBackToSystemClock) {
  crabs_hlc_state_t state;
  crabs_hlc_state_init(&state, "test");
  // No mock time source — should use system clock
  crabs_physical_time_t t = crabs_hlc_get_physical_time(&state);
  EXPECT_TRUE(t.valid);
}

// ============================================================
// HLC Receive Algorithm Tests (§4.2, §5, §12.4-12.6)
// ============================================================

// Null pointer tests
TEST(HLCReceive, NullPointers) {
  crabs_hlc_state_t state;
  crabs_hlc_state_init(&state, "alice");
  crabs_hlc_t received = {36000, 0, 0, "bob"};

  EXPECT_EQ(crabs_hlc_receive(NULL, &received), CRABS_HLC_REJECTED_SKEW);
  EXPECT_EQ(crabs_hlc_receive(&state, NULL), CRABS_HLC_REJECTED_SKEW);
}

// §12.4: BOUNDED Strategy — Accept
TEST(HLCReceive, BoundedAccept) {
  // Node A: local time = (36000, 0), max_skew_ms = 5000
  // Received from Node B: (36002, 0, 0, "bob") — 2 seconds ahead
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_BOUNDED;
  state.max_skew_ms = 5000;

  crabs_hlc_t received = {36002, 0, 0, "bob"};
  crabs_hlc_receive_result_e result = crabs_hlc_receive(&state, &received);

  EXPECT_EQ(result, CRABS_HLC_ACCEPTED);
  // State should be updated to max(local, received) = (36002, 0, 0)
  EXPECT_EQ(state.last.physical_seconds, 36002u);
  EXPECT_EQ(state.last.physical_nanos, 0u);
  EXPECT_EQ(state.last.logical_counter, 0u);
}

// §12.5: BOUNDED Strategy — Reject (time travel attack)
TEST(HLCReceive, BoundedRejectFuture) {
  // Node A: local time = (36000, 0), max_skew_ms = 5000
  // Received from Node M: (99999, 0, 0, "malicious") — far in future
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_BOUNDED;
  state.max_skew_ms = 5000;

  crabs_hlc_t received = {99999, 0, 0, "malicious"};
  uint64_t rejections_before = state.time_travel_attempts_rejected;
  crabs_hlc_receive_result_e result = crabs_hlc_receive(&state, &received);

  EXPECT_EQ(result, CRABS_HLC_REJECTED_SKEW);
  EXPECT_EQ(state.time_travel_attempts_rejected, rejections_before + 1);
  // State should NOT be updated
  EXPECT_EQ(state.last.physical_seconds, 0u);  // Initial state unchanged
}

// BOUNDED Strategy — Reject past (too far behind)
TEST(HLCReceive, BoundedRejectPast) {
  // Node A: local time = (36000, 0), max_skew_ms = 5000
  // Received from Node M: (35000, 0, 0, "old") — 10 seconds behind
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_BOUNDED;
  state.max_skew_ms = 5000;

  crabs_hlc_t received = {35000, 0, 0, "old"};
  uint64_t rejections_before = state.time_travel_attempts_rejected;
  crabs_hlc_receive_result_e result = crabs_hlc_receive(&state, &received);

  EXPECT_EQ(result, CRABS_HLC_REJECTED_SKEW);
  EXPECT_EQ(state.time_travel_attempts_rejected, rejections_before + 1);
}

// NAIVE Strategy — Accept everything
TEST(HLCReceive, NaiveAcceptsAll) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_NAIVE;

  // Even far-future timestamps accepted
  crabs_hlc_t received = {99999, 0, 0, "malicious"};
  crabs_hlc_receive_result_e result = crabs_hlc_receive(&state, &received);

  EXPECT_EQ(result, CRABS_HLC_ACCEPTED);
  // State should be updated to max(local, received) = (99999, 0, 0)
  EXPECT_EQ(state.last.physical_seconds, 99999u);
}

// §12.6: STRICT Strategy — accept but don't update
TEST(HLCReceive, StrictNoUpdate) {
  // Node A: state.last = (36000, 500, 3, "alice")
  // strict_mode = true
  // Received from Node B: (99999, 0, 0, "bob")
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 500000000);
  state.receive_strategy = HLC_STRATEGY_STRICT;
  state.strict_mode = true;

  // First, set state to a known timestamp
  state.last.physical_seconds = 36000;
  state.last.physical_nanos = 500000000;
  state.last.logical_counter = 3;

  crabs_hlc_t received = {99999, 0, 0, "bob"};
  crabs_hlc_receive_result_e result = crabs_hlc_receive(&state, &received);

  EXPECT_EQ(result, CRABS_HLC_ACCEPTED_STRICT);
  // State should be UNCHANGED
  EXPECT_EQ(state.last.physical_seconds, 36000u);
  EXPECT_EQ(state.last.physical_nanos, 500000000u);
  EXPECT_EQ(state.last.logical_counter, 3u);
}

// Max rule: received ahead of local
TEST(HLCReceive, MaxRuleReceivedAhead) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_NAIVE;
  // Set state to a known timestamp
  state.last = {36000, 0, 0, "alice"};

  crabs_hlc_t received = {36001, 500000000, 0, "bob"};
  crabs_hlc_receive(&state, &received);

  // max(local=36000.0, received=36001.500) = 36001.500
  // max is ahead of last → reset counter
  EXPECT_EQ(state.last.physical_seconds, 36001u);
  EXPECT_EQ(state.last.physical_nanos, 500000000u);
  EXPECT_EQ(state.last.logical_counter, 0u);
}

// Max rule: received same time as last — take max of counters
TEST(HLCReceive, MaxRuleSameTimeMaxCounter) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 500000000);
  state.receive_strategy = HLC_STRATEGY_NAIVE;
  state.last = {36000, 500000000, 3, "alice"};

  crabs_hlc_t received = {36000, 500000000, 7, "bob"};
  crabs_hlc_receive(&state, &received);

  // Same time → take max(3, 7) + 1 = 8
  EXPECT_EQ(state.last.physical_seconds, 36000u);
  EXPECT_EQ(state.last.physical_nanos, 500000000u);
  EXPECT_EQ(state.last.logical_counter, 8u);
}

// Max rule: local counter higher than received
TEST(HLCReceive, MaxRuleSameTimeLocalCounterHigher) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 500000000);
  state.receive_strategy = HLC_STRATEGY_NAIVE;
  state.last = {36000, 500000000, 10, "alice"};

  crabs_hlc_t received = {36000, 500000000, 3, "bob"};
  crabs_hlc_receive(&state, &received);

  // Same time → take max(10, 3) + 1 = 11
  EXPECT_EQ(state.last.logical_counter, 11u);
}

// BOUNDED: time source unavailable → reject
TEST(HLCReceive, BoundedRejectNoTimeSource) {
  crabs_hlc_state_t state;
  crabs_hlc_state_init(&state, "alice");
  state.receive_strategy = HLC_STRATEGY_BOUNDED;
  state.max_skew_ms = 5000;
  state.time_source_ops = &g_mock_ops;

  g_mock_time.valid = false;

  crabs_hlc_t received = {36000, 0, 0, "bob"};
  crabs_hlc_receive_result_e result = crabs_hlc_receive(&state, &received);

  EXPECT_EQ(result, CRABS_HLC_REJECTED_SKEW);
}

// Statistics tracking
TEST(HLCReceive, StatisticsTracking) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_BOUNDED;
  state.max_skew_ms = 5000;

  EXPECT_EQ(state.time_travel_attempts_rejected, 0u);

  // First rejection
  crabs_hlc_t future = {99999, 0, 0, "malicious"};
  crabs_hlc_receive(&state, &future);
  EXPECT_EQ(state.time_travel_attempts_rejected, 1u);

  // Second rejection
  crabs_hlc_receive(&state, &future);
  EXPECT_EQ(state.time_travel_attempts_rejected, 2u);
}

// QUORUM strategy (stub) — accepts
TEST(HLCReceive, QuorumStubAccepts) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_QUORUM;

  crabs_hlc_t received = {36001, 0, 0, "bob"};
  crabs_hlc_receive_result_e result = crabs_hlc_receive(&state, &received);

  // Stub accepts (no network infrastructure to collect confirmations)
  EXPECT_EQ(result, CRABS_HLC_ACCEPTED);
}

// TRUSTED strategy (stub) — accepts
TEST(HLCReceive, TrustedStubAccepts) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_TRUSTED;

  crabs_hlc_t received = {36001, 0, 0, "bob"};
  crabs_hlc_receive_result_e result = crabs_hlc_receive(&state, &received);

  // Stub accepts (no verification infrastructure)
  EXPECT_EQ(result, CRABS_HLC_ACCEPTED);
}

// Multiple receives in sequence
TEST(HLCReceive, MultipleReceives) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_NAIVE;
  state.last = {36000, 0, 0, "alice"};

  // Receive timestamp ahead
  crabs_hlc_t r1 = {36001, 0, 0, "bob"};
  crabs_hlc_receive(&state, &r1);
  EXPECT_EQ(state.last.physical_seconds, 36001u);

  // Receive another timestamp ahead with same time but higher counter
  crabs_hlc_t r2 = {36001, 0, 5, "carol"};
  crabs_hlc_receive(&state, &r2);
  EXPECT_EQ(state.last.logical_counter, 6u);  // max(0, 5) + 1

  // Receive timestamp behind — state unchanged (already ahead)
  crabs_hlc_t r3 = {36000, 500000000, 10, "dave"};
  crabs_hlc_receive(&state, &r3);
  // State stays at (36001, 0, 6) since max(local=36001, received=36000.5) = 36001
  // which equals last, so we go to the "same time" branch with max counter
  EXPECT_EQ(state.last.physical_seconds, 36001u);
}