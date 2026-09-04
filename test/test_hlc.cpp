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
#include "Serialization/serialization.h"
#include "StateMachine/state_machine.h"
#include "Crypto/crypto.h"
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

TEST(HLCGeneration, HttpsAuthWithoutOpsFailsClosed) {
  // R8-H-1: HTTPS_AUTH must not fall back to the unauthenticated system clock
  // when no time source ops are attached. Fail closed instead.
  crabs_hlc_state_t state;
  crabs_hlc_state_init(&state, "alice");
  state.time_source = CRABS_TIME_SOURCE_HTTPS_AUTH;
  state.time_source_ops = NULL;

  crabs_physical_time_t phys = crabs_hlc_get_physical_time(&state);
  EXPECT_FALSE(phys.valid);
}

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

// QUORUM strategy (not implemented) — fails closed (rejects) rather than
// accepting blindly. The audit (H-12) found the prior stub accepted every
// timestamp, providing no time-travel protection.
TEST(HLCReceive, QuorumStubRejects) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_QUORUM;

  crabs_hlc_t received = {36001, 0, 0, "bob"};
  crabs_hlc_receive_result_e result = crabs_hlc_receive(&state, &received);

  EXPECT_EQ(result, CRABS_HLC_REJECTED_SKEW);
}

// TRUSTED strategy (not implemented) — fails closed (rejects).
TEST(HLCReceive, TrustedStubRejects) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_TRUSTED;

  crabs_hlc_t received = {36001, 0, 0, "bob"};
  crabs_hlc_receive_result_e result = crabs_hlc_receive(&state, &received);

  EXPECT_EQ(result, CRABS_HLC_REJECTED_SKEW);
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

// ============================================================
// Cross-System Operation Ordering Tests (§10.2)
// ============================================================

extern "C" {
#include "StateMachine/state_machine.h"
}

// §12.7: Cross-System Ordering — Lamport before HLC
TEST(HLCOrdering, LamportBeforeHLC) {
  operation_t a, b;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));

  // Operation A: Lamport (lamport_time=42, node="alice")
  a.ordering_system = CRABS_ORDERING_LAMPORT;
  a.lamport_time = 42;
  strncpy(a.node_id, "alice", CRABS_MAX_USER_ID - 1);

  // Operation B: HLC (36000, 500, 0, "bob")
  b.ordering_system = CRABS_ORDERING_HLC;
  b.hlc = {36000, 500000000, 0, "bob"};

  EXPECT_LT(crabs_operation_compare(&a, &b), 0);  // A < B
  EXPECT_GT(crabs_operation_compare(&b, &a), 0);  // B > A
}

// Lamport operations compared by lamport_time
TEST(HLCOrdering, LamportOrderingByTime) {
  operation_t a, b;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));

  a.ordering_system = CRABS_ORDERING_LAMPORT;
  a.lamport_time = 10;
  strncpy(a.node_id, "alice", CRABS_MAX_USER_ID - 1);

  b.ordering_system = CRABS_ORDERING_LAMPORT;
  b.lamport_time = 20;
  strncpy(b.node_id, "bob", CRABS_MAX_USER_ID - 1);

  EXPECT_LT(crabs_operation_compare(&a, &b), 0);  // 10 < 20
  EXPECT_GT(crabs_operation_compare(&b, &a), 0);  // 20 > 10
}

// Lamport operations with same time compared by node_id
TEST(HLCOrdering, LamportOrderingByNodeId) {
  operation_t a, b;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));

  a.ordering_system = CRABS_ORDERING_LAMPORT;
  a.lamport_time = 42;
  strncpy(a.node_id, "alice", CRABS_MAX_USER_ID - 1);

  b.ordering_system = CRABS_ORDERING_LAMPORT;
  b.lamport_time = 42;
  strncpy(b.node_id, "bob", CRABS_MAX_USER_ID - 1);

  EXPECT_LT(crabs_operation_compare(&a, &b), 0);  // alice < bob
}

// HLC operations compared by HLC fields
TEST(HLCOrdering, HLCOrderingByTime) {
  operation_t a, b;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));

  a.ordering_system = CRABS_ORDERING_HLC;
  a.hlc = {36000, 0, 0, "alice"};
  strncpy(a.node_id, "alice", CRABS_MAX_USER_ID - 1);

  b.ordering_system = CRABS_ORDERING_HLC;
  b.hlc = {36001, 0, 0, "bob"};
  strncpy(b.node_id, "bob", CRABS_MAX_USER_ID - 1);

  EXPECT_LT(crabs_operation_compare(&a, &b), 0);
  EXPECT_GT(crabs_operation_compare(&b, &a), 0);
}

// HLC operations with same physical time compared by counter
TEST(HLCOrdering, HLCOrderingByCounter) {
  operation_t a, b;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));

  a.ordering_system = CRABS_ORDERING_HLC;
  a.hlc = {36000, 500000000, 3, "alice"};
  strncpy(a.node_id, "alice", CRABS_MAX_USER_ID - 1);

  b.ordering_system = CRABS_ORDERING_HLC;
  b.hlc = {36000, 500000000, 7, "alice"};
  strncpy(b.node_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_LT(crabs_operation_compare(&a, &b), 0);  // 3 < 7
}

// Equal operations
TEST(HLCOrdering, EqualOperations) {
  operation_t a, b;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));

  a.ordering_system = CRABS_ORDERING_LAMPORT;
  a.lamport_time = 42;
  strncpy(a.node_id, "alice", CRABS_MAX_USER_ID - 1);

  b.ordering_system = CRABS_ORDERING_LAMPORT;
  b.lamport_time = 42;
  strncpy(b.node_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(crabs_operation_compare(&a, &b), 0);
}

// Null pointer handling
TEST(HLCOrdering, NullPointers) {
  operation_t a;
  memset(&a, 0, sizeof(a));
  a.ordering_system = CRABS_ORDERING_LAMPORT;
  a.lamport_time = 42;
  strncpy(a.node_id, "alice", CRABS_MAX_USER_ID - 1);

  EXPECT_EQ(crabs_operation_compare(NULL, NULL), 0);
  EXPECT_LT(crabs_operation_compare(NULL, &a), 0);
  EXPECT_GT(crabs_operation_compare(&a, NULL), 0);
}

// Default ordering_system is LAMPORT (backward compat)
TEST(HLCOrdering, DefaultOrderingIsLamport) {
  operation_t op;
  memset(&op, 0, sizeof(op));

  // After memset, ordering_system should be 0 = CRABS_ORDERING_LAMPORT
  EXPECT_EQ(op.ordering_system, CRABS_ORDERING_LAMPORT);
}

// ============================================================
// Ordering Config Integration Tests (§6.3)
// ============================================================

TEST(HLCOrdering, StateSetOrderingConfig) {
  state_t* state = state_create();

  // Default is NULL (Lamport)
  crabs_ordering_config_t* config = state_get_ordering_config(state);
  EXPECT_EQ(config, nullptr);

  // Set HLC config
  crabs_ordering_config_t hlc_config;
  crabs_ordering_config_init_hlc(&hlc_config, HLC_STRATEGY_BOUNDED);
  state_set_ordering_config(state, &hlc_config);

  config = state_get_ordering_config(state);
  EXPECT_NE(config, nullptr);
  EXPECT_EQ(config->ordering_system, CRABS_ORDERING_HLC);

  state_destroy(state);
}

TEST(HLCOrdering, StateSetNullConfig) {
  state_t* state = state_create();

  // Set NULL config (revert to default Lamport)
  state_set_ordering_config(state, NULL);

  crabs_ordering_config_t* config = state_get_ordering_config(state);
  EXPECT_EQ(config, nullptr);

  state_destroy(state);
}

TEST(HLCOrdering, LogEntryHasOrderingFields) {
  log_entry_t entry;
  memset(&entry, 0, sizeof(entry));

  // After memset, ordering_system should be 0 = LAMPORT
  EXPECT_EQ(entry.ordering_system, CRABS_ORDERING_LAMPORT);

  // Set HLC fields
  entry.ordering_system = CRABS_ORDERING_HLC;
  entry.hlc = {36000, 500000000, 42, "alice"};

  EXPECT_EQ(entry.ordering_system, CRABS_ORDERING_HLC);
  EXPECT_EQ(entry.hlc.physical_seconds, 36000u);
  EXPECT_EQ(entry.hlc.physical_nanos, 500000000u);
  EXPECT_EQ(entry.hlc.logical_counter, 42u);
  EXPECT_STREQ(entry.hlc.node_id, "alice");
}

// ============================================================
// HLC Serialization Tests (§9)
// ============================================================

TEST(HLCSerialization, SerializeDeserialize) {
  crabs_hlc_t original = {36000, 500123456, 42, "alice"};
  uint8_t buf[128];

  size_t written = crabs_hlc_serialize(&original, buf, sizeof(buf));
  EXPECT_GT(written, 0u);

  // Expected: 8 + 8 + 8 + 2 + 5 = 31 bytes
  EXPECT_EQ(written, 31u);

  crabs_hlc_t decoded;
  memset(&decoded, 0, sizeof(decoded));
  size_t consumed = crabs_hlc_deserialize(&decoded, buf, written);
  EXPECT_EQ(consumed, written);

  EXPECT_EQ(decoded.physical_seconds, 36000u);
  EXPECT_EQ(decoded.physical_nanos, 500123456u);
  EXPECT_EQ(decoded.logical_counter, 42u);
  EXPECT_STREQ(decoded.node_id, "alice");
}

TEST(HLCSerialization, SerializeEmptyNodeId) {
  crabs_hlc_t original = {36000, 0, 0, ""};
  uint8_t buf[64];

  size_t written = crabs_hlc_serialize(&original, buf, sizeof(buf));
  EXPECT_EQ(written, 26u);  // 26 + 0 bytes for empty node_id

  crabs_hlc_t decoded;
  size_t consumed = crabs_hlc_deserialize(&decoded, buf, written);
  EXPECT_EQ(consumed, 26u);
  EXPECT_STREQ(decoded.node_id, "");
}

TEST(HLCSerialization, SerializeBufferTooSmall) {
  crabs_hlc_t original = {36000, 0, 0, "alice"};
  uint8_t buf[10];  // Too small

  size_t written = crabs_hlc_serialize(&original, buf, sizeof(buf));
  EXPECT_EQ(written, 0u);
}

TEST(HLCSerialization, DeserializeBufferTooShort) {
  crabs_hlc_t decoded;
  uint8_t data[10];  // Too short
  memset(data, 0, sizeof(data));

  size_t consumed = crabs_hlc_deserialize(&decoded, data, sizeof(data));
  EXPECT_EQ(consumed, 0u);
}

TEST(HLCSerialization, DeserializeInvalidNanos) {
  // Create serialized data with invalid nanos >= 1B
  uint8_t buf[32];
  memset(buf, 0, sizeof(buf));

  // physical_seconds = 36000
  // physical_nanos = 1000000000 (invalid)
  uint64_t invalid_nanos = 1000000000ULL;
  for (int i = 7; i >= 0; i--) {
    buf[8 + (7 - i)] = (uint8_t)(invalid_nanos >> (i * 8));
  }

  crabs_hlc_t decoded;
  size_t consumed = crabs_hlc_deserialize(&decoded, buf, sizeof(buf));
  EXPECT_EQ(consumed, 0u);  // Should reject invalid nanos
}

TEST(HLCSerialization, NullPointers) {
  crabs_hlc_t hlc = {36000, 0, 0, "alice"};
  uint8_t buf[64];

  EXPECT_EQ(crabs_hlc_serialize(NULL, buf, sizeof(buf)), 0u);
  EXPECT_EQ(crabs_hlc_serialize(&hlc, NULL, sizeof(buf)), 0u);

  EXPECT_EQ(crabs_hlc_deserialize(NULL, buf, sizeof(buf)), 0u);
  EXPECT_EQ(crabs_hlc_deserialize(&hlc, NULL, sizeof(buf)), 0u);
}

TEST(HLCSerialization, LongNodeId) {
  char long_id[63];
  memset(long_id, 'X', 62);
  long_id[62] = '\0';

  crabs_hlc_t original = {36000, 500000000, 10, ""};
  strncpy(original.node_id, long_id, CRABS_HLC_NODE_ID_SIZE - 1);

  uint8_t buf[128];
  size_t written = crabs_hlc_serialize(&original, buf, sizeof(buf));
  EXPECT_GT(written, 0u);

  crabs_hlc_t decoded;
  size_t consumed = crabs_hlc_deserialize(&decoded, buf, written);
  EXPECT_EQ(consumed, written);
  EXPECT_STREQ(decoded.node_id, long_id);
}

TEST(HLCSerialization, CanonicalSigningIncludesOrderingSystem) {
  // Create a Lamport operation and verify serialization includes ordering_system
  operation_t op;
  memset(&op, 0, sizeof(op));
  strncpy(op.type, "__lock__", CRABS_MAX_OP_NAME - 1);
  op.ordering_system = CRABS_ORDERING_LAMPORT;
  op.lamport_time = 42;
  strncpy(op.node_id, "alice", CRABS_MAX_USER_ID - 1);

  serialized_buffer_t* sig_data = crabs_serialize_for_signing(&op);
  EXPECT_NE(sig_data, nullptr);
  EXPECT_GT(sig_data->len, 0u);

  serialized_buffer_destroy(sig_data);
}

TEST(HLCSerialization, CanonicalSigningHLCOperation) {
  // Create an HLC operation and verify serialization includes HLC fields
  operation_t op;
  memset(&op, 0, sizeof(op));
  strncpy(op.type, "__lock__", CRABS_MAX_OP_NAME - 1);
  op.ordering_system = CRABS_ORDERING_HLC;
  op.hlc = {36000, 500000000, 42, "alice"};
  strncpy(op.node_id, "alice", CRABS_MAX_USER_ID - 1);

  serialized_buffer_t* sig_data = crabs_serialize_for_signing(&op);
  EXPECT_NE(sig_data, nullptr);
  EXPECT_GT(sig_data->len, 0u);

  // HLC operation should serialize more bytes than Lamport
  // (due to extra HLC fields)
  operation_t lamport_op;
  memset(&lamport_op, 0, sizeof(lamport_op));
  strncpy(lamport_op.type, "__lock__", CRABS_MAX_OP_NAME - 1);
  lamport_op.ordering_system = CRABS_ORDERING_LAMPORT;
  lamport_op.lamport_time = 42;
  strncpy(lamport_op.node_id, "alice", CRABS_MAX_USER_ID - 1);

  serialized_buffer_t* lamport_data = crabs_serialize_for_signing(&lamport_op);
  EXPECT_NE(lamport_data, nullptr);
  // HLC has 3 extra uint64 fields (24 bytes) plus length-prefixed node_id
  EXPECT_GT(sig_data->len, lamport_data->len);

  serialized_buffer_destroy(sig_data);
  serialized_buffer_destroy(lamport_data);
}

// ============================================================
// HLC Lock Integration Tests (v1.6 Amd6 §8)
// ============================================================

TEST(HLCLockIntegration, LockPriorityEarlierWins) {
  // Earlier timestamp wins (first-come, first-served)
  crabs_hlc_t earlier = {1000, 500000000, 0, "alice"};
  crabs_hlc_t later = {1000, 600000000, 0, "bob"};

  int result = crabs_hlc_lock_priority(&earlier, &later);
  EXPECT_LT(result, 0);  // earlier wins → returns negative
}

TEST(HLCLockIntegration, LockPriorityLaterLoses) {
  crabs_hlc_t earlier = {1000, 500000000, 0, "alice"};
  crabs_hlc_t later = {1000, 600000000, 0, "bob"};

  int result = crabs_hlc_lock_priority(&later, &earlier);
  EXPECT_GT(result, 0);  // later loses → returns positive
}

TEST(HLCLockIntegration, LockPriorityTiebreakerNodeId) {
  crabs_hlc_t a = {1000, 500000000, 5, "alice"};
  crabs_hlc_t b = {1000, 500000000, 5, "bob"};

  // Same timestamp and counter, node_id breaks tie
  int result = crabs_hlc_lock_priority(&a, &b);
  EXPECT_LT(result, 0);  // "alice" < "bob" lexicographically
}

TEST(HLCLockIntegration, LockPrioritySameTimestamp) {
  crabs_hlc_t a = {1000, 500000000, 5, "alice"};
  crabs_hlc_t b = {1000, 500000000, 5, "alice"};

  int result = crabs_hlc_lock_priority(&a, &b);
  EXPECT_EQ(result, 0);
}

TEST(HLCLockIntegration, LockPriorityNullPointers) {
  crabs_hlc_t hlc = {1000, 500000000, 0, "alice"};
  // crabs_hlc_compare: NULL is treated as less than any value
  EXPECT_EQ(crabs_hlc_lock_priority(NULL, &hlc), -1);
  EXPECT_EQ(crabs_hlc_lock_priority(&hlc, NULL), 1);
  EXPECT_EQ(crabs_hlc_lock_priority(NULL, NULL), 0);
}

TEST(HLCLockIntegration, AddDurationBasic) {
  crabs_hlc_t base = {1000, 500000000, 0, "alice"};
  // Add 500ms = 500,000,000 nanos
  // 500M + 500M = 1,000,000,000 → normalization: seconds += 1, nanos = 0
  crabs_hlc_t result = crabs_hlc_add_duration(base, 500);
  EXPECT_EQ(result.physical_seconds, 1001u);
  EXPECT_EQ(result.physical_nanos, 0u);
}

TEST(HLCLockIntegration, AddDurationNanosecondOverflow) {
  crabs_hlc_t base = {1000, 800000000, 0, "alice"};
  // Add 300ms = 300,000,000 nanos → 800M + 300M = 1,100,000,000
  crabs_hlc_t result = crabs_hlc_add_duration(base, 300);
  EXPECT_EQ(result.physical_seconds, 1001u);
  EXPECT_EQ(result.physical_nanos, 100000000u);
  EXPECT_EQ(result.logical_counter, 0u);
}

TEST(HLCLockIntegration, AddDurationZero) {
  crabs_hlc_t base = {1000, 500000000, 5, "alice"};
  crabs_hlc_t result = crabs_hlc_add_duration(base, 0);
  EXPECT_EQ(result.physical_seconds, 1000u);
  EXPECT_EQ(result.physical_nanos, 500000000u);
  EXPECT_EQ(result.logical_counter, 5u);
}

TEST(HLCLockIntegration, AddDurationLargeValue) {
  crabs_hlc_t base = {1000, 0, 0, "alice"};
  // Add 5000 seconds = 5,000,000 ms
  crabs_hlc_t result = crabs_hlc_add_duration(base, 5000000);
  EXPECT_EQ(result.physical_seconds, 6000u);
  EXPECT_EQ(result.physical_nanos, 0u);
}

TEST(HLCLockIntegration, AddDurationPreservesNodeId) {
  crabs_hlc_t base = {1000, 500000000, 0, "testnode"};
  crabs_hlc_t result = crabs_hlc_add_duration(base, 100);
  EXPECT_STREQ(result.node_id, "testnode");
}

TEST(HLCLockIntegration, LockExpiredBasic) {
  crabs_hlc_state_t state;
  crabs_hlc_state_init(&state, "test");

  // Acquired in the past — lock should be expired
  crabs_hlc_t acquired_at = {1000, 0, 0, "test"};
  bool expired = crabs_hlc_lock_expired(&state, &acquired_at, 5000);
  EXPECT_TRUE(expired);  // acquired_at is far in the past, duration is only 5s
}

TEST(HLCLockIntegration, LockExpiredNullPointers) {
  crabs_hlc_state_t state;
  crabs_hlc_state_init(&state, "test");
  crabs_hlc_t acquired = {1000, 0, 0, "test"};
  EXPECT_TRUE(crabs_hlc_lock_expired(NULL, &acquired, 5000));
  EXPECT_TRUE(crabs_hlc_lock_expired(&state, NULL, 5000));
}

TEST(HLCLockIntegration, StateMachineLockExpiredLamportMode) {
  // In Lamport mode (default), lock expiry uses wall-clock millisecond comparison
  state_t* state = state_create();
  lock_state_t lock = {};
  lock.lock_expiry = 10000;
  lock.lock_acquired_at = {0, 0, 0, ""};

  // now_ms = 5000, expiry = 10000 → not expired
  EXPECT_FALSE(state_machine_lock_expired(state, &lock, 5000));
  // now_ms = 10001, expiry = 10000 → expired
  EXPECT_TRUE(state_machine_lock_expired(state, &lock, 10001));

  state_destroy(state);
}

TEST(HLCLockIntegration, StateMachineLockExpiredHLCMode) {
  // In HLC mode, lock expiry uses HLC timestamps
  state_t* state = state_create();
  crabs_ordering_config_t config;
  crabs_ordering_config_init_hlc(&config, HLC_STRATEGY_BOUNDED);
  state_set_ordering_config(state, &config);

  lock_state_t lock = {};
  lock.lock_expiry = 10000;
  // Acquired at a far-past timestamp — should be expired with short duration
  lock.lock_acquired_at = {1000, 0, 0, "test"};

  // R8-T-1: expiry uses the authenticated now_ms (not the system clock). Pass a
  // realistic "now" (2023-11-14) so the 1970 acquisition is long expired.
  bool expired = state_machine_lock_expired(state, &lock, 1700000000000ULL);
  EXPECT_TRUE(expired);

  state_destroy(state);
}

// ============================================================
// HLC Test Vectors (v1.6 Amd6 §12)
// ============================================================

TEST(HLCTestVectors, TV12_1_BasicHLCGeneration) {
  // §12.1: Initial timestamp from physical time
  crabs_hlc_state_t state;
  crabs_hlc_state_init(&state, "alice");

  // Mock physical time: epoch=36000, nanos=500000000
  g_mock_time = {36000, 500000000, true};
  g_mock_ops = {mock_get_time, mock_is_available, NULL};
  state.time_source_ops = &g_mock_ops;

  crabs_hlc_t result = crabs_hlc_next(&state);

  EXPECT_EQ(result.physical_seconds, 36000u);
  EXPECT_EQ(result.physical_nanos, 500000000u);
  EXPECT_EQ(result.logical_counter, 0u);
  EXPECT_STREQ(result.node_id, "alice");
}

TEST(HLCTestVectors, TV12_2_SameNanosecondEvents) {
  // §12.2: Same-nanosecond events increment logical counter
  crabs_hlc_state_t state;
  crabs_hlc_state_init(&state, "alice");

  // Mock time stays constant at (36000, 500000000)
  g_mock_time = {36000, 500000000, true};
  g_mock_ops = {mock_get_time, mock_is_available, NULL};
  state.time_source_ops = &g_mock_ops;

  crabs_hlc_t event1 = crabs_hlc_next(&state);
  EXPECT_EQ(event1.physical_seconds, 36000u);
  EXPECT_EQ(event1.physical_nanos, 500000000u);
  EXPECT_EQ(event1.logical_counter, 0u);

  crabs_hlc_t event2 = crabs_hlc_next(&state);
  EXPECT_EQ(event2.physical_seconds, 36000u);
  EXPECT_EQ(event2.physical_nanos, 500000000u);
  EXPECT_EQ(event2.logical_counter, 1u);

  crabs_hlc_t event3 = crabs_hlc_next(&state);
  EXPECT_EQ(event3.physical_seconds, 36000u);
  EXPECT_EQ(event3.physical_nanos, 500000000u);
  EXPECT_EQ(event3.logical_counter, 2u);

  // Verify ordering: 0 < 1 < 2
  EXPECT_LT(crabs_hlc_compare(&event1, &event2), 0);
  EXPECT_LT(crabs_hlc_compare(&event2, &event3), 0);
}

TEST(HLCTestVectors, TV12_3_ClockRegression) {
  // §12.3: Clock regression — counter increments on last known time
  crabs_hlc_state_t state;
  crabs_hlc_state_init(&state, "alice");

  // Set up: first advance to (36000, 500000000, 5)
  g_mock_time = {36000, 500000000, true};
  g_mock_ops = {mock_get_time, mock_is_available, NULL};
  state.time_source_ops = &g_mock_ops;

  // Generate events until counter reaches 5
  for (int i = 0; i <= 5; i++) {
    crabs_hlc_next(&state);
  }
  EXPECT_EQ(state.last.logical_counter, 5u);

  // Now clock regresses: physical time jumps BACK 600ms
  g_mock_time = {35999, 900000000, true};

  uint64_t regressions_before = state.clock_regressions_detected;
  crabs_hlc_t result = crabs_hlc_next(&state);

  EXPECT_EQ(result.physical_seconds, 36000u);
  EXPECT_EQ(result.physical_nanos, 500000000u);
  EXPECT_EQ(result.logical_counter, 6u);
  EXPECT_STREQ(result.node_id, "alice");
  EXPECT_EQ(state.clock_regressions_detected, regressions_before + 1);
}

TEST(HLCTestVectors, TV12_4_BoundedStrategyAccept) {
  // §12.4: BOUNDED strategy — timestamp within skew window
  crabs_hlc_state_t state;
  crabs_hlc_state_init_strategy(&state, "alice", HLC_STRATEGY_BOUNDED);
  state.max_skew_ms = 5000;

  // Mock local time = (36000, 0)
  g_mock_time = {36000, 0, true};
  g_mock_ops = {mock_get_time, mock_is_available, NULL};
  state.time_source_ops = &g_mock_ops;

  // Generate initial timestamp
  crabs_hlc_next(&state);

  // Received from Node B: (36002, 0, 0, "bob") — 2 seconds ahead
  crabs_hlc_t received = {36002, 0, 0, "bob"};

  crabs_hlc_receive_result_e result = crabs_hlc_receive(&state, &received);

  EXPECT_EQ(result, CRABS_HLC_ACCEPTED);
  // After max rule, state should have advanced to received time
  EXPECT_EQ(state.last.physical_seconds, 36002u);
}

TEST(HLCTestVectors, TV12_5_BoundedStrategyReject) {
  // §12.5: BOUNDED strategy — timestamp too far ahead
  crabs_hlc_state_t state;
  crabs_hlc_state_init_strategy(&state, "alice", HLC_STRATEGY_BOUNDED);
  state.max_skew_ms = 5000;

  // Mock local time = (36000, 0)
  g_mock_time = {36000, 0, true};
  g_mock_ops = {mock_get_time, mock_is_available, NULL};
  state.time_source_ops = &g_mock_ops;

  crabs_hlc_next(&state);
  crabs_hlc_t saved_last = state.last;

  // Received from Node M: (99999, 0, 0, "malicious") — far in future
  crabs_hlc_t received = {99999, 0, 0, "malicious"};

  uint64_t rejections_before = state.time_travel_attempts_rejected;
  crabs_hlc_receive_result_e result = crabs_hlc_receive(&state, &received);

  EXPECT_EQ(result, CRABS_HLC_REJECTED_SKEW);
  EXPECT_EQ(state.time_travel_attempts_rejected, rejections_before + 1);
  // State should be unchanged
  EXPECT_EQ(state.last.physical_seconds, saved_last.physical_seconds);
  EXPECT_EQ(state.last.physical_nanos, saved_last.physical_nanos);
  EXPECT_EQ(state.last.logical_counter, saved_last.logical_counter);
}

TEST(HLCTestVectors, TV12_6_StrictStrategy) {
  // §12.6: STRICT strategy — accepted but state unchanged
  crabs_hlc_state_t state;
  crabs_hlc_state_init_strategy(&state, "alice", HLC_STRATEGY_STRICT);

  // Set state.last = (36000, 500, 3, "alice")
  g_mock_time = {36000, 500, true};
  g_mock_ops = {mock_get_time, mock_is_available, NULL};
  state.time_source_ops = &g_mock_ops;
  crabs_hlc_next(&state);
  // Generate more events to get counter to 3
  for (int i = 0; i < 3; i++) {
    crabs_hlc_next(&state);
  }

  crabs_hlc_t saved_last = state.last;

  // Received from Node B: (99999, 0, 0, "bob")
  crabs_hlc_t received = {99999, 0, 0, "bob"};

  crabs_hlc_receive_result_e result = crabs_hlc_receive(&state, &received);

  EXPECT_EQ(result, CRABS_HLC_ACCEPTED_STRICT);
  // State must be UNCHANGED
  EXPECT_EQ(state.last.physical_seconds, saved_last.physical_seconds);
  EXPECT_EQ(state.last.physical_nanos, saved_last.physical_nanos);
  EXPECT_EQ(state.last.logical_counter, saved_last.logical_counter);
  EXPECT_STREQ(state.last.node_id, saved_last.node_id);
}

TEST(HLCTestVectors, TV12_7_CrossSystemOrdering) {
  // §12.7: Lamport operations sort before HLC operations
  operation_t op_a, op_b;
  memset(&op_a, 0, sizeof(op_a));
  memset(&op_b, 0, sizeof(op_b));

  // Operation A: Lamport (lamport_time=42, node="alice")
  op_a.ordering_system = CRABS_ORDERING_LAMPORT;
  op_a.lamport_time = 42;
  strncpy(op_a.node_id, "alice", CRABS_MAX_USER_ID - 1);

  // Operation B: HLC (36000, 500, 0, "bob")
  op_b.ordering_system = CRABS_ORDERING_HLC;
  op_b.hlc = {36000, 500, 0, "bob"};
  strncpy(op_b.node_id, "bob", CRABS_MAX_USER_ID - 1);

  // A is LAMPORT, B is HLC → A < B
  EXPECT_LT(crabs_operation_compare(&op_a, &op_b), 0);
  // B is HLC, A is LAMPORT → B > A
  EXPECT_GT(crabs_operation_compare(&op_b, &op_a), 0);
}

// Regression for audit R4-8: a received HLC timestamp with a logical counter
// at or above UINT64_MAX/2 must be rejected. Without this, a malicious node
// sending logical_counter = UINT64_MAX forces the local counter to saturate
// at UINT64_MAX permanently — breaking the total-order guarantee (all
// subsequent events at the same physical time share the same timestamp).
//
// Uses NAIVE strategy so the BOUNDED skew check doesn't interfere — we're
// testing the logical-counter rejection, not the time-skew rejection.
TEST(HLCTestVectors, TV12_8_RejectExtremeLogicalCounter) {
  crabs_hlc_state_t state;
  crabs_hlc_state_init_strategy(&state, "alice", HLC_STRATEGY_NAIVE);

  crabs_hlc_t received = {1000, 0, UINT64_MAX, "bob"};
  crabs_hlc_receive_result_e result = crabs_hlc_receive(&state, &received);
  EXPECT_EQ(result, CRABS_HLC_REJECTED_SKEW);

  // UINT64_MAX/2 is also rejected (the threshold is >= UINT64_MAX/2).
  received.logical_counter = UINT64_MAX / 2;
  result = crabs_hlc_receive(&state, &received);
  EXPECT_EQ(result, CRABS_HLC_REJECTED_SKEW);

  // A normal counter just below the threshold is accepted.
  received.logical_counter = UINT64_MAX / 2 - 1;
  result = crabs_hlc_receive(&state, &received);
  EXPECT_EQ(result, CRABS_HLC_ACCEPTED);

  // The local counter must NOT have been pushed to UINT64_MAX by the rejected
  // receives.
  EXPECT_LT(state.last.logical_counter, UINT64_MAX / 2);
}
// ============================================================
// HLC Replay Protection (R7-11 + v1.6 Amd6)
//
// Ops signed with HLC ordering carry lamport_time 0, so the replay guard
// must compare HLC-ordered ops by their HLC against the signer's last
// logged HLC — not by lamport_time (which would reject every op after a
// signer's first, as seen through the WASM bindings).
// ============================================================

extern "C" {
#include "test_helpers.h"
#include "../src/Util/allocator.h"
}

// Signs an HLC-ordered op with lamport_time left at 0, mirroring the
// production WASM signing path (key version stamped, no lamport stamp).
static void sign_hlc_op(crabs_test_env_t* env, operation_t* op) {
  state_t* state = env->state;
  user_t* signer = attribute_machine_find_user(state->attr_machine, op->signer_id);
  op->signer_key_version = signer->key_version;
  serialized_buffer_t* ser = crabs_serialize_for_signing(op);
  crypto_ecdsa_sign(env->admin_key->private_key, ser->data, ser->len, op->signature);
  serialized_buffer_destroy(ser);
}

static operation_t* make_hlc_lock_op(crabs_test_env_t* env, const char* resource) {
  state_t* state = env->state;
  operation_t* op = operation_create(CRABS_OP_LOCK);
  op->resources = (char(*)[CRABS_MAX_USER_ID])get_clear_memory(sizeof(char[CRABS_MAX_USER_ID]));
  strncpy(op->resources[0], resource, CRABS_MAX_USER_ID - 1);
  op->resource_count = 1;
  op->required_state = (protocol_state_e*)get_clear_memory(sizeof(protocol_state_e));
  op->required_state[0] = PROTOCOL_IDLE;
  op->next_state = (protocol_state_e*)get_clear_memory(sizeof(protocol_state_e));
  op->next_state[0] = PROTOCOL_LOCKED;
  strncpy(op->signer_id, "admin", CRABS_MAX_USER_ID - 1);

  // Stamp HLC ordering from the node's HLC state (as crabs_wasm_sign_operation does).
  op->ordering_system = CRABS_ORDERING_HLC;
  op->hlc = crabs_hlc_next(&state->hlc_state);
  strncpy(op->node_id, state->hlc_state.last.node_id, CRABS_MAX_USER_ID - 1);

  // Sign WITHOUT the test helper's lamport stamping: production WASM ops
  // carry lamport_time 0, and this test must reproduce exactly that.
  sign_hlc_op(env, op);
  return op;
}

TEST(HLCReplay, SecondHlcOpBySameSignerAccepted) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  state_t* state = env.state;

  // Put the node on HLC ordering with a mock clock (fresh, so ops differ).
  g_mock_time.seconds = 1000000;
  g_mock_time.nanos = 0;
  g_mock_time.valid = true;
  crabs_ordering_config_t* ordering_config =
      (crabs_ordering_config_t*)get_clear_memory(sizeof(crabs_ordering_config_t));
  crabs_ordering_config_init_hlc(ordering_config, HLC_STRATEGY_BOUNDED);
  state_set_ordering_config(state, ordering_config);
  crabs_hlc_state_init(&state->hlc_state, "admin");
  state->hlc_state.time_source_ops = &g_mock_ops;
  state->hlc_state_initialized = true;

  data_item_t* first = data_item_create("res1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  state_add_item(state, first);
  data_item_t* second = data_item_create("res2", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  state_add_item(state, second);

  operation_t* first_op = make_hlc_lock_op(&env, "res1");
  EXPECT_EQ(state_machine_execute(state, first_op), CRABS_SUCCESS);

  // A second, different op from the same signer with a newer HLC must be
  // accepted — it carries lamport_time 0, which the old lamport-only check
  // misread as a replay.
  operation_t* second_op = make_hlc_lock_op(&env, "res2");
  EXPECT_EQ(state_machine_execute(state, second_op), CRABS_SUCCESS);

  operation_destroy(first_op);
  operation_destroy(second_op);
  crabs_test_env_destroy(&env);
}

TEST(HLCReplay, ReplayedHlcOpRejected) {
  crabs_test_env_t env;
  crabs_test_env_init(&env);
  state_t* state = env.state;

  g_mock_time.seconds = 1000000;
  g_mock_time.nanos = 0;
  g_mock_time.valid = true;
  crabs_ordering_config_t* ordering_config =
      (crabs_ordering_config_t*)get_clear_memory(sizeof(crabs_ordering_config_t));
  crabs_ordering_config_init_hlc(ordering_config, HLC_STRATEGY_BOUNDED);
  state_set_ordering_config(state, ordering_config);
  crabs_hlc_state_init(&state->hlc_state, "admin");
  state->hlc_state.time_source_ops = &g_mock_ops;
  state->hlc_state_initialized = true;

  data_item_t* resource = data_item_create("res1", DATA_TYPE_RESOURCE, CRDT_PN_COUNTER);
  state_add_item(state, resource);

  operation_t* op = make_hlc_lock_op(&env, "res1");
  EXPECT_EQ(state_machine_execute(state, op), CRABS_SUCCESS);

  // Restore the pre-execute protocol state so the replay reaches the
  // ordering check rather than failing on a transition violation, and give
  // it a fresh UUID (re-signed, since the uuid is covered by the signature)
  // so only the HLC can identify it as a replay.
  resource->protocol_state = PROTOCOL_IDLE;
  resource->lock_state.lock_token_valid = false;
  for (uint32_t uuid_index = 0; uuid_index < CRABS_UUID_SIZE; uuid_index++) {
    op->uuid[uuid_index] = (uint8_t)(uuid_index + 200);
  }
  sign_hlc_op(&env, op);

  EXPECT_EQ(state_machine_execute(state, op), CRABS_ERR_ALREADY_EXECUTED);

  operation_destroy(op);
  crabs_test_env_destroy(&env);
}

// Audit finding: on a physical-time advance caused by a RECEIVED event, the
// local counter must adopt the received counter (standard HLC receive),
// not reset to 0 — otherwise the node's next same-second event sorts before
// the received op it causally follows.
TEST(HLCReceive, AdvanceAdoptsReceivedCounter) {
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_NAIVE;
  state.last = {36000, 0, 0, "alice"};

  // Receive an event strictly ahead of our last, carrying logical counter 5.
  crabs_hlc_t received = {36001, 0, 5, "bob"};
  crabs_hlc_receive(&state, &received);

  EXPECT_EQ(state.last.physical_seconds, 36001u);
  EXPECT_EQ(state.last.logical_counter, 5u);  // adopted, NOT reset to 0

  // The next local event must sort AFTER the received op.
  crabs_hlc_t next = crabs_hlc_next(&state);
  EXPECT_EQ(next.physical_seconds, 36001u);
  EXPECT_EQ(next.logical_counter, 6u);
  EXPECT_GT(crabs_hlc_compare(&next, &received), 0);
}

TEST(HLCReceive, AdvanceFromLocalClockStillResetsCounter) {
  // When our OWN clock advanced past both last and the received event, the
  // counter legitimately resets — the received event is causally behind.
  crabs_hlc_state_t state = make_mock_state("alice", 36000, 0);
  state.receive_strategy = HLC_STRATEGY_NAIVE;
  state.last = {36000, 0, 0, "alice"};

  crabs_hlc_t older = {36000, 500000000, 9, "bob"};
  crabs_hlc_receive(&state, &older);  // behind local mock clock (36000? see below)
  // Advance the local clock past everything, then receive an older message.
  g_mock_time.seconds = 36005;
  crabs_hlc_t stale = {36001, 0, 7, "carol"};
  crabs_hlc_receive(&state, &stale);

  EXPECT_EQ(state.last.physical_seconds, 36005u);
  EXPECT_EQ(state.last.logical_counter, 0u);  // local advance: reset is correct
}
