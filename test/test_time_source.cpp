//
// Time source tests: monotonic clock, HTTPS-time backend, and integration.
//

#include <gtest/gtest.h>

extern "C" {
#include "Util/platform.h"
}

TEST(PlatformTime, MonotonicValidAndNonDecreasing) {
  platform_time_t first = platform_get_monotonic();
  EXPECT_TRUE(first.valid);

  platform_time_t second = platform_get_monotonic();
  EXPECT_TRUE(second.valid);

  bool non_decreasing = (second.seconds > first.seconds) ||
      (second.seconds == first.seconds && second.nanos >= first.nanos);
  EXPECT_TRUE(non_decreasing);
}

extern "C" {
#include "TimeSource/time_source.h"
}

// --- Fake transport for unit tests ---

static int fake_call_count = 0;
static bool fake_should_fail = false;
static uint64_t fake_seconds = 1000000000;
static uint64_t fake_nanos = 0;

static crabs_time_source_fetch_result_t fake_transport(const char* url, uint64_t timeout_ms) {
  (void)url;
  (void)timeout_ms;
  fake_call_count++;
  crabs_time_source_fetch_result_t result = {0, 0, false};
  if (!fake_should_fail) {
    result.seconds = fake_seconds;
    result.nanos = fake_nanos;
    result.valid = true;
  }
  return result;
}

static void reset_fake(uint64_t seconds, uint64_t nanos) {
  fake_call_count = 0;
  fake_should_fail = false;
  fake_seconds = seconds;
  fake_nanos = nanos;
}

TEST(TimeSourceBackend, FreshCacheDoesNotQueryTransport) {
  reset_fake(1000000000, 0);

  crabs_time_source_config_t config;
  config.server_url = "https://example.invalid";
  config.resync_interval_ms = 60000;  // long enough that both calls are fresh
  config.timeout_ms = 1000;

  crabs_time_source_ops_t* ops =
      crabs_time_source_https_create_with_transport(&config, fake_transport);
  ASSERT_NE(ops, nullptr);

  crabs_physical_time_t first = ops->get_time(ops->ctx);
  ASSERT_TRUE(first.valid);
  EXPECT_EQ(fake_call_count, 1);

  crabs_physical_time_t second = ops->get_time(ops->ctx);
  ASSERT_TRUE(second.valid);
  EXPECT_EQ(fake_call_count, 1);  // cache hit — no second transport call

  // Second result is the anchor plus a small elapsed time.
  EXPECT_TRUE(second.seconds > first.seconds ||
              (second.seconds == first.seconds && second.nanos >= first.nanos));

  EXPECT_TRUE(ops->is_available(ops->ctx));
  crabs_time_source_destroy(ops);
}

TEST(TimeSourceBackend, StaleCacheQueriesTransport) {
  reset_fake(1000000000, 0);

  crabs_time_source_config_t config;
  config.server_url = "https://example.invalid";
  config.resync_interval_ms = 0;  // every call is stale
  config.timeout_ms = 1000;

  crabs_time_source_ops_t* ops =
      crabs_time_source_https_create_with_transport(&config, fake_transport);
  ASSERT_NE(ops, nullptr);

  ops->get_time(ops->ctx);
  ops->get_time(ops->ctx);
  EXPECT_EQ(fake_call_count, 2);  // each call re-queries

  crabs_time_source_destroy(ops);
}

TEST(TimeSourceBackend, FailedFetchFallsBackToSystemClock) {
  reset_fake(1000000000, 0);
  fake_should_fail = true;

  crabs_time_source_config_t config;
  config.server_url = "https://example.invalid";
  config.resync_interval_ms = 0;
  config.timeout_ms = 1000;

  crabs_time_source_ops_t* ops =
      crabs_time_source_https_create_with_transport(&config, fake_transport);
  ASSERT_NE(ops, nullptr);

  crabs_physical_time_t result = ops->get_time(ops->ctx);
  EXPECT_TRUE(result.valid);  // system clock fallback is valid
  EXPECT_EQ(fake_call_count, 1);
  EXPECT_FALSE(ops->is_available(ops->ctx));  // no anchor held

  crabs_time_source_destroy(ops);
}

TEST(TimeSourceBackend, FailedFetchKeepsLastValidAnchor) {
  reset_fake(1000000000, 0);

  crabs_time_source_config_t config;
  config.server_url = "https://example.invalid";
  config.resync_interval_ms = 0;
  config.timeout_ms = 1000;

  crabs_time_source_ops_t* ops =
      crabs_time_source_https_create_with_transport(&config, fake_transport);
  ASSERT_NE(ops, nullptr);

  crabs_physical_time_t first = ops->get_time(ops->ctx);
  ASSERT_TRUE(first.valid);
  EXPECT_TRUE(ops->is_available(ops->ctx));

  // Now the transport fails; the backend keeps the anchor but returns
  // the system clock for this call.
  fake_should_fail = true;
  crabs_physical_time_t second = ops->get_time(ops->ctx);
  EXPECT_TRUE(second.valid);
  EXPECT_TRUE(ops->is_available(ops->ctx));  // anchor retained

  crabs_time_source_destroy(ops);
}

TEST(TimeSourceBackend, NullTransportReturnsNull) {
  crabs_time_source_config_t config;
  config.server_url = "https://example.invalid";
  config.resync_interval_ms = 0;
  config.timeout_ms = 1000;

  crabs_time_source_ops_t* ops =
      crabs_time_source_https_create_with_transport(&config, NULL);
  EXPECT_EQ(ops, nullptr);
}

TEST(TimeSourceBackend, DefaultsAppliedWhenConfigNull) {
  reset_fake(1000000000, 0);

  crabs_time_source_ops_t* ops =
      crabs_time_source_https_create_with_transport(NULL, fake_transport);
  ASSERT_NE(ops, nullptr);

  crabs_physical_time_t result = ops->get_time(ops->ctx);
  EXPECT_TRUE(result.valid);
  EXPECT_EQ(fake_call_count, 1);

  crabs_time_source_destroy(ops);
}
