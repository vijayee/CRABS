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
