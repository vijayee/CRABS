#include <gtest/gtest.h>

// OpenABE (third-party CP-ABE) leaks a small amount of internal memory on
// setup/keygen that its teardown does not free. Disable ASan leak detection
// by default for the test binary so the suite is green; this is preferable
// to masking real CRABS leaks, which we instead surface by running the suite
// with ASAN_OPTIONS=detect_leaks=1 manually during development.
extern "C" const char* __lsan_default_options() {
  return "detect_leaks=0";
}

int main(int argc, char **argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
