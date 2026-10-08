// Test-only shim: recompile Lineage/lineage.c into the test executable so
// test_lineage.cpp can reach the STATIC canonical key-transition body writer
// for its cap-refusal unit test (audit A11-L2). The test binary defines every
// lineage symbol here, so the linker never extracts lineage.o from libcrabs —
// no duplicate symbols. Production builds are untouched.
#include "../src/Lineage/lineage.c"

size_t crabs_test_lineage_key_transition_write_body(
    uint64_t new_key_version, const uint8_t new_pk[33],
    const uint8_t old_pk[33], const char* parent_id, uint64_t created_at,
    uint8_t* out, size_t cap) {
  return _lineage_key_transition_write_body(new_key_version, new_pk, old_pk,
                                            parent_id, created_at, out, cap);
}
