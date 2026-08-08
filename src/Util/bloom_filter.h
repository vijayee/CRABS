//
// bloom_filter.h — fixed-size bloom filter for compaction safety.
//
// When compaction discards tombstones (2P-Set remove_set, PN-Counter neg
// entries), the operation UUIDs that created those tombstones are inserted
// here. A late-arriving operation on a compactible type is checked against
// this filter — a hit means the data it depends on has been compacted away
// and the operation must be rejected.
//

#ifndef CRABS_BLOOM_FILTER_H
#define CRABS_BLOOM_FILTER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define CRABS_BLOOM_BITS     (128 * 1024)   // 128 Kbits = 16 KB
#define CRABS_BLOOM_BYTES    (CRABS_BLOOM_BITS / 8)
#define CRABS_BLOOM_HASHES   10

typedef struct {
  uint8_t bits[CRABS_BLOOM_BYTES];
  size_t  count;
} crabs_bloom_filter_t;

// Insert a 16-byte operation UUID into the filter.
void crabs_bloom_add(crabs_bloom_filter_t* bf, const uint8_t uuid[16]);

// Check whether a UUID may have been inserted. Returns true if the UUID
// is probably present (subject to false positive rate).
bool crabs_bloom_contains(const crabs_bloom_filter_t* bf, const uint8_t uuid[16]);

// Reset the filter to empty.
void crabs_bloom_reset(crabs_bloom_filter_t* bf);

// Return the number of items inserted.
size_t crabs_bloom_count(const crabs_bloom_filter_t* bf);

#endif // CRABS_BLOOM_FILTER_H
