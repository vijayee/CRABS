//
// bloom_filter.c — fixed-size bloom filter for compaction safety.
//
// Operation UUIDs are 16 bytes of CSPRNG output, so the bits are already
// uniformly distributed. We read the UUID directly as two u64 seeds — no
// hash function needed. Bit positions are derived via Kirsch-Mitzenmacher
// enhanced double hashing:  bit_i = (h1 + i*h2 + i*i) % size
//

#include "bloom_filter.h"
#include <string.h>

static void hash_uuid(const uint8_t uuid[16], uint64_t* h1, uint64_t* h2) {
  memcpy(h1, uuid, 8);
  memcpy(h2, uuid + 8, 8);
}

void crabs_bloom_add(crabs_bloom_filter_t* bf, const uint8_t uuid[16]) {
  if (bf == NULL || uuid == NULL) return;

  uint64_t h1, h2;
  hash_uuid(uuid, &h1, &h2);

  for (uint32_t i = 0; i < CRABS_BLOOM_HASHES; i++) {
    uint64_t bit = (h1 + i * h2 + i * i) % CRABS_BLOOM_BITS;
    size_t byte_idx = (size_t)(bit / 8);
    uint8_t bit_mask = (uint8_t)(1 << (bit % 8));
    bf->bits[byte_idx] |= bit_mask;
  }
  bf->count++;
}

bool crabs_bloom_contains(const crabs_bloom_filter_t* bf, const uint8_t uuid[16]) {
  if (bf == NULL || uuid == NULL) return false;

  uint64_t h1, h2;
  hash_uuid(uuid, &h1, &h2);

  for (uint32_t i = 0; i < CRABS_BLOOM_HASHES; i++) {
    uint64_t bit = (h1 + i * h2 + i * i) % CRABS_BLOOM_BITS;
    size_t byte_idx = (size_t)(bit / 8);
    uint8_t bit_mask = (uint8_t)(1 << (bit % 8));
    if ((bf->bits[byte_idx] & bit_mask) == 0) {
      return false;
    }
  }
  return true;
}

void crabs_bloom_reset(crabs_bloom_filter_t* bf) {
  if (bf == NULL) return;
  memset(bf->bits, 0, CRABS_BLOOM_BYTES);
  bf->count = 0;
}

size_t crabs_bloom_count(const crabs_bloom_filter_t* bf) {
  if (bf == NULL) return 0;
  return bf->count;
}
