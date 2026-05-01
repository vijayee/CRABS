//
// Created by victor on 4/29/25.
//
#include "hash.h"
#include "allocator.h"
#include <string.h>

// Simple hash functions using built-in FNV-1a for portability
// (no external xxHash dependency needed)

#define FNV_OFFSET 14695981039346656037ULL
#define FNV_PRIME  1099511628211ULL

static uint64_t fnv1a(const uint8_t* data, size_t len) {
  uint64_t hash = FNV_OFFSET;
  for (size_t i = 0; i < len; i++) {
    hash ^= (uint64_t)data[i];
    hash *= FNV_PRIME;
  }
  return hash;
}

size_t hash_pointer(const void* ptr) {
  uint64_t g = (uint64_t)(uintptr_t)ptr;
  return (size_t)fnv1a((const uint8_t*)&g, sizeof(g));
}

size_t hash_uint32(const void* data) {
  return (size_t)fnv1a((const uint8_t*)data, 4);
}

size_t hash_uint64(const void* data) {
  return (size_t)fnv1a((const uint8_t*)data, 8);
}

size_t hash_size_t(const void* data) {
  return (size_t)fnv1a((const uint8_t*)data, sizeof(size_t));
}

int compare_uint32(const void* data1, const void* data2) {
  const uint32_t* _data1 = (const uint32_t*)data1;
  const uint32_t* _data2 = (const uint32_t*)data2;
  if (*_data1 == *_data2) return 0;
  return (*_data1 > *_data2) ? 1 : -1;
}

int compare_uint64(const void* data1, const void* data2) {
  const uint64_t* _data1 = (const uint64_t*)data1;
  const uint64_t* _data2 = (const uint64_t*)data2;
  if (*_data1 == *_data2) return 0;
  return (*_data1 > *_data2) ? 1 : -1;
}

int compare_size_t(const void* data1, const void* data2) {
  const size_t* _data1 = (const size_t*)data1;
  const size_t* _data2 = (const size_t*)data2;
  if (*_data1 == *_data2) return 0;
  return (*_data1 > *_data2) ? 1 : -1;
}

uint32_t* duplicate_uint32(const uint32_t* key) {
  uint32_t* copy = (uint32_t*)get_clear_memory(4);
  memcpy(copy, key, 4);
  return copy;
}

uint64_t* duplicate_uint64(const uint64_t* key) {
  uint64_t* copy = (uint64_t*)get_clear_memory(8);
  memcpy(copy, key, 8);
  return copy;
}

size_t* duplicate_size_t(const size_t* key) {
  size_t* copy = (size_t*)get_clear_memory(sizeof(size_t));
  memcpy(copy, key, sizeof(size_t));
  return copy;
}
