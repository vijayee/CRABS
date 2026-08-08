//
// tx_manager_memory.h — in-memory hash-set transaction manager.
//
// Tracks operation UUIDs in a hash set. O(1) average lookup, grows
// dynamically, no hard cap. Replaces the old processed_ops array and
// compaction bloom filter.
//

#ifndef CRABS_TX_MANAGER_MEMORY_H
#define CRABS_TX_MANAGER_MEMORY_H

#include "tx_manager.h"

// Create an in-memory transaction manager. The initial_capacity parameter
// sets the starting hash table size (0 = default of 1024 buckets).
crabs_tx_manager_t* crabs_tx_manager_memory(size_t initial_capacity);

#endif // CRABS_TX_MANAGER_MEMORY_H
