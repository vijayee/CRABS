//
// avl_uuid.h — minimal AVL tree keyed by 16-byte UUID.
//
// Adapted from the AVL patterns in src/OT/position_map.c. Stores UUIDs in a
// balanced tree for O(log n) lookup with unbounded growth.
//

#ifndef CRABS_AVL_UUID_H
#define CRABS_AVL_UUID_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef struct crabs_avl_uuid_t {
  struct crabs_avl_uuid_t* left;
  struct crabs_avl_uuid_t* right;
  uint8_t  uuid[16];
  uint32_t height;
} crabs_avl_uuid_t;

// Insert a UUID. Returns the new root. If the UUID already exists, the
// tree is unchanged and *inserted is set to false.
crabs_avl_uuid_t* crabs_avl_uuid_insert(crabs_avl_uuid_t* root,
                                         const uint8_t uuid[16], bool* inserted);

// Check if a UUID exists in the tree.
bool crabs_avl_uuid_contains(const crabs_avl_uuid_t* root, const uint8_t uuid[16]);

// Destroy the tree and free all nodes.
void crabs_avl_uuid_destroy(crabs_avl_uuid_t* root);

// Return the number of nodes in the tree.
size_t crabs_avl_uuid_count(const crabs_avl_uuid_t* root);

#endif // CRABS_AVL_UUID_H
