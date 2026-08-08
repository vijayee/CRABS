//
// avl_uuid.c — minimal AVL tree keyed by 16-byte UUID.
//

#include "avl_uuid.h"
#include "../Util/allocator.h"
#include <string.h>

static uint32_t _height(const crabs_avl_uuid_t* n) {
  return n ? n->height : 0;
}

static void _update_height(crabs_avl_uuid_t* n) {
  uint32_t lh = _height(n->left);
  uint32_t rh = _height(n->right);
  n->height = 1 + (lh > rh ? lh : rh);
}

static int64_t _balance_factor(const crabs_avl_uuid_t* n) {
  return n ? (int64_t)_height(n->left) - (int64_t)_height(n->right) : 0;
}

static crabs_avl_uuid_t* _rotate_right(crabs_avl_uuid_t* y) {
  crabs_avl_uuid_t* x = y->left;
  crabs_avl_uuid_t* t = x->right;
  x->right = y;
  y->left = t;
  _update_height(y);
  _update_height(x);
  return x;
}

static crabs_avl_uuid_t* _rotate_left(crabs_avl_uuid_t* x) {
  crabs_avl_uuid_t* y = x->right;
  crabs_avl_uuid_t* t = y->left;
  y->left = x;
  x->right = t;
  _update_height(x);
  _update_height(y);
  return y;
}

static crabs_avl_uuid_t* _rebalance(crabs_avl_uuid_t* n) {
  _update_height(n);
  int64_t bf = _balance_factor(n);

  if (bf > 1) {
    if (_balance_factor(n->left) < 0)
      n->left = _rotate_left(n->left);
    return _rotate_right(n);
  }
  if (bf < -1) {
    if (_balance_factor(n->right) > 0)
      n->right = _rotate_right(n->right);
    return _rotate_left(n);
  }
  return n;
}

static int _uuid_cmp(const uint8_t a[16], const uint8_t b[16]) {
  return memcmp(a, b, 16);
}

crabs_avl_uuid_t* crabs_avl_uuid_insert(crabs_avl_uuid_t* root,
                                         const uint8_t uuid[16], bool* inserted) {
  if (root == NULL) {
    crabs_avl_uuid_t* n = get_clear_memory(sizeof(crabs_avl_uuid_t));
    memcpy(n->uuid, uuid, 16);
    n->height = 1;
    if (inserted) *inserted = true;
    return n;
  }

  int cmp = _uuid_cmp(uuid, root->uuid);
  if (cmp < 0) {
    root->left = crabs_avl_uuid_insert(root->left, uuid, inserted);
  } else if (cmp > 0) {
    root->right = crabs_avl_uuid_insert(root->right, uuid, inserted);
  } else {
    if (inserted) *inserted = false;
    return root;
  }
  return _rebalance(root);
}

bool crabs_avl_uuid_contains(const crabs_avl_uuid_t* root, const uint8_t uuid[16]) {
  if (root == NULL) return false;
  int cmp = _uuid_cmp(uuid, root->uuid);
  if (cmp < 0) return crabs_avl_uuid_contains(root->left, uuid);
  if (cmp > 0) return crabs_avl_uuid_contains(root->right, uuid);
  return true;
}

void crabs_avl_uuid_destroy(crabs_avl_uuid_t* root) {
  if (root == NULL) return;
  crabs_avl_uuid_destroy(root->left);
  crabs_avl_uuid_destroy(root->right);
  free(root);
}

size_t crabs_avl_uuid_count(const crabs_avl_uuid_t* root) {
  if (root == NULL) return 0;
  return 1 + crabs_avl_uuid_count(root->left) + crabs_avl_uuid_count(root->right);
}
