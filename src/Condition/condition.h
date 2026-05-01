//
// Created by victor on 4/30/25.
//

#ifndef CRABS_CONDITION_H
#define CRABS_CONDITION_H

#include <stdint.h>
#include <stdbool.h>
#include "../CRABS/crabs.h"
#include "../CRABS/data_model.h"

// ============================================================
// Node Types (Amendment 1 §3.3 + Amendment 2 §3)
// ============================================================
typedef enum {
  NODE_COMPARISON  = 0x01,
  NODE_AND         = 0x02,
  NODE_OR          = 0x03,
  NODE_CONTAINS    = 0x04
} node_type_e;

typedef enum {
  CMP_GE      = 0x01,
  CMP_LE      = 0x02,
  CMP_GT      = 0x03,
  CMP_LT      = 0x04,
  CMP_EQ      = 0x05,
  CMP_NE      = 0x06,
  CMP_BETWEEN = 0x07,
  CMP_IN      = 0x08
} comparison_op_e;

typedef enum {
  CONTAINS_SINGLE = 0x01,
  CONTAINS_ANY    = 0x02,
  CONTAINS_ALL    = 0x03
} contains_type_e;

// ============================================================
// Condition AST Node (Amendment 1 §3.3 + Amendment 2 §3.1)
// ============================================================
typedef struct condition_node_t {
  node_type_e type;

  // For COMPARISON nodes:
  char           left_path[CRABS_MAX_POLICY_EXPR];
  comparison_op_e cmp_operator;
  char           right_path[CRABS_MAX_POLICY_EXPR];
  int64_t        right_literal;
  int64_t        right_literal_2;  // For BETWEEN

  // For CONTAINS nodes (Amendment 2):
  char           set_path[CRABS_MAX_POLICY_EXPR];
  char**         element_values;
  uint32_t       element_count;
  contains_type_e contains_type;
  bool           negated;

  // For AND/OR nodes:
  struct condition_node_t* left;
  struct condition_node_t* right;
} condition_node_t;

// ============================================================
// Condition Functions
// ============================================================
condition_node_t* condition_parse(const char* expression);
void               condition_node_destroy(condition_node_t* node);
bool               condition_evaluate(const condition_node_t* node, const state_t* state);
int64_t            condition_resolve_path(const state_t* state, const char* path);
condition_node_t*  condition_node_create_comparison(const char* left, comparison_op_e op,
                                                     int64_t literal);
condition_node_t*  condition_node_create_and(condition_node_t* left, condition_node_t* right);
condition_node_t*  condition_node_create_or(condition_node_t* left, condition_node_t* right);
condition_node_t*  condition_node_create_contains(const char* set_path, contains_type_e type,
                                                    bool negated, char** values, uint32_t count);

#endif // CRABS_CONDITION_H