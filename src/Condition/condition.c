//
// Created by victor on 4/30/25.
//

#include "condition.h"
#include "../Util/allocator.h"
#include "../CRDT/crdt_merge.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdio.h>

// ============================================================
// Token types for the lexer
// ============================================================
typedef enum {
  TOK_EOF,
  TOK_ERROR,
  TOK_IDENTIFIER,
  TOK_NUMBER,
  TOK_STRING,
  TOK_LPAREN,
  TOK_RPAREN,
  TOK_COMMA,
  TOK_DOT,
  TOK_GE,
  TOK_LE,
  TOK_GT,
  TOK_LT,
  TOK_EQ,
  TOK_NE,
  TOK_AND,
  TOK_OR,
  TOK_NOT,
  TOK_BETWEEN,
  TOK_IN,
  TOK_CONTAINS,
  TOK_CONTAINS_ANY,
  TOK_CONTAINS_ALL,
  TOK_TRUE,
  TOK_FALSE
} token_type_e;

typedef struct {
  token_type_e type;
  char         text[CRABS_MAX_POLICY_EXPR];
  int64_t      int_value;
} token_t;

typedef struct {
  const char* input;
  size_t      pos;
  size_t      length;
  token_t     current;
  bool        has_error;
} parser_ctx_t;

// ============================================================
// Keyword lookup
// ============================================================
typedef struct {
  const char*    keyword;
  token_type_e   type;
} keyword_entry_t;

static const keyword_entry_t _keywords[] = {
  {"AND",            TOK_AND},
  {"OR",             TOK_OR},
  {"NOT",            TOK_NOT},
  {"BETWEEN",        TOK_BETWEEN},
  {"IN",             TOK_IN},
  {"CONTAINS",       TOK_CONTAINS},
  {"CONTAINS_ANY",   TOK_CONTAINS_ANY},
  {"CONTAINS_ALL",   TOK_CONTAINS_ALL},
  {"true",           TOK_TRUE},
  {"false",          TOK_FALSE},
  {NULL,             TOK_EOF}
};

static token_type_e _lookup_keyword(const char* word) {
  for (int i = 0; _keywords[i].keyword != NULL; i++) {
    if (strcasecmp(word, _keywords[i].keyword) == 0) {
      return _keywords[i].type;
    }
  }
  return TOK_IDENTIFIER;
}

// ============================================================
// Lexer
// ============================================================
static void _lexer_skip_whitespace(parser_ctx_t* ctx) {
  while (ctx->pos < ctx->length && isspace((unsigned char)ctx->input[ctx->pos])) {
    ctx->pos++;
  }
}

static token_t _lexer_next(parser_ctx_t* ctx) {
  token_t tok;
  memset(&tok, 0, sizeof(tok));

  _lexer_skip_whitespace(ctx);
  if (ctx->pos >= ctx->length) {
    tok.type = TOK_EOF;
    return tok;
  }

  char c = ctx->input[ctx->pos];

  // Two-character operators
  if (ctx->pos + 1 < ctx->length) {
    char next = ctx->input[ctx->pos + 1];
    if (c == '>' && next == '=') {
      tok.type = TOK_GE;
      ctx->pos += 2;
      return tok;
    }
    if (c == '<' && next == '=') {
      tok.type = TOK_LE;
      ctx->pos += 2;
      return tok;
    }
    if (c == '=' && next == '=') {
      tok.type = TOK_EQ;
      ctx->pos += 2;
      return tok;
    }
    if (c == '!' && next == '=') {
      tok.type = TOK_NE;
      ctx->pos += 2;
      return tok;
    }
  }

  // Single-character operators and delimiters
  switch (c) {
    case '(':
      tok.type = TOK_LPAREN;
      ctx->pos++;
      return tok;
    case ')':
      tok.type = TOK_RPAREN;
      ctx->pos++;
      return tok;
    case ',':
      tok.type = TOK_COMMA;
      ctx->pos++;
      return tok;
    case '.':
      tok.type = TOK_DOT;
      ctx->pos++;
      return tok;
    case '>':
      tok.type = TOK_GT;
      ctx->pos++;
      return tok;
    case '<':
      tok.type = TOK_LT;
      ctx->pos++;
      return tok;
    default:
      break;
  }

  // String literal
  if (c == '"') {
    ctx->pos++; // skip opening quote
    size_t start = ctx->pos;
    while (ctx->pos < ctx->length && ctx->input[ctx->pos] != '"') {
      ctx->pos++;
    }
    size_t len = ctx->pos - start;
    if (len >= CRABS_MAX_POLICY_EXPR) {
      len = CRABS_MAX_POLICY_EXPR - 1;
    }
    strncpy(tok.text, ctx->input + start, len);
    tok.text[len] = '\0';
    tok.type = TOK_STRING;
    if (ctx->pos < ctx->length) {
      ctx->pos++; // skip closing quote
    }
    return tok;
  }

  // Number (including negative)
  if (isdigit((unsigned char)c) || (c == '-' && ctx->pos + 1 < ctx->length && isdigit((unsigned char)ctx->input[ctx->pos + 1]))) {
    size_t start = ctx->pos;
    if (c == '-') ctx->pos++;
    while (ctx->pos < ctx->length && isdigit((unsigned char)ctx->input[ctx->pos])) {
      ctx->pos++;
    }
    size_t len = ctx->pos - start;
    char num_buf[64];
    if (len >= sizeof(num_buf)) len = sizeof(num_buf) - 1;
    strncpy(num_buf, ctx->input + start, len);
    num_buf[len] = '\0';
    tok.int_value = atoll(num_buf);
    tok.type = TOK_NUMBER;
    strncpy(tok.text, ctx->input + start, len);
    tok.text[len] = '\0';
    return tok;
  }

  // Identifier or keyword (including underscored forms like CONTAINS_ANY)
  if (isalpha((unsigned char)c) || c == '_') {
    size_t start = ctx->pos;
    while (ctx->pos < ctx->length && (isalnum((unsigned char)ctx->input[ctx->pos]) || ctx->input[ctx->pos] == '_' || ctx->input[ctx->pos] == '-')) {
      ctx->pos++;
    }
    size_t len = ctx->pos - start;
    if (len >= CRABS_MAX_POLICY_EXPR) {
      len = CRABS_MAX_POLICY_EXPR - 1;
    }
    strncpy(tok.text, ctx->input + start, len);
    tok.text[len] = '\0';
    tok.type = _lookup_keyword(tok.text);
    if (tok.type == TOK_NUMBER) {
      // Shouldn't happen, but just in case
    }
    return tok;
  }

  // Unknown character
  tok.type = TOK_ERROR;
  ctx->pos++;
  return tok;
}

static void _parser_init(parser_ctx_t* ctx, const char* input) {
  ctx->input = input;
  ctx->pos = 0;
  ctx->length = strlen(input);
  ctx->has_error = false;
  ctx->current = _lexer_next(ctx);
}

static token_t _parser_peek(parser_ctx_t* ctx) {
  return ctx->current;
}

static token_t _parser_advance(parser_ctx_t* ctx) {
  token_t tok = ctx->current;
  ctx->current = _lexer_next(ctx);
  return tok;
}

static bool _parser_expect(parser_ctx_t* ctx, token_type_e expected) {
  if (ctx->current.type == expected) {
    _parser_advance(ctx);
    return true;
  }
  ctx->has_error = true;
  return false;
}

// ============================================================
// Parser: primary (path, number, string, true, false)
// ============================================================
typedef enum {
  PRIMARY_PATH,
  PRIMARY_NUMBER,
  PRIMARY_STRING,
  PRIMARY_TRUE,
  PRIMARY_FALSE
} primary_type_e;

typedef struct {
  primary_type_e type;
  char           path[CRABS_MAX_POLICY_EXPR];
  int64_t        number;
} primary_t;

static bool _parse_primary(parser_ctx_t* ctx, primary_t* result) {
  token_t tok = _parser_peek(ctx);

  if (tok.type == TOK_NUMBER) {
    result->type = PRIMARY_NUMBER;
    result->number = tok.int_value;
    strncpy(result->path, tok.text, CRABS_MAX_POLICY_EXPR - 1);
    result->path[CRABS_MAX_POLICY_EXPR - 1] = '\0';
    _parser_advance(ctx);
    return true;
  }

  if (tok.type == TOK_STRING) {
    result->type = PRIMARY_STRING;
    strncpy(result->path, tok.text, CRABS_MAX_POLICY_EXPR - 1);
    result->path[CRABS_MAX_POLICY_EXPR - 1] = '\0';
    _parser_advance(ctx);
    return true;
  }

  if (tok.type == TOK_TRUE) {
    result->type = PRIMARY_TRUE;
    result->number = 1;
    strncpy(result->path, "true", CRABS_MAX_POLICY_EXPR - 1);
    _parser_advance(ctx);
    return true;
  }

  if (tok.type == TOK_FALSE) {
    result->type = PRIMARY_FALSE;
    result->number = 0;
    strncpy(result->path, "false", CRABS_MAX_POLICY_EXPR - 1);
    _parser_advance(ctx);
    return true;
  }

  if (tok.type == TOK_IDENTIFIER) {
    // Parse a path: identifier ("." identifier)*
    result->type = PRIMARY_PATH;
    strncpy(result->path, tok.text, CRABS_MAX_POLICY_EXPR - 1);
    result->path[CRABS_MAX_POLICY_EXPR - 1] = '\0';
    _parser_advance(ctx);

    while (_parser_peek(ctx).type == TOK_DOT) {
      _parser_advance(ctx); // consume dot
      token_t ident = _parser_peek(ctx);
      if (ident.type != TOK_IDENTIFIER) {
        ctx->has_error = true;
        return false;
      }
      size_t path_len = strlen(result->path);
      if (path_len + 1 + strlen(ident.text) < CRABS_MAX_POLICY_EXPR) {
        result->path[path_len] = '.';
        strncpy(result->path + path_len + 1, ident.text, CRABS_MAX_POLICY_EXPR - path_len - 2);
        result->path[CRABS_MAX_POLICY_EXPR - 1] = '\0';
      }
      _parser_advance(ctx);
    }
    return true;
  }

  ctx->has_error = true;
  return false;
}

// ============================================================
// Parser: parse a list of values in parentheses
// ============================================================
static bool _parse_value_list(parser_ctx_t* ctx, char*** values, uint32_t* count) {
  *values = NULL;
  *count = 0;

  if (!_parser_expect(ctx, TOK_LPAREN)) return false;

  uint32_t capacity = 4;
  *values = get_memory(capacity * sizeof(char*));

  primary_t elem;
  if (!_parse_primary(ctx, &elem)) {
    return false;
  }
  (*values)[0] = strdup(elem.path);
  *count = 1;

  while (_parser_peek(ctx).type == TOK_COMMA) {
    _parser_advance(ctx); // consume comma
    if (*count >= capacity) {
      capacity *= 2;
      char** new_values = realloc(*values, capacity * sizeof(char*));
      if (new_values == NULL) return false;
      *values = new_values;
    }
    if (!_parse_primary(ctx, &elem)) {
      return false;
    }
    (*values)[*count] = strdup(elem.path);
    (*count)++;
  }

  if (!_parser_expect(ctx, TOK_RPAREN)) return false;

  return true;
}

// ============================================================
// Parser: parse comparison
// ============================================================
static condition_node_t* _parse_or_expr(parser_ctx_t* ctx);

static condition_node_t* _parse_comparison(parser_ctx_t* ctx) {
  // Parenthesized expression
  if (_parser_peek(ctx).type == TOK_LPAREN) {
    _parser_advance(ctx); // consume (
    condition_node_t* node = _parse_or_expr(ctx);
    if (!_parser_expect(ctx, TOK_RPAREN)) {
      condition_node_destroy(node);
      return NULL;
    }
    return node;
  }

  // Parse primary (could be path or value)
  primary_t primary;
  if (!_parse_primary(ctx, &primary)) {
    return NULL;
  }

  token_t next = _parser_peek(ctx);

  // Comparison operators: >=, <=, >, <, ==, !=
  if (next.type == TOK_GE || next.type == TOK_LE ||
      next.type == TOK_GT || next.type == TOK_LT ||
      next.type == TOK_EQ || next.type == TOK_NE) {
    comparison_op_e op;
    switch (next.type) {
      case TOK_GE: op = CMP_GE; break;
      case TOK_LE: op = CMP_LE; break;
      case TOK_GT: op = CMP_GT; break;
      case TOK_LT: op = CMP_LT; break;
      case TOK_EQ: op = CMP_EQ; break;
      case TOK_NE: op = CMP_NE; break;
      default: return NULL;
    }
    _parser_advance(ctx);

    primary_t right;
    if (!_parse_primary(ctx, &right)) {
      return NULL;
    }

    condition_node_t* node = get_clear_memory(sizeof(condition_node_t));
    node->type = NODE_COMPARISON;
    strncpy(node->left_path, primary.path, CRABS_MAX_POLICY_EXPR - 1);
    node->cmp_operator = op;

    if (right.type == PRIMARY_PATH) {
      strncpy(node->right_path, right.path, CRABS_MAX_POLICY_EXPR - 1);
    } else if (right.type == PRIMARY_NUMBER) {
      node->right_literal = right.number;
    } else if (right.type == PRIMARY_TRUE) {
      node->right_literal = 1;
    } else if (right.type == PRIMARY_FALSE) {
      node->right_literal = 0;
    } else if (right.type == PRIMARY_STRING) {
      strncpy(node->right_path, right.path, CRABS_MAX_POLICY_EXPR - 1);
    }
    return node;
  }

  // BETWEEN
  if (next.type == TOK_BETWEEN) {
    _parser_advance(ctx);

    primary_t low;
    if (!_parse_primary(ctx, &low)) return NULL;

    if (!_parser_expect(ctx, TOK_AND)) return NULL;

    primary_t high;
    if (!_parse_primary(ctx, &high)) return NULL;

    condition_node_t* node = get_clear_memory(sizeof(condition_node_t));
    node->type = NODE_COMPARISON;
    strncpy(node->left_path, primary.path, CRABS_MAX_POLICY_EXPR - 1);
    node->cmp_operator = CMP_BETWEEN;

    if (low.type == PRIMARY_NUMBER) {
      node->right_literal = low.number;
    } else if (low.type == PRIMARY_PATH) {
      strncpy(node->right_path, low.path, CRABS_MAX_POLICY_EXPR - 1);
    }

    // For BETWEEN, we store the upper bound in right_literal_2
    // but we need to handle the case where the lower bound is a path
    // We'll use element_values for path references in BETWEEN
    if (high.type == PRIMARY_NUMBER) {
      node->right_literal_2 = high.number;
    }
    return node;
  }

  // IN (with list)
  if (next.type == TOK_IN) {
    _parser_advance(ctx);

    if (_parser_peek(ctx).type == TOK_LPAREN) {
      // <path> IN (<value>, ...)
      char** values = NULL;
      uint32_t count = 0;
      if (!_parse_value_list(ctx, &values, &count)) return NULL;

      condition_node_t* node = get_clear_memory(sizeof(condition_node_t));
      node->type = NODE_COMPARISON;
      strncpy(node->left_path, primary.path, CRABS_MAX_POLICY_EXPR - 1);
      node->cmp_operator = CMP_IN;
      node->element_values = values;
      node->element_count = count;
      return node;
    } else {
      // <value> IN <path> → CONTAINS node
      primary_t path_primary;
      if (!_parse_primary(ctx, &path_primary)) return NULL;

      condition_node_t* node = get_clear_memory(sizeof(condition_node_t));
      node->type = NODE_CONTAINS;
      strncpy(node->set_path, path_primary.path, CRABS_MAX_POLICY_EXPR - 1);
      node->contains_type = CONTAINS_SINGLE;
      node->negated = false;
      node->element_values = get_memory(sizeof(char*));
      node->element_values[0] = strdup(primary.path);
      node->element_count = 1;
      return node;
    }
  }

  // CONTAINS
  if (next.type == TOK_CONTAINS) {
    _parser_advance(ctx);

    primary_t value;
    if (!_parse_primary(ctx, &value)) return NULL;

    condition_node_t* node = get_clear_memory(sizeof(condition_node_t));
    node->type = NODE_CONTAINS;
    strncpy(node->set_path, primary.path, CRABS_MAX_POLICY_EXPR - 1);
    node->contains_type = CONTAINS_SINGLE;
    node->negated = false;
    node->element_values = get_memory(sizeof(char*));
    node->element_values[0] = strdup(value.path);
    node->element_count = 1;
    return node;
  }

  // CONTAINS_ANY
  if (next.type == TOK_CONTAINS_ANY) {
    _parser_advance(ctx);

    char** values = NULL;
    uint32_t count = 0;
    if (!_parse_value_list(ctx, &values, &count)) return NULL;

    condition_node_t* node = get_clear_memory(sizeof(condition_node_t));
    node->type = NODE_CONTAINS;
    strncpy(node->set_path, primary.path, CRABS_MAX_POLICY_EXPR - 1);
    node->contains_type = CONTAINS_ANY;
    node->negated = false;
    node->element_values = values;
    node->element_count = count;
    return node;
  }

  // CONTAINS_ALL
  if (next.type == TOK_CONTAINS_ALL) {
    _parser_advance(ctx);

    char** values = NULL;
    uint32_t count = 0;
    if (!_parse_value_list(ctx, &values, &count)) return NULL;

    condition_node_t* node = get_clear_memory(sizeof(condition_node_t));
    node->type = NODE_CONTAINS;
    strncpy(node->set_path, primary.path, CRABS_MAX_POLICY_EXPR - 1);
    node->contains_type = CONTAINS_ALL;
    node->negated = false;
    node->element_values = values;
    node->element_count = count;
    return node;
  }

  // NOT (for NOT CONTAINS, NOT CONTAINS_ANY, NOT CONTAINS_ALL, NOT IN)
  if (next.type == TOK_NOT) {
    _parser_advance(ctx);

    token_t after_not = _parser_peek(ctx);

    // NOT CONTAINS
    if (after_not.type == TOK_CONTAINS) {
      _parser_advance(ctx);

      primary_t value;
      if (!_parse_primary(ctx, &value)) return NULL;

      condition_node_t* node = get_clear_memory(sizeof(condition_node_t));
      node->type = NODE_CONTAINS;
      strncpy(node->set_path, primary.path, CRABS_MAX_POLICY_EXPR - 1);
      node->contains_type = CONTAINS_SINGLE;
      node->negated = true;
      node->element_values = get_memory(sizeof(char*));
      node->element_values[0] = strdup(value.path);
      node->element_count = 1;
      return node;
    }

    // NOT CONTAINS_ANY
    if (after_not.type == TOK_CONTAINS_ANY) {
      _parser_advance(ctx);

      char** values = NULL;
      uint32_t count = 0;
      if (!_parse_value_list(ctx, &values, &count)) return NULL;

      condition_node_t* node = get_clear_memory(sizeof(condition_node_t));
      node->type = NODE_CONTAINS;
      strncpy(node->set_path, primary.path, CRABS_MAX_POLICY_EXPR - 1);
      node->contains_type = CONTAINS_ANY;
      node->negated = true;
      node->element_values = values;
      node->element_count = count;
      return node;
    }

    // NOT CONTAINS_ALL
    if (after_not.type == TOK_CONTAINS_ALL) {
      _parser_advance(ctx);

      char** values = NULL;
      uint32_t count = 0;
      if (!_parse_value_list(ctx, &values, &count)) return NULL;

      condition_node_t* node = get_clear_memory(sizeof(condition_node_t));
      node->type = NODE_CONTAINS;
      strncpy(node->set_path, primary.path, CRABS_MAX_POLICY_EXPR - 1);
      node->contains_type = CONTAINS_ALL;
      node->negated = true;
      node->element_values = values;
      node->element_count = count;
      return node;
    }

    // NOT IN (value NOT IN path)
    if (after_not.type == TOK_IN) {
      _parser_advance(ctx);

      primary_t path_primary;
      if (!_parse_primary(ctx, &path_primary)) return NULL;

      condition_node_t* node = get_clear_memory(sizeof(condition_node_t));
      node->type = NODE_CONTAINS;
      strncpy(node->set_path, path_primary.path, CRABS_MAX_POLICY_EXPR - 1);
      node->contains_type = CONTAINS_SINGLE;
      node->negated = true;
      node->element_values = get_memory(sizeof(char*));
      node->element_values[0] = strdup(primary.path);
      node->element_count = 1;
      return node;
    }

    ctx->has_error = true;
    return NULL;
  }

  // If we reach here, we didn't find a valid comparison operator
  ctx->has_error = true;
  return NULL;
}

// ============================================================
// Parser: AND expressions
// ============================================================
static condition_node_t* _parse_and_expr(parser_ctx_t* ctx) {
  condition_node_t* left = _parse_comparison(ctx);
  if (left == NULL) return NULL;

  while (_parser_peek(ctx).type == TOK_AND && !ctx->has_error) {
    _parser_advance(ctx);
    condition_node_t* right = _parse_comparison(ctx);
    if (right == NULL) {
      condition_node_destroy(left);
      return NULL;
    }
    left = condition_node_create_and(left, right);
  }

  return left;
}

// ============================================================
// Parser: OR expressions
// ============================================================
static condition_node_t* _parse_or_expr(parser_ctx_t* ctx) {
  condition_node_t* left = _parse_and_expr(ctx);
  if (left == NULL) return NULL;

  while (_parser_peek(ctx).type == TOK_OR && !ctx->has_error) {
    _parser_advance(ctx);
    condition_node_t* right = _parse_and_expr(ctx);
    if (right == NULL) {
      condition_node_destroy(left);
      return NULL;
    }
    left = condition_node_create_or(left, right);
  }

  return left;
}

// ============================================================
// Public API: condition_parse
// ============================================================
condition_node_t* condition_parse(const char* expression) {
  if (expression == NULL || expression[0] == '\0') return NULL;

  parser_ctx_t ctx;
  _parser_init(&ctx, expression);

  condition_node_t* root = _parse_or_expr(&ctx);
  if (ctx.has_error || root == NULL) {
    condition_node_destroy(root);
    return NULL;
  }

  // There should be no remaining tokens
  if (_parser_peek(&ctx).type != TOK_EOF) {
    condition_node_destroy(root);
    return NULL;
  }

  return root;
}

// ============================================================
// Node creation helpers
// ============================================================
condition_node_t* condition_node_create_comparison(const char* left, comparison_op_e op,
                                                    int64_t literal) {
  condition_node_t* node = get_clear_memory(sizeof(condition_node_t));
  node->type = NODE_COMPARISON;
  if (left != NULL) {
    strncpy(node->left_path, left, CRABS_MAX_POLICY_EXPR - 1);
  }
  node->cmp_operator = op;
  node->right_literal = literal;
  return node;
}

condition_node_t* condition_node_create_and(condition_node_t* left, condition_node_t* right) {
  condition_node_t* node = get_clear_memory(sizeof(condition_node_t));
  node->type = NODE_AND;
  node->left = left;
  node->right = right;
  return node;
}

condition_node_t* condition_node_create_or(condition_node_t* left, condition_node_t* right) {
  condition_node_t* node = get_clear_memory(sizeof(condition_node_t));
  node->type = NODE_OR;
  node->left = left;
  node->right = right;
  return node;
}

condition_node_t* condition_node_create_contains(const char* set_path, contains_type_e type,
                                                   bool negated, char** values, uint32_t count) {
  condition_node_t* node = get_clear_memory(sizeof(condition_node_t));
  node->type = NODE_CONTAINS;
  if (set_path != NULL) {
    strncpy(node->set_path, set_path, CRABS_MAX_POLICY_EXPR - 1);
  }
  node->contains_type = type;
  node->negated = negated;
  node->element_count = count;
  node->element_values = get_memory(count * sizeof(char*));
  for (uint32_t i = 0; i < count; i++) {
    node->element_values[i] = strdup(values[i]);
  }
  return node;
}

// ============================================================
// Node destruction
// ============================================================
void condition_node_destroy(condition_node_t* node) {
  if (node == NULL) return;

  // Free element_values
  if (node->element_values != NULL) {
    for (uint32_t i = 0; i < node->element_count; i++) {
      if (node->element_values[i] != NULL) {
        free(node->element_values[i]);
      }
    }
    free(node->element_values);
  }

  // Recursively destroy children
  condition_node_destroy(node->left);
  condition_node_destroy(node->right);

  free(node);
}

// ============================================================
// Path resolution
// ============================================================
static data_item_t* _find_item_by_path(const state_t* state, const char* path) {
  // Try full path first
  data_item_t* item = state_find_item((state_t*)state, path);
  if (item != NULL) return item;

  // Try progressively shorter prefixes
  char path_buf[CRABS_MAX_POLICY_EXPR];
  strncpy(path_buf, path, CRABS_MAX_POLICY_EXPR - 1);
  path_buf[CRABS_MAX_POLICY_EXPR - 1] = '\0';

  char* dot = strrchr(path_buf, '.');
  while (dot != NULL) {
    *dot = '\0';
    item = state_find_item((state_t*)state, path_buf);
    if (item != NULL) return item;
    dot = strrchr(path_buf, '.');
  }

  return NULL;
}

int64_t condition_resolve_path(const state_t* state, const char* path) {
  if (state == NULL || path == NULL) return 0;

  data_item_t* item = _find_item_by_path(state, path);
  if (item == NULL) return 0;
  if (item->value == NULL) return 0;

  switch (item->crdt_type) {
    case CRDT_G_COUNTER:
      return g_counter_value((const g_counter_t*)item->value);
    case CRDT_PN_COUNTER:
      return pn_counter_value((const pn_counter_t*)item->value);
    default:
      // For other types, try interpreting as raw int64_t
      return *(int64_t*)item->value;
  }
}

// ============================================================
// CONTAINS evaluation helper
// ============================================================
static bool _evaluate_contains(const condition_node_t* node, const state_t* state) {
  data_item_t* item = _find_item_by_path(state, node->set_path);
  if (item == NULL) {
    return node->negated; // Not found: negated=true means NOT in set = true
  }

  bool result = false;

  switch (item->crdt_type) {
    case CRDT_OR_SET: {
      or_set_t* set = (or_set_t*)item->value;
      if (set == NULL) break;

      switch (node->contains_type) {
        case CONTAINS_SINGLE:
          result = or_set_contains(set, node->element_values[0]);
          break;
        case CONTAINS_ANY:
          result = false;
          for (uint32_t i = 0; i < node->element_count; i++) {
            if (or_set_contains(set, node->element_values[i])) {
              result = true;
              break;
            }
          }
          break;
        case CONTAINS_ALL:
          result = true;
          for (uint32_t i = 0; i < node->element_count; i++) {
            if (!or_set_contains(set, node->element_values[i])) {
              result = false;
              break;
            }
          }
          break;
      }
      break;
    }
    case CRDT_2P_SET: {
      two_p_set_t* set = (two_p_set_t*)item->value;
      if (set == NULL) break;

      switch (node->contains_type) {
        case CONTAINS_SINGLE:
          result = two_p_set_contains(set, node->element_values[0]);
          break;
        case CONTAINS_ANY:
          result = false;
          for (uint32_t i = 0; i < node->element_count; i++) {
            if (two_p_set_contains(set, node->element_values[i])) {
              result = true;
              break;
            }
          }
          break;
        case CONTAINS_ALL:
          result = true;
          for (uint32_t i = 0; i < node->element_count; i++) {
            if (!two_p_set_contains(set, node->element_values[i])) {
              result = false;
              break;
            }
          }
          break;
      }
      break;
    }
    default:
      // Unsupported set type for CONTAINS
      break;
  }

  // Apply negation
  if (node->negated) {
    result = !result;
  }

  return result;
}

// ============================================================
// IN evaluation helper
// ============================================================
static bool _evaluate_in(const condition_node_t* node, const state_t* state) {
  int64_t left_value = condition_resolve_path(state, node->left_path);

  for (uint32_t i = 0; i < node->element_count; i++) {
    // Try to parse element as number
    char* endptr = NULL;
    int64_t elem_val = strtoll(node->element_values[i], &endptr, 10);
    if (endptr != node->element_values[i] && *endptr == '\0') {
      // It's a number
      if (left_value == elem_val) return true;
    } else {
      // It's a string, try resolving as path
      int64_t path_val = condition_resolve_path(state, node->element_values[i]);
      if (left_value == path_val) return true;
    }
  }
  return false;
}

// ============================================================
// Main evaluation
// ============================================================
bool condition_evaluate(const condition_node_t* node, const state_t* state) {
  if (node == NULL || state == NULL) return false;

  switch (node->type) {
    case NODE_COMPARISON: {
      int64_t left_value = condition_resolve_path(state, node->left_path);
      int64_t right_value;

      if (node->right_path[0] != '\0') {
        // Right side is a path reference
        right_value = condition_resolve_path(state, node->right_path);
      } else {
        right_value = node->right_literal;
      }

      switch (node->cmp_operator) {
        case CMP_GE:      return left_value >= right_value;
        case CMP_LE:      return left_value <= right_value;
        case CMP_GT:      return left_value > right_value;
        case CMP_LT:      return left_value < right_value;
        case CMP_EQ:      return left_value == right_value;
        case CMP_NE:      return left_value != right_value;
        case CMP_BETWEEN: return left_value >= right_value && left_value <= node->right_literal_2;
        case CMP_IN:      return _evaluate_in(node, state);
        default:          return false;
      }
    }

    case NODE_AND:
      return condition_evaluate(node->left, state) && condition_evaluate(node->right, state);

    case NODE_OR:
      return condition_evaluate(node->left, state) || condition_evaluate(node->right, state);

    case NODE_CONTAINS:
      return _evaluate_contains(node, state);

    default:
      return false;
  }
}