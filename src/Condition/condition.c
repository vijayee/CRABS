//
// Created by victor on 4/30/25.
//

#include "condition.h"
#include "../Util/platform.h"
#include "../Util/allocator.h"
#include "../CRDT/crdt_merge.h"
#include <string.h>
#include <strings.h>
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
  // Audit R4-7: track recursion depth so a future increase in
  // CRABS_MAX_POLICY_EXPR (or a path that bypasses the cap) cannot turn the
  // recursive-descent parser into a stack-overflow DoS. Each parenthesized
  // sub-expression adds one level via _parse_comparison -> _parse_or_expr.
  uint32_t   depth;
} parser_ctx_t;

// Audit R4-7: maximum nesting depth for the condition parser. 64 levels
// comfortably exceeds any legitimate policy expression (the 256-byte input
// cap allows ~85 levels of bare parens `(((...)))`), while blocking
// pathological inputs that could overflow the stack if the input cap is
// ever raised.
#define CRABS_CONDITION_MAX_DEPTH 64

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
  ctx->depth = 0;
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
static void _free_value_list(char** values, uint32_t count) {
  if (values == NULL) return;
  for (uint32_t i = 0; i < count; i++) {
    if (values[i] != NULL) free(values[i]);
  }
  free(values);
}

static bool _parse_value_list(parser_ctx_t* ctx, bool allow_string_elements,
                              char*** values, uint32_t* count) {
  *values = NULL;
  *count = 0;

  if (!_parser_expect(ctx, TOK_LPAREN)) return false;

  uint32_t capacity = 4;
  *values = get_memory(capacity * sizeof(char*));

  primary_t elem;
  if (!_parse_primary(ctx, &elem)) {
    _free_value_list(*values, 0);
    *values = NULL;
    return false;
  }
  // Audit fix (High, conf 9): in a numeric membership list (IN) a quoted
  // string element would be resolved as a state path at evaluation time
  // (missing path -> 0), so "x IN (\"a\")" matched any missing left side
  // (0 == 0). IN rejects quoted strings; CONTAINS_ANY/CONTAINS_ALL keep
  // accepting them because their elements are compared as strings against
  // CRDT set members, never resolved as paths.
  if (!allow_string_elements && elem.type == PRIMARY_STRING) {
    _free_value_list(*values, 0);
    *values = NULL;
    ctx->has_error = true;
    return false;
  }
  (*values)[0] = platform_strdup(elem.path);
  *count = 1;

  while (_parser_peek(ctx).type == TOK_COMMA) {
    _parser_advance(ctx); // consume comma
    if (*count >= capacity) {
      capacity *= 2;
      char** new_values = realloc(*values, capacity * sizeof(char*));
      if (new_values == NULL) {
        _free_value_list(*values, *count);
        *values = NULL;
        *count = 0;
        ctx->has_error = true;
        return false;
      }
      *values = new_values;
    }
    if (!_parse_primary(ctx, &elem)) {
      _free_value_list(*values, *count);
      *values = NULL;
      *count = 0;
      return false;
    }
    if (!allow_string_elements && elem.type == PRIMARY_STRING) {
      _free_value_list(*values, *count);
      *values = NULL;
      *count = 0;
      ctx->has_error = true;
      return false;
    }
    (*values)[*count] = platform_strdup(elem.path);
    (*count)++;
  }

  if (!_parser_expect(ctx, TOK_RPAREN)) {
    _free_value_list(*values, *count);
    *values = NULL;
    *count = 0;
    return false;
  }

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

    // Audit fix (High, conf 9): a quoted string is not a state path. It used
    // to be stored into right_path (or left_path below) and resolved via
    // condition_resolve_path, where a missing path yields 0 — so
    // "x == \"active\"" evaluated as 0 == 0 (true with no state at all), and
    // a rendered policy like "x == premium" made crypto_abe_eval_policy
    // atoll() both sides to 0. String operands never had working comparison
    // semantics, so they are rejected at parse time (fail closed) in both
    // operand positions.
    if (primary.type == PRIMARY_STRING) {
      ctx->has_error = true;
      return NULL;
    }

    primary_t right;
    if (!_parse_primary(ctx, &right)) {
      return NULL;
    }

    if (right.type == PRIMARY_STRING) {
      ctx->has_error = true;
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
    }
    return node;
  }

  // BETWEEN
  if (next.type == TOK_BETWEEN) {
    _parser_advance(ctx);

    // Audit fix (High, conf 9): the BETWEEN bounds were silently dropped
    // unless they were numbers (high bound) or a path/string mix (low bound),
    // so "balance BETWEEN 0 AND maxval" degraded to "balance <= 0" and a
    // quoted string low bound degraded to "balance >= 0". Both must be
    // numeric (the low bound may be a state-path reference) or the parse
    // fails (fail closed).
    if (primary.type == PRIMARY_STRING) {
      ctx->has_error = true;
      return NULL;
    }

    primary_t low;
    if (!_parse_primary(ctx, &low)) return NULL;

    if (low.type != PRIMARY_NUMBER && low.type != PRIMARY_PATH) {
      ctx->has_error = true;
      return NULL;
    }

    if (!_parser_expect(ctx, TOK_AND)) return NULL;

    primary_t high;
    if (!_parse_primary(ctx, &high)) return NULL;

    if (high.type != PRIMARY_NUMBER) {
      ctx->has_error = true;
      return NULL;
    }

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
      // Audit fix (High, conf 9): numeric membership needs a numeric left
      // side; a quoted-string left operand would resolve as a missing path
      // (0) and match a numeric element of 0. Quoted elements in the list
      // are rejected by _parse_value_list below. Bare identifier elements
      // stay allowed — they are path references, which is intended.
      if (primary.type == PRIMARY_STRING) {
        ctx->has_error = true;
        return NULL;
      }
      char** values = NULL;
      uint32_t count = 0;
      if (!_parse_value_list(ctx, false, &values, &count)) return NULL;

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
      node->element_values[0] = platform_strdup(primary.path);
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
    node->element_values[0] = platform_strdup(value.path);
    node->element_count = 1;
    return node;
  }

  // CONTAINS_ANY
  if (next.type == TOK_CONTAINS_ANY) {
    _parser_advance(ctx);

    char** values = NULL;
    uint32_t count = 0;
    if (!_parse_value_list(ctx, true, &values, &count)) return NULL;

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
    if (!_parse_value_list(ctx, true, &values, &count)) return NULL;

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
      node->element_values[0] = platform_strdup(value.path);
      node->element_count = 1;
      return node;
    }

    // NOT CONTAINS_ANY
    if (after_not.type == TOK_CONTAINS_ANY) {
      _parser_advance(ctx);

      char** values = NULL;
      uint32_t count = 0;
      if (!_parse_value_list(ctx, true, &values, &count)) return NULL;

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
      if (!_parse_value_list(ctx, true, &values, &count)) return NULL;

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
      node->element_values[0] = platform_strdup(primary.path);
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
  // Audit R4-7: bound recursion depth. Each parenthesized sub-expression
  // re-enters _parse_or_expr via _parse_comparison, so this check caps the
  // total nesting depth. Without it, a future increase in
  // CRABS_MAX_POLICY_EXPR could allow a deeply nested input to overflow
  // the stack.
  if (ctx->depth >= CRABS_CONDITION_MAX_DEPTH) {
    ctx->has_error = true;
    return NULL;
  }
  ctx->depth++;
  condition_node_t* left = _parse_and_expr(ctx);
  ctx->depth--;
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
  if (count > 0 && values != NULL) {
    node->element_values = get_memory(count * sizeof(char*));
    for (uint32_t i = 0; i < count; i++) {
      node->element_values[i] = platform_strdup(values[i]);
    }
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
  // Audit: resolve the FULL path only. The prior fallback stripped trailing
  // ".segment" components and returned the prefix item, so a condition on the
  // missing path "tenant.quota" silently resolved to an attacker-controlled
  // sibling item named "tenant". An unresolvable path must return not-found
  // and fall through to the caller's existing missing-value semantics
  // (resolve -> 0, CONTAINS -> not-contained); it must never alias an
  // unrelated item.
  return state_find_item((state_t*)state, path);
}

int64_t condition_resolve_path(const state_t* state, const char* path) {
  if (state == NULL || path == NULL) return 0;

  data_item_t* item = _find_item_by_path(state, path);
  if (item == NULL) {
    return 0;
  }
  if (item->value == NULL) {
    return 0;
  }

  switch (item->crdt_type) {
    case CRDT_G_COUNTER: {
      const g_counter_t* gc = (const g_counter_t*)item->value;
      int64_t v = g_counter_value(gc);
      return v;
    }
    case CRDT_PN_COUNTER: {
      int64_t v = pn_counter_value((const pn_counter_t*)item->value);
      return v;
    }
    default:
      if (item->crdt_type == CRDT_LWW_REG || item->type == DATA_TYPE_REGISTER) {
        const lww_register_t* reg = (const lww_register_t*)item->value;
        if (reg != NULL && reg->value_size >= sizeof(int64_t)) {
          return *(int64_t*)reg->value;
        }
      }
      return 0;
  }
}

// ============================================================
// CONTAINS evaluation helper
// ============================================================
static bool _evaluate_contains(const condition_node_t* node, const state_t* state) {
  if (node->element_count == 0 || node->element_values == NULL) {
    // No elements to check: CONTAINS_ANY → false, CONTAINS_ALL → true
    bool result = (node->contains_type == CONTAINS_ALL);
    return node->negated ? !result : result;
  }

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

// ============================================================
// Policy Pre-processing (Amendment 2 §5)
// ============================================================

// Detect a CONTAINS node reachable through an OR ancestor. The two-phase
// policy evaluator (CONTAINS via state, everything else via ABE) cannot
// soundly evaluate OR-of-CONTAINS — fail closed in that case.
static bool _contains_under_or(const condition_node_t* node, bool under_or) {
  if (node == NULL) return false;
  if (node->type == NODE_CONTAINS && under_or) return true;
  if (node->type == NODE_OR) {
    return _contains_under_or(node->left, true) ||
           _contains_under_or(node->right, true);
  }
  if (node->type == NODE_AND) {
    return _contains_under_or(node->left, under_or) ||
           _contains_under_or(node->right, under_or);
  }
  return false;
}

// Recursively filter CONTAINS nodes from a parsed AST.
// Returns a new AST with only non-CONTAINS nodes, or NULL if all filtered.
// Walk the AST and evaluate each CONTAINS node individually.
// Sets *all_pass to false if any CONTAINS node evaluates to false.
static void _evaluate_contains_nodes(const condition_node_t* node,
                                      const state_t* state, bool* all_pass) {
  if (node == NULL) return;
  if (node->type == NODE_CONTAINS) {
    if (!condition_evaluate(node, state)) {
      *all_pass = false;
    }
    return;
  }
  _evaluate_contains_nodes(node->left, state, all_pass);
  _evaluate_contains_nodes(node->right, state, all_pass);
}

static condition_node_t* _filter_contains_nodes(condition_node_t* node) {
  if (node == NULL) return NULL;

  if (node->type == NODE_CONTAINS) {
    // CONTAINS nodes are removed from the ABE policy
    return NULL;
  }

  if (node->type == NODE_AND) {
    condition_node_t* left = _filter_contains_nodes(node->left);
    condition_node_t* right = _filter_contains_nodes(node->right);

    if (left == NULL && right == NULL) return NULL;
    if (left == NULL) return right;
    if (right == NULL) return left;
    return condition_node_create_and(left, right);
  }

  if (node->type == NODE_OR) {
    condition_node_t* left = _filter_contains_nodes(node->left);
    condition_node_t* right = _filter_contains_nodes(node->right);

    if (left == NULL || right == NULL) return NULL;
    return condition_node_create_or(left, right);
  }

  // COMPARISON nodes pass through
  condition_node_t* copy = get_clear_memory(sizeof(condition_node_t));
  memcpy(copy, node, sizeof(condition_node_t));
  copy->element_values = NULL;
  copy->element_count = 0;
  copy->left = NULL;
  copy->right = NULL;

  // Deep-copy element_values if present (CMP_IN)
  if (node->element_values != NULL && node->element_count > 0) {
    copy->element_values = get_memory(node->element_count * sizeof(char*));
    for (uint32_t i = 0; i < node->element_count; i++) {
      copy->element_values[i] = platform_strdup(node->element_values[i]);
    }
    copy->element_count = node->element_count;
  }

  return copy;
}

// Convert an AST back to a policy string (for ABE consumption)
static void _ast_to_string(const condition_node_t* node, char* buf, size_t bufsize) {
  if (node == NULL || buf == NULL || bufsize == 0) return;

  size_t len = strlen(buf);
  if (len >= bufsize) return;
  size_t remaining = bufsize - len - 1;

  if (node->type == NODE_COMPARISON) {
    // Comparison: left_path op value
    char tmp[CRABS_MAX_POLICY_EXPR];
    const char* op_str = "";
    switch (node->cmp_operator) {
      case CMP_GE: op_str = ">="; break;
      case CMP_LE: op_str = "<="; break;
      case CMP_GT: op_str = ">"; break;
      case CMP_LT: op_str = "<"; break;
      case CMP_EQ: op_str = "=="; break;
      case CMP_NE: op_str = "!="; break;
      case CMP_BETWEEN:
        snprintf(tmp, sizeof(tmp), "%s BETWEEN %lld AND %lld",
                 node->left_path, (long long)node->right_literal, (long long)node->right_literal_2);
        strncat(buf, tmp, remaining);
        return;
      case CMP_IN: {
        snprintf(tmp, sizeof(tmp), "%s IN (", node->left_path);
        len = strlen(buf);
        if (len < bufsize) strncat(buf, tmp, bufsize - len - 1);
        for (uint32_t i = 0; i < node->element_count; i++) {
          len = strlen(buf);
          if (len >= bufsize) break;
          if (i > 0) strncat(buf, ", ", bufsize - len - 1);
          len = strlen(buf);
          if (len < bufsize) strncat(buf, node->element_values[i], bufsize - len - 1);
        }
        len = strlen(buf);
        if (len < bufsize) strncat(buf, ")", bufsize - len - 1);
        return;
      }
      default: op_str = "?"; break;
    }

    if (node->right_path[0] != '\0') {
      snprintf(tmp, sizeof(tmp), "%s %s %s", node->left_path, op_str, node->right_path);
    } else {
      snprintf(tmp, sizeof(tmp), "%s %s %lld", node->left_path, op_str, (long long)node->right_literal);
    }
    strncat(buf, tmp, remaining);
  } else if (node->type == NODE_AND) {
    // R7-09: emit prefix form ("AND <l> <r>") to match the ABE evaluator's
    // grammar. The prior infix "left AND right" made every compound policy
    // deny (the evaluator parsed the first token, then rejected the rest as
    // trailing garbage).
    strncat(buf, "AND ", remaining);
    _ast_to_string(node->left, buf, bufsize);
    len = strlen(buf);
    if (len < bufsize) strncat(buf, " ", bufsize - len - 1);
    _ast_to_string(node->right, buf, bufsize);
  } else if (node->type == NODE_OR) {
    strncat(buf, "OR ", remaining);
    _ast_to_string(node->left, buf, bufsize);
    len = strlen(buf);
    if (len < bufsize) strncat(buf, " ", bufsize - len - 1);
    _ast_to_string(node->right, buf, bufsize);
  }
}

// Resolve {user_id} placeholder in a string. Returns false on failure (the
// replacement does not fit) so the caller can fail preprocessing instead of
// truncating — the old truncation path memcpy'd the full placeholder length
// from a shorter signer_id, reading past its NUL (R7-L-7).
static bool _resolve_user_id_placeholder(char* str, const char* signer_id) {
  if (str == NULL || signer_id == NULL) return false;

  char placeholder[] = "{user_id}";
  char* pos;
  while ((pos = strstr(str, placeholder)) != NULL) {
    size_t plen = strlen(placeholder);
    size_t slen = strlen(signer_id);
    size_t remaining = strlen(pos + plen);

    // R8-CL-1: if the replacement is identical to the placeholder (signer_id is
    // literally "{user_id}"), replacing it with itself would loop forever. The
    // placeholder already equals the resolved value, so stop.
    if (slen == plen && memcmp(pos, signer_id, plen) == 0) {
      break;
    }

    if (slen <= plen) {
      // Replacement is shorter or equal: safe to copy in place
      memmove(pos + slen, pos + plen, remaining + 1);
      memcpy(pos, signer_id, slen);
    } else {
      // Replacement is longer: need to shift
      size_t offset = pos - str;
      size_t total_len = strlen(str);
      if (offset + slen + remaining < CRABS_MAX_POLICY_EXPR) {
        memmove(pos + slen, pos + plen, remaining + 1);
        memcpy(pos, signer_id, slen);
      } else {
        // Can't fit: fail preprocessing instead of truncating.
        return false;
      }
    }
  }
  return true;
}

policy_preprocess_result_t preprocess_policy(const char* policy, const state_t* state, const char* signer_id) {
  policy_preprocess_result_t result;
  memset(&result, 0, sizeof(result));
  result.resolved_ok = true;

  if (policy == NULL || policy[0] == '\0') {
    return result;
  }

  // Step 1: Make a working copy and resolve {user_id} placeholders
  char work_buf[CRABS_MAX_POLICY_EXPR];
  strncpy(work_buf, policy, CRABS_MAX_POLICY_EXPR - 1);
  work_buf[CRABS_MAX_POLICY_EXPR - 1] = '\0';

  if (!_resolve_user_id_placeholder(work_buf, signer_id)) {
    result.resolved_ok = false;
    return result;
  }

  // Step 2: Parse the policy into an AST
  condition_node_t* ast = condition_parse(work_buf);
  if (ast == NULL) {
    // Audit fix (High, conf 9): condition_parse now rejects quoted-string
    // operands. A policy that still contains a quote cannot be a valid bare
    // attribute token either (attribute tokens are "name:value" strings with
    // no quotes), so it is unambiguous user error — fail closed instead of
    // passing the raw expression through as an ABE token that would match
    // nothing (deny) or, worse, be re-atoll()ed by a downstream evaluator.
    if (strchr(work_buf, '"') != NULL) {
      result.resolved_ok = false;
      return result;
    }
    // Not a condition expression — treat as a bare attribute policy. Keep the
    // full "name:value" token: _build_attr_string emits "name:value" tokens and
    // crypto_abe_eval_policy matches whole tokens, so "role:admin" matches
    // "role:admin" exactly. Stripping the name prefix here (the old behavior)
    // made "role:admin" and "dept:admin" collide and let a self-asserted
    // "clearance:admin" satisfy a "role:admin" policy (audit F-1).
    strncpy(result.abe_policy, work_buf, CRABS_MAX_POLICY_EXPR - 1);
    result.abe_policy[CRABS_MAX_POLICY_EXPR - 1] = '\0';
    result.resolved_ok = true;
    return result;
  }

  // Step 3: Evaluate all CONTAINS nodes against state
  // Walk the AST and evaluate each CONTAINS node individually.
  // CONTAINS nodes verify that an element exists in the state's CRDT sets.
  // ABE comparison nodes are evaluated separately by the ABE engine.
  //
  // The two-phase evaluator can only soundly evaluate CONTAINS under AND (or
  // at the top). A CONTAINS under an OR makes the ABE/CONTAINS split
  // ambiguous — fail closed.
  if (_contains_under_or(ast, false)) {
    condition_node_destroy(ast);
    result.resolved_ok = false;
    return result;
  }

  bool all_contains_pass = true;

  // Walk and evaluate CONTAINS nodes
  condition_node_t* filtered = _filter_contains_nodes(ast);

  // Evaluate CONTAINS nodes independently from ABE nodes.
  // This ensures mixed CONTAINS + ABE policies aren't incorrectly rejected
  // when only the ABE comparison (not the CONTAINS check) fails.
  _evaluate_contains_nodes(ast, state, &all_contains_pass);

  // Step 4: Build the ABE policy string from the filtered AST
  if (filtered != NULL) {
    result.abe_policy[0] = '\0';
    _ast_to_string(filtered, result.abe_policy, CRABS_MAX_POLICY_EXPR);

    // Clean up the filtered AST
    condition_node_destroy(filtered);
  } else {
    // All nodes were CONTAINS nodes; ABE policy is empty (all resolved)
    result.abe_policy[0] = '\0';
  }

  // Clean up the original AST
  condition_node_destroy(ast);

  result.resolved_ok = all_contains_pass;
  return result;
}
