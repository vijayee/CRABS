CRABS Protocol Specification v1.2 — Amendment 2
Set Membership Conditions: The CONTAINS Operator
Amendment Status: Draft
Spec Version: 1.2.0
Date: April 30, 2026
Supersedes: Amendment 1 §3 (Condition Language)

Preamble
Amendment 1 introduced Threshold Triggers with a condition language for evaluating state expressions. However, the initial condition language only supported scalar comparisons (>=, ==, etc.). Many applications require querying set membership — checking whether a value exists within a set data item in the state.

This amendment extends the condition language with the CONTAINS, CONTAINS_ANY, and CONTAINS_ALL operators, enabling policies and triggers to directly query set membership without intermediate attribute issuance.

1. Motivation
   In the base CRABS protocol, sets are a fundamental data type (SET with OR-Set CRDT, 2P_SET). Applications naturally model group membership as sets:

Course enrollment: physics_101.enrolled = {alice, bob, carol}
Content moderation: mod_queue = {video_abc, video_def}
Access control lists: document_42.readers = {alice, bob}
Channel subscriptions: user_alice.subscriptions = {channel_x, channel_y}
Without set membership queries, policies must rely on pre-issued attributes that mirror set state. This creates a synchronization problem: when the set changes, attributes must be re-issued. The CONTAINS operator eliminates this indirection by allowing policies to query the state directly.

2. Changes to the Condition Language
   2.1 Extended Grammar
   The condition language grammar (Amendment 1 §3.1) is extended with three new comparison operators:

plaintext

<comparison> ::= <path> <op> <value>
               | <path> "BETWEEN" <value> "AND" <value>
               | <path> "IN" "(" <value> ("," <value>)* ")"
               | <path> "CONTAINS" <value>                          // NEW
               | <path> "CONTAINS_ANY" "(" <value> ("," <value>)* ")"  // NEW
               | <path> "CONTAINS_ALL" "(" <value> ("," <value>)* ")"  // NEW
               | <value> "IN" <path>                                 // NEW (syntactic sugar)
2.2 New Comparison Operators
Operator	Syntax	Semantics
CONTAINS	<path> CONTAINS <value>	True if the set at <path> includes <value>
CONTAINS_ANY	<path> CONTAINS_ANY (v1, v2, ...)	True if the set includes any of the listed values
CONTAINS_ALL	<path> CONTAINS_ALL (v1, v2, ...)	True if the set includes all of the listed values
IN (sugar)	<value> IN <path>	Syntactic sugar for <path> CONTAINS <value>
2.3 Examples
plaintext

// Basic membership
"physics_101.enrolled CONTAINS alice"
"alice IN physics_101.enrolled"                    // Equivalent sugar

// Multiple membership (any)
"mod_queue CONTAINS_ANY (video_abc, video_def)"

// Multiple membership (all)
"prerequisites CONTAINS_ALL (cs-101, cs-102)"

// Combined with other conditions
"physics_101.enrolled CONTAINS alice AND alice.role CONTAINS student"

// Nested path membership
"user_alice.enrolled_classes CONTAINS physics_101"

// Membership in trigger conditions
condition: "video_abc.flags >= 10 AND mod_queue NOT CONTAINS video_abc"
// Auto-add to mod queue if flagged but not already there
2.4 Negation
All CONTAINS operators support negation with NOT:

plaintext

<path> "NOT" "CONTAINS" <value>
<path> "NOT" "CONTAINS_ANY" "(" <value> ("," <value>)* ")"
<path> "NOT" "CONTAINS_ALL" "(" <value> ("," <value>)* ")"
<value> "NOT" "IN" <path>
Examples:

plaintext

"physics_101.enrolled NOT CONTAINS alice"
"alice NOT IN physics_101.enrolled"
"mod_queue NOT CONTAINS_ANY (video_abc, video_def)"
3. New AST Node Types
   3.1 Extended ConditionNode
   plaintext

ConditionNode = {
type: NodeType,

    // For COMPARISON nodes (existing):
    left_path: string,
    operator: ComparisonOp,
    right_path: string,
    right_literal: int64,
    right_literal_2: int64,
    
    // For CONTAINS nodes (NEW):
    set_path: string,              // Path to the set (e.g., "physics_101.enrolled")
    element_values: string[],      // Values to check membership for
    element_count: uint32,
    contains_type: ContainsType,   // CONTAINS, CONTAINS_ANY, CONTAINS_ALL
    negated: bool,                 // true if NOT CONTAINS
    
    // For BOOLEAN nodes (existing):
    left: ConditionNode,
    right: ConditionNode
}

NodeType = enum {
COMPARISON  = 0x01,
AND         = 0x02,
OR          = 0x03,
CONTAINS    = 0x04             // NEW
}

ContainsType = enum {
CONTAINS      = 0x01,  // Set contains a single value
CONTAINS_ANY  = 0x02,  // Set contains any of the values
CONTAINS_ALL  = 0x03   // Set contains all of the values
}
3.2 Parsing Examples
plaintext

Input:  "physics_101.enrolled CONTAINS alice"

Parsed AST:
{
type: CONTAINS,
set_path: "physics_101.enrolled",
element_values: ["alice"],
element_count: 1,
contains_type: CONTAINS,
negated: false
}
plaintext

Input:  "mod_queue CONTAINS_ANY (video_abc, video_def)"

Parsed AST:
{
type: CONTAINS,
set_path: "mod_queue",
element_values: ["video_abc", "video_def"],
element_count: 2,
contains_type: CONTAINS_ANY,
negated: false
}
plaintext

Input:  "physics_101.enrolled NOT CONTAINS alice"

Parsed AST:
{
type: CONTAINS,
set_path: "physics_101.enrolled",
element_values: ["alice"],
element_count: 1,
contains_type: CONTAINS,
negated: true
}
4. Evaluation Algorithm
   4.1 CONTAINS Evaluation
   plaintext

Algorithm: EVALUATE_CONTAINS

Input:
state          — Current CRABS state
set_path       — Path to a set value (e.g., "physics_101.enrolled")
element_values — Values to check membership for
contains_type  — CONTAINS, CONTAINS_ANY, or CONTAINS_ALL
negated        — Whether the condition is negated

Output:
bool — Whether the membership condition is satisfied

1. // Resolve the set from the state
2. set_value = RESOLVE_PATH(state, set_path)
3.
4. // Validate that the resolved value is actually a set
5. if set_value is not a set/array type:
6.     return false
7.
8. // Check membership based on type
9. switch contains_type:
10.    case CONTAINS:
11.        // Single value membership
12.        result = element_values[0] in set_value
13.
14.    case CONTAINS_ANY:
15.        // True if ANY of the values is in the set
16.        result = false
17.        for each val in element_values:
18.            if val in set_value:
19.                result = true
20.                break
21.
22.    case CONTAINS_ALL:
23.        // True if ALL of the values are in the set
24.        result = true
25.        for each val in element_values:
26.            if val not in set_value:
27.                result = false
28.                break
29.
30. // Apply negation
31. if negated:
32.     return not result
33. else:
34.     return result
4.2 Integration with Main Condition Evaluator
The main EVALUATE_CONDITION algorithm (Amendment 1 §5.1) is extended to handle the new CONTAINS node type:

plaintext

Algorithm: EVALUATE_CONDITION (v1.2)

Input:
state     — Current CRABS state
condition — Parsed ConditionNode AST

Output:
bool — Whether the condition is satisfied

1. switch condition.type:
2.     case COMPARISON:
3.         // ... unchanged from Amendment 1 ...
4.
5.     case CONTAINS:                          // NEW
6.         return EVALUATE_CONTAINS(
7.             state,
8.             condition.set_path,
9.             condition.element_values,
10.            condition.contains_type,
11.            condition.negated
12.        )
13.
14.    case AND:
15.        return EVALUATE_CONDITION(state, condition.left)
16.               AND EVALUATE_CONDITION(state, condition.right)
17.
18.    case OR:
19.        return EVALUATE_CONDITION(state, condition.left)
20.               OR EVALUATE_CONDITION(state, condition.right)
5. Policy Integration
   5.1 Direct Use in ABE Policies
   The CONTAINS operator can be used directly in ABE policy expressions that are evaluated by the state machine:

plaintext

// Standard ABE policy (attribute-based):
"role:student AND enrolled:physics_101"

// CONTAINS-based policy (state-querying):
"role:student AND enrolled_classes CONTAINS physics_101"
Important: The CONTAINS operator in policies is evaluated by the state machine during operation verification, not by the ABE cryptographic primitive. The ABE layer still sees standard attribute strings. The mapping works as follows:

plaintext

Policy written as:     "role:student AND enrolled_classes CONTAINS physics_101"
│                              │
▼                              ▼
ABE layer sees:        "role:student"              (evaluated by state machine)
(standard attr)             (dynamic state query)

Combined verification:
1. ABE decrypt: Does user have "role:student"? ✅ (cryptographic)
2. State query: Is "physics_101" in user's enrolled_classes set? ✅ (state lookup)
3. Both pass → authorized
   5.2 Policy Pre-processing
   When a policy contains CONTAINS expressions, the state machine pre-processes them before ABE verification:

plaintext

Algorithm: PREPROCESS_POLICY

Input:
policy    — Policy expression string
state     — Current CRABS state
signer_id — User ID of the operation signer

Output:
abe_policy    — ABE-compatible policy string (with CONTAINS resolved)
resolved_ok   — Whether all CONTAINS conditions were satisfied

1. abe_policy = policy
2. resolved_ok = true

3. // Find all CONTAINS expressions in the policy
4. contains_exprs = EXTRACT_CONTAINS_EXPRESSIONS(policy)

5. for each expr in contains_exprs:
6.     // Replace the path with the actual user reference
7.     resolved_path = expr.set_path.replace("{user_id}", signer_id)
8.
9.     // Evaluate the CONTAINS condition
10.    result = EVALUATE_CONTAINS(
11.        state,
12.        resolved_path,
13.        expr.element_values,
14.        expr.contains_type,
15.        expr.negated
16.    )
17.
18.    if not result:
19.        resolved_ok = false
20.        break
21.
22.    // Remove the CONTAINS expression from the policy
23.    // (it's been satisfied, so it doesn't need ABE evaluation)
24.    abe_policy = REMOVE_EXPRESSION(abe_policy, expr)

25. // The remaining policy is pure ABE attributes
26. return {abe_policy, resolved_ok}
    5.3 Example: Policy Resolution
    plaintext

Original policy:
"role:student AND enrolled_classes CONTAINS physics_101"

Step 1: Extract CONTAINS expression
CONTAINS: set_path="enrolled_classes", value="physics_101"

Step 2: Resolve path for signer (alice)
resolved_path = "user_alice.enrolled_classes"

Step 3: Evaluate
user_alice.enrolled_classes = {"cs-101", "physics_101", "algorithms_102"}
"physics_101" in set? → TRUE ✅

Step 4: Remove satisfied CONTAINS, keep remaining ABE policy
abe_policy = "role:student"
resolved_ok = true

Step 5: ABE verification
Does alice have "role:student"? → Check via ABE decryption ✅

Step 6: Both pass → AUTHORIZED
6. Trigger Integration
   The CONTAINS operator is available in trigger conditions (Amendment 1):

6.1 Enrollment-Based Trigger
plaintext

Trigger: "auto_enroll_attribute"
condition: "user.{id}.enrolled_classes CONTAINS physics_101"
effect: {
type: ISSUE_ATTRIBUTE,
issue_attribute: "enrolled:physics_101",
target_role: "{id}",       // Issue to the specific user
duration_ms: 0             // Permanent while condition holds
}
cooldown_ms: 0                 // Re-evaluate on every state change
6.2 Mod Queue Auto-Population
plaintext

Trigger: "auto_mod_queue"
condition: "video_abc.flags >= 10 AND mod_queue NOT CONTAINS video_abc"
effect: {
type: CUSTOM,
callback: "add_to_mod_queue",
callback_data: {video: "video_abc"}
}
cooldown_ms: 60000
6.3 Prerequisite Enforcement
plaintext

Trigger: "check_prerequisites"
condition: "user.{id}.completed_courses CONTAINS_ALL (cs-101, cs-102)"
effect: {
type: ISSUE_ATTRIBUTE,
issue_attribute: "prerequisites_met:algorithms_201",
target_role: "{id}",
duration_ms: 0
}
cooldown_ms: 0
7. Serialization
   7.1 CONTAINS Node Serialization
   plaintext

ConditionNodeSerialized = {
// ... existing fields for COMPARISON nodes ...

    // For CONTAINS nodes (NEW):
    node_type: uint8,                    // 0x04 = CONTAINS
    set_path_length: uint16,
    set_path: byte[set_path_length],
    element_count: uint32,
    element_values: byte[element_count][],  // Each: uint16 len + bytes
    contains_type: uint8,                // 0x01=CONTAINS, 0x02=CONTAINS_ANY, 0x03=CONTAINS_ALL
    negated: uint8                       // 0=false, 1=true
}
7.2 Policy Serialization Update
Policies containing CONTAINS expressions are stored as-is (string format) and pre-processed at evaluation time. No serialization format change is needed for policies.

8. Security Considerations
   8.1 Set Size and Performance
   Large sets could impact evaluation performance. Mitigations:

Set size limits: Configurable maximum set size (default: 10,000 elements)
Indexed lookup: Sets SHOULD use hash-based lookup for O(1) CONTAINS checks
Caching: CONTAINS results MAY be cached per (set_path, element) pair with TTL
8.2 Path Injection
The {user_id} placeholder in trigger conditions could be exploited if not properly sanitized. Mitigations:

Strict path validation: Only allow alphanumeric characters and underscores in path segments
No dynamic path construction: The path template is defined at trigger creation time and cannot be modified by user input
Scope restriction: CONTAINS can only query data items the evaluating node has access to
8.3 CONTAINS vs. ABE Attributes
plaintext

Consideration: CONTAINS is evaluated by the state machine,
not by the ABE cryptographic layer.

This means:
- CONTAINS is as trustworthy as the state machine
- ABE attributes are cryptographically guaranteed
- CONTAINS is suitable for authorization within a trusted node network
- For cryptographic guarantees, use ABE attributes derived from triggers

Recommendation:
- Use CONTAINS for intra-machine authorization (fast, dynamic)
- Use ABE attributes for cross-machine or offline authorization (cryptographic)
  8.4 Race Conditions
  If a set changes between policy evaluation and operation execution, a CONTAINS check could be stale. Mitigations:

Atomic evaluation: CONTAINS is evaluated in the same operation execution context as the state change
Read-your-writes: Within a single operation, CONTAINS sees the state AFTER the operation's own changes
Trigger re-evaluation: Triggers re-evaluate after every state change, so CONTAINS-based attributes are always current
9. Backward Compatibility
   9.1 Condition Language
   Existing conditions using only comparison operators (>=, ==, etc.) remain fully compatible. The new CONTAINS operators are additive.

9.2 Policy Evaluation
Existing policies without CONTAINS expressions are evaluated exactly as before. The pre-processing step is a no-op for policies without CONTAINS.

9.3 Trigger Definitions
Existing triggers without CONTAINS conditions remain unchanged. The CONTAINS operator is available for new trigger definitions.

10. Test Vectors
    10.1 Basic CONTAINS
    plaintext

Setup:
- State set "course.enrolled" = {"alice", "bob"}
- Condition: "course.enrolled CONTAINS alice"

Expected: TRUE

- Condition: "course.enrolled CONTAINS carol"

Expected: FALSE
10.2 CONTAINS_ANY
plaintext

Setup:
- State set "mod_queue" = {"video_abc", "video_def"}
- Condition: "mod_queue CONTAINS_ANY (video_abc, video_ghi)"

Expected: TRUE (video_abc is in the set)

- Condition: "mod_queue CONTAINS_ANY (video_ghi, video_jkl)"

Expected: FALSE (neither is in the set)
10.3 CONTAINS_ALL
plaintext

Setup:
- State set "prerequisites" = {"cs-101", "cs-102", "math-101"}
- Condition: "prerequisites CONTAINS_ALL (cs-101, cs-102)"

Expected: TRUE (both are in the set)

- Condition: "prerequisites CONTAINS_ALL (cs-101, cs-201)"

Expected: FALSE (cs-201 is not in the set)
10.4 Negation
plaintext

Setup:
- State set "course.enrolled" = {"alice", "bob"}
- Condition: "course.enrolled NOT CONTAINS carol"

Expected: TRUE (carol is not in the set)

- Condition: "course.enrolled NOT CONTAINS alice"

Expected: FALSE (alice IS in the set)
10.5 IN (Syntactic Sugar)
plaintext

Setup:
- State set "course.enrolled" = {"alice", "bob"}
- Condition: "alice IN course.enrolled"

Expected: TRUE (equivalent to "course.enrolled CONTAINS alice")
10.6 Combined Conditions
plaintext

Setup:
- State set "course.enrolled" = {"alice", "bob"}
- State counter "course.capacity" = 50
- Condition: "course.enrolled CONTAINS alice AND course.capacity > 10"

Expected: TRUE (both conditions satisfied)

- Condition: "course.enrolled CONTAINS alice AND course.capacity < 10"

Expected: FALSE (capacity condition not satisfied)
10.7 Trigger with CONTAINS
plaintext

Setup:
- Trigger: condition "mod_queue CONTAINS video_abc"
  effect: issue "needs_review:video_abc" to "moderator"
- State: mod_queue = {"video_def"}

Trigger evaluation: FALSE (video_abc not in mod_queue)

Operation: add video_abc to mod_queue
- mod_queue = {"video_def", "video_abc"}
- Trigger re-evaluates: TRUE
- Attribute "needs_review:video_abc" issued to all moderators
11. Summary of Changes
    Section	Change
    §2.1	Extended condition grammar with CONTAINS operators
    §2.2	New comparison operators table
    §2.3	Examples
    §2.4	Negation syntax
    §3.1	Extended ConditionNode with CONTAINS fields
    §3.2	Parsing examples
    §4.1	EVALUATE_CONTAINS algorithm
    §4.2	Extended EVALUATE_CONDITION
    §5	Policy integration with pre-processing
    §6	Trigger integration examples
    §7	Serialization format
    §8	Security considerations
    §9	Backward compatibility
    §10	Test vectors
    Appendix: Full Condition Language Grammar (v1.2)
    plaintext

<condition> ::= <or_expr>

<or_expr>   ::= <and_expr> ("OR" <and_expr>)*
<and_expr>  ::= <comparison> ("AND" <comparison>)*

<comparison> ::= <path> <scalar_op> <value>
               | <path> "BETWEEN" <value> "AND" <value>
               | <path> "IN" "(" <value> ("," <value>)* ")"
               | <path> "CONTAINS" <value>
               | <path> "CONTAINS_ANY" "(" <value> ("," <value>)* ")"
               | <path> "CONTAINS_ALL" "(" <value> ("," <value>)* ")"
               | <path> "NOT" "CONTAINS" <value>
               | <path> "NOT" "CONTAINS_ANY" "(" <value> ("," <value>)* ")"
               | <path> "NOT" "CONTAINS_ALL" "(" <value> ("," <value>)* ")"
               | <value> "IN" <path>
               | <value> "NOT" "IN" <path>

<path> ::= <identifier> ("." <identifier>)*

<scalar_op> ::= ">=" | "<=" | ">" | "<" | "==" | "!="

<value> ::= <number>
          | <string>
          | <path>
          | "true"
          | "false"
End of CRABS Protocol Specification v1.2 — Amendment 2

This amendment gives you the ability to write policies like:

plaintext

"enrolled_classes CONTAINS physics_101 AND role:student"
"mod_queue CONTAINS video_abc AND role:moderator"
"subscriptions CONTAINS channel_x AND role:viewer"
"prerequisites CONTAINS_ALL (cs-101, cs-102) AND role:student"
Set membership in the state is an attribute — no intermediate issuance needed. 🦀

Want me to write the implementation header crabs_condition.h with the parser and evaluator for the full condition language including CONTAINS?