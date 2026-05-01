CRABS Protocol Specification v1.1 — Amendment 1
Threshold Triggers: State-Conditional Attribute Issuance
Amendment Status: Draft
Spec Version: 1.1.0
Date: April 30, 2026
Author: Derived from protocol design discussion

Preamble
This amendment introduces Threshold Triggers as a first-class primitive in the CRABS protocol. A threshold trigger monitors the state machine's data items and, when a user-defined condition becomes true, automatically issues temporary attributes to specified roles. This enables state-conditional decryption — data can be encrypted under policies that reference dynamic state conditions rather than static attribute assignments.

1. Motivation
   The base CRABS protocol (v1.0) treats attributes as state that changes only through explicit operations (grant_role, self_assert, verify_identity). However, many applications require automatic attribute issuance based on state thresholds:

Content moderation: Reveal uploader contact info when flags on a video exceed a threshold
Reputation systems: Restrict upload privileges when a user's reputation drops below a threshold
Escalation workflows: Notify admins when a support ticket remains unresolved past a deadline
Progressive disclosure: Reveal increasingly sensitive data as conditions escalate
Trending detection: Mark content as "trending" when view counts cross a threshold
These use cases share a common pattern: "When state X reaches value Y, grant attribute Z to role W for duration D."

2. Changes to the Data Model
   2.1 New Type: ThresholdTrigger
   A new field is added to the machine state:

plaintext

State = {
// ... existing fields (version, items, policies, lock_manager, log, config) ...

    triggers: {
        "<trigger_id>": ThresholdTrigger,
        ...
    }
}
2.2 Trigger Definition
plaintext

ThresholdTrigger = {
// Identity
trigger_id: string,              // Unique identifier
description: string,             // Human-readable description

    // Condition
    condition: string,               // Expression string (see §3)
    condition_ast: byte[],           // Pre-parsed condition AST
    
    // Effect
    effect: TriggerEffect,
    
    // Timing
    cooldown_ms: uint64,             // Minimum interval between firings
    last_triggered_at: uint64,       // 0 = never fired
    
    // Lifecycle
    one_shot: bool,                  // Fire only once then self-disable
    enabled: bool,                   // Can be temporarily disabled
    expires_at: uint64,              // 0 = never expires
    created_at: uint64,
    created_by: string
}
2.3 Trigger Effect
plaintext

TriggerEffect = {
type: TriggerEffectType,

    // For ISSUE_ATTRIBUTE:
    issue_attribute: string,         // e.g., "flag_threshold_met:video_abc"
    target_role: string,             // e.g., "moderator"
    duration_ms: uint64,             // How long the attribute is valid
    attribute_value: string,         // Default: "true"
    
    // For COMPOSITE (multiple effects):
    sub_effects: TriggerEffect[]
}

TriggerEffectType = enum {
ISSUE_ATTRIBUTE      = 0x01,  // Issue temporary attribute to a role
CREATE_TRIGGER       = 0x02,  // Create a new trigger dynamically
DELETE_TRIGGER       = 0x03,  // Remove a trigger
DISABLE_TRIGGER      = 0x04,  // Temporarily disable a trigger
CHANGE_POLICY        = 0x05,  // Modify a state policy
CUSTOM               = 0xFF   // Application-defined callback
}
3. Condition Language
   3.1 Grammar
   plaintext

<condition> ::= <or_expr>

<or_expr>   ::= <and_expr> ("OR" <and_expr>)*
<and_expr>  ::= <comparison> ("AND" <comparison>)*

<comparison> ::= <path> <op> <value>
               | <path> "BETWEEN" <value> "AND" <value>
               | <path> "IN" "(" <value> ("," <value>)* ")"

<path> ::= <identifier> ("." <identifier>)*
         // e.g., "video_abc.flags", "user_alice.reputation"

<op> ::= ">=" | "<=" | ">" | "<" | "==" | "!="

<value> ::= <number>
          | <string>
          | <path>
          | "true"
          | "false"
3.2 Examples
plaintext

"video_abc.flags >= 10"
"user_alice.reputation < -50"
"video_abc.flags >= 10 AND video_abc.views >= 1000"
"(video_abc.flags >= 10 OR video_abc.flags_reported >= 5) AND role:moderator"
"video_abc.likes BETWEEN 100 AND 1000"
"user_alice.status IN (suspended, banned)"
3.3 Abstract Syntax Tree
plaintext

ConditionNode = {
type: NodeType,

    // For COMPARISON nodes:
    left_path: string,          // e.g., "video_abc.flags"
    operator: ComparisonOp,
    right_path: string,         // Empty if using literal
    right_literal: int64,       // Used if right_path is empty
    right_literal_2: int64,     // For BETWEEN operator
    
    // For BOOLEAN nodes:
    left: ConditionNode,
    right: ConditionNode
}

NodeType = enum {
COMPARISON  = 0x01,
AND         = 0x02,
OR          = 0x03
}

ComparisonOp = enum {
GE  = 0x01,  // >=
LE  = 0x02,  // <=
GT  = 0x03,  // >
LT  = 0x04,  // <
EQ  = 0x05,  // ==
NE  = 0x06,  // !=
BETWEEN = 0x07,
IN      = 0x08
}
4. New Built-in Operations
   4.1 __create_trigger__
   plaintext

Operation = {
type: "__create_trigger__",
payload: {
trigger_id: "flag_threshold_10",
description: "Reveal uploader contact when flags >= 10",
condition: "video_abc.flags >= 10",
effect: {
type: ISSUE_ATTRIBUTE,
issue_attribute: "flag_threshold_met:video_abc",
target_role: "moderator",
duration_ms: 86400000
},
cooldown_ms: 3600000,
one_shot: false
},
policy: "role:admin",
signature: {...}
}
4.2 __delete_trigger__
plaintext

Operation = {
type: "__delete_trigger__",
payload: { trigger_id: "flag_threshold_10" },
policy: "role:admin",
signature: {...}
}
4.3 __disable_trigger__
plaintext

Operation = {
type: "__disable_trigger__",
payload: {
trigger_id: "flag_threshold_10",
duration_ms: 86400000,  // Disable for 24 hours
reason: "Under review"
},
policy: "role:admin",
signature: {...}
}
4.4 __enable_trigger__
plaintext

Operation = {
type: "__enable_trigger__",
payload: { trigger_id: "flag_threshold_10" },
policy: "role:admin",
signature: {...}
}
5. New Algorithms
   5.1 Condition Evaluation
   plaintext

Algorithm: EVALUATE_CONDITION

Input:
state     — Current CRABS state
condition — Parsed ConditionNode AST

Output:
bool — Whether the condition is satisfied

1. switch condition.type:
2.     case COMPARISON:
3.         left_value = RESOLVE_PATH(state, condition.left_path)
4.
5.         if condition.right_path != "":
6.             right_value = RESOLVE_PATH(state, condition.right_path)
7.         else:
8.             right_value = condition.right_literal
9.
10.        switch condition.operator:
11.            case GE: return left_value >= right_value
12.            case LE: return left_value <= right_value
13.            case GT: return left_value > right_value
14.            case LT: return left_value < right_value
15.            case EQ: return left_value == right_value
16.            case NE: return left_value != right_value
17.            case BETWEEN:
18.                return right_value <= left_value <= condition.right_literal_2
19.            case IN:
20.                return left_value in right_value  // right_value is a set
21.
22.    case AND:
23.        return EVALUATE_CONDITION(state, condition.left)
24.               AND EVALUATE_CONDITION(state, condition.right)
25.
26.    case OR:
27.        return EVALUATE_CONDITION(state, condition.left)
28.               OR EVALUATE_CONDITION(state, condition.right)


Algorithm: RESOLVE_PATH

Input:
state — Current CRABS state
path  — Dot-separated path string (e.g., "video_abc.flags")

Output:
value — The resolved value

1. parts = split(path, ".")
2.
3. // First part is a data item name
4. item = state.items[parts[0]]
5. if item == null:
6.     // Check if it's a user reference
7.     user = attribute_machine.users[parts[0]]
8.     if user == null:
9.         return null
10.    current = user
11. else:
12.    current = item.value
13.
14. // Traverse remaining path segments
15. for i = 1 to len(parts) - 1:
16.     current = current[parts[i]]
17.     if current == null:
18.         return null
19.
20. return current
    5.2 Trigger Processing Engine
    plaintext

Algorithm: PROCESS_TRIGGERS

Input:
state — Current CRABS state (after applying an operation)

Output:
triggered — List of trigger IDs that fired

1. triggered = []

2. // Prune expired temporary attributes first
3. PRUNE_EXPIRED_TEMPORARY_ATTRIBUTES(attribute_machine)

4. for each (trigger_id, trigger) in state.triggers:
5.     // Skip if disabled
6.     if not trigger.enabled:
7.         continue
8.
9.     // Skip if in cooldown
10.    if trigger.last_triggered_at != 0:
11.        if now() - trigger.last_triggered_at < trigger.cooldown_ms:
12.            continue
13.
14.    // Skip if expired
15.    if trigger.expires_at != 0 and now() >= trigger.expires_at:
16.        trigger.enabled = false
17.        continue
18.
19.    // Skip if already fired (one-shot)
20.    if trigger.one_shot and trigger.last_triggered_at != 0:
21.        continue
22.
23.    // Evaluate condition
24.    if EVALUATE_CONDITION(state, trigger.condition_ast):
25.        // Execute the effect
26.        EXECUTE_TRIGGER_EFFECT(state, trigger.effect)
27.
28.        // Update trigger state
29.        trigger.last_triggered_at = now()
30.
31.        // Log the trigger fire
32.        LOG(state, {
                type: "__trigger_fired__",
                trigger_id: trigger_id,
                condition: trigger.condition,
                effect: trigger.effect,
                timestamp: now(),
                state_version: state.version
            })
33.
34.        triggered.append(trigger_id)

35. return triggered
    5.3 Effect Execution
    plaintext

Algorithm: EXECUTE_TRIGGER_EFFECT

Input:
state  — Current CRABS state
effect — TriggerEffect to execute

1. switch effect.type:
2.     case ISSUE_ATTRIBUTE:
3.         ISSUE_TEMPORARY_ATTRIBUTE(
4.             attribute_machine,
5.             attribute: effect.issue_attribute,
6.             value: effect.attribute_value,
7.             role: effect.target_role,
8.             duration_ms: effect.duration_ms
9.         )
10.
11.    case CREATE_TRIGGER:
12.        new_trigger = effect.new_trigger
13.        new_trigger.created_at = now()
14.        state.triggers[new_trigger.trigger_id] = new_trigger
15.        LOG(state, {
                type: "__trigger_created__",
                trigger_id: new_trigger.trigger_id,
                created_by: "__trigger__"  // System-created
            })
16.
17.    case DELETE_TRIGGER:
18.        delete state.triggers[effect.target_trigger_id]
19.        LOG(state, {
                type: "__trigger_deleted__",
                trigger_id: effect.target_trigger_id
            })
20.
21.    case DISABLE_TRIGGER:
22.        state.triggers[effect.target_trigger_id].enabled = false
23.        if effect.duration_ms > 0:
24.            state.triggers[effect.target_trigger_id].enabled_at = 
25.                now() + effect.duration_ms
26.
27.    case CHANGE_POLICY:
28.        state.policies[effect.operation] = effect.new_policy
29.        LOG(state, {
                type: "__policy_changed__",
                operation: effect.operation,
                new_policy: effect.new_policy,
                changed_by: "__trigger__"
            })
30.
31.    case CUSTOM:
32.        effect.callback(state, effect.callback_data)
5.4 Temporary Attribute Issuance
plaintext

Algorithm: ISSUE_TEMPORARY_ATTRIBUTE

Input:
attr_machine — The Attribute Machine state
attribute    — Attribute name (e.g., "flag_threshold_met:video_abc")
value        — Attribute value (e.g., "true")
role         — Target role (e.g., "moderator")
duration_ms  — Validity duration in milliseconds

1. affected_count = 0

2. for each (user_id, user) in attr_machine.users:
3.     if user.status != ACTIVE:
4.         continue
5.
6.     if not USER_HAS_ROLE(user, role):
7.         continue
8.
9.     // Add or update temporary attribute
10.    user.temporary_attributes[attribute] = {
       value: value,
       issued_at: now(),
       expires_at: now() + duration_ms
       }
11.
12.    // Increment key version — forces key refresh
13.    user.key_version += 1
14.    affected_count += 1

15. // Log the issuance
16. LOG(attr_machine, {
    type: "__attribute_issued__",
    attribute: attribute,
    value: value,
    role: role,
    duration_ms: duration_ms,
    affected_users: affected_count,
    timestamp: now()
    })

17. return affected_count
    5.5 Temporary Attribute Expiry
    plaintext

Algorithm: PRUNE_EXPIRED_TEMPORARY_ATTRIBUTES

Input:
attr_machine — The Attribute Machine state

// Called:
//   - Before every trigger evaluation
//   - Periodically (every 60 seconds)
//   - On user key refresh

1. for each (user_id, user) in attr_machine.users:
2.     expired_attrs = []
3.
4.     for each (attr_name, attr) in user.temporary_attributes:
5.         if now() >= attr.expires_at:
6.             expired_attrs.append(attr_name)
7.
8.     for each attr_name in expired_attrs:
9.         delete user.temporary_attributes[attr_name]
10.        user.key_version += 1
11.
12.        LOG(attr_machine, {
                type: "__attribute_expired__",
                user_id: user_id,
                attribute: attr_name,
                timestamp: now()
            })
6. Modified Existing Algorithms
   6.1 Modified Operation Execution
   The EXECUTE_OPERATION algorithm (Section 7.4 of the base spec) is modified to include trigger processing:

plaintext

Algorithm: EXECUTE_OPERATION (v1.1)

// Steps 1–7: Unchanged from v1.0
1. PRUNE_EXPIRED_LOCKS(state)
2. Check for duplicate UUID
3. Verify protocol state transitions
4. Verify lock claims
5. Verify ABE signature
6. Verify key version
7. Execute operation handler

// Step 8: Transition protocol states (unchanged)
8. for each (resource, next) in zip(op.resources, op.next_state):
   state.items[resource].protocol_state = next

// Step 9: NEW — Process threshold triggers
9. triggered = PROCESS_TRIGGERS(state)

// Step 10: Log operation AND any triggered events
10. log_entry = {
    version: state.version,
    uuid: op.uuid,
    type: op.type,
    signer_id: op.signer_id,
    triggered_triggers: triggered,  // NEW
    state_hash: SHA256(state)
    }
    state.log.append(log_entry)
    state.version += 1
    state.processed_ops.add(op.uuid)

11. return SUCCESS
    6.2 Modified Key Refresh
    The REFRESH_ABE_KEY algorithm (Section 8.5 of the base spec) is modified to include temporary attributes:

plaintext

Algorithm: REFRESH_ABE_KEY (v1.1)

// Steps 1–3: Unchanged
1. user = state.users[user_id]
2. if user.status != ACTIVE: return USER_SUSPENDED
3. PRUNE_EXPIRED_TEMPORARY_ATTRIBUTES(state)  // NEW

// Step 4: Build attribute string from BOTH permanent and temporary attributes
4. attrs = []
5. for each (name, attr) in user.attributes:
   attrs.append("{name}:{attr.value}")
6. for each (name, attr) in user.temporary_attributes:
   if now() < attr.expires_at:  // Only include active temporaries
   attrs.append("{name}:{attr.value}")

// Steps 7–14: Unchanged
7. attr_string = join(attrs, "|")
8. sk_abe = ABE_keygen(msk, mpk, attr_string)
9. envelope = {
   user_id: user_id,
   state_version: state.version,
   attributes_hash: SHA256(canonical_encode(user.attributes ∪ user.temporary_attributes)),
   sk_abe: sk_abe,
   temporary_attributes: user.temporary_attributes  // Inform user of active temporaries
   }
10. user.key_version = state.version
11. user.updated_at = now()
12. return envelope
7. Changes to the Attribute Machine
   7.1 User Record Extension
   The user record in the Attribute Machine is extended to include temporary attributes:

plaintext

User = {
// ... existing fields (attributes, public_key, status, key_version, ...)

    temporary_attributes: {
        "<attribute_name>": TemporaryAttribute,
        ...
    }
}

TemporaryAttribute = {
value: string,         // e.g., "true"
issued_at: uint64,
expires_at: uint64
}
7.2 New Attribute Machine Policies
plaintext

AttributeMachine = {
// ... existing fields ...

    policies: {
        // ... existing policies ...
        
        // NEW: Trigger management policies
        "__create_trigger__": "role:admin",
        "__delete_trigger__": "role:admin",
        "__disable_trigger__": "role:admin",
        "__enable_trigger__": "role:admin"
    },
    
    // NEW: Trigger registry
    triggers: {
        // ... as defined in §2.2 ...
    }
}
8. Serialization
   8.1 Trigger Serialization
   plaintext

TriggerSerialized = {
trigger_id_length: uint16,
trigger_id: byte[trigger_id_length],
description_length: uint16,
description: byte[description_length],
condition_length: uint16,
condition: byte[condition_length],
condition_ast_length: uint32,
condition_ast: byte[condition_ast_length],
effect_type: uint8,
issue_attribute_length: uint16,
issue_attribute: byte[issue_attribute_length],
target_role_length: uint16,
target_role: byte[target_role_length],
duration_ms: uint64,
attribute_value_length: uint16,
attribute_value: byte[attribute_value_length],
cooldown_ms: uint64,
last_triggered_at: uint64,
one_shot: uint8,
enabled: uint8,
expires_at: uint64,
created_at: uint64,
created_by_length: uint16,
created_by: byte[created_by_length]
}
8.2 State Serialization Update
The state serialization format (Section 13 of the base spec) is updated to include the triggers field:

plaintext

SerializedState = {
// ... existing fields ...

    trigger_count: uint32,              // NEW
    triggers: TriggerSerialized[],      // NEW
    
    // ... existing fields (checksum, etc.) ...
}
9. Security Considerations
   9.1 Trigger Spam
   An attacker might rapidly trigger and un-trigger a condition to cause repeated attribute issuance. Mitigations:

Cooldown period: Minimum interval between firings (configurable per trigger)
One-shot triggers: Fire only once, then self-disable
Attribute expiry: Temporary attributes expire automatically
Rate limiting: Maximum number of trigger firings per time window (configurable at machine level)
9.2 False Triggers
An attacker might manipulate state to trigger conditions illegitimately. Mitigations:

Weighted counters: Use reputation-weighted flagging rather than raw counts
Multi-signature thresholds: Require multiple independent actors to trigger
Audit trail: Every trigger fire is logged with full context
Rollback capability: Trigger effects can be reversed by admin operations
9.3 Trigger Cascade
A trigger that creates other triggers could lead to unbounded cascade. Mitigations:

Maximum cascade depth: Configurable limit (default: 3)
Trigger creation requires policy: __create_trigger__ requires role:admin
No recursive self-triggering: A trigger cannot trigger itself (detected by trigger_id)
9.4 Temporary Attribute Lifetime
plaintext

Attack: User saves old ABE key with temporary attribute,
uses it after attribute expires

Mitigation: Key versioning
- When attribute expires, user.key_version increments
- Old key is STALE — state machine rejects it
- User MUST refresh key to get a valid one
- Refreshed key does NOT include expired attributes
10. Backward Compatibility
    10.1 State Migration
    Existing CRABS v1.0 states can be migrated to v1.1 by adding an empty triggers field:

plaintext

Migration:
state_v1_0 → state_v1_1:
state_v1_1 = copy(state_v1_0)
state_v1_1.triggers = {}  // Empty trigger registry
state_v1_1.version = state_v1_0.version  // Version unchanged
10.2 Operation Compatibility
All v1.0 operations remain valid. The new operations (__create_trigger__, etc.) are only recognized by v1.1 nodes. A v1.0 node receiving a v1.1 operation with an unknown type will return UNKNOWN_OPERATION.

11. Test Vectors
    11.1 Basic Trigger Fire
    plaintext

Setup:
- State with counter "test_counter" = 5
- Trigger: condition "test_counter >= 10", issue "threshold_met" to "viewer"

Operation:
- type: "increment"
- resource: "test_counter"
- payload: { delta: 5 }

Expected:
- test_counter = 10
- Trigger fires
- All users with role "viewer" get temporary attribute "threshold_met"
- Log entry includes triggered_triggers: ["test_threshold"]
  11.2 Cooldown
  plaintext

Setup:
- Trigger with cooldown_ms = 60000
- Trigger fired at t=0

Operation at t=0:
- Increment counter past threshold

Expected:
- Trigger fires (first time)

Operation at t=30000:
- Increment counter again

Expected:
- Trigger does NOT fire (in cooldown until t=60000)

Operation at t=60000:
- Increment counter again

Expected:
- Trigger fires (cooldown elapsed)
  11.3 Temporary Attribute Expiry
  plaintext

Setup:
- Trigger with duration_ms = 5000
- Trigger fires at t=0

At t=0:
- User has temporary attribute "threshold_met" expiring at t=5000

At t=3000:
- User refreshes key
- New key includes "threshold_met"

At t=5000:
- PRUNE_EXPIRED_TEMPORARY_ATTRIBUTES runs
- Attribute removed from user
- user.key_version incremented

At t=6000:
- User tries to use old key (key_version from t=3000)
- REJECTED: KEY_STALE
12. Future Extensions
    12.1 Cross-Machine Triggers
    A trigger in one machine could reference state in another machine:

plaintext

condition: "video_abc.flags >= 10 AND user_abc.reputation < -20"
↑ Machine A              ↑ Machine B
This would require a trigger broker that monitors multiple machines. Not specified in this amendment.

12.2 Trigger Weights
Instead of binary fire/don't-fire, triggers could have a confidence score:

plaintext

effect: {
type: ISSUE_ATTRIBUTE,
issue_attribute: "flag_threshold_met:video_abc",
confidence_threshold: 0.8,  // Only issue if condition confidence > 80%
duration_ms: 86400000 * confidence  // Longer duration for higher confidence
}
12.3 Scheduled Triggers
Triggers based on time rather than state:

plaintext

condition: "now() >= video_abc.created_at + 86400000"
// Fire 24 hours after video creation
Appendix: Summary of Changes from v1.0
Section	Change
§2 Data Model	Added triggers field to State
§2 Data Model	Added temporary_attributes field to User
§3 (new)	Condition language specification
§4 (new)	New built-in operations
§5 (new)	New algorithms for trigger processing
§6.1	Modified EXECUTE_OPERATION to include trigger processing
§6.2	Modified REFRESH_ABE_KEY to include temporary attributes
§7.1	Extended User record with temporary_attributes
§7.2	Added trigger management policies
§8	Updated serialization formats
§9 (new)	Security considerations for triggers
§10 (new)	Backward compatibility
§11 (new)	Test vectors
End of CRABS Protocol Specification v1.1 — Amendment 1

This formalizes the threshold trigger concept as a proper protocol extension. It integrates cleanly with the existing CRABS model — triggers are just another kind of state, managed by the same operation/policy/logic framework.

Want me to write the implementation header for this — crabs_trigger.h with all the data structures and function signatures?