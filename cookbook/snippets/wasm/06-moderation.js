'use strict';
// Recipe 6 — progressive disclosure moderation (crabs-wasm, run in Node).
// A threshold trigger turns a community counter (abuse reports) into a
// TEMPORARY clearance attribute for members; a policy gate turns that
// attribute into access to a contact-card op; the contact card itself is
// ABE-sealed under an attribute policy. Cooldown rate-limits the trigger.

const { Node, KeyPair, Operation } = require('../../../bindings/wasm');

const UNAUTHORIZED = 0x2001; // CRABS_ERR_UNAUTHORIZED (src/CRABS/crabs.h:77)

async function main() {
  const node = await Node.create('admin', { ordering: 'hlc' });

  const aliceKey = await KeyPair.generate();
  node.registerUser('alice', aliceKey.publicKeyHex(), 'adult');
  node.grantRole('alice', 'role', 'member', 'admin');

  // The threshold item: a counter of abuse reports, incremented by the
  // signed 'report' op. Trigger conditions resolve item names to their
  // logical values (condition_resolve_path, src/Condition/condition.c).
  node.addCounter('abuse_reports');
  node.addCounter('contact_reads');
  node.setPolicy('report_abuse', 'role:member');
  node.registerHandlerJs('report_abuse', (state, op) => {
    state.incrementCounter('abuse_reports', 1, op.signerId);
    return 0;
  });
  const report = async () => {
    const op = await Operation.create('report_abuse');
    op.signerId = 'alice';
    op.nodeId = 'alice';
    node.sign(op, aliceKey.privateKeyHex());
    node.execute(op);
    op.destroy();
  };

  // The gated action: reading the moderator contact card. The clearance
  // clause is satisfiable ONLY by the temporary attribute the trigger issues
  // — a policy 'AND role:member clearance:moderator' cannot be met before.
  node.setPolicy('view_contact', 'AND role:member clearance:moderator');
  node.registerHandlerJs('view_contact', (state, op) => {
    state.incrementCounter('contact_reads', 1, op.signerId);
    return 0;
  });
  const viewContact = async () => {
    const op = await Operation.create('view_contact');
    op.signerId = 'alice';
    op.nodeId = 'alice';
    node.sign(op, aliceKey.privateKeyHex());
    const outcome = [];
    try {
      node.execute(op);
      outcome.push('executed');
    } catch (refusal) {
      outcome.push(String(refusal.message));
    }
    op.destroy();
    return outcome[0];
  };

  // Triggers are installed by a SIGNED '__create_trigger__' op — the type
  // needs its own policy; 'role:admin' is the devtools-demo wiring
  // (examples/devtools_demo/demo.js:54). The bootstrap admin holds role:admin.
  node.setPolicy('__create_trigger__', 'role:admin');

  // The trigger: when the counter crosses 3, every holder of an attribute
  // NAMED 'role' (targetRole is the audience attribute NAME —
  // attribute_machine_issue_temporary fans out over role holders,
  // src/Attribute/attribute_machine.c) receives a temporary
  // 'clearance:moderator' for 10 minutes. oneShot false + cooldownMs makes
  // re-fires rate-limited, not disabled.
  node.createTrigger({
    triggerId: 'clearance_gateway',
    condition: 'abuse_reports >= 3',
    description: 'issue verifier clearance when 3 abuse reports accumulated',
    effectType: 'issue_attribute',
    issueAttribute: 'clearance',
    targetRole: 'role',
    attributeValue: 'moderator',
    durationMs: 600000,
    oneShot: false,
    cooldownMs: 60000,
  });

  // Before the threshold: the policy gate itself refuses, nothing lands.
  const preThresholdOutcome = await viewContact();
  if (!preThresholdOutcome.includes('unauthorized')) {
    throw new Error(`pre-threshold view_contact must be refused, got "${preThresholdOutcome}"`);
  }

  const triggerEvents = [];
  node.on('change', (event) => {
    if (event.kind === 'trigger') triggerEvents.push(event);
  });

  await report();
  await report();
  if (node.getCounter('abuse_reports') !== 2) {
    throw new Error(`expected 2 reports, got ${node.getCounter('abuse_reports')}`);
  }
  if (triggerEvents.length !== 0) {
    throw new Error('trigger must not fire below threshold');
  }
  const alicePre = node.getUser('alice');
  if (alicePre.attributes.some((attribute) => attribute.temporary)) {
    throw new Error(`no temporary attribute before the threshold, got ${JSON.stringify(alicePre.attributes)}`);
  }

  // Third report: the op lands, the machine's post-execute trigger pass
  // (Step 9, src/StateMachine/state_machine.c:1508-1520) sees the condition
  // true and issues the temporary attribute synchronously.
  await report();
  if (node.getCounter('abuse_reports') !== 3) {
    throw new Error(`expected 3 reports, got ${node.getCounter('abuse_reports')}`);
  }
  if (triggerEvents.length !== 1) {
    throw new Error(`expected exactly 1 trigger event, got ${triggerEvents.length}`);
  }
  const alicePost = node.getUser('alice');
  const clearance = alicePost.attributes.find((attribute) => attribute.temporary);
  if (!clearance) {
    throw new Error(`temporary clearance must be issued, got ${JSON.stringify(alicePost.attributes)}`);
  }
  // Observed shape, pinned exactly: the temp attribute's value IS the plain
  // 'name:value' token ('clearance:moderator') — the same string the C
  // policy evaluator matches (src/Crypto/crypto.c:1143) and what the
  // node mapper returns (bindings/node/src/crabs_node.cc:1208).
  if (clearance.value !== 'clearance:moderator' ||
      clearance.verifiedBy !== 'trigger') {
    throw new Error(`unexpected temp attribute shape: ${JSON.stringify(clearance)}`);
  }

  // Disclosure: the same gate now passes and the effect lands.
  if ((await viewContact()) !== 'executed') {
    throw new Error('post-threshold view_contact must execute');
  }
  if (node.getCounter('contact_reads') !== 1) {
    throw new Error(`expected 1 contact read, got ${node.getCounter('contact_reads')}`);
  }

  // Cooldown: a 4th report (condition still true) must NOT re-fire while the
  // 60s cooldown is in force — rate-limiting the escalation.
  await report();
  if (triggerEvents.length !== 1) {
    throw new Error(`cooldown must suppress the immediate re-fire, got ${triggerEvents.length} events`);
  }

  // The payload itself is sealed, not just gated: ABE-encrypt the contact
  // string under an attribute policy. The container layout is
  // u16le policy byte length + policy bytes + u32le ciphertext length +
  // ciphertext (bindings/wasm/index.d.ts:306 prose; smoke.js:111-130).
  const sealed = node.encrypt('contact for verified viewers', 'moderator and member');
  const view = new DataView(sealed.buffer, sealed.byteOffset, sealed.byteLength);
  const policyByteLength = view.getUint16(0, true);
  const policyText = new TextDecoder().decode(sealed.subarray(2, 2 + policyByteLength));
  if (policyText !== 'moderator and member') {
    throw new Error(`policy must round-trip in the container, got "${policyText}"`);
  }
  const ciphertextLength = view.getUint32(2 + policyByteLength, true);
  if (2 + policyByteLength + 4 + ciphertextLength !== sealed.byteLength) {
    throw new Error(`container length ${sealed.byteLength} must match header ${2 + policyByteLength + 4 + ciphertextLength}`);
  }

  console.log('moderation OK: threshold trigger issued clearance, gate opened, cooldown re-fired suppression, payload sealed');
  node.destroy();
  aliceKey.destroy();
}
main()
  .then(() => process.exit(0))
  .catch((error) => { console.error(error); process.exit(1); });