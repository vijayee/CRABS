'use strict';

// State restore + merge + sealed/signed snapshots (parity-fill P1).
//
// serialize({sealKey?, signed?}) emits the C sealed / node-key-signed
// snapshot families; deserialize() REPLACES the wrapper's machine with the
// restored state (the wrapper stays usable) and returns the restore report
// {authorityRestored, mskSectionPresent}; mergeState() merges a foreign
// snapshot into this machine via crdt_merge_state (counters max-per-node /
// sum-across-nodes, register LWW, OR-set union).

const { Node, KeyPair, Operation } = require('..');

(async () => {
  const SEAL_KEY_A = 'aa'.repeat(32);
  const SEAL_KEY_B = 'bb'.repeat(32);

  // ------------------------------------------------------------------
  // 1. Plain serialize -> deserialize round trip into a FRESH wrapper.
  // ------------------------------------------------------------------
  const source = await Node.create('m1', { ordering: 'hlc' });
  source.addCounter('hits');
  source.incrementCounter('hits', 5, 'm1');
  source.addRegister('rank', 0);
  source.setRegister('rank', 42, 'm1');
  source.addORSet('tags');
  source.setAdd('tags', 'crdt', 'writer-a');
  source.setAdd('tags', 'abe', 'writer-b');
  const aliceKey = await KeyPair.generate();
  source.registerUser('alice', aliceKey.publicKeyHex(), '');
  source.grantRole('alice', 'role', 'member', 'm1');
  const wire1 = source.serialize();

  const restored = await Node.create('fresh', { ordering: 'hlc' });
  const plainReport = restored.deserialize(wire1);
  if (plainReport.authorityRestored !== false ||
      plainReport.mskSectionPresent !== false) {
    throw new Error(`plain snapshot report must be plain (got ${JSON.stringify(plainReport)})`);
  }
  if (restored.getCounter('hits') !== 5) {
    throw new Error(`counter did not restore (got ${restored.getCounter('hits')})`);
  }
  if (restored.getRegister('rank') !== 42) {
    throw new Error(`register did not restore (got ${restored.getRegister('rank')})`);
  }
  if (!restored.setContains('tags', 'crdt') || !restored.setContains('tags', 'abe')) {
    throw new Error('OR-set members did not restore');
  }
  const alice = restored.getUser('alice');
  if (!alice || alice.userId !== 'alice') {
    throw new Error('user registry did not restore');
  }
  if (!alice.attributes.some(attr => attr.value === 'role:member')) {
    throw new Error('restored user record lost the granted role');
  }

  // Garbage wire refuses (wrong magic/length lands inside the checksum gate).
  let refused = null;
  try { restored.deserialize(new Uint8Array([0x00, 0x01, 0x02])); }
  catch (caught) { refused = caught; }
  if (!refused) throw new Error('garbage wire must refuse deserialize');

  // ------------------------------------------------------------------
  // 2. mergeState: divergent machines converge on crdt_merge_state's rules.
  // ------------------------------------------------------------------
  const mergerLeft = await Node.create('ml', { ordering: 'hlc' });
  mergerLeft.addCounter('hits');
  mergerLeft.incrementCounter('hits', 3, 'm-left');
  mergerLeft.addRegister('rank', 0);
  mergerLeft.setRegister('rank', 7, 'm-left');
  mergerLeft.addORSet('tags');
  mergerLeft.setAdd('tags', 'shared', 'left');
  const mergerRight = await Node.create('mr', { ordering: 'hlc' });
  mergerRight.addCounter('hits');
  mergerRight.incrementCounter('hits', 9, 'm-right');
  mergerRight.addRegister('rank', 0);
  mergerRight.setRegister('rank', 99, 'm-right');
  mergerRight.addORSet('tags');
  mergerRight.setAdd('tags', 'shared', 'right');
  mergerRight.setAdd('tags', 'extra', 'right');
  leftMerge(mergerLeft, mergerRight.serialize());
  function leftMerge(leftNode, wire) { leftNode.mergeState(wire); }

  // Distinct node contributions SUM (g_counter_merge takes max per node).
  if (mergerLeft.getCounter('hits') !== 12) {
    throw new Error(`merged counter expected 12, got ${mergerLeft.getCounter('hits')}`);
  }
  // LWW register: the later timestamp wins.
  if (mergerLeft.getRegister('rank') !== 99) {
    throw new Error(`merged register expected 99, got ${mergerLeft.getRegister('rank')}`);
  }
  // OR-set union: both machines' tags survive, plus the new element.
  if (!mergerLeft.setContains('tags', 'shared') ||
      !mergerLeft.setContains('tags', 'extra')) {
    throw new Error('merged OR-set lost elements');
  }
  // The right machine is untouched by a one-way merge.
  if (mergerRight.getCounter('hits') !== 9) {
    throw new Error('mergeState must not mutate the source machine');
  }

  // Malformed merge input refuses with nothing merged.
  let mergeRefused = null;
  try { mergerLeft.mergeState(new Uint8Array(8)); }
  catch (caught) { mergeRefused = caught; }
  if (!mergeRefused) throw new Error('garbage mergeState input must refuse');
  if (mergerLeft.getCounter('hits') !== 12) {
    throw new Error('refused merge must leave the machine untouched');
  }

  // ------------------------------------------------------------------
  // 3. Sealed snapshot: same key restores authority, wrong key does not.
  // ------------------------------------------------------------------
  const sealedWire = source.serialize({ sealKey: SEAL_KEY_A });
  const unsealer = await Node.create('unsealer', { ordering: 'hlc' });
  const sealReport = unsealer.deserialize(sealedWire, { sealKey: SEAL_KEY_A });
  if (sealReport.mskSectionPresent !== true) {
    throw new Error('sealed snapshot must report the MSK section present');
  }
  if (sealReport.authorityRestored !== true) {
    throw new Error('correct seal key must restore the machine authority');
  }
  if (unsealer.getCounter('hits') !== 5) {
    throw new Error('sealed snapshot content did not restore');
  }

  const wrongKeyNode = await Node.create('wrongkey', { ordering: 'hlc' });
  const wrongReport = wrongKeyNode.deserialize(sealedWire, { sealKey: SEAL_KEY_B });
  if (wrongReport.mskSectionPresent !== true ||
      wrongReport.authorityRestored !== false) {
    throw new Error(`wrong seal key must refuse the authority (got ${JSON.stringify(wrongReport)})`);
  }
  // The content still loads on the compatibility path.
  if (wrongKeyNode.getCounter('hits') !== 5) {
    throw new Error('wrong-key restore must still load the substrate');
  }

  // ------------------------------------------------------------------
  // 4. Signed snapshot: self-restore + tamper refusal.
  // ------------------------------------------------------------------
  const signedWire = source.serialize({ signed: true });
  const tampered = new Uint8Array(signedWire);
  tampered[16] ^= 0xFF;  // flip one payload byte (signature must catch it)
  let tamperRefused = null;
  try { source.deserialize(tampered, { verify: 'node-key' }); }
  catch (caught) { tamperRefused = caught; }
  if (!tamperRefused) throw new Error('tampered signed snapshot must refuse');

  // Untampered self-restore: the same machine verifies with its own node key.
  const signedReport = source.deserialize(signedWire, { verify: 'node-key' });
  if (source.getCounter('hits') !== 5 || source.getRegister('rank') !== 42) {
    throw new Error('signed self-restore lost the snapshot content');
  }
  // A machine WITHOUT the signer's key must not pass a foreign signed blob.
  const foreign = await Node.create('foreign', { ordering: 'hlc' });
  let foreignRefused = null;
  try { foreign.deserialize(signedWire, { verify: 'node-key' }); }
  catch (caught) { foreignRefused = caught; }
  if (!foreignRefused) throw new Error('foreign node key must not verify a foreign signature');

  // ------------------------------------------------------------------
  // 5. Sealed + signed: both families compose from the wrapper.
  // ------------------------------------------------------------------
  const sealedSignedWire = source.serialize({ sealKey: SEAL_KEY_A, signed: true });
  const sealedSignedReport =
      source.deserialize(sealedSignedWire,
                         { sealKey: SEAL_KEY_A, verify: 'node-key' });
  if (sealedSignedReport.authorityRestored !== true ||
      sealedSignedReport.mskSectionPresent !== true) {
    throw new Error(`sealed+signed restore lost both guarantees (got ${JSON.stringify(sealedSignedReport)})`);
  }
  if (source.getCounter('hits') !== 5) {
    throw new Error('sealed+signed content did not restore');
  }

  // After the restore loop the machine still works end to end.
  source.setRegister('rank', 43, 'm1');
  if (source.getRegister('rank') !== 43) {
    throw new Error('restored machine must stay writable');
  }

  source.destroy();
  restored.destroy();
  unsealer.destroy();
  wrongKeyNode.destroy();
  foreign.destroy();
  mergerLeft.destroy();
  mergerRight.destroy();
  aliceKey.destroy();

  console.log('state-restore OK: round trip, merge convergence, sealed/signed snapshots');
})().catch(e => { console.error(e); process.exit(1); });