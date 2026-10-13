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

  // ------------------------------------------------------------------
  // 6. OT items: a machine WITH one round trips its own snapshot, and a
  //    merge HOLDS the item instead of planting a NULL-value husk (P1
  //    review follow-up: the poisoning probe as tests).
  // ------------------------------------------------------------------
  const otSource = await Node.create('ot-m1', { ordering: 'hlc' });
  otSource.setPolicy('__execute_ot__', 'role:admin');
  otSource.addOrderedSet('doc');
  otSource.orderedInsert('doc', 'a', 0, { id: { node: 'ot-m1', seq: 1, ts: 1000 } });
  otSource.orderedInsert('doc', 'b', 1, { id: { node: 'ot-m1', seq: 2, ts: 1000 } });
  otSource.addCounter('hits');
  otSource.incrementCounter('hits', 4, 'ot-m1');

  // Round trip: serialize -> deserialize -> the SAME readback.
  const otWire = otSource.serialize();
  const otRestored = await Node.create('ot-fresh', { ordering: 'hlc' });
  otRestored.deserialize(otWire);
  otRestored.setPolicy('__execute_ot__', 'role:admin');
  const otReadback = otRestored.getOrderedSet('doc').elements.join(',');
  if (otReadback !== 'a,b') {
    throw new Error(`OT item did not round trip (got [${otReadback}])`);
  }
  if (otRestored.getCounter('hits') !== 4) {
    throw new Error(`OT round trip lost the counter (got ${otRestored.getCounter('hits')})`);
  }
  // And the restored machine re-serializes to a re-readable blob.
  otRestored.deserialize(otRestored.serialize());
  if (otRestored.getOrderedSet('doc').elements.join(',') !== 'a,b') {
    throw new Error('re-serialized OT snapshot did not re-restore');
  }

  // Merge: the OT item is HELD (merge returns SUCCESS) — no NULL-value husk
  // crosses, the counter in the same snapshot still merges, and the hold
  // surfaces as a __merge_held__ change event.
  const otMerger = await Node.create('ot-m2', { ordering: 'hlc' });
  otMerger.setPolicy('__execute_ot__', 'role:admin');
  otMerger.addCounter('hits');
  otMerger.incrementCounter('hits', 1, 'ot-m2');
  const mergeEvents = [];
  otMerger.on('change', (event) => mergeEvents.push(event));
  otMerger.mergeState(otWire);
  if (otMerger.getCounter('hits') !== 5) {
    throw new Error(`merge of the held snapshot lost the counter (got ${otMerger.getCounter('hits')})`);
  }
  let held = null;
  try { otMerger.getOrderedSet('doc'); } catch (caught) { held = caught; }
  if (!held) {
    throw new Error('the unmergeable OT item must NOT cross the merge (no husk expected)');
  }
  const heldEvents = mergeEvents.filter((event) => event.type === '__merge_held__');
  if (heldEvents.length !== 1 || heldEvents[0].target !== 'doc' ||
      heldEvents[0].kind !== 'merge' ||
      heldEvents[0].result !== 0x3004 /* CRABS_ERR_TYPE_MISMATCH */) {
    throw new Error(`held divergence event missing (got ${JSON.stringify(mergeEvents)})`);
  }

  // ------------------------------------------------------------------
  // 7. destroy(): mergeState + plain deserialize refuse consistently
  //    (the same gate shape the verify:'node-key' path uses).
  // ------------------------------------------------------------------
  const doomed = await Node.create('doomed', { ordering: 'hlc' });
  doomed.destroy();
  let destroyedMerge = null;
  try { doomed.mergeState(otWire); } catch (caught) { destroyedMerge = caught; }
  if (!destroyedMerge || !/destroyed node/.test(destroyedMerge.message)) {
    throw new Error(`mergeState on a destroyed node must refuse (got ${destroyedMerge})`);
  }
  let destroyedRestore = null;
  try { doomed.deserialize(otWire); } catch (caught) { destroyedRestore = caught; }
  if (!destroyedRestore || !/destroyed node/.test(destroyedRestore.message)) {
    throw new Error(`deserialize on a destroyed node must refuse (got ${destroyedRestore})`);
  }

  // ------------------------------------------------------------------
  // 8. HLC continuity: the restored machine's clock CONTINUES the previous
  //    machine's HLC — the restored watermark EQUALS the live pre-restore
  //    watermark (getHLC is the last-issued readback). A zeroed restarted
  //    clock would come back undefined (or at counter 0 at an older tick).
  // ------------------------------------------------------------------
  const clockNode = await Node.create('clock-m1', { ordering: 'hlc' });
  clockNode.addCounter('ticks');
  clockNode.incrementCounter('ticks', 1, 'clock-m1');
  const clockWire = clockNode.serialize();
  // Advance the LIVE machine's clock past the snapshot's watermark so the
  // continuity source is the LIVE clock, never the snapshot's.
  clockNode.addRegister('rank', 0);
  clockNode.setRegister('rank', 1, 'clock-m1');
  const liveBefore = clockNode.getHLC();
  if (!liveBefore) throw new Error('a live HLC machine must report its watermark');
  clockNode.deserialize(clockWire);
  const clockAfter = clockNode.getHLC();
  if (!clockAfter) {
    throw new Error('restored machine lost its HLC clock (getHLC undefined)');
  }
  if (clockAfter.seconds !== liveBefore.seconds ||
      clockAfter.nanos !== liveBefore.nanos ||
      clockAfter.logicalCounter !== liveBefore.logicalCounter) {
    throw new Error(`restored clock must CONTINUE (live ${JSON.stringify(liveBefore)}, after ${JSON.stringify(clockAfter)})`);
  }

  otSource.destroy();
  otRestored.destroy();
  otMerger.destroy();
  clockNode.destroy();

  // ------------------------------------------------------------------
  // 9. Raft pairing: a restore migrates the attached module to the restored
  //    machine — status readback pins the imported term/commit tip, and the
  //    host's raftPump keeps driving the RESTORED machine (notifications
  //    flow; the next committed decree materializes).
  // ------------------------------------------------------------------
  const raftNode = await Node.create('raft-m1', { ordering: 'hlc' });
  const raftKey = await KeyPair.generate();
  const RAFT_OP = 'council_write';
  const RAFT_ITEM = 'council';
  raftNode.registerUser('alice', raftKey.publicKeyHex(), '');
  raftNode.grantRole('alice', 'role', 'member', 'raft-m1');
  const materialize = (state, op) => {
    state.setRegisterBytes(RAFT_ITEM, new TextEncoder().encode(op.payload), 'alice');
    return 0;
  };
  raftNode.registerHandlerJs(RAFT_OP, materialize);
  raftNode.setPolicy(RAFT_OP, 'role:member');
  raftNode.defineItem(RAFT_ITEM, 'register', 'lww_reg', { domain: 'group' });
  const raftHost = raftNode.attachRaft({ peers: ['raft-m1'], seed: 5, tickMs: 20 });
  // The storage seam is load-bearing for commits: an entry commits only
  // after its persist window resolves (in-memory map here).
  const persistWindows = new Map();
  raftHost.setRaftStorage(async (persistHandle, windowBlob) => {
    persistWindows.set(Number(persistHandle), windowBlob);
  });
  raftHost.startRaftHost();

  const waitFor = async (predicate, what, timeoutMs = 15000) => {
    const deadline = Date.now() + timeoutMs;
    for (;;) {
      if (predicate()) return;
      if (Date.now() > deadline) throw new Error(`timeout waiting for: ${what}`);
      await new Promise((resolve) => setTimeout(resolve, 20));
    }
  };
  await waitFor(() => raftNode.raftStatus() !== null && raftNode.raftStatus().isLeader,
                'the single-node cluster to elect its only member');
  const firstDecree = await Operation.create(RAFT_OP);
  firstDecree.signerId = 'alice';
  firstDecree.payload = 'decree-1\x00';
  firstDecree.addResource(RAFT_ITEM);
  raftNode.sign(firstDecree, raftKey);
  raftNode.execute(firstDecree);
  await waitFor(() => {
    const status = raftNode.raftStatus();
    return status !== null && status.commitTip > 0 &&
           new TextDecoder().decode(raftNode.getRegisterBytes(RAFT_ITEM))
               .includes('decree-1');
  }, 'decree-1 to commit + materialize');

  // Snapshot, stop the ticking host during the restore, restore.
  const raftWire = raftNode.serialize();
  const preTerm = raftNode.raftStatus().term;
  const preTip = raftNode.raftStatus().commitTip;
  raftHost.stopRaftHost();
  raftNode.deserialize(raftWire);
  // The module re-attached to the restored machine with its durable history.
  const restoredStatus = raftNode.raftStatus();
  if (restoredStatus === null || restoredStatus.term < preTerm ||
      restoredStatus.commitTip < preTip) {
    throw new Error(`restore lost the raft pairing (status ${JSON.stringify(restoredStatus)}, pre term ${preTerm} tip ${preTip})`);
  }
  // The host still drives the RESTORED machine: re-apply the runtime-only
  // handler (it never serializes) and let the next decree commit — its
  // notification must materialize through the restored machine's pipeline.
  raftNode.registerHandlerJs(RAFT_OP, materialize);
  raftHost.startRaftHost();
  // The imported module restarts as a FOLLOWER (elections re-run) — wait
  // for the restored node to take the leadership again.
  await waitFor(() => raftNode.raftStatus() !== null && raftNode.raftStatus().isLeader,
                'the restored module to re-elect');
  const secondDecree = await Operation.create(RAFT_OP);
  secondDecree.signerId = 'alice';
  secondDecree.payload = 'decree-2\x00';
  secondDecree.addResource(RAFT_ITEM);
  raftNode.sign(secondDecree, raftKey);
  raftNode.execute(secondDecree);
  await waitFor(() => {
    const status = raftNode.raftStatus();
    return status !== null && status.commitTip > preTip &&
           new TextDecoder().decode(raftNode.getRegisterBytes(RAFT_ITEM))
               .includes('decree-2');
  }, 'decree-2 to commit on the RESTORED machine', 30000);

  raftHost.destroy();
  raftNode.destroy();
  raftKey.destroy();

  console.log('state-restore OK: round trip, merge convergence, sealed/signed snapshots, OT hold, raft rebind, HLC continuity');
})().catch(e => { console.error(e); process.exit(1); });