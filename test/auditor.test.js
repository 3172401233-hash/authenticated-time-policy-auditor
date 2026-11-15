'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Keyring, TimePolicyAuditor, signStatement } = require('../index.js');
const {
  makeClocks,
  makeSource,
  makeAuditor,
  makeStatement,
  establishConsensus,
} = require('../test-support/helpers.js');

const T0 = 1_700_000_000_000;

function threeSourceSetup(config = {}) {
  const clocks = makeClocks(T0);
  const sources = [makeSource('alpha'), makeSource('beta'), makeSource('gamma')];
  const auditor = makeAuditor({ sources, clocks, config });
  return { clocks, sources, auditor };
}

test('accepts a properly signed statement and reaches consensus', () => {
  const { sources, auditor } = threeSourceSetup();
  establishConsensus(auditor, sources, T0);
  const snap = auditor.snapshot();
  assert.equal(snap.status, 'ok');
  assert.equal(snap.trustedTime, T0);
});

test('rejects tampered signatures, wrong certs, unknown sources, expired statements', () => {
  const { sources, auditor } = threeSourceSetup();

  const tampered = makeStatement(sources[0], { time: T0, issuedAt: T0 });
  tampered.time = T0 + 999;
  assert.equal(auditor.ingestStatement(tampered).reason, 'bad-signature');

  const wrongCert = makeStatement(sources[0], {
    time: T0,
    issuedAt: T0,
    overrides: { certId: 'cert-attacker' },
  });
  assert.equal(auditor.ingestStatement(wrongCert).reason, 'cert-mismatch');

  const stranger = makeSource('stranger');
  const unknownStmt = makeStatement(stranger, { time: T0, issuedAt: T0 });
  assert.equal(auditor.ingestStatement(unknownStmt).reason, 'unknown-source');

  const expired = makeStatement(sources[0], {
    time: T0 - 60_000,
    issuedAt: T0 - 60_000,
    ttlMs: 1_000,
  });
  assert.equal(auditor.ingestStatement(expired).reason, 'statement-expired');

  const future = makeStatement(sources[0], { time: T0 + 60_000, issuedAt: T0 + 60_000 });
  assert.equal(auditor.ingestStatement(future).reason, 'statement-from-future');
});

test('accepts requests within drift and enforces past/future boundaries', () => {
  const { sources, auditor } = threeSourceSetup();
  establishConsensus(auditor, sources, T0);

  assert.equal(auditor.authorize({ nonce: 'n-drift', timestamp: T0 + 500 }).accepted, true);
  assert.equal(auditor.authorize({ nonce: 'n-future-edge', timestamp: T0 + 2_000 }).accepted, true);

  const tooFuture = auditor.authorize({ nonce: 'n-future-over', timestamp: T0 + 2_001 });
  assert.equal(tooFuture.accepted, false);
  assert.ok(tooFuture.reasons.includes('future-skew-exceeded'));

  assert.equal(auditor.authorize({ nonce: 'n-past-edge', timestamp: T0 - 5_000 }).accepted, true);

  const tooPast = auditor.authorize({ nonce: 'n-past-over', timestamp: T0 - 5_001 });
  assert.equal(tooPast.accepted, false);
  assert.ok(tooPast.reasons.includes('past-skew-exceeded'));
});

test('correction window accepts both old and new timestamps during clock correction', () => {
  const { clocks, sources, auditor } = threeSourceSetup();
  establishConsensus(auditor, sources, T0);
  assert.equal(auditor.authorize({ nonce: 'n-old', timestamp: T0 - 4_000 }).accepted, true);

  clocks.advance(3_000);
  establishConsensus(auditor, sources, T0 + 3_000);
  const trusted = auditor.trustedNow();
  assert.equal(auditor.authorize({ nonce: 'n-new', timestamp: trusted }).accepted, true);
  assert.equal(auditor.authorize({ nonce: 'n-old-still', timestamp: trusted - 4_999 }).accepted, true);
});

test('nonce replay is rejected', () => {
  const { sources, auditor } = threeSourceSetup();
  establishConsensus(auditor, sources, T0);
  assert.equal(auditor.authorize({ nonce: 'nonce-1', timestamp: T0 }).accepted, true);
  const replay = auditor.authorize({ nonce: 'nonce-1', timestamp: T0 });
  assert.equal(replay.accepted, false);
  assert.ok(replay.reasons.includes('nonce-replay'));
});

test('restart recovery: persisted nonce and time floor survive a restart', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'auditor-'));
  const stateFile = path.join(dir, 'state.json');
  const clocks = makeClocks(T0);
  const sources = [makeSource('alpha'), makeSource('beta'), makeSource('gamma')];

  const first = makeAuditor({ sources, clocks, stateFile });
  establishConsensus(first, sources, T0);
  assert.equal(first.authorize({ nonce: 'nonce-persist', timestamp: T0 }).accepted, true);

  const second = makeAuditor({ sources, clocks, stateFile });
  assert.ok(second.trustedNow() >= T0, 'trusted time must not drop below persisted floor');
  establishConsensus(second, sources, T0);
  const replay = second.authorize({ nonce: 'nonce-persist', timestamp: T0 });
  assert.equal(replay.accepted, false);
  assert.ok(replay.reasons.includes('nonce-replay'));
  assert.equal(second.authorize({ nonce: 'nonce-fresh', timestamp: T0 }).accepted, true);
});

test('system clock rollback never moves trusted time backwards', () => {
  const { clocks, sources, auditor } = threeSourceSetup();
  establishConsensus(auditor, sources, T0);
  clocks.advance(10_000);
  establishConsensus(auditor, sources, T0 + 10_000);
  const before = auditor.trustedNow();

  clocks.rollbackUtc(60_000);
  const after = auditor.trustedNow();
  assert.ok(after >= before, 'trusted time must be monotonic across UTC rollback');
  assert.equal(auditor.snapshot().rollbackDetected, true);
  assert.equal(auditor.authorize({ nonce: 'n-post-rollback', timestamp: after }).accepted, true);
});

test('brief partition survives on monotonic advance, long partition fails closed', () => {
  const { clocks, sources, auditor } = threeSourceSetup();
  establishConsensus(auditor, sources, T0);

  clocks.advance(30_000); // brief outage: monotonic clock carries trusted time
  const trusted = auditor.trustedNow();
  assert.ok(trusted >= T0 + 30_000);
  assert.equal(auditor.authorize({ nonce: 'n-partition', timestamp: trusted }).accepted, true);

  clocks.advance(31_000); // 61s total > maxPartitionMs (60s default)
  const denied = auditor.authorize({ nonce: 'n-partition-late', timestamp: auditor.trustedNow() });
  assert.equal(denied.accepted, false);
  assert.ok(denied.reasons.includes('partition-exceeded'));
});

test('time-source conflict fails closed', () => {
  const { sources, auditor } = threeSourceSetup();
  const times = [T0, T0 + 10_000, T0 + 20_000];
  sources.forEach((source, i) => {
    auditor.ingestStatement(makeStatement(source, { time: times[i], issuedAt: T0 }));
  });
  assert.equal(auditor.snapshot().status, 'conflict');
  const denied = auditor.authorize({ nonce: 'n-conflict', timestamp: T0 });
  assert.equal(denied.accepted, false);
  assert.ok(denied.reasons.includes('time-source-conflict'));
});

test('key overlap: old and new keys both honored during rotation window', () => {
  const oldPair = crypto.generateKeyPairSync('ed25519');
  const newPair = crypto.generateKeyPairSync('ed25519');
  const pem = (key) => key.export({ type: 'spki', format: 'pem' });

  const keyring = new Keyring();
  keyring.addSource('alpha', {
    priority: 1,
    certIds: ['cert-alpha'],
    keys: [
      { keyId: 'old', publicKey: pem(oldPair.publicKey), notBefore: 0, notAfter: T0 + 5_000 },
      { keyId: 'new', publicKey: pem(newPair.publicKey), notBefore: T0 - 5_000, notAfter: Infinity },
    ],
  });
  const clocks = makeClocks(T0);
  const auditor = new TimePolicyAuditor({
    keyring,
    now: clocks.now,
    monotonicNow: clocks.monotonicNow,
  });

  const signWith = (pair, keyId, issuedAt) => {
    const statement = {
      sourceId: 'alpha',
      keyId,
      certId: 'cert-alpha',
      time: issuedAt,
      issuedAt,
      validUntil: issuedAt + 30_000,
      seq: 1,
    };
    statement.signature = signStatement(statement, pair.privateKey);
    return statement;
  };

  // Old key still valid inside the overlap window.
  assert.equal(auditor.ingestStatement(signWith(oldPair, 'old', T0)).accepted, true);
  // New key accepted after rotation.
  assert.equal(auditor.ingestStatement(signWith(newPair, 'new', T0 + 1_000)).accepted, true);
  // Old key past its notAfter is no longer usable.
  assert.equal(
    auditor.ingestStatement(signWith(oldPair, 'old', T0 + 6_000)).reason,
    'no-valid-key'
  );
});

test('leap-second smear widens the accepted skew inside the smear window', () => {
  const smear = { startMs: T0 - 10_000, endMs: T0 + 10_000, offsetMs: -1_000 };
  const { sources, auditor } = threeSourceSetup({ leapSmear: smear });
  establishConsensus(auditor, sources, T0);
  // Smear offset at T0 is -500ms, so future tolerance is 2000 + 500 = 2500ms.
  assert.equal(auditor.authorize({ nonce: 'n-smear-ok', timestamp: T0 + 2_400 }).accepted, true);
  const denied = auditor.authorize({ nonce: 'n-smear-over', timestamp: T0 + 2_600 });
  assert.equal(denied.accepted, false);
  assert.ok(denied.reasons.includes('future-skew-exceeded'));
});

test('bounded replay window evicts oldest nonces beyond capacity', () => {
  const { sources, auditor } = threeSourceSetup({ replayWindowSize: 3, replayWindowTtlMs: 3_600_000 });
  establishConsensus(auditor, sources, T0);
  for (const nonce of ['a', 'b', 'c', 'd']) {
    assert.equal(auditor.authorize({ nonce, timestamp: T0 }).accepted, true);
  }
  assert.equal(auditor.snapshot().replayWindowSize, 3);
  assert.equal(auditor.authorize({ nonce: 'd', timestamp: T0 }).accepted, false);
});
