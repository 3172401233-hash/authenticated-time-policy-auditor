'use strict';

const crypto = require('node:crypto');
const { Keyring, TimePolicyAuditor, signStatement } = require('../index.js');

function makeClocks(startUtc = 1_700_000_000_000) {
  const state = { utc: startUtc, mono: 0 };
  return {
    state,
    now: () => state.utc,
    monotonicNow: () => state.mono,
    advance(ms) {
      state.utc += ms;
      state.mono += ms;
    },
    rollbackUtc(ms) {
      state.utc -= ms; // monotonic clock never moves backwards
    },
  };
}

function makeSource(sourceId, { priority = 1, certId = `cert-${sourceId}`, keyOptions = {} } = {}) {
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  return {
    sourceId,
    priority,
    certId,
    privateKey,
    publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }),
    keyId: keyOptions.keyId || `key-${sourceId}`,
    notBefore: keyOptions.notBefore,
    notAfter: keyOptions.notAfter,
  };
}

function buildKeyring(sources) {
  const keyring = new Keyring();
  for (const source of sources) {
    keyring.addSource(source.sourceId, {
      priority: source.priority,
      certIds: [source.certId],
      keys: [
        {
          keyId: source.keyId,
          publicKey: source.publicKeyPem,
          notBefore: source.notBefore,
          notAfter: source.notAfter,
        },
        ...(source.extraKeys || []),
      ],
    });
  }
  return keyring;
}

function makeStatement(source, { time, issuedAt, ttlMs = 30000, seq = 1, overrides = {} } = {}) {
  const statement = {
    sourceId: source.sourceId,
    keyId: source.keyId,
    certId: source.certId,
    time,
    issuedAt,
    validUntil: issuedAt + ttlMs,
    seq,
    ...overrides,
  };
  statement.signature = signStatement(statement, source.privateKey);
  return statement;
}

function makeAuditor({ sources, clocks, config = {}, stateFile = null }) {
  return new TimePolicyAuditor({
    keyring: buildKeyring(sources),
    now: clocks.now,
    monotonicNow: clocks.monotonicNow,
    stateFile,
    config,
  });
}

// Feeds one fresh statement per source so the auditor reaches consensus.
function establishConsensus(auditor, sources, timeMs) {
  for (const source of sources) {
    const result = auditor.ingestStatement(
      makeStatement(source, { time: timeMs, issuedAt: timeMs })
    );
    if (!result.accepted) throw new Error(`consensus setup failed: ${result.reason}`);
  }
}

module.exports = { makeClocks, makeSource, makeAuditor, makeStatement, establishConsensus, buildKeyring };
