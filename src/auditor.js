'use strict';

const { Keyring } = require('./keyring');
const { computeConsensus } = require('./consensus.js');
const { ReplayWindow } = require('./replay-window.js');
const {
  validateShape,
  verifyStatementSignature,
} = require('./statements.js');

const DEFAULTS = {
  consensusToleranceMs: 2000, // sources must agree within this spread
  maxPastSkewMs: 5000, // correction window: old timestamps still accepted
  maxFutureSkewMs: 2000, // boundary: how far ahead a request may be
  statementTtlMs: 30000, // freshness of source statements
  maxPartitionMs: 60000, // monotonic-only survival budget during partition
  replayWindowSize: 10000,
  replayWindowTtlMs: 600000,
  maxNonceLength: 256,
  leapSmear: null, // { startMs, endMs, offsetMs }
};

class TimePolicyAuditor {
  constructor(options = {}) {
    this.config = { ...DEFAULTS, ...(options.config || {}) };
    this.keyring = options.keyring || new Keyring();
    this.now = options.now || (() => Date.now());
    this.monotonicNow = options.monotonicNow || (() => performance.now());
    this.replay = ReplayWindow.load({
      maxSize: this.config.replayWindowSize,
      ttlMs: this.config.replayWindowTtlMs,
      stateFile: options.stateFile || null,
    });

    this.statements = new Map(); // sourceId -> latest accepted statement
    this.base = null; // { trustedMs, monoMs } anchor from last consensus
    this.lastConsensusMonoMs = null;
    this.lastTrustedMs = this.replay.floorMs;
    this.lastUtcMs = null;
    this.rollbackDetected = false;
    this.status = 'unavailable';
  }

  smearOffsetAt(timeMs) {
    const smear = this.config.leapSmear;
    if (!smear) return 0;
    if (timeMs <= smear.startMs) return 0;
    if (timeMs >= smear.endMs) return smear.offsetMs;
    const ratio = (timeMs - smear.startMs) / (smear.endMs - smear.startMs);
    return smear.offsetMs * ratio;
  }

  // Trusted time only ever advances. During a partition it advances with the
  // monotonic clock up to maxPartitionMs; a system-clock rollback is never
  // "cancelled out" by re-anchoring onto UTC plus a monotonic delta.
  trustedNow() {
    const utcMs = this.now();
    if (this.lastUtcMs !== null && utcMs < this.lastUtcMs) {
      this.rollbackDetected = true;
    }
    this.lastUtcMs = this.lastUtcMs === null ? utcMs : Math.max(this.lastUtcMs, utcMs);

    let candidate = this.lastTrustedMs;
    if (this.base) {
      const elapsed = Math.max(0, this.monotonicNow() - this.base.monoMs);
      const capped = Math.min(elapsed, this.config.maxPartitionMs + this.config.statementTtlMs);
      candidate = Math.max(candidate, this.base.trustedMs + capped);
    }
    candidate = Math.max(candidate, this.replay.floorMs);
    this.lastTrustedMs = candidate;
    return candidate;
  }

  partitionExceeded() {
    if (this.lastConsensusMonoMs === null) return true;
    return this.monotonicNow() - this.lastConsensusMonoMs > this.config.maxPartitionMs;
  }

  ingestStatement(statement) {
    const shapeError = validateShape(statement);
    if (shapeError) return { accepted: false, reason: shapeError };

    const source = this.keyring.getSource(statement.sourceId);
    if (!source) return { accepted: false, reason: 'unknown-source' };
    if (!this.keyring.certIdAccepted(statement.sourceId, statement.certId)) {
      return { accepted: false, reason: 'cert-mismatch' };
    }

    const key = this.keyring.findKey(statement.sourceId, statement.keyId, statement.issuedAt);
    if (!key) return { accepted: false, reason: 'no-valid-key' };
    if (!verifyStatementSignature(statement, key.publicKey)) {
      return { accepted: false, reason: 'bad-signature' };
    }

    const reference = this.base ? this.trustedNow() : this.now();
    if (statement.validUntil <= reference) {
      return { accepted: false, reason: 'statement-expired' };
    }
    if (statement.issuedAt > reference + this.config.maxFutureSkewMs + Math.abs(this.smearOffsetAt(reference))) {
      return { accepted: false, reason: 'statement-from-future' };
    }

    const previous = this.statements.get(statement.sourceId);
    if (previous && previous.issuedAt >= statement.issuedAt) {
      return { accepted: false, reason: 'stale-statement' };
    }
    this.statements.set(statement.sourceId, statement);
    this.#recomputeConsensus();
    return { accepted: true, reason: null };
  }

  #recomputeConsensus() {
    const reference = this.base ? this.trustedNow() : this.now();
    const smearMargin = Math.abs(this.smearOffsetAt(reference));
    const samples = [];
    for (const [sourceId, statement] of this.statements) {
      if (statement.issuedAt + this.config.statementTtlMs < reference) {
        this.statements.delete(sourceId);
        continue;
      }
      const source = this.keyring.getSource(sourceId);
      samples.push({ sourceId, priority: source.priority, timeMs: statement.time });
    }
    const result = computeConsensus(samples, this.config.consensusToleranceMs + smearMargin);
    if (result.status !== 'ok') {
      this.status = result.status; // conflict: hold last trusted time, fail closed
      return result;
    }
    const trustedMs = Math.max(result.timeMs, this.lastTrustedMs, this.replay.floorMs);
    this.base = { trustedMs, monoMs: this.monotonicNow() };
    this.lastConsensusMonoMs = this.monotonicNow();
    this.replay.updateFloor(trustedMs);
    this.replay.persist();
    this.status = 'ok';
    return result;
  }

  authorize({ nonce, timestamp } = {}) {
    const reasons = [];
    if (typeof nonce !== 'string' || nonce.length === 0 || nonce.length > this.config.maxNonceLength) {
      reasons.push('bad-nonce');
    }
    if (!Number.isFinite(timestamp)) reasons.push('bad-timestamp');
    if (reasons.length > 0) return { accepted: false, reasons, trustedTime: null };

    if (this.partitionExceeded()) {
      return { accepted: false, reasons: ['partition-exceeded'], trustedTime: null };
    }
    if (this.status === 'conflict') {
      return { accepted: false, reasons: ['time-source-conflict'], trustedTime: null };
    }

    const trusted = this.trustedNow();
    const smearMargin = Math.abs(this.smearOffsetAt(trusted));
    const skew = timestamp - trusted;
    if (skew > this.config.maxFutureSkewMs + smearMargin) {
      reasons.push('future-skew-exceeded');
    }
    if (-skew > this.config.maxPastSkewMs + smearMargin) {
      reasons.push('past-skew-exceeded');
    }
    this.replay.prune(trusted);
    if (this.replay.has(nonce)) {
      reasons.push('nonce-replay');
    }
    if (reasons.length > 0) {
      return { accepted: false, reasons, trustedTime: trusted };
    }
    this.replay.record(nonce, trusted);
    this.replay.updateFloor(trusted);
    this.replay.persist();
    return { accepted: true, reasons: [], trustedTime: trusted };
  }

  snapshot() {
    return {
      status: this.status,
      trustedTime: this.trustedNow(),
      rollbackDetected: this.rollbackDetected,
      partitionExceeded: this.partitionExceeded(),
      replayWindowSize: this.replay.nonces.size,
      floorMs: this.replay.floorMs,
    };
  }
}

module.exports = { TimePolicyAuditor, DEFAULTS };
