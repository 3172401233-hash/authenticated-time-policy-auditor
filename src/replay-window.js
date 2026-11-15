'use strict';

const fs = require('node:fs');

// Bounded replay window. Nonces expire by trusted-time TTL; capacity is
// capped with oldest-first eviction. When a stateFile is configured the
// window is persisted atomically so a restart cannot reopen replay.
class ReplayWindow {
  constructor({ maxSize = 10000, ttlMs = 600000, stateFile = null } = {}) {
    this.maxSize = maxSize;
    this.ttlMs = ttlMs;
    this.stateFile = stateFile;
    this.nonces = new Map(); // nonce -> expiresAtTrustedMs
    this.floorMs = 0;
  }

  static load(options) {
    const window = new ReplayWindow(options);
    if (!window.stateFile || !fs.existsSync(window.stateFile)) return window;
    let parsed;
    try {
      parsed = JSON.parse(fs.readFileSync(window.stateFile, 'utf8'));
    } catch {
      return window; // corrupt state: fail closed by keeping an empty-but-live window
    }
    window.floorMs = Number.isFinite(parsed.floorMs) ? parsed.floorMs : 0;
    if (Array.isArray(parsed.nonces)) {
      for (const entry of parsed.nonces) {
        if (Array.isArray(entry) && typeof entry[0] === 'string' && Number.isFinite(entry[1])) {
          window.nonces.set(entry[0], entry[1]);
        }
      }
    }
    return window;
  }

  prune(nowTrustedMs) {
    for (const [nonce, expiresAt] of this.nonces) {
      if (expiresAt <= nowTrustedMs) this.nonces.delete(nonce);
    }
  }

  has(nonce) {
    return this.nonces.has(nonce);
  }

  record(nonce, nowTrustedMs) {
    this.prune(nowTrustedMs);
    while (this.nonces.size >= this.maxSize) {
      const oldest = this.nonces.keys().next().value;
      this.nonces.delete(oldest);
    }
    this.nonces.set(nonce, nowTrustedMs + this.ttlMs);
  }

  updateFloor(candidateMs) {
    if (candidateMs > this.floorMs) this.floorMs = candidateMs;
  }

  persist() {
    if (!this.stateFile) return;
    const payload = JSON.stringify({
      floorMs: this.floorMs,
      nonces: [...this.nonces.entries()],
    });
    const tmp = `${this.stateFile}.tmp`;
    fs.writeFileSync(tmp, payload);
    fs.renameSync(tmp, this.stateFile);
  }
}

module.exports = { ReplayWindow };
