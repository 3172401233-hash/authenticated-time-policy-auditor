'use strict';

class Keyring {
  constructor() {
    this.sources = new Map();
  }

  addSource(sourceId, { priority = 1, certIds = [], keys = [] } = {}) {
    if (!sourceId || typeof sourceId !== 'string') {
      throw new TypeError('sourceId must be a non-empty string');
    }
    if (!Number.isFinite(priority) || priority <= 0) {
      throw new TypeError('priority must be a positive number');
    }
    const normalizedKeys = keys.map((key) => {
      if (!key.keyId || !key.publicKey) {
        throw new TypeError('each key requires keyId and publicKey (PEM)');
      }
      const notBefore = key.notBefore ?? -Infinity;
      const notAfter = key.notAfter ?? Infinity;
      if (!(notBefore < notAfter)) {
        throw new TypeError(`key ${key.keyId}: notBefore must be < notAfter`);
      }
      return { keyId: key.keyId, publicKey: key.publicKey, notBefore, notAfter };
    });
    this.sources.set(sourceId, {
      sourceId,
      priority,
      certIds: new Set(certIds),
      keys: normalizedKeys,
    });
    return this;
  }

  getSource(sourceId) {
    return this.sources.get(sourceId) || null;
  }

  certIdAccepted(sourceId, certId) {
    const source = this.getSource(sourceId);
    if (!source) return false;
    if (source.certIds.size === 0) return true;
    return source.certIds.has(certId);
  }

  // Key overlap: a key is usable only for statements issued inside its
  // validity window, so old and new keys may coexist during rotation.
  findKey(sourceId, keyId, issuedAtMs) {
    const source = this.getSource(sourceId);
    if (!source) return null;
    return (
      source.keys.find(
        (key) =>
          key.keyId === keyId &&
          issuedAtMs >= key.notBefore &&
          issuedAtMs <= key.notAfter
      ) || null
    );
  }
}

module.exports = { Keyring };
