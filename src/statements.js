'use strict';

const crypto = require('node:crypto');

const STATEMENT_FIELDS = ['sourceId', 'keyId', 'certId', 'time', 'issuedAt', 'validUntil', 'seq'];

function canonicalize(statement) {
  const canonical = {};
  for (const field of STATEMENT_FIELDS) {
    canonical[field] = statement[field] ?? null;
  }
  return JSON.stringify(canonical);
}

function signStatement(statement, privateKey) {
  const payload = Buffer.from(canonicalize(statement), 'utf8');
  return crypto.sign(null, payload, privateKey).toString('base64');
}

function validateShape(statement) {
  if (!statement || typeof statement !== 'object') return 'statement-not-object';
  if (typeof statement.sourceId !== 'string' || statement.sourceId.length === 0) return 'bad-source-id';
  if (typeof statement.keyId !== 'string' || statement.keyId.length === 0) return 'bad-key-id';
  if (typeof statement.certId !== 'string' || statement.certId.length === 0) return 'bad-cert-id';
  if (!Number.isFinite(statement.time)) return 'bad-time';
  if (!Number.isFinite(statement.issuedAt)) return 'bad-issued-at';
  if (!Number.isFinite(statement.validUntil)) return 'bad-valid-until';
  if (!(statement.validUntil > statement.issuedAt)) return 'bad-validity-window';
  if (typeof statement.signature !== 'string' || statement.signature.length === 0) return 'bad-signature';
  return null;
}

function verifyStatementSignature(statement, publicKeyPem) {
  let signature;
  try {
    signature = Buffer.from(statement.signature, 'base64');
  } catch {
    return false;
  }
  try {
    return crypto.verify(
      null,
      Buffer.from(canonicalize(statement), 'utf8'),
      publicKeyPem,
      signature
    );
  } catch {
    return false;
  }
}

module.exports = { canonicalize, signStatement, validateShape, verifyStatementSignature };
