'use strict';

/**
 * Independently pinned, root-signed trust registry for the clean room pilot.
 * Registry keys are PUBLIC. The root private key never enters Room B.
 * A minimum revision from an independent operator checkpoint prevents a
 * verifier from silently accepting a rolled-back registry.
 */
const { KeyObject, createPrivateKey, createPublicKey, sign, verify } = require('node:crypto');
const { canonicalStringify, sha256 } = require('./index');

const FORMAT = 'rudevolution.cleanroom.registry/v1';
const SIGNED_FORMAT = 'rudevolution.cleanroom.registry-signature/v1';
const DOMAIN = SIGNED_FORMAT + '\n';
const ROLES = new Set(['primary', 'secondary', 'worker']);
const ID = /^[A-Za-z0-9][A-Za-z0-9_.@-]{1,79}$/;
const FP = /^[a-f0-9]{64}$/;
const verifiedStates = new WeakSet();

function reject(reason) { throw new Error('Clean room registry rejected: ' + reason); }
function exact(value, keys, at) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.keys(value).length !== keys.length ||
      Object.keys(value).some(key => !keys.includes(key))) reject(at + ' has unknown or missing fields');
}
function iso(value) {
  return typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}
function publicKey(value) {
  let key;
  try {
    if (typeof value !== 'string' || Buffer.byteLength(value) > 4096) reject('key too large');
    key = createPublicKey(value);
  } catch (error) { reject('invalid public key'); }
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') reject('Ed25519 public key required');
  return key;
}
function fingerprint(value) {
  const key = value instanceof KeyObject ? value : publicKey(value);
  return sha256(key.export({ type: 'spki', format: 'der' }));
}
function validateDocument(doc) {
  exact(doc, ['format','revision','issuedAt','expiresAt','keys'], 'document');
  if (doc.format !== FORMAT) reject('unsupported registry format');
  if (!Number.isSafeInteger(doc.revision) || doc.revision < 1) reject('invalid registry revision');
  if (!iso(doc.issuedAt) || !iso(doc.expiresAt)) reject('invalid registry dates');
  const validFor = Date.parse(doc.expiresAt) - Date.parse(doc.issuedAt);
  if (validFor <= 0 || validFor > 31 * 86400000) reject('registry lifetime must not exceed 31 days');
  if (!Array.isArray(doc.keys) || doc.keys.length < 2 || doc.keys.length > 32) reject('invalid key count');
  const ids = new Set(), fingerprints = new Set();
  const groups = new Set();
  for (const entry of doc.keys) {
    exact(entry, ['id','role','publicKey','validFrom','validUntil','revokedAt'], 'key');
    if (typeof entry.id !== 'string' || !ID.test(entry.id) || ids.has(entry.id)) reject('invalid or duplicate key identity');
    ids.add(entry.id);
    if (!ROLES.has(entry.role)) reject('invalid key role');
    groups.add(entry.role);
    if (!iso(entry.validFrom) || !iso(entry.validUntil) ||
        Date.parse(entry.validFrom) >= Date.parse(entry.validUntil)) reject('invalid key validity interval');
    if (entry.revokedAt !== null && !iso(entry.revokedAt)) reject('invalid revocation timestamp');
    if (Date.parse(entry.validUntil) < Date.parse(doc.issuedAt)) reject('expired key registered');
    const fp = fingerprint(entry.publicKey);
    if (fingerprints.has(fp)) reject('one key cannot hold multiple registry identities');
    fingerprints.add(fp);
  }
  if (!groups.has('primary') || !groups.has('secondary')) reject('registry needs primary and secondary reviewers');
  if (Buffer.byteLength(canonicalStringify(doc)) > 32 * 1024) reject('registry too large');
  return doc;
}
function signRegistry(doc, rootPrivateKey) {
  validateDocument(doc);
  const key = rootPrivateKey instanceof KeyObject ? rootPrivateKey : createPrivateKey(rootPrivateKey);
  if (key.asymmetricKeyType !== 'ed25519' || key.type !== 'private') reject('root Ed25519 private key required');
  const encoded = canonicalStringify(doc);
  return {
    format: SIGNED_FORMAT,
    registry: doc,
    signature: sign(null, Buffer.from(DOMAIN + encoded), key).toString('base64'),
  };
}
function strictSignature(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(value)) reject('invalid signature');
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== 64 || decoded.toString('base64') !== value) reject('noncanonical signature');
  return decoded;
}
function deepFreeze(value) {
  if (Array.isArray(value)) value.forEach(deepFreeze);
  else if (value && typeof value === 'object') Object.values(value).forEach(deepFreeze);
  return Object.freeze(value);
}
function verifyRegistry(envelope, pinnedRootPublicKey, { minimumRevision = 1, now = new Date() } = {}) {
  exact(envelope, ['format','registry','signature'], 'signed registry');
  if (envelope.format !== SIGNED_FORMAT) reject('unsupported signed registry');
  validateDocument(envelope.registry);
  if (!Number.isSafeInteger(minimumRevision) || minimumRevision < 1) reject('invalid minimum revision');
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) reject('invalid verifier clock');
  const doc = envelope.registry;
  if (doc.revision < minimumRevision) reject('registry revision rolled back');
  if (Date.parse(doc.issuedAt) > now.getTime() + 5 * 60000) reject('registry issued in the future');
  if (Date.parse(doc.expiresAt) <= now.getTime()) reject('registry expired');
  const key = pinnedRootPublicKey instanceof KeyObject ? pinnedRootPublicKey : publicKey(pinnedRootPublicKey);
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519') reject('invalid root verifier key');
  if (!verify(null, Buffer.from(DOMAIN + canonicalStringify(doc)), key, strictSignature(envelope.signature))) {
    reject('invalid root registry signature');
  }
  // Copy and freeze so later external object mutations cannot alter a
  // previously verified trust decision.
  const trusted = Object.freeze({
    document: deepFreeze(JSON.parse(JSON.stringify(doc))),
    registrySha256: sha256(canonicalStringify(doc)),
    rootFingerprint: fingerprint(key),
  });
  verifiedStates.add(trusted);
  return trusted;
}
function findTrusted(trusted, role, id, { now = new Date() } = {}) {
  if (!verifiedStates.has(trusted)) reject('registry has not been authenticated');
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) reject('invalid verifier time');
  if (Date.parse(trusted.document.expiresAt) <= now.getTime()) reject('registry expired');
  const entry = trusted.document.keys.find(item => item.role === role && item.id === id);
  if (!entry) reject('unknown trusted identity or role');
  if (Date.parse(entry.validFrom) > now.getTime() ||
      Date.parse(entry.validUntil) <= now.getTime()) reject('key outside validity interval');
  if (entry.revokedAt !== null && Date.parse(entry.revokedAt) <= now.getTime()) reject('key revoked');
  return Object.freeze({ id: entry.id, role: entry.role, publicKey: entry.publicKey, fingerprint: fingerprint(entry.publicKey) });
}

module.exports = { FORMAT, SIGNED_FORMAT, validateDocument, signRegistry, verifyRegistry, findTrusted, fingerprint };
