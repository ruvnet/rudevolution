'use strict';

/**
 * One-way, two-person handoff for interface-only clean room contracts.
 * The Room A scan does not export source markers, analysis traces or a DLP log.
 * The Room B verifier uses only the independently signed trust registry.
 */
const { KeyObject, createPrivateKey, sign, verify } = require('node:crypto');
const { canonicalStringify, verifyApproved, validateSpec, sha256 } = require('./index');
const { findTrusted, fingerprint } = require('./trust-registry');

const FORMAT = 'rudevolution.cleanroom.release/v1';
const DOMAIN = FORMAT + '\n';
const REASONS = new Set(['interoperability', 'compatibility', 'security-testing']);
const ID = /^[A-Za-z0-9][A-Za-z0-9_.@-]{1,79}$/;
const HEX = /^[a-f0-9]{64}$/;
const MAX_RELEASE_AGE_MS = 24 * 3600000;

function reject(message) { throw new Error('Clean room transfer rejected: ' + message); }
function exact(obj, fields, at) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj) ||
      Object.getPrototypeOf(obj) !== Object.prototype ||
      Object.keys(obj).length !== fields.length ||
      Object.keys(obj).some(k => !fields.includes(k))) reject(at + ' has unknown/missing fields');
}
function utc(s) {
  return typeof s === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(s) &&
    Number.isFinite(Date.parse(s)) && new Date(s).toISOString() === s;
}
function signatureBytes(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(value)) reject('malformed Ed25519 signature');
  const b = Buffer.from(value, 'base64');
  if (b.length !== 64 || b.toString('base64') !== value) reject('noncanonical signature encoding');
  return b;
}
function normalize(s) { return s.toLowerCase().replace(/[^a-z0-9]/g, ''); }
function allStrings(value, out) {
  if (typeof value === 'string') out.push(value);
  else if (Array.isArray(value)) value.forEach(item => allStrings(item, out));
  else if (value && typeof value === 'object') Object.values(value).forEach(item => allStrings(item, out));
}
function checkDisclosure(spec, restrictedMarkers = []) {
  validateSpec(spec);
  if (!Array.isArray(restrictedMarkers) || restrictedMarkers.length > 128) reject('invalid restricted marker list');
  const strings = [];
  allStrings(spec, strings);
  const visible = normalize(strings.join(' '));
  const serialized = normalize(canonicalStringify(spec));
  for (const marker of restrictedMarkers) {
    if (typeof marker !== 'string' || marker.length < 8 || marker.length > 4096) reject('invalid restricted marker');
    const variants = [marker, Buffer.from(marker, 'utf8').toString('hex'), Buffer.from(marker, 'utf8').toString('base64')];
    for (const variant of variants) {
      const code = normalize(variant);
      if (code.length >= 8 && (visible.includes(code) || serialized.includes(code))) {
        reject('prohibited source marker or common encoding detected');
      }
    }
  }
  // Intentionally conservative. An opaque 32-byte token has no obvious
  // interoperability role in this v1 primitive-only interface contract.
  for (const value of strings) {
    if (value.length >= 32 &&
      (/^[0-9a-fA-F]{24,}$/.test(value) ||
       (/^[a-zA-Z0-9+/=]{32,}$/.test(value) && new Set(value).size > 12))) {
      reject('opaque high-entropy scalar requires independent redaction');
    }
    if (/-----BEGIN |[{};<>\n\r]/.test(value)) reject('code or key-shaped string');
  }
  const integers = spec.vectors.flatMap(item => [
    ...item.arguments.filter(x => Number.isInteger(x) && x >= 32 && x <= 126),
    ...(Number.isInteger(item.expected) && item.expected >= 32 && item.expected <= 126 ? [item.expected] : []),
  ]);
  if (integers.length >= 12) reject('numerical character encoding requires manual reduction');
  return true;
}
function signedMessage({approvalSha256, primaryFingerprint, reviewer, reviewedAt, reason}) {
  return DOMAIN + canonicalStringify({approvalSha256, primaryFingerprint, reviewer, reviewedAt, reason});
}
function reviewRelease(approved, primaryPublicKey, {
  reviewer, privateKey, reason = 'interoperability', restrictedMarkers = [], now = new Date(),
} = {}) {
  const first = verifyApproved(approved, primaryPublicKey);
  if (typeof reviewer !== 'string' || !ID.test(reviewer) || reviewer === first.reviewer) reject('independent second reviewer required');
  if (!REASONS.has(reason)) reject('invalid review purpose');
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) reject('invalid review clock');
  const age = now.getTime() - Date.parse(first.approvedAt);
  if (age < 0 || age > MAX_RELEASE_AGE_MS) reject('primary review is stale or in the future');
  checkDisclosure(first.spec, restrictedMarkers);
  const key = privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey);
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') reject('Ed25519 secondary signing key required');
  const firstFP = fingerprint(primaryPublicKey), secondFP = fingerprint(key);
  if (firstFP === secondFP) reject('primary and secondary reviewer keys must differ');
  const review = {
    reviewer,
    reviewedAt: now.toISOString(),
    approvalSha256: first.approvalSha256,
    primaryFingerprint: firstFP,
    reason,
  };
  const signature = sign(null, Buffer.from(signedMessage(review)), key).toString('base64');
  const released = {
    format: FORMAT,
    approved,
    secondReview: { ...review, signature },
  };
  if (Buffer.byteLength(canonicalStringify(released)) > 32 * 1024) reject('release too large');
  return released;
}
function verifyRelease(released, trustedRegistry, { now = new Date() } = {}) {
  exact(released, ['format','approved','secondReview'], 'release');
  if (released.format !== FORMAT) reject('unsupported release format');
  exact(released.secondReview,
    ['reviewer','reviewedAt','approvalSha256','primaryFingerprint','reason','signature'], 'secondary review');
  const secondary = released.secondReview;
  if (typeof secondary.reviewer !== 'string' || !ID.test(secondary.reviewer)) reject('invalid secondary reviewer');
  if (!utc(secondary.reviewedAt) || !REASONS.has(secondary.reason) ||
      typeof secondary.primaryFingerprint !== 'string' || !HEX.test(secondary.primaryFingerprint) ||
      typeof secondary.approvalSha256 !== 'string' || !HEX.test(secondary.approvalSha256)) reject('invalid review metadata');
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) reject('invalid verifier clock');
  // Both reviewer keys come ONLY from a root-authenticated registry.
  const firstId = released.approved?.review?.reviewer;
  const primary = findTrusted(trustedRegistry, 'primary', firstId, { now });
  const second = findTrusted(trustedRegistry, 'secondary', secondary.reviewer, { now });
  const first = verifyApproved(released.approved, primary.publicKey);
  if (first.reviewer === secondary.reviewer || primary.fingerprint === second.fingerprint) reject('two distinct reviewers required');
  if (secondary.primaryFingerprint !== primary.fingerprint ||
      secondary.approvalSha256 !== first.approvalSha256) reject('primary approval mismatch');
  checkDisclosure(first.spec);
  const time = Date.parse(secondary.reviewedAt);
  if (time > now.getTime() + 5 * 60000 ||
      time < Date.parse(first.approvedAt) ||
      now.getTime() - time > MAX_RELEASE_AGE_MS) reject('secondary review stale or not causally ordered');
  const message = signedMessage(secondary);
  if (!verify(null, Buffer.from(message), second.publicKey, signatureBytes(secondary.signature))) {
    reject('invalid secondary reviewer signature');
  }
  const releaseSha256 = sha256(canonicalStringify(released));
  return Object.freeze({
    approved: released.approved,
    approvalSha256: first.approvalSha256,
    specSha256: sha256(canonicalStringify(first.spec)),
    releaseSha256,
    registrySha256: trustedRegistry.registrySha256,
    registryRevision: trustedRegistry.document.revision,
    primaryPublicKey: primary.publicKey,
    primaryReviewer: primary.id,
    secondaryReviewer: second.id,
    secondaryFingerprint: second.fingerprint,
  });
}
module.exports = { FORMAT, checkDisclosure, reviewRelease, verifyRelease };
