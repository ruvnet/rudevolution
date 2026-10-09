'use strict';

/**
 * Hash-chained Room B evaluation ledger. It stores only bounded digests.
 * File append is serialized with an exclusive lock. The operator must keep
 * an independent expected head to detect rollback or truncation.
 * This is not WORM storage or hardware attestation.
 */
const fs = require('node:fs');
const path = require('node:path');
const { canonicalStringify, sha256 } = require('./index');
const { verifyAttestation } = require('./attestation');
const { findTrusted, fingerprint } = require('./trust-registry');
const { verifyRelease } = require('./release');

const FORMAT = 'rudevolution.cleanroom.evidence-ledger/v1';
const ZERO = '0'.repeat(64);
const HEX = /^[a-f0-9]{64}$/;
const MAX_RECORDS = 1024;
const MAX_BYTES = 4 * 1024 * 1024;
const KEYS = ['format','sequence','previousSha256','releaseSha256','registrySha256',
  'approvalSha256','reportSha256','signedEvaluationSha256','workerId','status','recordedAt','entrySha256'];

function reject(msg) { throw new Error('Clean room ledger rejected: ' + msg); }
function strict(value, names) {
  if (!value || typeof value !== 'object' || Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Object.prototype ||
      Object.keys(value).length !== names.length ||
      Object.keys(value).some(key => !names.includes(key))) reject('unexpected ledger fields');
}
function iso(value) {
  return typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}
function assertParents(filename) {
  let cursor = path.resolve(path.dirname(filename));
  for (;;) {
    const stat = fs.lstatSync(cursor);
    if (!stat.isDirectory() || stat.isSymbolicLink()) reject('unsafe ledger directory');
    const parent = path.dirname(cursor);
    if (parent === cursor) return;
    cursor = parent;
  }
}
function readExisting(filename) {
  assertParents(filename);
  let fd;
  try {
    fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  } catch (e) {
    if (e.code === 'ENOENT') return null;
    throw e;
  }
  try {
    const stat = fs.fstatSync(fd);
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > MAX_BYTES) reject('invalid ledger file');
    const bytes = fs.readFileSync(fd);
    if (bytes.length !== stat.size) reject('ledger changed while reading');
    return bytes.toString('utf8');
  } finally { fs.closeSync(fd); }
}
function digest(entry) {
  const { entrySha256, ...fields } = entry;
  return sha256(canonicalStringify(fields));
}
function verifyLedgerText(text, { expectedHead = undefined } = {}) {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > MAX_BYTES) reject('invalid ledger text');
  if (expectedHead !== undefined && (typeof expectedHead !== 'string' || !HEX.test(expectedHead))) reject('invalid trusted checkpoint');
  if (text && !text.endsWith('\n')) reject('partial final record');
  const lines = text ? text.trimEnd().split('\n') : [];
  if (lines.length > MAX_RECORDS) reject('ledger record limit exceeded');
  let head = ZERO, sequence = 0;
  for (const line of lines) {
    if (line.length > 2048) reject('oversize ledger record');
    let entry;
    try { entry = JSON.parse(line); } catch { reject('malformed ledger JSON'); }
    strict(entry, KEYS);
    if (entry.format !== FORMAT || !Number.isSafeInteger(entry.sequence) ||
        entry.sequence !== sequence + 1 || entry.previousSha256 !== head) reject('broken ledger chain');
    for (const key of ['previousSha256','releaseSha256','registrySha256','approvalSha256',
      'reportSha256','signedEvaluationSha256','entrySha256']) {
      if (typeof entry[key] !== 'string' || !HEX.test(entry[key])) reject('invalid ledger digest');
    }
    if (!iso(entry.recordedAt) ||
        typeof entry.workerId !== 'string' || !/^[a-z][a-z0-9-]{0,47}$/.test(entry.workerId) ||
        !['passed','failed','timeout','runner_error'].includes(entry.status)) reject('invalid ledger metadata');
    if (digest(entry) !== entry.entrySha256) reject('ledger entry digest mismatch');
    head = entry.entrySha256;
    sequence++;
  }
  if (expectedHead !== undefined && expectedHead !== head) reject('ledger head does not match independent checkpoint');
  return Object.freeze({ head, sequence });
}
function readLedger(filename, options = {}) {
  const text = readExisting(filename);
  return verifyLedgerText(text === null ? '' : text, options);
}
function composeEntry(verifiedRelease, envelope, trustedRegistry, { now = new Date() } = {}) {
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) reject('invalid ledger clock');
  const workerId = envelope?.attester?.workerId;
  const worker = findTrusted(trustedRegistry, 'worker', workerId, { now });
  if (worker.fingerprint !== envelope.attester.publicKeyFingerprint) reject('worker fingerprint differs from trusted registry');
  const checked = verifyAttestation(envelope, worker.publicKey, {
    workerId, approvalSha256: verifiedRelease.approvalSha256, now,
  });
  const report = checked.report;
  if (report.specSha256 !== verifiedRelease.specSha256 ||
      report.publicKeyFingerprint !== fingerprint(verifiedRelease.primaryPublicKey)) {
    reject('evaluation does not match released contract');
  }
  if (verifiedRelease.registrySha256 !== trustedRegistry.registrySha256) reject('registry mismatch');
  return {
    format: FORMAT,
    releaseSha256: verifiedRelease.releaseSha256,
    registrySha256: trustedRegistry.registrySha256,
    approvalSha256: verifiedRelease.approvalSha256,
    reportSha256: checked.reportSha256,
    signedEvaluationSha256: sha256(canonicalStringify(envelope)),
    workerId,
    status: report.status,
    recordedAt: now.toISOString(),
  };
}
function appendEvidence(filename, release, envelope, trustedRegistry, {
  expectedHead, now = new Date(),
} = {}) {
  if (typeof expectedHead !== 'string' || !HEX.test(expectedHead)) reject('independent expected head required');
  assertParents(filename);
  const verifiedRelease = verifyRelease(release, trustedRegistry, { now });
  const fields = composeEntry(verifiedRelease, envelope, trustedRegistry, { now });
  const lock = filename + '.lock';
  const lockFd = fs.openSync(lock, fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW, 0o600);
  try {
    const current = readExisting(filename);
    const before = verifyLedgerText(current === null ? '' : current, { expectedHead });
    if (before.sequence >= MAX_RECORDS) reject('ledger full; rotate with retained independent checkpoint');
    const entry = { ...fields, sequence: before.sequence + 1, previousSha256: before.head };
    entry.entrySha256 = digest(entry);
    const bytes = JSON.stringify(entry) + '\n';
    if (Buffer.byteLength(current || '') + Buffer.byteLength(bytes) > MAX_BYTES) reject('ledger size exceeded');
    const flags = current === null
      ? fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW
      : fs.constants.O_APPEND | fs.constants.O_WRONLY | fs.constants.O_NOFOLLOW;
    const fd = fs.openSync(filename, flags, 0o600);
    try {
      const stat = fs.fstatSync(fd);
      if (!stat.isFile() || stat.nlink !== 1 || stat.size !== Buffer.byteLength(current || '')) {
        reject('ledger changed before append');
      }
      const written = fs.writeSync(fd, Buffer.from(bytes));
      if (written !== Buffer.byteLength(bytes)) reject('incomplete ledger append');
      fs.fsyncSync(fd);
    } finally { fs.closeSync(fd); }
    return verifyLedgerText((current || '') + bytes);
  } finally {
    fs.closeSync(lockFd);
    fs.unlinkSync(lock);
  }
}

module.exports = { FORMAT, ZERO, verifyLedgerText, readLedger, appendEvidence };
