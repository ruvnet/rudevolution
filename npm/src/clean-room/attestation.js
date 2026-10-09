'use strict';

/**
 * Optional Ed25519 integrity attestation for a Room B evaluation report.
 * A signature identifies the signing key and binds report bytes. It does not
 * attest host isolation, source independence or the legality of reimplementation.
 */
const { KeyObject, createPublicKey, createPrivateKey, sign, verify } = require('node:crypto');
const { canonicalStringify, sha256 } = require('./index');

const FORMAT = 'rudevolution.cleanroom.evaluation-attestation/v1';
const REPORT = 'rudevolution.cleanroom.sandbox-report/v2';
const DOMAIN = FORMAT + '\n';
const ID = /^[a-z][a-z0-9-]{0,47}$/;
const HEX = /^[a-f0-9]{64}$/;
const IMAGE = /^[a-z0-9][a-z0-9./_-]{0,127}@sha256:[a-f0-9]{64}$/;
const REPORT_KEYS = ['format','approvalSha256','specSha256','policySha256',
  'publicKeyFingerprint','implementationSha256','harnessSha256','image',
  'vectorCount','executedVectors','passedVectors','status','exitCode',
  'durationMs','stdoutSha256','stderrSha256'];

function reject(text) { throw Error('Clean room attestation rejected: ' + text); }
function exact(obj, keys) {
  if (!obj || Array.isArray(obj) || Object.getPrototypeOf(obj) !== Object.prototype ||
      Object.keys(obj).length !== keys.length ||
      Object.keys(obj).some(k => !keys.includes(k))) reject('unexpected/missing fields');
}
function validDate(s) {
  return typeof s === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(s) &&
    Number.isFinite(Date.parse(s)) && new Date(s).toISOString() === s;
}
function fp(key) {
  const pub = key instanceof KeyObject && key.type === 'public' ? key : createPublicKey(key);
  return sha256(pub.export({ format:'der', type:'spki' }));
}
function validateReport(r) {
  exact(r, REPORT_KEYS);
  if (r.format !== REPORT) reject('unsupported report version');
  for (const k of REPORT_KEYS.filter(k => k.endsWith('Sha256') || k === 'publicKeyFingerprint')) {
    if (typeof r[k] !== 'string' || !HEX.test(r[k])) reject('invalid digest ' + k);
  }
  if (typeof r.image !== 'string' || !IMAGE.test(r.image)) reject('untrusted image');
  if (!Number.isInteger(r.vectorCount) || r.vectorCount < 1 || r.vectorCount > 24) reject('invalid vector count');
  for (const k of ['executedVectors','passedVectors']) {
    if (!Number.isInteger(r[k]) || r[k] < 0 || r[k] > r.vectorCount) reject('invalid vector accounting');
  }
  if (r.passedVectors > r.executedVectors) reject('passing vectors exceed executed');
  if (!['passed','failed','timeout','runner_error'].includes(r.status)) reject('invalid status');
  if (r.exitCode !== null && (!Number.isInteger(r.exitCode) || r.exitCode < 0 || r.exitCode > 255)) reject('invalid exit code');
  if (!Number.isInteger(r.durationMs) || r.durationMs < 0 || r.durationMs > 120000) reject('invalid duration');
  if (r.status === 'passed' && (r.exitCode !== 0 || r.executedVectors !== r.vectorCount ||
    r.passedVectors !== r.vectorCount)) reject('unexecuted vectors cannot pass');
  if (Buffer.byteLength(canonicalStringify(r)) > 8192) reject('report too large');
  return r;
}
function message(r, workerId, signedAt, digest) {
  return DOMAIN + canonicalStringify({ report:r, workerId, signedAt, reportSha256:digest });
}
function attestReport(report, {privateKey, workerId, now=new Date()}) {
  validateReport(report);
  if (typeof workerId !== 'string' || !ID.test(workerId)) reject('invalid worker ID');
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) reject('invalid clock');
  const key = privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey);
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') reject('Ed25519 private key required');
  const signedAt = now.toISOString(), reportSha256 = sha256(canonicalStringify(report));
  const signature = sign(null, Buffer.from(message(report, workerId, signedAt, reportSha256)), key).toString('base64');
  return { format:FORMAT, report, attester:{
    workerId, signedAt, reportSha256, publicKeyFingerprint:fp(key), signature,
  }};
}
function verifyAttestation(envelope, trustedPublicKey, {
  workerId, approvalSha256, maxAgeHours=168, now=new Date(),
}={}) {
  exact(envelope, ['format','report','attester']);
  if (envelope.format !== FORMAT) reject('unsupported attestation');
  const report = validateReport(envelope.report);
  const a = envelope.attester;
  exact(a, ['workerId','signedAt','reportSha256','publicKeyFingerprint','signature']);
  if (typeof a.workerId !== 'string' || !ID.test(a.workerId) || !validDate(a.signedAt)) reject('invalid attester metadata');
  if (typeof a.reportSha256 !== 'string' || a.reportSha256 !== sha256(canonicalStringify(report))) reject('report digest mismatch');
  if (typeof a.publicKeyFingerprint !== 'string' || !HEX.test(a.publicKeyFingerprint)) reject('invalid signer fingerprint');
  if (typeof a.signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(a.signature)) reject('invalid signature encoding');
  const sig=Buffer.from(a.signature, 'base64');
  if (sig.length !== 64 || sig.toString('base64') !== a.signature) reject('noncanonical signature');
  const key=trustedPublicKey instanceof KeyObject ? trustedPublicKey : createPublicKey(trustedPublicKey);
  if (key.type !== 'public' || key.asymmetricKeyType !== 'ed25519' || fp(key) !== a.publicKeyFingerprint) reject('untrusted signing key');
  if (!verify(null, Buffer.from(message(report,a.workerId,a.signedAt,a.reportSha256)), key, sig)) reject('bad signature');
  if (workerId !== undefined && workerId !== a.workerId) reject('untrusted worker identity');
  if (approvalSha256 !== undefined && approvalSha256 !== report.approvalSha256) reject('unexpected approval');
  if (!Number.isInteger(maxAgeHours) || maxAgeHours < 1 || maxAgeHours > 720 ||
      !(now instanceof Date) || !Number.isFinite(now.getTime())) reject('invalid verification policy');
  const delta=now.getTime()-Date.parse(a.signedAt);
  if (delta < -300000 || delta > maxAgeHours*3600000) reject('future/expired attestation');
  return {report,workerId:a.workerId,reportSha256:a.reportSha256,publicKeyFingerprint:a.publicKeyFingerprint};
}
module.exports={FORMAT,REPORT,validateReport,attestReport,verifyAttestation};
