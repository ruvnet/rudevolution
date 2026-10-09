'use strict';

/**
 * Operator-controlled, one-way clean room pilot.
 *
 * The intake side only sees an already reviewed release, root-signed trust
 * registry and independently provisioned root key. It does not import the
 * decompiler, reference material or Room A agent memory.
 *
 * No arbitrary shell commands and no automatic AI model invocation.
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { createPrivateKey, KeyObject } = require('node:crypto');
const { canonicalStringify, scaffoldFiles, sha256 } = require('./index');
const { readRegular, sandboxTest } = require('./isolated-runner');
const { verifyRegistry, findTrusted, fingerprint } = require('./trust-registry');
const { verifyRelease } = require('./release');
const { attestReport } = require('./attestation');
const { appendEvidence } = require('./evidence-ledger');

function reject(message) { throw new Error('Clean room pilot rejected: ' + message); }
function json(filename, limit) {
  let object;
  try { object = JSON.parse(readRegular(filename, limit).toString('utf8')); }
  catch (error) { reject('invalid input file or JSON: ' + error.message); }
  return object;
}
function safeParent(filename) {
  let parent = path.resolve(path.dirname(filename));
  for (;;) {
    const stat = fs.lstatSync(parent);
    if (stat.isSymbolicLink() || !stat.isDirectory()) reject('unsafe workspace parent');
    const up = path.dirname(parent);
    if (up === parent) return;
    parent = up;
  }
}
function uniqueOutput(filename) {
  safeParent(filename);
  if (fs.existsSync(filename)) reject('destination already exists');
}
function loadIntake({ releaseFile, registryFile, rootPublicKeyFile, minimumRevision, now = new Date() }) {
  if (!Number.isSafeInteger(minimumRevision) || minimumRevision < 1) reject('operator-provided registry revision floor is required');
  const registry = json(registryFile, 48 * 1024);
  const rootKey = readRegular(rootPublicKeyFile, 4096);
  const trusted = verifyRegistry(registry, rootKey, { minimumRevision, now });
  const release = json(releaseFile, 32 * 1024);
  const verified = verifyRelease(release, trusted, { now });
  return { release, trusted, verified };
}
function createIntake({ releaseFile, registryFile, rootPublicKeyFile, minimumRevision, outputDir, now = new Date() }) {
  const checked = loadIntake({ releaseFile, registryFile, rootPublicKeyFile, minimumRevision, now });
  uniqueOutput(outputDir);
  const files = scaffoldFiles(checked.verified.approved, checked.verified.primaryPublicKey);
  fs.mkdirSync(outputDir, { mode: 0o700, recursive: false });
  try {
    for (const [name, content] of Object.entries(files)) {
      fs.writeFileSync(path.join(outputDir, name), content, { flag: 'wx', mode: 0o600 });
    }
  } catch (error) {
    fs.rmSync(outputDir, { recursive: true, force: true });
    throw error;
  }
  return Object.freeze({
    operationCount: checked.verified.approved.spec.operations.length,
    vectorCount: checked.verified.approved.spec.vectors.length,
    approvalSha256: checked.verified.approvalSha256,
    releaseSha256: checked.verified.releaseSha256,
    registryRevision: checked.verified.registryRevision,
  });
}
function readSigningKey(filename) {
  const data = readRegular(filename, 8192);
  const stat = fs.statSync(filename);
  if ((stat.mode & 0o077) !== 0) reject('worker private key has group/other permissions');
  const key = createPrivateKey(data);
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') reject('worker Ed25519 private key required');
  return key;
}
/**
 * Evaluates ONLY an independently authored Room B project in a pre-pulled,
 * pinned image. The signed release and root registry never enter Docker.
 *
 * The caller keeps returned report/attestation outside the project and
 * independently checkpoints the returned ledger head.
 */
function evaluateIntake({
  releaseFile, registryFile, rootPublicKeyFile, minimumRevision,
  policyFile, projectDir, image, workerPrivateKeyFile, workerId,
  ledgerFile, expectedHead, now = new Date(), spawn = undefined,
}) {
  const checked = loadIntake({ releaseFile, registryFile, rootPublicKeyFile, minimumRevision, now });
  const worker = findTrusted(checked.trusted, 'worker', workerId, { now });
  const signer = readSigningKey(workerPrivateKeyFile);
  if (fingerprint(signer) !== worker.fingerprint) reject('worker signing key not in trusted registry');
  if (worker.fingerprint === checked.verified.secondaryFingerprint ||
      worker.fingerprint === fingerprint(checked.verified.primaryPublicKey)) {
    reject('worker signing key must not be shared with a reviewer');
  }
  // These are the ONLY contract artifacts copied into a temporary staging
  // directory on the Room B host. Room A source is never accepted as input.
  const stage = fs.mkdtempSync(path.join(os.tmpdir(), 'rudevolution-intake-'));
  let report, attestation;
  try {
    const approvedFile = path.join(stage, 'approved.json');
    const publicKeyFile = path.join(stage, 'primary-public.pem');
    fs.writeFileSync(approvedFile, JSON.stringify(checked.verified.approved), { flag: 'wx', mode: 0o600 });
    fs.writeFileSync(publicKeyFile, checked.verified.primaryPublicKey, { flag: 'wx', mode: 0o600 });
    report = spawn === undefined
      ? sandboxTest({ approvedFile, publicKeyFile, policyFile, projectDir, image, now })
      : sandboxTest({ approvedFile, publicKeyFile, policyFile, projectDir, image, now }, spawn);
    attestation = attestReport(report, { privateKey: signer, workerId, now });
  } finally {
    fs.rmSync(stage, { recursive: true, force: true });
  }
  const checkpoint = appendEvidence(ledgerFile, checked.release, attestation, checked.trusted,
    { expectedHead, now });
  return Object.freeze({
    report, attestation,
    checkpoint, releaseSha256: checked.verified.releaseSha256,
    registrySha256: checked.trusted.registrySha256,
  });
}

module.exports = { loadIntake, createIntake, evaluateIntake };
