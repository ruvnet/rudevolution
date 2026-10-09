'use strict';

/**
 * Room B only: verify an externally pinned review policy and run an
 * independently authored implementation in an offline Docker container.
 *
 * Never accepts an original source path. Never mounts the project directory.
 * Docker access is privileged on the host; operate this tool only in a
 * dedicated Room B worker with no Room A data, credentials, or shared AI state.
 */
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { randomBytes } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { verifyApproved, scaffoldFiles, sha256 } = require('./index');

const POLICY_FORMAT = 'rudevolution.cleanroom.policy/v1';
const REPORT_FORMAT = 'rudevolution.cleanroom.sandbox-report/v1';
const IMAGE = /^[a-z0-9][a-z0-9./_-]{0,127}@sha256:[a-f0-9]{64}$/;
const HEX = /^[a-f0-9]{64}$/;
const REVIEWER = /^[A-Za-z0-9][A-Za-z0-9_.@-]{1,79}$/;
const TARGET = /^[a-z][a-z0-9-]{0,47}$/;
const REQUIRED = ['APPROVAL.txt', 'compat.test.mjs', 'contract.json', 'implementation.mjs'];
const MAX_IMPL = 256 * 1024;

function deny(message) { throw new Error('Room B isolation rejected: ' + message); }
function isObject(value) {
  return value !== null && typeof value === 'object' &&
    !Array.isArray(value) && Object.getPrototypeOf(value) === Object.prototype;
}
function fields(value, names, where) {
  if (!isObject(value) || Object.keys(value).length !== names.length ||
      Object.keys(value).some(key => !names.includes(key))) deny(where + ' contains prohibited or missing fields');
}
function iso(value) {
  return typeof value === 'string' &&
    /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) &&
    Number.isFinite(Date.parse(value)) && new Date(value).toISOString() === value;
}
function checkPolicy(policy, verified, now = new Date()) {
  fields(policy, ['format', 'target', 'reviewer', 'publicKeyFingerprint', 'expiresAt', 'maxApprovalAgeHours'], 'policy');
  if (policy.format !== POLICY_FORMAT) deny('unsupported policy format');
  if (typeof policy.target !== 'string' || !TARGET.test(policy.target)) deny('invalid target');
  if (typeof policy.reviewer !== 'string' || !REVIEWER.test(policy.reviewer)) deny('invalid reviewer');
  if (typeof policy.publicKeyFingerprint !== 'string' || !HEX.test(policy.publicKeyFingerprint)) deny('invalid fingerprint');
  if (!iso(policy.expiresAt)) deny('invalid policy expiry');
  if (!Number.isInteger(policy.maxApprovalAgeHours) || policy.maxApprovalAgeHours < 1 || policy.maxApprovalAgeHours > 720) deny('invalid approval age limit');
  if (!(now instanceof Date) || !Number.isFinite(now.getTime())) deny('invalid clock');
  if (policy.target !== verified.spec.target || policy.reviewer !== verified.reviewer) deny('target or reviewer not permitted');
  if (policy.publicKeyFingerprint !== verified.publicKeyFingerprint) deny('trusted key fingerprint mismatch');
  if (now.getTime() > Date.parse(policy.expiresAt)) deny('trust policy expired');
  const signed = Date.parse(verified.approvedAt);
  if (signed > now.getTime() + 5 * 60 * 1000) deny('approval timestamp is in the future');
  if (now.getTime() - signed > policy.maxApprovalAgeHours * 3600000) deny('approval is too old');
  if (signed > Date.parse(policy.expiresAt)) deny('approval beyond policy expiry');
  return verified;
}

function checkAncestors(filename) {
  let current = path.resolve(filename);
  for (;;) {
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink()) deny('symlink in trusted path');
    if (current !== path.resolve(filename) && !stat.isDirectory()) deny('non-directory path parent');
    const parent = path.dirname(current);
    if (parent === current) return;
    current = parent;
  }
}
function readRegular(filename, maxBytes) {
  checkAncestors(filename);
  const fd = fs.openSync(filename, fs.constants.O_RDONLY | fs.constants.O_NOFOLLOW | fs.constants.O_NONBLOCK);
  try {
    const before = fs.fstatSync(fd);
    if (!before.isFile() || before.size > maxBytes || before.nlink !== 1) deny('file not regular, uniquely linked, or within size limit');
    const content = fs.readFileSync(fd);
    const after = fs.fstatSync(fd);
    if (content.length !== before.size || before.size !== after.size || before.mtimeMs !== after.mtimeMs) deny('file changed during read');
    return content;
  } finally { fs.closeSync(fd); }
}
function readJson(filename, limit) {
  let data;
  try { data = JSON.parse(readRegular(filename, limit).toString('utf8')); }
  catch (error) { deny('invalid or inaccessible JSON: ' + error.message); }
  return data;
}
function strictProject(directory) {
  checkAncestors(directory);
  if (!fs.statSync(directory).isDirectory()) deny('Room B project is not a directory');
  const entries = fs.readdirSync(directory);
  if (entries.length !== REQUIRED.length ||
      entries.some(name => !REQUIRED.includes(name))) deny('Room B project contains unexpected files or directories');
  const buffers = {};
  for (const name of REQUIRED) {
    buffers[name] = readRegular(path.join(directory, name), name === 'implementation.mjs' ? MAX_IMPL : 32 * 1024);
  }
  return buffers;
}
function prepareRoomB({ approvedFile, publicKeyFile, policyFile, projectDir, now = new Date() }) {
  const approval = readJson(approvedFile, 24 * 1024);
  const key = readRegular(publicKeyFile, 8192);
  const policy = readJson(policyFile, 4096);
  const verified = checkPolicy(policy, verifyApproved(approval, key), now);
  const reference = scaffoldFiles(approval, key);
  const supplied = strictProject(projectDir);
  for (const name of REQUIRED) {
    if (name === 'implementation.mjs') continue;
    if (!supplied[name].equals(Buffer.from(reference[name], 'utf8'))) deny('trusted scaffold artifact was changed: ' + name);
  }
  // Never stage approved.json, Room A receipts, private keys, the source tree,
  // or a project directory containing arbitrary files.
  return {
    verified,
    vectorCount: verified.spec.vectors.length,
    files: {
      'contract.json': reference['contract.json'],
      'compat.test.mjs': reference['compat.test.mjs'],
      'implementation.mjs': supplied['implementation.mjs'],
    },
  };
}
function assertImage(image) {
  if (typeof image !== 'string' || !IMAGE.test(image)) deny('container image must use an immutable sha256 digest');
  return image;
}
function dockerArgs(stageDir, image, containerName) {
  assertImage(image);
  if (!/^\/[A-Za-z0-9_./-]+$/.test(stageDir)) deny('unsafe temporary bind mount path');
  if (!/^rudevolution-b-[a-f0-9]{24}$/.test(containerName)) deny('invalid container name');
  return [
    '--host=unix:///var/run/docker.sock', 'run', '--rm', '--pull=never',
    '--name=' + containerName, '--network=none', '--read-only',
    '--cap-drop=ALL', '--security-opt=no-new-privileges=true',
    '--pids-limit=64', '--memory=256m', '--memory-swap=256m', '--cpus=1',
    '--user=65534:65534', '--ulimit=nofile=64:64',
    '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777',
    '--mount=type=bind,source=' + stageDir + ',target=/work,readonly',
    '--workdir=/work', '--env=HOME=/tmp', '--env=TMPDIR=/tmp',
    '--entrypoint=node', image, '--test', 'compat.test.mjs',
  ];
}
function sandboxTest(options, spawn = spawnSync) {
  if (process.platform !== 'linux') deny('isolated runner requires Linux');
  const { approvedFile, publicKeyFile, policyFile, projectDir, image, now = new Date() } = options;
  assertImage(image);
  const prepared = prepareRoomB({ approvedFile, publicKeyFile, policyFile, projectDir, now });
  const stageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'rudevolution-room-b-'));
  const containerName = 'rudevolution-b-' + randomBytes(12).toString('hex');
  let started = false;
  let ended = false;
  const start = Date.now();
  try {
    for (const [name, data] of Object.entries(prepared.files)) {
      fs.writeFileSync(path.join(stageDir, name), data, { flag: 'wx', mode: 0o444 });
    }
    fs.chmodSync(stageDir, 0o555);
    const result = spawn('docker', dockerArgs(stageDir, image, containerName), {
      encoding: 'utf8', timeout: 60000, killSignal: 'SIGKILL',
      maxBuffer: 128 * 1024, windowsHide: true,
    });
    started = true;
    const timedOut = result.error && result.error.code === 'ETIMEDOUT';
    const errored = result.error && !timedOut;
    const passed = result.status === 0 && !result.signal && !result.error;
    const report = {
      format: REPORT_FORMAT,
      approvalSha256: prepared.verified.approvalSha256,
      specSha256: sha256(require('./index').canonicalStringify(prepared.verified.spec)),
      publicKeyFingerprint: prepared.verified.publicKeyFingerprint,
      implementationSha256: sha256(prepared.files['implementation.mjs']),
      image, vectorCount: prepared.vectorCount,
      status: passed ? 'passed' : timedOut ? 'timeout' : errored ? 'runner_error' : 'failed',
      exitCode: Number.isInteger(result.status) ? result.status : null,
      durationMs: Math.max(0, Date.now() - start),
      stdoutSha256: sha256(result.stdout || ''),
      stderrSha256: sha256(result.stderr || ''),
    };
    return report;
  } finally {
    if (started) {
      const cleanup = spawn('docker', [
        '--host=unix:///var/run/docker.sock', 'rm', '--force', containerName,
      ], { encoding: 'utf8', timeout: 5000, maxBuffer: 4096, windowsHide: true });
      // With --rm a finished container is normally already gone. An
      // interrupted container must be terminated and cleanup verified.
      ended = cleanup.status === 0 ||
        (cleanup.status === 1 && /No such container/i.test(cleanup.stderr || ''));
    }
    fs.chmodSync(stageDir, 0o700);
    fs.rmSync(stageDir, { recursive: true, force: true });
    if (started && !ended) deny('Docker cleanup could not be verified');
  }
}

module.exports = {
  POLICY_FORMAT, REPORT_FORMAT, checkPolicy, readRegular, prepareRoomB,
  dockerArgs, sandboxTest,
};
