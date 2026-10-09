'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { generateKeyPairSync } = require('node:crypto');
const { approveSpec, scaffoldFiles } = require('../src/clean-room');
const {
  POLICY_FORMAT, checkPolicy, readRegular, prepareRoomB, dockerArgs, parseTapSummary, sandboxTest,
} = require('../src/clean-room/isolated-runner');
const fixture = require('../../examples/clean-room/calculator.spec.json');

const NOW = new Date('2026-10-09T00:00:00.000Z');
const IMAGE = 'node@sha256:' + 'e'.repeat(64);
const createTemp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'rudevolution-room-b-tests-'));

function setupRoom() {
  const root = createTemp();
  const roomA = path.join(root, 'room-a');
  const roomB = path.join(root, 'room-b');
  fs.mkdirSync(roomA);
  fs.mkdirSync(roomB);
  const marker = 'PROPRIETARY_ORIGINAL_DO_NOT_LEAK_CLEANROOM_47328';
  fs.writeFileSync(path.join(roomA, 'reference-source.js'), 'const internalSecret = "' + marker + '";\n');
  const keys = generateKeyPairSync('ed25519');
  const { artifact, receipt } = approveSpec(fixture, {
    reviewer: 'reviewer.one', privateKey: keys.privateKey,
    now: new Date('2026-10-08T20:00:00.000Z'),
  });
  const approvedFile = path.join(roomB, 'approved.json');
  const publicKeyFile = path.join(roomB, 'trusted-public.pem');
  const policyFile = path.join(roomB, 'trusted-policy.json');
  const projectDir = path.join(roomB, 'independent-implementation');
  fs.writeFileSync(approvedFile, JSON.stringify(artifact));
  fs.writeFileSync(publicKeyFile, keys.publicKey.export({ format: 'pem', type: 'spki' }));
  const policy = {
    format: POLICY_FORMAT,
    reviewer: 'reviewer.one',
    target: 'calculator-compatibility',
    publicKeyFingerprint: receipt.publicKeyFingerprint,
    runtimeImage: IMAGE,
    expiresAt: '2026-12-31T00:00:00.000Z',
    maxApprovalAgeHours: 168,
  };
  fs.writeFileSync(policyFile, JSON.stringify(policy));
  fs.mkdirSync(projectDir);
  const scaffold = scaffoldFiles(artifact, keys.publicKey);
  for (const [name, source] of Object.entries(scaffold)) {
    fs.writeFileSync(path.join(projectDir, name), source);
  }
  const options = { approvedFile, publicKeyFile, policyFile, projectDir, image: IMAGE, now: NOW };
  return { root, roomA, roomB, marker, artifact, keys, policy, receipt, options, projectDir };
}
function scoped(fn) {
  const env = setupRoom();
  try { return fn(env); }
  finally { fs.rmSync(env.root, { recursive: true, force: true }); }
}

test('policy gates signer, reviewer, target, approval age and trust expiration', () => scoped(env => {
  const { artifact, keys, policy } = env;
  const { verifyApproved } = require('../src/clean-room');
  const verified = verifyApproved(artifact, keys.publicKey);
  assert.equal(checkPolicy(policy, verified, NOW), verified);
  const change = (key, val) => ({ ...policy, [key]: val });
  for (const candidate of [
    change('publicKeyFingerprint', 'a'.repeat(64)),
    change('runtimeImage', 'node@sha256:' + 'a'.repeat(64)),
    change('reviewer', 'other.reviewer'),
    change('target', 'other-target'),
    change('expiresAt', '2026-10-08T21:00:00.000Z'),
    change('maxApprovalAgeHours', 1),
    change('maxApprovalAgeHours', 0),
    change('maxApprovalAgeHours', 721),
    change('format', 'unknown'),
    { ...policy, source: 'hidden implementation' },
  ]) assert.throws(() => checkPolicy(candidate, verified, NOW, IMAGE), /rejected/);
  assert.throws(() => checkPolicy(policy, verified, new Date('2026-10-08T19:00:00.000Z')), /future/);
}));

test('Room A marker, receipts and keys cannot enter allowlisted stage', () => scoped(env => {
  const prepared = prepareRoomB(env.options);
  assert.deepEqual(Object.keys(prepared.files).sort(), ['compat.test.mjs', 'contract.json', 'implementation.mjs']);
  assert.equal(prepared.vectorCount, 3);
  const body = Object.values(prepared.files).join('\n');
  assert.doesNotMatch(body, new RegExp(env.marker));
  assert.doesNotMatch(body, /PRIVATE KEY/);
  assert.doesNotMatch(body, /receipt/i);
  assert.equal(fs.existsSync(path.join(env.roomB, 'reference-source.js')), false);
}));

test('fail closed on changed tests, changed contract, extra project files or symlink', () => scoped(env => {
  const dir = env.projectDir;
  for (const name of ['contract.json', 'compat.test.mjs', 'APPROVAL.txt']) {
    const filename = path.join(dir, name);
    const original = fs.readFileSync(filename);
    fs.appendFileSync(filename, '\n// modified by a malicious worker\n');
    assert.throws(() => prepareRoomB(env.options), /rejected/);
    fs.writeFileSync(filename, original);
  }
  const unexpected = path.join(dir, 'original.js');
  fs.writeFileSync(unexpected, 'DO_NOT_TRANSFER_SOURCE');
  assert.throws(() => prepareRoomB(env.options), /unexpected files/);
  fs.unlinkSync(unexpected);
  const implementation = path.join(dir, 'implementation.mjs');
  const original = fs.readFileSync(implementation);
  fs.unlinkSync(implementation);
  fs.symlinkSync(path.join(env.roomA, 'reference-source.js'), implementation);
  assert.throws(() => prepareRoomB(env.options), /symlink/);
  fs.unlinkSync(implementation);
  fs.writeFileSync(implementation, original);
}));

test('Docker args allow only one read-only stage mount and deny network, privilege and writable root', () => {
  const args = dockerArgs('/tmp/rudevolution-room-b-example', IMAGE, 'rudevolution-b-' + 'a'.repeat(24));
  assert.equal(args[0], '--host=unix:///var/run/docker.sock');
  assert(args.includes('--pull=never'));
  assert(args.includes('--network=none'));
  assert(args.includes('--read-only'));
  assert(args.includes('--cap-drop=ALL'));
  assert(args.includes('--security-opt=no-new-privileges=true'));
  assert(args.includes('--user=65534:65534'));
  assert(args.includes('--memory=256m'));
  assert(args.includes('--pids-limit=64'));
  assert(args.includes('--entrypoint=node'));
  const mounts = args.filter(item => item.startsWith('--mount='));
  assert.equal(mounts.length, 1);
  assert.match(mounts[0], /^--mount=type=bind,source=\/tmp\/rudevolution-room-b-example,target=\/work,readonly$/);
  assert.equal(args.at(-3), IMAGE);
  assert.throws(() => dockerArgs('/tmp/with,malicious', IMAGE, 'rudevolution-b-' + 'a'.repeat(24)), /rejected/);
  assert.throws(() => dockerArgs('/tmp/safe', 'node:22-alpine', 'rudevolution-b-' + 'a'.repeat(24)), /immutable sha256/);
  assert.throws(() => dockerArgs('/tmp/safe', IMAGE, 'contaminated'), /rejected/);
});

test('isolated runner mounts only a verified minimal staging copy and produces hashed evidence', () => scoped(env => {
  const invoked = [];
  let tempDir;
  const fakeDocker = (program, args) => {
    assert.equal(program, 'docker');
    invoked.push(args);
    if (args.includes('run')) {
      const mount = args.find(arg => arg.startsWith('--mount='));
      tempDir = mount.split('source=')[1].split(',target=')[0];
      assert.deepEqual(fs.readdirSync(tempDir).sort(), ['compat.test.mjs', 'contract.json', 'implementation.mjs']);
      assert.equal(fs.statSync(tempDir).mode & 0o222, 0);
      for (const name of fs.readdirSync(tempDir)) {
        assert.equal(fs.statSync(path.join(tempDir, name)).mode & 0o222, 0);
        const text = fs.readFileSync(path.join(tempDir, name), 'utf8');
        assert.doesNotMatch(text, new RegExp(env.marker));
      }
      return { status: 0, stdout: 'TAP version 13\n1..3\n# tests 3\n# suites 0\n# pass 3\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n', stderr: '', signal: null };
    }
    return { status: 1, stderr: 'No such container', stdout: '' };
  };
  const report = sandboxTest(env.options, fakeDocker);
  assert.equal(report.status, 'passed');
  assert.equal(report.vectorCount, 3);
  assert.equal(report.exitCode, 0);
  assert.match(report.implementationSha256, /^[a-f0-9]{64}$/);
  assert.deepEqual(invoked.length, 2);
  assert.equal(fs.existsSync(tempDir), false);
}));

test('timeout kills container and failure to clean up fails closed', () => scoped(env => {
  let cleanupCount = 0;
  const fakeDocker = (program, args) => {
    if (args.includes('run')) return {
      status: null, signal: 'SIGKILL', stdout: '',
      stderr: '', error: Object.assign(new Error('timeout'), { code: 'ETIMEDOUT' }),
    };
    cleanupCount += 1;
    return { status: 0, stderr: '', stdout: '' };
  };
  const result = sandboxTest(env.options, fakeDocker);
  assert.equal(result.status, 'timeout');
  assert.equal(cleanupCount, 1);
  assert.throws(() => sandboxTest(env.options, (program, args) =>
    args.includes('run') ? { status: 0, stdout: '', stderr: '' } : { status: 2, stderr: 'daemon offline' }
  ), /cleanup could not be verified/);
}));

test('wrong public key, stale approval and invalid image prevent runner invocation', () => scoped(env => {
  let called = false;
  const runner = () => { called = true; throw new Error('runner reached unexpectedly'); };
  const replacement = generateKeyPairSync('ed25519');
  fs.writeFileSync(env.options.publicKeyFile, replacement.publicKey.export({ format: 'pem', type: 'spki' }));
  assert.throws(() => sandboxTest(env.options, runner), /rejected/);
  assert.equal(called, false);
  fs.writeFileSync(env.options.publicKeyFile, env.keys.publicKey.export({ format: 'pem', type: 'spki' }));
  assert.throws(() => sandboxTest({ ...env.options, now: new Date('2026-11-08T00:00:00.000Z') }, runner), /too old/);
  assert.equal(called, false);
  assert.throws(() => sandboxTest({ ...env.options, image: 'node:latest' }, runner), /immutable sha256/);
  assert.throws(() => sandboxTest({ ...env.options, image: 'node@sha256:' + 'a'.repeat(64) }, runner), /image is not authorized/);
  assert.equal(called, false);
}));

test('no symlinked policy and no hardlinked implementation', () => scoped(env => {
  const link = path.join(env.roomB, 'linked-policy.json');
  fs.symlinkSync(env.options.policyFile, link);
  assert.throws(() => prepareRoomB({ ...env.options, policyFile: link }), /rejected/);
  const file = path.join(env.projectDir, 'implementation.mjs');
  const sibling = path.join(env.roomB, 'hardlink.mjs');
  fs.linkSync(file, sibling);
  assert.throws(() => readRegular(file, 1024 * 1024), /uniquely linked/);
}));

test('TAP parser refuses zero tests, incomplete counters, skipped tests and forged counts', () => {
  const valid = 'TAP version 13\n# tests 3\n# pass 3\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n';
  assert.deepEqual(parseTapSummary(valid, 3), { executedVectors: 3, passedVectors: 3 });
  const invalid = [
    '',
    '# tests 3\n# pass 3\n',
    'TAP version 13\n# tests 0\n# pass 0\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n',
    valid.replace('# pass 3', '# pass 2'),
    valid.replace('# skipped 0', '# skipped 1'),
    valid.replace('# fail 0', '# fail 1'),
    valid.replace('# todo 0', '# todo 1'),
    valid.replace('# cancelled 0', '# cancelled 1'),
    valid + '# tests 3\n',
  ];
  for (const str of invalid) assert.equal(parseTapSummary(str, 3), null);
});

test('even Docker exit 0 is not sufficient without verified vector accounting', () => scoped(env => {
  const fake = (program, args) => args.includes('run')
    ? { status: 0, signal: null, stderr: '', stdout: 'TAP version 13\n# tests 0\n# pass 0\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n' }
    : { status: 1, stderr: 'No such container', stdout: '' };
  const report = sandboxTest(env.options, fake);
  assert.equal(report.status, 'failed');
  assert.equal(report.vectorCount, 3);
  assert.equal(report.executedVectors, 0);
  assert.equal(report.passedVectors, 0);
}));
