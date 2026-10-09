'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { generateKeyPairSync } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { approveSpec, scaffoldFiles } = require('../src/clean-room');
const { POLICY_FORMAT, REPORT_FORMAT } = require('../src/clean-room/isolated-runner');
const spec = require('../../examples/clean-room/calculator.spec.json');

const IMAGE = process.env.RUDEVOLUTION_TEST_IMAGE;
const CLI = path.resolve(__dirname, '../src/clean-room/cli.js');

function cli(args) {
  return spawnSync(process.execPath, [CLI, ...args], {
    encoding: 'utf8', timeout: 90000, maxBuffer: 8192,
    env: { PATH: process.env.PATH, HOME: process.env.HOME },
  });
}

test('real Docker Room B denies Room A filesystem, network and writes while testing independent code', {
  skip: !IMAGE ? 'Set RUDEVOLUTION_TEST_IMAGE to an already-pulled image@sha256 digest' : false,
  timeout: 120000,
}, () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rudevolution-container-test-'));
  try {
    const a = path.join(root, 'room-a');
    const b = path.join(root, 'room-b');
    fs.mkdirSync(a, { mode: 0o700 });
    fs.mkdirSync(b, { mode: 0o700 });
    const secretFile = path.join(a, 'secret-implementation.js');
    fs.writeFileSync(secretFile, 'const VERY_PRIVATE_REFERENCE = "NEVER_CROSS_ROOM_BOUNDARY_383";\n');

    const keys = generateKeyPairSync('ed25519');
    const { artifact, receipt } = approveSpec(spec, {
      reviewer: 'independent.reviewer', privateKey: keys.privateKey, now: new Date(),
    });
    const approvedFile = path.join(b, 'approved.json');
    const publicKeyFile = path.join(b, 'pinned-public.pem');
    const policyFile = path.join(b, 'room-b-policy.json');
    const projectDir = path.join(b, 'implementation');
    const reportFile = path.join(b, 'test-report.json');
    fs.writeFileSync(approvedFile, JSON.stringify(artifact));
    fs.writeFileSync(publicKeyFile, keys.publicKey.export({ format: 'pem', type: 'spki' }));
    const expiresAt = new Date(Date.now() + 4 * 3600000).toISOString();
    const policy = {
      format: POLICY_FORMAT,
      target: spec.target,
      reviewer: 'independent.reviewer',
      publicKeyFingerprint: receipt.publicKeyFingerprint,
      expiresAt,
      maxApprovalAgeHours: 24,
    };
    fs.writeFileSync(policyFile, JSON.stringify(policy));
    fs.mkdirSync(projectDir, { mode: 0o700 });
    for (const [name, content] of Object.entries(scaffoldFiles(artifact, keys.publicKey))) {
      fs.writeFileSync(path.join(projectDir, name), content);
    }

    // Room B is built from the signed behavioral contract. This test code is
    // authored independently, and deliberately tries to access Room A, write
    // to its readonly mount and find a non-loopback interface.
    const independent = [
      "import { existsSync, writeFileSync } from 'node:fs';",
      "import { networkInterfaces } from 'node:os';",
      'const reference = ' + JSON.stringify(secretFile) + ';',
      'function requireIsolation() {',
      "  if (process.getuid() !== 65534) throw new Error('worker is privileged');",
      "  if (existsSync(reference)) throw new Error('Room A source is mounted');",
      "  if (Object.keys(networkInterfaces()).some(x => x !== 'lo')) throw new Error('network is enabled');",
      "  try { writeFileSync('/work/forbidden.txt', 'x'); throw new Error('workspace is writable'); }",
      "  catch (error) { if (!['EACCES', 'EROFS'].includes(error.code)) throw error; }",
      '}',
      'export function add(a, b) { requireIsolation(); return a + b; }',
      "export function greet(name) { requireIsolation(); return 'Hello ' + name; }",
      '',
    ].join('\n');
    fs.writeFileSync(path.join(projectDir, 'implementation.mjs'), independent);
    const result = cli(['sandbox-test', approvedFile, publicKeyFile, policyFile, projectDir, IMAGE, reportFile]);
    assert.equal(result.status, 0, 'Docker smoke test failed: ' + result.stdout + result.stderr);
    const report = JSON.parse(fs.readFileSync(reportFile, 'utf8'));
    assert.equal(report.format, REPORT_FORMAT);
    assert.equal(report.status, 'passed');
    assert.equal(report.vectorCount, 3);
    assert.equal(report.exitCode, 0);
    assert.equal(report.publicKeyFingerprint, receipt.publicKeyFingerprint);
    assert(!fs.readFileSync(reportFile, 'utf8').includes('NEVER_CROSS_ROOM_BOUNDARY_383'));
    assert(!fs.readdirSync(b).includes('secret-implementation.js'));

    // Invalid/unsigned edits must be rejected before creating a report or
    // calling Docker. Each run uses a fresh report file.
    fs.writeFileSync(path.join(projectDir, 'source-map.json'), '{"secret":true}');
    const bad = cli(['sandbox-test', approvedFile, publicKeyFile, policyFile, projectDir, IMAGE, path.join(b, 'should-not-exist.json')]);
    assert.notEqual(bad.status, 0);
    assert.equal(fs.existsSync(path.join(b, 'should-not-exist.json')), false);
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});
