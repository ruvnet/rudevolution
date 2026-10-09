'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
const { FORMAT, REPORT, validateReport, attestReport, verifyAttestation } = require('../src/clean-room/attestation');

const pair = () => generateKeyPairSync('ed25519');
const NOW = new Date('2026-10-08T22:00:00.000Z');
const digest = c => c.repeat(64);
const sample = () => ({
  format: REPORT,
  approvalSha256: digest('a'), specSha256: digest('b'), policySha256: digest('c'),
  publicKeyFingerprint: digest('d'), implementationSha256: digest('e'),
  harnessSha256: digest('f'), image: 'node@sha256:' + digest('9'),
  vectorCount: 3, executedVectors: 3, passedVectors: 3,
  status: 'passed', exitCode: 0, durationMs: 812,
  stdoutSha256: digest('1'), stderrSha256: digest('2'),
});
const clone = o => JSON.parse(JSON.stringify(o));

test('independent worker key signs complete evaluation report and verifies offline', () => {
  const { privateKey, publicKey } = pair();
  const report = sample();
  const signed = attestReport(report, { privateKey, workerId: 'worker-a', now: NOW });
  assert.equal(signed.format, FORMAT);
  assert.equal(signed.report.status, 'passed');
  const checked = verifyAttestation(signed, publicKey, {
    workerId: 'worker-a', approvalSha256: report.approvalSha256,
    now: new Date('2026-10-08T22:01:00.000Z'),
  });
  assert.equal(checked.reportSha256, signed.attester.reportSha256);
  assert.equal(checked.report.approvalSha256, report.approvalSha256);
});

test('report signature rejects tampering and untrusted worker identity', () => {
  const { privateKey, publicKey } = pair();
  const attested = attestReport(sample(), { privateKey, workerId: 'worker-a', now: NOW });
  const cases = [
    signed => { signed.report.status = 'failed'; },
    signed => { signed.report.passedVectors = 2; },
    signed => { signed.report.stdoutSha256 = digest('8'); },
    signed => { signed.report.harnessSha256 = digest('8'); },
    signed => { signed.attester.workerId = 'worker-b'; },
    signed => { signed.attester.signedAt = '2026-10-07T22:00:00.000Z'; },
    signed => { signed.attester.signature = 'A'.repeat(86) + '=='; },
    signed => { signed.debugSource = 'secret'; },
    signed => { signed.report.referenceSource = 'secret'; },
  ];
  for (const change of cases) {
    const copy = clone(attested);
    change(copy);
    assert.throws(() => verifyAttestation(copy, publicKey, { now: NOW }), /rejected/);
  }
  assert.throws(() => verifyAttestation(attested, pair().publicKey, { now: NOW }), /untrusted/);
  assert.throws(() => verifyAttestation(attested, publicKey, { workerId: 'wrong', now: NOW }), /untrusted/);
  assert.throws(() => verifyAttestation(attested, publicKey, { approvalSha256: digest('9'), now: NOW }), /unexpected approval/);
});

test('reports cannot lie about executed vectors or use unsigned extra fields', () => {
  const bad = [
    r => { r.status = 'passed'; r.executedVectors = 0; },
    r => { r.status = 'passed'; r.passedVectors = 2; },
    r => { r.vectorCount = 25; },
    r => { r.vectorCount = -1; },
    r => { r.passedVectors = 7; },
    r => { r.exitCode = 999; },
    r => { r.status = 'opaque'; },
    r => { r.image = 'node:latest'; },
    r => { r.harnessSha256 = 'wrong'; },
    r => { r.durationMs = -1; },
    r => { r.source = 'impl'; },
  ];
  for (const mutate of bad) {
    const report = sample();
    mutate(report);
    assert.throws(() => validateReport(report), /rejected/);
  }
});

test('failed evaluations can be attested but cannot be misreported as passing', () => {
  const pair0 = pair();
  const failed = { ...sample(), status: 'failed', exitCode: 1, executedVectors: 0, passedVectors: 0 };
  const signed = attestReport(failed, { privateKey: pair0.privateKey, workerId: 'worker-failure', now: NOW });
  const verified = verifyAttestation(signed, pair0.publicKey, { now: NOW });
  assert.equal(verified.report.status, 'failed');
  assert.equal(verified.report.passedVectors, 0);
});

test('attestation age, clocks and key types are validated', () => {
  const { privateKey, publicKey } = pair();
  const signed = attestReport(sample(), { privateKey, workerId: 'worker-a', now: NOW });
  assert.throws(() => verifyAttestation(signed, publicKey, { now: new Date('2026-11-01T22:00:00.000Z') }), /expired/);
  assert.throws(() => verifyAttestation(signed, publicKey, { now: new Date('2026-10-08T21:00:00.000Z') }), /future/);
  assert.throws(() => attestReport(sample(), { privateKey: publicKey, workerId: 'worker-a', now: NOW }), /private key required/);
  assert.throws(() => attestReport(sample(), { privateKey, workerId: 'INVALID!', now: NOW }), /worker ID/);
  assert.throws(() => verifyAttestation(signed, privateKey, { now: NOW }), /public key required/);
});
