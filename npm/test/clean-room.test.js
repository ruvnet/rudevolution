'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { generateKeyPairSync } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const {
  validateSpec, approveSpec, verifyApproved, scaffoldFiles, canonicalStringify,
} = require('../src/clean-room');

const fixture = require('../../examples/clean-room/calculator.spec.json');
const CLI = path.resolve(__dirname, '../src/clean-room/cli.js');
const clone = object => JSON.parse(JSON.stringify(object));
const spec = () => clone(fixture);
const keys = () => generateKeyPairSync('ed25519');
const signSpec = (s = spec(), pair = keys()) => ({ ...approveSpec(s, { reviewer: 'reviewer.one', privateKey: pair.privateKey, now: new Date('2026-10-08T20:00:00.000Z') }), pair });
const temporary = () => fs.mkdtempSync(path.join(os.tmpdir(), 'rudevolution-cleanroom-test-'));
const cli = args => spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8', timeout: 15000, env: { PATH: process.env.PATH, HOME: process.env.HOME } });

test('valid constrained contract and deterministic canonicalization', () => {
  const valid = spec();
  assert.equal(validateSpec(valid), valid);
  const reverse = { vectors: valid.vectors, operations: valid.operations, target: valid.target, format: valid.format };
  assert.equal(canonicalStringify(valid), canonicalStringify(reverse));
});

test('signed review has an independently verifiable Ed25519 signature and receipt', () => {
  const { artifact, receipt, pair } = signSpec();
  const verified = verifyApproved(artifact, pair.publicKey);
  assert.equal(verified.spec.target, 'calculator-compatibility');
  assert.equal(verified.approvalSha256, receipt.approvalSha256);
  assert.equal(verified.publicKeyFingerprint, receipt.publicKeyFingerprint);
  assert.equal(receipt.reviewedSource, undefined);
});

test('signature rejects changed contract, changed reviewer, changed approval time and wrong key', () => {
  const { artifact, pair } = signSpec();
  const mutations = [
    a => { a.spec.vectors[0].expected = 99; },
    a => { a.review.reviewer = 'somebody.else'; },
    a => { a.review.approvedAt = '2026-10-09T20:00:00.000Z'; },
    a => { a.review.signature = 'A'.repeat(86) + '=='; },
  ];
  for (const change of mutations) {
    const copy = clone(artifact);
    change(copy);
    assert.throws(() => verifyApproved(copy, pair.publicKey), /rejected/);
  }
  assert.throws(() => verifyApproved(artifact, keys().publicKey), /signature invalid/);
});

test('additional source and code-bearing fields are rejected at each schema boundary', () => {
  const invalid = [
    s => { s.source = 'do_not_transfer'; },
    s => { s.operations[0].body = 'return a+b;'; },
    s => { s.operations[0].inputs[0].sourceLine = 'func();'; },
    s => { s.vectors[0].snippet = 'return 5;'; },
    s => { s.vectors[0].arguments[0] = 'function f(){}'; },
    s => { s.vectors[2].arguments[0] = 'mystery\nline'; },
    s => { s.vectors[2].arguments[0] = 'a'.repeat(65); },
    s => { s.vectors[2].arguments[0] = 'secret\u200bmarker'; },
    s => { s.operations[0].name = 'class'; },
    s => { s.operations[0].inputs[0].name = 'default'; },
  ];
  for (const mutate of invalid) { const s = spec(); mutate(s); assert.throws(() => validateSpec(s), /rejected/); }
});

test('type, arity, uniqueness, case limits, and unsupported format fail closed', () => {
  const invalid = [
    s => { s.format = 'legacy'; },
    s => { s.operations[1].name = 'add'; },
    s => { s.operations[0].inputs[1].name = 'a'; },
    s => { s.operations[0].returns = 'object'; },
    s => { s.operations[0].errors = ['invalid_argument', 'invalid_argument']; },
    s => { s.vectors[0].arguments = [2]; },
    s => { s.vectors[0].expected = '5'; },
    s => { s.vectors[0].expected = Infinity; },
    s => { s.vectors[0].operation = 'system'; },
    s => { s.vectors = Array.from({length: 25}, () => s.vectors[0]); },
    s => { s.vectors = []; },
    s => { s.vectors = s.vectors.filter(v => v.operation !== 'greet'); },
    s => { s.operations = []; },
    s => { s.target = '../escape'; },
  ];
  for (const mutate of invalid) { const s = spec(); mutate(s); assert.throws(() => validateSpec(s), /rejected/); }
});

test('malformed artifact is not executable or silently accepted', () => {
  const { artifact, pair } = signSpec();
  const copies = [
    { ...clone(artifact), debugSource: 'export default secret' },
    { ...clone(artifact), format: 'none' },
    { ...clone(artifact), review: { ...artifact.review, forbidden: 'yes' } },
    { ...clone(artifact), review: { ...artifact.review, signature: 'x' } },
    { ...clone(artifact), review: { ...artifact.review, approvedAt: 'not-a-date' } },
  ];
  for (const copy of copies) assert.throws(() => verifyApproved(copy, pair.publicKey), /rejected/);
});

test('scaffold contains only approved contract, review receipt and independent test vectors', () => {
  const { artifact, pair } = signSpec();
  const files = scaffoldFiles(artifact, pair.publicKey);
  assert.deepEqual(Object.keys(files).sort(), ['APPROVAL.txt','compat.test.mjs','contract.json','implementation.mjs']);
  assert.match(files['implementation.mjs'], /export function add\(a, b\)/);
  assert.match(files['implementation.mjs'], /UNIMPLEMENTED/);
  assert.doesNotMatch(Object.values(files).join('\n'), /proprietary.source.file/);
});

test('CLI enforces explicit reviewer approval, signing key isolation and distinct output files', () => {
  const root = temporary();
  try {
    const roomA = path.join(root, 'room-a'); const roomB = path.join(root, 'room-b');
    fs.mkdirSync(roomA); fs.mkdirSync(roomB);
    const privateMarker = 'PROPRIETARY_ORIGINAL_CODE_DO_NOT_COPY_123456789';
    fs.writeFileSync(path.join(roomA, 'original.js'), `const hidden = '${privateMarker}';\n`);
    const { privateKey, publicKey } = keys();
    const priv = path.join(roomA, 'private.pem'); const pub = path.join(roomB, 'public.pem');
    fs.writeFileSync(priv, privateKey.export({ format: 'pem', type: 'pkcs8' }), {mode: 0o600});
    fs.writeFileSync(pub, publicKey.export({ format: 'pem', type: 'spki' }));
    const input = path.join(roomA, 'proposal.json'); fs.writeFileSync(input, JSON.stringify(spec()));
    const approval = path.join(roomA, 'approved-export.json'); const receipt = path.join(roomA, 'receipt.json');
    const transferred = path.join(roomB, 'approved.json');
    assert.equal(cli(['validate', input]).status, 0);
    assert.equal(cli(['approve', input, priv, 'reviewer.one', approval, receipt, '--not-reviewed']).status, 1);
    assert.equal(fs.existsSync(approval), false);
    assert.equal(cli(['approve', input, priv, 'reviewer.one', approval, receipt, '--ack-reviewed']).status, 0);
    assert.equal(cli(['approve', input, priv, 'reviewer.one', approval, receipt, '--ack-reviewed']).status, 1);
    // Model a manual, reviewed transfer: Room A never writes directly to Room B.
    fs.copyFileSync(approval, transferred, fs.constants.COPYFILE_EXCL);
    assert.equal(cli(['verify', transferred, pub]).status, 0);
    const generated = path.join(roomB, 'fresh');
    assert.equal(cli(['scaffold', transferred, pub, generated]).status, 0);
    assert.equal(cli(['scaffold', transferred, pub, generated]).status, 1);
    assert.equal(fs.existsSync(path.join(roomB, 'private.pem')), false);
    assert.equal(fs.existsSync(path.join(roomB, 'original.js')), false);
    for (const file of fs.readdirSync(generated)) {
      assert.doesNotMatch(fs.readFileSync(path.join(generated, file), 'utf8'), new RegExp(privateMarker));
    }
    assert.doesNotMatch(fs.readFileSync(transferred, 'utf8'), new RegExp(privateMarker));
    // Contract tests deliberately fail until the independent author writes an implementation.
    const before = spawnSync(process.execPath, ['compat.test.mjs'], { cwd: generated, encoding: 'utf8', timeout: 15000 });
    assert.notEqual(before.status, 0, before.stdout + before.stderr);
    fs.writeFileSync(path.join(generated, 'implementation.mjs'), "export function add(a,b) {return a+b;}\nexport function greet(name) {return 'Hello '+name;}\n");
    const after = spawnSync(process.execPath, ['compat.test.mjs'], { cwd: generated, encoding: 'utf8', timeout: 15000 });
    assert.equal(after.status, 0, after.stderr + after.stdout);
    // Even after scaffold approval, test vectors remain bound to the signed contract.
    const localContract = path.join(generated, 'contract.json');
    const originalContract = fs.readFileSync(localContract, 'utf8');
    const changedContract = JSON.parse(originalContract);
    changedContract.vectors[0].expected = 100;
    fs.writeFileSync(localContract, JSON.stringify(changedContract));
    fs.writeFileSync(path.join(generated, 'implementation.mjs'), "import { writeFileSync } from 'node:fs';\nwriteFileSync('imported.marker', 'executed');\nexport function add(a,b){return a+b;}\nexport function greet(name){return 'Hello '+name;}\n");
    const modifiedRun = spawnSync(process.execPath, ['compat.test.mjs'], { cwd: generated, encoding: 'utf8', timeout: 15000 });
    assert.notEqual(modifiedRun.status, 0);
    assert.match(modifiedRun.stderr + modifiedRun.stdout, /integrity mismatch/);
    assert.equal(fs.existsSync(path.join(generated, 'imported.marker')), false, 'untrusted implementation must not be imported before contract integrity check');
    fs.writeFileSync(localContract, originalContract);
    // Tampering with signed artifact must not create a Room B implementation directory.
    const tampered = path.join(roomB, 'tampered.json');
    const altered = JSON.parse(fs.readFileSync(transferred, 'utf8')); altered.spec.vectors[0].expected = 42;
    fs.writeFileSync(tampered, JSON.stringify(altered));
    assert.equal(cli(['scaffold', tampered, pub, path.join(roomB, 'blocked')]).status, 1);
    assert.equal(fs.existsSync(path.join(roomB, 'blocked')), false);
  } finally { fs.rmSync(root, {recursive:true, force:true}); }
});

test('CLI rejects symlinked inputs and symlinked output parent', () => {
  const root = temporary();
  try {
    const real = path.join(root, 'spec.json'); fs.writeFileSync(real, JSON.stringify(spec()));
    const link = path.join(root, 'linked.json'); fs.symlinkSync(real, link);
    assert.equal(cli(['validate', link]).status, 1);
    const dir = path.join(root, 'real'); fs.mkdirSync(dir);
    const fake = path.join(root, 'fake'); fs.symlinkSync(dir, fake, 'dir');
    const {artifact, pair} = signSpec();
    const p = path.join(root, 'artifact.json'); const pub = path.join(root, 'pub.pem');
    fs.writeFileSync(p, JSON.stringify(artifact)); fs.writeFileSync(pub, pair.publicKey.export({format:'pem',type:'spki'}));
    assert.equal(cli(['scaffold', p, pub, path.join(fake, 'out')]).status, 1);
  } finally { fs.rmSync(root, {recursive:true, force:true}); }
});
