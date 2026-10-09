'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { generateKeyPairSync } = require('node:crypto');
const { approveSpec, canonicalStringify, sha256 } = require('../src/clean-room');
const { POLICY_FORMAT } = require('../src/clean-room/isolated-runner');
const { verifyAttestation } = require('../src/clean-room/attestation');
const { signRegistry, verifyRegistry, findTrusted, fingerprint } = require('../src/clean-room/trust-registry');
const { reviewRelease, verifyRelease, checkDisclosure } = require('../src/clean-room/release');
const { loadIntake, createIntake, evaluateIntake } = require('../src/clean-room/pilot');
const { ZERO, readLedger, verifyLedgerText } = require('../src/clean-room/evidence-ledger');

const SPEC = require('../../examples/clean-room/calculator.spec.json');
const NOW = new Date('2026-10-09T12:00:00.000Z');
const IMAGE = 'node@sha256:' + 'a'.repeat(64);
const SECRET = 'RUVSECRETXYZABC';
const clone = x => JSON.parse(JSON.stringify(x));
const pemPublic = keys => keys.publicKey.export({ type: 'spki', format: 'pem' });
const pemPrivate = keys => keys.privateKey.export({ type: 'pkcs8', format: 'pem' });

function setup() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'rudevolution-e2e-unit-'));
  const roomA = path.join(root, 'room-a');
  const roomB = path.join(root, 'room-b');
  fs.mkdirSync(roomA, { mode: 0o700 });
  fs.mkdirSync(roomB, { mode: 0o700 });
  const rootKey = generateKeyPairSync('ed25519');
  const primary = generateKeyPairSync('ed25519');
  const secondary = generateKeyPairSync('ed25519');
  const worker = generateKeyPairSync('ed25519');
  const makeEntry = (id, role, keys) => ({
    id, role, publicKey: pemPublic(keys),
    validFrom: '2026-10-01T00:00:00.000Z',
    validUntil: '2026-10-14T00:00:00.000Z',
    revokedAt: null,
  });
  const document = {
    format: 'rudevolution.cleanroom.registry/v1',
    revision: 7,
    issuedAt: '2026-10-09T09:00:00.000Z',
    expiresAt: '2026-10-11T00:00:00.000Z',
    keys: [
      makeEntry('reviewer.one', 'primary', primary),
      makeEntry('reviewer.two', 'secondary', secondary),
      makeEntry('worker-one', 'worker', worker),
    ],
  };
  fs.writeFileSync(path.join(roomA, 'original.js'), 'const SUPPLIED_PROPRIETARY_MARKER = "' + SECRET + '";\n', { mode: 0o600 });
  const rootPublicKeyFile = path.join(roomB, 'root.pem');
  const registryFile = path.join(roomB, 'signed-registry.json');
  const releaseFile = path.join(roomB, 'approved-release.json');
  const policyFile = path.join(roomB, 'policy.json');
  const workerPrivateKeyFile = path.join(roomB, 'worker.pem');
  const signedRegistry = signRegistry(document, rootKey.privateKey);
  fs.writeFileSync(rootPublicKeyFile, pemPublic(rootKey));
  fs.writeFileSync(registryFile, JSON.stringify(signedRegistry));
  const { artifact } = approveSpec(clone(SPEC), {
    reviewer: 'reviewer.one', privateKey: primary.privateKey, now: new Date('2026-10-09T11:00:00.000Z'),
  });
  const release = reviewRelease(artifact, pemPublic(primary), {
    reviewer: 'reviewer.two', privateKey: secondary.privateKey,
    now: new Date('2026-10-09T11:05:00.000Z'),
    restrictedMarkers: [SECRET],
  });
  fs.writeFileSync(releaseFile, JSON.stringify(release));
  fs.writeFileSync(workerPrivateKeyFile, pemPrivate(worker), { mode: 0o600 });
  const policy = {
    format: POLICY_FORMAT,
    target: 'calculator-compatibility',
    reviewer: 'reviewer.one',
    publicKeyFingerprint: fingerprint(primary.publicKey),
    runtimeImage: IMAGE,
    expiresAt: '2026-10-11T00:00:00.000Z',
    maxApprovalAgeHours: 48,
  };
  fs.writeFileSync(policyFile, JSON.stringify(policy));
  return {
    root, roomA, roomB, keys: {rootKey,primary,secondary,worker},
    document, signedRegistry, artifact, release, registryFile, releaseFile,
    rootPublicKeyFile, workerPrivateKeyFile, policyFile,
    opts: {releaseFile, registryFile, rootPublicKeyFile, minimumRevision: 7, now: NOW},
  };
}
function scoped(fn) {
  const env = setup();
  try { return fn(env); }
  finally { fs.rmSync(env.root, { recursive: true, force: true }); }
}
function generateProject(env) {
  const projectDir = path.join(env.roomB, 'fresh-project');
  const output = createIntake({...env.opts, outputDir: projectDir});
  assert.equal(output.vectorCount, 3);
  fs.writeFileSync(path.join(projectDir, 'implementation.mjs'),
    "export function add(a,b) { return a+b; }\nexport function greet(name) { return 'Hello '+name; }\n");
  return projectDir;
}
function fakeDocker(marker, inspected) {
  return (executable, args) => {
    assert.equal(executable, 'docker');
    if (args.includes('run')) {
      const mount = args.find(x => x.startsWith('--mount=type=bind,'));
      const stage = mount.split('source=')[1].split(',target=')[0];
      const names = fs.readdirSync(stage).sort();
      assert.deepEqual(names, ['compat.test.mjs','contract.json','implementation.mjs']);
      for (const name of names) {
        const bytes = fs.readFileSync(path.join(stage,name),'utf8');
        assert.equal(bytes.includes(marker), false, 'Room A marker crossed the stage');
      }
      assert(args.includes('--network=none'));
      inspected.count++;
      return {
        status:0,signal:null,stderr:'',
        stdout:'TAP version 13\n1..3\n# tests 3\n# suites 0\n# pass 3\n# fail 0\n# cancelled 0\n# skipped 0\n# todo 0\n',
      };
    }
    return {status:1,stderr:'No such container',stdout:''};
  };
}

test('root-signed registry validates roles, expiry, revocation and pinned revision', () => scoped(env => {
  const trusted = verifyRegistry(env.signedRegistry, pemPublic(env.keys.rootKey),
    {minimumRevision:7,now:NOW});
  assert.equal(trusted.document.revision,7);
  assert.equal(findTrusted(trusted,'primary','reviewer.one',{now:NOW}).fingerprint,fingerprint(env.keys.primary.publicKey));
  assert.throws(() => verifyRegistry(env.signedRegistry,pemPublic(env.keys.rootKey),
    {minimumRevision:8,now:NOW}), /revision rolled back/);
  const tampered = clone(env.signedRegistry);
  tampered.registry.revision = 8;
  assert.throws(() => verifyRegistry(tampered,pemPublic(env.keys.rootKey),
    {minimumRevision:7,now:NOW}), /root registry signature/);
  assert.throws(() => verifyRegistry(env.signedRegistry,pemPublic(generateKeyPairSync('ed25519')),
    {minimumRevision:7,now:NOW}), /root registry signature/);
  const revoked = clone(env.document);
  revoked.revision = 8;
  revoked.keys[1].revokedAt = '2026-10-09T11:30:00.000Z';
  const state = verifyRegistry(signRegistry(revoked,env.keys.rootKey.privateKey),pemPublic(env.keys.rootKey),
    {minimumRevision:8,now:NOW});
  assert.throws(() => findTrusted(state,'secondary','reviewer.two',{now:NOW}), /revoked/);
  assert.throws(() => verifyRelease(env.release,state,{now:NOW}), /revoked/);
}));

test('two distinct signatures are required; prohibited source markers never cross release', () => scoped(env => {
  const trusted = verifyRegistry(env.signedRegistry,pemPublic(env.keys.rootKey),{minimumRevision:7,now:NOW});
  const checked = verifyRelease(env.release,trusted,{now:NOW});
  assert.equal(checked.primaryReviewer,'reviewer.one');
  assert.equal(checked.secondaryReviewer,'reviewer.two');
  assert.equal(checked.registryRevision,7);
  const mutation = clone(env.release);
  mutation.approved.spec.vectors[0].expected = 666;
  assert.throws(() => verifyRelease(mutation,trusted,{now:NOW}), /rejected/);
  const second = clone(env.release);
  second.secondReview.reason = 'security-testing';
  assert.throws(() => verifyRelease(second,trusted,{now:NOW}), /secondary reviewer signature/);
  const invalid = clone(SPEC);
  invalid.vectors[2].expected = SECRET;
  assert.throws(() => checkDisclosure(invalid,[SECRET]), /prohibited source marker/);
  invalid.vectors[2].expected = Buffer.from(SECRET).toString('base64');
  assert.throws(() => checkDisclosure(invalid,[SECRET]), /prohibited source marker/);
  invalid.vectors[2].expected = Buffer.from(SECRET).toString('hex');
  assert.throws(() => checkDisclosure(invalid,[SECRET]), /prohibited source marker|high-entropy/);
  assert.throws(() => reviewRelease(env.artifact,pemPublic(env.keys.primary),{
    reviewer:'reviewer.one',privateKey:env.keys.secondary.privateKey,now:NOW,
  }), /independent second reviewer/);
  assert.equal(JSON.stringify(env.release).includes(SECRET),false);
}));

test('Room B creates only a verified scaffold, rejects stale trust and never sees source', () => scoped(env => {
  const projectDir = path.join(env.roomB,'fresh-project');
  const output = createIntake({...env.opts,outputDir:projectDir});
  assert.equal(output.registryRevision,7);
  assert.deepEqual(fs.readdirSync(projectDir).sort(),['APPROVAL.txt','compat.test.mjs','contract.json','implementation.mjs']);
  for (const file of fs.readdirSync(projectDir)) {
    assert.equal(fs.readFileSync(path.join(projectDir,file),'utf8').includes(SECRET),false);
  }
  assert.equal(fs.existsSync(path.join(env.roomB,'original.js')),false);
  assert.throws(() => createIntake({...env.opts,outputDir:projectDir}),/destination already exists/);
  assert.throws(() => loadIntake({...env.opts,minimumRevision:8}),/revision rolled back/);
  const revoked = clone(env.document);
  revoked.revision = 8;
  revoked.keys[0].revokedAt = '2026-10-09T11:30:00.000Z';
  fs.writeFileSync(env.registryFile,JSON.stringify(signRegistry(revoked,env.keys.rootKey.privateKey)));
  assert.throws(() => createIntake({...env.opts,minimumRevision:8,outputDir:path.join(env.roomB,'blocked')}),/revoked/);
  assert.equal(fs.existsSync(path.join(env.roomB,'blocked')),false);
}));

test('signed independent Room B evaluation produces linked, replay-resistant ledger entries', () => scoped(env => {
  const projectDir = generateProject(env);
  const ledgerFile = path.join(env.roomB,'evidence.jsonl');
  const invoked = {count:0};
  const options = {
    ...env.opts,policyFile:env.policyFile,projectDir,image:IMAGE,
    workerPrivateKeyFile:env.workerPrivateKeyFile,workerId:'worker-one',
    ledgerFile,expectedHead:ZERO,spawn:fakeDocker(SECRET,invoked),
  };
  const first = evaluateIntake(options);
  assert.equal(invoked.count,1);
  assert.equal(first.report.status,'passed');
  assert.equal(first.report.executedVectors,3);
  assert.equal(first.checkpoint.sequence,1);
  assert.match(first.checkpoint.head,/^[a-f0-9]{64}$/);
  assert.notEqual(first.checkpoint.head,ZERO);
  const worker = findTrusted(verifyRegistry(env.signedRegistry,pemPublic(env.keys.rootKey),
    {minimumRevision:7,now:NOW}),'worker','worker-one',{now:NOW});
  const verified = verifyAttestation(first.attestation,worker.publicKey,
    {workerId:'worker-one',approvalSha256:first.report.approvalSha256,now:NOW});
  assert.equal(verified.report.status,'passed');
  assert.equal(fs.readFileSync(ledgerFile,'utf8').includes(SECRET),false);
  assert.equal(readLedger(ledgerFile,{expectedHead:first.checkpoint.head}).sequence,1);
  assert.throws(() => evaluateIntake(options),/independent checkpoint/);
  assert.equal(invoked.count,2,'rollback attempt may evaluate but cannot append an invalid ledger');
  const second = evaluateIntake({...options,expectedHead:first.checkpoint.head});
  assert.equal(second.checkpoint.sequence,2);
  assert.notEqual(second.checkpoint.head,first.checkpoint.head);
  const tamper = fs.readFileSync(ledgerFile,'utf8').replace('"status":"passed"','"status":"failed"');
  assert.throws(() => verifyLedgerText(tamper),/entry digest mismatch/);
  assert.throws(() => readLedger(ledgerFile,{expectedHead:first.checkpoint.head}),/independent checkpoint/);
  const edit = JSON.parse(JSON.stringify(first.attestation));
  edit.report.passedVectors=0;
  assert.throws(() => verifyAttestation(edit,worker.publicKey,{now:NOW}),/rejected/);
}));

test('revoked worker or wrong signer cannot issue evaluation receipt', () => scoped(env => {
  const projectDir = generateProject(env);
  const ledgerFile = path.join(env.roomB,'evidence.jsonl');
  const wrongKey=generateKeyPairSync('ed25519');
  fs.writeFileSync(env.workerPrivateKeyFile,pemPrivate(wrongKey),{mode:0o600});
  const counted={count:0};
  const options={...env.opts,policyFile:env.policyFile,projectDir,image:IMAGE,
    workerPrivateKeyFile:env.workerPrivateKeyFile,workerId:'worker-one',
    ledgerFile,expectedHead:ZERO,spawn:fakeDocker(SECRET,counted)};
  assert.throws(() => evaluateIntake(options),/worker signing key not in trusted registry/);
  assert.equal(counted.count,0);
  fs.writeFileSync(env.workerPrivateKeyFile,pemPrivate(env.keys.worker),{mode:0o600});
  const next=clone(env.document);
  next.revision=8;
  next.keys[2].revokedAt='2026-10-09T11:00:00.000Z';
  fs.writeFileSync(env.registryFile,JSON.stringify(signRegistry(next,env.keys.rootKey.privateKey)));
  assert.throws(() => evaluateIntake({...options,minimumRevision:8}),/revoked/);
  assert.equal(counted.count,0);
  assert.equal(fs.existsSync(ledgerFile),false);
}));
