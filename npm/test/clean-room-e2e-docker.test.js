'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { generateKeyPairSync } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { approveSpec } = require('../src/clean-room');
const { fingerprint } = require('../src/clean-room/trust-registry');
const { ZERO, readLedger } = require('../src/clean-room/evidence-ledger');
const { verifyAttestation } = require('../src/clean-room/attestation');

const IMAGE = process.env.RUDEVOLUTION_TEST_IMAGE;
const CLI = path.resolve(__dirname,'../src/clean-room/pilot-cli.js');
const MARKER = 'ROOMA_UNEXPORTED_PROPRIETARY_SENTINEL_78261';
const SPEC = require('../../examples/clean-room/calculator.spec.json');
const publicPem = pair => pair.publicKey.export({format:'pem',type:'spki'});
const privatePem = pair => pair.privateKey.export({format:'pem',type:'pkcs8'});
function operator(args) {
  return spawnSync(process.execPath,[CLI,...args],{
    timeout:90000,encoding:'utf8',maxBuffer:8192,
    env:{PATH:process.env.PATH,HOME:process.env.HOME},
  });
}
function mustPass(result,stage) {
  assert.equal(result.error,undefined,stage + ': ' + result.error?.message);
  assert.equal(result.status,0,stage + ': ' + result.stdout + result.stderr);
}
function useKey(filename,content) {
  fs.writeFileSync(filename,content,{mode:0o600,flag:'wx'});
}
function allFiles(root) {
  const files=[];
  function walk(dir) {
    for(const entry of fs.readdirSync(dir,{withFileTypes:true})){
      const file=path.join(dir,entry.name);
      if(entry.isDirectory()) walk(file);
      else files.push(file);
    }
  }
  walk(root);
  return files;
}

test('full synthetic clean room: two reviewers, isolated author, Docker evaluation, signed ledger, revocation', {
  skip:!IMAGE?'Requires already-pulled immutable RUDEVOLUTION_TEST_IMAGE':false,
  timeout:180000,
},()=>{
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'rudevolution-e2e-docker-'));
  const roomA=path.join(root,'room-a');
  const roomB=path.join(root,'room-b');
  fs.mkdirSync(roomA,{mode:0o700});
  fs.mkdirSync(roomB,{mode:0o700});
  try {
    const keys={
      root:generateKeyPairSync('ed25519'),
      primary:generateKeyPairSync('ed25519'),
      secondary:generateKeyPairSync('ed25519'),
      worker:generateKeyPairSync('ed25519'),
    };
    const files={
      privateSource:path.join(roomA,'private-reference.js'),
      primaryKey:path.join(roomA,'primary-private.pem'),
      primaryPub:path.join(roomA,'primary-public.pem'),
      secondaryKey:path.join(roomA,'secondary-private.pem'),
      rootKey:path.join(roomA,'registry-root-private.pem'),
      doc:path.join(roomA,'registry.json'),
      spec:path.join(roomA,'interface.json'),
      approved:path.join(roomA,'approved.json'),
      denied:path.join(roomA,'forbidden-markers.json'),
      signedRegistry:path.join(roomA,'registry.signed.json'),
      roomARelease:path.join(roomA,'release.json'),
      release:path.join(roomB,'release.json'),
      registry:path.join(roomB,'registry.signed.json'),
      rootPub:path.join(roomB,'pinned-root.pem'),
      workerKey:path.join(roomB,'worker-private.pem'),
      workerPub:path.join(roomB,'trusted-worker.pem'),
      policy:path.join(roomB,'policy.json'),
      project:path.join(roomB,'independent-implementation'),
      report:path.join(roomB,'result.json'),
      envelope:path.join(roomB,'attested-result.json'),
      ledger:path.join(roomB,'evidence.jsonl'),
      authorStage:path.join(roomB,'authoring-stage'),
    };
    // A's original source is intentionally more expressive than the approved
    // contract and can never be mounted in B or passed to the signer.
    fs.writeFileSync(files.privateSource,'const proprietaryMarker = "'+MARKER+'";\n' +
      'function hiddenImplementation(a,b){return a+b;}\n',{mode:0o600});
    useKey(files.primaryKey,privatePem(keys.primary));
    useKey(files.secondaryKey,privatePem(keys.secondary));
    useKey(files.rootKey,privatePem(keys.root));
    fs.writeFileSync(files.primaryPub,publicPem(keys.primary));
    fs.writeFileSync(files.spec,JSON.stringify(SPEC));
    fs.writeFileSync(files.denied,JSON.stringify([MARKER]));
    const now=Date.now();
    const from=new Date(now-600000).toISOString();
    const till=new Date(now+3600000).toISOString();
    const keyEntry=(id,role,pair)=>({
      id,role,publicKey:publicPem(pair),validFrom:from,validUntil:till,revokedAt:null,
    });
    const registry={
      format:'rudevolution.cleanroom.registry/v1',
      revision:14,issuedAt:from,expiresAt:till,
      keys:[
        keyEntry('primary.one','primary',keys.primary),
        keyEntry('secondary.two','secondary',keys.secondary),
        keyEntry('worker-one','worker',keys.worker),
      ],
    };
    fs.writeFileSync(files.doc,JSON.stringify(registry));
    mustPass(operator(['registry-sign',files.doc,files.rootKey,files.signedRegistry]),'root registry signing');
    const approval=approveSpec(SPEC,{reviewer:'primary.one',privateKey:keys.primary.privateKey});
    fs.writeFileSync(files.approved,JSON.stringify(approval.artifact));
    const unreviewed=operator(['release',files.approved,files.primaryPub,files.secondaryKey,'secondary.two',
      files.roomARelease,'--no-independent-review',files.denied]);
    assert.notEqual(unreviewed.status,0,'second review is mandatory');
    assert.equal(fs.existsSync(files.roomARelease),false);
    mustPass(operator(['release',files.approved,files.primaryPub,files.secondaryKey,'secondary.two',
      files.roomARelease,'--ack-independent',files.denied]),'second independent review');
    assert.equal(fs.readFileSync(files.roomARelease,'utf8').includes(MARKER),false);
    // Explicitly transfer ONE vetted artifact. Trust anchors travel through a
    // separate channel, with registry revision floor chosen by Room B.
    fs.copyFileSync(files.roomARelease,files.release,fs.constants.COPYFILE_EXCL);
    fs.copyFileSync(files.signedRegistry,files.registry,fs.constants.COPYFILE_EXCL);
    fs.writeFileSync(files.rootPub,publicPem(keys.root));
    useKey(files.workerKey,privatePem(keys.worker));
    fs.writeFileSync(files.workerPub,publicPem(keys.worker));
    const policy={
      format:'rudevolution.cleanroom.policy/v1',
      target:SPEC.target,reviewer:'primary.one',
      publicKeyFingerprint:fingerprint(keys.primary.publicKey),
      runtimeImage:IMAGE,expiresAt:till,maxApprovalAgeHours:12,
    };
    fs.writeFileSync(files.policy,JSON.stringify(policy));
    mustPass(operator(['intake',files.release,files.registry,files.rootPub,'14',files.project]),'Room B intake');

    // Separate Room B authoring process. It sees only the public contract and
    // a fixture author program, never Room A files, repository, keys, agent
    // memory, vector store or signing inputs.
    fs.mkdirSync(files.authorStage,{mode:0o777});
    fs.chmodSync(files.authorStage,0o777);
    fs.copyFileSync(path.join(files.project,'contract.json'),path.join(files.authorStage,'contract.json'));
    const syntheticAuthor=[
      "import { existsSync, readFileSync, writeFileSync } from 'node:fs';",
      "import { networkInterfaces } from 'node:os';",
      'if (existsSync('+JSON.stringify(files.privateSource)+")) throw Error('Room A mounted in author');",
      "if (Object.keys(networkInterfaces()).some(x=>x!=='lo')) throw Error('author network enabled');",
      "const contract=JSON.parse(readFileSync('/author/contract.json','utf8'));",
      "if (contract.target!=='calculator-compatibility' || contract.operations.length!==2) throw Error('wrong contract');",
      "writeFileSync('/author/implementation.mjs',",
      "  \"export function add(a,b){return a+b;}\\nexport function greet(name){return 'Hello '+name;}\\n\");",
    ].join('\n');
    fs.writeFileSync(path.join(files.authorStage,'author.mjs'),syntheticAuthor,{mode:0o644});
    const args=[
      '--host=unix:///var/run/docker.sock','run','--rm','--pull=never','--network=none',
      '--read-only','--cap-drop=ALL','--security-opt=no-new-privileges=true',
      '--pids-limit=64','--memory=256m','--cpus=1','--user=65534:65534',
      '--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777',
      '--mount=type=bind,source='+files.authorStage+',target=/author',
      '--workdir=/author','--entrypoint=node',IMAGE,'author.mjs',
    ];
    const authored=spawnSync('docker',args,{encoding:'utf8',timeout:60000,maxBuffer:8192});
    mustPass(authored,'isolated Room B fixture authoring');
    const independent=fs.readFileSync(path.join(files.authorStage,'implementation.mjs'),'utf8');
    assert.equal(independent.includes(MARKER),false);
    fs.writeFileSync(path.join(files.project,'implementation.mjs'),independent);
    // Remove the mutable authoring workspace so it cannot be used as a
    // backdoor into the evaluation phase.
    fs.rmSync(files.authorStage,{recursive:true,force:true});

    // Critical noncontamination check over all Room B artifacts before
    // evaluation. B may contain a path reference to A in this test host, but
    // never original source bytes, markers, keys or raw decompiler results.
    for (const file of allFiles(roomB)) {
      assert.equal(fs.readFileSync(file,'utf8').includes(MARKER),false,'marker leaked to Room B: '+path.basename(file));
    }
    mustPass(operator(['evaluate',files.release,files.registry,files.rootPub,'14',files.policy,
      files.project,IMAGE,files.workerKey,'worker-one',files.ledger,ZERO,files.report,files.envelope]),
      'offline Docker compatibility evaluation');
    const report=JSON.parse(fs.readFileSync(files.report,'utf8'));
    assert.equal(report.status,'passed');
    assert.equal(report.vectorCount,3);
    assert.equal(report.executedVectors,3);
    assert.equal(report.passedVectors,3);
    const attested=JSON.parse(fs.readFileSync(files.envelope,'utf8'));
    const verified=verifyAttestation(attested,keys.worker.publicKey,{
      workerId:'worker-one',approvalSha256:report.approvalSha256,
    });
    assert.equal(verified.report.status,'passed');
    const checkpoint=readLedger(files.ledger);
    assert.equal(checkpoint.sequence,1);
    assert.notEqual(checkpoint.head,ZERO);
    mustPass(operator(['verify-evidence',files.envelope,files.workerPub,'worker-one',
      report.approvalSha256,files.ledger,checkpoint.head]),'independent evidence verification');
    mustPass(operator(['ledger-check',files.ledger,checkpoint.head]),'external checkpoint');
    assert.notEqual(operator(['ledger-check',files.ledger,ZERO]).status,0,'missing checkpoint must fail');
    const poison=path.join(roomB,'poisoned-ledger.jsonl');
    fs.writeFileSync(poison,fs.readFileSync(files.ledger,'utf8').replace('"status":"passed"','"status":"failed"'));
    assert.notEqual(operator(['ledger-check',poison,checkpoint.head]).status,0,'edited ledger must fail');
    // If a key is revoked in a higher root-signed registry revision, the old
    // release must be rejected before any new Room B project can be created.
    const revoked=JSON.parse(JSON.stringify(registry));
    revoked.revision=15;
    revoked.keys[1].revokedAt=new Date().toISOString();
    fs.writeFileSync(files.doc,JSON.stringify(revoked));
    const updatedRegistry=path.join(roomA,'revoked-registry.json');
    mustPass(operator(['registry-sign',files.doc,files.rootKey,updatedRegistry]),'revocation signing');
    fs.copyFileSync(updatedRegistry,files.registry);
    assert.notEqual(operator(['verify-release',files.release,files.registry,files.rootPub,'15']).status,0,'revoked reviewer must fail');
    const blocked=path.join(roomB,'blocked-project');
    assert.notEqual(operator(['intake',files.release,files.registry,files.rootPub,'15',blocked]).status,0);
    assert.equal(fs.existsSync(blocked),false);
    for (const file of allFiles(roomB)) {
      assert.equal(fs.readFileSync(file,'utf8').includes(MARKER),false,'marker leaked after evaluation');
    }
  } finally {
    fs.rmSync(root,{recursive:true,force:true});
  }
});
