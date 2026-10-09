'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { generateKeyPairSync } = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { approveSpec } = require('../src/clean-room');

const CLI = path.resolve(__dirname,'../src/clean-room/pilot-cli.js');
const SPEC = require('../../examples/clean-room/calculator.spec.json');
const pemPub = key => key.publicKey.export({type:'spki',format:'pem'});
const pemPriv = key => key.privateKey.export({type:'pkcs8',format:'pem'});
const root = () => fs.mkdtempSync(path.join(os.tmpdir(),'rudevolution-pilot-cli-'));
const run = args => spawnSync(process.execPath,[CLI,...args],{
  encoding:'utf8',timeout:15000,env:{PATH:process.env.PATH,HOME:process.env.HOME},
});
const writeKey = (filename,value) => fs.writeFileSync(filename,value,{mode:0o600});
function fixtures() {
  const dir=root();
  const keys={root:generateKeyPairSync('ed25519'),a:generateKeyPairSync('ed25519'),b:generateKeyPairSync('ed25519')};
  const instant=Date.now();
  const issued=new Date(instant-3600000).toISOString();
  const until=new Date(instant+86400000).toISOString();
  const from=new Date(instant-86400000).toISOString();
  const keyDoc=(id,role,key)=>({id,role,publicKey:pemPub(key),validFrom:from,validUntil:until,revokedAt:null});
  const document={
    format:'rudevolution.cleanroom.registry/v1',revision:12,issuedAt:issued,expiresAt:until,
    keys:[keyDoc('primary.one','primary',keys.a),keyDoc('secondary.two','secondary',keys.b)],
  };
  const files={
    registry:path.join(dir,'registry.json'),rootPrivate:path.join(dir,'root.pem'),
    rootPublic:path.join(dir,'root-public.pem'),primaryPublic:path.join(dir,'primary-public.pem'),
    secondaryPrivate:path.join(dir,'secondary-private.pem'),
    approved:path.join(dir,'approved.json'),signedRegistry:path.join(dir,'signed-registry.json'),
    release:path.join(dir,'release.json'),markers:path.join(dir,'markers.json'),
    project:path.join(dir,'project'),
  };
  fs.writeFileSync(files.registry,JSON.stringify(document));
  writeKey(files.rootPrivate,pemPriv(keys.root));
  fs.writeFileSync(files.rootPublic,pemPub(keys.root));
  fs.writeFileSync(files.primaryPublic,pemPub(keys.a));
  writeKey(files.secondaryPrivate,pemPriv(keys.b));
  const approved=approveSpec(SPEC,{reviewer:'primary.one',privateKey:keys.a.privateKey}).artifact;
  fs.writeFileSync(files.approved,JSON.stringify(approved));
  fs.writeFileSync(files.markers,JSON.stringify(['RUVSECRETXYZABC']));
  return {dir,keys,files};
}

test('CLI root signing, dual reviewer release, independent intake and replay fail closed',()=>{
  const x=fixtures(),f=x.files;
  try {
    const signed=run(['registry-sign',f.registry,f.rootPrivate,f.signedRegistry]);
    assert.equal(signed.status,0,signed.stderr);
    assert.equal(fs.existsSync(f.signedRegistry),true);
    const noAck=run(['release',f.approved,f.primaryPublic,f.secondaryPrivate,'secondary.two',f.release,'--no-review']);
    assert.notEqual(noAck.status,0);
    assert.equal(fs.existsSync(f.release),false);
    const release=run(['release',f.approved,f.primaryPublic,f.secondaryPrivate,'secondary.two',f.release,'--ack-independent',f.markers]);
    assert.equal(release.status,0,release.stderr);
    const verify=run(['verify-release',f.release,f.signedRegistry,f.rootPublic,'12']);
    assert.equal(verify.status,0,verify.stderr);
    const intake=run(['intake',f.release,f.signedRegistry,f.rootPublic,'12',f.project]);
    assert.equal(intake.status,0,intake.stderr);
    assert.deepEqual(fs.readdirSync(f.project).sort(),['APPROVAL.txt','compat.test.mjs','contract.json','implementation.mjs']);
    assert.notEqual(run(['intake',f.release,f.signedRegistry,f.rootPublic,'12',f.project]).status,0);
    const rolled=run(['verify-release',f.release,f.signedRegistry,f.rootPublic,'13']);
    assert.notEqual(rolled.status,0);
  } finally {fs.rmSync(x.dir,{recursive:true,force:true});}
});

test('CLI refuses marker leakage before file creation, symlinked trust and key permission errors',()=>{
  const x=fixtures(),f=x.files;
  try {
    const approved=JSON.parse(fs.readFileSync(f.approved));
    approved.spec.vectors[2].expected='RUVSECRETXYZABC';
    // A valid primary signature over the leaked string still fails the
    // independent Room A disclosure gate.
    fs.writeFileSync(f.approved,JSON.stringify(
      approveSpec(approved.spec,{reviewer:'primary.one',privateKey:x.keys.a.privateKey}).artifact
    ));
    const leak=run(['release',f.approved,f.primaryPublic,f.secondaryPrivate,'secondary.two',f.release,'--ack-independent',f.markers]);
    assert.notEqual(leak.status,0);
    assert.equal(fs.existsSync(f.release),false);
    fs.chmodSync(f.secondaryPrivate,0o644);
    const keyfail=run(['release',f.approved,f.primaryPublic,f.secondaryPrivate,'secondary.two',f.release,'--ack-independent']);
    assert.notEqual(keyfail.status,0);
    const symlink=path.join(x.dir,'link-public.pem');
    fs.symlinkSync(f.rootPublic,symlink);
    assert.notEqual(run(['verify-release',f.release,f.signedRegistry,symlink,'12']).status,0);
  } finally {fs.rmSync(x.dir,{recursive:true,force:true});}
});
