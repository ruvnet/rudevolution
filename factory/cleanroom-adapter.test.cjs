'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { generateKeyPairSync } = require('node:crypto');
const { approveSpec, canonicalStringify, sha256 } = require('../npm/src/clean-room');
const { signRegistry } = require('../npm/src/clean-room/trust-registry');
const { reviewRelease } = require('../npm/src/clean-room/release');
const { createDispatchEnvelope, FORMAT } = require('./cleanroom-adapter.cjs');
const spec = require('../examples/clean-room/calculator.spec.json');
const now = new Date('2026-10-11T12:00:00.000Z');
const clone = x => JSON.parse(JSON.stringify(x));
function fixture() {
  const root = generateKeyPairSync('ed25519');
  const primary = generateKeyPairSync('ed25519');
  const secondary = generateKeyPairSync('ed25519');
  const document = { format: 'rudevolution.cleanroom.registry/v1', revision: 7,
    issuedAt: '2026-10-11T09:00:00.000Z', expiresAt: '2026-10-13T09:00:00.000Z',
    keys: [[primary,'reviewer.one','primary'],[secondary,'reviewer.two','secondary']].map(([key,id,role]) => ({
      id,role,publicKey:key.publicKey.export({type:'spki',format:'pem'}),
      validFrom:'2026-10-01T00:00:00.000Z',validUntil:'2026-10-14T00:00:00.000Z',revokedAt:null,
    })),
  };
  const approved = approveSpec(clone(spec), {reviewer:'reviewer.one',privateKey:primary.privateKey,now}).artifact;
  const released = reviewRelease(approved, primary.publicKey, {reviewer:'reviewer.two',privateKey:secondary.privateKey,now});
  return {root,document, options:{released,signedRegistry:signRegistry(document,root.privateKey),
    pinnedRootPublicKey:root.publicKey,minimumRevision:7,now}};
}
test('real dual signatures produce a minimal immutable contract dispatch', () => {
  const {options} = fixture();
  const result = createDispatchEnvelope(options);
  assert.deepEqual(Object.keys(result).sort(), ['format','approvedContract','specSha256','approvalSha256','releaseSha256','registrySha256','registryRevision'].sort());
  assert.equal(result.format,FORMAT);
  assert.equal(result.releaseSha256,sha256(canonicalStringify(options.released)));
  assert.deepEqual(result.approvedContract,spec);
  assert.ok(Object.isFrozen(result.approvedContract.operations));
  options.released.approved.spec.target='mutated';
  assert.equal(result.approvedContract.target,spec.target);
});
test('rejects unsigned, altered and source-bearing releases', () => {
  for (const mutate of [r=>delete r.secondReview, r=>r.approved.spec.vectors[0].expected=999,
    r=>r.source='secret reference source', r=>r.secondReview.signature='A'.repeat(86)+'==']) {
    const {options}=fixture(); mutate(options.released);
    assert.throws(()=>createDispatchEnvelope(options));
  }
});
test('rejects unpinned registry, rollback, revoked reviewer and expired release', () => {
  const {options,root,document}=fixture();
  assert.throws(()=>createDispatchEnvelope({...options,minimumRevision:undefined}));
  assert.throws(()=>createDispatchEnvelope({...options,minimumRevision:8}),/rolled back/);
  assert.throws(()=>createDispatchEnvelope({...options,pinnedRootPublicKey:generateKeyPairSync('ed25519').publicKey}),/signature/);
  const revoked = clone(document);
  revoked.keys[1].revokedAt='2026-10-11T11:00:00.000Z';
  assert.throws(()=>createDispatchEnvelope({...options,signedRegistry:signRegistry(revoked,root.privateKey)}),/revoked/);
  assert.throws(()=>createDispatchEnvelope({...options,now:new Date('2026-10-12T13:00:00.000Z')}),/stale/);
});
test('rejects oversize transfer before verification', () => {
  const {options}=fixture(); options.released.source='x'.repeat(32769);
  assert.throws(()=>createDispatchEnvelope(options),/limit/);
});
