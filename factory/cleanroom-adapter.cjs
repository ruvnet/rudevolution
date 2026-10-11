'use strict';

// Trusted Node-side transfer preparation. Cloudflare receives metadata only;
// this helper is not a signer, authoring agent, evaluator or publication gate.
const { verifyRegistry } = require('../npm/src/clean-room/trust-registry');
const { verifyRelease } = require('../npm/src/clean-room/release');
const { canonicalStringify } = require('../npm/src/clean-room');
const FORMAT = 'rudevolution.factory.cleanroom-dispatch/v1';
const MAX_BYTES = 32768;

function boundedCopy(value, label) {
  const encoded = JSON.stringify(value);
  if (typeof encoded !== 'string' || Buffer.byteLength(encoded) > MAX_BYTES) {
    throw new Error(label + ' exceeds transfer limit');
  }
  return JSON.parse(encoded);
}
function deepFreeze(value) {
  if (value && typeof value === 'object') {
    Object.values(value).forEach(deepFreeze);
    Object.freeze(value);
  }
  return value;
}

/**
 * Call only in a trusted coordinator with independently pinned public root and
 * monotonic registry checkpoint. Never derive these from the request payload.
 * Room B must separately verify the original signed release and registry before
 * accepting this contract. This unsigned envelope is a dispatch aid, not proof.
 */
function createDispatchEnvelope({ released, signedRegistry, pinnedRootPublicKey,
  minimumRevision, now = new Date() } = {}) {
  if (!Number.isSafeInteger(minimumRevision) || minimumRevision < 1) {
    throw new Error('An independent minimum registry revision is required');
  }
  const registry = verifyRegistry(boundedCopy(signedRegistry, 'Registry'), pinnedRootPublicKey,
    { minimumRevision, now });
  const release = boundedCopy(released, 'Release');
  const verified = verifyRelease(release, registry, { now });
  const envelope = {
    format: FORMAT,
    approvedContract: release.approved.spec,
    specSha256: verified.specSha256,
    approvalSha256: verified.approvalSha256,
    releaseSha256: verified.releaseSha256,
    registrySha256: verified.registrySha256,
    registryRevision: verified.registryRevision,
  };
  if (Buffer.byteLength(canonicalStringify(envelope)) > MAX_BYTES) {
    throw new Error('Dispatch exceeds transfer limit');
  }
  return deepFreeze(envelope);
}
module.exports = { FORMAT, createDispatchEnvelope };
