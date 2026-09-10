/** SHA-256 integrity manifests. These do not prove semantic equivalence or authorship. */
'use strict';
const crypto = require('node:crypto');
const sha256 = data => crypto.createHash('sha256').update(data).digest('hex');
const HASH = /^[a-f0-9]{64}$/;
function rootHash(sourceHash, modules) {
  return sha256(JSON.stringify(['rudevolution-witness-v2', sourceHash,
    modules.map(m => [m.name, m.hash])]));
}
function buildWitnessChain(source, modules) {
  const source_hash = sha256(source);
  const names = new Set();
  const module_hashes = modules.map(m => {
    if (typeof m.name !== 'string' || !m.name || names.has(m.name)) {
      throw new TypeError('Module names must be nonempty and unique');
    }
    names.add(m.name);
    return { name: m.name, hash: sha256(m.content) };
  });
  const root = rootHash(source_hash, module_hashes);
  return { version: 2, algorithm: 'sha256', source_hash, module_hashes, root,
    chain: [{ hash: source_hash, label: 'source', parent: null },
      ...module_hashes.map(m => ({ hash: m.hash, label: `module:${m.name}`, parent: source_hash })),
      { hash: root, label: 'root', parent: source_hash }],
    created: new Date().toISOString() };
}
/** Optional source and module bytes are required for full artifact verification. */
function verifyWitnessChain(witness, sourceContent, modules) {
  const errors = [];
  const invalid = message => ({ valid: false, chain_length: 0, root: '',
    sourceVerified: false, modulesVerified: false, errors: [message] });
  if (!witness || witness.version !== 2 || witness.algorithm !== 'sha256' ||
      typeof witness.source_hash !== 'string' || !HASH.test(witness.source_hash) ||
      typeof witness.root !== 'string' || !HASH.test(witness.root) ||
      !Array.isArray(witness.module_hashes) || !Array.isArray(witness.chain)) {
    return invalid('Invalid or unsupported witness schema; regenerate legacy manifests');
  }
  const names = new Set();
  for (const m of witness.module_hashes) {
    if (!m || typeof m.name !== 'string' || !m.name || names.has(m.name) ||
        typeof m.hash !== 'string' || !HASH.test(m.hash)) return invalid('Invalid module manifest');
    names.add(m.name);
  }
  if (rootHash(witness.source_hash, witness.module_hashes) !== witness.root) errors.push('Root mismatch');
  const expected = [{ hash: witness.source_hash, label: 'source', parent: null },
    ...witness.module_hashes.map(m => ({ hash: m.hash, label: `module:${m.name}`, parent: witness.source_hash })),
    { hash: witness.root, label: 'root', parent: witness.source_hash }];
  if (witness.chain.length !== expected.length || expected.some((n, i) => {
    const actual = witness.chain[i];
    return !actual || actual.hash !== n.hash || actual.label !== n.label || actual.parent !== n.parent;
  })) errors.push('Chain topology mismatch');
  let sourceVerified = false;
  if (sourceContent !== undefined) {
    sourceVerified = (typeof sourceContent === 'string' || Buffer.isBuffer(sourceContent)) &&
      sha256(sourceContent) === witness.source_hash;
    if (!sourceVerified) errors.push('Source hash mismatch');
  }
  let modulesVerified = false;
  if (modules !== undefined) {
    modulesVerified = Array.isArray(modules) && modules.length === witness.module_hashes.length &&
      witness.module_hashes.every((m, i) => {
        const actual = modules[i];
        return actual && actual.name === m.name &&
          (typeof actual.content === 'string' || Buffer.isBuffer(actual.content)) && sha256(actual.content) === m.hash;
      });
    if (!modulesVerified) errors.push('Module content, order or name mismatch');
  }
  return { valid: errors.length === 0, chain_length: witness.chain.length, root: witness.root,
    sourceVerified, modulesVerified, errors };
}
module.exports = { sha256, buildWitnessChain, verifyWitnessChain };
