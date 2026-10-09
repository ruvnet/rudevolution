'use strict';

/**
 * Minimal signed, reviewed interface-only handoff for an independently isolated Room B.
 * No original source, AST, declarations, strings, model output, or implementation bodies
 * are imported from the ruDevolution analysis APIs.
 */
const { createHash, sign, verify, createPublicKey, createPrivateKey, KeyObject } = require('node:crypto');

const SPEC_FORMAT = 'rudevolution.cleanroom.spec/v1';
const APPROVAL_FORMAT = 'rudevolution.cleanroom.approval/v1';
const DOMAIN = 'rudevolution.cleanroom.approval/v1\n';
const ID = /^[A-Za-z][A-Za-z0-9_]{0,39}$/;
const TARGET = /^[a-z][a-z0-9-]{0,47}$/;
const REVIEWER = /^[A-Za-z0-9][A-Za-z0-9_.@-]{1,79}$/;
const JS_RESERVED = new Set(('await break case catch class const continue debugger default delete do else enum export extends false finally for function if import in instanceof new null return super switch this throw true try typeof var void while with yield let static implements interface package private protected public arguments eval').split(' '));
const SAFE_STRING = /^[A-Za-z0-9 _./:@+\-]{0,64}$/;
const TYPES = new Set(['string', 'number', 'boolean']);
const RESULTS = new Set([...TYPES, 'void']);
const ERRORS = new Set(['invalid_argument', 'not_found', 'conflict', 'unavailable']);

function fail(message) { throw new Error(`Clean room rejected: ${message}`); }
function plain(value) { return value !== null && typeof value === 'object' && !Array.isArray(value) && (Object.getPrototypeOf(value) === Object.prototype || Object.getPrototypeOf(value) === null); }
function exact(value, fields, where) {
  if (!plain(value)) fail(`${where} must be an object`);
  const keys = Object.keys(value);
  if (keys.length !== fields.length || keys.some(k => !fields.includes(k))) fail(`${where} contains missing or prohibited fields`);
}
function limitedString(value, regex, where) {
  if (typeof value !== 'string' || !regex.test(value)) fail(`${where} does not match its constrained grammar`);
}
function integerWithin(n, min, max, where) {
  if (!Number.isInteger(n) || n < min || n > max) fail(`${where} must be within ${min}..${max}`);
}
function unique(names, where) {
  if (new Set(names).size !== names.length) fail(`${where} contains duplicate identifiers`);
}
function scalar(value, type, where) {
  if (type === 'string') limitedString(value, SAFE_STRING, where);
  if (type === 'number' && (typeof value !== 'number' || !Number.isFinite(value) || Math.abs(value) > 1e9)) fail(`${where} must be a bounded finite number`);
  if (type === 'boolean' && typeof value !== 'boolean') fail(`${where} must be boolean`);
  if (type === 'void' && value !== null) fail(`${where} must be null to represent void`);
}
function validateSpec(spec) {
  exact(spec, ['format', 'target', 'operations', 'vectors'], 'specification');
  if (spec.format !== SPEC_FORMAT) fail('unsupported specification format');
  limitedString(spec.target, TARGET, 'target');
  if (!Array.isArray(spec.operations)) fail('operations must be an array');
  integerWithin(spec.operations.length, 1, 16, 'operations count');
  const operations = new Map();
  for (const [i, op] of spec.operations.entries()) {
    exact(op, ['name', 'inputs', 'returns', 'errors'], `operation ${i}`);
    limitedString(op.name, ID, `operation ${i} name`);
    if (JS_RESERVED.has(op.name)) fail('reserved operation name');
    if (operations.has(op.name)) fail('duplicate operation name');
    if (!Array.isArray(op.inputs)) fail('inputs must be an array');
    integerWithin(op.inputs.length, 0, 8, 'input count');
    for (const [j, input] of op.inputs.entries()) {
      exact(input, ['name', 'type'], `input ${i}.${j}`);
      limitedString(input.name, ID, `input ${i}.${j} name`);
      if (JS_RESERVED.has(input.name)) fail('reserved input name');
      if (!TYPES.has(input.type)) fail('unsupported input type');
    }
    unique(op.inputs.map(input => input.name), 'input names');
    if (!RESULTS.has(op.returns)) fail('unsupported return type');
    if (!Array.isArray(op.errors)) fail('errors must be an array');
    integerWithin(op.errors.length, 0, 4, 'error count');
    if (op.errors.some(error => !ERRORS.has(error))) fail('unsupported error identifier');
    unique(op.errors, 'error names');
    operations.set(op.name, op);
  }
  if (!Array.isArray(spec.vectors)) fail('vectors must be an array');
  integerWithin(spec.vectors.length, 0, 24, 'vector count');
  for (const [i, vector] of spec.vectors.entries()) {
    exact(vector, ['operation', 'arguments', 'expected'], `vector ${i}`);
    const op = operations.get(vector.operation);
    if (!op) fail(`vector ${i} names an unknown operation`);
    if (!Array.isArray(vector.arguments) || vector.arguments.length !== op.inputs.length) fail(`vector ${i} has incorrect arity`);
    op.inputs.forEach((input, j) => scalar(vector.arguments[j], input.type, `vector ${i} argument ${j}`));
    scalar(vector.expected, op.returns, `vector ${i} expected`);
  }
  const canonical = canonicalStringify(spec);
  if (Buffer.byteLength(canonical, 'utf8') > 16 * 1024) fail('specification exceeds 16 KiB');
  return spec;
}

/** Reproducible canonical JSON for this deliberately narrow plain-object schema. */
function canonicalStringify(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalStringify).join(',')}]`;
  if (plain(value)) return `{${Object.keys(value).sort().map(k => `${JSON.stringify(k)}:${canonicalStringify(value[k])}`).join(',')}}`;
  if (typeof value === 'number' && !Number.isFinite(value)) fail('nonfinite number');
  const serialized = JSON.stringify(value);
  if (serialized === undefined) fail('unsupported JSON value');
  return serialized;
}
const sha256 = text => createHash('sha256').update(text).digest('hex');
const fingerprint = key => sha256((key instanceof KeyObject && key.type === 'public' ? key : createPublicKey(key)).export({ type: 'spki', format: 'der' }));
const isoDate = value => typeof value === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(value) && !Number.isNaN(Date.parse(value)) && new Date(value).toISOString() === value;
function payload(spec, reviewer, approvedAt, digest) { return `${DOMAIN}${canonicalStringify({ spec, reviewer, approvedAt, specSha256: digest })}`; }

function approveSpec(spec, { reviewer, privateKey, now = new Date() }) {
  validateSpec(spec);
  limitedString(reviewer, REVIEWER, 'reviewer');
  if (!(now instanceof Date) || Number.isNaN(now.getTime())) fail('invalid approval clock');
  const key = privateKey instanceof KeyObject ? privateKey : createPrivateKey(privateKey);
  if (key.asymmetricKeyType !== 'ed25519') fail('Ed25519 private key required');
  const approvedAt = now.toISOString();
  const specSha256 = sha256(canonicalStringify(spec));
  const signature = sign(null, Buffer.from(payload(spec, reviewer, approvedAt, specSha256), 'utf8'), key).toString('base64');
  const artifact = {
    format: APPROVAL_FORMAT,
    spec,
    review: { reviewer, approvedAt, specSha256, signature },
  };
  return { artifact, receipt: {
    format: 'rudevolution.cleanroom.room-a-receipt/v1',
    approvalSha256: sha256(canonicalStringify(artifact)),
    specSha256,
    reviewer,
    publicKeyFingerprint: fingerprint(key),
    approvedAt,
  }};
}

function verifyApproved(artifact, publicKey) {
  exact(artifact, ['format', 'spec', 'review'], 'approved artifact');
  if (artifact.format !== APPROVAL_FORMAT) fail('unsupported approval format');
  validateSpec(artifact.spec);
  exact(artifact.review, ['reviewer', 'approvedAt', 'specSha256', 'signature'], 'review');
  const { reviewer, approvedAt, specSha256, signature } = artifact.review;
  limitedString(reviewer, REVIEWER, 'reviewer');
  if (!isoDate(approvedAt)) fail('invalid approval timestamp');
  if (specSha256 !== sha256(canonicalStringify(artifact.spec))) fail('spec digest mismatch');
  if (typeof signature !== 'string' || !/^[A-Za-z0-9+/]{86}==$/.test(signature)) fail('malformed Ed25519 signature');
  const decoded = Buffer.from(signature, 'base64');
  if (decoded.length !== 64 || decoded.toString('base64') !== signature) fail('noncanonical signature encoding');
  const key = publicKey instanceof KeyObject ? publicKey : createPublicKey(publicKey);
  if (key.asymmetricKeyType !== 'ed25519') fail('Ed25519 public key required');
  if (!verify(null, Buffer.from(payload(artifact.spec, reviewer, approvedAt, specSha256), 'utf8'), key, decoded)) fail('signature invalid or reviewer not trusted');
  const encoded = canonicalStringify(artifact);
  if (Buffer.byteLength(encoded, 'utf8') > 24 * 1024) fail('approval artifact exceeds size limit');
  return { spec: artifact.spec, approvalSha256: sha256(encoded), reviewer, approvedAt, publicKeyFingerprint: fingerprint(key) };
}

function scaffoldFiles(artifact, publicKey) {
  const verified = verifyApproved(artifact, publicKey);
  const { spec } = verified;
  const fnDocs = spec.operations.map(op => {
    const args = op.inputs.map(x => x.name).join(', ');
    const comments = op.inputs.map(x => ` * @param {${x.type}} ${x.name}`).join('\n');
    return `/**\n${comments ? `${comments}\n` : ''} * @returns {${op.returns === 'void' ? 'undefined' : op.returns}}\n */\nexport function ${op.name}(${args}) {\n  throw new Error('UNIMPLEMENTED');\n}`;
  }).join('\n\n');
  const contractText = `${canonicalStringify(spec)}\n`;
  const contractDigest = sha256(contractText);
  const runner = `import test from 'node:test';\nimport assert from 'node:assert/strict';\nimport { createHash } from 'node:crypto';\nimport { readFileSync } from 'node:fs';\nconst contractBytes = readFileSync(new URL('./contract.json', import.meta.url));\nconst observedDigest = createHash('sha256').update(contractBytes).digest('hex');\nif (observedDigest !== '${contractDigest}') throw new Error('Approved contract integrity mismatch');\nconst spec = JSON.parse(contractBytes.toString('utf8'));\nconst implementation = await import('./implementation.mjs');\nfor (const [index, vector] of spec.vectors.entries()) {\n  test(\`compatibility vector \${index}: \${vector.operation}\`, () => {\n    const actual = implementation[vector.operation](...vector.arguments);\n    assert.deepStrictEqual(actual, vector.expected === null && spec.operations.find(op => op.name === vector.operation).returns === 'void' ? undefined : vector.expected);\n  });\n}\n`;
  return {
    'contract.json': contractText,
    'implementation.mjs': `${fnDocs}\n`,
    'compat.test.mjs': runner,
    'APPROVAL.txt': `Approved source-independent interface contract\nTarget: ${spec.target}\nReviewer: ${verified.reviewer}\nApproved UTC: ${verified.approvedAt}\nArtifact SHA-256: ${verified.approvalSha256}\nPinned key fingerprint: ${verified.publicKeyFingerprint}\nNo source code is transferred or made available by this tool.\n`,
  };
}

module.exports = { SPEC_FORMAT, APPROVAL_FORMAT, validateSpec, canonicalStringify, approveSpec, verifyApproved, scaffoldFiles, sha256 };
