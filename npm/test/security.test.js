'use strict';
const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const { buildWitnessChain, verifyWitnessChain } = require('../src/decompiler/witness');
const { validateReconstruction, checkFunctionalEquivalence } = require('../src/decompiler/validator');
const { reconstructRunnable } = require('../src/decompiler/reconstructor');
const { decompileSource, decompileUrl, writeOutput } = require('../src/decompiler');
const { loadPatterns } = require('../src/decompiler/name-predictor');
const { fetchText, MAX_BYTES } = require('../src/decompiler/safe-fetch');
const clone = x => JSON.parse(JSON.stringify(x));
const modules = [{ name: 'alpha', content: 'const a = 1;' }, { name: 'tools/beta', content: 'const b = 2;' }];

test('validation and runnable reconstruction never invoke a VM evaluator', t => {
  t.mock.method(vm, 'createContext', () => { throw new Error('must not execute'); });
  t.mock.method(vm.Script.prototype, 'runInContext', () => { throw new Error('must not execute'); });
  const source = 'var a = 1; module.exports = {a};';
  const result = validateReconstruction(source, source);
  assert.equal(result.functionallyEquivalent, true);
  assert.equal(reconstructRunnable(source).code, source);
  assert.equal(vm.createContext.mock.callCount(), 0);
  assert.equal(vm.Script.prototype.runInContext.mock.callCount(), 0);
});
test('changed or throwing programs never receive a false equivalence pass', () => {
  assert.equal(checkFunctionalEquivalence('throw 1;', 'throw 2;').equivalent, null);
  assert.equal(validateReconstruction('module.exports = 1;', 'module.exports = 2;').functionallyEquivalent, null);
  assert.equal(reconstructRunnable('const = ;').runnable, false);
  const source = 'function f(undefined) { return void 0; } var x = "keep !0";';
  assert.equal(reconstructRunnable(source).code, source);
});
test('witness validates exact source and modules, including empty source', () => {
  const w = buildWitnessChain('', modules);
  const result = verifyWitnessChain(w, '', modules);
  assert.equal(result.valid, true);
  assert.equal(result.sourceVerified, true);
  assert.equal(result.modulesVerified, true);
  assert.equal(verifyWitnessChain(w).sourceVerified, false);
  assert.equal(verifyWitnessChain(w).modulesVerified, false);
  assert.equal(verifyWitnessChain(buildWitnessChain('x', modules), '', modules).valid, false);
});
test('witness rejects malformed schemas without throwing', () => {
  for (const input of [null, {}, { chain: [], root: 'anything' }, { version: 2 },
    { ...buildWitnessChain('', modules), module_hashes: [null] },
    { ...buildWitnessChain('', modules), chain: {} }]) {
    assert.equal(verifyWitnessChain(input).valid, false);
  }
});
test('witness binds names, order, topology and actual bytes', () => {
  const w = buildWitnessChain('source', modules);
  for (const mutate of [
    x => { x.module_hashes[0].name = 'renamed'; },
    x => { x.module_hashes.reverse(); },
    x => { x.chain[1].parent = x.root; },
    x => { x.chain.pop(); },
    x => { x.chain[1].label = 'forged'; },
    x => { x.module_hashes[1].name = x.module_hashes[0].name; },
    x => { x.algorithm = 'md5'; },
  ]) {
    const changed = clone(w); mutate(changed);
    assert.equal(verifyWitnessChain(changed, 'source', modules).valid, false);
  }
  const changed = clone(modules); changed[0].content += 'tampered';
  assert.equal(verifyWitnessChain(w, 'source', changed).valid, false);
  assert.throws(() => buildWitnessChain('', [modules[0], modules[0]]));
});
test('pipeline hashes final reconstructed output', () => {
  const source = 'var a = !0; var b = "preserved_value";';
  const result = decompileSource(source, { reconstruct: true, validate: true, useRust: false });
  assert.equal(verifyWitnessChain(result.witness, source, result.modules).valid, true);
});
test('custom pattern loads cannot poison default pattern cache', () => {
  const before = loadPatterns();
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'patterns-'));
  try {
    const filename = path.join(tmp, 'custom.json');
    fs.writeFileSync(filename, '[]');
    assert.deepEqual(loadPatterns(filename), []);
    assert.deepEqual(loadPatterns(), before);
    assert.ok(before.length > 0);
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});
test('remote inputs reject private addresses, credentials and unapproved hosts before fetching', async t => {
  const fetch = t.mock.method(global, 'fetch', () => { throw new Error('unexpected network call'); });
  for (const url of ['http://unpkg.com/x', 'https://127.0.0.1/x', 'https://[::1]/x',
    'https://169.254.169.254/', 'file:///etc/passwd', 'https://unpkg.com.evil.test/',
    'https://user:pass@unpkg.com/x', 'https://unpkg.com:8443/x', 'https://example.com/x']) {
    await assert.rejects(decompileUrl(url));
  }
  assert.equal(fetch.mock.callCount(), 0);
});
test('redirect destinations are revalidated', async t => {
  const fetch = t.mock.method(global, 'fetch', async () => new Response(null,
    { status: 302, headers: { location: 'http://169.254.169.254/' } }));
  await assert.rejects(fetchText('https://unpkg.com/x'), /approved/);
  assert.equal(fetch.mock.callCount(), 1);
});
test('approved relative redirects and body fetch work', async t => {
  let calls = 0;
  t.mock.method(global, 'fetch', async (url, opts) => {
    assert.equal(opts.redirect, 'manual');
    assert.ok(opts.signal instanceof AbortSignal);
    if (calls++ === 0) return new Response(null, { status: 302, headers: { location: '/x@1/index.js' } });
    assert.equal(url, 'https://unpkg.com/x@1/index.js');
    return new Response('const x = 1;');
  });
  assert.equal(await fetchText('https://unpkg.com/x'), 'const x = 1;');
});
test('redirect loops terminate after six responses', async t => {
  const fetch = t.mock.method(global, 'fetch', async () => new Response(null,
    { status: 302, headers: { location: '/again' } }));
  await assert.rejects(fetchText('https://unpkg.com/x'), /Too many/);
  assert.equal(fetch.mock.callCount(), 6);
});
test('oversized advertised and streamed bodies are rejected', async t => {
  t.mock.method(global, 'fetch', async () => new Response('small',
    { headers: { 'content-length': String(MAX_BYTES + 1) } }));
  await assert.rejects(fetchText('https://unpkg.com/x'), /32 MiB/);
  let cancelled = false;
  t.mock.method(global, 'fetch', async () => new Response(new ReadableStream({
    pull(controller) { controller.enqueue(new Uint8Array(1024 * 1024)); },
    cancel() { cancelled = true; },
  })));
  await assert.rejects(fetchText('https://unpkg.com/x'), /32 MiB/);
  assert.equal(cancelled, true);
});
test('deadline covers a stalled response body', async t => {
  t.mock.timers.enable({ apis: ['setTimeout'] });
  t.mock.method(global, 'fetch', async (_url, { signal }) => new Response(new ReadableStream({
    start(controller) { signal.addEventListener('abort', () => controller.error(new Error('aborted'))); },
  })));
  const pending = assert.rejects(fetchText('https://unpkg.com/x'), /aborted/);
  t.mock.timers.tick(30_000);
  await pending;
});
test('output rejects traversal, symlinks and overwrites; saved bytes match witness', () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'output-'));
  const result = { modules, metrics: {}, witness: buildWitnessChain('', modules) };
  try {
    const root = path.join(tmp, 'valid');
    writeOutput(result, root);
    const saved = modules.map((m, i) => ({ name: m.name, content: fs.readFileSync(
      path.join(root, i === 0 ? 'module-001-alpha.js' : 'tools/beta.js'), 'utf8') }));
    assert.equal(verifyWitnessChain(result.witness, '', saved).valid, true);
    assert.throws(() => writeOutput(result, root), /EEXIST/);
    for (const name of ['../escape', '/absolute', 'a/../../escape', 'bad\nname', 'a\\b']) {
      assert.throws(() => writeOutput({ ...result, modules: [{ name, content: '' }] }, path.join(tmp, 'invalid')));
    }
    const outside = path.join(tmp, 'outside'); fs.mkdirSync(outside);
    const linked = path.join(tmp, 'linked'); fs.symlinkSync(outside, linked);
    assert.throws(() => writeOutput(result, linked), /Unsafe/);
    const output = path.join(tmp, 'nested'); fs.mkdirSync(output);
    fs.symlinkSync(outside, path.join(output, 'tools'));
    assert.throws(() => writeOutput({ ...result, modules: [modules[1]] }, output), /Unsafe/);
    assert.deepEqual(fs.readdirSync(outside), []);
    const json = path.join(tmp, 'json'); fs.mkdirSync(json);
    const marker = path.join(tmp, 'marker'); fs.writeFileSync(marker, 'untouched');
    fs.symlinkSync(marker, path.join(json, 'decompiled.json'));
    assert.throws(() => writeOutput(result, json, 'json'), /EEXIST/);
    assert.equal(fs.readFileSync(marker, 'utf8'), 'untouched');
  } finally { fs.rmSync(tmp, { recursive: true, force: true }); }
});
