'use strict';
const { performance } = require('node:perf_hooks');
const assert = require('node:assert/strict');
const os = require('node:os');
const current = require('../src/decompiler/reference-tracker');
const baseline = process.argv[2] ? require(require('node:path').resolve(process.argv[2])) : null;
function measure(fn, source, renames) {
  for (let i = 0; i < 2; i++) fn(source, renames);
  const samples = [];
  for (let i = 0; i < 7; i++) {
    const start = performance.now(); fn(source, renames); samples.push(performance.now() - start);
  }
  samples.sort((a, b) => a - b);
  return { medianMs: samples[3], p95Ms: samples[6], samples };
}
const rows = [];
for (const lines of [1000, 5000, 10000]) {
  const source = 'a = a + b; b = a + 1;\n'.repeat(lines);
  const renames = [{ oldName: 'a', newName: 'counter' }, { oldName: 'b', newName: 'total' }];
  const expected = 'counter = counter + total; total = counter + 1;\n'.repeat(lines);
  for (const api of ['applyRename', 'applyAllRenames']) {
    const run = impl => api === 'applyRename' ? (s => impl.applyRename(s, 'a', 'counter')) : impl.applyAllRenames;
    const actual = run(current)(source, renames);
    assert.equal(actual, api === 'applyRename' ? source.replace(/\ba\b/g, 'counter') : expected);
    if (baseline) assert.equal(actual, run(baseline)(source, renames));
    const after = measure(run(current), source, renames);
    const before = baseline ? measure(run(baseline), source, renames) : null;
    rows.push({ api, lines, inputBytes: Buffer.byteLength(source), before, after,
      speedup: before ? before.medianMs / after.medianMs : null });
  }
}
console.log(JSON.stringify({ node: process.version, platform: `${os.platform()} ${os.arch()}`,
  cpu: os.cpus()[0].model, warmups: 2, repeats: 7, workload: 'synthetic repeated assignments; output equality asserted', rows }, null, 2));
