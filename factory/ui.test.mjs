import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { createRunRequester, js } from './ui.mjs';

function storage() {
  const values = new Map();
  return { getItem: key => values.get(key) ?? null, setItem: (key, value) => values.set(key, value), removeItem: key => values.delete(key) };
}

test('an uncertain run request keeps its key across page reload and clears only after acknowledgement', async () => {
  const saved = storage();
  const requests = [];
  const first = createRunRequester({ storage: saved, randomUUID: () => 'first-key', send: async payload => { requests.push(payload); throw new Error('Connection lost after server commit'); } });
  await assert.rejects(first('project-one'), /Connection lost/);
  const second = createRunRequester({ storage: saved, randomUUID: () => 'second-key', send: async payload => { requests.push(payload); return { run: { id: 'existing-run' } }; } });
  await second('project-one');
  assert.equal(requests[0].idempotency_key, requests[1].idempotency_key);
  await second('project-one');
  assert.equal(requests[2].idempotency_key, 'second-key');
});

test('project keys are independent and malformed acknowledgement cannot clear a pending request', async () => {
  const saved = storage(); let serial = 0; const requests = [];
  const request = createRunRequester({ storage: saved, randomUUID: () => String(++serial), send: async payload => { requests.push(payload); return {}; } });
  await assert.rejects(request('one'), /acknowledgement missing/);
  await assert.rejects(request('two'), /acknowledgement missing/);
  await assert.rejects(request('one'), /acknowledgement missing/);
  assert.deepEqual(requests.map(item => item.idempotency_key), ['1', '2', '1']);
});

test('storage failure prevents sending a run without a durable retry key', async () => {
  let sent = false;
  const request = createRunRequester({ storage: { getItem: () => null, setItem: () => { throw new Error('Storage unavailable'); } }, randomUUID: () => 'key', send: async () => { sent = true; } });
  await assert.rejects(request('one'), /Storage unavailable/);
  assert.equal(sent, false);
});

test('actual browser script exposes sign-in after JSON 401', async () => {
  const nodes = new Map();
  const get = id => { if (!nodes.has(id)) nodes.set(id, { hidden: true, textContent: '', disabled: false, classList: { toggle() {} }, addEventListener() {} }); return nodes.get(id); };
  const context = vm.createContext({ document: { getElementById: get }, fetch: async () => ({ ok: false, status: 401, headers: { get: () => 'application/json' }, json: async () => ({ error: 'Access authentication required' }) }), console });
  vm.runInContext(js, context);
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(get('login').hidden, false);
  assert.equal(get('project-fields').disabled, true);
  assert.match(get('notice').textContent, /Sign in with Cloudflare Access/);
});
