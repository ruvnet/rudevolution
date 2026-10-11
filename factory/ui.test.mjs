import { test } from 'node:test';
import assert from 'node:assert/strict';
import vm from 'node:vm';
import { createRunRequester, html, js } from './ui.mjs';

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

function browserHarness(handler) {
  const nodes = new Map();
  const calls = [];
  const get = id => { if (!nodes.has(id)) nodes.set(id, { hidden: true, textContent: '', value: '', disabled: false, events: {}, classList: { toggle() {} }, addEventListener(name, callback) { this.events[name] = callback; }, replaceChildren() {}, append() {} }); return nodes.get(id); };
  const context = vm.createContext({ document: { getElementById: get, createElement: () => ({ classList: { toggle() {} }, append() {} }) }, fetch: async (path, options = {}) => { calls.push({ path, options }); const result = await handler(path, options); return { ok: (result.status || 200) < 400, status: result.status || 200, headers: { get: () => 'application/json' }, json: async () => result.body }; }, console });
  vm.runInContext(js, context);
  return { get, calls, settle: () => new Promise(resolve => setImmediate(resolve)) };
}

test('both Start free calls to action lead to Cloudflare sign-in and free limits are explicit', () => {
  assert.equal((html.match(/class="start-free[^"]*" href="\/login"/g) || []).length, 2);
  assert.match(html, /1 project · 1 run request every 24 hours · No credit card/);
  assert.match(html, /Creating a request does not provision build resources or publish software/);
});

test('verified visitor can create free workspace; upgrade records interest without changing plan', async () => {
  let registered = false;
  const harness = browserHarness(async (path, options) => {
    if (path === '/api/session') return { body: { user: { email: 'maker@example.com' }, registered, plan: 'free', limits: { projects: 1, runs_per_24h: 1 }, usage: { projects: 0, runs_last_24h: 0 } } };
    if (path === '/api/register') { registered = true; return { body: { user: { id: 'u', email: 'maker@example.com' } } }; }
    if (path === '/api/projects') return { body: { projects: [] } };
    if (path === '/api/runs') return { body: { runs: [] } };
    if (path === '/api/upgrade') { assert.equal(JSON.parse(options.body).message, 'Need more projects'); return { status: 201, body: { request: { id: 'request-one', status: 'requested' } } }; }
    return { body: { ok: true } };
  });
  await harness.settle();
  assert.equal(harness.get('registration').hidden, false);
  assert.equal(harness.get('upgrade').disabled, true);
  await harness.get('register').events.click();
  assert.equal(harness.get('registration').hidden, true);
  assert.equal(harness.get('project-fields').disabled, false);
  assert.equal(harness.get('plan-label').textContent, 'Free workspace');
  harness.get('upgrade-message').value = 'Need more projects';
  await harness.get('upgrade').events.click();
  assert.equal(harness.get('notice').textContent, 'Request saved. No charge or plan change.');
  assert.equal(harness.get('plan-label').textContent, 'Free workspace');
  assert.equal(harness.calls.filter(call => call.path === '/api/upgrade').length, 1);
  assert.equal(harness.calls.filter(call => call.path === '/api/session').length, 2, 'registration refresh reuses its verified session');
});

test('failed upgrade does not claim success and displays server text without HTML injection', async () => {
  const message = '<img src=x onerror=alert(1)> Try again later';
  const harness = browserHarness(async path => {
    if (path === '/api/session') return { body: { user: { email: 'maker@example.com' }, registered: true, plan: 'free' } };
    if (path === '/api/projects') return { body: { projects: [] } };
    if (path === '/api/runs') return { body: { runs: [] } };
    if (path === '/api/upgrade') return { status: 503, body: { error: message } };
    return { body: {} };
  });
  await harness.settle();
  await harness.get('upgrade').events.click();
  assert.equal(harness.get('notice').textContent, message);
  assert.equal(harness.get('notice').innerHTML, undefined);
  assert.equal(harness.get('plan-label').textContent, 'Free workspace');
  assert.equal(harness.get('upgrade').disabled, false);
});
