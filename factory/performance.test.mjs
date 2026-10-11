import { test } from 'node:test';
import assert from 'node:assert/strict';
import { handle } from './worker.mjs';

test('public assets use content versions and conditional responses without caching API data', async () => {
  const origin = 'https://factory.example';
  const page = await handle(new Request(origin), {});
  const html = await page.text();
  assert.equal(page.headers.get('cache-control'), 'public, no-cache');
  assert.ok(page.headers.get('content-security-policy').includes("frame-ancestors 'none'"));
  for (const path of ['/style.css', '/app.js']) {
    const version = html.match(new RegExp(path.replace('.', '\\.') + '\\?v=([a-f0-9]{64})'))?.[1];
    assert.ok(version);
    const response = await handle(new Request(origin + path + '?v=' + version), {});
    assert.match(response.headers.get('cache-control'), /immutable/);
    assert.ok((await response.text()).length > 0);
    const etag = response.headers.get('etag');
    const cached = await handle(new Request(origin + path, { headers: { 'if-none-match': '"older", W/' + etag } }), {});
    assert.equal(cached.status, 304);
    assert.equal(await cached.text(), '');
    const stale = await handle(new Request(origin + path + '?v=obsolete'), {});
    assert.equal(stale.headers.get('cache-control'), 'public, no-cache');
    const head = await handle(new Request(origin + path, { method: 'HEAD' }), {});
    assert.equal(await head.text(), '');
    assert.equal(head.headers.get('etag'), etag);
  }
  const api = await handle(new Request(origin + '/api/session'), {});
  assert.equal(api.headers.get('cache-control'), 'no-store');
  assert.equal(api.headers.get('etag'), null);
});
