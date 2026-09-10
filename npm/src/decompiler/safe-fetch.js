/** Bounded HTTPS retrieval from fixed public registries/CDNs, including redirects. */
'use strict';
const ALLOWED_HOSTS = new Set(['registry.npmjs.org', 'unpkg.com', 'cdn.jsdelivr.net', 'data.jsdelivr.com']);
const MAX_BYTES = 32 * 1024 * 1024;
const TIMEOUT_MS = 30_000;
function validateUrl(value) {
  const url = new URL(value);
  if (url.protocol !== 'https:' || url.username || url.password ||
      (url.port && url.port !== '443') || !ALLOWED_HOSTS.has(url.hostname)) {
    throw new Error('Remote input requires HTTPS on an approved npm registry or CDN host; use a local file for other sources');
  }
  return url;
}
async function fetchText(value) {
  let url = validateUrl(value);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    for (let redirects = 0; redirects <= 5; redirects++) {
      const response = await fetch(url.href, { redirect: 'manual', signal: controller.signal });
      if ([301, 302, 303, 307, 308].includes(response.status)) {
        await response.body?.cancel();
        if (redirects === 5) throw new Error('Too many redirects');
        const location = response.headers.get('location');
        if (!location) throw new Error('Redirect has no location');
        url = validateUrl(new URL(location, url));
        continue;
      }
      if (!response.ok) {
        await response.body?.cancel();
        throw new Error(`Remote fetch failed (HTTP ${response.status})`);
      }
      if (Number(response.headers.get('content-length')) > MAX_BYTES) {
        await response.body?.cancel();
        throw new Error('Remote input exceeds 32 MiB');
      }
      if (!response.body) return '';
      const reader = response.body.getReader();
      const chunks = [];
      let size = 0;
      try {
        while (true) {
          const { value: chunk, done } = await reader.read();
          if (done) break;
          size += chunk.byteLength;
          if (size > MAX_BYTES) throw new Error('Remote input exceeds 32 MiB');
          chunks.push(Buffer.from(chunk));
        }
      } catch (error) {
        await reader.cancel().catch(() => {});
        throw error;
      } finally { reader.releaseLock(); }
      return Buffer.concat(chunks, size).toString('utf8');
    }
  } finally { clearTimeout(timer); }
}
module.exports = { fetchText, validateUrl, MAX_BYTES, TIMEOUT_MS };
