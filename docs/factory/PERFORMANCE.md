# Delivery and engagement improvements

2026-10-11

## Measured behavior

Public HTML, CSS and JavaScript now have content derived SHA-256 validators, computed once per Worker isolate. Conditional requests return 304 with zero body bytes instead of downloading unchanged content. Correct content version URLs use a one year immutable policy; unversioned or incorrect versions revalidate. HTML revalidates on every use so a deployment points to its current assets. API responses remain no-store with no ETag.

Local response check: HTML 12,407 bytes, CSS 8,169 bytes, JavaScript 8,383 bytes. An unchanged conditional visit transfers zero representation body bytes instead of 28,959 bytes. HTTP headers, TLS, network requests and browser overhead still exist. This is body transfer reduction, not a measured latency improvement or CDN hit rate.

Registered startup reuses the verified session response: five startup requests become four including health, a 20 percent request reduction. Token signature verification remains per authenticated request. No identity, role or quota caching was introduced.

## Engagement

Visitors can try the shipped README Proof package before registration using a pinned version and inspect its release evidence. The hero identifies developers building CLI, MCP and library integrations. Social metadata describes the same bounded outcome. No social posts, fake popularity, vote requests or tracking scripts were added. Product Hunt stays draft-only.

## Risk and rollback

Immutable caching applies only when the requested version equals the current asset hash. Prior deployment versions fall back to revalidation. Authenticated endpoints cannot enter the public asset map. Roll back the Worker modules together. Public signup through authorized publication still needs live evidence before launch.

## Acceptance

Run npm run test:factory. Verify HTML references content version URLs, CSS/JS correct versions are immutable, stale versions revalidate, conditional public requests return empty 304 responses, API responses remain no-store, and registration does not duplicate its session request. Confirm both registration CTAs and the local example remain usable.

Reference: https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Caching
