# Software factory control plane

This factory adds a Cloudflare UI, registration and durable orchestration around ruDevolution's reviewed clean-room handoff. It does not turn recovered source into an automatically approved replacement.

## What is connected

The Worker and schema implement the control plane. The Node adapter verifies a real dual-signed release using existing clean-room APIs. UI and job records describe work; they are not evidence of an independently implemented, tested or published product. Consult the deployment configuration for actual bindings and routes; missing infrastructure must remain a visible blocker.

Run the adapter tests from the repository root:

```sh
node --test factory/cleanroom-adapter.test.cjs
```

Prepare a dispatch from a trusted coordinator:

```js
const { createDispatchEnvelope } = require('./factory/cleanroom-adapter.cjs');
const dispatch = createDispatchEnvelope({
  released,                 // existing dual-signed release JSON
  signedRegistry,           // existing root-signed public registry JSON
  pinnedRootPublicKey,      // provisioned independently, never from the request
  minimumRevision: 7,       // operator's monotonic checkpoint, not caller-selected
});
```

The adapter returns an immutable `rudevolution.factory.cleanroom-dispatch/v1` envelope with `approvedContract`, `specSha256`, `approvalSha256`, `releaseSha256`, `registrySha256` and `registryRevision`. Its contract uses the existing constrained primitive grammar. It has no signing or publication API. The envelope itself is unsigned and must not be used as a substitute for Room B's verification of the original signed release and registry.

## Production setup still required

1. Provision separate Room A and Room B execution identities and environments. Do not share source repositories, model context, memories, vector indexes, logs, caches, secrets or mounts. An agent already exposed to reference source cannot become an independent implementer by starting another prompt.
2. Establish authorization to analyze the reference, independent reviewer procedures, key custody, a separately pinned public root and an anti-rollback registry checkpoint. Approve the narrow behavior contract through the existing two-reviewer workflow.
3. Transfer the approved signed release and public registry through the controlled handoff. Room B independently verifies them and uses the existing intake/scaffold workflow. Implement from the approved contract only.
4. Connect the independent authoring backend and isolated evaluator. Pin the container digest and policy; verify complete vector accounting, worker attestations and ledger continuity. The current evaluator isolates tests, not the authoring agent.
5. Connect the release backend with package-specific allowlists, minimal credentials, artifact digest reconciliation and failure receipts. The Cloudflare control plane does not currently publish npm/PyPI packages. Keep Product Hunt launches as unscheduled drafts.

Scheduling creates orchestration work only when its actual configured backend supports it. A scheduled event, UI transition or HTTP success is not a completed sweep. Report missing backends and failed gates explicitly; never replace reviewers with an automatic approval toggle.

See [ADR 144](../adr/ADR-144-cloudflare-software-factory.md), [clean-room guide](../clean-room/README.md) and [dual-reviewer pilot](../clean-room/E2E.md).
