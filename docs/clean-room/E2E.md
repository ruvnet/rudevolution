# Clean Room End to End Pilot

This is a **synthetic, permissioned interoperability pilot**, not an automatic cloning tool or legal certification. The new optional operator CLI verifies both Room A reviewers, enforces an independently signed key registry, creates a minimal Room B project, runs its independently written code in Docker, signs the result and maintains a hash-chained evidence ledger.

The original decompiler is never imported into Room B.

## Architectural boundary

~~~text
Room A: authorized reference and human-reviewed interface
    |
    v
Primary Ed25519 approval
    |
    v
Second reviewer signature + known-source marker screening
    |
    +-----> signed release.json (only approved transfer)
               |
               v
Room B: independent root public key + signed registry + revision floor
               |
               v
Verify BOTH signatures, key roles, expiry and revocation
               |
               v
Generate 4-file independent scaffold
               |
               v
Independent author (no Room A access or shared memory)
               |
               v
Offline, restricted Docker compatibility evaluation
               |
               v
Separate worker Ed25519 signature
               |
               v
Append digests and status to ledger using EXTERNAL expected head
~~~

**Production warning:** The test runs on a disposable GitHub runner and uses a deterministic, synthetic author. It does not prove VM or cloud tenant separation for a real coding agent. For protected source, provision separate Room A and Room B hosts, accounts, GitHub access, prompt stores, RuFlo/Federation routing, RuVector memory and audit logs. Never let the independent author read the analyzer's data or state.

## Required operators and prerequisites

Use Node 22 or 24. Room B evaluation requires local Docker with a separately reviewed Node runtime pinned by immutable digest. Maintain three different Ed25519 roles: offline registry root, primary/secondary Room A reviewers, and a distinct Room B worker signing identity. Signing keys require owner-only filesystem permissions, and should be held in separate operator vaults.

### 1. Sign a fresh registry in the offline trust domain

The root officer prepares registry.json as shown below. Public keys are actual Ed25519 PEM text, not placeholders, and must correspond to independently established identities.

~~~json
{
  "format": "rudevolution.cleanroom.registry/v1",
  "revision": 14,
  "issuedAt": "2026-10-09T12:00:00.000Z",
  "expiresAt": "2026-10-10T12:00:00.000Z",
  "keys": [
    {
      "id": "primary.one", "role": "primary",
      "publicKey": "<approved Ed25519 PEM>",
      "validFrom": "2026-10-09T00:00:00.000Z",
      "validUntil": "2026-10-10T12:00:00.000Z", "revokedAt": null
    },
    {
      "id": "secondary.two", "role": "secondary",
      "publicKey": "<different Ed25519 PEM>",
      "validFrom": "2026-10-09T00:00:00.000Z",
      "validUntil": "2026-10-10T12:00:00.000Z", "revokedAt": null
    },
    {
      "id": "worker-one", "role": "worker",
      "publicKey": "<different worker Ed25519 PEM>",
      "validFrom": "2026-10-09T00:00:00.000Z",
      "validUntil": "2026-10-10T12:00:00.000Z", "revokedAt": null
    }
  ]
}
~~~

~~~bash
node npm/src/clean-room/pilot-cli.js registry-sign \
  registry.json registry-root-private.pem registry.signed.json
~~~

Revocation is a new root-signed revision with a revokedAt timestamp. Room B must obtain the updated registry through its independently controlled trust channel and raise its minimum accepted revision. An older signed registry cannot detect its own revocation.

### 2. Room A two-person review and disclosure controls

An authorized analyst writes the narrow interface specification. A primary reviewer approves it using the existing CLI. A **different human** reviews the proposal, signatures, purpose, rights and disclosure constraints and executes the secondary release step.

The optional restricted-markers.json remains in Room A and is **not** transferred. It contains known protected strings used as denylist sentinels. This scanner also rejects simple hex/base64 encodings and suspicious opaque scalars; it cannot guarantee absence of steganography in valid numbers or strings.

~~~bash
node npm/src/clean-room/cli.js approve \
  proposal.json primary-private.pem primary.one \
  approved.json room-a-receipt.json --ack-reviewed

node npm/src/clean-room/pilot-cli.js release \
  approved.json primary-public.pem secondary-private.pem \
  secondary.two release.json --ack-independent restricted-markers.json
~~~

Only the new release.json file crosses into Room B. The acknowledgement flags are auditable procedural assertions, not proof of human presence. Do not automatically turn ruDevolution decompiled output into a release.

### 3. Room B intake with separate trust anchor

Provision signed-registry.json, a trusted root public key, and the minimum revision through a controlled channel distinct from the release. This operator-controlled revision is a rollback defense; do not select it from untrusted metadata.

~~~bash
node npm/src/clean-room/pilot-cli.js verify-release \
  release.json registry.signed.json pinned-root-public.pem 14

node npm/src/clean-room/pilot-cli.js intake \
  release.json registry.signed.json pinned-root-public.pem 14 \
  independent-project
~~~

Intake creates exactly four scaffold files. Only implementation.mjs is edited. Implementers must work on a separate Room B machine with no Room A credentials, shared model context, prompt cache or retrieval index.

### 4. Evaluate and checkpoint

Keep policy.json outside the implementation directory. It independently pins the approved primary reviewer key fingerprint, immutable Docker image digest, target and expiry, as described in the [base handoff guide](README.md).

~~~bash
node npm/src/clean-room/pilot-cli.js evaluate \
  release.json registry.signed.json pinned-root-public.pem 14 \
  policy.json independent-project \
  'node@sha256:<pinned-runtime-digest>' \
  worker-private.pem worker-one evidence.jsonl \
  '<prior-external-64-hex-ledger-head>' \
  evaluation-report.json signed-evaluation.json

node npm/src/clean-room/pilot-cli.js verify-evidence \
  signed-evaluation.json trusted-worker-public.pem worker-one \
  '<approved-artifact-sha256>' evidence.jsonl \
  '<new-external-64-hex-ledger-head>'
~~~

For an empty ledger the prior head is exactly 64 zero characters. After evaluation, record the NEW head in an independent, access controlled checkpoint such as an immutable object or audit service. Every later append must supply the previously recorded head; reverting the ledger then fails.

The evidence ledger is a local exclusive-lock, fsync-backed, hash-chained JSONL file storing digests, status and sequence only. It is not write-once media, a trusted timestamp or proof of a safe host. A signature authenticates the Room B worker key, not software authorship or complete semantic equivalence.

### 5. Negative acceptance and key revocation

Set revokedAt on a reviewer or worker, increment the registry revision, sign it with the same independent root key and update Room B's trusted registry and revision floor. Reusing the old release must fail before creation of any implementation worktree or new Docker evaluation.

~~~bash
npm run test:cleanroom
npm test
~~~

The full synthetic end to end Docker test runs automatically in CI. Locally it is enabled with an already-pulled immutable image:

~~~bash
RUDEVOLUTION_TEST_IMAGE='node@sha256:<locally-available-image-digest>' \
  node --test npm/test/clean-room-e2e-docker.test.js
~~~

The Docker test checks unique Room A source markers never enter Room B, B authoring has no network or Room A mount, public compatibility vectors all execute, signed results verify, tampered ledgers fail and a revoked reviewer blocks further intake.

## Production acceptance is still separate

The pilot does not provision separate cloud service principals, block a malicious provider with shared model memory, attest the authoring host, enforce key revocation against stale independently pinned registries, provide general DLP or test held-out asynchronous/stateful protocols. Two person review and legal authorization must be independently established.

For the architectural threat model see [ADR 143](../adr/ADR-143-cleanroom-end-to-end-pilot.md) and the production gates in [core-memory issue 148](https://github.com/ruvnet/core-memory/issues/148).
