# ruDevolution Clean Room: reviewed interface handoff

**New:** [End to end dual reviewer pilot and registry/ledger operator guide](E2E.md). This extends the developer preview without replacing its explicit review and independent host requirements.

This is a **bounded developer preview** of an audited specification handoff. The workflow supports authorized behavioral analysis and independent implementation. It is *not* an automatic software cloning engine or a legal assurance of clean room independence.

> **Critical separation:** Room A may contain third-party original code and reviewer signing keys. Room B must never mount Room A data, repositories, private keys, execution logs, model context, retrieval indexes, or secrets. The new optional Docker runner restricts **evaluation of independently written Room B code**. It does **not** isolate the upstream coding agent, provision Room B hosts, or certify legal independence.

## Boundary

```text
                ROOM A                              ROOM B
  authorized behavior/spec review          fresh isolated OS identity
  reference, analysis, evidence            no original source, no shared memory
           |                                         ^
  reviewed interface-only spec             externally pinned public key
           |                                         |
  Ed25519 signature + local receipt                 |
           |                                         |
           +---------- approved.json -------------->+
                                                     |
                                            verify signed contract
                                                     |
                                            independent scaffold
                                                     |
                                       write implementation, run tests
```

The transfer contains only a small, strict JSON interface contract: named operations, primitive parameter and return types, enumerated errors and bounded input/output vectors. It excludes code bodies, recovered source, source maps, comments, free-text descriptions, ASTs, raw traces, evidence logs and signing keys. Human review and DLP remain necessary: **a constrained primitive can still encode a secret**.

## Quick start in separate controlled environments

Requires Node.js 22 or newer and OpenSSL. Use separate virtual machines or tightly configured containers with distinct service principals, unshared volumes, logs, credentials, model contexts and memory. Examples use filesystem paths for clarity; run the two room steps on different machines in production.

### Room A: authorized analysts and independent reviewers

Generate a dedicated signing key and store it in your restricted reviewer vault, never in git:

```bash
umask 077
openssl genpkey -algorithm Ed25519 -out reviewer-private.pem
openssl pkey -in reviewer-private.pem -pubout -out reviewer-public.pem
```

Place your *human-authored* interface-only `proposal.json` in a private Room A workspace. Use [the synthetic calculator contract](../../examples/clean-room/calculator.spec.json) for a public test. **Do not feed ruDevolution reconstructed source or decompiler output directly to the signer**.

```bash
node npm/src/clean-room/cli.js validate proposal.json
node npm/src/clean-room/cli.js approve proposal.json reviewer-private.pem reviewer.one approved-export.json reviewer-receipt.json --ack-reviewed
```

`--ack-reviewed` confirms a human independently inspected the contract against appropriate rights, provenance and disclosure policy. The flag itself is not human attestation. This command creates a signed export file plus a private receipt and refuses overwrites. Keep the receipt and private key in Room A.

Transfer **only `approved-export.json`** to Room B through your authorized, audited, one-way release process. Provision `reviewer-public.pem` independently as a trusted Room B key; never accept a public key copied from the same untrusted approval package without pinning it out of band.

### Room B: independent implementers

The following commands require only an approved artifact and an independently pinned public key:

```bash
node npm/src/clean-room/cli.js verify approved.json reviewer-public.pem
node npm/src/clean-room/cli.js scaffold approved.json reviewer-public.pem fresh-implementation
```

A new directory is required. The generated `implementation.mjs` deliberately throws `UNIMPLEMENTED`, so its contract tests initially fail. A separate implementer authors a new implementation **without any exposure to the reference code**:

```bash
cd fresh-implementation
node --test compat.test.mjs
```

Do not enable LLM agent tools that can read Room A knowledge, a shared RuVector index, a federation channel containing source material, private issues, or a contaminated conversation. Deploy RuFlo or MetaHarness with a dedicated Room B tenant and independent accounts if used for coordination or test automation.

## Optional Room B isolated evaluation

The new `sandbox-test` command enforces a narrow **evaluation-time** security boundary on Linux with a local Docker daemon. It does not run source from Room A, reconstruct third-party code, or create a clean room development machine. The independent implementation is still authored outside the test container and must come from a separately controlled Room B workspace.

**Prerequisites:** Linux, Docker with local `/var/run/docker.sock`, Node.js 22+, a private Room B worker host with no Room A data or credentials, and an **independently trusted** signing key. Access to the Docker daemon is privileged: use an isolated, operator-managed worker, not a general-purpose desktop shared with source analysts.

A Room B policy stored **outside** the signed handoff must pin all of the following:

```json
{
  "format": "rudevolution.cleanroom.policy/v1",
  "target": "calculator-compatibility",
  "reviewer": "reviewer.one",
  "publicKeyFingerprint": "<64 lowercase hex digits obtained from the independently trusted Ed25519 public key>",
  "runtimeImage": "node@sha256:<64 lowercase hex digits from your approved runtime image>",
  "expiresAt": "<future ISO UTC timestamp, for example 2026-12-31T00:00:00.000Z>",
  "maxApprovalAgeHours": 168
}
```

The placeholders above are intentionally **not usable** until the Room B operator supplies a real trusted key fingerprint, runtime digest and expiration. Never discover your trust anchor by trusting an unverified `approved.json` bundle. Pin the reviewer and image digest through your organization's independent approval process.

Retrieve the approved container image on the isolated worker **before** evaluation. A development smoke test can discover the digest of a fetched Node image:

```bash
docker pull node:22-alpine
docker image inspect node:22-alpine --format '{{index .RepoDigests 0}}'
```

For production, use a separately reviewed, patched image and independently pin its immutable digest in the Room B policy. The runner **refuses mutable image tags** and uses `--pull=never` to avoid fetching images while evaluating.

Run from the repository root, with the report destination **outside** the `fresh-implementation` scaffold:

```bash
node npm/src/clean-room/cli.js sandbox-test \
  approved.json \
  room-b-trusted-public.pem \
  room-b-policy.json \
  fresh-implementation \
  node@sha256:<approved-full-digest> \
  independent-evaluation-report.json
```

The command rechecks the signature, reviewer, target, age, policy expiration, key fingerprint and image digest **before** loading an implementation. It then requires the scaffold to contain exactly `APPROVAL.txt`, `contract.json`, `compat.test.mjs` and `implementation.mjs`. Only the last file may be edited. Unknown files, source maps, changed tests, symlinks, hardlinks and modified contracts are rejected.

The implementation runs in Docker with no container network, no elevated Linux capabilities, a read-only filesystem, an ephemeral `/tmp`, unprivileged UID 65534, CPU/memory/PID limits, and a single read-only mount containing **only three required files**. Neither Room A nor the original Room B project directory is mounted. The runner records a versioned JSON report with review, specification, policy, generated harness, implementation and image digests, verified vector counts, duration and hashed logs, without embedding raw execution logs.

If Docker is unavailable or the image is not locally present, the command fails rather than executing the implementation on the host. This is a defense-in-depth sandbox, not a mathematical noninterference proof or a substitute for independent implementation workflows.

For an end-to-end Linux smoke test using Docker, run:

```bash
RUDEVOLUTION_TEST_IMAGE='node@sha256:<locally-loaded-full-digest>' \
  node --test npm/test/clean-room-docker.test.js
```

The CI workflow derives a real digest and runs this integration test. Without that environment variable, the Docker test is skipped; policy, staging, malicious-file and cleanup tests still run locally.

See [ADR 141](../adr/ADR-141-room-b-isolated-evaluation.md) for the threat model and explicit runtime controls. The Docker flags correspond to documented options in [Docker run](https://docs.docker.com/reference/cli/docker/container/run), [bind mounts](https://docs.docker.com/engine/storage/bind-mounts/), and [tmpfs](https://docs.docker.com/engine/storage/tmpfs/).

## Verified-vector harness and signed Room B evidence

**Security fix:** Earlier scaffolds imported independent implementation code directly into the Node test runner before tests registered. An implementation containing only `process.exit(0)` could therefore cause a successful process exit without running any approved vectors. The hardened scaffold launches **one short-lived subprocess per approved vector**. Each child receives a single primitive call and must return one well-formed JSON result; the trusted parent checks the result. The Docker evaluator separately requires a complete TAP summary matching every vector, with no skips, failures or cancellations. Its report uses `rudevolution.cleanroom.sandbox-report/v2` and records `executedVectors`, `passedVectors`, and digests of both the approved policy and generated harness.

**Migration:** Existing Room B scaffolds do not have the hardened test runner and are intentionally rejected by the isolated evaluator. Create a fresh directory with `scaffold` using the same approved artifact and the independently pinned public key. Independently review and copy only your **Room B authored** implementation into the fresh scaffold. Do not copy old test scripts or third-party reference material.

An evaluator report may optionally be **signed by a separate Room B worker key** on the host after container termination. The worker key must be provisioned and protected independently from the Room A review key and must never be mounted in the test container. Generate a dedicated key in the isolated Room B signing environment:

```bash
umask 077
openssl genpkey -algorithm Ed25519 -out room-b-worker-private.pem
openssl pkey -in room-b-worker-private.pem -pubout -out trusted-worker-public.pem
```

Add the attestation arguments after the usual six evaluation inputs:

```bash
node npm/src/clean-room/cli.js sandbox-test \
  approved.json room-b-trusted-public.pem room-b-policy.json \
  fresh-implementation 'node@sha256:<approved-full-digest>' \
  evaluation-report.json \
  --attest room-b-worker-private.pem worker-one signed-evaluation.json
```

This writes an ordinary v2 evaluation report and a separately signed `rudevolution.cleanroom.evaluation-attestation/v1` envelope. Verify it with a public key obtained **out of band**, the expected worker identifier and the SHA256 of the independently approved artifact:

```bash
node npm/src/clean-room/cli.js verify-attestation \
  signed-evaluation.json trusted-worker-public.pem worker-one \
  <expected-approval-sha256>
```

Signatures bind the report bytes, approved artifact digest, image digest, implementation hash, policy digest, harness digest and recorded vector counts. They **do not attest** that the host ran unmodified software, that the implementation was independently authored, or that the replacement is legally permissible. The current signer does not use a hardware-backed or remote attestation service. Use a separate trusted Room B signing host and an external key lifecycle/revocation policy for higher assurance.

The v2 harness tests approved primitive call results independently. It cannot establish untested behavior, stateful equivalence, secret-independent development or immunity to malicious implementations that deliberately return memorized public test vectors.


## Reproducible smoke test

```bash
npm test
node --test npm/test/clean-room.test.js
```

The regression and Docker fixtures place a synthetic proprietary marker in a Room A-only file, signs a separately authored spec, verifies tamper rejection, and asserts the marker is absent from transferred/Room B artifacts. It also demonstrates expected failing tests from unimplemented stubs followed by passing tests for an independently supplied fixture implementation. That is a practical regression, not a proof that arbitrary permitted strings cannot carry secrets.

## Threats, decisions and next gates

* [ADR 139: Isolation and specification firewall](../adr/ADR-139-clean-room-isolation-and-specification-firewall.md)
* [ADR 140: Signed approvals and compatibility evidence](../adr/ADR-140-clean-room-attestation-and-compatibility-evidence.md)
* [ADR 141: Isolated Room B evaluation and pinned trust](../adr/ADR-141-room-b-isolated-evaluation.md)
* [ADR 143: Two room end to end pilot](../adr/ADR-143-cleanroom-end-to-end-pilot.md)
* [Prior security review](../reviews/2026-09-security-performance.md)

Before using third-party software, document authorization and obtain legal review. This command's sandbox does not guarantee the authoring agent is uncontaminated. Before claiming a **production** clean room deployment, validate OS isolation, access controls, audit retention, no shared model context, key custody, a red-team test for covert vector transfer, and independent reviewer procedures. For software compatibility, separate observable behavior from implementation details and report fixture coverage honestly.
