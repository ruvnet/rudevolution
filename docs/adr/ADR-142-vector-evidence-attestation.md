# ADR 142: Vector execution accounting and signed Room B evidence

Status: Accepted for clean room developer preview
Date: 2026-10-08
Dependencies: ADR 139, ADR 140, ADR 141

## Problem and observed failure

The prior generated `compat.test.mjs` imported `implementation.mjs` before registering the `node:test` vectors. An implementation containing only `process.exit(0)` could cause `node --test` to exit successfully without executing any approved compatibility vector. The v1 Docker evaluator treated exit code zero as success, so a malformed or adversarial Room B implementation could receive a passing report with no test evidence.

The signed specification handoff was not compromised; the failure was **untrusted implementer code controlling the test-harness lifecycle**. It also demonstrated why an exit code, successful harness startup, or self-reported result is not sufficient provenance.

The evaluator report also consisted of unsigned JSON. An operator or downstream process could alter counts, implementation digest or outcome without cryptographic detection.

## Decision

1. **Isolated vector subprocesses.** The trusted test runner never directly imports independent code. It reads the approved contract, verifies the contract hash, registers one test for each approved vector, then launches an individual short-lived Node subprocess that imports and calls one implementation operation. The untrusted child has a bounded input payload, isolated environment, 2-second timeout and 4 KiB output limit. It must emit exactly one primitive JSON outcome.
2. **Fail closed on premature exit.** `process.exit(0)`, forged TAP output, missing exports, malformed JSON, unexpected output, signals and timeouts cannot short circuit the parent test runner. The parent fails the corresponding vector.
3. **Independent counter verification.** After Docker exits, the host requires a complete Node TAP footer with exact `tests == pass == approved-vector-count`, and `fail == cancelled == skipped == todo == 0`. A zero exit code with absent, duplicate or incomplete counters becomes a failed evaluation.
4. **Versioned report.** `rudevolution.cleanroom.sandbox-report/v2` includes `executedVectors`, `passedVectors`, `policySha256`, and `harnessSha256`. These complement the existing approval, specification, implementation, runtime image and output-log hashes. Old unverified v1 reports are not silently promoted to v2.
5. **Optional worker-signed attestation.** After verified isolated execution and Docker cleanup, a separate Room B private Ed25519 key signs a canonical, domain-separated report commitment. The associated `rudevolution.cleanroom.evaluation-attestation/v1` envelope binds worker ID, signing time, report digest and public-key fingerprint. Independent verification requires an out-of-band trusted worker public key and expected approval digest.
6. **No original-source transfer.** Neither original source, analyst receipts, signer keys nor Room A knowledge are mounted in the isolated test container. The additional signing key resides only on the operator-controlled Room B host.

## Invariants

* **CR-10:** Every passing evaluation must have a matching count of actually registered and successful approved vectors.
* **CR-11:** Untrusted implementation code cannot terminate the trusted test parent via `process.exit(0)` in its own evaluation subprocess.
* **CR-12:** Signed evidence rejects modification of measured outcome, vector counts, approved-spec identity, implementation hash, harness hash, policy hash, runtime image and signing metadata.
* **CR-13:** The Room B worker attestation key is distinct from the independent Room A reviewer key, and never crosses the Docker mount boundary.

## Evidence limits

* These tests cover declared primitive operations and approved vectors, **not** complete API compatibility. Implementations can hardcode public vectors and still pass.
* The child subprocess shares the container's PID/user isolation domain. A malicious implementation may send signals to sibling processes. The report requires a trusted vector footer to pass, but this is not equivalent to process isolation across users, virtual machines or TEE attestation.
* Every vector starts a fresh child process, so the harness does not model cross-call state, session semantics, persistent storage, concurrency or performance.
* An Ed25519 evidence signature authenticates the signing key and the stated report bytes, not the honesty or integrity of the host evaluator. Host compromise or misuse of the worker signing key can yield a signed false claim.
* The initial protocol accepts only small primitive vectors. The signed contract can still carry covertly encoded information, so human review, DLP and legal authorization remain mandatory.
* Existing Room B scaffold test runners must be regenerated from an already approved artifact before the v2 evaluator can accept them. Only independently authored implementation code should be retained.

## Tests and promotion gate

From a clean checkout:

```bash
npm run test:cleanroom
npm test
```

The suite includes negative tests for premature exit, forged TAP, incomplete reports, modified signatures, forged worker identifiers, changed implementation hashes and wrong signing keys. The dedicated CI job runs an actual Docker implementation and checks the v2 counts and host signature. Local runs without a pinned Docker image intentionally skip the container smoke test.

### Acceptance

A synthetic `process.exit(0)` implementation must fail with zero verified vectors, while an independently supplied synthetic implementation passes all approved vectors. A modified signed outcome must fail independent worker-key verification. Node 22/24, Rust, dashboard and the Docker worker must pass CI before merge.

### Rollback

If optional evidence signing fails, disable only the signing mode while preserving the v2 subprocess harness and vector-accounting gate. **Do not revert to pre-v2 direct implementation import or exit-code-only pass criteria.** Revoke an exposed worker key through the organization's external trust system.
