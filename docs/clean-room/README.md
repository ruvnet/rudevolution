# ruDevolution Clean Room: reviewed interface handoff

This is a **bounded developer preview** of an audited specification handoff. The workflow supports authorized behavioral analysis and independent implementation. It is *not* an automatic software cloning engine or a legal assurance of clean room independence.

> **Critical separation:** Room A may contain third-party original code and reviewer signing keys. Room B must never mount Room A data, repositories, private keys, execution logs, model context, retrieval indexes, or secrets. The CLI checks signed artifacts, but **does not create that isolation for you**.

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

## Reproducible smoke test

```bash
npm test
node --test npm/test/clean-room.test.js
```

The regression fixture places a synthetic proprietary marker in a Room A-only file, signs a separately authored spec, verifies tamper rejection, and asserts the marker is absent from transferred/Room B artifacts. It also demonstrates expected failing tests from unimplemented stubs followed by passing tests for an independently supplied fixture implementation. That is a practical regression, not a proof that arbitrary permitted strings cannot carry secrets.

## Threats, decisions and next gates

* [ADR 139: Isolation and specification firewall](../adr/ADR-139-clean-room-isolation-and-specification-firewall.md)
* [ADR 140: Signed approvals and compatibility evidence](../adr/ADR-140-clean-room-attestation-and-compatibility-evidence.md)
* [Prior security review](../reviews/2026-09-security-performance.md)

Before using third-party software, document authorization and obtain legal review. Before claiming a **production** clean room deployment, validate OS isolation, access controls, audit retention, no shared model context, key custody, a red-team test for covert vector transfer, and independent reviewer procedures. For software compatibility, separate observable behavior from implementation details and report fixture coverage honestly.
