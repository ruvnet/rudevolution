# ADR 144: Cloudflare software factory control plane

Status: Implemented control-plane foundation; independent execution and publication backends remain unconnected.

## Context

ruDevolution already has interface-only specifications, two distinct reviewer signatures, a root-signed trust registry with rollback checkpoints, isolated evaluation and signed evidence. A daily software factory needs a registration UI and durable job state without collapsing the two-room boundary into a shared agent conversation.

## Decision

Use Cloudflare for the factory UI and job control plane. Treat registration as an application for access, not proof of identity, permission to execute code, or authorization to release packages. Authenticated operator actions and configured infrastructure are separate gates. The scheduled path may record work awaiting a backend; it must never fabricate successful implementation, tests, optimization, publication or clean-room verification.

Keep the existing clean-room verifier authoritative. `factory/cleanroom-adapter.cjs` runs on a trusted Node coordinator and calls `verifyRegistry` and `verifyRelease`. It requires an independently pinned root public key and explicit minimum registry revision, checks both reviewer signatures and freshness, and emits only the approved primitive contract and its approval/release/registry digests. No source code, decompiler output, AST, free-text instructions, logs, credentials or signing keys are dispatched.

The output is unsigned routing data, not a new attestation. Room B independently receives the existing signed release and signed registry through the controlled handoff and re-verifies them against its own trust anchor before intake. An HTTP field asserting `verified` is never equivalent to this verification. Cloudflare registration or a successful queue write cannot unlock release approval.

## Production boundaries

Room A and Room B require independent hosts or equivalently enforced environments, service identities, storage, model sessions, retrieval indexes, logs, caches and credentials. Room B agents must never have seen Room A source or analysis. The operator provisions the root trust anchor, monotonic revision checkpoint, reviewer key custody, pinned runtime image, Room B policy and worker signer independently of submitted work.

The implementation in this change does not provision those environments or attest source independence. The Docker runner isolates evaluation only. The existing [pilot](../clean-room/E2E.md) remains the supported reference for verified intake, evaluation and ledger evidence. Independent authoring agents and package publication need explicit backends, their own least-privilege identities, result verification and immutable artifact reconciliation before unattended releases can be claimed.

Product Hunt promotion remains draft-only. Package publishing authorization does not authorize a Product Hunt launch.

## Validation and consequences

Adapter tests generate real independent Ed25519 keys and signatures over the existing synthetic calculator fixture. They test accepted handoff, tampering, source-bearing extra fields, missing review, wrong root, rollback, revocation, expiration and payload limits. These tests verify the transfer gate; they do not demonstrate production host separation, implementer independence or a published package.

The initial deployment can demonstrate UI, registration and durable orchestration state. A complete software factory additionally requires independently provisioned agents and verified execution, benchmark, media and release adapters. Until connected, state must communicate that work is pending or blocked.
