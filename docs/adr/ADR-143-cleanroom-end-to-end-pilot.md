# ADR 143: Two room synthetic interoperability pilot

Status: Implemented as an opt-in developer pilot, not production accreditation
Date: 2026-10-09
Depends on: ADR 139, 140, 141, 142

## Decision

Extend the existing signed specification handoff and isolated evaluator with a root-signed reviewer registry, independent second approval, one-way transport, constrained disclosure checks and a hash-chained audit ledger.

1. Room A performs authorized static analysis. A human writes a bounded interface-only proposal. The primary Ed25519 reviewer explicitly approves it using the existing CLI.
2. A different secondary reviewer signs a domain-separated release commitment. The signers and signer keys must differ. Room A applies restricted-marker disclosure checks, including simple encoded equivalents and high-entropy scalar rejection. Reviewer acknowledgement is a procedural assertion, not cryptographic proof of a human review.
3. An independently managed root Ed25519 private key signs a versioned trust registry containing public reviewer/worker keys, role scopes, validity, revocation timestamps and expiry. Room B independently provisions the root PUBLIC key and a minimum acceptable registry revision. Registry rollback, expiration, or current revocation fail closed.
4. Only the approved release is transferred from Room A. Room B verifies the registry and both signatures before creating any scaffold. It receives no reference code, recovered AST, raw traces, private keys, agent memory or source map.
5. Room B authoring is independent of Room A. In CI, a synthetic fixture author runs inside a restricted Docker container with no network, a contract-only mount and a distinct unprivileged process identity. This tests authoring-stage isolation, NOT separate production hosts.
6. The existing offline Docker evaluator accepts only an independently authored implementation and validated harness/contract. It requires complete vector accounting, rejects early successful exit, and stages only three files.
7. A distinct worker Ed25519 key signs the v2 evaluation report. A bounded local JSONL hash chain stores only approval/release/registry/evaluation digests and status. Every append requires an external expected ledger head. An independent checkpoint must be maintained outside the mutable file.
8. An incremented root-signed registry revocation must block old releases and workers once the independent minimum revision is raised.

## Security invariants

CR-14: The only Room A to Room B payload is the signed, schema validated two-person release.

CR-15: The Room B root public key and minimum registry revision are supplied independently and never accepted from an untrusted release.

CR-16: Reviewer identities, reviewer signing keys and the worker signing key are pairwise distinct and role scoped.

CR-17: The CI authoring container mounts no Room A source, keys, shared agent memory, vector index or repository.

CR-18: Every ledger append verifies an active reviewer release, active worker signing role and a valid signed v2 result against a separately anchored prior head.

CR-19: Restricted plaintext, common base64/hex encodings and obvious opaque scalar values fail the Room A transfer scanner. This is a limited check, not general steganographic prevention.

CR-20: No original source or root/reviewer/worker private signing key enters the evaluation container.

## Trust domains

| Domain | Allowed materials | Forbidden materials |
| --- | --- | --- |
| Room A analyst | Authorized original source and local analysis evidence | Room B implementation write identity |
| Primary and secondary reviewers | Human-reviewed interface and separate private reviewer keys | Room B authoring state or worker signing key |
| Offline trust officer | Public key roster and root private signing key | Default app runtime and shared AI memory |
| Room B author | Reviewed public contract and independent workspace | Original source, Room A prompts/logs/repos/retrieval/credentials |
| Room B evaluator | Signed release, independently pinned root key, restricted policy, own worker key | Original source or arbitrary Room A artifacts |
| External auditor | Signed outcome, root public trust anchor, independently anchored ledger head | All private keys and original source |

## Validation and residual boundaries

Unit tests cover registry tampering, dual approval, source marker disclosure, revoked reviewer/worker, rollback floor, symlink/overwrites, and evidence hash chain tampering.

An independent GitHub Actions job additionally runs a synthetic full workflow using a real offline Docker authoring process, followed by the hardened isolated Docker compatibility evaluator and verified signed worker evidence. The marker remains only in Room A throughout the test.

These tests do NOT demonstrate that a real coding model has unlearned proprietary source, that human reviewers are independent, that the source license permits reverse engineering, or that all possible covert channels are blocked. Public primitive test vectors can be memorized. Docker shares a host kernel and daemon authority is privileged. CI runs on a single disposable runner and is not equivalent to independently provisioned production VMs.

Production promotion requires distinct RuFlo/Federation/RuVector identities and contexts, independent service principals and GitHub permissions, human rights review, HSM or managed key lifecycle, held-out stateful and asynchronous tests, external write-once anchoring, and adversarial exfiltration exercises.

## Rollback

The new operator CLI is opt-in. Disable it without weakening existing Ed25519 approvals or v2 isolated evaluation. Preserve externally anchored ledger heads and historical signed receipts; publish higher signed registry revisions to revoke compromised keys.

See the operator runbook in docs/clean-room/E2E.md and the outstanding governance gates in ruvnet/core-memory issue 148.
