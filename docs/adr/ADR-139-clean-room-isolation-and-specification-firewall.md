# ADR 139: Clean room separation and the specification firewall

Status: Accepted for a bounded v1 implementation
Date: 2026-10-08
Owners: ruDevolution maintainers and designated clean room reviewers

## Context

ruDevolution is useful for inspecting minified third-party JavaScript, but inspecting code and generating a replacement from the same agent context is **not** a clean room workflow. Model instructions such as "forget the source" are not isolation. A shared AI chat, prompt cache, retrieval index, vector store, telemetry log, workspace, IDE, or filesystem can silently transmit protected implementation details.

The decompiler's name guesses and recovered module boundaries are hypotheses. Neither its SHA3-256 witnesses nor its source maps prove independent design or behavioral compatibility. Whether the underlying activity is lawful depends on licensing, authorization, purpose, contracts, trade-secret handling, and the jurisdiction.

## Decision

Introduce a narrow, explicit **Room A / Room B handoff** in the independent `npm/src/clean-room` module, rather than wiring executable decompilation results directly into an implementation generator.

1. **Room A (analysis and human specification review)** may inspect authorized reference materials using existing tools and write a human-authored `rudevolution.cleanroom.spec/v1` proposal. Automated analysis is advisory and never directly exported to Room B.
2. The **specification firewall** accepts only a closed JSON schema with bounded identifiers, primitive argument/return types, enumerated errors and bounded primitive compatibility vectors. Unknown keys, source bodies, ASTs, maps, byte arrays, snippets, comments, arbitrary documentation, hidden Unicode and large values are rejected. All values are validated *again* by Room B. These restrictions reduce accidental leakage; no grammar can ensure absence of encoded secrets.
3. A designated human reviewer must examine the contract and exercise `approve ... --ack-reviewed` with a dedicated **Ed25519 private key** in Room A. Approval signs a canonical JSON commitment bound to reviewer, UTC timestamp, and SHA256 digest. A receipt remains in Room A. An approval is evidence of a keyholder's approval, not proof that a person actually reviewed it or that the spec is lawful.
4. Only the signed contract crosses the one-way handoff. Room B is provisioned separately with the approved artifact and an **independently pinned** trusted public key. It validates the signature and schema before creating a new implementation scaffold and public test vectors. No direct decompiler import or source execution occurs in Room B's tool.
5. Use distinct OS identities or isolated containers/VMs with **no shared filesystem mounts, LLM context, memory indexes, logs, telemetry, browser profile, caches, tokens or original-source repository access**. Implementations must be created from the approved spec only. The v1 code does not provision or attest those machines. Operators remain responsible for enforcing this requirement.
6. Compatibility testing in Room B executes only the *new* implementation and bounded approved vectors. Room A may maintain independently authorized black-box oracle measurements in its restricted environment. The v1 software never executes the reference JavaScript or asserts semantic equivalence.

## Data flow and invariant

```text
Authorized reference materials (Room A only)
    |
    v
Observations and candidate behavior (Room A only)
    |
    v
Human-authored constrained interface JSON
    |
    v
Schema validation + independent review + Ed25519 signature
    |   \--> Room A receipt + evidence, never exported
    v
One-way transfer of approved.json only
    |
    v
Pinned-key verification + schema revalidation (Room B)
    |
    v
Independent implementation scaffold + compatibility tests
```

**Invariant CR-1:** No original source bytes, snippets, code bodies, recovered ASTs, proprietary comments, raw trace logs, or Room A private key are passed to Room B by this module.

**Invariant CR-2:** Room B creates zero output files if schema validation, signature validation, or destination preconditions fail.

**Invariant CR-3:** A reviewer cannot modify a signed spec without invalidating its signature, and a forged approval from a different key fails against the pinned public key.

**Invariant CR-4:** The shipped regression fixture places a synthetic proprietary marker in a Room A-only file and checks that neither the approved artifact nor the Room B output contains it. This is a local non-contamination regression, **not a formal noninterference proof**.

## Deliberately narrow v1

Only ≤16 operations, each with ≤8 inputs of `string`, `number`, or `boolean`, primitive return values (or `void`), four enumerated error types, and 1–24 vectors covering every operation are accepted. Test strings use a short ASCII grammar and numeric values are finite/bounded. No arbitrary free-text prose is exported to Room B. No reference artifacts are decompiled or synthesized automatically during this workflow.

These restrictions limit expressiveness but make the first gate straightforward to inspect and test. JSON and simple scalar vectors can **still covertly encode protected information**. Human review and organizational DLP controls are mandatory independently of schema validity.

## Security and governance

| Threat | Protection | Residual risk / mitigation |
| --- | --- | --- |
| Source copied into Room B | Allowlists, bounded scalars, no decompiler data import | Encoded information can pass through any allowed scalar; human review, DLP and physical isolation required |
| Artifact tampered in transit | Canonical SHA256 digest + Ed25519 signature verification | Signing key theft or incorrectly provisioned trust anchor; use external key custody, rotation and revocation |
| Approval forged as "human reviewed" | Named reviewer and explicit CLI acknowledgment | CLI flags can be automated; enforce independent review policy and auditable ceremonies |
| Shared AI memory/cache contaminates implementer | Separate OS identities and distinct provider tenants | Not enforced by local CLI; deploy with independent secrets, egress, logs and separate service principals |
| Untrusted source executes during analysis | Only static, approved contracts processed here | Oracle testing or package fetchers elsewhere require separate hardening and sandboxing |
| Filesystem injection | Exclusive output creation, non-symlink file checks, bounded reads | Concurrent ancestor replacement is a TOCTOU risk; deploy in caller-owned locked workspace |
| Misleading equivalence/legal claims | Scope tests to approved vectors and state legal boundary explicitly | Passing fixtures is not general behavioral equivalence or legal clearance |

## Rejected alternatives

* **Directly feed decompiled code or inferred symbols to a generator.** This violates the basic transfer boundary.
* **Use prompt instructions to make an exposed agent forget.** The model has already consumed the implementation; instructions are not a security boundary.
* **Treat cryptographic witnesses as proof of clean room independence.** Integrity and independence are different properties.
* **Automatically release every syntax-valid contract.** Valid strings can encode source details, so a review gate is required.

## Consequences

Positive: auditable, deterministic, no dependency additions, offline signing/verification, independent room inputs and testable rejection behavior.

Cost: manual review, reduced contract expressiveness, operations staffing, pinned keys and OS-level isolation. No automatic Rust/Node decompiler-to-spec bridge is enabled. Production isolation, DLP, legal review and key revocation are follow-on controls, not implied by a green test suite.

## Rollback

Remove the `npm/src/clean-room` entrypoint and its documentation/tests without affecting the existing decompiler APIs. Revoke compromised signing keys outside the repository. Maintain prior approval receipts in the restricted Room A evidence vault.

## Acceptance

From a fresh clone, run `npm test`. Require rejection of extra source fields, tampered signatures, wrong keys, code-shaped payloads, symlinks and overwrites; require a complete positive CLI approval-to-scaffold round trip. In Room B, a deliberately unimplemented function must fail its contract vectors until an independent implementation is supplied.
