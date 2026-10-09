# ADR 140: Signed clean room contracts, evidence and compatibility testing

Status: Accepted for v1 signature and test artifact, with future deployment controls specified
Date: 2026-10-08
Dependencies: ADR 139 and ADR 138

## Problem

A graph-based decompiler may make a program understandable without proving that inferred names or transformed code are correct. A clean room implementation needs a reviewable contract independent of the original program, traceable approval, and a behavioral evaluation that cannot execute untrusted source by accident. It also needs to avoid conflating a cryptographic signature with legal defensibility.

## Decision and protocol

The portable artifact contains only:

```json
{
  "format": "rudevolution.cleanroom.approval/v1",
  "spec": {
    "format": "rudevolution.cleanroom.spec/v1",
    "target": "example-compatibility",
    "operations": [
      {
        "name": "add",
        "inputs": [{"name":"a","type":"number"},{"name":"b","type":"number"}],
        "returns": "number",
        "errors": ["invalid_argument"]
      }
    ],
    "vectors": [{"operation":"add","arguments":[2,3],"expected":5}]
  },
  "review": {
    "reviewer": "reviewer.one",
    "approvedAt": "2026-10-08T20:00:00.000Z",
    "specSha256": "<64 lowercase hex digits>",
    "signature": "<Ed25519 signature in canonical base64>"
  }
}
```

`specSha256 = SHA256(canonicalJSON(spec))`. Signing message bytes are UTF-8:

```text
rudevolution.cleanroom.approval/v1\n
canonicalJSON({approvedAt, reviewer, spec, specSha256})
```

`canonicalJSON` recursively sorts object keys, retains array order and serializes JSON scalar values with JavaScript JSON escaping. The domain prefix disambiguates signatures from other applications. Only approved bounded schema values can reach this canonicalizer in the signature pathway. The standalone Room A receipt records the approval artifact SHA256, the spec digest, reviewer, UTC time and SHA256 of the signer's DER SPKI public key; **do not copy the Room A receipt or private key to Room B**.

The trust anchor is **external** to the signed artifact: the reviewer public key provisioned through the independent Room B approval policy. A signature and a self-reported reviewer name do not demonstrate reviewer employment, independence, copyright compliance, source independence, legal permission, or acceptable test coverage.

## Independent compatibility tests

The Room B scaffold includes `contract.json`, `implementation.mjs` with unimplemented function exports, `compat.test.mjs`, and `APPROVAL.txt`. Contract vectors only test simple public input/output behavior. The test runner imports and calls **only the independent implementation**, never the reference JavaScript or the decompiler's reconstructed source.

A failing scaffold is intentional: compliance requires implementing the operations from specification and rerunning `node --test compat.test.mjs` in the separately isolated Room B. Passing these vectors is a necessary fixture check, not general equivalence. Any future differential testing must use a legally authorized reference oracle in isolated Room A infrastructure; observable results must pass the same reviewed firewall before they can become Room B vectors.

## Governance and evaluation ledger

Record the following outside Room B: a reference artifact fingerprint (not the source), analysis tool revision, reviewer identity and independent evidence review, legal authorization, approval receipt, review decisions and rejected candidates. Room B records only signed specification digest, trusted key fingerprint, implementation commit ID, independent test vector pass count, wall time and deployment version. Retain both ledgers separately with operator-controlled access.

Recommended acceptance metrics for operational rollout:

* **Zero** successfully accepted tampered artifacts, changed reviewers, changed timestamps, or untrusted signing keys in negative tests.
* **Zero** references to the synthetic proprietary marker in the handed-off approval or generated Room B files.
* **100%** approved-vectors passing on the independently written implementation. Report number of vectors and operations, not an accuracy percentage across untested inputs.
* Signed approval metadata verified against an independently pinned key. The tool does not provide key revocation or expiry, so a production verifier must apply those organization-specific policies.
* No Room A data, keys or shared AI state mounted in Room B; deployment and red-team attestation is required before describing the deployment as clean room.

## Operational boundaries

This code is a developer-facing prototype, not a network service or a complete compliance system. It does **not** create hardened VM isolation, attest a human reviewer, filter encoded secrets perfectly, prove semantics, provide independently derived specifications, enforce a license, or guarantee lawful reimplementation. Avoid making any of those claims in product copy until independently demonstrated and reviewed.

## Future extensions

1. Separate signer/validator packages and isolate secret handling in an HSM or signing service, including rotation, revoke lists, and public-key pinning policies.
2. Add policy-specific schemas for state machines, error behavior and binary protocols only after an independent DLP and provenance evaluation.
3. Accept approved black-box oracle fixtures through a one-way evidence service, with reference execution confined to Room A and never triggered by this library.
4. Add hermetic worker launchers for Room B (distinct service identities, no source volume, no cross-room retrieval, egress policy, deterministic environment) and report measured non-contamination.
5. Introduce held-out multi-package compatibility studies reporting parse rate, behavioral pass rate, latency, memory and coverage separately. No blanket "clean room" or accuracy claims from current results.

## Acceptance / rollback

`npm test` includes signing verification, mutation testing, restricted schema tests, synthetic-source-marker non-contamination, overwrite and symlink checks, and a complete independent `add` / `greet` implementation test. Revert this ADR's companion module if a signed forbidden field is accepted or an unsigned/tampered artifact is scaffolded; revoke keys externally if exposure is suspected.
