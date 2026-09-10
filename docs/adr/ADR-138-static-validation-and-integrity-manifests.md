# ADR-138: Static validation and artifact integrity

Status: Accepted for this change, 2026-09-10.

## Context

The Node decompiler accepted untrusted JavaScript, executed it through VM contexts during validation, and treated matching export shapes or simultaneous errors as equivalence. Its witness could describe pre-reconstruction bytes. Those behaviors violate the invariant that analyzing code must not execute it and that a manifest must describe the returned artifact.

## Decision

1. Validation is static. Byte-identical source may pass identity checking; changed programs have unknown behavioral equivalence. Runnable reconstruction preserves bytes and rejects unproven edits.
2. Node witness v2 binds source hash plus ordered module name/hash pairs using domain-separated JSON encoding and SHA-256. Verify source and output bytes explicitly; hashes are not semantic proofs or signatures.
3. Create witness and metrics after reconstruction. Saved module files contain exact content bytes.
4. Remote input is bounded and restricted to fixed HTTPS registry/CDN hosts at every redirect. Other downloads are an explicit caller action outside this API.
5. Output uses validated relative module paths, checked directories and exclusive files. Require a caller-owned directory rather than claiming protection against a concurrently hostile filesystem owner.
6. Model loading is bounded and exact tensor shapes are checked before inference.
7. Replacement output assembly uses ordered slices and one join, preserving the prior heuristic matcher and asserting exact baseline output in benchmarks.

## Alternatives

Keeping VM execution with a shorter timeout does not provide an isolation boundary. Merely moving it to a child process also leaves filesystem and network privileges unless OS policy is applied. Replacing regex rewriting with an AST and scope engine is the preferred correctness direction but requires a separate evaluation corpus. An allow-all URL policy with DNS address filtering requires reliable address pinning, proxy policy and redirect revalidation; a fixed public-host contract is smaller and reviewable here.

## Consequences

Compatibility changes are deliberate: unknown behavioral results are nullable, runnable edits are withheld, legacy Node manifests require regeneration, arbitrary remote URLs fail, and existing files are never overwritten. The Node source API and Rust build now work from this standalone repository. The larger copied RuVector CLI remains outside the packaging contract. The review includes benchmarks and explicit residual risks; none of the research references imply comparable accuracy was established here.

See [review and acceptance evidence](../reviews/2026-09-security-performance.md).
