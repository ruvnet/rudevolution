# ADR 141: Enforced Room B evaluation with pinned trust and offline containers

Status: Accepted for an opt-in evaluation runner, not production clean room attestation
Date: 2026-10-08
Dependencies: ADR 139, ADR 140

## Context

The v1 handoff signs an interface-only specification and independently scaffolds Room B. It does not isolate the machine or runtime in which an implementer executes new code. Treating a passing signature as a clean room certificate would conflate approval, implementation independence and runtime containment.

The highest risk in a multi-agent workflow is an implementation agent with access to original source through mounts, GitHub permissions, search indexes, retained conversation state or network calls. A second risk is executing an unknown newly generated implementation directly on the operator workstation.

## Decision

Add an **optional Linux-only Room B evaluation command** which fails closed unless:

1. A versioned Room B trust policy independently pins an Ed25519 SPKI fingerprint, signed reviewer, target, immutable container image digest, maximum approval age and expiry time.
2. The signed handoff is verified again against the trusted public key and matching policy before touching any implementation or creating any worker directory.
3. Room B's project contains **exactly four expected scaffold files**. The approved contract, compatibility runner and approval summary must match the verified scaffold byte for byte. Only \`implementation.mjs\` may change. Symlinks, hardlinks, extra files, changed tests, changed contracts and size violations fail.
4. A temporary staging directory contains exactly \`contract.json\`, \`compat.test.mjs\` and \`implementation.mjs\`. The original project directory, signed artifact, public key, reviewer receipt, Room A sources, logs and credentials are **not mounted** in the container.
5. Docker runs on the **local Linux Unix socket** only, with no network, read-only root and input bind, all Linux capabilities dropped, no-new-privileges, UID 65534, 64 PID limit, 256 MiB memory limit, one CPU and a 60-second subprocess deadline. The chosen digest must be already installed. No automatic pull is permitted at evaluation time.
6. The test runner executes only the independent implementation against the signed, allowlisted compatibility vectors. CLI writes a small JSON report outside the implementation tree with approval/spec digests, public-key fingerprint, implementation hash, runtime digest, vector count, outcome and hashes of captured stdout/stderr, without exposing raw logs.
7. Timed-out runs trigger Docker container removal. Cleanup failure is an error, not a successful result. Temporary stage files are removed on completion.

No Docker socket, agent credentials, Room A analysis output, entire repository, host home directory or shared vector index is mounted in the container. A distinct Room B machine, project, tenant, agent state, reviewer and rights review remain external deployment requirements.

## Data flow

\`\`\`text
 Room A                                   Room B (separate tenant / VM)
 original source                          trusted reviewer key and policy
     |                                               |
 independent authorized review                        v
     |                                    verify approved.json + policy
 approved.json ---- one-way transfer --->            |
                                                     v
                                      allowlist exact scaffold contents
                                                     |
                                                     v
                                      copy 3 files into ephemeral stage
                                                     |
                                       Docker on Room B worker only
                                       network none + read-only + no caps
                                                     |
                                                     v
                                      run generated test runner on new code
                                                     |
                                                     v
                                       hashed evaluation report (Room B)
\`\`\`

## Threats and residual risks

| Threat | Enforced control | Remaining risk |
| --- | --- | --- |
| Source/code leak to implementation stage | Exact three-file staging, no project directory mount, reject unexpected project entries | Allowed implementation text can itself be contaminated by a person/agent; stage is not a legal clearance or information-flow proof |
| Mutated interface contract or test harness | Signature verification and byte-for-byte scaffold regeneration | Legitimate reviewer can approve undesirable data; covert encoding in permitted scalar vectors still possible |
| Stolen reviewer key / forged claimed review | Out-of-band fingerprint, target/reviewer allowlist, expiry and age window | No online revocation, hardware-backed custody or proof a human reviewed |
| Malicious model-generated code | Offline, read-only, unprivileged container and bounded resources | Docker daemon access is privileged; kernel/container escape, runtime supply-chain compromise and local host compromise remain |
| Docker image substitution | Room B trust policy fixes image by SHA256 digest; \`--pull=never\` | Trusted image acquisition/scan and digest policy governance are external |
| Host secrets through mounts | Staged copy is the only bind mount | Full docker daemon control on a host containing Room A data would still be unsafe |
| Report manipulation | Exclusive output with digests and fixed fields | Unsigned local report can be edited later; remote attestation and signed ledger are separate future controls |
| Unsafe inference that passed fixtures prove equivalence | Report records only vector count and pass/fail | Unseen inputs, stateful protocols, asynchronous behavior and performance are not covered |

## Safety invariants

**CR-5:** No original source path or arbitrary project directory is a Docker mount.

**CR-6:** A stale, mutated, unsigned or wrongly pinned artifact cannot launch the evaluation runner.

**CR-7:** Unknown project files, symlinks, modified tests and mutable image tags are rejected.

**CR-8:** Execution has no container network connectivity, a read-only filesystem and no elevated Linux capabilities; the runtime image is pre-approved by digest.

**CR-9:** Report is generated outside project and contains hashes rather than raw execution logs.

## Validation

Unit tests inject a fake Docker client to inspect mount arguments and staged files, validate policy rejection, tamper/symlink failures and kill/cleanup behavior. An independent GitHub Actions job pulls a test Node runtime, derives the digest and exercises a **real Docker** worker with a synthetic Room A sentinel. A malicious implementation checks that original source is invisible, the mounted stage cannot be written and only loopback networking exists, then passes three public compatibility vectors.

Run:

\`\`\`bash
npm run test:cleanroom
\`\`\`

The real Docker test is enabled when \`RUDEVOLUTION_TEST_IMAGE\` references a locally available, pinned image digest. It is intentionally skipped without that environment variable; the CI job supplies it.

These checks establish a narrow, reproducible execution boundary **for the evaluation run**, not source independence of the implementer or formal noninterference. Production use still requires a separate Room B OS identity or VM, operator-reviewed legal permissions, image security patching, isolated model context, key lifecycle and an external evidence ledger.

## Rollback

Disable \`sandbox-test\` and revert this runner/CI suite; v1 \`validate\`, \`approve\`, \`verify\` and \`scaffold\` remain unaffected. Revoke any exposed reviewer keys through an external trust policy and prevent reuse of old worker images.
