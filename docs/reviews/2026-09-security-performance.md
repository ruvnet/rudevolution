# Security, research and performance review

Date: 2026-09-10. Baseline: `c6ca63020687487bf0c07dc43714f10d1996d0b4`.

## Decision

Ship a bounded hardening and performance change. Do not label this repository state of the art on name recovery, or describe hashes as proof of semantic equivalence. No comparable held out evaluation establishes either claim. The historical training statistics remain labeled as unverified historical results.

Scope: the standalone Rust crate, Node decompiler API, source test harness, dashboard dependency graph, and static dashboard rendering. The copied monorepo CLI is not a complete distributable in this checkout. No production probes, credential tests, malicious sample execution, GPU training, or external dataset execution were performed.

## Research review

| Primary source | Finding relevant to this repository | Engineering decision |
| --- | --- | --- |
| [CASCADE, July 2025](https://arxiv.org/abs/2507.17691) | Combines model guidance with deterministic compiler IR transformations rather than relying on language model output alone. | Introduce a binding aware AST/IR before promoting heuristic renames to runnable transformations. This PR does not implement CASCADE. |
| [JsDeObsBench, June 2025](https://arxiv.org/abs/2506.20170) | Separates simplification from syntax and execution reliability across multiple obfuscation techniques. | Treat readability, syntax, exact name recovery and behavioral correctness as different metrics; changed code is unverified here. |
| [JSIMPLIFIER, December 2025](https://arxiv.org/abs/2512.14070) | Combines static analysis, execution tracing and model assisted naming, with a broader dataset and multiple evaluation dimensions. | A 210 pattern system and one training validation split cannot establish a cross-system ranking. Do not compare incompatible percentages. |
| [BinMirror, August 2026](https://arxiv.org/abs/2608.20628) | Uses observed behavior as specifications for binary deobfuscation and validates synthesized code against those observations. | Relevant evaluation direction, not a JavaScript baseline. Future differential execution must happen in disposable OS isolation with resource and network controls. |
| [Node VM documentation](https://nodejs.org/api/vm.html) | VM contexts are not a security mechanism for untrusted code. | Remove every input execution path from Node validation and runnable reconstruction. |

The next useful experiment is a sealed corpus split by package family and obfuscator, comparing original, formatted, heuristic and AST based reconstruction under the same budget. Report parse success, exact name accuracy, behavioral pass rate, wall time and peak memory separately. An analysis-only route should remain available when reconstruction is unnecessary. No result from this PR establishes general semantic recovery accuracy.

## Confirmed findings and remediation

| ID | Severity and exposure | Baseline evidence | Fix and regression evidence |
| --- | --- | --- | --- |
| SEC-01 | High, Node validation of hostile input | `validator.js` calls `safeEvalExports`; `reconstructor.js` invokes VM execution using host-created functions and objects. VM is not an isolation boundary. Export getters also escape the intended timeout when inspected by host code. | Remove VM execution entirely. Changed input yields `functionallyEquivalent: null`; runnable mode rejects unproven edits and preserves bytes. Tests intercept VM APIs and assert zero calls; throwing and different-export programs cannot pass as equivalent. No exploit was executed. |
| SEC-02 | High when URL API is exposed by a service | `decompileUrl` allowed any HTTP host and automatically followed redirects, including private network destinations. All remote fetches were unbounded. | Fixed HTTPS host policy applied on every redirect; no credentials or custom ports; 32 MiB streamed/decompressed body limit; 30 second total deadline; maximum five redirects. Mock transport tests cover private destinations, redirect escapes, loops, advertised and streamed size, and stalled body cancellation. |
| SEC-03 | Medium, integrity consumers | Empty/malformed witness objects could pass; empty source skipped verification; module names and chain topology were not authenticated; actual module bytes were never checked. Pipeline generated hashes before reconstruction. | Versioned, domain-separated manifest root binds names/order/hash tuples. Strict schema/topology checks and optional source/module byte verification. Build after final reconstruction and recompute final metrics. Tamper, malformed, empty source and pipeline tests. |
| SEC-04 | Medium, output into an attacker-prepared directory | Lexical path cleanup did not prevent following symlink directories or overwriting existing files. | Reject traversal and control characters, check parent directories, use exclusive file creation and no-follow flags. Saved module bytes match manifest hashes. Tests ensure external sentinels survive. Use a caller-owned directory; this is not a defense against concurrent ancestor replacement by an actor controlling the same filesystem namespace. |
| SEC-05 | High availability risk when loading supplied weights | Tensor rank allocated directly; dimensions multiplied unchecked; truncated/duplicate/nonfinite tensors accepted; loaded tensor shapes not checked against forward indexing. | Bound file reads to 256 MiB; rank 1..8; at most 1024 tensors; checked element/byte arithmetic; reject truncated, duplicate, nonfinite input; embedding at most 1024, FFN at most 4096, at most 32 layers; exact expected tensor shapes. Rust malformed dimension, overflow, duplicate, NaN and model dimension regressions pass. |
| DEP-01 | Advisory findings, exploitability varies by dependency and deployment | Dashboard lockfile audit: 11 affected packages, 5 high, 4 moderate, 2 low. These are package-level audit counts, not 11 demonstrated exploits. | Compatible audit fixes plus React Router 7.18.3; zero reported vulnerabilities in final lockfile audit; TypeScript and Vite production build pass. Dev server is not a production deployment. |

Additional repairs: restore a standalone Cargo manifest using published `ruvector-mincut = 2.0.6`; commit a resolved lockfile; fix default pattern path and custom-pattern cache contamination; correct the Rust example location; use a private random temporary directory with cleanup; obey witness=false for Rust output; keep reconstruction requests on the Node branch rather than silently ignoring them.

## Threat model and residual boundaries

Assets are host process privileges, filesystem content, network access, model-loader availability and integrity claims. Entry points are remote sources, local bundles, model files, supplied output names/directories and witness JSON. Input code is treated as data; package fetchers have no install hooks. Fixed remote hosts are trusted public registry/CDN infrastructure; DNS, TLS and proxy configuration remain trusted. The allowlist deliberately cannot be expanded by request options.

Static parsing and regex reconstruction can still consume significant CPU, and local file inputs are not size limited. Services must add worker isolation, request quotas and a supervisor wall-time limit. The general readability pipeline is heuristic: strings, regular expressions, properties, template expressions, scope shadowing and hoisting can be mishandled. Runnable mode therefore preserves the original source. Syntax checks support script/function-body syntax, not every ESM construct; `runnable` describes parse validity, not safe or successful execution.

A witness is self-consistent integrity metadata, not a signature, a trusted timestamp or a semantic proof. Compare its root with a separately trusted record. Node v2 verification rejects legacy Node manifests and does not parse the native Rust SHA3 witness schema. Node results from the Rust adapter receive a Node v2 manifest over returned module bytes. Headers were removed from saved Node module files so those bytes are directly verifiable. Existing output files cause failure and output writes are not transactional.

Rust audit reports no known vulnerabilities, with one informational warning: [RUSTSEC-2025-0141, bincode unmaintained](https://rustsec.org/advisories/RUSTSEC-2025-0141.html), reached transitively through the RuVector graph dependency. Migration belongs upstream; replacing a serialization format locally would be an untested compatibility change. The optional neural feature compiles; no external ONNX model runtime or GPU inference was validated. The format does not encode attention head count; the existing head inference convention remains and may not match arbitrary models.

## Scanner evidence and triage

Ruflo runtime: `@claude-flow/cli@3.25.6`. Initial full source scan reported 3 high and 5 medium pattern matches. The high matches are in `dashboard/public/data/v0.2.x/source/permission-system.js`, `v1.0.x/source/permission-system.js`, and `v1.0.x/source/agent-loop.js`: archived source text fetched with `response.text()` in `dashboard/src/App.tsx`, rendered as text in `CodeViewer.tsx`; it is not imported or executed by the dashboard. These are not reachable SQL/command execution sinks in this application. Medium matches likewise include archive text and regex detector strings in `npm/bin/cli.js:4622-4628`, not active eval or HTML assignments. No raw secret values are included here.

The deep rescan of `npm/src` reports zero pattern findings. Ruflo secret scanning reports no secrets detected. Its STRIDE run is advisory pattern matching, not proof of isolation. The scanner does not analyze Rust tensor arithmetic or infer VM boundary escapes; the confirmed issues above came from manual source review and regression tests. Source zero findings is not a clean bill of health for every repository component.

Commands:

```bash
npx -y @claude-flow/cli@3.25.6 security scan --target . --depth deep --type all
npx -y @claude-flow/cli@3.25.6 security scan --target npm/src --depth deep --type code
npx -y @claude-flow/cli@3.25.6 security secrets --action scan --path .
npx -y @claude-flow/cli@3.25.6 security threats --model stride --scope npm/src/decompiler
(cd dashboard && npm audit --json --ignore-scripts)
cargo audit --json
```

Audit time: 2026-09-10 UTC. `cargo-audit 0.22.2`, RustSec database commit `b50980aad8b8f14f77e25a97b32dd94bf008b0af`, updated 2026-09-09T12:49:52+02:00, 1243 advisories. npm audit uses the registry advisory feed and does not return its database revision; the captured response is the evidence snapshot.

Lockfile SHA-256:

* Cargo.lock: `10374b48cd03864e53d06ceaf92e3e5c9922e98c735054470a90ac38c0eadf6e`
* dashboard/package-lock.json: `2f6ea68673c6bbffc26d4a1c2361696edc00fca6b248175ff05612d5454521d9`

## Benchmark results

Environment: Linux x64, AMD EPYC 9V74, Node v24.19.0, Rust/cargo 1.98.1. Node runs use two warmups and seven measured iterations per size/API. Baseline is the exact original reference-tracker source from the commit above; the harness asserts byte equality against it and a separately generated expected output. Raw samples, p95 and system details are in [rename-benchmark.json](evidence/rename-benchmark.json).

| Input bytes | API | Baseline median ms | Updated median ms | Speedup |
| --- | --- | --- | --- | --- |
| 22,000 | applyRename | 0.86 | 0.57 | 1.50x |
| 110,000 | applyRename | 4.16 | 2.80 | 1.49x |
| 220,000 | applyRename | 8.77 | 5.09 | 1.72x |
| 22,000 | applyAllRenames | 16.31 | 1.78 | 9.17x |
| 110,000 | applyAllRenames | 2602.10 | 5.56 | 467.92x |
| 220,000 | applyAllRenames | 10742.24 | 11.91 | 902.04x |

Mechanism: replace repeated full-string reconstruction and character-array splicing with ordered slices and one join. This reduces output assembly to linear work in output size plus edit count. Reference collection retains its existing heuristic behavior and complexity. The repeated-assignment fixture deliberately stresses high edit density; these numbers are not end to end package speedups, memory measurements, or real-world accuracy gains. No performance percentage is asserted for the Rust parser, which was not optimized in this change.

The Rust Criterion parser run covers synthetic 1 KB, 10 KB, 100 KB and 1 MB bundles, using 20 samples, one second warmup and two second requested measurement. The final 1 MB run reports a 14.568 to 14.812 ms confidence interval, 13,720 declarations. It is a standalone reference measurement; see [raw estimates](evidence/rust-parser-benchmark.json). No comparable standalone baseline could build before the manifest repair.

Reproduce Node before/after:

```bash
git show c6ca63020687487bf0c07dc43714f10d1996d0b4:npm/src/decompiler/reference-tracker.js > /tmp/rudevolution-baseline.js
node npm/bench/rename.js /tmp/rudevolution-baseline.js
cargo bench --locked --bench bench_parser -- --warm-up-time 1 --measurement-time 2 --noplot
```

## Validation and acceptance

Baseline Node suite: 92 passing assertions, 3 failing, due to the stale pattern path. Final legacy suite: 93 passing assertions, zero failures; two assertions were consolidated when unsafe runnable style transformations were replaced by byte identity. Added 14 Node security regression cases. Rust: 44 unit tests, 17 integration tests and one doc test pass, including three new tensor hardening tests. Optional neural compilation passes. Dashboard audit and production build pass.

CI adds Node 22/24 correctness, current-path benchmark assertions, dashboard install/audit/build, Rust locked tests, neural compilation and benchmark compilation. Actions are pinned to commit hashes, job token permissions are read-only. Actual PR checks must pass before merge; this document records local evidence, not a prediction of CI results.

Acceptance: from a fresh checkout, run `npm test`, `cargo test --locked`, `cargo check --locked --features neural`, then `npm ci --ignore-scripts`, `npm audit --audit-level=moderate` and `npm run build` inside dashboard. A modified witness module or private URL must fail the regression tests, and no input evaluation may occur. For behavioral improvements, require an independently held out differential corpus before enabling runnable rewrites.

Rollback: revert this PR as a unit; retain v2 manifests with their producing revision. Do not silently downgrade verification or reenable VM execution to restore the old API behavior.
