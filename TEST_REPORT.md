# v12.1 Test Results and Evidence Boundaries

**English** | [简体中文](TEST_REPORT.zh-CN.md)

Evidence cutoff: **October 14, 2026 (Beijing time)**. This document summarizes the release evidence. The full design, failure records, charts, and index are available in the Chinese [HTML](reports/MatrixHub-v12.1-测试与设计报告.html) / [PDF](reports/MatrixHub-v12.1-测试与设计报告.pdf) report. Counts are based on the [final fact summary](evidence/runtime/streaming-v12-20261013/report-prep/v121-supplement-final-v2.json); post-packaging verification is recorded in independent delivery receipts.

This report distinguishes actual runs of the current candidate, reused evidence supported by identical component bytes, historical results, compilation only, and incomplete work. Results from different layers, repeated runs, and parent/child test events are not added together as independent attack samples.

## 1. Version under test

| Item | Identity |
| --- | --- |
| Upstream base | `84bb83043dc17b6cb3d1858620ac40c171bd8eff` |
| Source scope | 1,527 exported files; 44 explicitly listed overlays; credentials sanitized in 5 upstream test helper files |
| Final source manifest SHA256 | `0533edefe39719e0c6418e9a4117574dabe47f7cbbc58e83d12003304f3f86ee` |
| Overlay manifest SHA256 | `722f85c0eaac8f0547f534649bed55c1a98afd260d2badfb655ed5b740d562d5` |
| Actual Linux/amd64 backend SHA256 | `09f277772bfcf8e15d777369c88f58e716f117d2c3d3f76dce27e69aa4df3f34` |
| Local DCO commit | `e22d87dd63b0789cad1d09573a5a9a6e46cde11e` |
| Detection engines | ClamAV 1.4.6; Picklescan 1.0.5; this project's bounded static format checks |

See [VERSION_LOCK.json](VERSION_LOCK.json) for tool versions, dependency locks, and component relationships. Sanitized helpers in the export differ from the original Git blobs. The DCO verification binds the 44 tested overlays. A source manifest is not a binary build receipt.

## 2. Actual execution of the current candidate

| Validation layer | Observed result | What it establishes / scope |
| --- | --- | --- |
| Full-source compilation and selected security regressions | All 12 steps exited 0 | A newly compiled Linux/amd64 CGO backend; existing dependencies and images were reused, so this was not a cold-cache build |
| Domain security tests | 45 top-level tests passed, 0 failures/skips | Includes race detection; subtests are not counted again as top-level tests |
| Repository security tests | 64 top-level tests passed, 0 failures/skips | Persistence behavior for security evidence, jobs, caches, audits, and human review |
| Handler security tests | 14 top-level tests passed, 0 failures/skips | API validation, identity/authorization, and admission behavior |
| API server security tests | 7 top-level tests passed, 0 failures/skips | Includes method routing and rejection behavior over real new TCP connections |
| Full application / HF / LFS / multiple revisions | **794/794 business assertions passed** | 11 revisions, 12 reports, and 12 completed audit bindings; isolated local deployment with fresh volumes |
| Generation changes for the same commit | **17 + 23 assertions passed** | Separate business sequences; an earlier permission cannot carry over after the rule generation changes |
| Human-review role API | **55/55 checks passed** | Append-only reviews, permissions, cross-project isolation, unchanged complete machine-report JSON, and continued HTTP 403 responses for risky downloads |
| Desktop browser | **8/8 checks passed** | 1280×900, real backend, no mocked routes; pass/block/fail states, risk details, and a real review POST returning 201 |
| Portable HF client smoke test | Complete upload, scan, and download with matching SHA | The delivered `hf_smoke.py` was executed; one 17,739,144-byte BERT weight file, using an existing dependency and service environment |
| Actual demonstration video | **224.92 seconds / 1280×900** | Real browser recording, offline decoding, and visual inspection of 10 sampled frames; not frame-by-frame inspection or a soak test |

See [compilation facts](evidence/runtime/streaming-v12-20261013/report-prep/v121-compile-facts-v2.json) for build and package-level counts. These are explicitly selected security regressions; **they are not reported as a fresh execution of the repository-wide `make test.unit` target**. The real-socket tests also include a negative control for the old default PATCH matcher, 12 method/body combinations, and 6 requests using prohibited mutation methods. These are already included in their respective test trees and must not be added again as independent totals.

Application details are in the [current application record](evidence/runtime/streaming-v12-20261013/report-prep/v121-current-app-facts-v2.json); UI/API details are in the [combined acceptance record](evidence/runtime/streaming-v12-20261013/report-prep/v121-ui-acceptance-facts-v1.json). The application client's business sequence took 198.477911 seconds, while the complete controller run took 351.459212 seconds. Their scopes differ; neither measures a single file scan.

**794 is a count of business assertions, not files, malicious samples, or the denominator of an attack-detection accuracy metric.** Risk fixtures use controlled, inert content and do not execute malicious payloads. Detecting a dangerous static reference does not mean that code execution occurred.

## 3. Three realistic business scenarios

### Normal delivery and reuse across revisions

The test used an original publicly available trained BERT-Tiny safetensors file (17,739,144 bytes), weight shards derived from the same model, controlled format samples, and a separate synthetic CPU legacy FloatStorage capacity fixture of approximately 1 GiB. Files were uploaded through real HF `create_commit` / LFS operations, followed by waiting for complete reports and performing complete downloads.

The main application sequence completed **27 full downloads totaling 1,180,190,711 bytes**. Every response was read in full and its SHA256 verified. BERT and its derived shards still represent one model family. The synthetic GiB file tests large-file capacity and the admission path; it is not presented as a real GiB-scale trained model. No training or inference was performed.

### Blocking risky revisions and reviewing findings

A revision containing dangerous static references was marked block, and the server denied its protected downloads. A previously safe, pinned commit remained downloadable. After an Editor/Admin appended a comment such as “suspected false positive,” the complete machine-report JSON remained unchanged and risky downloads still returned 403. A human review does not grant a new machine-issued permission to download.

### Incomplete evidence and rule upgrades

Truncated or nonconforming serialized revisions were marked fail. They could not pass merely because no conventional virus signature was reported. After the scanner generation changed, the same commit first entered pending and its downloads were denied. An incomplete result from the new check was also denied. Old cache entries did not carry forward as permission under new rules.

## 4. Performance observations and measurement scope

| Experiment | Observation | Interpretation and limits |
| --- | --- | --- |
| Current APP V7: complete repository revision containing BERT, derived shards, and synthetic 1 GiB content | Report `durationMs=114534`; 8 cache hits among 13 files | One local run with the GB profile; neither a repository-wide cold-cache scan nor pure antivirus-engine time |
| Current APP V8: next revision with a README-only change | Report `durationMs=3386`; 12 cache hits among 13 files | Different workload from V7; dividing the two timings does not establish an approximately 34× scan-algorithm speedup |
| Separate Stage diagnostic: 1,073,742,186-byte file with an invalid version field, prefix check enabled | 65,536 source bytes read; rejected after 2.280729 seconds in Stage | One sample with deterministically invalid format metadata; not a general malicious-file detection speed |
| Same invalid file with the prefix check disabled | Stage: 3.018188 seconds; complete Analyze call: 182.191916 seconds | One comparison, without p50/p95; measurement points differ from application-report `durationMs` |
| Separate Stage diagnostic: real BERT safetensors | All 17,739,144 bytes read; Stage: 0.079124 seconds; Analyze: 5.998025 seconds | Prefix probe was not invoked; the complete check passed |

The Stage diagnostic was compiled from v12. The four production components it actually invoked are byte-identical to v12.1. This is **reused evidence for identical components**, not a repeated run of the current complete application. See [Stage facts](evidence/runtime/streaming-v12-20261013/report-prep/stage-readcount-facts-v1.json). Read counts measure bytes read from the application's source, not physical operating-system disk I/O or the user's initial upload traffic.

Current optimizations include overlapping staging and scanning across files, bounded prefix prechecks that can reject but cannot approve, and caching keyed by content and scanner generation. A prefix result can only reject or remain undecided; it cannot provide complete scan evidence. Valid files still require complete antivirus and digest checks. A parallel `pread` candidate for ClamAV/static parsing was experimentally tested but **was not promoted into this release's production implementation**. Its timings are not reported as stable gains for the released version. Complete pre-scan and post-scan SHA256 checks remain in place.

There are not enough repeated paired experiments to support a stable speedup ratio, throughput limit, p95, or public-network download-performance claim. The timings above are not interchangeable.

With production scanner bytes unchanged, an additional real Linux regression run under the default configuration passed **59 unit tests + 13 integration tests + 15 prefix tests, totaling 87 checks with 0 failures/skips**. This is evidence for the native isolated scanner. It is not added to earlier repeated prefix-test runs or converted into accuracy on real malicious models.

## 5. Validation reused on the basis of byte-identical components

| Item | Actual execution and result | Attribution to this release |
| --- | --- | --- |
| UI typecheck / targeted lint / Vitest / Vite | Actually completed on the previous candidate; 3 suites and 15 tests passed | All 392 inputs and 168 outputs have matching SHA values; the final source was not rebuilt |
| MySQL human-review transactions | MySQL 8.4.11; 4 real cases passed, 0 failures/skips | Corresponding current domain/repository/SQL bytes are identical; not full MySQL acceptance of the current complete application |
| Stage source-read diagnostic | Three input categories behaved as expected; no temporary part-file or quota leaks after rejection | Four production components are byte-identical; scope is described above |

References: [component equivalence](evidence/runtime/streaming-v12-20261013/report-prep/v121-module-equivalence-facts-v2.json), [UI build](evidence/runtime/streaming-v12-20261013/report-prep/v121-ui-build-facts-v1.json), and [MySQL](evidence/runtime/streaming-v12-20261013/report-prep/v121-mysql-facts-v1.json). Reuse is not presented as re-execution.

## 6. Official E2E / KIND: historical execution and current compilation only

For the current candidate, **only the three official E2E binaries were compiled**. The complete `make test.e2e` / `make test.e2e.kind` suites were not rerun.

Both historical runs actually executed the outer `make test.e2e.kind` target, deployed through a single-node Kubernetes cluster and the official Helm chart, and then invoked the inner `make test.e2e` / Ginkgo suite. Security features were disabled in this compatibility path, so these runs do not demonstrate Kubernetes acceptance of the current security configuration.

| Historical version and Beijing time | Cases and duration | Three exit statuses and final result |
| --- | --- | --- |
| Directory-fixture adaptation `6e2b4ee5a6525383da784fb42b8f677e3163343f`; 2026-10-09 22:14:09–22:19:31 | 11 suites; 187 passed, 0 failures/skips; 321.625 seconds | Outer make 0 / inner Ginkgo 0 / strict runner 0; PASS |
| v10 `84bb83043dc17b6cb3d1858620ac40c171bd8eff`; 2026-10-13 02:23:25–02:28:31 | 11 suites; 186 passed, 0 failures, 1 pre-existing M00036 directory case skipped; 305.691 seconds | Outer make 0 / inner Ginkgo 0 / strict runner 1; FAIL against the strict “all 187 pass” requirement |

The first run adapted the directory fixture in the per-case model factory; it is not described as a completely unmodified official suite. A successful command exit in the second run does not mean all cases passed. The two runs cannot be added together as 374 independent security scenarios. Exact outcomes and commands are recorded in the [historical KIND facts](evidence/runtime/streaming-v12-20261013/delivery-prep/v121/historical-kind-facts-v121.json).

## 7. Failures and incomplete work

Recorded failures include typed404 wrapping that was incompatible with `errors.Is`, an isolated build cache running out of space, omitted migration SQL during deployment, an incorrect comparison of projected digests in the test client, and a cmux connection reset when PATCH was the first packet. These records are retained, with explicit subsequent passing evidence after the relevant fixes. Failures must not be hidden in summaries or incorrectly labeled as still-unfixed current issues.

The root cause of browser wait timeouts in v5/v6/v7 remains unconfirmed. Final v8 passed without changing product bytes. This proves success of that particular desktop flow, not that the intermittent issue was fixed. The video uses small controlled fixtures and does not show BERT or GiB uploads.

The following remain incomplete:

- A complete official E2E / KIND rerun on the current version, and current Kubernetes acceptance with security enabled.
- Complete build, deployment, and end-to-end reproduction on a fresh machine with empty caches.
- The planned 16-hour continuous business soak test. Historical evidence contains only 195 successful cycles, 196 observations, and 11,642.813 seconds; coverage requirements were not met.
- Compatibility across broad model families and multiple complete framework versions, plus representative false-blocking and missed-detection measurements.
- Complete streaming antivirus during the initial network upload; a stable performance speedup ratio or high-concurrency throughput conclusion.
- A public upstream proposal and effective maintainer acknowledgment; local tests and a DCO commit are not substitutes.

References: [earlier browser failures](evidence/runtime/streaming-v12-20261013/report-prep/v121-ui-partial-facts-v3.json), [historical boundaries](evidence/runtime/streaming-v12-20261013/report-prep/historical-boundaries-v1.json), and [limitations](LIMITATIONS.md).

## 8. Delivery integrity

The original local delivery archive, `MatrixHub-v12.1-source-evidence-demo.zip`, is **84,803,273 bytes** and contains 1,729 members. Its SHA256 is:

```text
dc28b6111c0f18312085ad1b685231485eb8e02abf51beb9ee3f9677ed02cdf6
```

Independent verification read every member and checked SHA values, CRC values, modes, and the exact member set. The packaged source-verification entry point was then actually executed in a new extraction directory and checked all 1,527 source files. **This verifies source integrity, not deployment on a fresh machine.** Documents such as the README added during publication preparation are outside this earlier archive's digest. A GitHub publication tree or new archive needs its own manifest; the earlier digest cannot represent added content.

The HTML and 15-page PDF were actually generated and visually inspected. The real video was inspected through 10 sampled frames. More detailed evidence and file digests are retained in the release report and index.
