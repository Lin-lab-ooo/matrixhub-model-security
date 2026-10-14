# Known Limitations and Validation Gaps

**English** | [简体中文](LIMITATIONS.zh-CN.md)

This document describes the actual boundaries of v12.1. See [TEST_REPORT.md](TEST_REPORT.md) for evidence and [VERSION_LOCK.json](VERSION_LOCK.json) for the current version identity.

## Security meaning

“Download allowed” means that the immutable revision completed checks within the currently supported scope and satisfied the policy. It is not a guarantee that the model is absolutely safe, comes from a trusted source, meets quality requirements, or has no unknown vulnerabilities. A dangerous static reference demonstrates the presence of a risky construct, not that its payload executed. This project does not load models under inspection or perform inference or dynamic malware analysis.

ClamAV, Picklescan, and this project's bounded semantic checks each have coverage limits. Unsupported constructs, truncated content, or analysis that cannot finish remain fail/incomplete; the absence of a virus-signature match is insufficient for approval. Bounded CPU tensor semantics cannot be generalized to arbitrary GPU storage, custom Python classes, or every PyTorch version.

Strict admission requires a complete deployment with all downloads routed through protected paths. Running the isolated scanner alone does not establish automatic protection for every protocol. Paths such as raw Git fetching and historical patches need restrictions according to the security deployment design. Direct infrastructure-level access to files that bypasses the application is outside application-level authorization checks.

## Performance and streaming capabilities

Prefix prechecks operate only while the server reads repository/LFS content into a scan snapshot. The initial HF upload has already completed; complete antivirus scanning during that initial network upload is not implemented. Early rejection after 64 KiB applies only to supported legacy metadata that can be determined invalid within a bounded prefix. If no problem is found, a complete scan is still required. Small files may be affected by the precheck's fixed overhead.

The cross-file pipeline scans previously completed snapshots, not the same continuously growing file. Complete pre-scan/post-scan SHA256 checks and complete antivirus scanning remain in place. ClamAV accounts for a major observed portion of large-file processing time. The parallel `pread` candidate was not promoted into the production implementation, and the ClamAV engine itself was not modified.

Current performance data comes from single local runs or individual diagnostics. The 114.534-second V7 report includes 8 cached files; the 3.386-second README-only V8 report includes 12 cached files. These do not form a speedup ratio for identical workloads. There are no stable p95, high-concurrency, public-network, or cross-hardware conclusions.

## Data representativeness and compatibility

The actual trained model coverage is primarily one BERT-Tiny family. Derived shards do not constitute additional independent families. The approximately 1 GiB file is a synthetic capacity fixture, not real GiB-scale trained weights. Controlled risk samples do not represent the population of malicious files encountered in practice. The number 794 counts business assertions; it must not be presented as 794 successfully detected attacks, a 100% detection rate, or zero false positives.

Multiple revisions of one repository, scanner-generation updates, and different serialization formats are separate dimensions of compatibility. They do not establish a completed matrix of multiple full framework/service versions.

## Deployment and verification

- The current complete application uses existing local images and dependencies, a newly compiled Linux backend, fresh empty volumes, and bound migration SQL. It is not a new production image built entirely from scratch.
- Complete reproduction on a fresh machine with empty caches has not been completed. Scripts and documentation provide reproduction entry points; they do not prove one-command deployment in arbitrary environments.
- The default Compose file-size limit is 64 MiB. The GB profile requires clamd, additional memory, and appropriate job/staging quotas, timeouts, and leases. The portable HF smoke test is limited to 64 MiB and does not replace the full GB-scale, multi-revision controller.
- Major tools and project dependency files are pinned, but newly downloaded rules, apt packages, and transitive dependencies of the portable Python environment do not constitute a fully frozen environment. Each reproduction should record the actual rules, images, tools, and results.
- The current candidate's three official E2E binaries were compiled only; complete official E2E/KIND suites were not rerun. Historical KIND results are compatibility evidence for different versions with security disabled.
- The 16-hour continuous soak test is incomplete. Waiting time, interruptions, and periods without execution do not count as successful coverage.
- Some WARN expectations for unknown content in the historical upstream `source/scripts/security/e2e.py` predate the newer completeness constraints. They must not be treated directly as the current specification, nor should admission be relaxed merely to pass older tests.

## UI and human review

The current passing scope is a 1280×900 desktop. Earlier mobile, second-desktop-context, and initial-business-page flows experienced wait timeouts whose root cause remains unconfirmed. A later desktop pass does not establish that those issues were fixed. Preliminary mobile checks of the three states also passed, but this neither establishes complete mobile acceptance nor supports a claim that mobile is generally unusable.

Human review appends comments only. It does not allow editing, deleting, overriding the machine verdict, or forcing a download to be allowed. Suspected false positives require further rule or file correction and a new check. Atomicity of comment and audit writes has been verified; this is not proof of long-term production reliability.

## Release and project identity

This is a contribution snapshot derived from upstream, not an official MatrixHub release. A local DCO commit, report, and video do not establish upstream acceptance, maintainer endorsement, or a competition award. The actual status of the public repository, external proposals, and subsequent community acknowledgment should be recorded separately. Third-party engines and upstream capabilities retain their explicit attribution and are not presented as original detection algorithms developed by this project.
