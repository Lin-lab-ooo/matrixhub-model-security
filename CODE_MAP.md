# Developer Code Map

[English](CODE_MAP.md) | [简体中文](CODE_MAP.zh-CN.md)

The repository root contains publication documentation and evidence; the application source is in `source/`. The entry points below identify the implementation. Historical version descriptions in design documents do not override the version lock at the repository root.

| Mechanism | Production implementation | Related tests |
| --- | --- | --- |
| Job states, file batches, cross-file pipeline, and cache use | [service.go](source/internal/domain/security/service.go) | [service_pipeline_test.go](source/internal/domain/security/service_pipeline_test.go), [batch_test.go](source/internal/domain/security/batch_test.go) |
| Git/LFS content reads, snapshots, and 64 KiB prefix prechecks | [security_artifacts.go](source/internal/repo/security_artifacts.go), [security_stream.go](source/internal/repo/security_stream.go) | [security_artifacts_test.go](source/internal/repo/security_artifacts_test.go), [security_prefix_test.go](source/internal/repo/security_prefix_test.go) |
| Unix socket scanning protocol, request budgets, and priority for full scans | [security_scanner.go](source/internal/repo/security_scanner.go), [security_scanner_gate.go](source/internal/repo/security_scanner_gate.go) | [security_scanner_gate_test.go](source/internal/repo/security_scanner_gate_test.go) |
| ClamAV/Picklescan integration, format structure, and bounded semantic analysis | [scanner.py](source/deploy/security-scanner/scanner.py) | [tests.py](source/deploy/security-scanner/tests.py), [integration_tests.py](source/deploy/security-scanner/integration_tests.py), [prefix_tests.py](source/deploy/security-scanner/prefix_tests.py) |
| Complete evidence persistence, jobs, and auditing | [security_db.go](source/internal/repo/security_db.go) | [security_db_evidence_test.go](source/internal/repo/security_db_evidence_test.go), [security_db_completion_test.go](source/internal/repo/security_db_completion_test.go) |
| Identity binding and transactions for manual review | [review.go](source/internal/domain/security/review.go), [security_review.go](source/internal/repo/security_review.go) | [review_test.go](source/internal/domain/security/review_test.go), [security_review_test.go](source/internal/repo/security_review_test.go) |
| Web security card, risk evidence, and review forms | [ModelSecurityCard.tsx](source/ui/src/features/models/security/ModelSecurityCard.tsx), [SecurityReportEvidence.tsx](source/ui/src/features/models/security/SecurityReportEvidence.tsx), [SecurityReviews.tsx](source/ui/src/features/models/security/SecurityReviews.tsx) | [security.evidence.test.ts](source/ui/src/features/models/security/security.evidence.test.ts), [security.reviews.test.ts](source/ui/src/features/models/security/security.reviews.test.ts) |
| Dedicated local deployment and scanner isolation configuration | [compose.yaml](source/deploy/security/compose.yaml), [Scanner documentation](source/deploy/security-scanner/README.md) | [Reproduction entry point](reproduce/reproduce-linux.sh); a complete run on a fresh machine remains unverified |

Start with the root [README](README.md) and [TEST_REPORT](TEST_REPORT.md), then follow `Stage → Cached → Analyze/AnalyzeBatch → persist complete evidence → download admission` through the source. Cache hits still require the preceding file reads and digest verification. A prefix check alone cannot authorize a download.

## Scope of Verification Commands

```bash
# File integrity in a clean publication directory; does not execute the product
python3 scripts/verify_publication.py
python3 reproduce/verify_source.py

# Run only after preparing the environment and dependencies: selected Go security regressions
bash reproduce/reproduce-linux.sh test-go

# Prepare the complete signatures and scanner image first: isolated scanner tests on Linux
bash reproduce/reproduce-linux.sh test-scanner
```

Run the upstream `make test.unit` / `make test.e2e` / `make test.e2e.kind` commands inside `source/`. They have different environment prerequisites; the integrity workflow at this repository's root cannot replace them. See the [reproduction instructions for this version (Chinese)](README.zh.txt) for the complete deployment steps and GB-scale quota settings.
