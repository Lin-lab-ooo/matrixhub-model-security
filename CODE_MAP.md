# 开发者代码导航

本仓库根目录用于发布说明与证据，应用源码位于 `source/`。从下列入口可定位实际实现；历史设计文档中的版本描述不覆盖根目录版本锁。

| 要了解的机制 | 生产实现 | 相关测试 |
| --- | --- | --- |
| 任务状态、文件批次、跨文件流水线与缓存使用 | [service.go](source/internal/domain/security/service.go) | [service_pipeline_test.go](source/internal/domain/security/service_pipeline_test.go)、[batch_test.go](source/internal/domain/security/batch_test.go) |
| Git/LFS 内容读取、快照、64 KiB 前缀预检 | [security_artifacts.go](source/internal/repo/security_artifacts.go)、[security_stream.go](source/internal/repo/security_stream.go) | [security_artifacts_test.go](source/internal/repo/security_artifacts_test.go)、[security_prefix_test.go](source/internal/repo/security_prefix_test.go) |
| Unix socket 扫描协议、请求预算和完整扫描优先 | [security_scanner.go](source/internal/repo/security_scanner.go)、[security_scanner_gate.go](source/internal/repo/security_scanner_gate.go) | [security_scanner_gate_test.go](source/internal/repo/security_scanner_gate_test.go) |
| ClamAV/Picklescan 集成、格式结构和有限语义解析 | [scanner.py](source/deploy/security-scanner/scanner.py) | [tests.py](source/deploy/security-scanner/tests.py)、[integration_tests.py](source/deploy/security-scanner/integration_tests.py)、[prefix_tests.py](source/deploy/security-scanner/prefix_tests.py) |
| 完整证据保存、任务与审计 | [security_db.go](source/internal/repo/security_db.go) | [security_db_evidence_test.go](source/internal/repo/security_db_evidence_test.go)、[security_db_completion_test.go](source/internal/repo/security_db_completion_test.go) |
| 人工复核身份绑定与事务 | [review.go](source/internal/domain/security/review.go)、[security_review.go](source/internal/repo/security_review.go) | [review_test.go](source/internal/domain/security/review_test.go)、[security_review_test.go](source/internal/repo/security_review_test.go) |
| Web 安全卡、风险证据、复核表单 | [ModelSecurityCard.tsx](source/ui/src/features/models/security/ModelSecurityCard.tsx)、[SecurityReportEvidence.tsx](source/ui/src/features/models/security/SecurityReportEvidence.tsx)、[SecurityReviews.tsx](source/ui/src/features/models/security/SecurityReviews.tsx) | [security.evidence.test.ts](source/ui/src/features/models/security/security.evidence.test.ts)、[security.reviews.test.ts](source/ui/src/features/models/security/security.reviews.test.ts) |
| 专用本地部署与扫描器隔离配置 | [compose.yaml](source/deploy/security/compose.yaml)、[扫描器说明](source/deploy/security-scanner/README.md) | [复现入口](reproduce/reproduce-linux.sh)；新机完整运行仍待验证 |

建议先读根 [README](README.md) 和 [TEST_REPORT](TEST_REPORT.md)，再沿 `Stage → Cached → Analyze/AnalyzeBatch → 保存完整证据 → 下载准入` 阅读源码。缓存命中仍经过前面的文件读取和摘要校验；前缀检查不能单独产生下载批准。

## 验证命令的范围

```bash
# 干净发布目录的文件完整性，不执行产品
python3 scripts/verify_publication.py
python3 reproduce/verify_source.py

# 环境和依赖准备好后才运行：选择性的 Go 安全回归
bash reproduce/reproduce-linux.sh test-go

# 先准备完整规则与扫描器镜像：真实 Linux 隔离扫描器测试
bash reproduce/reproduce-linux.sh test-scanner
```

上游 `make test.unit` / `make test.e2e` / `make test.e2e.kind` 在 `source/` 内执行。它们具有不同环境前提，不能用本仓库根目录的完整性工作流替代。完整部署步骤与 GB 配额见 [本版复现说明](README.zh.txt)。
