# 交接说明：模型后门审计链路（代码 + Hub 接入需求）

> 给接手的工程/评审：这份文档说明"已经有什么、代码在哪、怎么验证、Hub 还差什么"。

## 0. 当前状态（一句话）

- **Python 审计侧：已在云端真实跑通**（2 个公开木马检出、2 个基座放行、worker+marker+403 闭环）；
- **Go Hub 侧：代码已写完，`go build ./...`、`go vet`、适配器单测均通过**；
- **尚未做**：把 Hub 服务真正启动、打开开关、走一次 HTTP 下载验证 403（需要构建镜像并准备模型仓库）。

## 1. 代码清单

### 1.1 Python（本仓库 `source/deploy/security/audit/`）

| 文件 | 作用 | 关键接口 |
|---|---|---|
| `audit_pair.py` | 审计主程序：一次加载 base+suspect，跑 diff/probes/blind，输出 report | `python audit_pair.py --model <dir> --base <dir> --verifier refusal_logit --out report.json` |
| `binding.py` | 内容绑定：模型/基座目录摘要（大模型采样哈希并记录方法） | `manifest_digest(dir) -> {digest, method, bytes, files}` |
| `gate.py` | 报告 → 决策；校验报告完整性；marker 带 binding | `decide(report)`；CLI `--report --marker-dir --out --fail-closed` |
| `gate_guard.py` | 下载侧校验：marker 必须与期望的 digest/版本匹配，否则 403 | `ensure_download_allowed(model_dir, expected)` 抛 `AuditDenied` |
| `audit_worker.py` | 异步 worker：领取队列、跑审计+gate、写 report/status/marker；attempt + 租约恢复 | `python audit_worker.py --queue-dir q --report-dir r --once` |
| `hooks.py` | **给 Hub 的两个调用**：入队、下载检查 | `enqueue_audit(...)`、`check_download(...)`、`expected_for(record)` |
| `blind_invert.py` | 盲检：软前缀反演 + 自然词坐标搜索（探索性，见局限） | CLI `--suspect --base --refine` |
| `verifiers.py` | 验证器集合（refusal_shift / payload_* / judge 等） | `make_verifier(name)` |
| `probes.py` / `diff.py` / `verdict.py` / `audit_cli.py` | 分阶段旧版（保留兼容） | — |
| `test_audit_units.py` / `test_audit_v2.py` / `test_worker.py` / `test_gate_guard.py` / `test_hooks.py` / `test_gate_worker_v2.py` | 单元/集成测试 | `python -m unittest ...` 或直接运行 |
| `AUDIT_CHAIN_CN.md` | 链路完整说明（架构/五段/契约/状态机/Go 接入/实测/局限） | — |
| `INNOVATION_CN.md` | 创新点、难点、与现有方法的对比定位（含"未做 head-to-head"声明） | — |
| `EVIDENCE.md` | 实测证据（云端运行数字、规则演进、规避矩阵、盲检结果） | — |
| `HOOKS.md` / `INTEGRATION.md` / `REVIEW_WORKFLOW.md` / `RUNBOOK.md` | 接入/复核/运维文档 | — |

### 1.2 Go（MatrixHub 仓库，本次新增/修改）

| 文件 | 状态 | 内容 |
|---|---|---|
| `internal/domain/security/modelaudit.go` | 新增 | `ModelAuditState`、`ModelAudit`、`ModelAudits` 接口、`WithModelAudits`、`checkModelAudit` |
| `internal/domain/security/service.go` | 修改 | `Service` 增加 `modelAudits` 字段；`Check` 调 `checkModelAudit`；`Process` 在扫描成功后 `Enqueue` |
| `internal/repo/modelaudit.go` | 新增 | `ModelAuditFileStore`：读 `status.json`、写队列项；路径模板展开 |
| `internal/repo/modelaudit_test.go` | 新增 | pending / deny / 入队 / 未配置 四个用例 |
| `internal/apiserver/security.go` | 修改 | `MATRIXHUB_MODEL_AUDIT_*` 环境变量开关，注入 `WithModelAudits` |

## 2. 数据契约（Hub ↔ Python 的唯一接口）

### 2.1 队列项（Hub 写，worker 读）

路径：`<MATRIXHUB_MODEL_AUDIT_QUEUE>/<repo 中 / 替换为 _>@<sha 中 @ 替换为 _>.json`

```json
{
  "revision": "org/model@<40位 commit SHA>",
  "modelPath": "/srv/models/org/model/<sha>",
  "basePath": "/srv/models/base/<sha>",
  "verifier": "refusal_logit",
  "prompts": 8,
  "enqueuedAt": "2026-10-28T09:00:00Z"
}
```

### 2.2 报告（worker 写，`report/<repo>_<sha>/report.json`）

关键字段：`schema`、`verdict`(high/medium/low)、`evidence`、`stages.diff`、`stages.probes`、
`modelBinding`、`baseBinding`、`complete`、`seconds`。

### 2.3 状态（worker 写，`report/<repo>_<sha>/status.json`）

```json
{"schema": "matrixhub.model-audit.worker/1", "revision": "...", "gate": {...}, "finishedAt": "..."}
```

`gate` 即 `gate.py` 的输出，Go 适配器只读这里。

### 2.4 Marker（worker 写，`<modelPath>/.matrixhub-audit.json`）

```json
{
  "schema": "matrixhub.model-audit.gate/2",
  "verdict": "high",
  "decision": "deny",
  "action": "quarantine",
  "evidence": ["trigger ... rate=0.972 clean=0.304 margin=0.217"],
  "binding": {
    "model": {"digest": "...", "method": "sha256-sampled"},
    "base": {"digest": "...", "method": "sha256-sampled"},
    "auditVersion": "2.0",
    "policyVersion": "matrixhub-behaviour-audit/2026-10-28",
    "verifier": "refusal_logit",
    "prompts": 8,
    "thresholds": {}
  },
  "decidedAt": "..."
}
```

## 3. Hub 接入需求（Go 侧三处）

### 3.1 下载准入（必须）

`Service.Check` 在文件扫描检查通过后调用：

```go
if err = s.checkModelAudit(ctx, repo, commit, &d); err != nil {
    _ = s.audit(ctx, repo, commit, "model-audit-admission", &d)
    return d, err
}
```

`OpenApproved` / `CheckLFS` 都经过 `Check`，因此 HTTP 下载、HEAD、Range、LFS 共用同一判定。

**要求**：这段必须在"返回任何模型字节、206、304、下载地址"之前执行；若 Hub 还有其他旁路
（预签名 URL、对象直链、ZIP 打包），必须先收敛到 `Check` 或单独加同样的检查。

### 3.2 扫描完成入队（必须）

`Service.Process` 在 `store.Finish` 接受报告后：

```go
if s.modelAudits != nil && report.Complete && (report.State == Pass || report.State == Warn) {
    enqueueCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
    defer cancel()
    if enqueueErr := s.modelAudits.Enqueue(enqueueCtx, task.Repo, task.Revision); enqueueErr != nil {
        _ = s.audit(enqueueCtx, task.Repo, task.Revision, "model-audit-enqueue", ...)
    }
}
```

**要求**：只在"完整封存 + 扫描 complete + pass/warn"后入队；不能按单文件上传或 HTTP 200 触发。

### 3.3 适配器与开关（必须）

- `ModelAuditFileStore`：读 `status.json`，写队列项；路径模板由环境变量提供。
- 开关（不设置即保持旧行为）：

| 环境变量 | 必填 | 示例 |
|---|---|---|
| `MATRIXHUB_MODEL_AUDIT_REPORTS` | 是 | `/srv/matrixhub/audit/report` |
| `MATRIXHUB_MODEL_AUDIT_QUEUE` | 是 | `/srv/matrixhub/audit/queue` |
| `MATRIXHUB_MODEL_AUDIT_MODEL_PATTERN` | 是 | `/srv/models/{repo}/{commit}` |
| `MATRIXHUB_MODEL_AUDIT_BASE_PATTERN` | 是 | `/srv/models/base/{commit}` |

**要求**：未设置 `REPORTS` 时 Hub 行为与现在完全一致；设置后，缺报告/报告损坏/非 allow 一律拒绝。

## 4. 状态与失败语义

| 状态 | 下载 | 说明 |
|---|---|---|
| pending | 403 `audit_pending` | 排队/运行/重试 |
| deny | 403 `audit_denied` | 审计拒绝 |
| review | 403 `audit_review` | 需人工复核，或审计无法完成 |
| allow | 正常 | 仍受文件扫描与权限约束 |

- worker 崩溃/OOM/超时 → 重试期间 pending，耗尽后 review；
- 报告缺字段、`complete=false`、marker 缺失/损坏/digest 不匹配/版本过期 → 拒绝；
- **基础设施失败不得当 allow，也不得当成"检测到后门"**。

## 5. 验证方式

### 5.1 Python 侧（已跑通）

```bash
python test_audit_units.py
python test_audit_v2.py
python test_worker.py
python test_gate_guard.py
python test_hooks.py
python test_gate_worker_v2.py

# 真实审计（需要 GPU + 模型）
python audit_pair.py --model <model> --base <base> --verifier refusal_logit --prompts 8 --out report.json
python gate.py --report report.json --marker-dir <model> --out gate.json --fail-closed
python audit_worker.py --queue-dir queue --report-dir report --once
```

### 5.2 Go 侧（已验证）

```bash
docker run --rm -v <hub>:/src -w /src -e GOPROXY=https://goproxy.cn,direct -e GOSUMDB=off \
  golang:1.26.8-alpine3.23 sh -c "go build ./...; go vet ./internal/domain/security/ ./internal/repo/"
# 结果：BUILD_EXIT=0，VET_EXIT=0

# 适配器单测
go test ./internal/repo/ -run TestModelAudit -count=1
# 结果：ok
```

### 5.3 还没做（接手后第一件事）

1. 构建 Hub 镜像；
2. 用 `MATRIXHUB_MODEL_AUDIT_*` 启动；
3. 上传/准备一个模型仓库 → 触发扫描 → 观察队列文件生成；
4. 跑 worker（独立容器，挂同一 report/queue 卷）；
5. 下载该模型：pending/deny 时返回 403，allow 后返回 200；
6. 补 5 个测试：HEAD、Range、304、marker 缺失、worker 崩溃。

## 6. 已知缺口（交接时明确）

1. **Hub 未做真实 HTTP 端到端**（只有 Python 侧闭环演练）；
2. **位置覆盖只有前缀/后缀**，句中和换行后未实现（已被实验证明后缀可规避）；
3. **盲检不可归因**（软前缀 gap 1.0，离散 0.44）；
4. **样本量 2 正 2 负**，统计区间宽；
5. **无自适应攻击测试**（正则化/延迟触发/语义触发）；
6. **未与开源检测方法做 head-to-head**（已在 `INNOVATION_CN.md` 明确声明）；
7. 本地笔记本 8 GB 显存只能跑小模型，4B/8B 靠云端或量化档（量化档需单独标定）。

## 7. 给接手方的建议顺序

1. 先读 `AUDIT_CHAIN_CN.md`（整体）→ `HOOKS.md`（Hub 三处）→ 本文档（代码位置）；
2. 跑 Python 测试确认环境；
3. 跑 Go build/vet/test 确认编译；
4. 构建 Hub 镜像，用 env 打开开关，做 5 个 HTTP 用例；
5. 再决定是否补位置覆盖与开源对比。