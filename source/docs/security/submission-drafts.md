# 社区功能提案与 PR 本地草稿

这些文本尚未发送到 GitHub、邮件或其他社区渠道。它们用于审阅和后续投稿，
不是社区认可或合并记录。最终应用 E2E、故障、性能与长测结果应先在
`REPORT.zh.md` 和 `EVIDENCE_INDEX.zh.md` 中核验，再将下面的验证状态更新为实测结果。
不在草稿中填入临时账号、令牌、私钥或测试密码。

本稿按照仓库 `.github/ISSUE_TEMPLATE/01-FEATURE.md`、
`.github/PULL_REQUEST_TEMPLATE.md` 和 `CONTRIBUTING.md` 的现有字段组织。
大型贡献的技术范围仍需维护者讨论；本地实现不代表维护者已经同意方案。

## Feature Issue 草稿

**Title**

`[Feature] Bind model scan evidence to immutable artifacts and current download admission`

**What would you like to be added**:

Add an opt-in artifact security workflow that keeps uploads asynchronous, records
complete static scan evidence for an immutable model commit, and admits file
downloads only when that evidence still satisfies current authorization, scanner
generation and project policy.

For example, if a branch moves after a client obtains an LFS action, reopening
that action should continue to refer to the original commit and verified bytes.
If a forced rescan, rule update, policy change or role removal invalidates access,
the previously issued action should be checked again when content is opened.

The proposed first version includes:

- A domain service and repository interfaces for tasks, reports, policies and
  decision audits, following the existing backend dependency boundaries.
- Durable six-state tasks (`pending`, `scanning`, `pass`, `warn`, `block`, `fail`),
  attempt/lease fencing, cancellation, forced rescans and immutable report history.
- Verified Git/LFS bytes staged as read-only snapshots. A complete report and
  subsequent file response refer to the same immutable commit, size and SHA256.
- A fixed Unix-socket scanner protocol with pinned ClamAV and Picklescan, complete
  rule snapshots, no application credentials or network, and explicit resource
  and format coverage limits. No uploaded model is loaded or executed.
- Consistent admission for HF resolve/resolve-cache, native file URLs and scoped
  LFS actions/content, with existing project RBAC and an evidence UI.

**Why is this needed**:

A finding list is useful only when it describes the bytes the client receives.
Mutable refs, LFS indirection, cached actions and alternate transports make this
binding a separate concern from choosing a scanning engine. The workflow also
needs to distinguish a completed static analysis from an unavailable scanner,
unsupported format or coverage limit; these conditions must never appear as a
clean approval.

This proposal deliberately starts with a bounded deployment: one staging writer
and one scanner worker, 64 MiB per file, 256 MiB per task, 1,000 files, and retained
snapshot byte/entry quotas. When enforcement is enabled, raw HTTP/SSH Git fetch,
historical patch output and global LFS object reads are restricted because they
do not provide the required per-file admission context. These compatibility
costs, format support and cleanup requirements should be reviewed explicitly.

Static engine results do not prove that arbitrary model code is safe to execute.
The host, application database, staging writer, scanner wrapper and selected
engines remain trusted components. Multi-replica staging and automatic
report-aware garbage collection are future work.

**Completion checklist**:

- [ ] Design doc: review `docs/security/design.md`, `adr-scanner.md` and
  `threat-model.md`; agree on the supported transports and enforcement costs.
- [ ] API change: review evidence, history, rescan, task cancellation, policy and
  audit routes under `/api/security/v1alpha1/models/{namespace}/{model}`.
- [ ] Test: review domain/store/transport coverage and executed official-client,
  real-engine, fault-recovery and workload evidence in the evidence index.
- [ ] Docs update: review deployment, operational limits, unsupported formats,
  the localized report and reproducible scripts.

Suggested task split for maintainer review: (1) domain/store/migrations and
snapshot binding; (2) scanner protocol and hardened deployment; (3) transport
admission and compatibility controls; (4) evidence API/UI and operational tests.
Each task should link its own focused PR before the parent checklist is closed.

## Pull Request 草稿

**Title**

`Add opt-in model artifact evidence and consistent download admission`

#### What type of PR is this?

/kind feature

/kind api-change

#### What this PR does / why we need it:

Adds asynchronous, opt-in model artifact scanning whose complete evidence is
bound to an immutable commit, actual Git/LFS bytes and a scanner generation.
Supported file downloads reopen the verified snapshot after checking current
project authorization and policy, so a moved branch, stale LFS action or changed
policy cannot turn a previous approval into access to different bytes.

The implementation adds domain ports, durable task/report/cache/policy/audit
adapters, SQLite/MySQL migrations, a bounded worker, protected content handlers,
an evidence API/UI, and a credential-free offline scanner deployment using
ClamAV and Picklescan. Report publication uses attempt/lease fencing; cancellation
and rescans retain historical reports. Incomplete format coverage, missing
engines, timeouts and resource limits remain denied even in audit mode.

#### Which issue(s) this PR fixes:

`Refs <maintainer-reviewed feature issue URL>`

Replace this placeholder only after an actual issue exists. Use `Fixes` only if
the reviewed issue's complete checklist is fulfilled by this PR.

#### Special notes for your reviewer:

- Enabling global enforcement restricts raw HTTP/SSH Git fetch, historic patch
  output and unscoped global LFS content. The supported file routes, current
  policy checks and denial behavior are described in `docs/security/design.md`.
- The first deployment validates one staging writer and one scanner worker.
  Coverage limits are 64 MiB/file, 256 MiB/task and 1,000 files, with retained
  byte/entry quotas. Automatic snapshot garbage collection and shared staging
  writers are outside this version.
- The scanner wrapper and engines are trusted; they share a constrained
  container and UID. Read-only inputs, absent credentials and blocked network
  reduce access but do not establish integrity after a scanner compromise.
- Validation records: `REPORT.zh.md`, `EVIDENCE_INDEX.zh.md`, and
  `docs/security/scanner-validation.md`. Final application E2E, reversible faults,
  benchmarks and soak results must be populated from the actual run artifacts
  before publishing this draft. A pending run is not a passing check.
- Workload Docker stats are single observations after each case/iteration.
  Eight sampled range requests use nearest-rank p95, which equals the sample
  maximum; neither measurement establishes a production peak or SLO.
- All submitted commits require a DCO signoff. This local draft contains no
  assertion of remote CI status, maintainer approval or upstream merge.

#### Checklist

- [x] Tests (unit, transport, scanner and reproducible application harnesses)
  added or updated. Final live-run status remains recorded separately above.
- [x] Technical and usage docs added, including threat boundaries, scanner
  provenance, deployment and operating limits.
- [ ] Final unit/static/database checks and live application results verified
  against the exact submitted source and scanner generation.
- [ ] Issue reference, DCO signoffs and remote CI results verified after the
  external contribution exists.

#### Does this PR introduce a user-facing, API-facing, or operator-facing change?

```release-note
Added opt-in model artifact security evidence, project policies and protected
file downloads for complete immutable scan results. Action required when
enabling enforcement: provision the isolated scanner and verified rule snapshot,
configure staging quotas, and account for restricted raw Git/history and global
LFS reads. Uploads remain asynchronous; unsupported or incomplete analysis is
denied, and operators can inspect reports, request rescans and cancel tasks.
```

## 投稿前核对记录

把最终结果文件中的 source/script hashes、实际 backend/scanner image IDs、扫描
generation、测试数、失败保留路径和长测起止时间对应到证据索引。只描述已经执行
的验证，不把计划、离线单测或扫描器直测替代成正式应用测试。公开附件不得含
临时凭据；确认账号身份后以 `git commit -s` 生成真实 DCO 签署。

此 Feature Issue 讨论新增能力，不指控未经复现的上游漏洞。若后续发现独立的
可复现漏洞，按仓库 `SECURITY.md` 的私密 GitHub Security Advisory 流程单独处理。
