# 实测证据索引

截点：2026-10-09 01:26（Asia/Shanghai）。源码仓库与 runtime 是同级目录，以下路径均相对 `上海开源赛2026/runtime/`。报告入口为 [REPORT.zh.md](REPORT.zh.md)。独立套件有重叠，不合并成虚假的总计数。证据 hashes 由 `runtime/report-delivery/evidence-index.json` 和 `SHA256SUMS.txt` 记录。

## 最新精确加载引用验收（2026-10-09 01:26）

测试代码提交 `63c0e0e9b1ebdf02a707c378747962e96c57bb16`。下面 C 系列对应新增规则及证据 UI；F / B / S 系列为各自历史版本，不自动覆盖新源码。

| ID | 原始文件 / 目录 | 用途与结论 |
| --- | --- | --- |
| C01 | capability-lab-v1/scanner-unit-final.log + scanner-unit-final-exit.json + scanner-accepted-evidence.json | 52/52，36.538s，0 skip，真实核心镜像 e1baab9f… 执行；最终 b7eb7ecc… 只改集成断言，scanner/tests.py 字节相同，未重复执行这52例 |
| C02 | capability-lab-v1/scanner-integration-accepted.log + scanner-integration-accepted-exit.json | 最终 b7eb7ecc… Unix 11/11，119.512s，exit0；新 generation 2e17cfeb… |
| C03 | capability-lab-v1/scanner-integration-final.log + scanner-integration-final-exit.json | 先前11组 exit1，131.384s；SAFE+broken 的422精确错误码断言不符，原失败保留，不计PASS |
| C04 | capability-lab-v1/official-unit-attempt02.log + official-unit-attempt02-exit.json + official-unit-summary.json | 实际官方 make test.unit exit0，23包PASS/26无test，short/count1、默认排除HF；没有运行完整Ginkgo/KIND，不声称race或覆盖率 |
| C05 | capability-ui-checks-v1/ui-build-manifest.json | 新证据UI：8/8定向测试、TypeScript、lint、生产build和167资产hash；不与旧32测试相加 |
| C06 | capability-lab-v1/application-build-evidence.json + build-manifest.json | app 356f1566…、scanner b7eb7ecc…；35源码/8harness与测试代码提交绑定 |
| C07 | capability-lab-v1/results/capability-97f08f51dfda/experiment/results.json + supervisor-result.json + capability-lab-v1/outer-attempt02-exit.json | 六个真实HF/HTTP业务场景全部PASS，真实child0/parent0，17项API/文件/session收尾与三个自有卷清理complete；最终PASS由监督器联合判定，child的success-candidate不是单独PASS |
| C08 | capability-lab-v1/results/capability-97f08f51dfda/ui-review.json + ui-proof/*.jpg | 正常新会话真实产品route、静态引用/stream0/offset2、高阈值策略v2核对；console error/warn0。reference截图为视口截图，风险卡细节另有真实CUA观察与review字段；不冒充全页截图 |
| C09 | capability-lab-v1/results/capability-f2aea7f76703/supervisor-result.json | 首次Git信任目录preflight失败，child未执行、无fixture；旧manifest/script/result/hash完整保留 |
| C10 | official-e2e-20261009-v1/ | 官方E2E/KIND静态计划；NOT EXECUTED。共享helper含既有凭据的读取被自动审批拒绝，未绕过或间接使用 |

当前六场景总child时间519.375s包含样本准备、业务、等待只读UI与清理，不能称纯扫描耗时。63MiB=66,060,288bytes是合成合法U8 Safetensors，不是训练模型或多GB容量证明。检测到受限入口引用不能证明调用或恶意。两次失败和已中断16h原证据保留。

## 历史终轮证据

| ID | 原始文件 / 目录 | 用途与结论 |
| --- | --- | --- |
| F01 | backend-final-build-04.json + linux-feature-build-final-04.log + docker-backend-build-final-04.log | app image cfd5e30a...、binary a3a84b5e...；build exit 0，构建标识只对应这轮 |
| F02 | feature-tests/repository-unit-suite-final-03.jsonl | 23 包 pass，215 顶层 / 403 pass events，2 Windows skip、26 no-test 包；包含最终 SQLite |
| F03 | feature-tests/hf-security-final-03.jsonl | 6 顶层 / 47 events pass，25.687 s，0 skip |
| F04 | feature-tests/linux-security-race-final-02.jsonl | Linux -race 60 顶层 / 103 events，2 包 pass，0 skip |
| F05 | feature-tests/mysql-security-final-02.jsonl + mysql-security-final-02-fixture.json | MySQL8.4.11，38 顶层 / 66 events pass，21.503 s；fixture exit0且已移除，密码未写入报告 |
| F06 | feature-tests/go-vet-final-03.log + golangci-final-02.log | vet exit0；golangci 0 issues；保留初次 lint 失败 |
| F07 | feature-tests/mock-generation-final-03.json + .log + mock-generation-final-04.json + .log + security-handler-after-generation-04.jsonl | final03 一文件变化；final04 16/16 identical；随后 handler10顶层/18events pass |
| F08 | feature-tests/mysql-security-final-01-setup-failure.json | unavailable local tag setup exit125、testExecuted=false；不可计作业务失败或pass |
| F09 | security-evidence/scanner-final-20261008-115828-summary.json + -evidence.json + -build.log + -unit.log + -integration.log + -capacity.log | scanner a4736049... / generation9acc7486...；29UT/11Unix/5容量，0skip，真实原日志SHA |
| F10 | security-lab-results/job-002/results.json + command.log + deployment.json | 12:05:50-12:08:02北京；20/20=17业务+3token清理；真实SSH RawGitDisabled、2 Safetensors全链路、6states、47审计记录；passed=true |
| F14 | security-lab-results/matrix-security-lab-v3/job-103/results.json + command.log + deployment.json + script-snapshot.py | 13:54:31-13:59:59北京，6/6应用benchmark；cold/cache/force、官方上传、manifest9/33/34/9/5/2、48Range+6HEAD+6GET，单次事后stats，328.141s；failures0 |
| F15 | security-lab-results/matrix-security-lab-v3/job-104/soak-start-evidence.json + deployment.json + script-snapshot.py | 14:01:34 开始；控制器丢失，195 成功轮，INCOMPLETE。原结果、日志和启动记录保留；新实验不拼接旧时长 |
| F13 | security-lab-results/matrix-security-lab-v3/job-102/results.json + command.log + deployment.json | 13:46:58-13:53:45北京；4/4真实fault，failures0、406.968s；tasks-only offline恢复、160s取消观察、SIGKILL Exit137+lease、完整CVD+canarygeneration切换与恢复；完整history不变 |
| F12 | security-lab-results/matrix-security-lab-v3/job-101/results.json + command.log + deployment.json | 13:43:33-13:45:48北京；最终冻结harness SHA6bdb137f...独立v3 fixture，20/20=17业务+3token清理；6states、真实SSH/Safetensors、47audits，passed=true |
| F11 | security-lab-results/job-003/command.log + deployment.json | compose JSON 默认GBK解码前置失败，业务未执行；修复后真实业务通过另见F13 |

短 hash 只用于表中辨识；完整固定 image、generation、binary、script hash 见原 JSON 与报告第6节。已测试镜像标识不自动覆盖后续源码或 harness 改动。封版源码包另有源码清单，不能以 binary hash 代替。

## 独立复核记录（review-only）

| ID | 原始文件 / 目录 | 用途与边界 |
| --- | --- | --- |
| Q01 | ASTRA_RELIABILITY_REVIEW_20261008.md | 只读代码/断言与 Windows Job 生命周期复核；保存三个最终 harness SHA256；不是新测试通过证明 |

复核结论允许进入真实 v3 实验。控制器跨独立工具调用存活不证明能承受 app 退出、用户休眠或机器重启；控制器终止后的新 fixture 不能与旧时长拼接成连续长测。

## 历史与其他独立证据

| ID | 原始文件 / 目录 | 用途与结论 |
| --- | --- | --- |
| B01 | feature-tests/repository-unit-suite-02.jsonl | 官方单元选择集 23包 pass，182顶层 / 329 events，2平台 skip；非所有集成测试 |
| B02 | feature-tests/domain-batch-02.jsonl | domain batch / fallback 17顶层 / 32events pass |
| B03 | feature-tests/security-db-01.jsonl | 初版 SQLite 11 pass |
| B04 | feature-tests/mysql-security-01.jsonl | 初版 MySQL8.4.11 11 pass，已由 F05 新终轮补全 |
| B05 | feature-tests/security-repo-02.jsonl | Git/LFS / immutable artifacts 20顶层 / 27events pass |
| B06 | feature-tests/linux-security-race-01.jsonl | Linux竞争 40顶层 / 79events pass；非新增全部补丁终轮 |
| B07 | feature-tests/domain-store-final-review-01.jsonl | 45顶层 / 84events，3包 pass |
| B08 | feature-tests/security-atomic-offline-01.jsonl | 60顶层 / 103events，2包 pass，含离线/原子审计 |
| V01 | feature-tests/govulncheck-01.jsonl | 3 module、0 package / symbol finding；保留已知依赖风险 |
| V02 | feature-tests/golangci-01.log | 初次14issues失败，不能当最终成功证据 |
| S01 | security-evidence/scanner-batch-unit.log | 21容器checks pass |
| S02 | security-evidence/scanner-batch-integration.log | 10 Unix组 pass |
| S03 | security-evidence/scanner-resource-limits.log | 2资源组 pass |
| S04 | security-evidence/scanner-baseline8.log + scanner-batch8.log | 八文件109.5724→14.3484s，同规则同限制，非应用吞吐 |
| S05 | security-evidence/scanner-capacity-corrected-harness.log | 63MiB / 32files / exact256MiB成功；33files / +1byte拒绝 |
| S06 | security-evidence/scanner-integration.log + scanner-integration-fixed-fixture.log | 初始warning fixture错误与更正后的成功，规则未弱化 |
| S07 | security-evidence/scanner-capacity.log | 初次harness失败保留 |
| S08 | security-evidence/safetensors-dispatch-probe.log | header128分派失败probe保留；F09/F10新generation修复复测通过 |
| E01 | security-e2e/run02/results.json + samples.json + e2e-script-snapshot.py | 17/18pass、六状态真实、hash/版本/协议证据；SSH失败 |
| E02 | security-e2e/run02-ssh-supplement/results.json | 已认证后security_unavailable，暴露canonical scope问题 |
| E03 | transport-ssh-scope-fix.log | 源码修复Go回归；真实SSH终轮另见 F10 |
| U01 | security-ui-full-lint.log / security-ui-typecheck.log / security-ui-build.log / security-ui-full-tests.log | UI四检查成功，6files32tests |
| U02 | security-openapi-verification.json + .log | 8operations / 29local refs / params |
| U03 | security-cookie-tests.log + security-ui-cookie-auth-failure.jpg | Cookie修复回归与原失败截图 |
| U04 | security-ui-clean-run02-zh.jpg / eicar-findings / unsafe-findings / audits / history / policy | 真实中文页面，原像素可复核 |
| D01 | demo-capture/run01/matrixhub-security-demo.webm + .zh.srt | 253.5s真实采样视频/8段字幕，无音轨 |
| D02 | demo-capture/run01/manifest.json + trim-manifest.json + video-verification.json + video-qa.json + SHA256SUMS.txt | 165原帧 / UTC / hash / 剪辑 / 解码QA |
| D03 | demo-capture/run01/视频提交说明.md + 中文演讲提纲.md + qa/*.png | 透明说明采样与边界；八章节视觉检查 |

`security-e2e/run01` 和其他初次构建 / 测试失败在原工作区保留。公开证据包只挑选无秘密 allowlist 文件，并分别注明成功、失败、跳过与待复测。不得打包 live DB、data volume、token、private key、临时密码 / 密码 hash、浏览器 session 或含旧凭据的脚本。源图/视频以已有独立 SHA 清单为准，不修改原证据来消除失败。

## 流式结果统计方法

Go JSONL 按 `Action=pass` 且有 `Test` 区分测试事件；无 `/` 的名称算顶层测试，有 `/` 的为 subtest。package pass、无测试和 Test skip 分开记录。govulncheck 使用 JSON stream decoder，不能假定每行一个完整对象；finding trace 只有 module 为 module层，含 package 为 package层，含 function / symbol 和调用栈才用于可达符号说明。exit0不删除module风险。

## 封版时增补

独立 scanner、新 generation、runtime E2E、lint、mock、MySQL 已补入终轮表。fault已由F13补齐；应用benchmark已由F14补齐；soak只记录F15启动，终态到达后继续添加独立行、运行镜像标识、时间、脚本hash与结果，并更新报告截点。不覆盖旧run02，不能把多个不同版本的部分成功拼成同一个全通过封版结果。
