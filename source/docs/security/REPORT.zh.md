# MatrixHub 模型制品恶意内容扫描与安全准入系统

2026 上海开源软件应用创新大赛 · DaoCloud 赛题技术与实测报告

**证据截点：2026-10-09 01:26（Asia/Shanghai）。新一轮精确嵌套加载引用规则、结构化证据、真实六场景与产品 UI 已完成联合验收；监督器及实验子进程实际 exit 0，独立卷和临时会话已清理。此前版本的 E2E、故障和基准分别保留；16 小时长测 INCOMPLETE，完整官方 E2E / KIND 未执行。**

基于官方 MatrixHub 上游提交 `6890726abe272767d26ce1a6b0580b0718f232c0`。本报告只把已保存原始结果的执行记为通过；每轮明确区分源码测试、镜像构建和真实运行验证，不把不同版本的部分成功拼接成一轮通过。作者身份按用户已提供信息为复旦大学本科生，姓名与参赛团队信息由本人补充。

## 1. 作品解决什么问题

模型仓库的上传权限不能证明模型文件可安全分发。一个仓库版本可能含 Git 文件、真实 LFS 对象、危险序列化引用或恶意软件签名；分支、文件源、用户权限和规则版本还会变化。作品将“扫描了什么”与“实际下载了什么”绑定起来：解析不可变提交，验证真实字节，发布只读快照，保存完整证据，并在每次受保护下载时核对当前身份、策略和扫描器版本。

上传与异步扫描分离。待扫描、扫描中、通过、警告、阻断、扫描失败六种状态分别展示。不完整覆盖、扫描器离线、格式不支持和超限都不会成为安全通过。静态检查与签名检测有误报、漏报和格式边界；一次通过不是执行模型的安全许可。

**本轮最新成果：**精确识别 `torch.storage._load_from_bytes` 静态引用并标为 high；修复 memo-of-GET 字面符号传播，保存指令与哈希化归档证据。新运行 `capability-97f08f51dfda` 六场景全部符合预期：默认 high 已阻断受限引用所在的完整 revision，正常 63 MiB 合成 Safetensors 仍可下载，普通 unknown 保持 medium。真实产品页面展示引用及策略，17 项 API / 本地文件 / 会话收尾和 3 个独立卷清理完成。52 项单测基于相同核心源码字节继承，最终镜像 11 组 Unix 协议实跑通过；边界和固定版本见第 14 节。ASTRA ULTRA 297 项只读证据核验、0 失败，是复审断言数，不是 297 个新增业务测试。

**此前版本的实测结果：**完整官方规则下真实 ClamAV 1.4.6 识别标准 EICAR；Picklescan 1.0.5 静态识别危险 Pickle 引用。历史正式 E2E `job-101（v3）` 为 20 / 20 通过，其中 17 项业务验证、3 项测试 token 撤销；真实 SSH 拒绝协议、有效 128-byte header Safetensors 上传到下载、伪装 Safetensors 覆盖失败均通过，六状态全部真实观察。v3/job-102 的四项真实故障恢复均通过，整体 failures=0、406.968 秒；v3/job-103 六组完整应用 benchmark 全部通过，冷上传到准入为13.660-27.802秒。此前 `9acc7486...` generation 独立扫描器 29 项容器单测、11 组 Unix 集成和 5 个容量条件通过，均无 skip；这些不视为本轮新 generation 的重新执行结果。旧 generation 下八个小文件批量扫描由 109.5724 秒降至 14.3484 秒，提速 7.64 倍；该对照保留为历史微基准，不能视为新 generation 的应用性能。不同套件覆盖重叠，不相加成一个“总测试数”。

**尚未完成的结论：**完整官方 `make test.e2e` / `make test.e2e.kind` 均未执行；本地执行准备在受限旧凭据 helper 边界被自动审批拒绝，状态 BLOCKED，不读取旧凭据、数据库或协议账号脚本来绕过。真实六场景是独立专项验收，不能代替官方完整 Ginkgo / Kubernetes 部署套件。最终 PDF / HTML / 清洁源码包和文件 hash 由独立交付流程生成及复核，本报告不预先宣称这些产物完成。16 小时长测 v3/job-104 于 14:01:34 开始；控制器与子进程后来丢失，心跳停在 17:16:44。原始记录为 195 成功轮、196 观测、0 已记录失败，但无完成时间、真实退出码或收尾，状态 INCOMPLETE，不能声称 16 小时通过。`job-003` 故障轮在 compose 配置 JSON 读取阶段因 Windows 默认 GBK 解码失败，业务用例未执行；UTF-8 helper 修复后，独立 v3/job-102 的四项业务已正式通过。长测控制器的旧心跳不是实际连续运行时长，未声称 16 小时长测完成。旧 run02 的 SSH 失败和补充轮路径问题完整保留，新 job-101（v3） 的成功单独记载。维护者或社区有效认可仍待公开沟通，未发送 Issue、PR、报名或邮件，不宣称参赛资格全部完成或保证获奖。

## 2. 与原始赛题的逐项对应

依据用户提供的四页《【智算云赛道】DaoCloud 赛题：MatrixHub 模型制品恶意内容扫描与安全准入系统》。该赛题的专项评分是 25% / 25% / 15% / 15% / 10% / 10%；不以官网其他赛道的通用比例替代。官网入口为 [2026 上海开源大赛](https://www.oschina.net/os2026/)。最终赛道、报名和上传格式按主办方正式确认；通用资料中“自主选题 / 开源 AI 工具”的暂定记录不作为本命题的确定分类。

| 赛题能力或交付项 | 实现与对应证据 | 截点状态 |
| --- | --- | --- |
| 上传触发并关联明确 revision | Git / HF 上传入队，稳定 project:model ID + commit；branch move、old SHA、内容缓存 job-101（v3） | 已实测直接上传；代理缓存与同步非本轮实测范围 |
| 通用恶意软件与危险序列化静态检测 | ClamAV + Picklescan；新增精确嵌套加载引用 high 规则与有界字面符号传播；从不加载模型 | 历史签名 / 危险引用已测；新规则 6 / 6 专项验收通过，非代表性检出率 |
| 文件级汇总及六状态 | 完整 manifest；job-101（v3） `observedStates` 六项、无未观察状态 | 已实测 |
| 官方 HF 客户端兼容 | `huggingface_hub==2.1.1`；历史 model_info 安全字段；新轮真实上传和强制下载、独立新缓存 | 历史 job-101 及新轮六场景分别通过；不扩大为全部 HF 接口兼容 |
| 真实下载准入 | 历史 HF / LFS / SSH / 权限撤销；新轮 GET / HEAD / Range / 官方 HF 下载及整 revision 风险传播 | 新六场景通过；历史 job-101 的其他入口证据独立保留 |
| 可解释报告与治理 | 新增固定符号 ID、reference 语义、流 / 偏移、哈希化成员链；真实 API、中文 UI、历史及策略审计 | 新轮产品 CUA 及六场景通过；截图视口限制见第 14 节 |
| 重扫与结果复用 | 完整分析按 scope / digest / size / type / generation 复用；force 不复用，历史不可变 | job-101（v3）、domain / store 通过 |
| 隔离和资源限制 | 低权限、断网、只读、无凭据 / Docker socket、容器和进程限制 | 独立扫描器实测通过 |
| 离线、取消、重启、晚到结果 | durable intent、lease + attempt fence、取消不复活、原子审计 | 源码回归与 v3/job-102 四项真实故障均通过 |
| 性能与稳定性报告 | 历史微基准、容量及六组应用基准；新轮 1 / 8 / 63 MiB 合法合成张量制品 | 各轮独立；未验证多 GB；16h 长测 INCOMPLETE |
| 可复现部署、规则、样本、版本、许可 | compose、pin/hash、样本脚本、证据索引、THIRD_PARTY；本轮代码 DCO 提交及镜像固定 | 代码已封版；最终视觉报告 / 清洁源码包及各自产物 hash 按交付记录确认 |
| 3-5 分钟真实演示 | 4 分 13.5 秒 WebM，真实 CUA 采样，中文 SRT，来源与剪辑清单 | 已完成并解码 QA |
| 公开提案及有效社区认可 | 本地提交材料准备，公开沟通须用户授权 | 未完成外部步骤 |

专项评审映射：检测覆盖与准确性（25%）看第 5、7 节；集成与准入（25%）看第 3、6 节；执行安全（15%）看第 4 节；可靠性与规模适应（15%）看第 7、8 节和待补长测；解释与治理（10%）看第 6、10 节；工程质量与社区认可（10%）看第 9、11 节。没有自行估算分数。

## 3. 三个方向与关键决策

方向一是制品证据与一致准入：验证真实 LFS 长度 / SHA256，冻结提交，把扫描和下载都指向相同快照。方向二是隔离分析服务：成熟引擎通过 Unix socket 提供 generation 绑定的结果。方向三是故障恢复与证据控制台：持久任务、租约、历史、RBAC、策略和中文 UI。最终以方向一为主线，后两者构成完整闭环。

应用户要求，ASTRA ULTRA 子代理参与架构和关键权衡审查，特别是完整覆盖、过期完成 fencing、离线重扫失效、任务取消恢复、原子策略审计、逻辑字节 / entry 双额度与同 UID 信任边界。AI 审查不是第三方安全认证；最终依据仍是代码、原始日志与真实请求。可靠性专项只读复核另存 `ASTRA_RELIABILITY_REVIEW_20261008.md`（review-only），检查故障断言、长测连续性和最终 harness hash；其审查结论不能替代真实故障或长测通过。

| 决策 | 原因与代价 |
| --- | --- |
| 成熟引擎 + 精确受限能力规则，保持独立进程 | ClamAV / Picklescan 提供基础检测；有界字面符号跟踪补足特定加载入口引用，不实现可执行 Pickle VM；API 不执行模型 |
| 完整扫描快照及同一 FD 校验 | 防止扫描 LFS 指针、mutable source 替换和扫描 / 下载字节不一致 |
| 严格模式禁 raw Git / history patch / global LFS | Git pack 可带历史对象，当前不承诺包级过滤；兼容性成本明确，HF 文件路径继续可用 |
| 无完整证据即拒绝 | audit 模式可以放行已完整分析的风险，但不能放行未知覆盖 |
| 有界批量，一次载入 ClamAV 规则 | 每个 RPC 批次最多 32 个缓存未命中文件；任务完整清单最多 1000 文件、256 MiB，逐批全覆盖；减少规则重复加载，不增加常驻引擎并发 |
| 单 writer、单 scanner worker、保留快照 | 降低跨进程额度 / 删除竞争；无自动 GC，多副本共写不在本版范围 |

最新精确能力规则选择固定 `(module, name)`，不将整个 torch 包或全部 unknown 升级为恶意。它补的是受限加载能力引用，不证明入口被调用，也不等于任意 PyTorch 模型的执行安全；普通 unknown 保持 medium，人工复核实体尚未实现。

现有上游相关 PR #1067 在已审阅版本中也读取真实 LFS 字节，不能说它只扫描指针。本文贡献着重在字节验证、不可变证据与准入、多入口和竞争控制；静态比较不等同于复现他人漏洞。

## 4. 技术流程与威胁边界

流程为：上传提交 → 持久待处理任务 → 解析不可变 commit 和完整 tree → 预留额度 → 流式读真实 Git / LFS 内容并核对 size / digest → sync 后原子发布只读快照 → Unix socket 双引擎完整扫描 → 事务保存 report 与可复用 analysis → 当前权限 / policy / generation 准入 → 同一快照 FD 再验证并响应 GET / HEAD / Range → 保存决定审计。

domain 位于 `internal/domain/security`，通过 ports 使用 repo adapter；handler 管身份及协议，job processor 调 domain；SQLite / MySQL 保存任务、报告、cache、policy、audit。API 仅拨固定 Unix socket、拒绝重定向和代理、限响应大小、要求两个具名引擎及完整结果。任务通过 token / attempt / 有效租约 CAS 完成，旧 worker、超时、取消或强制重扫不能覆盖新证据。

攻击者可控制上传字节、文件名、LFS pointer、archive member、分支变化及重扫竞争；数据库、staging writer、宿主机管理员与容器运行时受信。扫描器 supervisor 和 engine 同 UID / 容器，因此资源隔离不是被攻破 parser 后的强租户隔离：一个已被攻破的 scanner 可能伪造 verdict。只读输入、无业务凭据、断网、无 capabilities 会限制访问面，不能证明扫描器进程完整性。主服务不获得 Docker socket。宿主机 / 可信 writer 被攻破、模型输出有害性、训练投毒、模型后门和对抗样本不属于本轮安全保证。

扫描容器实际 profile：Linux / amd64，UID/GID 65532，网络 none，root / input / rules 只读，drop ALL、no-new-privileges，1 CPU，3 GiB 内存且无 swap，32 PID，256 MiB tmpfs（noexec,nosuid,nodev）。子进程固定 `python -I`，限制 CPU / address space / FD / 输出 / core；父 supervisor 对 90 秒墙钟超时与断连取消杀整个进程组。

## 5. 检测覆盖、样本与解释边界

真实 ClamAV 1.4.6 LTS 扫描全部文件；真实 Picklescan 1.0.5 分析 Pickle 及受支持嵌套内容。`pickletools.genops` 负责结构解析，新增有界栈 / memo 跟踪字面符号引用；它不执行反序列化，不是完整 Pickle 虚拟机或通用恶意行为证明器。STOP、拼接 stream 和尾随字节全部消费；扩展名、magic 和结构共同识别，重命名 `.txt` 不能隐藏危险引用。没有 `pickle.load`、`torch.load`、模型 import 或样本 callable invocation。

| 输入 | 处理与边界 |
| --- | --- |
| 受 pin 版本支持的 Pickle | 静态结构 + callable 风险；普通未知引用 medium，危险引用 critical，精确受限嵌套加载引用 high；模糊 / 不完整符号分析拒绝 |
| ZIP / gzip / tar、PyTorch ZIP data.pkl | 在深度 / 展开量 / ratio 限制内静态分析；不写入 archive 控制路径 |
| Safetensors | Header / offset 校验 + ClamAV；新 generation 单测与 job-101（v3） 全链路验证 header=128；原失败 probe 保留 |
| 未知普通文件 | ClamAV + Pickle context 探测；保守识别可能拒绝相似但不完整字节 |
| NumPy object、dill、HDF5、7z、RAR、xz、bzip2 | 本版无完整覆盖，失败并拒绝，不声称恶意 |
| 加密 / 异常 / 过量 archive、格式尾随 / EXT registry | 完整性失败；不以成功进程退出冒充全部扫描 |
| 大于容量上限 | 扫描前拒绝；不只扫前缀再声称全文件通过 |

测试只含无害标准 EICAR、静态 opcode / GLOBAL 引用、普通文件和异常覆盖样本，不运行真实活跃恶意软件。正式 job-101（v3） 关键样本如下；完整来源为该轮 `results.json` 的 samples 字段，hash 用于复核字节，不包含账户凭据。

| 样本 | Bytes | SHA256 |
| --- | ---: | --- |
| config.json | 43 | c65c375d8c7039117756f76f34c6fcbf05ae3d39c2b85ae174c3d0941337687d |
| benign.pkl | 13 | 094df2152cfa75a23bf09867a401f6380f902e9391a09916d89584cb7abc8b87 |
| warning.pkl | 42 | 2b4734d823bbddb20273211323db89e960552986d53c24b27424acdf6a147056 |
| unsafe-global.pkl | 14 | 7072e107c42927b16285ea4e9b6464b5420faab96560e10a41ca435bee8985fd |
| eicar.txt | 68 | 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f |
| unsupported.npy | 8 | 21eaac327f0aecbb787b9a1ce54d68aa855cfc59ae5c9f4f6924cd61028bcd90 |
| valid-128.safetensors | 137 | 70b43758f7933b5b71c28ef8c70bac9037001f99ced3dff3fe9f93d6c182af33 |
| renamed-unsafe.safetensors | 14 | 7072e107c42927b16285ea4e9b6464b5420faab96560e10a41ca435bee8985fd |
| stage-limit.bin | 67108865 | 64941c4303803d180cb614a234bd1d3cfdb8e130841a6f17017076d983274d34 |

## 6. 实际客户端与 UI 结果

本节主体记录此前 v3 / `9acc7486...` 镜像结果；最新 `2e17cfeb...` generation 的六场景及实际产品 UI 见第 14 节。历史 SSH、LFS、权限和 32 项 UI 测试不自动计为新版本复跑。

正式 `job-101（v3）` 于北京时间 2026-10-08 13:43:33-13:45:48 执行，使用官方 `huggingface_hub==2.1.1` / Python 3.12.14，整体 `passed=true`，20 / 20 项通过，其中 17 项业务验证和 3 项测试 token 撤销。`model_info(securityStatus=True, files_metadata=True)` 由真实客户端解析。clean 首次报告覆盖完整、缓存 0；相同文件复用与分支更新正确区分；旧 commit 仍返回旧内容。force 重扫产生新 attempt、缓存 0，保留历史；旧 LFS action 返回 `LFSManifestMismatch`。viewer、outsider、anonymous、权限撤销与跨租户 OID 得到相应拒绝。

EICAR 和 dangerous GLOBAL 为 complete block，分别保存真实 ClamAV / Picklescan finding；unknown callable 为 complete warn，默认 high threshold 可下载，收紧策略后阻断，audit 下允许已完整证据。unsupported、64 MiB+1 和伪装 `.safetensors` 的危险 Pickle 均为 incomplete fail，官方客户端及 GET / HEAD / resolve-cache 拒绝；不把后者声称为已完成恶意检测。合法 137-byte Safetensors 的 128-byte header 被完整验证，官方上传、扫描、下载 SHA256、HEAD 200 和 Range 206 全链路通过。

GET / HEAD / Range / resolve-cache 和 scoped LFS 都走服务器准入。raw HTTP Git、global LFS GET / HEAD 和历史 compare patch 被严格模式拒绝。真实 SSH 完成认证后，`git-upload-pack` 返回 `RawGitDisabled`，客户端 exit 1、stdout 0，符合预期拒绝协议。原生审计记录 47 条，覆盖 git-http、git-ssh、hf-compare、hf-resolve、hf-resolve-cache、lfs-batch、lfs-content、post-receive、rest-security。任务真实观察到 pending / scanning / pass / warn / block / fail 六种状态，无未观察状态。

| job-101（v3） 实际标识 | 固定值 |
| --- | --- |
| Application image | `sha256:cfd5e30afe82d2d077ef3012ac91327c94d03c4d284e1fa5fbcfdcd6bcd38357` |
| Application binary SHA256 | `a3a84b5e0ed7665cafd3a7fb3f5773f59a5ddbb2725a2b3505b7b63dc14185ce` |
| Scanner image | `sha256:a4736049103ff53efff2374fcee5d40e2685f3590b8f7b9d33903308f62ce8d2` |
| Scanner generation | `9acc748673c456930b9e9ab0fee574671b5d32a632cfbbb6e7b30c03e107e330` |
| E2E script SHA256 | `6bdb137f7bb409665bac6de215e206dfa1ddaf593a369b44c2645260bb4cc08e` |

构建结果 `backend-final-build-04.json` 的 Linux / image build exit code 均为 0。上述镜像与二进制标识针对已测试构建；文档、测试 harness 或后续源码变更不能自动视为已被该二进制覆盖。最终清洁源码包将另存源码清单与 hash，不用二进制 hash 代替源代码证明。

此前 `security-lab-results/job-002` 于 12:05:50-12:08:02 完成，同一 app / scanner image 与 generation 下亦为 20 / 20；原 E2E script SHA256 为 `e86a66153dc4b06e2c021f598cd5429e29ff336d45027ce2c8ea1e72c97bd994`。其结果保留，最终冻结 UTF-8 helper 后另建独立 v3 fixture 执行上述 job-101，没有重用旧凭据或改写旧结果。

旧 `security-e2e/run02` 于 03:57:08-03:59:10 执行，为 17 / 18、`passed=false`。旧 app / scanner image 分别为 `907206000fa39d8e3efff947d1c8a6bd8dd57181b9fc8708c4b097dd1aa9f148` / `ceac687740477ac5e23fb2b896ea0a9cdabacc4dbd4316d5ecaea12ff718616f`，generation 为 `1a956066f220c924195e951f6a41c30531850676289449534d1e1fcd02084b57`。SSH 首次因 exFAT 密钥权限失败，补充轮认证后仍返回 `security_unavailable`；修正 `/namespace/model.git` 规范化后，源码回归及新 job-101（v3） 的真实 SSH 均通过。旧失败与对应标识保留，不能改写旧轮为成功。

UI 全量 lint / typecheck / build 通过；Vitest 6 个文件 32 项通过。OpenAPI 检查 8 个 operation、29 个本地引用与 path parameter。真实中文页面展示 clean、EICAR、危险引用、history、policy、audit；浏览器曾发生 Cookie 登录鉴权失败，HTTP 标准 `r.Cookie` 修复、源码回归及真实页面恢复均保存证据。

## 7. 已执行的自动化验证账本

每行独立计数，不重复累加。文件名中的 final 表示对应历史轮次的终轮，不表示全部在本轮 `63c0e0e9...` 代码上重新执行。Go 顶层 test 数与包含 subtest 的事件数分别注明；日志的 package 无测试状态不作为失败。完整日志路径、hash 和命令入口见 [证据索引](EVIDENCE_INDEX.zh.md)。

本轮新增：官方 `make test.unit` 真实 exit 0、23 包通过 / 26 包无测试；默认 `-short -count=1`、不含 race / coverage，排除 HF handler，未配置外部 MySQL fixture 的测试可能 skip。52 / 52 scanner 单测的核心源码字节相同继承、11 / 11 最终 Unix 协议实跑、UI 两文件 8 项及 TS / 目标 lint / build、真实六场景与 CUA 联合验收均见第 14 节。完整官方 `make test.e2e` / `make test.e2e.kind` 未执行，不能由本表历史 race / MySQL / 容量结果推导新版全部通过。

| 套件与原始日志 | 实际结果 | 范围 / 限制 |
| --- | --- | --- |
| repository-unit-suite-final-03.jsonl | 23 包通过；215 顶层 / 403 pass test events；2 Windows skip；26 包无测试 | 最终官方单元选择集；含 SQLite 回归，非所有外部集成 |
| hf-security-final-03.jsonl | 6 顶层 / 47 events 通过，25.687 s | HF 六状态、下载入口、范围及拒绝协议 |
| linux-security-race-final-02.jsonl | 60 顶层 / 103 events 通过，2 包，0 skip | Linux -race，含离线 / fence / atomic audit |
| mysql-security-final-02.jsonl | MySQL 8.4.11，38 顶层 / 66 events 通过，21.503 s，0 skip | 最终 store 回归；fixture exit 0 且已移除 |
| security-handler-after-generation-04.jsonl | 10 顶层 / 18 events 通过，0.134 s | mock 重生成后一轮 handler 回归 |
| mock-generation-final-04.json | generation exit 0；前后 16 / 16 文件 byte-identical | final-03 曾有 1 文件变化，失败事实单独保留 |
| go-vet-final-03.log | exit 0 | 静态 vet，日志为空不代表额外用例执行 |
| golangci-final-02.log | `0 issues.` | 最终 lint；初次 14 issues 原日志保留 |
| scanner-final-20261008-115828-unit.log | 29 项通过，24.928 s，0 skip | 新 generation 容器真实隔离、格式、archive、digest、batch |
| scanner-final-20261008-115828-integration.log | 11 Unix 组通过，102.148 s，0 skip | 包含真引擎、timeout、cancel、busy、generation、资源限制 |
| scanner-final-20261008-115828-capacity.log | 5 个容量条件符合预期 | 63 MiB、32 / 33 文件、256 MiB / 超 1 byte |
| security-lab-results/matrix-security-lab-v3/job-101/results.json | 20 / 20，整体 passed=true；17 业务 + 3 token cleanup | 正式新镜像、真实 SSH、Safetensors、六状态 |
| security-lab-results/matrix-security-lab-v3/job-102/results.json | 4 / 4 业务 case，passed=true、failures=0，406.968 s | offline / cancel / SIGKILL+lease / generation 切换 |
| security-lab-results/matrix-security-lab-v3/job-103/results.json | 6 / 6，passed=true、failures=0，328.141s | 官方上传、cold/cache/force、4并行Range、HEAD/GET与事后资源采样 |
| security-e2e/run02/results.json | 17 / 18，整体 passed=false | 历史轮 SSH 失败；不改写为成功 |
| domain-batch-02 / security-db-01 / security-repo-02 | 17 / 11 / 20 顶层通过；详细事件数见索引 | 早期独立覆盖，保留、不与 final 相加 |
| domain-store-final-review-01 / security-atomic-offline-01 | 45 / 60 顶层通过；84 / 103 events | 修复过程回归，含离线 / 原子审计 |
| security-ui-full-tests.log 等 | 6 文件 / 32 项 + lint / typecheck / build 通过 | 中文 UI 与 SDK / schema 另存日志 |
| govulncheck-01.jsonl | exit 0；3 module、0 package / symbol findings | 未报告可达符号风险；不等于依赖零漏洞 |

旧 scanner 的 21 项单测、10 组 Unix、2 组资源限制和容量原日志仍保留；它们支持历史微基准，不能替代新 generation 的终轮。Windows 跳过的 SQLite 现有文件权限与符号链接两项测试有明确平台原因，未计入 pass。
govulncheck 1.8.0、Go 1.26.8，source / symbol 模式，数据库更新时间 2026-10-07T14:10:51Z。输出是连续 JSON 对象，按 stream decoder 解码 308 对象。`GO-2022-0635` 与 `GO-2022-0646` 对应 `github.com/aws/aws-sdk-go v1.55.8` 的 S3 Crypto SDK 风险；`GO-2026-5932` 对应 `golang.org/x/crypto v0.56.0` 的 openpgp 弃用与不安全设计。未报告相应包 / 调用栈可达性只是该构建和分析条件下的结果，不能据此删除依赖风险或声称“零漏洞”。

## 8. 性能、容量与资源

本节的独立容量与完整应用基准属于此前明确 generation；最新六场景含合法 1 / 8 / 63 MiB 合成张量文件，但不是新的吞吐、并发或生产性能基准。完整子脚本 519.375 秒包含准备、鉴权、UI 等待与收尾；真实 UI 所示报告 19620 ms 也不是纯引擎时间。

Docker Desktop engine 29.4.3、Linux `6.6.114.1-microsoft-standard-WSL2`，Docker 可见 32 logical CPUs / 16,655,593,472 bytes host memory。独立 scanner 实际限制为 1 CPU、3 GiB memory、完整官方 ClamAV 数据库，未使用微型 test-only rules。以下八文件前后对照来自旧 generation `1a956066...`，非新 generation 性能轮。每份为独立 1,028 bytes，共 8,224 bytes；直接调用 scanner、均无 domain cache，可能有宿主文件缓存。包括规则及输入重新 hash，不包括上传、Git、DB、API 排队。

| 相同八文件任务 | Wall time | Peak child RSS | Cgroup memory peak |
| --- | ---: | ---: | ---: |
| 逐文件新建 ClamAV 进程 | 109.5724 s | 985344 KiB | 1065512960 bytes |
| 有界一次 batch | 14.3484 s | 985344 KiB | 1057845248 bytes |

8 文件小负载 wall time 减少 86.9%，速度 7.64 倍。主要来源是一次加载规则；没有减少扫描内容或更改风险规则。batch 共享 wall time 不能把每个成员的 duration 累加为串行 CPU 时间。

下表来自新 generation `9acc7486...` 的终轮容量实测。

| 独立容量 case | 结果 | 时间 |
| --- | --- | ---: |
| 单文件 63 MiB | HTTP 200、完整结果 | 18.0123 s |
| 32 个独立 1 KiB 文件 | HTTP 200、完整结果 | 16.0031 s |
| 33 个文件 | HTTP 400 invalid_request | 0.0061 s |
| 4 × 64 MiB，恰好 256 MiB | HTTP 200、完整结果 | 23.3237 s |
| 256 MiB + 1 byte | HTTP 400 invalid_request | 0.0060 s |

容量轮记录 child max RSS 1,050,692 KiB、container peak 1,118,191,616 bytes；这是该轮累计观测，不是每个 case 的独立峰值。边界等于容量，不是“支持任意大模型”。应用默认 64 MiB/file、256 MiB/task、1,000 files/task、2 GiB retained logical bytes、100,000 retained files + directories、1 writer、1 worker、120 秒任务 timeout、150 秒 lease；batch 上限独立为 32 files。

### 8.1 完整应用基准（已完成）

v3/job-103 于北京时间13:54:31-13:59:59执行，6/6通过、failures=0，328.141秒。沿用同一正式app/scanner镜像与generation9acc7486...；workload script SHA256为 `d9bdb1e81fbfa274e2926ada335fe4aadc0c1953c4cddcdb426605cfad9635eb`。采用真实官方HF上传，验证完整manifest、全部条目双引擎、digest/size、冷扫描cache0、新commit缓存复用、force cache0和pending HEAD403。

每轮cold manifest额外含官方上传生成的 `.gitattributes`（1,519bytes）。因此用户32个文件实际33项，超出单RPC32项批量边界；不能把它描述为32文件一次满批测试。缓存commit只增加128-byte marker，其余9/33/34/9/5/2项分别真实复用；force扫描包含marker的新完整revision，没有复用分析。

| 应用负载（用户文件） | 实际manifest项 | 扫描Bytes | 上传→准入s | cache等待s | force等待s |
| --- | ---: | ---: | ---: | ---: | ---: |
| 8 × 1 KiB | 9 | 9711 | 13.660 | 13.140 | 13.594 |
| 32 × 1 KiB | 33 | 34287 | 26.322 | 14.047 | 28.125 |
| 33 × 1 KiB | 34 | 35311 | 27.802 | 14.016 | 28.610 |
| 8 × 1 MiB | 9 | 8390127 | 14.944 | 14.156 | 14.156 |
| 4 × 8 MiB | 5 | 33555951 | 16.200 | 13.500 | 15.578 |
| 1 × 63 MiB | 2 | 66061807 | 16.478 | 13.500 | 14.656 |

下表展示不同计时边界。上传到准入=官方create_commit耗时+上传后观察terminal的等待，含真实HTTP、排队、staging、扫描和轮询；不是纯引擎时间。首次scanning为上传后每0.5秒轮询的观察时间，不能作为精确任务队列时间；Report duration为服务器报告字段，不把共享batch成员duration相加。

| 应用时间分解 | 上传ms | 上传后等待s | Report duration ms | 首次scanning观察s |
| --- | ---: | ---: | ---: | ---: |
| 8 × 1 KiB | 66.472 | 13.594 | 12586 | 1.047 |
| 32 × 1 KiB | 150.668 | 26.171 | 25551 | 0.562 |
| 33 × 1 KiB | 162.007 | 27.640 | 27061 | 0.531 |
| 8 × 1 MiB | 335.112 | 14.609 | 13451 | 1.047 |
| 4 × 8 MiB | 1059.074 | 15.141 | 14470 | 0.547 |
| 1 × 63 MiB | 399.664 | 16.078 | 14992 | 1.062 |

每case进行8次Range（parallelism4）、1次HEAD和1次fullGET，校验返回hash/size。Range最近秩p95在n=8时正好等于样本最大值，以下按“最大”列示，不作为生产SLO。GET只下载该case的一个用户文件（1KiB/1MiB/8MiB/63MiB），不是全部revision吞吐。资源栏是每case结束后一次docker stats读数，app限制4GiB、scanner限制3GiB；它不是峰值或连续追踪，不能据此否定真实引擎工作时约1GiB的独立峰值。

| 应用读取 | Range中位/最大ms | HEAD / GET ms | 事后app/scanner MiB |
| --- | ---: | ---: | ---: |
| 8 × 1 KiB | 45.330 / 121.875 | 12.936 / 36.046 | 20.62 / 19.8 |
| 32 × 1 KiB | 56.225 / 107.130 | 12.365 / 12.206 | 23.33 / 19.59 |
| 33 × 1 KiB | 78.720 / 197.568 | 14.431 / 15.439 | 24.97 / 19.68 |
| 8 × 1 MiB | 40.561 / 55.008 | 12.631 / 16.949 | 59.49 / 19.64 |
| 4 × 8 MiB | 46.859 / 94.983 | 15.914 / 81.333 | 250 / 19.41 |
| 1 × 63 MiB | 106.544 / 157.991 | 50.001 / 454.864 | 412 / 20.08 |

### 8.2 16 小时长测（已中断，INCOMPLETE）

v3/job-104于北京时间2026-10-08 14:01:34开始，计划2026-10-09 06:01左右结束。首次成功业务观察为14:01:48，仅证明启动后已有实际请求，不是长测完成证据。固定启动快照为 `soak-start-evidence.json`，报告manifest只收入该不可变无秘密快照、deployment和固定script snapshot；中断后保留原始 events/results/command.log，后续清单另行封版；没有修改原结果为 PASS。

长测用户payload为8×64KiB=524,288bytes；`declaredBudget` 50,855,936bytes仅是payload估算，生成元文件和运行数据另计，不是实际磁盘硬上界。每轮脚本校验完整manifest覆盖、引擎/generation和已知文件SHA，但事件只记录reportId与repo revision等结果，未保存每一轮完整原始manifest快照。

预先声明16h/57,600秒、每60秒一轮、每10轮force、最多960计划轮、至少768成功轮（80%）、最大成功观测间隔180秒。目标时长、首轮和尾部空窗、最少成功覆盖及全部业务断言须共同满足后才记PASS。临时线程system-activity request实测applied=true，未改变电源计划、屏幕或awaymode，不能阻止用户主动休眠。实验控制器随机凭据只在内存，自身终止后无法恢复同一实验；跨工具调用存活不证明能承受app退出或机器重启，新fixture不与旧时长拼接。

实际中断记录：195 成功轮、196 成功观测，已记录 failures=0、gapViolations=0、minimumCoverageMet=false。状态文件观察跨度 11642.813 秒，最后业务事件 elapsed=11656.906 秒，两者是不同截点，不能拼成 16 小时。控制器凭据仅在内存；不读取或恢复旧凭据，不重设旧卷、不将新实验续接旧时长。用户随后确认执行过 Docker Desktop factory reset；这不能确定早先进程丢失的原因。Docker stats 瞬时采样不冒充峰值，有限测试不构成生产 SLA。

## 9. 实际故障恢复、修复与证据保留

v3/job-102 于北京时间 13:46:58-13:53:45 完成，`passed=true`、`failures=0`，406.968 秒；固定 app/scanner images 与最终 E2E 相同。测试只作用于独立 v3 fixture，使用无害 ASCII 样本。

| 真实故障 | 观察与结果 |
| --- | --- |
| 停止 scanner，离线 force + 新上传 | 旧 approval 立即失效、下载 403；原 task12 attempt1→2 自动 pass，unavailable intent13 按设计 fail并标记 superseded by task12；新上传 task14 自动pass。恢复先只读tasks证明，不依赖report惰性创建；force cache0，历史整份JSON不变 |
| 取消已领取的 scanning 任务 | attempt3 被取消，状态 fail；160秒观察窗口内保持取消、重复下载拒绝403、历史整份JSON不变。未声称实际引擎曾发布迟到结果，也不把稀疏采样扩大为每一瞬间的证明 |
| 后端 SIGKILL | 容器 stopped ExitCode137；重启后立即下载403；old attempt5→new attempt6。配置lease150秒，kill时剩余149.638秒，从kill到pass162.938秒，完成不早于已捕获leaseUntil |
| 不可变规则快照切换 | 保留完整main/daily/bytecode CVD，增加无害canary签名；新generation `310e1bc7a3bc46b17efba831b5eacf9cb249e11e027d4fac323d3b2b09ee21b4`，14.187秒观察到complete block，真实ClamAV finding；旧approval拒绝，历史整份JSON不变；结束恢复原generation `9acc7486...` |

Fault script SHA256 为 `b61de85ab9a7cd292feb5c2be479376939b0b51d81fa9ce61df8fd747737fd6e`，compose SHA256 为 `4e3b638a49477a740e65d5f79071f4184eb8a32ea383ef00b202dab329bc7f44`。规则切换时的立即拒绝可能处于scanner启动阶段；新generation就绪后的完整block与再次拒绝提供后续证据，不能仅用立即拒绝推断新规则命中。该有界实验不构成任意故障或生产恢复SLA。

以下保留开发过程真实失败与对应修复，不覆盖原日志。

| 真实遇到的失败 | 处理与验证状态 |
| --- | --- |
| 初次 warning fixture 使用 lowercase unknown 字符串，被引擎判 critical | 定位 Picklescan 规则；修正惰性引用样本为 protocol-2 `matrixhub_e2e_fixture.UnknownCallable`，不弱化规则；保留初次失败和成功 rerun |
| 初次 scanner capacity harness 报 scanner did not become ready | 修正测试 harness 后五个容量条件通过；保留初次 readiness 失败与成功 rerun，不将失败记为容量验证通过 |
| UI Cookie 鉴权失败 | 标准 Cookie 解析补丁与回归通过，真实中文页恢复；原失败截图保留 |
| Windows / exFAT SQLite 权限 / symlink 测试 | 两项平台跳过记录在官方 suite，Linux 另验；不计为运行通过 |
| SSH 私钥权限及后续路径规范化错误 | 环境修正后定位规范化问题；源码回归及 job-101（v3） 新镜像真实 SSH 已通过 |
| 离线任务丢失、force 旧 approval / late completion、audit 非原子竞争 | durable intent / attempt fence / policy+audit 同事务补丁；Linux60顶层/MySQL38顶层终轮通过；v3/job-102验证四项具体运行故障 |
| 零字节制品绕过逻辑 byte cap 风险 | 增加 files+directories entry reservation / restart counting；源码quota回归通过；应用零字节entry极限不是本轮运行负载实测 |
| Safetensors 128-byte header 与 Pickle probe 混淆 | 原失败 probe 保留；新 generation 单测、Unix 集成及 job-101（v3） 两条全链路均通过 |
| MySQL 终轮初次请求不可用 local tag | 测试前 setup exit 125，业务未执行；改用已核验 immutable MySQL image 后 final-02 全项通过 |
| mock 重生成 final-03 一个 service_mock 变化 | 记录 identical=false；更新后 final-04 16 / 16 byte-identical，handler 回归通过 |
| job-003 故障 harness 的 compose JSON 解码失败 | 默认 GBK 读取中文路径错误，业务未执行；原 command.log 保留；UTF-8 helper 修复后 v3/job-102 四项全部通过 |
| 初次 golangci 14 issues | 逐项修复；golangci-final-02 为 0 issues，原失败保留 |

## 10. 视频与评审材料

下述 4 分 13.5 秒视频为此前版本的真实演示，不能证明新增精确嵌套加载规则已包含在视频中。新轮只新增原始产品截图和 CUA / API 复核证据，见第 14 节；没有把离线图或报告渲染 PNG 当成产品截图。

演示为 253.5 秒、1280×720、VP8/WebM、2 fps、无音轨；附 8 段 UTF-8 中文字幕及中文讲解稿。来源是真实本地 MatrixHub 页面由 CUA 采样得到的 165 张未修改 JPEG，原始跨度 526.061 秒。剪辑只删除第 235.347–508.335 秒的上下文恢复等待，保留时间关系；它是实际操作截图采样剪辑，不能称为 30 fps 原生录屏。演示说明页明确标注说明性质，产品报告、签名、危险引用和准入审计均来自真实页面。

八章已实际解码 PNG 并检查：问题 / clean / EICAR / unsafe / audit / history / policy / ending。WebM SHA256 为 `fe7ac685ad0c100afd532880936d107ecc19f0205c3a327bd80885fd3e91f586`。字幕末尾 253.073 秒，早于视频末尾。视频未宣称 SSH 成功，策略表单仅打开后取消。现有视频满足赛题的 3-5 分钟时长；最终上传若限定格式，需转换并重新核验。

## 11. 可复现与交付清单

主入口：[应用安全部署](../../deploy/security/README.md)、[独立扫描器部署](../../deploy/security-scanner/README.md)、[设计](design.md)、[威胁模型](threat-model.md)、[ADR](adr-scanner.md)、[扫描器验证](scanner-validation.md)。源码遵循仓库 domain / repo / handler 结构与 DCO signoff 要求。公开沟通的本地可审阅正文见 [Issue / PR 草稿](submission-drafts.md)，目前未外发。

以下为可复现命令入口，**不是新增执行结果**。先按 deploy/security 文档正常部署一个全新独立环境，为 Compose project、卷、HTTP / SSH 端口和输出目录分别选择从未使用的新标识；不要复用旧 v2 / v3 / capability fixture、账号或卷，不恢复它们的内存凭据。新轮 capability-97f08f51dfda 已完成清理，原地址不再是可访问演示环境。只使用操作者为这个新环境明确提供的新测试环境变量，不读取受限旧凭据 helper 或协议账号脚本。示例的尖括号内容都是必须替换的占位，不是已有环境参数；报告不写密码 / token / 私钥 / 密码 hash。

```sh
go test -json ./internal/domain/security ./internal/repo -run '^TestSecurity' -count=1
go test -race ./internal/domain/security ./internal/repo -run '^TestSecurity' -count=1
cd ui
pnpm lint
pnpm typecheck
pnpm test
pnpm build
```

```sh
python scripts/security/e2e.py --base-url <NEW_ISOLATED_HTTP_URL> --ssh-port <NEW_SSH_PORT> --output-dir <NEW_EVIDENCE_DIRECTORY>
python scripts/security/workload.py --mode benchmark --base-url <NEW_ISOLATED_HTTP_URL> --docker-project <NEW_UNIQUE_COMPOSE_PROJECT> --output-dir <NEW_EVIDENCE_DIRECTORY>
python scripts/security/workload.py --mode soak --base-url <NEW_ISOLATED_HTTP_URL> --docker-project <NEW_UNIQUE_COMPOSE_PROJECT> --duration-hours 16 --output-dir <NEW_EVIDENCE_DIRECTORY>
```

本轮 scanner 单测及 Unix 集成的真实入口分别是镜像内 `/opt/scanner/tests.py` 与 `/opt/scanner/integration_tests.py`。按独立扫描器 README 构建新镜像并准备完整、不可变的规则与全新测试 input 挂载；沿用其断网、低权限、只读、CPU / 内存 / PID 限制，把 `--entrypoint python <NEW_SCANNER_IMAGE> -I /opt/scanner/tests.py` 换成 integration_tests.py 才是协议回归。这里只列入口，不借用已结束 fixture 的旧卷。官方 `make test.unit` 是另一条源码入口；`make test.e2e` / `make test.e2e.kind` 必须另建可授权的独立环境，本轮未执行。

Fault 脚本仅在独立受控 lab 上按文档设置 compose / rules / project 参数运行，避免作用于其它容器。scanner 的准确隔离 flags、规则获取、版本与 benchmark 指令在其 README 中。最终提交包应包含清洁源码、上述文档、可运行 compose、锁文件、无秘密证据清单、视频 / SRT / 说明、SHA256SUMS 与对应第三方许可 / source notices。详细核对见 [提交材料清单](SUBMISSION_CHECKLIST.zh.md) 与 [第三方说明](../../THIRD_PARTY.md)。

## 12. 已知限制与后续路线

完整检测依赖 pin 引擎及规则，无法证明未知攻击不存在。当前格式支持保守，异常相似字节可能误拒绝；unsupported 要表述为覆盖不可用，不是已检测恶意。容量有限，尚未验证 multi-GB 模型、multi-worker、高并发、跨副本共享 staging。逻辑 bytes 不是物理磁盘 block quota，operators 还须预算 metadata / DB。旧报告和 snapshot 不自动删除，额度耗尽 fail closed，离线 report-aware cleanup 需停 writer / reader。

strict enforce 模式禁原始 Git 拉取和历史 patch，这是真实兼容性成本。自动 GC、强 parser 隔离、proxy / sync 的完整负载验证、更多序列化格式及多副本设计需要单独方案与实测。规则更新必须发布不可变新快照和 generation，旧 approval 失效，不能原地换规则继续沿用结果。

精确加载能力规则、结构化证据与新镜像独立六场景 / 产品 UI 验收已完成，代码 DCO 提交已保存；不能再将这项实现列为待开发。后续是最终视觉报告与清洁源码包的生成 / 核验、完整官方 E2E / KIND 的独立可授权环境、代表性兼容性与误报语料、多 GB 及大规模性能实验、人工复核治理和社区沟通。16 小时长测继续保留 INCOMPLETE，不拼接新时长。此前 SQLite / MySQL / Linux race、四项故障和六组应用基准的证据保留，但尚未全部在本轮新 generation 复跑。公开社区对齐和报名仍须用户授权。

## 13. 主要出处

- 原始赛题：用户提供 `E:/大三下/x_信道编码/dao_cloud_matrix_hub_1_PECU13fk9F.pdf`，4 页；本报告不转载其完整正文。
- [官方比赛页面](https://www.oschina.net/os2026/)；赛程与材料以主办方最新确认优先。
- [MatrixHub 官方仓库](https://github.com/matrixhub-ai/matrixhub) 与固定上游 SHA。
- [ClamAV 1.4.6 官方 release](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.4.6)、[官方扫描文档](https://docs.clamav.net/manual/Usage/Scanning.html)；版本选择依据 release parser security fixes。
- [Picklescan 官方仓库与 MIT license](https://github.com/mmaitre314/picklescan)、[Python pickletools 文档](https://docs.python.org/3/library/pickletools.html)。
- [HF Malware Scanning](https://huggingface.co/docs/hub/security-malware)、[HF Pickle Scanning](https://huggingface.co/docs/hub/security-pickle)。
- 原始执行：`上海开源赛2026/runtime` 下的受控证据；本报告不把其它项目日志混入结果。

## 14. 最新成果：精确嵌套加载引用与真实产品验收

### 14.1 要补的具体缺口

官方 PyTorch v2.9.0 的 `torch.storage._load_from_bytes` 会调用 `torch.load(..., weights_only=False)`。若仅按框架包名前缀信任 torch，或将这个已知加载入口当成一般 unknown / medium，默认 high 阈值可能允许带有该引用的制品分发。这里描述的是入口具有再次反序列化数据的能力，不是证明一个上传样本已经执行了代码；原始源码依据见本节出处。

新规则精确匹配 `(torch.storage, _load_from_bytes)`，输出 `pickle.nested-deserialization-reference`、severity=high。它只改变这个版本化受限能力的分类：普通 `pickle.unknown-global` 仍为 medium，既有危险引用仍为 critical。扫描器不 import 模型模块、不执行 callable、不使用 `pickle.load` 或 `torch.load`；报告的 observation 固定为 reference，不能称为“恶意调用已发生”。

### 14.2 如何得到符号：有界栈与 memo，而非执行模型

GLOBAL / INST 可直接给出模块与名称；STACK_GLOBAL 的两个操作数则来自 Pickle 栈。只看相邻字符串或让 GET 保留成“索引”会遗漏 memo-of-GET：一个已知字符串被 GET 取回，再通过 MEMOIZE 存入另一个槽，最后从该槽取回供 STACK_GLOBAL 使用。ASTRA ULTRA 在首轮只读审查发现此缺口，随后补代码和回归；早期 41 项通过不覆盖这个新发现的问题。

`SymbolicReferences` 只传播字面 Unicode 字符串、MARK 与 OPAQUE 三类静态值。PUT / BINPUT / LONG_BINPUT / MEMOIZE 保存当前栈顶的实际静态值；GET / BINGET / LONG_BINGET 从 memo 取回该值，DUP / POP 与可信 pickletools 元数据维护栈效果。STACK_GLOBAL 只有在两个操作数都可由字面字符串导出时才形成符号。容器及 REDUCE / BUILD 的结果始终为 OPAQUE，不构造对象、不调用函数，因此它不是完整 Pickle 执行器。

简化的数据流为：字面字符串 → memo 槽 A → GET A 得到同一字符串 → memo 槽 B → GET B → STACK_GLOBAL。相同字符串经过多次 memo 转存仍保持其值，而不是只保留槽号。测试同时覆盖同名近似符号、普通 unknown、容器 / memo 边界、拼接流与解析分歧，防止把规则写成全文字符串搜索或整个 torch 包黑名单。

栈、memo 和已观察符号共用有界 slot 预算，累计指令、字符串参数、归档深度及展开字节也有上限。未定义 GET、非字面 STACK_GLOBAL、EXT registry、超限、结构异常或无法消除的解析器分歧进入 incomplete。拼接 stream 还同时核对“同一 Unpickler 保留 memo”与“新 Unpickler 使用空 memo”的解释；无法一致得到符号时拒绝，不择一个有利解释称为通过。普通危险 / 未知符号若有界解析与 Picklescan 不一致，同样失败关闭；仅已精确识别的受限入口由专项规则给出 high 引用证据。

### 14.3 机器报告与产品页面怎么解释证据

可选 `Finding.evidence` 同步到 Go、REST/OpenAPI、TypeScript 及数据库 JSON，旧报告没有此字段仍兼容。固定 `knownSymbolId=torch-storage-load-from-bytes-v1` 在 UI 映射为可信标签 `torch.storage._load_from_bytes`，不渲染上传方提供的原始模块名或归档成员名。

| 证据字段 | 含义与边界 |
| --- | --- |
| observation=reference | 静态引用；不证明 REDUCE 调用、代码执行或恶意意图 |
| source=pickletools | 本轮真实引用位置来自有界静态指令解析；协议还允许 picklescan 来源，但不能伪造其精确位置 |
| streamIndex | 从 0 开始的 Pickle 流索引；0 与 null 明确不同 |
| opcodeOffset | 当前根制品或当前归档成员内的指令字节偏移，不是另一个流内重新归零的偏移 |
| archiveMemberChain | 由外到内的成员序号和成员名称 SHA256；不显示原始成员名。本轮根引用为 null，嵌套 ZIP 为两层成员 #0 |
| null / unsupported evidence | 位置不可用或格式不受支持，不推测成 0；报告不能据此声称执行 |

数字字段限制为非负安全整数，哈希为小写 64 位；Go 指针与 TypeScript `number | null` 保持缺值语义。真实 direct 引用是 stream=0、offset=2，memo-of-GET 的 STACK_GLOBAL 是 stream=0、offset=47；两层 ZIP 引用在内层成员中 offset=2。报告总规则名仍标引擎 picklescan，而具体 evidence.source=pickletools 区分分类与定位来源。

### 14.4 如何把检测接入下载闭环

扫描结果仍绑定不可变 commit、完整 manifest、文件 digest / size、scanner generation 和历史 report ID。每个受保护下载按当前策略重新判断整个 revision；在 enforce/high 下，任一文件含该 high 引用，版本整体拒绝。新轮验证含引用的 Pickle / ZIP、同版本没有 finding 的 Safetensors、甚至 `.gitattributes` 元数据都返回 403 RevisionBlocked，不能绕开风险文件只下载权重。

策略变化不改写旧报告，不需要重新扫描来“改变风险”。普通 unknown 在 high 时允许，在 medium 时阻断；前后 report ID、report / manifest / history hash 与 generation 保持不变，策略版本与准入审计记录变化。损坏 Safetensors 的完整性失败无论 high / medium 都是 403 RevisionFailed，不能靠提高阈值或 audit 变成完整分析。人工复核实体及人工安全放行流程尚未实现；按钮、警告文字或审批意向不等于复核已经完成。

### 14.5 本轮真实六场景

固定运行 `runtime/capability-lab-v1/results/capability-97f08f51dfda`。六场景通过表示预先声明的允许 / 拒绝及绑定断言全部满足，不表示六种文件全部“安全”。官方 HF 强制下载使用独立新缓存，避免本地缓存掩盖服务器拒绝；直接 GET / HEAD / Range 同时验证。

| 场景 | 静态输入及完整报告 | 真实下载与结果 |
| --- | --- | --- |
| direct GLOBAL + 63 MiB | 35-byte 惰性引用；完整 block，high；stream0 / offset2 | 默认 high 与显式 high 均阻断风险文件、权重和元数据，HTTP / HF 拒绝；PASS |
| memo-of-GET / STACK_GLOBAL + 8 MiB | 49-byte 惰性引用；完整 block，high；stream0 / offset47 | 默认 high 与显式 high 均整版本阻断，HTTP / HF 拒绝；PASS |
| 两层 ZIP 引用 + 1 MiB | 265-byte ZIP；成员链两层 index0，内层 offset2；完整 block | 归档、同版本权重和元数据均阻断，HTTP / HF 拒绝；PASS |
| 普通 unknown + 1 MiB | 29-byte 惰性引用；完整 warn、medium | high 时 GET / HEAD 200、Range206、HF完整下载；medium 时两文件403；同一报告未重扫；PASS |
| 纯数据 Pickle + 63 MiB | 13-byte 原始数据 + 有效 Safetensors；完整 pass，无 finding | medium 时 GET / HEAD200、Range206、HF完整下载，完整长度 / SHA256一致；PASS |
| 损坏 Safetensors | Header 不完整；fail、complete=false，非“已检测恶意” | high / medium 下 HTTP / HF 都403 RevisionFailed；PASS |

1 / 8 / 63 MiB 文件大小分别为 1,048,576 / 8,388,608 / 66,060,288 bytes，均为合成合法 Safetensors，单个 U8 张量及字面数据，不是训练得到的模型，不证明训练 / 推理兼容，也不是多 GB 模型测试。前五个 manifest 各 3 项，包含本轮 134-byte `.gitattributes`；不能把历史轮 1,519-byte 元数据的预算直接套入本轮。损坏格式 manifest 期望 2 项，报告未声称完整覆盖。

子脚本北京时间 01:17:19-01:25:58，elapsed=519.375 秒，包含样本准备、鉴权、全部场景、UI 等待和 API / 文件 / 会话收尾，不是六次扫描性能之和。监督器 01:26:03 完成，实际 childExitCode=0；外层监督器 exit0，最终 verified-pass=true。子结果按设计仍是 `success-candidate` / `passed=false`，由已观察真实退出的监督器联合验证后发布通过。17 项收尾全部完成，3 个独立卷移除；没有复用旧密码、修改旧账号或拼接旧长测时长。

### 14.6 真实产品 UI 与测试版本

CUA 实际访问新部署的 `/projects/<本轮namespace>/models/capability-direct-global`，从真实报告展开风险项，观察 fixed symbol、reference 说明、high、source=pickletools、stream0 / offset2，并核对 enforce / high / policyVersion2。UI 复核保存 2 张原始 JPEG，consoleErrors=0。风险截图的 720 像素视口在卡片附近截断，不能说这张图完整展示了全部详情；完整字段观察由真实 CUA accessibility tree、ui-review.json 与 API 证据共同支持。策略截图直接展示 enforce / high / v2。真实页面中的 report duration=19620 ms 是报告字段，不是纯引擎性能指标。

| 本轮绑定 | 固定值 / 执行范围 |
| --- | --- |
| 验收时代码 DCO 提交 | `63c0e0e9b1ebdf02a707c378747962e96c57bb16`；后续报告文档 hash 独立封版 |
| Application image | `sha256:356f156690deb3860bdae470eb187685d8da3ce5946699b44a0f2e7bcd8fc63d` |
| 最终 Scanner image | `sha256:b7eb7eccd33cffdac34ab37b7a2fb4ee1ff414b794634fd0ffda63128368249d` |
| 真实 Scanner generation | `2e17cfeb2fefd0744d6a688f5218663e069e6e563ee17fb5351ce3ab0df312b8` |
| 52 项 scanner 单测 | 36.538 s、0 skip，实际运行于 `e1baab9f...daad654` 镜像；最终 b7 镜像未重复运行52项 |
| 52 项继承依据 | 最终只修 integration_tests.py 一行错误码期望；scanner.py / tests.py 字节完全相同，按核心源码字节继承，不伪写成 b7 重新执行 |
| 最终 Unix 协议集成 | 最终 b7 镜像真实11 / 11，119.512 s；初轮131.384 s失败原日志保留 |
| 官方 make test.unit | 真实exit0，23包通过 / 26包无测试；short/count1、无race/coverage、排除HF；外部MySQL可能skip |
| UI 源码检查 | 两文件8 / 8；全UI TS、目标lint及生产build通过，167产物文件复制hash一致 |
| ASTRA ULTRA 终复核 | 297项只读证据断言、0失败；不是297项新测试、第三方认证或获奖保证 |

初轮 Unix 的旧期望为 invalid_serialization，新有界分析对同一异常输入返回422 pickle_symbol_analysis_incomplete，拒绝结论未改变。仅修正测试期望并重建测试层后11项实跑通过，未弱化扫描规则；旧失败及最初监督器 Git preflight 失败均保留，后者没有启动 child / fixture。历史完整 E2E、race、MySQL、容量、故障和基准不能升级为新版全部通过，完整官方 E2E / KIND 仍 NOT EXECUTED / 旧凭据 helper 边界 BLOCKED。

### 14.7 达成什么、还缺什么

已经达成“这个精确受限能力的静态引用，在默认 high 下载策略下可解释地阻断整个版本”，并验证普通 unknown、正常纯数据、大文件字节完整性和格式失败的行为区别。它不是任意反序列化的全语义安全证明：动态构造函数、其他加载入口、仓库 Python / trust_remote_code、模型后门等仍需各自策略和分析；representative recall / 误报率、真实 checkpoint 兼容语料、多 GB、千文件、高并发和长期稳定性没有由本轮证明。

合法旧 PyTorch Storage 也可能引用此入口并被保守阻断。适用时优先让可信生产方提供纯张量数据格式，不在宿主机加载未知 Pickle 来转换；不自动关闭 consumer 限制或切回 weights_only=False。独立人工复核、业务可接受风险记录和更强隔离属于后续工作。现在的交付环节是把已完成事实编译成视觉报告与清洁源码包，并以每个实际文件的 hash / QA 记录确认，不在源报告内预先填造输出 hash。

本节原始依据：新轮 experiment/results.json、supervisor-result.json、ui-review.json、outer-attempt02-exit.json；scanner-unit-final.log、scanner-integration-accepted.log 及原失败；official-unit-summary.json、UI构建清单；ASTRA_FINAL_REVIEW.zh.md 与297项只读核验。公开技术出处为 [PyTorch v2.9.0 固定源码](https://github.com/pytorch/pytorch/blob/v2.9.0/torch/storage.py)、[Python Pickle 文档](https://docs.python.org/3/library/pickle.html) 及 [pickletools 文档](https://docs.python.org/3/library/pickletools.html)。完整路径与 hash 在伴随证据索引，不读取或包装旧凭据文件。
