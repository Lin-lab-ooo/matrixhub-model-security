# MatrixHub 制品安全与历史内容门禁

MatrixHub 的安全闭环把模型制品的上传、不可变扫描报告和下载准入连接起来，并对能够直接返回历史内容的 Git 出口执行统一策略。扫描使用静态分析，识别危险反序列化引用、格式与归档问题；整个流程不加载模型、不运行推理，也不执行样本中的代码。

证据截点：北京时间 2026-10-09 22:22:18；应用代码 6e2b4ee5a6525383da784fb42b8f677e3163343f。新后端和应用镜像已实际构建并核验字节；独立安全验收的四种全局/仓库策略组合仅在历史source ad7e5040a9f09e82cc2a6e17faea649c1e57e40a 有四组合PASS；当前6e2版本未重跑该独立四组合，ad7 PASS不跨版本继承。官方完整入口最近归档的 official-cec54a92 为 187/187 PASS，187/187 已报告；passed=187，资源清理=true。旧4737性能实测覆盖1/8/63MiB合成制品及独立超限拒绝；原16小时长测保持INCOMPLETE。

## 产品问题与检测边界

模型制品不总是纯数据。Pickle 在加载时可重建对象、调用被引用函数；框架的辅助加载函数也可能再次反序列化内部字节。项目在文件进入下载链路前做静态分析、完整性核验和准入控制，不运行模型、不反序列化样本，也不通过执行恶意负载判断安全。

目前可解释具体 module/name、成员、流和偏移。精确识别 torch.storage._load_from_bytes 属于高风险执行能力引用；未知引用仍是 medium/不确定，不能统称恶意。发现静态引用不证明调用已发生、文件已经攻击系统或作者有恶意。合法旧格式可能被保守策略阻断，格式完整和扫描通过也不保证任意推理环境安全。

这个原型覆盖制品扫描、不可变报告、受控下载、策略和审计。它尚未实现独立人工复核实体及意见/依据/结论提交闭环，也没有受控模型加载器、全部仓库脚本/auto_map/TorchScript 代码语义分析或代表性误报/漏报率。因此不能称“加载零执行风险”或“治理全部完成”。

## 上传、扫描、报告和下载的完整链路

直接上传先保存 Git/LFS 版本，不把上传接口等待扫描完成。后端以规范仓库身份和不可变 revision 建立完整 manifest，包含 HF 自动 metadata；逐路径核对 Blob/LFS 身份、尺寸和完整 SHA256，将受限字节写入只读扫描快照。Stage/hash 与配额发生在准入前，未覆盖、格式不完整、预算不足或错误均不能成为完整通过。

任务经持久化状态、租约和 attempt fencing 交给 scanner。应用与 scanner 通过 Unix socket 和共享只读快照通信；包装层将已核验文件句柄传给分析进程，执行固定 generation 的 ClamAV 和 Picklescan。格式解析有归档、成员、深度、尺寸和时间预算。扫描报告绑定仓库、revision、manifest、文件摘要、engine 和 generation，旧 attempt 的结果不能覆盖新任务或取消后的状态。

下载时重新读取当前仓库策略、报告完整性和 generation，再打开批准快照。同一文件句柄上完整计算 SHA256 后 Seek 并 ServeContent，因此 HEAD 和小 Range 也有随文件大小增长的预验证读取成本。缓存命中仍执行完整 Stage/hash，只省去分析引擎成本；没有跳过这些语义来制造性能提升。

任务状态、扫描结果和每次准入分别记录。generation 更新会使旧批准失效；策略阈值改变可影响同一报告的准入，不必伪造新的扫描报告。人工重扫、取消或修改策略不等于人工复核结论。

## 历史内容出口与策略组合

普通 HF/LFS/native 文件下载可以核对批准快照；原始 Git 则可能暴露可达的历史对象。HTTP Git discovery/upload-pack、SSH upload-pack、HF compare 与 native commit diff 也是内容出口。旧实现部分入口只判断全局模式，没有读取当前仓库策略；全局 audit、仓库 enforce 的组合因此存在准入覆盖缺口。这是源码控制流确认的问题，没有对旧部署做漏洞利用复现，不等于任意私有仓库越权或已经发生模型代码执行。

新中央门禁 DenyRawGit(ctx, canonicalRepo) 先检查读取授权，再读有效仓库策略、验证规范身份/版本/模式/严重性并写审计。缺少策略行时采用配置 fallback 与 Version 1；数据库错误不能伪装成缺行。授权、策略读取、有效性或审计失败都不能放行。阻断条件为 globalMode == enforce OR effectiveRepositoryPolicy.Mode == enforce。

| 全局模式 | 仓库有效模式 | HTTP Git、SSH upload-pack、HF compare | native commit |
| --- | --- | --- | --- |
| audit | audit | 授权、有效策略和审计成功后保留原路径 | 保留原 diff |
| audit | enforce | 拒绝原始历史内容 | 仅正常 RawGitDisabled 转为 metadata-only |
| enforce | audit | 拒绝原始历史内容 | 仅正常 RawGitDisabled 转为 metadata-only |
| enforce | enforce | 拒绝原始历史内容 | 仅正常 RawGitDisabled 转为 metadata-only |

安全关闭保留原功能与授权行为；仓库 audit 不能放宽全局 enforce。native commit 的 WithoutCommitDiff 标记使 repository 层跳过 c.Diff()，模型层复制对象并清空 Diff；其他错误直接失败。该机制不承诺元数据保密或 Git 对象存储零读取。audit/audit 的兼容路径也不表示所有历史已被扫描。

历史 4737 门禁增量为 16 个内部路径：9 个生产文件、7 个单测文件，其中 3 个新单测文件；672 行增加、52 行删除。最新 ad7 另改 SSH server、existing regression、增加 canonical regression 并修正式 Compose，4 个路径本地 DCO。scanner 核心及 generation 未变，新版本仍须独立核定 binary/image，不继承旧版本业务 PASS。

| 全局模式 | 仓库模式 | 实际预期 |
| --- | --- | --- |
| audit | audit | 允许已授权读取；完整SSH/HTTP PACK及旧、新提交字节校验 |
| audit | enforce | HTTP/SSH历史原始内容阻断 |
| enforce | audit | HTTP/SSH历史原始内容阻断 |
| enforce | enforce | HTTP/SSH历史原始内容阻断 |

v12 campaign 04fd668b031c 实际四组合PASS（86.401262秒）。允许路径明确协商no-progress：SSH exit0、stderr0、stdout970B、PACK962B，与HTTP PACK SHA一致；index-pack和两份32B旧/新README读取均exit0且SHA精确匹配。其余三组合均阻断。两mode的supervisor/child均exit0；每mode四项API清理、2容器/3卷、parent absence和本地pack目录清理均完成。该结论适用于ad7独立安全验收；source发生变化后须另行验收，不自动继承。

## 停止状态与并发写回保护

同步任务和子job被停止后，旧worker持有的对象仍可能尝试保存运行状态。当前版本将task/job更新写成原子数据库条件更新：已有STOPPED记录只接受STOPPED写入，其他旧状态不能覆盖它；零值字段仍可更新，已删除行不会被Save重新插入。两个SQLite回归入口分别验证停止状态保持、零值更新和不重新插入三种行为。历史dad3db95的SP0030失败保留在附录，后续兼容结果以本轮完整官测真实终态为准。

## 产品界面与操作含义

模型安全卡片按仓库scope和revision查询状态，展示该revision对应的报告与generation。证据页显示严重性和具体发现，并提供revision/generation复制；任务页显示扫描任务并支持取消、重新扫描；策略页配置audit/enforce和阻断严重性；审计页展示准入及策略相关记录。任务状态、报告结论与当前准入决定分别展示，策略调整和手动重扫不会生成虚假的新扫描报告。

界面没有独立的人工复核实体、审核结论或反馈提交接口。现有253.5秒演示视频和六个真实能力case来自code63c0/doc5552。当前镜像内UI index字节与其锁定值一致；相同UI字节不能代替新版本实际界面演示。

## 实际验证结果与版本范围

| 验证 | 实际结果 | 适用范围 |
| --- | --- | --- |
| 6e2b4ee实际unit | exit=0；23通过包/26无测试包、246顶层/297子测试；107.784s | official default literal make test.unit; short/count=1; HF handler excluded; report-only go test JSON shim；失败=0；跳过=0 |
| ad7历史SSH整包单测 | PASS；13顶层、48子测试、1包；0失败/跳过；31.859s | 定向SSH包，CGO=0；不是ad7全仓单测 |
| 6e2b4eeCGO单测与构建总流程 | PASS；223.047s；70665544B | CGO=1；15036 SDK文件SHA/size/mode及集合全部核验；6e2总流程包含SDK核验、两项定向回归、官方unit和backend构建 |
| 6e2b4ee镜像与payload | PASS；build/payload实际exit0；backend/UI字节核验 | 固定新backend；自有临时资源清理完成 |
| ad7历史门禁 | 四组合PASS | source ad7e504；当前source继承=false |
| 4737官方默认unit | 23包PASS、26包无测试；238顶层/263子测试；177.280s | CGO=1；默认排除HF handler；不继承为ad7全量unit |
| 官方query-only a419 | PASS；211.641s；首次Go查询0tables | 旧4737准备链；未migration/seed；0业务spec |
| 6e2b4ee官方完整入口 | 187/187 PASS；187/187 已报告；passed=187 | official-cec54a92；安全功能关闭；与独立安全验收分开 |
| 旧scanner | 52核心例；最终11Unix组实际PASS | 52在e1baab执行；b7核心字节相同继承；不是ad7新增测试 |
| 旧能力与UI | 6真实case及实际UI证据 | code63c0/doc5552，版本范围独立 |

顶层测试、子测试和package有包含关系，数量不能相加成独立用例，也不能与Ginkgo spec直接比较。官方默认unit完成所选范围，不等于全部仓库包已运行。literal make test.unit是独立单元入口；官方兼容由外层make test.e2e.kind进入KIND，再执行nested make test.e2e，11个Ginkgo包从当轮源码编译后报告187spec。两层实际退出码分别记录，unit事件与E2E spec不累加。新源码官方unit包含SSH回归和两项SQLite STOPPED回归；单独目标2顶层/6子测试是重复执行的定向范围，不能再加到官方unit计数。

| 代码或产物 | 固定标识 |
| --- | --- |
| 当前代码 | 6e2b4ee5a6525383da784fb42b8f677e3163343f |
| 当前backend SHA256 | 358b6aa5031e683f3e4274cdb523847e5196d9795a193566815317e56cd78440 |
| 当前应用OCI index | sha256:05fd4b2f1fa039a0a7b4bfcaedff8004c32bf0a9bb692b2ea9b303ee8c555fa2 |
| 当前linux/amd64 manifest | sha256:07b51639959a9961a809a63f66605e0bff0bf4d3fb349784301a10b0ac32072e |
| 当前OCI config digest | sha256:466b43b6b5cf34bf9a1a0f161c1b2e8f632ae70a867a52ebd1e9317e38b0f7ad |
| ad7历史linux/amd64 manifest | sha256:d0e8034f44f9e1e102789d6b3450a2d4df65395abb2834bf61c8dd91a9e5ea66 |
| UI index SHA256 | 01e15e40d3913c740420b830dfbdd00c78ef5a5da47be6d2275ae8ad2e965e49 |
| scanner镜像 | sha256:b7eb7eccd33cffdac34ab37b7a2fb4ee1ff414b794634fd0ffda63128368249d |
| scanner generation | 2e17cfeb2fefd0744d6a688f5218663e069e6e563ee17fb5351ce3ab0df312b8 |
| 旧4737代码 | 4737a0c59c93605fa5d813dbe9564c9499832431 |
| 实际官方runner | sha256:8159e6ef6cb8c460aa2c100eec6be080218dc402815be9ea29bc164eda6d1a63 |

OCI index、platform manifest和config digest属于不同层级。部署身份应按实际manifest→config及CRI记录核对，并与运行中的backend/UI字节核验共同解释。MySQL使用官方8.4系列，锁定版本8.4.11；早期“8.0”记录错误。认证TCP就绪和空库查询已有实证，生产迁移及后续应用阶段按各轮实际终态分别列示。

## 官方测试的规模和兼容范围

固定上游为 6890726abe272767d26ce1a6b0580b0718f232c0。原上游静态对比涉及40个公开文件（33个suite和7个入口/CI文件），该静态记录不是最终执行源的33文件字节相同声明。最终执行源中32个官方suite文件逐字节相同，model_test.go仅在createGitModelFixture的准备流程追加目录初始化调用；新小helper写入49B inert目录内容。187项It回调体、标签、Skip和Expect断言的AST保持相同，项目没有新增业务spec。官方suite仍为11包、187 active It。项目向该 Ginkgo 树新增 0 个 spec。smoke 静态选择 13 项，早期 165 过滤方案都不能称完整 187 项；官方 PR workflow 可传 all，静态比较不证明云端 CI 已通过。

| 测试类型 | 数量或输入 | 它能证明什么 | 它不能替代什么 |
| --- | --- | --- | --- |
| 4737官方默认单测 | 23通过包、26包无测试 | 该版本默认入口选中范围 | ad7完整单测、默认排除HF部分、部署兼容与安全全链路 |
| 官方 Ginkgo 业务套件 | 187 静态身份，11 包；11 ELF 已编译 | suite 可以在锁定工具/source 下编译 | 实际187业务结果，见实际结果表 |
| 旧 scanner 核心/Unix | 52/52、36.538s；最终 Unix11/11、119.512s | 52在e1baab镜像真实执行；b7核心字节相同继承，未重跑52 | 代表性检出率、恶意行为执行、新ad7四模式网络验收 |
| 旧能力与产品UI | 6真实case、独立真实UI | code63c0/doc5552精确引用/准入范围 | 4737或ad7全部出口组合；UIhash相同不能冒充新backend演示 |
| ad7历史门禁v12 | 四组合实际PASS | 允许路径完整PACK/旧新字节与三种阻断组合 | 全仓兼容、检测准确率、性能或人工复核 |
| 4737性能v3与独立v4 | 1/8/63MiB三个正例PASS；64MiB+1单负例PASS | 完整manifest/终态/全字节下载、配额拒绝与真实资源采样 | v3整轮FAIL保留；不能证明单轮四corePASS、ad7性能、并发/多GB或提速 |

官方 HF00003 的明确本地上传样本为 10 MiB+1（10485761 字节）周期数据，文件名 weights.safetensors，不是合法 Safetensors 或训练 checkpoint。我们旧实测的 63 MiB 是整文件 66060288 字节合法 U8 合成张量。这些测试互补，不能以文件名、合成大小或用例数量证明真实多 GB 模型、推理兼容或统计检出率。

官方兼容 lane 安全功能关闭，验证官方原有业务；独立安全 lane 开启功能，验证准入和策略组合，结果必须分别说明。SP0020仅将原公网外部endpoint适配为本轮自有fresh endpoint，原业务断言保留；此适配必须披露，不能称已向原公网目标PUSH。

## 性能实测与容量边界

性能 v3 campaignd1c470ec4e08/run073ef33d6dac 为 code4737 独立 fresh fixture 实跑；303.531s 整轮 FAIL，原失败保留。1/8/63 MiB 三个正例的完整 manifest、COMPLETE PASS、新 payload SHA/cached=false、forceDownload 网络200/完整字节及独立 SHA 均真实通过。每个 manifest 另含1519B自动 metadata。以下包含应用上传、轮询观测与完整下载/hash成本，不能当单独 engine 时间或并发吞吐。

| 合成 payload | 上传 s | 提交至观察终态 s | 完整网络下载与 hash s | 正例状态 |
| --- | --- | --- | --- | --- |
| 1 MiB | 0.281 | 29.328 | 0.563 | COMPLETE PASS |
| 8 MiB | 0.250 | 29.813 | 0.390 | COMPLETE PASS |
| 63 MiB | 2.515 | 56.563 | 2.266 | COMPLETE PASS |

时钟为 monotonic、区间互斥且 overhead 单列；相互包含的 polling/upload-to-terminal 不相加。提交至终态包括任务等待、staging、扫描、持久化和轮询；首次观察 scanning 也不是精确队列等待。单次、串行、三种合成尺寸不足以给稳定吞吐、误差区间或整体服务容量，未测高并发、多 GB、真实 trained weights。仅有 metadata warm cache 与新 payload cold 观测，没有 engine 调用计数或可信的基线提速结论。

v3 的64MiB+1已进入 file-limit fail/incomplete、HEAD/GET403；GET body.code 契约期待 ScanIncomplete 导致原场景失败，原 body 未保留，不倒填新结论。独立 negative-only v4 campaign1e7ac9d4ccc5/runf52683e5471a 实际35.406s PASS：67108865B、controlled-payload-file-limit、0scanned、HEAD403 RevisionFailed/空body、GET403/133B固定四key JSON RevisionFailed/statefail、无Location、0制品字节。API及2容器/3新卷实际清理TRUE。三正例与新单负例分别覆盖，不能拼成一轮 FourCorePassed，负例不计吞吐样本。

v3 observer 每5s按两exact container ID采样，15s命令预算；54samples/54valid/0error，max实际间隔5.079s、overrun0.079s，STOP/wait完整后才清理。application 采样最大 CPU75.57% / rounded Linux cache-subtracted memory106011033.6B；scanner100.93% /1062207488B。这是 Docker 样本与显示精度换算，不是瞬时peak、RSS或host RAM；采样自身可能影响workload。功能结果与observer complete分开；所有API/fixture资源已清理。

原型默认64MiB/file、256MiB/task、1000files/task、单staging writer/单scanner worker、2GiB retained logical bytes；逻辑配额不等于物理磁盘配额，历史快照无自动GC。未证明生产多GB、高并发或代表性检出率。规则、wrapper和engine同容器信任边界也不等于microVM隔离。

## 赛题覆盖与明确限制

赛题权重为检测25%、集成准入25%、执行安全15%、可靠性与规模15%、解释与治理10%、社区沟通10%；这些是评审权重，本文不声称获得分数或推算获奖概率。直接上传的小闭环已实现，proxy/sync属于可选扩展。

| 要求 | 已具备证据 | 仍有边界 |
| --- | --- | --- |
| 制品检测与可解释发现 | 静态引用、格式/归档、固定双engine与generation、scanner回归 | 未建立代表性误报/漏报率；未覆盖所有仓库脚本、auto_map与TorchScript风险 |
| 上传、扫描与准入 | HF/HTTP/UI、不可变报告、下载字节校验、ad7四策略组合 | 静态通过不保证任意模型推理安全；兼容结果按实际官方187终态 |
| 治理与人工复核 | 策略、任务、报告、取消、重扫、审计 | 没有独立人工审核实体、结论、反馈/申诉提交接口 |
| 性能与可靠性 | 4737三个合成正例、独立超限拒绝、54个资源样本 | v3整轮FAIL保留；多GB/高并发/真实checkpoint/稳定吞吐/缓存提速未证明；16h INCOMPLETE |
| 文档、源码和演示 | 固定源代码/制品标识、复现recipe、旧253.5秒演示 | 旧演示明确code63c0/doc5552；公开recipe尚未在新机器构建/实跑 |
| 社区沟通 | 本地可审设计草稿 | 没有已获社区有效认可的证据 |

默认配额64MiB/文件、256MiB/任务、1000文件/任务，单staging writer与单scanner worker，retained logical bytes上限2GiB。逻辑配额不能代表物理磁盘总量；没有历史制品自动GC。wrapper和扫描engine同容器，隔离边界不能等同microVM。

## 公开复现配方及输入条件

独立reproduction-v4-stopfix的profile绑定source 6e2b4ee5a6525383da784fb42b8f677e3163343f，1502个执行源码元数据条目，freshENV新生成auth/fixtures/protocol/bootstrap及公开inventory适配器。runner包含认证MySQL TCP就绪、有界forward观测、strict空库、生产迁移与fresh admin创建；DSN对齐生产charset=utf8mb4&multiStatements=true&parseTime=true三参数。原v2的4737方案和早期ad7迁移候选保留原字节。

本轮执行源码闭包包含1502项：32个官方suite保持原字节，1个model suite仅调整fixture准备；187项It bodies、labels、Skip与Expect断言AST相同。createGitModelFixture会创建独立private空模型仓库，原全局seed不能覆盖它；补充helper为该仓库写入49B inert目录内容。此变化不修改应用生产源码、backend、官方unit所选源或187业务断言。

基础v3曾实际通过75项纯AST/隔离契约检查、五个生成Go文件AST可解析；此记录保持原版本范围，不能继承为v4新源码复现通过；公开成员清单目前52项。纯检查不等于Go类型编译、KIND业务或新机器复现。最终部署身份适配以该清单中的控制代码和锁为准，不能从旧8159镜像ID推断重建产物身份。

公开toolbox提供Dockerfile、source-lock、prepare-context和SDK runtime verifier：固定官方Python base digest，Go1.26.8 archive、kind0.31、kubectl1.32.3、Helm3.16.4的官方来源/SHA，Ginkgo2.32.0由生产go.mod/go.sum约束；15项Python依赖版本及签名Debian snapshot锁定。recipe不依赖未公开的本地builder/flatbase或旧embedded bootstrap。APT和wheel的实际字节、ELF及新image ID须在重建时核验；“build时捕获wheel字节/SHA”是recipe行为，本文没有声称本机已经捕获或toolbox已经重建。

复现前显式提供Linux Docker、固定app/MySQL/node镜像、公开SDK archive和只读Go module cache；输入与运行凭据由freshENV生成或显式设置。默认预检不执行Docker；缺失输入或不匹配hash拒绝继续。新机器实跑尚无证据。private kubeconfig、SSH私钥、Secret、DB/token/cookie、缓存、原helper及联系方式不作为交付成员。

## 附录A：官方入口和查询的逐轮真实终态

official-243a2eeb 于 UTC 05:57:17 至 05:58:05 实际运行 47.9593214 秒。literal make test.e2e.kind E2E_LABELS=all 确实开始；private SDK 恢复核验后进入 kind-setup，kind create child 返回 1，外层/attach/container 为 1、make 为 2。owned node 创建及归属已核对，runner/tmpfs、node/network 和 alias 检查均实际清理。

该次没有进入 nested E2E，187 项均 NOT RUN：PASS=0、FAIL=0、SKIP=0、NOT RUN=187，而非“187 FAIL”。具体 KIND 根因当时未证明。该轮未进入nested make test.e2e业务运行。

后续 official-5d4903ae 是独立 create-only 诊断，实际 112.5453896 秒、外层/container/setup/list/create 均 0，kind create 耗时 71.238611 秒；固定 boot marker 观察到 multi-user target，没有命中已定义失败 marker。owned node/volume、进程组、private 目录、runner/network 均实际清理。本轮没有应用/MySQL 部署、账号、SDK 编译或 Ginkgo 业务，187 仍 NOT RUN。

同一固定 image/config 的单独创建成功，说明该截点具备创建能力；它不恢复旧失败轮，也不证明旧故障原因、永久修复或官方全套通过。下一完整业务必须是新 run、完整 ownership/gate 和真实终态。

新完整入口 official-88473005 于 UTC 08:09:04 至 08:10:44 实际运行 100.3947705 秒。KIND list/create 实际 exit 0，create 为 57.2562 秒；随后 setup 的 owned command 返回 1，分类仅为 generic-owned-command-exit。外层/container 为 1、make 为 2，未进入应用/MySQL 部署、内层 E2E 或 Ginkgo，suiteCount=0、187 NOT RUN。进程组已 wait/absent，owned node/volume、private tmpfs、runner/network 实际清理完整；源与控制冻结未变化。后续独立 post-setup-only 诊断真实定位 resource-update 的 memory/swap 冲突；修复为显式有限 RAM+swap 总量后另一次全新完整入口，原失败不改。

历史完整入口 official-80655293 于 UTC 09:15:03–09:17:20 实际运行 137.047 秒。KIND/setup 成功，owned node 实核 Memory=6442450944、MemorySwap=12884901888、NanoCpus=6000000000；这些是 6 GiB RAM/12 GiB RAM+swap/6 CPU 预算，不是占用。bootstrap-proof passed=false、step=empty_database_guard，外层/container=1、make=2，suite=0、187 NOTRUN，cleanup 全 true。当前证明合并了查询失败与非零表数，根因仍未证明；chart 仅一套 replica0 部署，job.enabled 配置不能证明 worker 提前迁移。当时后续query-only实跑在 MySQL image load 失败，未进入SQL查询，仍未定位806的空库守卫根因；不放宽空库条件，不预写187 PASS。

| 完整官测 | 代码 | 整轮 | 秒 | 业务计数 | 阶段与清理 |
| --- | --- | --- | --- | --- | --- |
| official-8df6b493 | ad7e5040 | FAIL | 134.484 | 0/187 已报告；not-run=187 | production_migration；cleanup=true |
| official-cec54a92 | 6e2b4ee5 | 187/187 PASS | 321.625 | 187/187 已报告；passed=187 | complete；cleanup=true |
| official-aa2d33d9 | ad7e5040 | FAIL | 138.484 | 0/187 已报告；not-run=187 | complete；cleanup=true |
| official-dad3db95 | ad7e5040 | FAIL | 345.250 | 187/187 已报告；passed=185、failed=1、skipped=1 | complete；cleanup=true |
| official-8b7aa2f7 | 6e2b4ee5 | FAIL | 364.141 | 187/187 已报告；passed=186、skipped=1 | complete；cleanup=true |

8df6b493的首次strict查询成功且0tables，随后production_migration失败；DSN遗漏multiStatements与生产Chart不同。下一aa2d33d9轮138.484s仍FAIL/187NOTRUN：DSN修复后生产migration、fresh admin和应用backend/UI字节守卫已通过，随后镜像身份守卫失败。该阶段失败不能回写为产品migration未通过，也不能将运行中的OCI/config层级差异直接断言为错误backend。两轮失败保持原结果，后续轮次按表中真实终态计数。

8b7aa2f7在source6e2上实际364.141s，完整187身份/11包全部报告，186PASS、0FAIL、1SKIP M00036；原Make.kind/nested Ginkgo均exit0，要求187全PASS的严格wrapper为1，清理与freeze unchanged均true。SP0030停止状态已PASS；目录case的Skip来自model helper创建的独立private空repo只有.gitattributes，全局seed的fixture/README不适用于它。后续仅fixture setup调整和结果另列，原Skip保留。

query-only official-a419de6b 的认证TCP SELECT1前五次实际1/MySQL2003 HY000，第六次实际0/stdout exact1，共11.0517s；原forward/socket/alive与首次Go查询实际0/0tables。forward活至受控停止-15，wait、drain EOF和stderr0已记录；清理=true。该轮未执行migration、seed或187业务。旧261ef3f6在MySQL load失败，临时512MiB空间不足只是当时假说；d2e726b5的原forward已退出，未执行查询。query-only通过不能反推旧806全部根因。

## 附录B：历史门禁逐轮失败与修复依据

以下内容按每轮当时的执行范围记账。后续成功不会将前轮失败、未执行或清理缺口改写为PASS。

每轮独立 scope、新空卷和进程随机凭据；失败 scope、harness、消费标记和结果均保留，不清标记复用、不恢复旧密码。前一轮失败不由后一轮补写为通过。

| 轮次 | 实际结论 | 范围与清理 |
| --- | --- | --- |
| v1 | 外层 1；监督器预检失败 | 业务未启动；2 容器/3 新卷清理完成，具体原错误码缺失 |
| v2 | 外层 1；精确只读 bind 守卫误拒 started Linux 表达 | SHA/目标/只读相符；业务未启动、清理完整；never-start probe 只证明 create 阶段 |
| v3 | 外层 1；README 报告不是 COMPLETE PASS | 业务开始但四组合未开始；fixture 清理完整；APIcomplete=false 原记录不改，SSH key 已内存生成但未注册/落盘 |
| v4 | 外层 1；报告 fail/incomplete，scannedBytes=0/fileCount=0 | expectedFiles=2；错误当时只定位到首个 FileReport 之前，不能定为 scanner 引擎故障；fixture 清理完整 |
| v5 | 外层 1；固定 known-filesystem-error/mkdirat/permission-denied | scannedBytes=0；2 容器/3 新卷清理完整；没有四组合通过 |
| v6 | 外层 1；首 audit/enforce 组合 PASS，下一 audit/audit 本地 pack verifier FAIL | API 四步 PASS、fixture 清理完整；全局 enforce 未启动，整体验收 FAIL |
| v7 | 外层 1；首 audit/enforce PASS，下一 audit/audit 的四个 Git phase 均 exit 0 后 Windows PermissionError | 原 API 四步 PASS 但 cleanup.complete=false；fixture 清理完整，后续 ROOT 精确 owned pack 清理确认 absent，原 FAIL 保留 |
| v8 | 首 audit/enforce PASS，下一 audit/audit 的 SSH advertisement 截断，整轮 FAIL | API 四步与 fixture 两容器/三新卷实际清理完整；全局 enforce 未启动 |
| v9 | 首 audit/enforce PASS，下一标准 SSH 路径收到 0 字节首 header 后 EOF/exit1，整轮 FAIL | 固定stderr permission-denied，cleanup完整，code4737 |
| v10 | 新ad7 audit/enforce实际PASS；下一audit/audit广告/SHA通过后SSH历史读取失败，整轮FAIL | ssh-audit-history-read-failed，原观测未保存；清理完整 |
| v11 | audit/enforce PASS，audit/audit strict stderr守卫FAIL，整轮FAIL | exit0/stdout970B NAK-PACK/stderr611B git-progress-only；未校验完整PACK，旧FAIL保留 |
| v12 | 新ad7四组合实际PASS | audit/audit完整SSH+HTTP旧新历史允许；其余三组合阻断；API/fixture/packdir清理全true |

v6 campaign d3c1fb4fee97、audit run 587637cd94a6，实际 UTC 07:23:06.981603 至 07:24:30.516849。所有 owned named volume NoCopy、有效 UID/GID65532、input/data0750、socket0770，以及应用 exclusive inert mkdir/write/fsync/remove 均实际通过。旧/新 README 两个 revision 均为 COMPLETE PASS，完整 manifest 各 2 文件/1551 字节（1519 字节 HF metadata 加 32 字节 README），报告 durationMs 为 27314/25596；这是报告字段，不是新 benchmark 或只含引擎的耗时，不能据此计算性能增益。

首 global audit/repo enforce 组合实际验证：HTTP discovery/upload-pack 为 403 RawGitDisabled；SSH upload-pack 拒绝且 stdout=0；HF compare 403；native commit 200 但 diffBytes=0；receive-pack discovery/empty RPC 保持授权与匿名 RBAC，未注册 SSH key 被拒。策略更新及 raw-git 入口审计存在，并绑定规范 repo、policy version、报告/manifest/generation。此结论只覆盖本次已完成组合。

下一 audit/audit case 的固定失败码为 local-inert-pack-validation-failed。原 harness 没有保存具体 Git 子命令 phase，因此不能证明返回 pack 损坏、允许出口错误或其中 old/new 内容无效。独立 fresh empty bare Git 探针在相同过滤环境下 init=0，未设置 trust 的 rev-parse=128/dubious-ownership；仅命令级 safe.directory=该 exact owned 目录后 rev-parse=0/bare=true。它支持精确目录 trust 的最小适配，不反推 v6 原 pack 有效。v7 保留 OLD/NEW 和 pack 严格断言，增加 exact trust 与固定 phase/exit 观测，不能使用 wildcard 或修改全局 Git 配置。

v7 campaign ca91aa5fd9d1、audit run 2b2284f3cf94 于 UTC 07:57:58.340 至 08:00:38.639 真实运行，整轮仍 FAIL。首 audit/enforce 完成；下一 audit/audit 的四个本地 Git phase 均 exit 0，随后 Windows 删除只读 pack 对象触发 PermissionError。原结果 API delete SSH key/model/project/revoke token 四步 PASS，但 cleanup.complete=false；父 fixture 两容器/三新卷清理完整。ROOT 后续只读取明确 owned pack 目录元数据，精确清理 3 个只读对象并确认目录 absent；它补足遗留清理，不把 v7 原结果改成 PASS，也不宣称 audit/audit case 通过。v8 campaign 3a7913ed9231、run dae6f3a30e13 于北京时间 16:32:12.697 至 16:34:24.224 实际执行。首 audit/enforce PASS；下一 audit/audit 固定失败码 ssh-advertisement-truncated，整轮 FAIL、全局 enforce 未启动。API 四步 cleanup.complete=true，fixture 两容器/三新卷实际清理完整；此轮不是 pack 删除失败。v9 已实际运行并仍 FAIL，标准路径问题的生产修复和新 unit 见下节。

## 附录C：标准SSH路径和NoCopy修复

v9 campaign8060ce5d9f51/run90db0bfe371c 实际 UTC09:35:44.582–09:36:30.094。audit/enforce PASS；下一 audit/audit 的首 header received=0、EOF/exit1，bounded stderr 17 字节精确命中 permission-denied，SHA256 b77f13ea8d89b1be38c219acdb71af52a13e7030789a67c22a834c02c30bd39c。API 四步和 2 容器/3 新卷真实清理完成。静态调用链与固定 stderr 对应：Git 客户端标准 '/project/model.git' 在 securityGate 局部移除 leading slash，但 permissionHook 仍收到原 scope，RBAC SplitN 得到空 project，提前拒绝，尚未进入 Git 工具。此前工具 ELF 探针只能排除工具缺失，不证明这条允许路径已执行。

新 ad7 canonicalSSHRepoName 只去掉一个可选 leading slash；空 component、'.'、'..'、反斜杠、NUL/换行等歧义 scope 拒绝，不用 path.Clean 重新解释路径。标准 scope 在 executeCommand 和 LFS authenticate 的授权/存储链前保持一致，保留既有读写 RBAC 和门禁错误处理。没有通过改 fixture 去掉 slash 掩盖标准 URL 问题。新完整 SSH package -count=1/CGO=0 actual0/31.859s，13 顶层/48 子测试/1package、0 fail/skip；这是真实回归，尚不是新部署网络四组合通过。

ROOT 空卷 metadata probe 已证明同 dev/inode 的 input volume 初始化 uid/gid65532:65532/0750，application CREATE ONLY 后0755，scanner 只读 CREATE ONLY 后0:0/0755，业务未启动并完整清理。Docker 默认 copy-up 可预填空 named volume；volume.nocopy:true 抑制该行为，read_only 与 nocopy 是两个字段。[Docker volume 说明](https://docs.docker.com/engine/storage/volumes/)，[Compose 长格式](https://docs.docker.com/reference/compose-file/services/#volumes)。

正式 Compose 的 init3/scanner2/application3 共8个 named mount 现已改长格式 nocopy:true。SHA2562514a0d7804529be6f79d7c6079ce87e2a3b11723fb953566d5d774de6dcbf9b；YAML semantic equality 仅允许预期 mount delta，readonly/bind/UID/caps/limits 保持。docker compose config actual0，现有旧卷未改、业务未启动。v6 fixture 的 UID/write/fsync/remove PASS 是历史实测，正式新 Compose 仍需匹配版本运行验证；NoCopy 不负责修旧卷 owner。

新 backend 第一尝试 a19a41d857a7 为 Python 入口 container127，第二尝试134717a9d159为SDK metadata CRLF不符，两者均未进入Go build、清理true；第三次新编译结果见最新运行终态。新代码/配置须与最终镜像、源码manifest和真实测试版本共同冻结。

## 附录D：单测、构建和工具准备失败

下表及离线编译记录属于旧4737基线，当前源码构建与实际unit单独列于正文。

| 验证 | 实际结果 | 范围与限制 |
| --- | --- | --- |
| 定向回归 | 7 包；26 顶层 PASS、66 子测试 PASS；0 fail/skip | CGO=0；中央组合和路由 wiring 分开验证，不是网络四组合全部通过 |
| 4737官方 make test.unit 第二次 | make exit 0；177.2799538 秒；23 包 PASS、26 包无测试；238 顶层 PASS、263 子测试 PASS；0 fail/skip | CGO=1，SQLite repo/session 实际运行；官方默认排除 HF handler；short/count=1，无 race/coverage |
| 后端编译 | actual exit 0 | Go 1.26.8、CGO=1、trimpath；固定 binary SHA256 |
| 应用镜像构建 | 第二次 actual exit 0 | apt 层 CACHED；不宣称本次重新下载 |
| 镜像内字节与 Git 探针 | actual exit 0 | backend/UI/revision 绑定；应用 Git 为 3713416 字节 ELF、git 2.39.5 命令 exit 0 |
| 官方 E2E 离线编译 | Ginkgo compile exit 0，219.173736875 秒；11 个 ELF | 未执行业务、未创建业务 fixture；187 Go AST 身份/标签和 11 suite 严格匹配 |
| 最终 runner light proof | 外层、attach、container exit 0；58.802 秒 | wrapper、6 payload、10 tools、12 inert contract、SDK/source 字节通过；继承已有真实编译，不重复计数 |

旧scanner52例在e1baab核心镜像真实exit0/36.538s/0skip；最终b7只改集成错误码断言，scanner.py/tests.py字节相同继承，未在b7重复执行52。最终b7 Unix11/11 actual0/119.512s；此前11组actual1/131.384s原失败保留。更早a473/generation9acc的29UT/11Unix是另一版本，不作为52的来源。旧6case的inner success-candidate不单独构成PASS，最终supervisor passed=true和完整清理共同判定，版本code63c0，不替代4737或ad7。

顶层、子测试与 package 有包含关系，不能相加当独立用例，也不能与 Ginkgo spec 数直接比较。官方默认入口完整执行其选择范围，不等于全仓所有包都运行。

首次单测 make exit 2、258.6795899 秒，因测试临时目录 noexec，业务测试二进制未运行；第二次仅修测试容器执行权限和预算。首次应用镜像和首次 runner apt 构建断网遇缓存 miss，实际失败，证据均保留。后续 runner 曾出现 Docker/Git/Git LFS 空文件及 SDK runtime 字节与安装记录不一致；这些准备失败不是产品测试通过或产品漏洞结论。

最终离线编译不信任损坏的镜像 SDK。将固定官方 Go archive 作为只读单文件 bind，在自有 private tmpfs 新提取 SDK，逐条验证 15036 文件、232512886 字节的 SHA256/size/mode 和无额外文件，明确 GOROOT、禁止自动 toolchain。旧4737 source为1499文件精确哈希闭包，33 个官方 suite 与固定上游字节一致。编译的临时 ELF 和缓存已经清理，该离线编译不作为新ad7业务执行结果；新ad7执行源码闭包为1500条。


新ad7后端a19a41d857a7因Python入口缺失actual127，134717a9d159因SDK metadata Windows CRLF与LF差异actual1；两次均未到Go build，清理完成。15036文件内容SHA已匹配；仅metadata换行归一化后，第三次5f920f63d443实际编译PASS，未放宽SDK内容校验。独立v3复现的首次公开文件类型guard失败也保留，不把准备检查写成业务通过。

## 附录E：长期运行与演示的继承范围

原16小时长测195轮/196观察保持INCOMPLETE，没有完整长测终态。约7小时中断、后续恢复和独立新fixture耗时不能拼接成长测。此前52 scanner核心例、11 Unix组、六个能力case的版本范围分别列示，不能跨scope相加。

旧253.5秒、4417700B、VP8/1280×720视频为CUA采样编辑，SHA256 fe7ac685ad0c100afd532880936d107ecc19f0205c3a327bd80885fd3e91f586；它属于code63c0/doc5552。旧18页PDF和原包保持原字节，作为版本明确的历史材料。Docker恢复只证明恢复检查时Engine健康；它不能保证中断中的业务成功。

## 附录F：公开证据的定位与摘要边界

报告中的技术摘要由明确原文件及SHA绑定；摘要不是原receipt。公开证据按精确成员清单选择，不递归runtime，不含原始私有Ginkgo输出、凭据、缓存或联系方式。

| 证据文件 | 字节 | SHA256 |
| --- | --- | --- |
| runtime/history-policy-fix-v2/source-application-receipt.json | 1181 | 5fa8ab9d0527dd5a7f2110acb02aff9a7cb0ccff3f0352bdd25a1dae178e4ebe |
| runtime/history-policy-fix-v2/compose-nocopy-application-receipt.json | 515 | f56749a0acd82929305ef1096bc0f37b79041e106cc01cb6f0397360df650e75 |
| runtime/history-policy-fix-v2/compose-nocopy-docker-config-validation.json | 361 | 1a1a62a9875ea91fe3c0dc6a101562b56a754003762fe1f0ade69af907ad6017 |
| runtime/history-policy-fix-v2/ssh-package-tests-attempt-01-receipt.json | 555 | 220a4c12c866898a570286c5bee8bde1d37bec867ddbcf74c81ec7620f56c7a0 |
| runtime/history-policy-fix-v2/backend-builds/a19a41d857a7/host-receipt.json | 498 | e063f22f6e399b0564f1a4aabedfeb5d7d94b315fc1a7845d4d965774f2803a1 |
| runtime/security-evidence/scanner-final-20261008-115828-summary.json | 2566 | 228aac514fd0b23707fdb7e8b76262f779316bcbc85091b7621c095c992f6abb |
| runtime/capability-delivery-v1/evidence/runtime/capability-lab-v1/results/capability-97f08f51dfda/supervisor-result.json | 6529 | 591803778b154b74a489b2e02f27eae1be1f45ea5e0df50ce3ffd0261aab3c62 |
| runtime/capability-delivery-v1/evidence/runtime/capability-lab-v1/results/capability-97f08f51dfda/experiment/results.json | 130833 | 9c0a7bb4128bfbbed78b8bda02c054982911f7b03d6760625369e7c71947a396 |
| runtime/history-policy-fix-v2/image-builds/20261009T101702Z/image-build-receipt.json | 770 | 947cb3aca3479e3f32dd466d225fe679279ac5a8831c20d46c513d731a1372b4 |
| runtime/history-policy-fix-v2/image-payload-verification.json | 535 | 90ecebe0314db7b94d463f8cef642e7429715677fdb2dc3b3299b57de2b73e13 |
| runtime/history-policy-fix-v2/runtime-version-lock.json | 1546 | 5a38a1326c8f402f863655863a2921306c02b5c1fdc083cef0701e30971f10b1 |
| runtime/sync-stop-fix-v1/image-builds/20261009T133620Z/image-build-receipt.json | 756 | 6982b0d6eed8677ba2b4cc92298fc495675d8c5bd6f5d17984dc8f2b2d6d0349 |
| runtime/sync-stop-fix-v1/image-payload-verification.json | 598 | 261184bcad5d4dd95f3d10cdd342ad305195048fb9ce5fa870d8d8a255d02180 |
| runtime/sync-stop-fix-v1/runtime-version-lock.json | 1724 | f31037b8983fdbbbae1ef0829cb23f011736a9a407dcc0dd24087e1601f2f0e6 |
| runtime/sync-stop-fix-v1/backend-builds/32ca0e0f9b40/unit-facts.json | 1096 | b7f03c3c81f12fcb0ade0ca73e4c4dcd0bbc03c8035c8be4b351b5a8afac06f7 |
| runtime/history-policy-lab-v9/controller-results/8060ce5d9f51/controller-result.json | 6008 | 9e7991173498af02f7ae83695741e46deb229b2ef779fa8b7e8895720ae6e2d0 |
| runtime/history-policy-lab-v9/results/90db0bfe371c/experiment/results.json | 12273 | 9df35f68f16db3037e40b399ab7f0b3bb4e7423b7220236dd93a9d6fb973bc94 |
| runtime/application-benchmark-v4/controller-results/1e7ac9d4ccc5/controller-result.json | 7579 | da5d5901bd4a12721317c97d5bb956290c2fde4dff135fe9a3aacbc885d86a16 |
| runtime/application-benchmark-v4/results/f52683e5471a/experiment/results.json | 15415 | 21a1f7267f373dca4563c4b9eaac67adeb76cf89bed99232e6d95faa9974f37f |
| runtime/official-e2e-20261009-v1/runs/official-a419de6b/bootstrap-query-final-receipt.json | 14023 | 213b66bbb67aa889c9b10cf993afaebcb4d6cb300d354745cffd73a1f81e66ef |
| runtime/official-e2e-20261009-v1/runs/official-d2e726b5/bootstrap-query-final-receipt.json | 4418 | e994cf36d47ff597162ec6ab0e1157181c5096590397881c3a4bffa9a4dff55a |
| runtime/official-e2e-20261009-v1/runs/official-d2e726b5/selected-query-public-receipt.json | 2357 | 4d077ceb088135f4cecada815db287de1d032bde08280c0abef7e1d40c6b6beb |
| runtime/history-policy-lab-v12/controller-results/04fd668b031c/controller-result.json | 11000 | d32c21244346b50feebd8a1e34a401bc5db21bb8eb0f8dddfb80ef0751a52570 |
| runtime/history-policy-lab-v12/results/25923ce51e64/experiment/results.json | 22872 | 2c183387d53c579dfb77192196165cfff5781f07016511d578bf6f98194da63c |
| runtime/history-policy-lab-v12/results/25923ce51e64/experiment/audit-audit/ssh-terminal-observation.json | 433 | d011d98d9b71d3869a9b20a42dbeb77f3970539eeb818855f7e4b6c9a1bcb244 |
| runtime/history-policy-lab-v12/results/919b923dda72/experiment/results.json | 22348 | 0a4aca0becbbba21f9ee22078574ebb2e90b5ba41ecaf61c32a1f87befd130bb |
| runtime/history-policy-lab-v10/controller-results/10b1e9014c88/controller-result.json | 6008 | f5030f78d2faf18c594d55d129ee4424ec0778f8aaee2cd11bbae230fa13e8fe |
| runtime/history-policy-lab-v10/results/82afbbcfdb01/experiment/results.json | 12259 | 161f48042d502ba61fde624dfe01cf8dffe6f55bf8759f33a3b3697e5fbbbcbc |
| runtime/history-policy-lab-v11/controller-results/46f325d9addb/controller-result.json | 6008 | c3447c976156ecf422d33e4d0ef21ccb8819aa8b6f182ab84059dfb76f2f120e |
| runtime/history-policy-lab-v11/results/b46da1191885/experiment/results.json | 12241 | 06024307915a335249667ba654b4edb42c63b09168fbba9ecd10b5840cbba5db |
| runtime/history-policy-lab-v11/results/b46da1191885/experiment/audit-audit/ssh-terminal-observation.json | 447 | e38264b218d09bdba1837697a372b3ef4f09e6c168a8ae26eed875296dd0026d |
| runtime/official-e2e-directoryfix-20261009-v1/runs/official-cec54a92/final-receipt.json | 1728 | c5c2f5b1c41a587ce6341d206430837d6f58afe5b6e91308b07d0ca8cdfa2241 |
| runtime/official-e2e-directoryfix-20261009-v1/runs/official-cec54a92/bootstrap-proof.json | 816 | 5aaee11ea9a1be7776e033773a51c81da5a547325858bf210adb776594d54a7e |
| runtime/official-e2e-ad7-20261009-v1/runs/official-8df6b493/final-receipt.json | 1741 | aa7b57770e7eba47ade78e1f98f17f897394362cf49bb1633c43088298a8d234 |
| runtime/official-e2e-ad7-20261009-v1/runs/official-8df6b493/bootstrap-proof.json | 264 | 30186a2d6649e7b7bf03f00399dce8b2e06bcd1ef2dc2c0a268176f1e2595a83 |
| runtime/official-e2e-ad7-20261009-v1/runs/official-aa2d33d9/final-receipt.json | 1741 | 508cb0e6fdf11a9de7b5592598c7d8315f860e676de4f297984ea5ec0980e037 |
| runtime/official-e2e-ad7-20261009-v1/runs/official-aa2d33d9/bootstrap-proof.json | 816 | c088d55e3256480d1d7b3dcf033201e26d2b9a34e4399795e87245fc4c2cb58a |
| runtime/official-e2e-ad7-20261009-v1/runs/official-dad3db95/final-receipt.json | 1730 | 949a4351a474f81a2f14f5d4af370343a06c7ea503503de5b4d650cf62070ac3 |
| runtime/official-e2e-ad7-20261009-v1/runs/official-dad3db95/bootstrap-proof.json | 816 | bfd92f0f5bfffa9e05718b4edac13e14d32e3cfd74964f649cb8a355a7e150d8 |
| runtime/official-e2e-stopfix-20261009-v1/runs/official-8b7aa2f7/final-receipt.json | 1741 | cfd917af85a34597881e82a1209c3cef906ca270f379b7361f1a87de7ce12c9d |
| runtime/official-e2e-stopfix-20261009-v1/runs/official-8b7aa2f7/bootstrap-proof.json | 816 | 945e3ff4a8e057d4c3989ac4dea6ad95469b1a1ac39c290c88e6a725e602bda2 |
| runtime/capability-delivery-v1/evidence/runtime/capability-lab-v1/scanner-unit-final-exit.json | 14 | 6041df3e9b345d68be886f995c452395674ea950cd3ca9992c13b64f3aa9cbd0 |
| runtime/capability-delivery-v1/evidence/runtime/capability-lab-v1/scanner-accepted-evidence.json | 1238 | 0dd6f8cace0bdc50d247547fec4a18ba29bf8738885e961ef7900516395bb924 |
| runtime/capability-delivery-v1/evidence/runtime/capability-lab-v1/scanner-integration-accepted-exit.json | 14 | 6041df3e9b345d68be886f995c452395674ea950cd3ca9992c13b64f3aa9cbd0 |

