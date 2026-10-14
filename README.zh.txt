MatrixHub v12.1 完整源码交付与独立复现

本包的用途
这是完整源码快照及复现入口：1527个已校验文件，含API、数据库迁移、扫描器、UI、Compose、Dockerfile、单元测试和上游E2E源码。不是只含扫描器的增量包。
源码基底为84bb83043dc17b6cb3d1858620ac40c171bd8eff，另有44项明确列出的工作树覆盖。VERSION_LOCK.json和evidence/source-manifest.json共同说明实际版本；旧提交号不能代表新实现。
5个上游测试辅助文件已做凭据净化，测试密码必须由操作者在新建环境中提供。包中没有本机账号、会话、token、私钥、数据库、容器卷、1GiB模型、规则库、SDK或依赖缓存。原始账户helper不在本包中。

实际结果与复现入口分开
本轮测试结果以另附报告和带SHA的收据为准。下面新增的便携脚本是准备好供接收者执行的复现入口，其整套新机器构建/部署尚未实际执行，不能直接继承本机Linux编译或新空卷APP验收的PASS。
流式能力的边界：前缀检查发生在服务端从仓库/LFS内容读取并暂存扫描快照的过程中，可以提前拒绝已经确定有问题的legacy元数据；它没有在首次HF上传的网络PUT流中完成完整ClamAV扫描。跨文件流水线让下一批暂存与上一批完整扫描重叠，任何前缀“未发现问题”都不能建立完整证据或提前允许下载；最终仍需完整文件哈希、完整扫描及generation一致性检查。
最新结果见 reports/MatrixHub-v12.1-测试与设计报告.html（及同名PDF）及 evidence/ 下按项目相对路径组织的真实收据；证据目录没有执行过的计划不能当成PASS。源码身份与本地DCO绑定见VERSION_LOCK.json及local-dco-commit-proof-v122.json。v12历史应用结果与v12.1新人工复核结果分列，不能重复累计。
源内docs/security/REPORT.zh.md等文件保留历史版本说明；本包新版本身份以VERSION_LOCK.json为准，最新测试结果以交付报告为准。不要把历史官方E2E/KIND、v11扫描结果或本轮计划相互当作已经执行。

一、校验源码
在解压目录运行：
  python3 reproduce/verify_source.py
它仅核对清单内1527个源码文件的大小和完整SHA，不执行源码。自行构建产生的bin、ui/dist、node_modules等不属于原始清单，也不应重新塞入提交源码包。
先用发行方附带的ZIP SHA验证压缩包，再运行此校验；包内校验器和清单不能替代可信的外部包摘要。

二、准备构建环境
建议在Debian 12/bookworm的Linux/amd64虚拟机执行。需要官方Go 1.26.8、GCC、Git、Node.js（本轮工具核验为24.19.0）、pnpm 10.17.0、Python 3.11+和Docker Compose。
Go下载页：https://go.dev/dl/ ，对应Linux amd64 SDK SHA在VERSION_LOCK.json。
使用Debian 12是为了让CGO生成的glibc依赖与Dockerfile.runtime的bookworm运行时匹配。不要把Windows exe或在更高glibc系统生成的二进制直接塞进这个运行时镜像。
第一次构建需要访问Go module、npm、Docker基础镜像、官方ClamAV发布资产和PyPI；本包不包含这些大依赖。go.sum、pnpm-lock.yaml及扫描器requirements.lock约束项目依赖；apt软件包与新下载的病毒规则不是逐字节可重复的冻结镜像，因此还须记录实际构建日志、镜像ID、规则SHA和时间。

构建：
  bash reproduce/reproduce-linux.sh build
该脚本核对源码，构建UI与CGO API，再从源内Dockerfile构建matrixhub-security:local和matrixhub-security-scanner:1.4.6。二进制版本明确写入v12.1-candidate和working-tree overlay标识；不把旧base commit写成新实现的提交身份。
源内deploy/docker/matrixhub/Dockerfile是上游普通构建入口。本安全组合使用deploy/security/Dockerfile.runtime及deploy/security/compose.yaml，因为它们包含隔离扫描器、共享快照/Unix socket和安全准入配置。

三、准备完整病毒规则
按source/deploy/security-scanner/README.md中的“Prepare a complete immutable rules snapshot”执行官方freshclam更新步骤。规则下载器可联网，运行中的扫描器不联网。
新目录必须包含main.cvd、daily.cvd和bytecode.cvd，记录三个文件的SHA，并保持目录不可变。测试用小签名文件不能替代完整规则。
  export SCAN_RULES_DIR=/absolute/path/to/new-immutable-rules
测试规则更新会产生新的scanner generation，不能沿用旧批准。不要原地改写已挂载的规则目录。

四、从新数据卷启动API、扫描器和UI
  export MATRIXHUB_REPRO_PROJECT=matrix-v12-review001
  bash reproduce/reproduce-linux.sh up
脚本要求全新的Compose project名称，并拒绝复用该名称下已有容器或卷。默认仅发布127.0.0.1:3002和2223，扫描器只有Unix socket。它不会下载镜像，须先完成build。
  curl --fail http://127.0.0.1:3002/healthz
浏览器打开http://127.0.0.1:3002。空SQLite卷第一次启动会执行source/db/migrations/sql/sqlite/0_init.up.sql，创建引导管理员admin。其公开引导密码为changeme：已离线验证公开迁移中的bcrypt值与README公开默认值相符，没有读取既有账号或尝试远程登录。这里没有独立的首次注册页面；只适用于刚创建的空卷，不能用于猜测既有实例的密码。首次登录后立即在个人设置更换引导密码，再在平台管理中创建普通测试用户。个人登录操作见source/website/docs/operations/login-logout/index.md。
UI中创建一个非代理的私有项目。使用下述smoke时只创建项目，模型名必须尚不存在；smoke通过原生API创建模型，再执行HF上传。手动使用UI时可直接创建模型。上传者须有Editor/Admin角色。在个人设置中生成一次性测试访问令牌；不要把令牌写进本包、报告或命令历史。测试后在UI中撤销。
模型详情页“模型安全”卡会显示状态、固定revision、scanner generation、文件证据、任务和审计；“安全策略”可切换策略。pending/scanning/failed/incomplete都不能下载，成功上传本身不是批准。
新增“人工复核”页签：Editor/Admin可为已终态报告追加“确认风险／认为误报／需要跟进”和1—1000 Unicode字符说明；Viewer可读、不可写，跨项目不可读取。每条意见绑定reportId、revision、scanner generation及服务端actorId，写入后追加审计。认为误报不会改变机器报告、缓存或下载准入，须修正文件或规则后重新完整扫描。SQLite/MySQL均新增第3号迁移；本便携默认环境实际采用SQLite。

停止本次部署（保留数据便于检查）：
  cd source
  docker compose --project-name "$MATRIXHUB_REPRO_PROJECT" -f deploy/security/compose.yaml down
检查后再按自己的数据保留策略清理该专用环境。此入口不删除其他容器或已有测试数据。

五、运行代码级及真实隔离扫描器测试
  bash reproduce/reproduce-linux.sh test-go
执行真实命令：
  CGO_ENABLED=1 go test -json -race -count=1 -p=2 -mod=readonly -timeout=5m ./internal/domain/security
  CGO_ENABLED=1 go test -json -count=1 -p=2 -mod=readonly -timeout=5m -run '^TestSecurity' ./internal/repo
  CGO_ENABLED=1 go test -json -count=1 -p=2 -mod=readonly -timeout=5m ./internal/apiserver/handler/security
  CGO_ENABLED=1 go test -json -count=1 -p=2 -mod=readonly -timeout=5m -run '^TestSecurity' ./internal/apiserver
SQLite依赖CGO，CGO_ENABLED=0造成的stub失败不能当产品已通过。

  bash reproduce/reproduce-linux.sh test-scanner
该入口在3GiB、1CPU、只读根、network none、低权限、完整只读规则和只读/input下运行tests、integration_tests及prefix_tests；任何skip都返回失败。
源码Dockerfile尚未把prefix_tests.py COPY进镜像，脚本显式将锁定扫描器源目录只读挂载到/opt/scanner，三个套件都使用同一版scanner.py。这是源码挂载测试，不伪称仅凭镜像内文件完成测试。

六、一个可搬运的真实HF业务 smoke
在专用Python虚拟环境中安装huggingface_hub==2.1.1。此便携smoke只锁定直接客户端版本；完整递归依赖锁与精确环境见本机验收证据，不能因此声称任意新安装字节完全相同。
可以使用官方Google BERT-Tiny的训练权重：
  https://huggingface.co/google/bert_uncased_L-2_H-128_A-2/resolve/30b0a37ccaaa32f332884b96992754e246e48c5f/model.safetensors
模型卡（Apache-2.0）：
  https://huggingface.co/google/bert_uncased_L-2_H-128_A-2/blob/30b0a37ccaaa32f332884b96992754e246e48c5f/README.md
大小17,739,144字节，SHA256 7fb69ad9f6866d8983183c930e33828f326470bf6ad8bbb2ad4ed957a92e9414。下载到自己选择的数据盘，再核对SHA。本包不携带权重或训练/推理代码。
假设UI中已创建review私有项目，model-v12-001尚不存在：
  python reproduce/hf_smoke.py --execute --base-url http://127.0.0.1:3002 --repo review/model-v12-001 --model-file /your/data/model.safetensors --expected-sha256 7fb69ad9f6866d8983183c930e33828f326470bf6ad8bbb2ad4ed957a92e9414 --output /your/results/smoke-001.json
脚本交互读取token且不落盘；受控自动化也可通过--token-stdin传入单个有界临时token，禁止在命令参数中写token。只访问指定loopback同源，禁用代理和重定向。文件上限64MiB；超过1MiB必须走LFS，若服务端错误指定普通base64模式则直接失败。先用原生POST /api/v1alpha1/models明确新建模型并拒绝复用已有名称；随后用真实HF create_commit上传、model_info(securityStatus=True,files_metadata=True)等待完整PASS，并严格绑定revision、generation、reportId，再流式读取全部下载内容并比对SHA。没有torch.load、pickle.load、模型导入或推理。它不会打印HTTP异常正文，失败结果保留错误类型；需在UI查看对应报告。
这只是一个独立小模型smoke，不是本轮11版本/12报告控制器的替代；也不是恶意软件总体准确率、GB训练模型或完整升级故障测试。

七、GB与上游官方测试的边界
默认Compose限制64MiB/文件，不能直接上传1GiB并期待通过。GB配置需同时启用SCAN_CLAMAV_BACKEND=clamd、SCAN_PROFILE=gb，设置对应容器资源（实测使用6GiB），并增大应用文件/任务/快照额度和timeout/lease；批次仍为32文件/256MiB，大文件走单文件协议。准确上限和限制在source/deploy/security-scanner/README.md。
本轮受控GB应用验收使用1,342,177,280B文件上限、4GiB/task、8GiB暂存预算、20m超时、21m租约、concurrency=1，以及独立空卷。这个配置的控制器使用本机验证缓存和路径，不包含在便携脚本中，也没有承诺换机免配置即可复现整个历史控制器。
上游make test.unit、make test.e2e、make test.e2e.kind源码均保留。E2E需要正在运行且对应版本的服务；KIND还需要kubectl/kind/Helm和专用新集群。上游普通部署没有自动接入本安全组合，不能用默认latest镜像冒充本候选。
历史KIND已有真实终态：两次均实际运行外层make test.e2e.kind，在单节点Kubernetes中用官方Helm chart部署，再调用内层make test.e2e/Ginkgo。它们是securityMode=disabled的业务兼容性通道，不证明v12.1安全组合已在KIND验收；本轮v12.1没有重放KIND。
  - 较早的目录夹具适配版本，source 6e2b4ee5a6525383da784fb42b8f677e3163343f：北京时间2026-10-09 22:14:09至22:19:31，321.625秒，11套/187项全部通过，0失败、0跳过。三层退出码为KIND make=0、内层Ginkgo=0、严格证据汇总runner=0；final passed=true，专用资源清理及源文件冻结校验通过。该次调整了逐用例模型工厂的目录夹具，不能称完全未改官方测试。
  - 后来的v10版本，source 84bb83043dc17b6cb3d1858620ac40c171bd8eff：北京时间2026-10-13 02:23:25至02:28:31，305.691秒，11套/187项身份全部报告，186通过、0失败、1跳过。M00036目录路径断言在官方model_test.go第706/708行跳过。三层退出码为KIND make=0、内层Ginkgo=0、严格证据汇总runner=1；严格all187Passed=false、final passed=false保留，专用资源清理及源文件冻结校验通过。“命令成功”不能改写为“187项全部通过”。
两份final-receipt.json的SHA分别为c5c2f5b1c41a587ce6341d206430837d6f58afe5b6e91308b07d0ca8cdfa2241和fd3e5137ce0e9ade48c63ee29491296bda12af165be064572a75c58509e3ae13。精确命令、版本、日期、清理及公开证据路径见evidence/runtime/streaming-v12-20261013/delivery-prep/v121/historical-kind-facts-v121.json。这两组历史运行不能累计为374项独立安全覆盖。
已净化官方测试要求MATRIXHUB_ADMIN_USERNAME、MATRIXHUB_ADMIN_PASSWORD以及MATRIXHUB_FRESH_TEST_RUN_ID，由操作者为新测试环境提供。不要复用既有服务器账号。完整官方命令参见source/Makefile和source/docs/development.md。
source/scripts/security/e2e.py保留历史安全验收实现，其中unknown仅WARN允许的预期早于v11完整性规则。直接对v12.1运行可能正确地报告差异；不得为使它“全通过”而放宽未知构造器准入。最新完整业务证据以本轮冻结客户端和收据为准。

提交与社区
PR-DRAFT.en.txt只是本地可审阅草稿，未提交。赛题要求公开提案/Issue及维护者有效认可；实际外部认可必须单独获得，不能用本地测试或草稿替代。

九、最终 HTTP 入口修复与复用证据的边界
真实人工复核 API 验收发现：同一 TCP 端口的 cmux.HTTP1Fast 默认只识别一组常用 HTTP 方法，没有 PATCH。此前 PATCH 在抵达 Echo 路由前被关闭连接，客户端观测到连接重置，而不是有状态码的权限/方法拒绝。最终候选在共用 matcher 中显式加入 http.MethodPatch，并增加每次使用新 TCP 连接、禁用 keep-alive 的回归：旧 matcher 拒绝控制组、HTTP 方法分流及真实安全路由六格请求。既有路由仍负责授权和不支持方法的 HTTP 响应；此修复不开放 PATCH 写入或修改复核意见。
最终源码 manifest SHA256：0533edefe39719e0c6418e9a4117574dabe47f7cbbc58e83d12003304f3f86ee。overlay SHA256：722f85c0eaac8f0547f534649bed55c1a98afd260d2badfb655ed5b740d562d5。相比前一候选333c，仅 internal/apiserver/apiserver.go 与 internal/apiserver/security_review_test.go 两文件变化，其余1525文件逐manifest相同。
UI完整392输入和168构建文件逐SHA一致，复用已完成的typecheck/lint/15测试/vite记录；未重新构建UI。16个SQL迁移、人工复核存储和扫描流水线相关组件不变。既有MySQL与性能实验仅归属相同模块字节，不声称在新完整后端上重新运行。新完整后端的编译/真实业务/API/UI结果仍以报告中的独立终态收据为准，准备或部分通过不是最终PASS。
模块等价证据：evidence/runtime/streaming-v12-20261013/compile-prepared-v7/module-equivalence-proof.json。UI输入/产物完整等价证据：evidence/runtime/streaming-v12-20261013/application-prepared-v8/release-ui-manifest-v12.json。本机验收采用新编译Linux二进制、新空卷和冻结16个SQL只读挂载；不等同新生产镜像构建或新机器复现。
