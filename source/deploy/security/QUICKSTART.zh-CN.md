# 安全部署与规则维护

先按 [英文构建步骤](README.md#build-from-source) 在本地构建应用与扫描器镜像。
需要 Python 3.11+、Docker Compose v2 和 Linux 容器引擎。所有目录均应使用本次部署
专属位置；项目名以 `mh-sec-` 开头，避免接管已有账号、容器或数据卷。

在源码根目录执行一次命令，导入已有官方完整规则并启动：

```sh
python scripts/newsetup/setup.py start --initialize-admin \
  --rules-source /srv/downloaded-official-cvd \
  --rules-store /srv/matrixhub/rules \
  --state /srv/matrixhub/deploy-demo \
  --project mh-sec-demo
```

在 Linux/POSIX 文件系统上首次运行时，终端会安全提示输入并确认新管理员密码，
长度为 14–72 个 UTF-8 字节；中文与 emoji 按实际字节计，不会静默截断。无法关闭回显时
直接失败。规则来源必须包含 `main.cvd`、`daily.cvd`、`bytecode.cvd` 三个官方完整文件。
工具不自动下载镜像、不读取旧账号或恢复旧密码；此入口只为本工具新建的自有 SQLite
部署设置首次密码。它先在无网络、无发布端口的容器内完成迁移，核对精确 seed、session、
角色及所有用户内容表为空，再将 bcrypt 密码与归属 marker 放在同一事务中提交，成功后
才发布 API。目标镜像的 libcrypt 须先通过公开已知答案和随机盐自检，无需本机安装 bcrypt。

如只想初始化并暂不启动服务，将 action 换成 `initialize`，不传 `--initialize-admin`。
之后重启使用同一 state/project 的 `start`，**不再传首次初始化标志**。二次初始化、已有
非 seed 账号或未知数据会被拒绝，此命令不用于重置账号。数据库已提交而宿主 checkpoint
未写完时，`start` 可通过只读 marker/账号元数据恢复，不需要重设密码。

仅在明确的非交互秘密提供器通过匿名管道供值时，首次初始化可加 `--password-stdin`。
密码不放参数、环境、shell 历史、配置、日志或报告。初始化后打开默认
`http://127.0.0.1:3002`，使用用户名 `admin` 和刚设置的密码；冲突时指定未用的
`--http-port`、`--ssh-port`。正常停机/重启保留卷，不重新设密。

当前入口已有 45 项离线/纯合同测试通过，实际通用 Compose/libcrypt/普通登录 smoke
由 ROOT 单独验收，当前仍待执行；不能把纯测试写成新机器部署通过。

工具会逐个运行 ClamAV 1.4.6 的 `sigtool` 验证数字签名，再加载完整规则库，核对外层
CVD 头与受签名保护的内部元数据。之后执行全量 SHA-256、完整性、未来时间、回滚和
年龄检查，在新目录封存，再原子替换外置 `active.json` 指针。JSON 清单本身未签名；
官方签名与完整引擎加载提供来源验证，清单用于发现意外损坏。每次启动重新核验。
默认 SLA 为 daily 规则构建后七天，`rules_snapshot.py prepare --max-age-days 1` 可收紧。
扫描器接收由验证后的 daily 时间计算的绝对到期时间，到期后拒绝继续批准。宿主时钟
属于信任边界；修改 mtime 或重启服务不能延长有效期。

本轮实际快照到期时间为 `1793168749`，即 2026-10-28 06:25:49 UTC。若 10 月 29 日
路演，必须保留原 CDN 冷却状态，按正常 update/prepare 重新验签、校验年龄并实测新
generation；不能关闭新鲜度约束或沿用旧的绿色结果。当前首次账号简化入口针对 SQLite
Compose；Helm/MySQL 仍有独立的 Secret 和账号 bootstrap 步骤，不称为全平台一键。

`setup.py check` 只做预检和临时无网络验证，不启动长期服务；`status` 检查运行状态。
预检会写入本部署的公开配置与身份标记。失败时仅停止匹配该身份的项目服务，保留卷
供排查，不接管别的 Compose 项目。临时工具容器有独立随机身份和最终清理逻辑。

联网更新必须先检查已有 CDN 冷却门禁，再把其到期 Unix 时间传入：

```sh
python scripts/newsetup/rules_snapshot.py update \
  --store /srv/matrixhub/rules --network-not-before 已有门禁到期的Unix时间
```

仅在确实没有既有冷却时使用 `0`。这是独立且非 root 的 FreshClam 一次性任务，使用
全新下载目录，保留本工具 SHA 绑定的 `freshclam.dat` 与更长的 CDN 冷却状态，最短
尝试间隔为 24 小时，不自动重试。离线环境可用 `prepare --source ... --store ...`
导入官方 CVD。失败、缺库或过期结果不会切换当前快照。准备新快照后，用相同 state
和 project 再执行 `setup.py start`，重建扫描器；generation 改变后旧批准失效。
禁止在运行扫描器已挂载的规则目录中原位更新。

运行时 API 与 scanner 均为 UID/GID 65532，去掉全部 capability、根文件系统只读。
规则只读；staging 对 API 可写、对 scanner 只读；Unix socket 为 0660。只有无网络的
一次性卷初始化进程使用 UID 0，权限限于 `CHOWN`/`FOWNER`，仅操作本项目三个卷。
不使用 privileged 或全员可写数据目录。默认 scanner 3 GiB、API 4 GiB，Docker 至少
分配 8 GiB，宿主至少留 10 GiB。`--native-threads 2/4` 是同一个扫描器内部有界并行，
CPU 配额同步调整；同一 staging 仍只允许一个 API 实例拥有。

大仓库与单文件容量应分开理解。100 GiB 多分片仓库可使用独立的容量 profile；每个文件
仍受完整 AV 上限约束。详细磁盘、批量与复制预算见 [profile说明](profiles/README.md)。
安全 Helm chart 的挂载与共享 Pod 网络边界见 [Helm说明](helm/README.md)。

历史安全报告现在可按分支/标签、提交标题、时间、短 SHA 选择。提交列表每页 20 条，
查询使用完整不可变 SHA；加载失败、权限不足与空列表有单独状态。切换提交时不会把
旧版本报告展示成新版本；完整 SHA 不匹配的返回内容会隐藏。

## 本轮交付怎么使用

- 查看历史报告：打开模型详情的“模型安全”，在“分支或标签”和“历史提交”中按标题、时间、短 SHA 选择；不必手填完整 SHA。展开“版本与报告标识”可核对完整提交、报告 ID 和扫描器 generation。翻页不改变当前选择，选择另一提交才切换报告；请求加载时旧证据隐藏。
- 并行含义：native 线程数大于 1 时，新的 byte waves 在一个 active batch 内按最多 2 GiB 的有界整文件分组执行，属于扫描器内部并行，不代表多 API 副本或多写入者横向扩容。每个文件仍必须满足完整 AV 上限，压缩展开上限仍为 128 MiB。
- Windows 大数据目录：实测 G 盘 exFAT bind 的 fchmod0440 返回 EPERM，不能用于该安全封存路径。大仓库 profile 会用真实低权探针拒绝不支持 POSIX 语义的目录；请使用独立 Linux/ext4 存储。不要用全员可写权限绕过，也不要擅自移动原 Docker 数据。
- Helm：首轮及 typed v2/v3 失败均保留；独立 [typed v4](../../../evidence/v15/typed-kind-v4-strict-pass-receipt.json) 实际整轮通过461.484秒，覆盖原8API+10SDK、CNI允许/拒绝、同Pod两次ready/零重启、两个SSH角色相同RSA和清理。它是Pod级网络控制与未认证SSH就绪，不是容器间隔离、SSH授权、原官方187或41GB容量证明；MySQL Secret与首次账号bootstrap仍按说明另行准备。

本次个人演示入口与通用部署工具分开：它只为新建的小型演示实例保留专属 ext4 数据卷，
由本人设密，或在本人明确授权后自动生成新密码。自动模式只在 RAM 中处理明文，数据库保存
bcrypt，另外保存绑定本次 run ID 的 Windows CurrentUser DPAPI 密文；默认命令不解密，
不读取或重置旧账号。停止、重启与截止时间不自动删该账号卷，删除需单独明确操作。
它不是通用管理员初始化、生产密钥托管或模型签名服务，GB 大载荷仍走独立 ext4 VM。

当前真实浏览器验收覆盖新个人实例的正常登录、三种 BERT 场景、六个历史版本、加载时隐藏
旧证据及分页选择；真实接口验收覆盖同密码重新登录、仅自有容器重启后的报告/下载保持和
21 个微小提交分页。上述较早浏览器证明对应 e195…，不重标新扫描器。当前同账号已升级37d/GEN2d7f并实际通过六版本复扫与下载门禁；它使用expiry0离线兼容，不继承新鲜规则SLA。独立匹配Chromium已实际通过24.484秒：正常登录/登出、六完整SHA/GEN、旧证据隐藏、20+下一页和Job/profile清理；ROOT查看了全部10张公开截图。该UI证明不作为大模型容量或检测准确率结果。
完整证据范围、实际 receipt 链接与尚未执行的权限/集群项目见
[英文 v15 开发说明](../../docs/model-security-v15.md#current-evidence-boundary)。


部署验收边界（本源码冻结前）：通用fresh v2已实际完成新72UTF8字节Unicode密码初始化和完整规则复验，但后续start失败，normalLogin=false，整轮56.906秒失败并完成自有清理。它不是完整一键部署/正常Go登录或重启通过。v3仅新增固定诊断；后续终态请查看[公开索引](../../../evidence/v15/INDEX.md)及最终技术报告，不重置既有账号绕过问题。
