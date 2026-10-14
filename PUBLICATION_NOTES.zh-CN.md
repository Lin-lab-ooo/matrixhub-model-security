# 发布说明与证据来源

发布目标：`Lin-lab-ooo/matrixhub-model-security`。这是独立的 MatrixHub 安全集成与证据仓库；不是上游官方发行，也不表示已获得维护者认可。GitHub 发布完成后再同步到 Gitee，当前未写入任何 Gitee 远程。

## 文件组织

| 路径 | 内容 |
| --- | --- |
| `source/` | 1527 个经过净化和完整 SHA 校验的源码文件，保留上游目录、署名、许可证 |
| `reproduce/` | 源码校验、Linux 构建/隔离部署/测试入口、真实 HF 小模型 smoke |
| `reports/` | 原始中文 HTML / PDF 报告 |
| `evidence/` | 带版本身份的真实测试收据、原交付清单 |
| `media/` | 真实桌面截图与 224.92 秒演示视频 |
| 根目录 Markdown | 本次增加的公开说明、测试摘要、限制和发行说明 |
| `scripts/verify_publication.py` | 验证公开文件集合、SHA、来源一致性；不执行产品或模型 |

原交付 ZIP 的 SHA256：

```text
dc28b6111c0f18312085ad1b685231485eb8e02abf51beb9ee3f9677ed02cdf6
```

ZIP 为 84,803,273 字节，可作为 GitHub Release 附件；不重复加入 Git 历史。视频保留在 `media/`，以免破坏离线报告的相对路径；也可作为 Release 附件提供。全部文件均小于 GitHub 普通 Git 单文件限制，无需为本次源码快照启用 LFS。参见 [GitHub 官方大文件说明](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github)。

## 冻结源码与历史文档

`source/` 和原交付证据的字节不因本次排版、重命名项目或发布而改变。根 `.gitattributes` 禁止 Git 自动换行转换。原先净化的五个上游测试辅助文件使用新测试环境的显式凭据，不复用本机既有账号；变换身份已记录在 `VERSION_LOCK.json`。

冻结目录中的 `source/docs/EVIDENCE_SUPPLEMENT.zh.md`、`source/docs/security/REPORT.zh.md`、`source/deploy/security/README.md` 和 `source/THIRD_PARTY.md` 含历史提交、环境、配额或镜像记录。它们中的“当前”指原文编写时点。**本次版本身份以 `VERSION_LOCK.json` 为准，当前验收以根 `TEST_REPORT.md`、`reports/` 最终报告及其对应收据为准。** 不将旧的 64 MiB 默认配额视为 GB 验收配置。

旧源码内 workload/本机实验脚本可能绑定 Windows、固定项目名称或历史目录；便携入口是根 `reproduce/`。这套新机器入口尚未完成一次空缓存、全新机器的端到端验证，不能把本机受控验收直接转移为便携部署已通过。使用前请读 [完整复现说明](README.zh.txt)。

## 隐私与凭据范围

公开候选来自原先显式允许的源码/证据清单，不包含 live DB、Docker 卷、访问令牌、SSH 私钥、既有账号 helper、病毒规则二进制、GB 样本或 SDK 缓存。人工与模式审查没有发现私钥头和常见提供商令牌形状；这不构成穷尽性的秘密检测保证。

部分历史收据与构建日志保留本机非秘密路径，包括 Windows 用户目录名与项目所在盘符。为维持原始收据的 SHA，未静默改写这些字段；它们是运行出处信息，不是跨机器使用说明。上游固定示例密码/合成测试字符串也有保留，均不应作为真实服务凭据。该发布包不是完全匿名的数据集。

## 验证与 CI 的准确含义

在干净的发布目录中运行：

```bash
python3 scripts/verify_publication.py
python3 reproduce/verify_source.py
```

第一条检查当前公开清单、全部文件字节、原交付映射和额外文件；第二条检查原有 1527 个列出源码。可选 [CI 模板](docs/ci-templates/release-integrity.yml) 只做这些完整性检查，**不是**产品安全套件、官方 E2E、KIND 或部署验收。模板当前位于文档目录，不会执行；此文件编写时没有 GitHub Actions 云端运行结果。

上游工作流完整保留于 `source/.github/`，不会作为本发布仓库根目录的 GitHub Actions 自动运行。首发没有启用任何根工作流，不申请 GitHub OAuth 的 workflow 权限。若以后启用可选模板，须另行明确授权并更新公开清单；模板本身只有手动触发和只读仓库权限。

`PUBLICATION_MANIFEST.json` 为本次公开目录的文件清单；`evidence/original-archive-manifest.json` 为原交付清单。后者保留创建计划时的状态字段，只作为原始清单使用；原 ZIP 的实际创建/验证由原交付收据证明。清单和脚本不能代替可信的外部 ZIP SHA 或已核验的 Git 提交。
