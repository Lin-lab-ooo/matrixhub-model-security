# 提交材料核对单

依据用户给定 DaoCloud 四页赛题，2026-10-09 01:26 更新。此清单区分本地工程交付和外部参赛步骤；勾选必须有实际文件或平台证据。中文技术报告见 [REPORT.zh.md](REPORT.zh.md)。

## 本地交付

- [x] 官方 MatrixHub 基线与上游 SHA，保持 Apache-2.0 / 项目架构。
- [x] 需求、三方向、设计、威胁模型、ADR、格式覆盖与局限文档。
- [x] 双真实引擎、完整官方规则、隔离 compose、固定版本与 hash。
- [x] 直接上传、官方 HF model_info 参数组合、真实下载准入及六状态日志。
- [x] 文件证据、历史、策略、RBAC、审计的中文 UI 与 API。
- [x] 独立scanner分类、资源、timeout、cancel、batch、容量与前后性能证据。
- [x] 4:13.5真实演示、中文SRT、讲解稿、原帧来源、剪辑与解码QA；2fps无音轨已披露。
- [x] 原始失败保存；govuln module finding 与Windows skip明示。
- [x] 第三方出处及二进制redistribution注意事项。
- [x] 新 generation scanner 29UT / 11Unix / 5容量全部通过，无 skip；固定 image/generation 已记录。
- [x] 最终冻结harness、独立v3新镜像job-101正式E2E 20/20（17业务+3token清理），含真实SSH和两条Safetensors全链路。
- [x] v3/job-102真实scanner offline / cancel160秒 / backendSIGKILL137+lease恢复 / rule-generation切换4/4，history完整不变；job-003前置GBK失败仍保留。
- [x] 最终SQLite / MySQL / Linux-race / 官方unit / HF / vet / golangci / mock一致性检查；2 Windows skip与初次mock变化保留。
- [x] v3/job-103完整应用benchmark6/6：upload-to-approval、观察计时边界、cache、force、4并行Range/HEAD/GET、事后单次资源采样；HF .gitattributes实际manifest已披露。
- [ ] v3/job-104 的 16h 长测已中断：195 成功轮，minimumCoverageMet=false，缺完成、实际退出与收尾证据，INCOMPLETE。不得将新实验拼接成连续 16h。
- [x] 新精确受限加载入口high规则、有界memo/stack传播、结构化证据与实际产品UI；DCO代码提交63c0e0e9…。
- [x] 新52/52静态回归（同字节核心继承）/最终11Unix/实际官方make test.unit/UI8测试及build；各自版本和计数口径单列。
- [x] 新capability-97f08f51dfda真实六场景，1/8/63MiB，HF/GET/HEAD/Range、整revision阻断、实际UI与完整退出/清理联合PASS。
- [ ] 官方完整make test.e2e / make test.e2e.kind：尚未执行；共享helper凭据材料读取被自动审批拒绝，准备计划不记通过。
- [ ] 封版报告PDF / HTML视觉复核 / 清洁源码包 / 版本锁 / 交付SHA256SUMS；文档DCO封版待完成。
- [ ] 若交付二进制镜像：对应engine源代码、许可证、完整package inventory及notice一起核对。

## 包的建议结构

`source/` 放源码和license；`report/` 放中文技术报告、设计、证据索引、测试说明；`evidence/` 放无秘密allowlist日志、结果JSON、样本生成清单、版本与hash；`demo/` 放WebM/SRT/视频说明/QA索引；根目录README解释安装、执行、复核和容量边界。原始165帧可以独立大附件保存，视频hash和完整manifest必须可获得。

不得把live DB、旧测试data、临时账号seed凭据、密码/密码hash、token、SSH私钥、浏览器状态、依赖缓存、未许可二进制或vendor下载假装“源码”一起打包。视频SRT与WebM同名，格式限制须向正式上传要求核对；不把WebM标成MP4。

## 外部步骤（需要用户授权和平台确认）

- [ ] 公共Issue / 设计提案 / PR，与维护者对齐并保留真实链接。
- [ ] 维护者或社区有效认可证据；本地代码和AI评审不能代替。
- [ ] 比赛报名，命题赛道与单人学生身份由主办方确认。
- [ ] 组委会邮件 / 上传指引，按正式格式提交代码、文档和视频链接。
- [ ] 可公开访问的视频 / 仓库 / 文档链接及下载权限验证。
- [ ] 参赛者真实姓名、团队与联系方式由本人提供；不编造。

目前只准备本地材料，[公开 Issue / PR 本地草稿](submission-drafts.md) 可审阅，尚未发送任何外部消息。比赛结果、有效认可、奖金与获奖不作保证。截止日期、出席和提交格式以官方后续指引为准。
