# 实际验证证据与适用范围

## 实际结果

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

## 公开证据

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

