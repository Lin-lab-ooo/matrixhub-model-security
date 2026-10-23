# v15 public evidence index — prepared subset, not final freeze

This explicit subset contains sanitized public JSON copies only. No account DB,
password, DPAPI ciphertext, owner/private receipt, token, rule CVD, model weights,
VM disk, dependency cache or raw subprocess log is included. The manifest binds
byte-for-byte copies and their original public provenance paths. Those paths are
metadata, not additional package inclusions. A PASS applies only to the exact
source, generation, inputs and assertions of that receipt.

## Existing evidence retained

| Included receipt | Scope |
| --- | --- |
| [Small APP summary](small-app-summary.json) / [public receipt](small-app-receipt.json) | Source16a, GEN8df, GoC2b;8 API+10 SDK checks, anonymous403, cleanup. |
| [Browser](human-browser-receipt.json) / [persistence](human-persistence-receipt.json) | Personal e195 compatibility instance, six versions/pagination and same-password owned-container restart. Not a37d UI or Docker-engine restart result. |
| [Fresh controls](fresh-controls-run.json) | Source16a,14 harmless/inert controls and recovery; no malware-accuracy denominator. |
| [1GiB SDK canary](canary-sdk-receipt.json) / [export](canary-export-receipt.json) | Source16a, four256MiB files, complete uncached APP report/fullGET. |
| [Go source/runtime drift](runtime-go-drift.json) |280 exact file hashes tied to compilation; not final whole-tree freeze. |

## New source16a synthetic capacity evidence

| Included receipt | Outcome and limits |
| --- | --- |
| [100GB host](large100gb-host-receipt.json) / [public application](large100gb-public-evidence.json) | Actual complete PASS for373 synthetic-capacity files and100000000000B. The measured scanner is source16a, not the later37d typed-write fix. |
| [100GB SDK](large100gb-sdk-receipt.json) / [export](large100gb-export-receipt.json) | Complete SDK metadata/report/fullGET SHA, zero cache, source pre/post SHA and cleanup are bound by these exact public receipts. Synthetic capacity is separate from real-model coverage. |

## New source37d bounded typed-write validation

| Included receipt | Outcome and limits |
| --- | --- |
| [Static160](typed-static160-receipt.json) / [inert advisory41](typed-advisory41-receipt.json) | Static component tests and5valid+16structural+20reference controls. No live malware execution or detection-accuracy claim. |
| [Native overall](typed-native-run-receipt.json) / [21 controls](typed-controls-native-receipt.json) | Native full-AV/input-integrity/cleanup assertions:5clean and16incomplete. Application approval remains false. |
| [Native three real artifacts](typed-real3-native-receipt.json) | Three public artifacts totaling1507777036B, including full-input hashes. This is not a41GB/100GB application run. |
| [Fresh-rules default GET](typed-default-bundle-get-receipt.json) / [gb4 GET](typed-gb4-bundle-get-receipt.json) | Actual bundle metadata readiness only; gb4 GEN2d7f. No artifact scan, application or KIND PASS follows from a GET. |

## Actual failures retained

| Included receipt | Outcome and limits |
| --- | --- |
| [Original187 first attempt](official187-first-failure-receipt.json) | Original top-level make E2E/KIND attempt overall FAIL. A missing/unretained fixture cannot establish187 passing cases. |
| [Default CGO1 unit first attempt](official-unit-first-failure-receipt.json) | Original make test.unit actual FAIL. Any DB/migration cause remains a diagnosis until independently checked; no production-defect conclusion is inferred. |
| [Typed strict Chart first attempt](typed-kind-first-failure-receipt.json) | Overall FAIL with guest result not retained. Completed phases do not prove CNI or18 application checks passed. |

No pending acceptance is represented by a fabricated receipt. Typed41GB clean+
negative application and typed human upgrade/browser
remain unbound here until an actual sanitized receipt is
reviewed and copied. Historical results keep their original source/date.

[Complete public-copy hashes and provenance](public-receipts-manifest.json).
These copies are prepared evidence, not a final source freeze or approval to
publish. No native benchmark or application test was rerun to create this index.


## Actual official unit target with an explicit test-only overlay

[Migration compatibility test-overlay unit receipt](official-unit-test-overlay-receipt.json)
records an actual make test.unit PASS with Go1.26.8/default CGO1,49 selected
packages (including no-test packages), source/module/SDK pre/post integrity,
no OOM and successful cleanup. Target time94s; whole run155.1657109s.
Only internal/infra/db/sqlite_test.go test expectations were adapted to current
migrations; production Go/Make/default flags were unchanged. This is not an
unmodified upstream baseline PASS. The original67c unit FAIL above remains.
Test-case and skip counts are unknown (null); race was not run.


## Independent existing-ISO verification, not application acceptance

[Original ISO build failure](real-iso-original-build-failure.json) remains
FAIL_NO_APPROVAL. A separate [full current-content revalidation](real-iso-revalidation-receipt.json)
actually passed in185.94s:277 exact public ISO members,55 real-model files /
41297486024B, full source/ISO/Rock Ridge file SHA checks. It binds ISO5abfaf...
and a new execution locke1829e..., without rebuilding, renaming or rewriting ISO.
Historical pre-rename identity and ISO hash remain unavailable; no rename
continuity, VM execution or APP PASS is claimed by this receipt.

## Other report-linked public receipts included explicitly

| Report | Included copy | Scope / evidence boundary |
| --- | --- | --- |
| E01 | [report-e01-receipt.json](report-e01-receipt.json) | native003取消/崩溃恢复独立scanner; PASS. |
| E02 | [report-e02-receipt.json](report-e02-receipt.json) | small 1/2/4线程独立scanner; PASS. |
| E03 | [report-e03-receipt.json](report-e03-receipt.json) | real1真实模型独立scanner; PASS. |
| E04 | [report-e04-receipt.json](report-e04-receipt.json) | real2独立scanner最终冻结; PENDING; report binding PENDING, native aggregate actualPASS. |
| E07 | [report-e07-receipt.json](report-e07-receipt.json) | Go Linux测试事件; PASS. |
| E08 | [report-e08-receipt.json](report-e08-receipt.json) | 新100GB VM/APP完整链路; FAIL. |
| E09 | [report-e09-receipt.json](report-e09-receipt.json) | 新Helm原生与CNI验收; FAIL. |
| E11 | [report-e11-receipt.json](report-e11-receipt.json) | 公开语料元数据一致性（不含扫描或 APP 验收）; PASS. |
| E12 | [report-e12-receipt.json](report-e12-receipt.json) | 1GiB synthetic native pilot曲线; PASS. |
| E13 | [report-e13-receipt.json](report-e13-receipt.json) | newsetup离线完整规则验签与加载; PASS. |
| E14 | [report-e14-receipt.json](report-e14-receipt.json) | 新16a小APP首轮; FAIL. |
| E15 | [report-e15-receipt.json](report-e15-receipt.json) | freshcontrols首轮; FAIL. |
| E19 | [report-e19-receipt.json](report-e19-receipt.json) | exact1GiB APP canary v2; PASS. |
| E20 | [report-e20-receipt.json](report-e20-receipt.json) | 通用fresh SQLite首次账号入口：源码与45项离线合同；真实Compose/libcrypt/Go登录待验; PREPARED; PREPARED_NOT_EXECUTED. |

E12 is a native-pilot export from an overall failed100GB attempt; it does not upgrade that attempt to an APP PASS. E11 is metadata consistency only. E13 contains a rules metadata manifest, never CVD bytes. E20 is a preparation lock, not an executed first-login result. Report E10 remains an unverified historical reference with no fabricated receipt.


## Typed Chart v2: retained component results, overall FAIL

[Typed Chart v2 public receipt](typed-kind-v2-component-results-receipt.json)
retains the actual source37d/default-fresh GEN6b355 guest results. The original
8API+10SDK application checks passed in27.805456s; CNI positive control, DB/DNS
allowance and unselected-pod TCP denial passed, and pod readiness/restart checks
were retained. Overall status is **FAIL** (481.25s): node-port SSH reached TCP and
banner but returned zero RSA keys / commandExit1. These component PASS facts do
not establish complete KIND acceptance. Prior Chart failures remain included.


## Typed real41GB first attempt stopped before application

[First boot failure](typed-real41gb-boot-first-failure-receipt.json) records overall
FAIL / boot-deadline in241.4433534s. No guestReady or guestResult proof was retained
(the original receipt omits both fields); owned cleanup succeeded. No application
scan or download acceptance ran. This is not a scanner detection or41GB performance
result, and no unique failure cause is inferred. Independent current-ISO content
verification above remains separate; a newer host-only boot-budget preparation
is not an executed APP receipt.


## Original official target v2: failed runner, no187-case results

[Official target v2 failure](official187-v2-failure-receipt.json) records overall
FAIL607.9364003s / official phase289.501163s, cleanup successful. The target entry
was actually attempted, but fixture=null and runner process exit1/noOOM/stdout0 /
stderr974/invalidJSON/ValueError/tracebackSeen=true were retained as fixed typed
diagnostics. No raw stderr or traceback is exported. There are no retained actual
187-case results, so this is not a187-case PASS or a known per-case failure count.
Original assertions were not relaxed to obtain a success.


## Typed real41GB second attempt: reached SDK commit, no clean checkpoint

[Second real-repository failure](typed-real41gb-sdk-commit-failure-receipt.json)
records overall **FAIL** in1230.9282049s. Guest READY, storage and prior phases
were retained, but the upload-scan-download phase stopped after317.8805598s at
SDK commit (fixed Failure / negative-scenario-failed / exit2, no OOM). PAT
revocation, logout and owned cleanup succeeded. application, cleanGate and
negativeScenario are null; nativeRuns is empty. The55-file manifest describes
41,297,486,024B of inputs, not completed upload or scan coverage. No clean
checkpoint, clean revision acceptance, malicious-revision block or41GB performance
success is claimed. The prior first-attempt boot failure is preserved separately.


## Original official target v3:187 reported,184 passed,3 skipped; overall FAIL

[Original official target v3](official187-v3-184pass-3skip-failure-receipt.json)
retains real results for187 declarations:184 passed,3 skipped, zero failed and
zero other states. The skipped cases are M00036 (model_test.go:706, skip708),
SP0020 (sync_policy_manual_push_test.go:31, skip45), and SP0030
(sync_policy_stop_test.go:31, skip83). Overall remains **FAIL** in597.297s
(official-target309.410305s): required real upstream Git traffic and delayed
request observations were both zero (metadataRequests1). The original full187
PASS and Git/delay requirements were not relaxed. Source before/after checks
matched and originalAssertionsChanged=false; the runner emitted valid publicJSON
with exit2, zero stderr, no OOM, and all owned cleanup succeeded. The original
make process exit0 does not override these stricter combined acceptance gates.
This receipt replaces no earlier failed evidence and is not a complete E2E PASS.


## Typed37d human demonstration upgrade: API PASS, browser attempt FAIL

[Actual typed upgrade](human-typed-upgrade-receipt.json) passed in55.1786394s:
six immutable versions were rescanned with zero file-cache reuse under GB4
generation2d7f. Four permitted17,739,144B weights completed full GET+SHA checks;
one inert dangerous-reference revision was blocked and one malformed revision
failed closed, each with an explicit403 code. Logout and session cleanup
succeeded; the existing account was not reset. This is API and file-delivery
acceptance, not browser proof or detection accuracy.

[First typed browser attempt](human-typed-browser-first-failure-receipt.json)
failed in4.75s at browser-launch/target-closed with zero screenshots. Its owned
process tree and temporary profile were cleaned up. No UI walkthrough success is
claimed from this attempt.

[Plan descriptor erratum](human-upgrade-plan-source-errata.json) preserves the
original locked plan and records its non-runtime descriptive scannerSource typo
(65-character wrong value;64-character canonical37d value). The affected field
is not consumed for runtime identity: full source files, contract and actual
bundle generation provide that proof. This public correction is not a new
locked input or an additional execution/PASS receipt.


## Typed KIND v3: application/CNI PASS, NodePort RSA still FAIL

[Typed KIND v3](typed-kind-v3-component-failure-receipt.json) records overall
FAIL435.704s. Original8API+10SDK application checks, CNI controls and ready
zero-restart pods passed. Pod-loopback RSA succeeded; all six NodePort attempts
returned exit1 with zero RSA keys although TCP/banner were available. Owned
cleanup succeeded. This remains incomplete strict KIND acceptance.

## Fresh persistent deployment: two pre-initialization failures

[First](fresh-init-typed-first-failure-receipt.json) and
[second](fresh-init-typed-second-failure-receipt.json) fresh-init attempts failed
in25.907s and25.547s before first initialization or normal login. Old accounts
were not read and owned cleanup succeeded. These attempts do not establish
successful fresh deployment or persistent-password acceptance.

[Resource-boundary unit observation](fresh-init-resource-unit-observation-receipt.json)
records ROOT-observed33 pure tests passing. Its source hashes were recorded
**after** the run; no pre/post mutation proof is asserted. Engine verification
was mocked and no native engine ran. This is separate from the actual failures.

## Pre-auth browser probes: failures before account/product access

[First](browser-launch-preauth-first-failure-receipt.json) and
[second](browser-launch-preauth-second-failure-receipt.json) probes failed in
80.422s and79.812s. Public typed results retain target-closed/browser-launch
and outer Refused; temporary profiles were removed. No credentials, account
database or product was accessed. The collectors did not preserve every mode's
result, so missing mode records do not prove those modes never started. Neither
attempt establishes UI acceptance. Raw stderr was not exported.

## Real-repository fixture diagnosis: pure tests, not integration

[Inline metadata diagnosis](real-inline-metadata-diagnosis-receipt.json) records
12 pure checks reproducing bounded-read, metadata-body-size and upload-mode
incompatibilities against pinned public SDK methods. The proposed policy is
NOT_INTEGRATED/NOT_APP, and a unique cause of run192a's failure is not proven.
The real41GB application/negative-revision checks remain incomplete; these
pure diagnostics add no model-safety accuracy or full-model throughput result.


## Typed KIND v4: strict end-to-end acceptance PASS

[Typed KIND v4 strict acceptance](typed-kind-v4-strict-pass-receipt.json)
passed in461.484s under scanner37d/default-fresh generation6b355. All8API
scenarios and10 official SDK checks passed, with CNI positive control, DB/DNS
allowance and denial of unselected-pod TCP access. The same pod was ready at
both observations with zero container restarts. CNI evidence is pod-level;
it does not claim isolation between containers sharing a pod.

Both SSH readiness roles passed with the same normalized RSA public-key digest
`f1e751545aa0204d2701b3b1bd6b2190813d96ed42b26ffab69fe2d3eae614f4`.
The NodePort hostname attempt failed in0.007141s with zero RSA keys; the second
attempt to the independently verified owned IPv4`172.18.0.2` passed in0.012691s
with one RSA key and exit0, within the unchanged shared30s budget. This is an
actual transport-path comparison, not proof that NSS is the unique root cause.
It checks SSH readiness/host-key consistency, not SSH account authentication.
All owned cleanup succeeded and both private root/data disks were removed.

Earlier strict KIND failures remain preserved. This PASS covers this fresh
security-enforced Helm/KIND fixture; it does not convert the separate original
187-case protocol baseline or real41GB scenario into PASS.


## Typed37d Chromium UI: normal login/history/pagination/logout PASS

[Actual fresh Chromium UI acceptance](human-typed-chromium-ui-pass-receipt.json)
passed in24.484s with normal product login/logout, all six immutable report
revisions under GB4generation2d7f, history-combobox selection, page-two browsing
after20 options, and hiding completed old evidence while a selection is pending.
Its process tree/profile were cleaned up; no old browser session was used and
no account was modified. Earlier Edge/browser-launch failures remain preserved.

[ROOT visual review](human-typed-chromium-root-visual-qa.json) separately records
that ROOT opened all10 public screenshots and found readable pass/block/fail
state, revision, generation and report information. This is visual review,
not automatic secret-free certification; horizontally offscreen table columns
and rows are not claimed to be visible in each screenshot. This index includes
the public JSON receipts, not an implicit recursive copy of image/profile data.

## Fresh persistent deployment v2: real initialization PASS, start/login incomplete

[Fresh-init v2 run2097](fresh-init-typed-v2-initialized-start-failure-receipt.json)
remains overallFAIL56.906s. First initialization with a new72-byteUTF8 Unicode
password and rules-snapshot verification truly succeeded; service start failed
before normal login. Cleanup succeeded. Second-init refusal/restart/login are
not proved by this failed run. It must not be presented as complete first
deployment or persistent-password acceptance. A diagnostic-only follow-up
preparation does not change this result.

## Historical16a real2 native receipt: exact source attribution

[Actual real2 native receipt](source16a-real2-native-receipt.json) is now bound
explicitly: scanner16a,3 real trained files totaling1,507,777,036B,2 native
threads, elapsed138.5779977s/native136.0197063s, no OOM and cleanup successful.
It is native-only under the older scanner, not37d APP or KIND acceptance;
rule freshness was not claimed. Aggregate job status is not used in place of
this exact per-job source receipt.


## Original official target v4: route alias prepared, STOP still skipped

[Actual original official target v4](official187-v4-184pass-3skip-failure-receipt.json)
remains overall**FAIL**614.75s (official-target292.528911s).187 declarations
produced184 passed,3 skipped and zero failed/other states. Skips remain M00036
(model_test.go706→708), SP0020(manual_push31→45), and SP0030(stop31→83);
STOP spent60.497259s without satisfying its RUNNING precondition. The upstream
retained metadata1/Git0/delay0/disconnect0. The exact transport-alias repair
therefore did not establish actual STOP or delayed-Git coverage, and no unique
runtime failure cause is inferred from these bounded counters.

The original make/Ginkgo process exited0 with its skips, but the combined
strict all187-pass and positive-Git/exact-delay acceptance gates remain FAIL.
The runner emitted validJSON/exit2, zero stderr and no OOM. Original assertions
were unchanged, full source pre/post checks matched, and owned processes plus
private root/data disks were cleaned up. Prior attempts are retained. This is
the separate security-disabled original protocol baseline, not a reversal of
the typed security-enforced KIND v4 PASS above.


## Fresh persistent deployment v3: fixed start-refusal diagnostic retained

[Actual fresh-init v3 diagnostic](fresh-init-typed-v3-diagnostic-failure-receipt.json)
remains overallFAIL60.0990235s. Initialization with a new72-byteUTF8 Unicode
password and rules verification passed. Start exited1 with the exact public
CLI code`administrator-proof-required-run-initialize-once`; normal login was
not reached. Before cleanup, exact owned-label proofs enclosed a public-state
projection containing only the init-volumes container(created,Exit0,noOOM); no
API/scanner container was present. Cleanup succeeded. This identifies the
refused administrator-proof gate, not its underlying DB/state cause. No raw
stderr, old deployment state, account database, owner file or credential was
read for diagnosis. No further retry or full fresh-deployment PASS is claimed.
