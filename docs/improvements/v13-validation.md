# v13 validation checkpoint

Status: local development candidate; terminal native scanner acceptance recorded on 2026-10-22 (Asia/Shanghai).
Baseline commit: `6d936cab06206c877837068a52958ab07588816b` (local v12.2).
This checkpoint is updated during the user-authorized engineering run,
restarted for six hours on 2026-10-22. Local delivery only; no new public release.
Neither the old publication manifest nor v12.1 application results certify v13.

## Changes with direct implementation evidence

- Before constructing nested ZIP objects, validate the real central-directory
  records and remaining global entry budget. Count directory entries.
- Reject directory payloads, links and special entries instead of silently
  skipping them. Preserve valid empty stored/deflated ZIP directories.
- Preflight physical TAR headers, including PAX/GNU metadata, before TarFile
  parses it. Apply finite entry, extension-byte and field budgets; document
  unsupported sparse/layout-changing structures as incomplete coverage.
- Bound Safetensors rank to 64 and tensors to 65,536; catch deep JSON errors
  locally. These are supported-profile limits, not malware classifications.
- Reuse deterministic repeated-symbol classification only within one Pickle
  inspection. Full Picklescan analysis and every opcode check remain.
- Hash full streams through a reusable 1 MiB readinto buffer. Short reads
  continue until actual EOF; invalid/nonblocking counts and I/O errors fail.
  No complete artifact, rule or engine hash traversal was removed.
- Fence generic Pickle operand reads before allocation, including LONG4 and
  bounded protocol-0 lines; retain the complete independent Picklescan pass
  and reject any budget exception it swallowed internally.
- Reject unsupported PROTO declarations in both generic opcode loops, including
  later concatenated streams. Preserve headerless input and declarations 0-5.
- For an unconfirmed Pickle hypothesis only, prove a missing oversized operand
  with actual EOF within the original argument budget and temporary chunks no
  larger than 64 KiB. Short nonempty reads are not EOF; exhausted budget still
  rejects. PROTO and observed executable/reference indicators retain strict
  inspection. Full AV, SHA, Picklescan and error semantics remain unchanged.
  See [candidate-probe-v13.md](candidate-probe-v13.md).
- Harden approved snapshot Open against writable files, observed metadata or
  identity changes, cancellation and signed-size overflow. Reuse only scratch
  memory, never a verification result; return the same verified open reader.
- Recheck authorization and current approval after the complete snapshot hash.
  Reject changed report/task/generation/policy/artifact identities, close the
  reader on every failure, and retain the original verified descriptor.
- Reuse only the ordinary copy tail's 128 KiB scratch buffer. Keep the 64 KiB
  prefix independently allocated, since the prober may retain it; all full-file
  hashing, verification passes and final approval checks remain unchanged.

## Completed component checks

| Check | Result | Scope |
| --- | --- | --- |
| Earlier host parser/hash/operand/protocol checkpoint | 130 methods passed; 0 failures/errors/skips | Windows, import-only OS shim, real Picklescan 1.0.5; excludes Linux-only suites |
| Current selected Linux Go suites from Prepared6 | 144 top-level tests and 250 subtest pass events; 0 failures/skips | Four selected packages: domain with race, repo, security handler, apiserver; actual fresh compile6 execution, not complete upstream make test.unit |
| Earlier Linux-only file/process component checks | 20 methods passed; 0 failures/errors/skips; container peak 61,071,360 bytes | Six snapshot/worker/process-isolation/resource classes; AV mocked in worker tests; no CVD mounted |
| Current isolated Linux scanner unit modules | 180 methods passed; 0 failures/errors/skips; whole-container peak 1,048,588,288 bytes | Current b95 scanner, actual Linux isolation/FD checks and real Picklescan; not application or native-27 acceptance |
| Current native scanner protocol acceptance | 27/27 candidate expectations matched; baseline OBSERVED with 17/27 judgments matching | Actual ClamAV 1.4.6/Picklescan 1.0.5; 22 HTTP 200 and five precise expected HTTP 422 responses; all three EICAR controls complete with critical native findings; no coverage short-circuits or operational failures |
| Current ordinary copy controls | 118 controls passed: 84 variant/mode + 32 concurrent + 2 post-GC | 23 finite ordinary RAM inputs, maximum 1 MiB; not AV or model-format detection samples |
| Current ordinary copy allocation experiment | 1 MiB nil-prober 131,152 to 2,712 B/op; prefix mode 196,688 to 70,880 B/op | Five alternating pairs, 50 copies per leaf; 60 measured leaves plus 60 one-copy calibrations; no full-scanner speed claim |
| Protocol-boundary reproducer | Three methods: 12 failing subcases before the fix; all three methods passed afterward | Inert PROTO 6/255 declarations; supported 0-5 and headerless input still use actual Picklescan |
| New deterministic adversarial probes | Same 19 inputs / 27,845 bytes; 16 meet original expectations, three FRAME questions unresolved | All ten ZIP/TAR controls preserve expected outcomes; this probe is not reported as an overall PASS |
| Go snapshot host checks | 17 top-level tests passed; two symlink subcases skipped due to Windows privilege | Historical Windows Go 1.26.8 / CGO-disabled run; separate current Linux repo results below |
| Go security domain after admission revalidation | 51 top-level methods; 125 pass events including subtests; 0 failures/skips | Windows Go 1.26.8, CGO disabled, offline unit tests; the original reproducer failed before the fix |
| Native-result judge contracts | 15 methods passed; no skips | Pure synthetic protocol frames; not product detection samples |
| Earlier positive format compatibility checkpoint | 66/66 trials, 11 provenance labels but 9 unique SHA-256 values | Two scanner versions, three paired rounds; one trained BERT, random GPT-2/ViT and small Torch 2.8/2.9 save fixtures; static only |
| Earlier repeated-symbol paired microbenchmark | 7 alternating pairs, median 0.0934963 s to 0.0933581 s | Same 520,002-byte inert input, 20,000 references; 0.15% difference does not establish a stable speedup |
| Earlier operand-fence defense cost | Seven pairs per input; approximately +5% to +16% static parsing time versus the pre-fence v13 source | Historical 82f4177 source before protocol fix; raw allocation defense adds work; no whole-scanner speed claim |
| Official SDK offline contracts | 11 methods passed; zero skips | Real huggingface_hub 2.1.1 / httpx2 2.13.1 with MockTransport, no fixture or network; not actual deployed client acceptance |
| SHA read-loop experiment | 5 rounds, 1 GiB warm synthetic file; read128KiB 0.63445 s versus readinto1MiB 0.60692 s | Standalone Windows SHA loops, not whole-scanner timing |
| Go snapshot allocation benchmark | 8 MiB input, three rounds: 134,650 to 4,023 allocated bytes/op | Complete SHA retained; approximately 1% timing difference does not establish throughput improvement |
| GiB snapshot Open benchmark | Three alternating pairs: 134,608 to 3,376 allocated bytes/op; 651.3287 to 645.6504 ms | Whole 1,073,742,142-byte synthetic snapshot hashed every time, equal warmups, same returned FD checked at both ends; Windows, no AV or HTTP |

The earlier host parser/positive-compatibility checkpoint binds scanner SHA-256
`d823484c4788a9d6baa24245021ae80043d7d18bf8bdef553c34e6e32a80bfbc`.
The current 180-method Linux unit and 27-case native results bind scanner
`b95ba560d32523c8e04d01dc2f2b863abfb6e65244d217fa6647e6cb54e4644d`.
The focused candidate-probe repair has 14 passing methods, including an
independent run; its original 13-method/eight-error reproducer and the
intermediate two-failure old-contract result are retained.
The Go snapshot product file is
`0a366a2a5d4a0f49e0d70f29ed9a1fcd55127ba02c25c0abaa209aecbe402d0c`.
The earlier parser attempt accidentally selected four Linux FD worker tests on
Windows; it failed on unavailable O_DIRECTORY and is retained. The corrected
host suite explicitly excludes those tests. The separate current Linux-only
20-method run now executes those integrity classes with the actual Linux FD
interfaces; its worker antivirus calls are mocked, not real AV detection.
The earlier 14.66% repeated-reference observation belongs to the pre-operand-
fence source and is retained as historical evidence; it is not the final
candidate's performance result.

These are method counts and bounded synthetic experiments, not attack-dataset
accuracy, production false-positive rates, cold-cache latency or end-to-end
speedup. Baseline source and candidate source identities are stored separately.

## Acceptance status and remaining work

- Two pinned public tiny-random test-weight files (GPT-2 and ViT) were downloaded
  and SHA-256 verified. They extend family/structure coverage; they are not
  trained production weights and will not be bundled as original code.
- A non-sparse 1,279 MiB protocol-4 synthetic legacy payload was generated and
  independently read back (complete file: 1,341,129,030 bytes). It has not yet
  passed a complete native scan. The existing 1,280 MiB envelope is unchanged.
- The native protocol harness actually ran all 27 cases: 25 inert/AV controls
  plus two public random-weight files. The original d823 run failed overall with 24/27 expectations matched,
  including three EICAR controls that returned `pickle_argument_limit` rather
  than an AV finding. The repaired b95 run passed all 27 unchanged expectations,
  including complete critical ClamAV findings for flat/ZIP/double-ZIP EICAR,
  exact HTTP 422 operand and archive budgets, and exact incomplete-coverage
  findings for unsupported protocols. The baseline is OBSERVED, not accepted.
  Whole native job: 265.878711 seconds, peak 1,149,231,104 bytes across both
  variants/startup, no operational failures or native coverage short-circuits.
  The original failure is preserved; this is finite regression evidence,
  not an accuracy rate, false-positive-rate dataset or GiB throughput result.
- The previous fifth source export is frozen and round-trip verified: 1,541
  files and 15 reviewed source differences, including the ordinary scratch pool.
  Manifest `afa1244f3414f3d364563d25a1907916916b74d8312a10365ec56e36bdde591e`;
  overlay `91f8d358d20968c31966251166e0aca4f02d28ebdd6ecaa08169b2a8faa82e26`.
  This exact export was actually compiled on Linux/amd64, with all 12 selected
  build/test steps passing and selected source/module identities checked before
  and after. The fresh backend ELF is
  `78b0b2845c9b9aab36a64a7a56de7db0d00efad953806ff0d7866573c9b53e28`.
  Three official API E2E binaries were compiled, not executed. No image was
  pulled/built; the fixed compiler image was reused and its owned resources
  were cleaned. This is historical Prepared5 compilation with d823 Python;
  its unchanged Go components remain identified separately.
- The current sixth source export is frozen and round-trip verified: 1,542
  files and 16 reviewed source changes, including the candidate-probe repair.
  Manifest `5b967d7af234ecac747c0b073dbaea71faa3d509e53fd9c4da0a4ce3b86d4db9`;
  overlay `4be6b872ca266946f96cad3042b62c8c3095458e96c756b1891fd29cc187471c`.
  Prepared6 compilation completed PASS: all 12 selected steps exited zero,
  source and module postflight identities matched, no OOM was observed, and
  owned cleanup completed. Backend ELF SHA-256:
  `18f4bcc77d5b2cf893a5ae632ef81bfbb368aa7a5c56b44cacfe66725a2feb00`.
  The inner compile proof is
  `cdf948c6800a6104b612d28e98fd7ff53da1f194de84b534b7ecbffa64a11c33`.
  This build result does not claim an application deployment result.
  Compilation of official E2E binaries does not execute those suites.
- The original fresh-instance and rule tools retain their 32/20 offline
  contract results. The new APP v2 adds the actual official SDK child: 49
  independently checked offline contracts, with eight planned business scenes,
  ten metadata calls and one anonymous check counted separately. None is a
  deployed APP result. The six-hour deadline-only update passed two targeted
  deadline/cleanup methods; the original 49-method receipt is retained.
- The first local rule-preparation attempt failed the FreshClam version
  preflight with `freshclamAttempts=0`, before any updater call. The exact
  uncontacted failure and lock were archived after fixed native version checks;
  the original failure evidence remains. The first actual official updater
  call then completed PASS with a VERIFIED manifest and successful cleanup.
  All three CVD signatures/full SHA values were verified, and daily freshness
  passed the unchanged policy; old rules were unchanged. Manifest SHA:
  `275f5bc2e8ffbe360a260a5749044ddf28ca23414bf95bf9ea459f95a121dc60`.
  Daily version 28160 was built at 2026-10-21T06:25:49 UTC; its SHA is
  `7e0439c6b3b55ca244365e65f36a5b9b44865bf867f53fdf0ab4fcd9614509da`.
  There was one real updater call, not a claim that the zero-call failure
  successfully updated anything. No freshness/signature requirement was weakened.
- The task requires actual
  `HfApi.model_info(securityStatus=True, files_metadata=True)` compatibility.
  The new isolated SDK harness is ready, but offline SDK contracts and JSON
  inspection do not replace its real deployed execution.

Docker was manually started by the user. The actual current Linux scanner
unit and native protocol runs are complete as recorded above. Prepared5's
selected Go build/tests are historical component evidence; the complete
Prepared6 selected build and Go suites have now passed. Still required:
GB boundary scans, paired complete-scanner timing,
and fresh-instance upload/report/download with the official SDK. Official
E2E/KIND are separate and have not been run for v13.
The three unresolved FRAME questions remain limitations; no new FRAME defense
was landed or counted as a completed result.

The default/fresh APP profile is not the GiB profile. APP v2 uses a 32 MiB file
limit and does not establish GiB business-path capacity. Configured limits and
one prepared 1,279 MiB payload are not measured capacity. Arbitrary GiB archives
also remain subject to the separate 128 MiB ordinary expansion budget.

Local retained evidence lives under
`runtime/optimization-v13-20261022/`: `host-parser-checks-v6/`, `snapshot-go/`,
`domain-admission-after-v2/`, `compatibility-host/run-004/`, `operand-budget/`,
`protocol-boundary-v13/`, `static-adversarial-probes-v13/after-protocol-fix/`,
`sdk-contract-probe-v13/run-003/`, `snapshot-gb-prep/run-001/`,
`reference-benchmark-v4.json`, `hash-host-benchmark.json`,
`staging-io-pool-v13/run-001/`, `build-prep/compile-v13-5/`,
`linux-isolation-only-v13/b94adc470e754b11/`,
`unit-6e35b679d4744fa8/`, `native-6cd28546fdb94f1f/`,
`native-9eb326f90ee944ac/`, `candidate-probe-v13/`,
`candidate-probe-native-pass-update/`,
`rules-prep/runs/5b429a2f0d63e8cc/`, the ASTRA review
and independent baseline probes. Reports preserve superseded failures rather
than relabelling them as successes.
