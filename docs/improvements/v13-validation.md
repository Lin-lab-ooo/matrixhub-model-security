# v13 validation checkpoint

Status: development candidate, first checkpoint on 2026-10-22 (Asia/Shanghai).
Baseline commit: `6d936cab06206c877837068a52958ab07588816b` (local v12.2).
This document is updated during the authorized eight-hour engineering run.
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
- Harden approved snapshot Open against writable files, observed metadata or
  identity changes, cancellation and signed-size overflow. Reuse only scratch
  memory, never a verification result; return the same verified open reader.
- Recheck authorization and current approval after the complete snapshot hash.
  Reject changed report/task/generation/policy/artifact identities, close the
  reader on every failure, and retain the original verified descriptor.

## Completed host checks

| Check | Result | Scope |
| --- | --- | --- |
| Current parser/hash/operand/protocol regression checkpoint | 130 methods passed; 0 failures/errors/skips | Windows, import-only OS shim, real Picklescan 1.0.5; excludes Linux-only suites |
| Protocol-boundary reproducer | Three methods: 12 failing subcases before the fix; all three methods passed afterward | Inert PROTO 6/255 declarations; supported 0-5 and headerless input still use actual Picklescan |
| New deterministic adversarial probes | Same 19 inputs / 27,845 bytes; 16 meet original expectations, three FRAME questions unresolved | All ten ZIP/TAR controls preserve expected outcomes; this probe is not reported as an overall PASS |
| Go snapshot checks | 17 top-level tests passed; two symlink subcases skipped due to Windows privilege | Go 1.26.8, CGO disabled; Linux and application tests pending |
| Go security domain after admission revalidation | 51 top-level methods; 125 pass events including subtests; 0 failures/skips | Windows Go 1.26.8, CGO disabled, offline unit tests; the original reproducer failed before the fix |
| Native-result judge contracts | 15 methods passed; no skips | Pure synthetic protocol frames; not product detection samples |
| Positive format compatibility | 66/66 trials, 11 provenance labels but 9 unique SHA-256 values | Two scanner versions, three paired rounds; one trained BERT, random GPT-2/ViT and small Torch 2.8/2.9 save fixtures; static only |
| Current repeated-symbol paired microbenchmark | 7 alternating pairs, median 0.0934963 s to 0.0933581 s | Same 520,002-byte inert input, 20,000 references; 0.15% difference does not establish a stable speedup |
| Earlier operand-fence defense cost | Seven pairs per input; approximately +5% to +16% static parsing time versus the pre-fence v13 source | Historical 82f4177 source before protocol fix; raw allocation defense adds work; no whole-scanner speed claim |
| Official SDK offline contracts | 11 methods passed; zero skips | Real huggingface_hub 2.1.1 / httpx2 2.13.1 with MockTransport, no fixture or network; not actual deployed client acceptance |
| SHA read-loop experiment | 5 rounds, 1 GiB warm synthetic file; read128KiB 0.63445 s versus readinto1MiB 0.60692 s | Standalone Windows SHA loops, not whole-scanner timing |
| Go snapshot allocation benchmark | 8 MiB input, three rounds: 134,650 to 4,023 allocated bytes/op | Complete SHA retained; approximately 1% timing difference does not establish throughput improvement |
| GiB snapshot Open benchmark | Three alternating pairs: 134,608 to 3,376 allocated bytes/op; 651.3287 to 645.6504 ms | Whole 1,073,742,142-byte synthetic snapshot hashed every time, equal warmups, same returned FD checked at both ends; Windows, no AV or HTTP |

The final parser checkpoint binds scanner SHA-256
`d823484c4788a9d6baa24245021ae80043d7d18bf8bdef553c34e6e32a80bfbc`.
The Go snapshot product file is
`0a366a2a5d4a0f49e0d70f29ed9a1fcd55127ba02c25c0abaa209aecbe402d0c`.
The earlier parser attempt accidentally selected four Linux FD worker tests on
Windows; it failed on unavailable O_DIRECTORY and is retained. The corrected
host suite explicitly excludes those tests; they remain required on Linux.
The earlier 14.66% repeated-reference observation belongs to the pre-operand-
fence source and is retained as historical evidence; it is not the final
candidate's performance result.

These are method counts and bounded synthetic experiments, not attack-dataset
accuracy, production false-positive rates, cold-cache latency or end-to-end
speedup. Baseline source and candidate source identities are stored separately.

## Prepared, not yet accepted

- Two pinned public tiny-random test-weight files (GPT-2 and ViT) were downloaded
  and SHA-256 verified. They extend family/structure coverage; they are not
  trained production weights and will not be bundled as original code.
- A non-sparse 1,279 MiB protocol-4 synthetic legacy payload was generated and
  independently read back (complete file: 1,341,129,030 bytes). It has not yet
  passed a complete native scan. The existing 1,280 MiB envelope is unchanged.
- The native protocol harness prepares 25 inert/AV-control cases plus the two
  public weights. It records actual HTTP responses and permits only explicitly
  defined native coverage rejection; engine failures/timeouts cannot pass.
  The added ZIP and double-ZIP EICAR controls require an actual complete native
  AV finding; an incomplete-coverage rejection cannot satisfy either control.
  Two tiny oversized-operand declarations require the precise worker budget
  error; generic failures are not accepted as that defense.
  Two unsupported-protocol declarations require the precise per-file incomplete
  finding over HTTP 200, not a whole-request failure or unrelated AV rejection.
- Four complete source exports were frozen and round-trip verified. The fourth
  includes the domain admission, operand and protocol fixes: 1,541 files, 14 reviewed source differences,
  manifest `47fe0f28f1fb0037dab7881baff5e5dd5ec59d3fad19831bd3997c2e2b7bf946`.
  Further source edits require another export. No new Docker image or complete
  application is claimed.
- Fresh-instance API acceptance and official-rule preparation tools have passed
  32 and 20 offline contract tests respectively and independent review. Docker
  is mocked in those tests. No live fixture, signed-rule download or native
  signature verification is implied. Old daily rules are over seven days old;
  their freshness failure is not disabled.
- The existing eight-case fresh-instance plan uses standard-library HTTP. The
  task's actual `HfApi.model_info(securityStatus=True, files_metadata=True)`
  compatibility requirement needs a separate deployed SDK check; offline SDK
  contracts and hand-inspected JSON are insufficient. A new isolated client
  harness is being prepared without replacing the original tool evidence.

At this checkpoint Docker is unavailable and the user has been asked to start
it. Still required: Linux FD/symlink/resource regressions, real full-database
ClamAV protocol checks, GB boundary scans, paired complete-scanner timing,
new-source Linux compilation, and fresh-instance upload/report/download
acceptance. Official E2E/KIND are separate and have not been run for v13.

Local retained evidence lives under
`runtime/optimization-v13-20261022/`: `host-parser-checks-v6/`, `snapshot-go/`,
`domain-admission-after-v2/`, `compatibility-host/run-004/`, `operand-budget/`,
`protocol-boundary-v13/`, `static-adversarial-probes-v13/after-protocol-fix/`,
`sdk-contract-probe-v13/run-003/`, `snapshot-gb-prep/run-001/`,
`reference-benchmark-v4.json`, `hash-host-benchmark.json`, the ASTRA review
and independent baseline probes. Reports preserve superseded failures rather
than relabelling them as successes.
