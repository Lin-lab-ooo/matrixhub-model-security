# Isolated MatrixHub artifact scanner

This service runs ClamAV 1.4.6 LTS and Picklescan 1.0.5. It never deserializes a
model. MatrixHub sends verified snapshot descriptors over a Unix socket; the
scanner returns file-bound findings and completeness under a fixed generation.
See [the ADR](../../docs/security/adr-scanner.md) for trust boundaries and format
coverage, and [the application deployment](../security/compose.yaml) for the
API, volume initialization and scanner together.

## Build

Linux/amd64 is the tested target. Docker Desktop uses its Linux containers.
The base image is pinned in `Dockerfile`; the official ClamAV `.deb` and
Picklescan wheel are pinned by SHA256. No host Python packages are installed.

```sh
docker build -t matrixhub-security-scanner:1.4.6 deploy/security-scanner
```

An optional verified local cache avoids downloading the engine during a build:

```sh
python deploy/security-scanner/fetch_engine.py \
  deploy/security-scanner/vendor/clamav-1.4.6.linux.x86_64.deb
```

The vendor file is ignored by Git. The Docker build verifies it again and
does not keep the download or development static archive in the final image.
Ordinary builds use the pinned base digest. When a daemon cannot reach Docker
Hub, `fetch_official_image.py` can download the official Python image through
an explicitly provided existing proxy, verify manifest/config/layer hashes
and rootfs diffIDs, and produce a `docker load` archive. A local-tag build
override is only appropriate after that verification; record the loaded image
ID and image-lock file in build evidence. Do not substitute an unverified tag.

Build-time proxy arguments are optional and belong only to the build process.
The deployed scanner has no proxy variables or network interface other than
loopback and its Unix socket. No Docker daemon settings need to be changed.

## Prepare a complete immutable rules snapshot

Use a separate trusted updater with network access, never the running scanner.
`freshclam.conf` points at the official database service. A Linux example is:

```sh
mkdir -p rules-2026-10-08
docker run --rm --user 0:0 \
  --mount type=bind,src="$PWD/rules-2026-10-08",dst=/rules \
  --mount type=bind,src="$PWD/deploy/security-scanner/freshclam.conf",dst=/config/freshclam.conf,readonly \
  --entrypoint /usr/local/bin/freshclam matrixhub-security-scanner:1.4.6 \
  --config-file=/config/freshclam.conf --stdout
chmod 0444 rules-2026-10-08/*.cvd
```

If an approved local proxy is needed, add `HTTPProxyServer` and `HTTPProxyPort`
to a temporary updater-only copy of the config. Do not put credentials in this
repository. FreshClam verifies its downloaded database before publishing it.
Keep the resulting `main.cvd`, `daily.cvd`, `bytecode.cvd` and their hashes in
the release evidence. An empty rules directory fails startup; a tiny test-only
signature file is not a substitute for the complete production ruleset.

Do not update a directory mounted by a running scanner. Prepare a new versioned
directory, stop the old scanner, mount the new directory read-only and restart.
The changed generation invalidates prior approvals until a rescan completes.
In-place accidental changes also make `/v1/bundle` return 503.

## Run

The complete `deploy/security/compose.yaml` initializes shared volumes for
UID/GID 65532. Configure `SCAN_RULES_DIR` for that composition. For a standalone
scanner, set `STAGING_DIR` and `RULES_DIR` and run this directory's compose file:

```sh
export STAGING_DIR=/absolute/path/to/matrixhub-staging
export RULES_DIR=/absolute/path/to/rules-2026-10-08
docker compose -f deploy/security-scanner/compose.yaml up -d
```

The API mounts staging read/write and the socket volume read-only, and uses
`/run/matrix-security/scanner.sock`. The scanner mounts staging at `/input`
read-only and rules at `/rules` read-only. Both services use UID/GID 65532.
One API process owns each staging root. Keep the directory inaccessible to
untrusted local users. Published directories are `0750`, files `0440`, and
the socket is `0660`.

The scanner has no general TCP endpoint or native-Windows production mode.
The Linux container uses network `none`, a read-only root, all capabilities
dropped, `no-new-privileges`, one CPU, 3 GiB memory without swap, 32 processes,
bounded descriptors and a 256 MiB `noexec,nosuid,nodev` tmpfs. Each fixed Python
child additionally gets a CPU/address-space/output/descriptor limit and a
90-second wall-clock deadline. Cancellation kills the whole child process
group. The supervisor permits one analysis request at a time; configure one
API scanning worker for this deployment.

## Protocol and batch behavior

`GET /v1/bundle` advertises the exact generation, engine versions, file limit,
and optional batch file/byte limits. `POST /v1/analyze` remains supported.
`POST /v1/analyze-batch` accepts `{"artifacts":[...]}` with at most 32 unique
snapshot IDs and 256 MiB total declared bytes. Each artifact is at most 64 MiB.
Both calls require the `X-Expected-Generation` header.

The batch response is `{"results":[{"artifactId":"...","analysis":{...}}]}`
in input order. Each file is SHA256-verified and held open. A single ClamAV
process scans `/proc/self/fd/N` aliases with inherited descriptors, so its
rules load once. Every descriptor must have an explicit mapped `OK` or
`FOUND` result; missing, skipped, duplicated or unknown output invalidates
the whole batch. Pickle inspection still runs separately for each file.

An allowlisted static format/coverage failure is isolated to its file. Its
analysis has `complete:false` and one fixed `coverage.<code>` finding; ClamAV
findings and already observed static references remain available. Other files
and later batches continue. The repository report remains `fail` and incomplete,
so all downloads are denied even in audit mode and the report is not cached.
An HTTP 200 scanner response can therefore contain incomplete analyses; it means
the bounded protocol exchange succeeded, not that the model was approved.

Snapshot integrity, rule changes, resource budgets, malformed protocol results,
worker failure and ClamAV coverage failures still invalidate the whole batch.
Every returned identity, generation, engine and coverage code is validated before
any batch member is added to a report. No parser exception text or payload bytes
are returned. Reports retain the complete batch wall time on each member's
analysis; those shared durations must not be summed as serial CPU time. Old
scanners advertise no batch limits and the API continues to use the single-file
protocol, with the same file-level completeness contract.

An accepted scan attempt also writes a `scan-completed` audit event in the same
database transaction as the fenced task transition, report and cache. The
`completion` payload binds the task, attempt, report, generation and file counts.
Audit insertion failure rolls the transaction back; duplicate, cancelled and
expired claims create no completion event. This event records task completion,
including an incomplete/failed report, and does not imply download approval.

The only error details that cross the boundary are fixed allowlisted codes,
such as `unsupported_container_or_serialization`, `archive_ratio_limit`,
`scan_timeout`, `snapshot_digest`, `rules_changed` and `scanner_busy`. Arbitrary
parser exceptions, stderr, payload bytes and unexpected JSON fields are not
relayed. Unsupported coverage always fails closed, including in audit mode.

## Reproduce checks

Run Go adapter tests from the repository root:

```sh
go test ./internal/repo -run '^TestSecurity' -count=1
```

Run container checks with the same isolation profile as production. For
example, after setting `RULES_DIR`:

```sh
docker run --rm --network none --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges --cpus 1 \
  --memory 3g --memory-swap 3g --pids-limit 32 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777 \
  --mount type=volume,src=matrix-scanner-test-input,dst=/input,readonly \
  --mount type=bind,src="$RULES_DIR",dst=/rules,readonly \
  -e VERIFY_CONTAINER_ISOLATION=1 -e TEST_RULES_DIR=/rules \
  --entrypoint python matrixhub-security-scanner:1.4.6 -I /opt/scanner/tests.py
```

Use the same flags with `/opt/scanner/integration_tests.py` for actual Unix
requests, classification, hash/generation mismatch, cancellation, wall time,
busy behavior, batch mapping and incomplete-batch rejection. That harness
deliberately uses private `/tmp` snapshots to inject integrity faults; the
separate isolation test checks the real read-only `/input` mount.

Use `/opt/scanner/benchmark.py` with `BENCH_MODE=sequential` and `BENCH_MODE=batch`
to compare the same eight unique 1,028-byte benign files. Each run reports wall
time, peak child RSS and cgroup peak memory. Classification fixtures contain
only inert bytes: safe Pickle opcodes, callable references without invocation,
ordinary metadata and the standard harmless EICAR antivirus test string.
They are generated inside Linux containers and never loaded as models.

The capacity harness creates only inert ASCII data, requiring about 320 MiB
of host space. Prepare a new empty directory, then use the same production
limits and complete rules snapshot. Its inputs stay on the read-only input
mount, outside the 256 MiB temporary filesystem:

```sh
python deploy/security-scanner/capacity_tests.py --prepare "$PWD/capacity-input"
docker run --rm --network none --read-only --user 65532:65532 \
  --cap-drop ALL --security-opt no-new-privileges --cpus 1 \
  --memory 3g --memory-swap 3g --pids-limit 32 \
  --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m,mode=1777 \
  --mount type=bind,src="$PWD/capacity-input",dst=/input,readonly \
  --mount type=bind,src="$RULES_DIR",dst=/rules,readonly \
  --entrypoint python matrixhub-security-scanner:1.4.6 \
  -I /opt/scanner/capacity_tests.py --run
```

It checks one 63 MiB source, 32 distinct 1 KiB sources, exactly 256 MiB in
four sources, and rejection of 33 sources or 256 MiB plus one byte. Timings
include real engines and verified snapshots; the printed memory peak covers
the entire harness container, not an individual case.

## Nested deserialization reference evidence

The exact symbol `torch.storage._load_from_bytes` has a restricted nested-loading
capability. Its reference is reported as high severity by the fixed rule
`pickle.nested-deserialization-reference`, with a trusted known-symbol ID.
This is a capability restriction: a reference does not prove invocation or
malicious execution, and legitimate legacy PyTorch Storage artifacts can be
rejected. Other suspicious unknown symbols retain their medium-severity finding,
but now also make the analysis incomplete. Raising the blocking threshold to
high does not approve a constructor whose semantics were not established.
The pinned Picklescan rules can classify some names more severely; a severity
label and completeness are separate decisions.

A bounded static symbol tracker reads `pickletools` opcodes without invoking an
Unpickler, model function or imported payload module. It propagates literal
strings through stack copies and memo reads/writes; computed values remain
opaque. Unresolved symbols and analysis disagreement fail closed. Concatenated
streams outside the bounded legacy profile below must agree under both
fresh-memo and persistent-memo interpretations; ambiguous cross-stream
references remain unsupported. Existing opcode, argument, archive and resource
limits remain.

The optional structured evidence includes an observation of reference, source,
zero-based stream index, byte offset in the currently inspected artifact/member,
and outer-to-inner archive indices with SHA-256 of member names. It contains no
raw archive names, payload bytes, callable arguments or outer artifact paths.
Exact positions are recorded only when statically established. Old findings
without evidence remain readable; this new rule requires its evidence object.
Changing the scanner source changes its advertised generation and prevents old
analyses from being reused as new-rule coverage. The product evidence panel
shows the same typed fields and the compatibility limit.

## Container-write target type proof

The version 15 typed-write inspector independently tracks the target of Pickle
`SETITEM` and `SETITEMS`. Only `DICT`, `EMPTY_DICT`, or the exact
`collections.OrderedDict()` symbol with an empty argument tuple establishes a
map. Memo aliases preserve that identity. Unknown reducer, persistent-storage,
or constructor results cannot acquire map status through `BUILD`. A known
non-map target is an invalid serialization; an unknown target is unsupported.
Both cases remain incomplete, including when the byte stream contains no
dangerous global reference. Existing dangerous-reference evidence is retained
before this structural check. No constructor, reducer or deserializer runs.

The symbol and write-type abstract domains each retain at most
`max_pickle_opcodes` stack-plus-memo entries, including their fresh/retained
cross-stream interpretations. Thus those entries total at most twice that
limit; auxiliary MARK indices are separately bounded by their corresponding
stack lengths. This is a count bound, not a byte-memory claim. Existing operand,
opcode, address-space, CPU, wall-clock, archive and full-file hashing/AV limits
remain enforced. Keeping the budgets independent preserves established opcode
limit behavior instead of silently halving the original symbol budget.

The inert regressions cover invalid list, integer, tuple and storage write
targets, legitimate dict/empty OrderedDict cases and memo/stack behavior. They
do not reproduce a published CVE or prove arbitrary Pickle loadability, such as
key hashability or every object method. Runtime evidence must name the exact
source and generation; prior results for another source do not establish this
version's coverage. `typed_write_tests.py` runs the bounded observer checks with
the Python standard library; the full static/native suites remain separate.

## Bounded legacy PyTorch compatibility

Version 11 recognizes the ordinary CPU typed-tensor / tensor-state-dict profile
of the legacy `torch.save(..., _use_new_zipfile_serialization=False)` format,
using Pickle protocols 2 or 4. It checks five independently memoized metadata
streams: magic, protocol version, system information, the object graph and
storage keys. Each following storage record must have the exact 8-byte
little-endian element count and `count * dtype_width` raw bytes. Storage keys,
references, full file length and EOF must agree. Raw weights are data, not
Pickle opcodes; ClamAV and the full-file SHA256 checks still cover those bytes.

The parser constructs only bounded abstract values. It never calls a reducer,
imports a payload module or loads a tensor. It validates the argument types and
arity of the supported `_rebuild_tensor_v2` form, nonnegative shape/stride/offset,
storage access bounds, gradient-compatible dtype, empty hooks and restricted
metadata/state. Shared storage, noncontiguous tensors, zero strides and empty
tensors are supported within those checks. Custom classes, GPU locations,
untyped storage and other unproved constructors remain incomplete and denied.
This is a finite compatibility contract, not a general PyTorch loader emulator.

The checked small-file fixtures were produced by PyTorch 2.8.0+cpu and
2.9.1+cpu, each with protocols 2 and 4. A version label alone does not make
arbitrary files from that version supported. The default integration suite
embeds the exact four public fixtures and verifies their SHA256 values.
Numeric NPY/NPZ and Safetensors have structural validation; NumPy object arrays
remain unsupported. Static completeness does not establish runtime model
behavior, model quality, training provenance or absence of every future exploit.

## Version 12.2: remove redundant legacy storage I/O

The version-12.2 worker avoids an extra read and SHA256 pass over numeric
storage payloads in a supported, top-level legacy PyTorch artifact. It still
parses all five Pickle metadata segments, runs the same threat analysis and
constructor checks, reads every storage-length header, and verifies that all
ranges partition the exact file length through EOF. Only the already-proven
numeric ranges are skipped by the static layout traversal.

This optimization follows `open_verified` on the held regular-file descriptor.
The complete pre-scan file SHA256, complete ClamAV scan, complete post-scan file
SHA256, rule checks, generation binding and resource limits are unchanged.
Nested legacy artifacts inside ZIP, TAR or Gzip keep the existing per-storage
digest pass. It changes wrapper I/O, not the ClamAV detection engine, signature
set or supported model-format contract.

`verify_legacy_torch(..., hash_storage_payloads=True)` and
`StaticInspector(..., hash_storage_payloads=True)` retain their default behavior
and full per-storage digest proof. The worker supplies the internal strict-bool
opt-in; HTTP clients cannot select it. In layout-only proofs, each
`payloadSHA256` is `null` and `storageDigestMode` is `"layout-only"`. These proofs
describe structural coverage, not an independent antivirus or admission verdict.
The scanner API response schema is unchanged. The changed source/version enters
the scanner generation, so results bound to the previous generation cannot be
reused as current coverage without a rescan.

Run the focused regression suite from this directory inside the pinned Linux
scanner environment:

```sh
python -m unittest -v tests prefix_tests legacy_io_tests
```

The new unit suite includes mocked native AV boundaries for deterministic
integrity fault injection; it does not substitute for real-engine protocol
checks. Parser-stage benchmarks and full scanner timings must be reported
separately. Historical version-11/12.1 results below are not acceptance evidence
for this revision. See the [v12.2 design and measurement plan](../../../docs/improvements/legacy-storage-io-v12.2.md)
for compatibility, reproducible commands and the current evidence status.
The image also includes `legacy_io_native.py` for real-engine correctness and
performance modes. It requires a read-only `/baseline/scanner.py` and complete
`/rules`; performance mode additionally requires separately prepared read-only
`/input/manifest.json` and its fixtures. It does not prepare large inputs or
test MatrixHub upload/download admission. See the design note before running it.

## Opt-in native engine and capacity profiles

The default Compose deployment stays on `SCAN_CLAMAV_BACKEND=clamscan` and
`SCAN_PROFILE=default`: 64 MiB per file, 128 MiB native scan budget, 90 seconds
wall time and 60 seconds worker CPU. Tests cover this actual default separately
from the optional warm daemon.

`SCAN_CLAMAV_BACKEND=clamd` explicitly enables a supervised, isolated native
daemon. `SCAN_PROFILE=gb` allows at most 1280 MiB per file, 1536 MiB native scan
bytes, 300 seconds wall time and 240 seconds worker CPU. It retains 2 GiB worker
address space and permits 4 GiB daemon address space; the GB test uses a
6 GiB container. The default 3 GiB Compose allocation is not a promise that this
larger profile will fit. Profile selection must be accompanied by appropriate
container limits. Default batch limits stay at 32 files / 256 MiB. The GB
profile can explicitly set `SCAN_MAX_BATCH_BYTES` up to 5120 MiB; descriptors
and held FDs are bounded independently, so this does not read the whole batch
into memory. The application must also opt into a matching bounded batch size.
An otherwise permitted file larger than its configured batch budget uses the
single-file endpoint.

`SCAN_PROFILE=gb-archive` additionally requires the daemon and
`SCAN_NATIVE_TEMP=/native-tmp`, a private bounded native temporary filesystem,
and permits a 3072 MiB native scan budget. Static expansion limits remain
separate. Environment overrides can lower the supported limits but cannot
raise their fixed ceilings. Resource exhaustion, skipped antivirus coverage
and timeouts remain incomplete; no profile converts them to a clean result.

For the version-11 iteration, 59 unit methods and 13 integration methods passed
under the actual default profile, with no skips. The separate synthetic legacy
FloatStorage file contains 1 GiB of raw data, 354 bytes of metadata and an
8-byte storage-length header (362 bytes of total overhead). It
passed complete hashing, real antivirus and structural scanning under `gb`
in 150.405 seconds of reported scan time (213.530 seconds for the whole fixture
run); whole-container memory peak was 2,144,198,656 bytes. This is one synthetic
capacity observation, not a trained model, a latency guarantee, or an application
upload/download test of a GB file. Current deployment/source and evidence hashes
must be recorded when reproducing any result.

## Bounded download preflight and staging pipeline

Version 12 adds an optional `maxPrefixBytes=65536` capability and the Unix-socket
`POST /v1/probe-legacy-prefix` endpoint. The application copies and hashes one
64 KiB prefix while staging a large file. For a protocol-2/4 Pickle routing hint,
it applies backpressure and asks the isolated parser to examine the bounded
prefix before copying the remainder. A complete, already-invalid legacy header
can stop the transfer early. Short or inconclusive prefixes return `pending`.
Neither `pending` nor a successful HTTP response certifies a file as safe.

The request binds the prefix SHA256, length, source length and expected scanner
generation. The response must match that binding and use the exact supported
schema. The prefix worker has independent 2-second CPU, 5-second wall, 512 MiB
address-space and 2 MiB temporary-file ceilings. It shares the scanner admission
semaphore; no antivirus verdict or cacheable full analysis is created by a probe.

The Go adapter shares one cancellable permit between probes and full scans.
Full scans have priority; a probe skips its optional optimization if the slot is
busy. A strict `503 {"error":"scanner_busy"}` may be retried within a bounded
window and the original request deadline, using the same generation and inputs.
Other errors are not retried as if they were busy. Older scanners that do not
advertise the capability retain the complete-file scanning path.

Upgrade the application adapter before switching to the version-12 scanner.
The new adapter accepts the older bundle without this capability. An older
adapter with strict JSON decoding may reject the new bundle field and leave
scanning unavailable; that mixed deployment is not a supported upgrade state.
Readiness and integration clients must validate the explicit new capability
instead of silently accepting arbitrary unknown response fields.

Staging can overlap a sealed batch's scan with copying the next bounded batch.
The scanner still has one active batch, with at most one producer-owned pending
batch and one already-staged file that triggers a flush. Existing whole-task
storage reservations remain in force. Cancellation joins the scanner worker
before releasing reservations. Partial results never publish an approved
repository revision; the final generation and coverage checks remain mandatory.

This provides early negative screening during download and a pipeline across
files. It does not claim that antivirus has scanned every byte of a file before
download finishes. Full antivirus, structural coverage, pre/post file hashes and
the immutable revision gate remain required before download admission. Small
repositories that fit in one batch do not gain cross-batch overlap.

Run `python -m unittest -v tests integration_tests prefix_tests` inside the
documented scanner environment. Linux is required for actual isolated-child,
Unix-socket, timeout and cancellation checks; skipped platform checks are not a
complete acceptance result. Run the application security tests with CGO enabled
because its repository tests use SQLite, and use Go's race detector for
`./internal/domain/security` when changing the pipeline.

## Limits and maintenance

The first version intentionally rejects unsupported serializations and archive
limits. It does not promise detection of every novel payload. A conservative
Pickle-context probe can also reject ordinary files resembling a malformed
serialization. Native parser correctness and the scanner service itself are
trusted; same-UID child processes are resource/fault isolation, not strong
tenant isolation after a scanner compromise. Stronger one-job container or
microVM pools require an external trusted orchestrator, not an API Docker socket.

Snapshots are retained for immutable report and download evidence. Retained
bytes and concurrent reservations share a hard global quota. Startup counts
abandoned partial copies. A separate default limit of 100,000 filesystem entries
counts files and directories, including empty files; concurrent creators reserve
entries before writing. This prevents zero-byte artifacts bypassing the byte
counter. Byte accounting is logical content size, not a filesystem block quota;
operators must provision space for bounded metadata and the database as well.
No automatic GC deletes an in-use snapshot. Stop
writers/readers and perform report-aware retention cleanup when required.

## Bounded parallel AV and rule expiration (version 15)

`SCAN_NATIVE_THREADS=1` preserves serial native scanning. Values `2` and `4`
require the `clamd` backend and are rejected for `gb-archive`, whose shared
scratch budget has not been validated for parallel extraction. Each admitted
batch uses at most that many FILDES connections, with one independently held FD
per artifact. `MaxThreads` and `MaxQueue=2*MaxThreads` are fixed in the native
configuration, and the selected thread and batch limits enter the generation.
For parallel scans, original-order greedy waves contain at most the configured
thread count and at most 2 GiB total verified held-FD bytes. A wave joins fully
before the next begins. The fixed byte budget and policy identifier enter the
generation. The request's total CPU and wall budgets span every wave without
resetting; this pressure limit cannot guarantee that the daemon avoids OOM.
The supervisor still admits one request at a time. Changing application task
concurrency does not create additional scanner request slots.

Every descriptor passes full SHA256 and identity checks before AV. Static
inspection starts only after all AV threads have joined, and every artifact
then passes another full SHA256 and identity check. A native failure shuts down
sibling sockets, joins all threads, and invalidates the whole batch; the
supervisor still enforces the aggregate native/worker CPU limit and kills the
owned worker process group on cancellation or timeout. The static parser remains
serial. Parallel scans retain the existing 4 GiB daemon address-space ceiling
under `gb`; memory exhaustion is incomplete, and suitable container memory and
actual measurements are required before choosing four threads.
The separate diagnostic phase receipt records each actual wave's selected file
count, held-FD byte total and completion. A failed wave remains a whole-batch
failure; its selected width does not prove that every socket began scanning.

Trusted provisioning can set `SCAN_RULES_EXPIRES_AT` to an absolute UTC Unix
epoch derived from verified, signed rule metadata plus its freshness policy.
The scanner rejects bundle requests and analysis at or after that deadline,
including a scan that crosses the deadline before publishing its result.
The deadline enters the generation. A value of `0`, the compatibility default,
disables freshness enforcement and makes no freshness claim. Startup time and
filesystem modification time do not establish when rules were built. The host
clock and provisioning tool are trusted; this control does not prevent an
administrator from setting the clock backward. Renew rules by provisioning a
new immutable snapshot and restarting the scanner, producing a new generation.

## Large models and reproducible performance measurements

ClamAV 1.4.6 does not support arbitrary large single files. Its
[`CL_ENGINE_MAX_FILESIZE` implementation](https://github.com/Cisco-Talos/clamav/blob/clamav-1.4.6/libclamav/others.c#L574-L588)
clamps the configured size to `INT_MAX-2`, or 2,147,483,645 bytes on the supported
32-bit-int build. MatrixHub's stricter 1280 MiB per-file ceiling remains in
place. `MaxScanSize` is a separate recursive scan budget; raising it does not
remove the file-size ceiling. FILDES and INSTREAM do not make an oversized file
supported. Cisco's
[large archive wrapper](https://github.com/Cisco-Talos/clamav-large-archive-scanner)
unpacks supported containers; it explicitly explains that cutting arbitrary
large files into chunks is not an effective complete AV scan. This project
does not use independent chunk verdicts to approve an oversized artifact.

A 100 GB repository whose every shard is supported and completely scanned can
use bounded batches and an atomic whole-revision gate. This differs from a
100 GB single file, which remains unsupported. A real trained model and an
inert file of the same size also establish different evidence. Record them as
separate datasets, including pinned upstream revision/SHA and license for real
weights. No benchmark here deserializes weights or executes model code.

`scale_fixtures.py` creates actual, nonsparse synthetic safetensors and small
inert budget/corruption controls. It requires a new destination, a total write
budget, and enough free space for the writes plus a configurable reserve
(70 GiB by default). It retains a partial owned fixture on error for explicit
cleanup. A 100 GB synthetic plan writes 100 GB of capacity data, not trained
parameters. An explicitly requested oversized single-file control is labeled
unsupported. Account for both the source and retained application snapshot
when budgeting an application test; neither may be silently dropped between
batches.

The historical default `--payload-pattern zero` writes zero tensor payloads.
Use `--payload-pattern shake256-counter` for the formal high-entropy synthetic
capacity run. Each 1 MiB block is
`shake_256(b"matrixhub-synthetic-capacity-public-seed-v1\x00" + struct.pack("<QQ", shard_index, block_index)).digest(1 << 20)`;
shard indices start at one and block indices at zero. The actual seed has one
NUL byte at the end. The final block is truncated to the remaining payload.
The manifest records pattern, public seed hex, seed version and block size;
the benchmark records pattern and seed version. This is reproducible synthetic
data, and neither pattern represents trained-weight throughput. Generation
time, scanner request time and final full-manifest verification are separate.

For example, prepare a small dataset on the host using an existing parent:

```bash
python scale_fixtures.py --prepare /owned/new-inputs --sizes-mib 1,8,32,63 \
  --total-write-budget-bytes 120000000 --reserve-bytes 75161927680
```

Run the benchmark in the hardened Linux scanner environment with inputs mounted
read-only. The following records complete production-protocol outcomes against
an already running fresh scanner; its PID is used only for accounting:

```bash
python scale_benchmark.py --input /input --socket /run/matrix-security/scanner.sock \
  --scanner-pid 1 --category synthetic-capacity --batch-files 1,2,4,8,32 \
  --repetitions 3 --configuration-label gb-threads2 > /evidence/protocol.jsonl
```

Restart the fresh scanner with `SCAN_NATIVE_THREADS=1`, `2`, and `4` and record
its actual ready configuration/generation for each run. Keep inputs, rules,
container resource limits and cache state consistent. The configuration label
is a requested label, not an independent attestation of native thread count.
Do not run a new daemon or phase diagnostic concurrently with an application
acceptance run. To isolate file/size effects, select separate datasets or runs
for each size and batch count, and distinguish warm page-cache observations
from actual block-device reads.

The separate `--phases` mode starts its own native engine, instruments the
same trusted worker, and uses the existing supervisor's CPU/wall/output/result
checks. It records full pre-hash/open, AV, static, full post-hash, and rule hash
time plus worker accounting. Its child returns the unchanged strict analysis
schema; measurements travel over a separate inherited descriptor. These are
diagnostics, and they do not publish application approvals. Run one profile at
a time and capture the full JSONL, including failures:

```bash
python scale_benchmark.py --input /input --rules /rules --phases \
  --category synthetic-capacity --batch-files 1,2,4 > /evidence/phases.jsonl
```

JSONL includes bytes/files, batch latency and throughput, strict result-schema
validation, complete/blocked/incomplete outcomes, sampled process-tree RSS,
whole-cgroup CPU/I/O deltas and lifetime cgroup memory peak where available.
The cgroup counters include the harness and any other processes in that cgroup;
live process-tree CPU is cumulative and can lose reaped children. RSS sampling
can miss short peaks, and a lifetime cgroup peak is not a per-request peak.

`scale_curves.py RECEIPT.jsonl ... --output /owned/new-curves` consumes the
public JSONL produced by `native_driver.py` and writes CSV/JSON measured points.
`--plot` also writes a time/size/resource PNG using preinstalled matplotlib;
the script installs nothing and never starts a scanner. Protocol and diagnostic
phase runs stay separate. Startup time is separate from request throughput.
Expected422 defensive controls and failures remain visible and cannot enter
the complete-scan frontier. An exploratory observed frontier compares recorded
throughput, aggregate CPU per byte and sampled RSS only under matching input,
source, rules, backend, mode, remaining limits and mean file size. It does not
establish a causal optimum; mean bytes/file does not prove uniform file sizes.
No curve is fabricated when measurements or cleanup verification are missing.
`expectedMatches` compares controlled fixtures only; file counts and business
assertions are not malware accuracy or recall. Report false blocks only with a
stated clean-control denominator, and report timeout/OOM/coverage failures
separately from detections. Plot successful throughput/latency against file
size, batch bytes, native threads and measured RSS, and keep failed points
visible instead of selecting only the fastest successful point.

The application integration remains Apache-2.0. Picklescan is MIT-licensed;
ClamAV is a separate GPLv2 process. Preserve its bundled license notices and
provide corresponding [ClamAV 1.4.6 source](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.4.6)
when redistributing an engine image as required by its license. Third-party
engine and rule authors retain their rights.
