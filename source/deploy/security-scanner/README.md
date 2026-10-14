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
container limits. Batch limits stay at 32 files / 256 MiB; large single files
use the single-file endpoint.

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

The application integration remains Apache-2.0. Picklescan is MIT-licensed;
ClamAV is a separate GPLv2 process. Preserve its bundled license notices and
provide corresponding [ClamAV 1.4.6 source](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.4.6)
when redistributing an engine image as required by its license. Third-party
engine and rule authors retain their rights.
