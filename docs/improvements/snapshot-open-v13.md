# v13 candidate: sealed snapshot verification and bounded scratch reuse

This change hardens the Go `SecurityArtifacts.Open` path. It does not change
scanner verdicts, supported formats, file-size ceilings, policy thresholds or
the number of complete-file SHA-256 checks required for download admission.

## Problem and implementation

The existing implementation opens an approved snapshot, checks its size,
computes its complete SHA-256, rewinds it and returns that same held file. The
download handler serves that reader rather than reopening a mutable repository
path. The v13 candidate retains that behavior and adds:

- cancellation checks at entry, after hashing and immediately before returning;
- early rejection of `math.MaxInt64` size descriptors, avoiding `size + 1`
  overflow in the bounded reader;
- `os.SameFile` comparison between the final path's `Lstat` result and the held
  file's initial `Stat` result;
- rejection of snapshots that still expose any write permission bits;
- another held-file `Stat` after complete hashing, requiring unchanged file
  identity, size, mode and modification time;
- a `sync.Pool` of fixed 128 KiB scratch buffers used only while hashing.

The pool contains temporary byte storage, **not** file identities, hashes,
approvals or scan results. Each call still reads and hashes the entire file.
The verified held file is rewound and returned directly. All failing paths
close their file before returning an error.

## Security boundary

These checks detect observed mutation during verification and avoid a path
reopen between verification and delivery. They do not freeze an inode against
a privileged or compromised writer. The single trusted MatrixHub writer must
still own the staging root, stop writing after sealing, and give scanners a
read-only mount. Metadata equality is not a cryptographic integrity proof, and
this portable Go comparison does not claim nanosecond ctime protection.

`chmod(0440)` is an ordinary permission setting, not a filesystem immutable bit
or write-once storage. Windows exposes its read-only attribute through different
permission semantics. Both Unix and Windows behavior require actual tests.

## Focused checks

From `source/`, with the repository's pinned Go toolchain and dependencies:

```sh
go test ./internal/repo \
  -run '^TestSecurityArtifact|^TestSecuritySnapshot' -count=1 -v -timeout=90s

go test ./internal/repo -run '^$' \
  -bench '^BenchmarkSecuritySnapshotOpen$' -benchmem -benchtime=1s -count=3
```

The new tests exercise writable snapshots, same-sized tampering after resealing,
empty-file cancellation, descriptor overflow, cancellation before return,
modification-time/mode changes while hashing, concurrent independent readers,
file/parent symbolic links, and holding the original reader after a path is
replaced. A deterministic test context changes metadata at an actual read
boundary; it does not replace the production filesystem, SHA function or Open.

The paired benchmark retains the previous Open implementation in test-only code
and hashes the same real sealed file with each variant. It measures Open and a
one-byte offset check, not HTTP delivery, scanner throughput or cold storage.

## Recorded Windows check

On 2026-10-22, Go 1.26.8, Windows/amd64, `CGO_ENABLED=0`:

- The targeted test command returned exit 0. There were 17 top-level PASS
  records, including the symbolic-link container test whose two subcases were
  **SKIP** because the Windows account cannot create symbolic links. This is not
  an all-platform/no-skip result.
- Path replacement after Open, both metadata-mutation subcases, and eight
  concurrent independent readers actually executed and passed.
- Source SHA-256 before and after the final unit and benchmark runs matched.
- The real product source tested was
  `0a366a2a5d4a0f49e0d70f29ed9a1fcd55127ba02c25c0abaa209aecbe402d0c`.

Each benchmark row below is the median of three measured repetitions against
the warm filesystem, on an AMD Ryzen 9 8945HX. Other machine activity and OS
cache state were not controlled.

| Fixture | Previous ns/op | Hardened ns/op | Previous B/op | Hardened B/op |
| --- | ---: | ---: | ---: | ---: |
| 64 KiB | 326,061 | 318,983 | 134,620 | 3,640 |
| 8 MiB | 5,247,412 | 5,192,160 | 134,650 | 4,023 |

Allocation counts remained 48/op in both variants. The clear result is about
128 KiB less allocated memory per Open (roughly 97% lower allocated bytes in
these rows). The observed median latency differences were about 2.17% and
1.05%; this small local observation is not evidence of a stable latency or
GB-scale throughput improvement.

Raw final evidence is retained under
`runtime/optimization-v13-20261022/snapshot-go/` in the task workspace:
`unit-windows-cgo0-v2.log`, its receipt,
`benchmark-windows-cgo0-v2.log`, its receipt, and
`verified-facts-windows-v2.json`. Preliminary logs were retained separately.

Linux symbolic-link execution, the race detector, current full-application
acceptance and official E2E/KIND are not established by these Windows results.

## Ordinary staging copy: scratch pooling

The ordinary copy tail in `internal/repo/security_stream.go` now borrows the
same fixed 128 KiB scratch buffer through `sync.Pool.Get`, defers exactly one
`Put`, and calls the same `io.CopyBuffer`. The baseline's allocation was
`make([]byte, 128<<10)` for every copy. The measured candidate stream source is
`042476a43ec7bb14ac6b2e67f651ad032e36b2021c8658876766501bbca1aa5b`;
the true frozen baseline is
`16c4e7f1db68396145ab8fbc522e8c8964df0649f1030fe50cf8e5a39a6e8e3a`.
The baseline overlay renames only the function and prefix constant. The common
context reader, bounded writer and pool are five exact AST declaration excerpts
from the unchanged production artifacts source identified above; they are not
hand-written replacement implementations.

The **64 KiB prefix and 128 KiB scratch buffer have separate purposes**. A
nonnil prefix prober and a declared size above 64 KiB still allocate and read
the complete independent prefix before the ordinary copy tail. This change does
not pool or shorten that prefix, alter its routing condition, or turn a prefix
observation into full-file approval. The test's ordinary bytes never route to
the model-format callback. The complete-file hashes, their number of passes,
declared-length/digest verification, snapshot sealing, full native scan,
generation/report completeness and download admission checks remain unchanged.
Only temporary byte storage is reused; no hash, verdict, policy or approval is
cached. Borrowed buffers are returned on the same success/error return paths.

On Windows/amd64 with Go 1.26.8, `CGO_ENABLED=0`, offline module resolution and
`GOMAXPROCS=4`, the actual host run completed **118 ordinary-copy controls**:
84 variant/mode controls, 32 copies across eight concurrent workers, and two
post-GC copies. The controls include size boundaries, short reads/writes,
terminal I/O errors/EOF, overflow/declared-size rejection, cancellation, byte
identity and correctness after GC. This was not a race-detector run.

The microbenchmark used 4 KiB, 128 KiB and 1 MiB deterministic RAM inputs in
nil-prober and non-routing ordinary-prefix modes. Five paired rounds alternated
**BC/CB/BC/CB/BC**. Across the six size/mode groups this produced 60 measured
leaves of 50 copies each and 60 separately retained initial one-copy calibration
leaves. Every complete destination SHA-256 was checked outside the copy timing
and allocation interval. Input digests, pair order, iteration counts, native
benchmem rows and unchanged selected-source identities were independently
recomputed from the saved log/measurements; no benchmark was rerun for that review.

| 1 MiB ordinary copy mode | Baseline B/op | Pooled B/op | Baseline → pooled allocs/op | Median of five paired copy-time reductions |
| --- | ---: | ---: | ---: | ---: |
| Nil prober | 131,152 | 2,712 | 4 → 3 | 31.36% |
| Nonnil, non-routing prefix | 196,688 | 70,880 | 5 → 4 | 27.47% |

The B/op entries are each variant's median; the final column is the median of
the five per-pair percentage reductions, **not** a percentage computed from two
independent time medians. In this run the corresponding allocated-byte reductions
were about 97.93% and 63.96%. The prefix-mode result still includes its separate
64 KiB allocation. Both paths have nonzero allocations. `sync.Pool` may discard
buffers at any GC, including between calibration and measurement; no persistent
warm pool, pointer identity or zero-allocation guarantee is asserted.

These observations measure only an ordinary in-memory copy helper with
preallocated destination storage. They exclude filesystem staging writes,
complete Stage execution, snapshot publication, AV/static parsing, hashing in
the application pipeline, HTTP upload/download, cold storage and GB artifacts.
Timer stopping/restarting, GC, OS scheduling and other host activity affect the
short measurements. The results do not establish complete Stage latency,
complete-scanner acceleration or deployed throughput capacity.

Selected small evidence is retained in
[`evidence/v13/staging-ordinary-pool`](../../evidence/v13/staging-ordinary-pool/):

- [`receipt-summary.json`](../../evidence/v13/staging-ordinary-pool/receipt-summary.json)
  is an explicit privacy-minimized summary, bound to the uncopied raw receipt's
  SHA-256. It omits the raw environment/PATH dump and records that omission.
- [`independent-verified-result.json`](../../evidence/v13/staging-ordinary-pool/independent-verified-result.json)
  contains all six independently recomputed groups and their five raw pairs.
- [`input-manifest.json`](../../evidence/v13/staging-ordinary-pool/input-manifest.json),
  [`measurements.json`](../../evidence/v13/staging-ordinary-pool/measurements.json),
  and [`identity-checks.json`](../../evidence/v13/staging-ordinary-pool/identity-checks.json)
  preserve the explicit input, measurement and selected-source checks.

This source change was included in Prepared5, with 1,541 source files and 15
reviewed source differences: manifest
`afa1244f3414f3d364563d25a1907916916b74d8312a10365ec56e36bdde591e`,
overlay `91f8d358d20968c31966251166e0aca4f02d28ebdd6ecaa08169b2a8faa82e26`.
A source freeze and this host microbenchmark are distinct from Linux compilation,
native-AV/application acceptance and official E2E/KIND execution; none of those
results is inferred by this section.
