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
