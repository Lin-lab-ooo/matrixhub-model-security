# ADR: immutable bytes and a bounded offline scanner

Status: implemented; execution evidence is recorded separately from design claims.

## Decision

Use a Go artifact adapter and Unix HTTP client in MatrixHub, with a pre-started
Linux container running ClamAV and Picklescan. Do not add a model deserializer,
an uploaded-code execution path, an API-accessible container launcher or a
Docker socket to MatrixHub. The domain service owns admission and policy; the
scanner supplies generation-bound findings and completeness.

The alternative of writing a new Go Pickle threat detector would introduce an
unnecessary detection engine to validate. The alternative of invoking Python
inside the API process would inherit business credentials and network access.
The selected approach uses mature engines behind a small, fixed protocol.

## What evidence approves a file

1. Resolve a branch or tag to one immutable Git commit before enumerating it.
2. Enumerate all supported regular tree entries, including actual LFS content
   descriptors. Symlinks, submodules, malformed pointers and coverage limits
   fail the revision; they are not omitted from a passing manifest.
3. Reserve the declared task bytes against retained bytes plus other active
   reservations. The default staging root has one trusted MatrixHub writer.
4. Stream each source once into a random temporary file while computing SHA256.
   LFS content must equal both pointer size and OID. Even an overlong source is
   stopped before extra bytes are written beyond its reservation.
5. Sync, make the snapshot read-only and publish atomically under a task and
   attempt-specific relative ID. Sync its directory on Linux. No snapshot is
   overwritten, and the scanner mounts the entire staging volume read-only.
6. The scanner opens components with `O_NOFOLLOW`, verifies the complete size
   and SHA256, and scans the same held file descriptor. It does not reopen an
   origin path or accept an arbitrary upload-controlled filesystem path.
7. Commit a complete report only through the domain/store attempt and lease
   fence. Admission rereads current authorization, generation and policy.
8. A download opens the recorded snapshot, checks SHA256 and size on that same
   descriptor, seeks to its start and returns it. Git/LFS origin replacement
   does not replace approved content.

Read-only mode and digest verification defend against accidental modification
and untrusted scanner writes. They do not claim protection against an already
compromised host or trusted writer that can modify a file while a reader uses
it. Those actors are outside this threat boundary.

## Protocol and tenant boundary

The only request fields are `artifactId`, `sha256`, `size` and `type`. IDs match
a generated two-component grammar; no repository path, shell command, model
script, URL or user credential crosses the boundary. The expected generation
is a header. The Go client only dials the configured Unix socket, disables
proxies, rejects redirects, caps response size and validates every result.

The scanner does not decide tenant access. MatrixHub keeps stable project and
model IDs in task/report/cache keys and checks the current model identity when
finishing work. The random task/attempt snapshot identifier is a storage key,
not an authorization token. Only trusted MatrixHub code can reach the socket.

The socket is mode `0660`. API and scanner use UID/GID 65532, snapshots use
directories `0750` and files `0440`, and the API is the only volume writer.
A trusted initialization step assigns an empty volume to this UID before the
services start. Giving scanner users access to the socket and input volume is
equivalent to trusting them with every staged tenant artifact.

## Completeness and format support

All files are passed to ClamAV. The wrapper additionally uses Picklescan for
recognized Pickle streams, including nested ZIP, gzip and tar members.
Extensions are only one input: magic and structural disassembly detect
renamed serialized content. In particular, ordinary Pickle opcodes preceding
a dangerous `GLOBAL` must not hide it in a `.txt` file. No `pickle.load`,
`torch.load`, model import or referenced callable execution is used.

`pickletools.genops` supplies a structural coverage check, not a competing
threat classifier. The wrapper requires STOP and consumes all concatenated
streams and trailing bytes. Picklescan 1.0.5 supplies callable risk rules.
Unknown callable references produce medium findings; dangerous references
produce critical findings. Neither permits a claim that arbitrary model code
is safe to execute.

| Input / condition | Behavior |
| --- | --- |
| Raw Pickle protocols understood by pinned Python/Picklescan | Full structural validation plus static findings |
| ZIP, gzip, tar; nested within budgets | Inspect members without writing archive-controlled paths |
| PyTorch ZIP containing `data.pkl` | Static member analysis; no framework loading |
| Safetensors | UTF-8/unique JSON keys, metadata, known dtype/shape/size and contiguous complete offsets plus ClamAV; no tensor execution |
| Unknown ordinary file | ClamAV and attempted Pickle-context recognition |
| Malformed recognized serialization, trailing bytes, `EXT` registry opcodes | Incomplete, denied |
| NumPy object serialization, dill, HDF5, 7z, RAR, xz, bzip2 in this first version | Unsupported coverage, denied |
| Legacy framework formats with unrecognized trailers | Incomplete, denied; no assertion of full framework compatibility |
| Encrypted, malformed or excessive archives | Incomplete, denied |
| File larger than complete-scanning limit | Rejected before scanning; never sample only a prefix |

The conservative identification can reject ordinary files that resemble a
partial serialization. The report must describe this as unavailable coverage,
not malicious content. Supporting a new format requires explicit tests and a
new generation. The extension remains part of the content cache context so a
`.txt` result cannot suppress extension-dependent analysis after renaming.

Archive magic takes precedence over extensions. A `.safetensors` source then
requires full format validation before the generic Pickle probe: a legitimate
128-byte little-endian header length begins with `80 00`, which also resembles
Pickle's PROTO opcode. This does not exempt the source from ClamAV, and a Pickle
renamed to `.safetensors` fails validation. Tensor offsets must cover the entire
data buffer without holes, overlap or trailing bytes; declared shape and dtype
must exactly match the byte length. Empty/scalar tensors and byte-aligned packed
types are checked without creating tensor objects. Headers are capped at 8 MiB;
unknown dtype names fail closed until explicitly supported in a new generation.

ClamAV limits can otherwise cause content to be skipped. The wrapper checks
file size itself, enables limit/encryption/broken-file alerts, and treats such
alerts, engine warnings, errors, unexpected output or process failure as
incomplete. A successful engine exit alone is not sufficient evidence.

## Isolation and resource decisions

The container has `network_mode: none`, a read-only root, read-only `/input`
and `/rules`, no business credentials, no Docker socket, all capabilities
dropped and `no-new-privileges`. `/tmp` is a bounded tmpfs with `noexec`,
`nosuid` and `nodev`. This is defense in depth around native parsers, not a
claim that a container is an absolute boundary against every kernel flaw.

Each request starts one fixed `python -I` child in a new process group with a
minimal environment. Child limits cover address space, CPU, descriptors,
single-file output and core dumps. Container limits cover aggregate memory,
CPU, processes and temporary storage. A supervisor enforces wall time and
kills the entire group, including ClamAV, on timeout or client disconnect.

The child and supervisor share a UID and container. This is resource and fault
isolation, not a strong tenant boundary after a parser compromise. The scanner's
integrity remains a trust assumption. A stronger per-job container/microVM pool
would need an external trusted orchestrator; giving the API a Docker socket is
not the selected design.

Only one analysis worker runs at a time. The formal deployment uses one
MatrixHub scan worker; a concurrent excess request receives an unavailable
response and cannot become clean. Raising parallelism requires measuring the
full ruleset's peak memory and adjusting aggregate limits. Per-process limits
alone do not bound the sum of several engine processes.

Initial limits are intentionally finite: 64 MiB per source, 128 MiB total
expanded members, 256 archive members, depth 3, expansion ratio 100, 90-second
scanner wall time, 60-second child CPU time, 2 GiB child address space,
3 GiB container memory, one CPU and 32 processes. These limits are part of
the generation. Larger production models remain outside the validated scope.

## Bounded batching after measurement

The original per-file child design measured 109.5724 seconds for eight unique
1,028-byte metadata files with complete official rules and one CPU. Repeated
ClamAV rule loading dominated this workload. Increasing the task deadline alone
would not address that cause.

The selected optimization batches up to 32 cache misses from the same revision,
with at most 256 MiB total input and the existing per-file limit. The domain
stages files and checks scoped caches first. An optional `BatchScanner`
interface is used only when `/v1/bundle` advertises positive batch limits;
legacy scanners continue through the single-file path.

The child verifies and holds every snapshot FD, inspects Pickle content
separately, and invokes ClamAV once with inherited `/proc/self/fd/N` paths.
Actual ClamAV 1.4.6 tests confirmed these aliases are scanned with
`--follow-file-symlinks=2`. Each requested FD must produce an explicit mapped
`OK` or `FOUND`; skipped aliases, missing/duplicate results, limits, warnings
and unexpected output invalidate the whole batch. Empty files only accept an
explicit empty result when their verified size is zero.

Responses preserve exact input order and artifact IDs. Go validates count,
order, generation, engine versions and completeness before returning any
analysis. One unsupported member yields no partial results. All files share
one finite process-group lifetime, so the batch does not create multiple
simultaneously resident ClamAV rule databases.

The same eight-file workload measured 14.3484 seconds with batching, about
7.64 times faster, with similar peak memory. This is a narrow service benchmark,
not an arbitrary-model throughput promise; details and exact evidence are in
[scanner-validation.md](scanner-validation.md). A permanently warm `clamd`
was not selected because it retains parser state across requests and
complicates per-request process killing and generation replacement.

## Engine and rules maintenance

The chosen LTS is ClamAV 1.4.6. The Debian Bookworm candidate inspected during
development was 1.4.3; upstream 1.4.6 includes parser security fixes, so the
release binary and its official SHA256 are pinned instead. Picklescan 1.0.5
is pinned to its wheel hash. Base image digest and the resulting image/package
inventory are recorded for reproducibility.

Rules are prepared by a separate trusted network-enabled FreshClam job, then
mounted as an immutable snapshot. Startup hashes rule contents, wrapper code,
engine versions, Python version and coverage limits into the generation.
Each worker hashes all rules before and after analysis. An in-place rules
change makes the service unavailable until it is restarted with a coherent
new snapshot. Existing reports with the old generation cannot approve content.

There is no automatic deletion of snapshots. Startup counts retained regular
files, including abandoned partial copies. Active reservations and retained
bytes share a global cap; cleanup failures retain their full reservation.
A separate 100,000-entry cap counts files and directories, including zero-byte
snapshots and failed-copy directories. Each creator reserves a file and possible
directory slot before creating either; restart reconstructs the retained count.
Logical byte accounting does not claim to be a physical filesystem block quota.
Quota exhaustion fails closed. Operators stop writers/readers and perform
report-aware retention cleanup. Multi-writer roots and online garbage
collection require a later design and are not supported by this version.

## Sources and licensing

- [ClamAV 1.4.6 release and security fixes](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.4.6).
- [Official release asset hashes](https://github.com/Cisco-Talos/clamav/releases/expanded_assets/clamav-1.4.6).
- [ClamAV scanning documentation](https://docs.clamav.net/manual/Usage/Scanning.html).
- [Picklescan source and license](https://github.com/mmaitre314/picklescan).
- [Python pickletools documentation](https://docs.python.org/3/library/pickletools.html).
- [Safetensors format](https://github.com/safetensors/safetensors#format) and
  [upstream dtype/offset validation](https://github.com/safetensors/safetensors/blob/main/safetensors/src/tensor.rs).

MatrixHub and this integration retain the repository's Apache-2.0 license.
Picklescan is MIT-licensed. ClamAV is a separate GPLv2 engine process; its
license and corresponding source must accompany any redistributed engine
image according to that license. Do not relabel third-party engines or rules
as original Apache-licensed detection code.
