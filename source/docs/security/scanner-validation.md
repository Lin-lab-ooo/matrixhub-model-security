# Scanner validation record

Measured on 2026-10-08, Asia/Shanghai. These are executed scanner checks;
application/HF E2E results are recorded separately.

## Environment and provenance

Docker Desktop engine 29.4.3 used Linux kernel
`6.6.114.1-microsoft-standard-WSL2`; Docker reported 32 logical CPUs and
16,655,593,472 bytes host memory. Each scanner container was constrained to
**one CPU, 3 GiB memory without swap, 32 PIDs, no network, UID/GID 65532,
read-only root and rules, all capabilities dropped, no-new-privileges, and a
256 MiB noexec/nosuid/nodev tmpfs**. Read-only `/input`, absence of business
credentials/Docker socket and failure to reach an external IP were tested.

| Component | Pinned provenance |
| --- | --- |
| Official Python 3.13-slim-bookworm index | `sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641` |
| Linux/amd64 manifest | `sha256:f040863673aea2570c3ff6a5c3fb4c673a016cbc5375005ad145915922b6b78a` |
| Original image config | `sha256:4143a73d5a9804c1bb2f93cc823a7c173dbc62964d4a5ccabcb1167229b0e2b9` |
| Official ClamAV 1.4.6 x86_64 .deb, 94663320 bytes | `d3ee9e401974855a1edc1761b1425417d126de618d5f0c91cd51209f69f6fcc2` |
| Picklescan 1.0.5 wheel | `2abb3d4959a7ee9ccb1e1296db7c56f624bf6d345b93a0a9cf4185bc650dc2fd` |
| Current validated image ID | `sha256:a4736049103ff53efff2374fcee5d40e2685f3590b8f7b9d33903308f62ce8d2` |
| Current wrapper SHA256 | `33e70b09d40293075f8e6a6ce3f0103cb1d52ea699ae1d8681b061ad60b8110e` |
| Earlier batch benchmark image ID | `sha256:ceac687740477ac5e23fb2b896ea0a9cdabacc4dbd4316d5ecaea12ff718616f` |

Direct daemon pulls were unavailable. The provided official-registry downloader
verified compressed layer hashes and uncompressed rootfs diffIDs, then used
`docker load`. Docker's locally repacked Python image ID was
`sha256:cc97cfed363946e85913ef9373e454d200c1c5249ef3b7291b0711248b83903a`.
A Debian 1.4.3 prototype was replaced after checking upstream security fixes;
all classification/performance results below use **ClamAV 1.4.6**.

FreshClam downloaded and tested the complete official snapshot. No miniature
test-only database was used for these classifications or timings.

| Database | Version / signatures | Bytes | SHA256 |
| --- | --- | ---: | --- |
| bytecode.cvd | 339 / 80 | 281702 | `6d4aa01f219e988060fc419f495d07f27e0cdf1a2cccc065971da922c76f7ffb` |
| daily.cvd | 28146 / 355728 | 23439346 | `4cc99bd2fbce18b7ba5f1dd65d01f8062ba762db5189a1175dd147b4bd5cdf45` |
| main.cvd | 63 / 3287027 | 89072577 | `0b2182d229f46981ec8f535382222f7c9dfdd656b250ad47988b910a8d302365` |

Legacy generation:
`63e30cb8d7fe056b13450efdbb4cf1d1899e2c2048818aa9be2e2194e6cd09af`.
Earlier batch benchmark generation:
`1a956066f220c924195e951f6a41c30531850676289449534d1e1fcd02084b57`.
Current validated generation:
`9acc748673c456930b9e9ab0fee574671b5d32a632cfbbb6e7b30c03e107e330`.

The final scanner build started at 11:58:28 on 2026-10-08, Asia/Shanghai.
The harness first checked the local Python image ID and every complete CVD
hash against the provenance above, then built with
`--pull=false --build-arg BASE_IMAGE=python:3.13-slim-bookworm`. The local-tag
override refers to that previously verified official download. No daemon
configuration or global proxy setting was changed by this validation.

## Executed checks

| Layer | Result | Coverage |
| --- | --- | --- |
| Go adapters | `go test ./internal/repo -run '^TestSecurity' -count=1`: pass, 4.968 s on Windows | Real Git/LFS staging, source replacement, size/OID/digest mismatch, tamper, quota/restart/concurrent reservations, generation/engine/completeness, fixed errors, batch order/count/partial rejection and legacy limits |
| Hardened-container unit checks | 29 pass, 24.928 s, no skips | Static Pickle/ZIP, six added Safetensors groups, malformed/trailing streams, unsupported formats, archive limits, integrity, actual isolation, real safe/EICAR, strict batch output mapping and child limits |
| Real Unix integration | 11 groups pass, 102.148 s, no skips | Safe/warn/block, EICAR, unsupported/ratio/tamper codes, wrong generation, wall-time kill, cancellation, busy rejection, rules checks, mixed batches including empty files, whole-batch failure and Safetensors dispatch |
| Child resource limits | 2 passing tests included in the 29 above | 256 MiB allocation rejected under 64 MiB address-space limit; 2 MiB write rejected under 1 MiB file limit; infinite CPU loop killed by 1-second CPU limit |
| Retained entry quota regression | Artifact tests pass, 4.913 s; `-race` pass, 11.758 s on Windows | Eight concurrent zero-byte creators admit only one file/directory pair at a two-entry limit; restart counts empty files/directories/partials; failed-copy directories remain charged |

The integration harness deliberately uses private writable `/tmp` snapshots
to inject faults. Production `/input` read-only isolation is checked separately.

| Static fixture; never deserialized | Observed outcome |
| --- | --- |
| Six-byte empty-dictionary Pickle | Complete, no findings |
| Renamed .txt Pickle with ordinary opcodes before os.system reference | Complete, Picklescan critical; callable never invoked |
| Protocol-2 matrixhub_e2e_fixture.UnknownCallable reference | Complete, Picklescan medium |
| Standard 68-byte EICAR antivirus test string | Complete, ClamAV critical |
| Empty ordinary file in batch | Complete, no findings |
| NumPy unsupported context | Incomplete, fixed unsupported code |
| Pickle with trailing junk | Incomplete, fixed serialization code |
| High-ratio ZIP | Incomplete, fixed archive-ratio code |
| Same-length snapshot replacement | Incomplete, fixed digest code |
| Legal Safetensors with a 128-byte JSON header, 137 bytes total | Complete, no findings; actual Unix HTTP 200 |
| Dangerous Pickle renamed to `.safetensors` | Incomplete, `invalid_safetensors_header`; actual Unix HTTP 422 |
| Valid Safetensors batched with that renamed Pickle | Entire batch incomplete, HTTP 422, no partial results |

The Safetensors probe initially reproduced a real dispatch error: its header
length began with `80 00` and was treated as a Pickle protocol prefix. The fix
keeps archive magic first, then fully validates `.safetensors` before generic
Pickle probing. Added checks reject duplicate keys, invalid metadata, unsupported
dtypes, bad shapes, mismatched byte counts, gaps, overlaps and trailing data.
Unit regressions also verify a renamed ZIP still reaches Picklescan and that
valid scalar, empty and byte-aligned packed tensors are accepted. No tensor
objects or referenced Pickle callables are created. The current image and
generation above include this fix; earlier benchmark evidence remains labeled.

An initial warning fixture named `unknown_model.Factory` produced critical.
Diagnosis found Picklescan 1.0.5 intentionally marks module/name strings
containing lowercase `unknown` as dangerous to protect unresolved references.
ClamAV reported that fixture clean. The test was corrected to the protocol-2
fixture above; **engine rules were not weakened or filtered**. The failed run
is retained alongside the successful rerun.

## Before/after performance

Both runs use eight distinct 1,028-byte benign metadata files (8,224 bytes),
the same complete rules and container limits. Every file misses the domain
cache; the harness calls the scanner directly after creating snapshots.
Workers rehash rule/input evidence. Host filesystem caches may be warm.
This measures small-file scanner overhead, excluding upload, Git, database
persistence and API queue time.

| Mode | Eight-file wall time | Peak child RSS | Container peak memory |
| --- | ---: | ---: | ---: |
| One ClamAV process per file | 109.5724 s | 985344 KiB | 1065512960 bytes |
| One bounded eight-file batch | 14.3484 s | 985344 KiB | 1057845248 bytes |

The measured speedup is **7.64×**, with **86.9% less wall time**. This amortizes
rule loading; it is not an analysis-cache hit or relaxed coverage. A five-file
mixed batch took 13.847 s and preserved safe, warning, critical and EICAR results.

This earlier eight-file comparison does not establish throughput for maximum
archives, concurrent workers or multi-GB production models. The separate final
capacity run below exercises larger inert sources and 32-entry batches. Cache
benefits and application throughput need their own measurements.

## Final capacity boundaries

All five cases passed on the current image and generation, using the full CVD
snapshot, one CPU, 3 GiB memory, the same child limits and no analysis cache.
The harness supplied inert ASCII sources on a read-only host input mount;
inputs were outside the bounded temporary filesystem, as in production.

| Case | Total input bytes | HTTP result | Wall time |
| --- | ---: | --- | ---: |
| One 63 MiB source | 66,060,288 | 200, complete and no findings | 18.0123 s |
| 32 distinct 1 KiB sources | 32,768 | 200, every result complete and correctly bound | 16.0031 s |
| 33 sources | 66,093,056 | 400, `invalid_request` | 0.0061 s |
| Four 64 MiB sources, exactly 256 MiB | 268,435,456 | 200, every result complete and correctly bound | 23.3237 s |
| 256 MiB plus one byte | 268,435,457 | 400, `invalid_request` | 0.0060 s |

Peak memory for the whole capacity container was **1,118,191,616 bytes**;
maximum child RSS was **1,050,692 KiB**. The Unix integration container peak
was **1,072,472,064 bytes**. These are whole-run cgroup peaks, not individual
case peaks or application API latency. Other project validation could run on
the host concurrently; every scanner container retained its one-CPU limit.

## Reproduce and raw evidence

Commands and exact isolation flags are in
[the scanner README](../../deploy/security-scanner/README.md). Run `tests.py`,
`integration_tests.py`, `capacity_tests.py --run`, then `benchmark.py` in
sequential/batch modes when comparing performance.
Development raw logs are under `上海开源赛2026/runtime/security-evidence/`:

- `scanner-integration.log`: initial warning-fixture mismatch.
- `scanner-integration-fixed-fixture.log`: corrected eight-group legacy run.
- `scanner-batch-unit.log`: 21 container checks.
- `scanner-batch-integration.log`: 10 real Unix groups.
- `scanner-baseline8.log` and `scanner-batch8.log`: before/after workloads.
- `scanner-resource-limits.log`: actual CPU/address-space/file-limit failures.
- `safetensors-dispatch-probe.log`: original valid-header dispatch failure.
- `scanner-final-20261008-115828-build.log`: verified-base final image build.
- `scanner-final-20261008-115828-unit.log`: final 29 checks, including child limits.
- `scanner-final-20261008-115828-integration.log`: final 11 real Unix groups.
- `scanner-final-20261008-115828-capacity.log`: all five final capacity boundaries.
- `scanner-final-20261008-115828-evidence.json`: current image, wrapper and rule hashes.
- `scanner-final-20261008-115828-summary.json`: bundle, executed counts/timings,
  capacity results and SHA256 of the source files and raw logs.
- `scanner-capacity.log` and `scanner-capacity-corrected-harness.log`: retained
  earlier capacity harness failure and corrected run on the earlier generation.
- `scanner-parser-windows-01-failure.log` and `scanner-parser-windows-02.log`:
  provisional Windows harness platform error and five parser-only checks;
  these are not counted as Linux engine/container verification.

Adding test/document files may change image IDs. Wrapper, rules, engine or
limit changes also alter the generation and invalidate approvals. These checks
do not imply public maintainer approval, upstream merge or full application E2E.
