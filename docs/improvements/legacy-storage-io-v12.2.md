# v12.2: bounded legacy storage I/O reduction

Status: scanner development candidate with completed, source-bound local checks
and measurements. It is not a sealed full-product release. Historical v12.1
application/UI evidence, `VERSION_LOCK.json` and `PUBLICATION_MANIFEST.json` remain tied to
the frozen publication and are not tests or a lock of this candidate.

## Problem and scope

A supported legacy PyTorch tensor file contains five bounded Pickle metadata
segments, followed by length-prefixed numeric storage payloads. The previous
static verifier read and hashed each payload to populate an internal
`storageRanges[].payloadSHA256` proof. The worker did not publish or consume those
per-storage digests when making its scanner response. Meanwhile, the complete
artifact already passed a SHA256 check before analysis, a full ClamAV scan, and
a second complete SHA256 check after analysis.

For a large numeric storage, the additional static pass therefore repeated I/O
and hashing. Version 12.2 removes that pass only in the worker's protected,
top-level legacy path. It does not optimize ClamAV's matching algorithm, replace
its signatures, add a new malicious-payload classifier, or claim that arbitrary
PyTorch objects are supported.

Implementation: [scanner.py](../../source/deploy/security-scanner/scanner.py).
Operational context: [scanner README](../../source/deploy/security-scanner/README.md).

## Processing and security argument

The worker retains this sequence:

1. Open the artifact through the existing directory-FD and `O_NOFOLLOW` path.
   Require a regular file, the expected size and complete SHA256, and retain
   that same open file descriptor.
2. Run the configured ClamAV backend over the complete artifact. All existing
   coverage, output, timeout, daemon and rule-validation requirements remain.
3. Run static inspection. For a top-level supported legacy file, validate the
   five metadata segments, opcode and symbol coverage, constructor arguments,
   storage references and dtype widths. Read each 8-byte element-count header.
   Check the calculated payload length against the remaining file size, then
   seek over only that numeric range. Verify each following header and exact EOF.
4. Recompute the complete artifact SHA256 and verify the held FD's identity,
   size and timestamps. A changed payload, including a same-length change,
   invalidates the attempt; a valid layout alone cannot publish a result.
5. Complete the existing post-analysis rules check and bound response handling.
   MatrixHub's revision, completeness, policy and download gates remain in place.

The optimization does not weaken the full-file integrity checks to metadata-only
checks. A storage range is exempt from Pickle opcode interpretation only after
the existing finite constructor/layout semantics establish it as numeric data.
It remains covered by native antivirus and complete file hashes.

Errors in layout lengths, truncated headers or payloads, extra trailing bytes,
unsupported constructors and incomplete threat analysis retain their existing
failure behavior. The optimized inspector requires a real regular-file FD.
An unavailable or malformed analysis context cannot become a clean result.

## Compatibility and proof semantics

The helper signature is:

```python
verify_legacy_torch(data, inspect_pickle_callback, limits,
                    *, hash_storage_payloads=True)
```

`StaticInspector` accepts the same keyword with the same default. Both require
an actual Python `bool`; strings, integers and other truthy/falsy values are
rejected. No HTTP request field, user model metadata or runtime environment
variable chooses this mode. The worker's trusted code opts in after verifying
the held descriptor.

The default `True` path retains the original proof fields and each actual
`payloadSHA256`. In the internal `False` path, each payload digest is explicitly
`null` and the proof adds `storageDigestMode: "layout-only"`. No old digest is
reused and no payload digest is fabricated. `completeByteCoverage` describes
the exact structural partition of the file; it is not a claim that this helper
alone physically read or scanned every byte. Calling the layout helper directly
does not establish a scanner verdict or download approval.

Only `depth == 0` with an empty archive chain can use the worker optimization.
Legacy content inside ZIP, TAR and Gzip retains its previous payload-digest
traversal. Standalone callers retain the full-digest default. The supported
legacy CPU tensor/state-dict profile, Pickle protocols 2/4, constructor checks,
limits and unsupported-format behavior are unchanged. Other formats and the
download prefix probe are unchanged.

The scanner identifies itself as
`matrixhub-security-scanner-v12.2-legacy-layout-io`. Both source SHA256 and wrapper
version are included in generation construction. Existing reports and caches
remain evidence of their original generation; they cannot be reused as current
coverage after switching the scanner. A new scan is required. The advertised
scanner response schema and application adapter contract do not change.

## Reproduce the focused checks

Use the pinned Linux scanner environment with ClamAV 1.4.6 and Picklescan 1.0.5.
Run the following from `source/deploy/security-scanner`:

```sh
python -m unittest -v tests prefix_tests legacy_io_tests
```

The focused suite checks the fixed real PyTorch 2.8.0/2.9.1 protocol-2/4 samples,
zero/multiple storages, layout failures, strict mode validation, nested
fallback and worker snapshot integrity. Deterministic worker fault tests mock
the AV boundary and process limits. They test control flow, not real antivirus
operation. Real-engine protocol validation is a separate acceptance step.

For the existing real default-profile Unix-socket integration suite, provide a
complete immutable rules directory as described in the scanner README, then
run in the same isolated Linux environment:

```sh
TEST_RULES_DIR=/rules python -m unittest -v integration_tests
```

This existing suite expects the default `clamscan` profile. Its 64 MiB per-file
limit is not a GB capability claim. GB measurements must explicitly use the
documented `gb` profile, warm `clamd` backend and suitable container allocation.
Use a fresh test fixture; never target a shared application's live database or
restart a recording/demo service to run these checks.

## Measure the static stage separately

`legacy_io_benchmark.py` accepts distinct immutable baseline and candidate
scanner source paths and writes retained, non-sparse synthetic fixtures plus
`benchmark.json`. Choose a new output directory for each run. From the same
scanner directory, in Linux with the pinned real Picklescan dependency:

```sh
python legacy_io_benchmark.py \
  --baseline /baseline/scanner.py \
  --candidate ./scanner.py \
  --output-dir /evidence/legacy-io-static \
  --size-mib 1 --size-mib 128 --rounds 3 --mode static
```

For a bounded GB static-stage experiment, use a separate output directory:

```sh
python legacy_io_benchmark.py \
  --baseline /baseline/scanner.py \
  --candidate ./scanner.py \
  --output-dir /evidence/legacy-io-static-gb \
  --size-mib 1024 --rounds 1 --mode static
```

The generated sizes refer to numeric payload MiB; the total file also contains
metadata and storage headers. These are format-valid synthetic capacity inputs,
not pretrained models or independently sampled production traffic. The harness
records source and fixture hashes and checks structural proof equivalence after
excluding the deliberately different storage digest fields. Its read counters
measure logical bytes returned to Python, not disk-device reads or cache misses.

`--mode static` uses the real static inspector and Picklescan. `--mode layout`
uses a no-op threat callback and is only a layout/parser microbenchmark. Neither
mode includes ClamAV, the worker's complete pre/post SHA passes, API admission,
upload or download. Do not describe either mode's speedup as end-to-end scanner
or product acceleration. The benchmark can raise its direct-parser file limit
to the fixture size; this does not prove that an actual deployment accepts it.

## Full-scanner comparison and acceptance

The Dockerfile packages `legacy_io_native.py` and its fixture helper. This harness
starts private scanner processes using `SCAN_PROFILE=gb` and
`SCAN_CLAMAV_BACKEND=clamd`; it does not target an existing application. Mount the
unchanged baseline source read-only at `/baseline/scanner.py`, the complete
immutable rule snapshot read-only at `/rules`, and separately prepared inputs
read-only at `/input`. The candidate is `/opt/scanner/scanner.py`. The recorded
acceptance runs reused a pinned engine image and mounted candidate source there
read-only; they did not build a new image from the updated Dockerfile.
Use the documented scanner isolation flags and a GB-appropriate container
allocation. The following are commands inside that prepared Linux environment,
after preparing inputs separately:

```sh
python -I /opt/scanner/legacy_io_native.py --mode correctness
python -I /opt/scanner/legacy_io_native.py --mode performance --inputs /input --rounds 3
```

The portable input preparation entry point is
[`legacy_io_prepare.py`](../../source/deploy/security-scanner/legacy_io_prepare.py).
Run it beside `legacy_io_fixtures.py`, using a new output directory. This command
prepares the standard 128 MiB and 1 GiB protocol-2 fixtures plus a warmup:

```sh
python legacy_io_prepare.py --output-dir /absolute/new/native-input
```

For a smaller preparation check, use:

```sh
python legacy_io_prepare.py --output-dir /absolute/new/prepare-smoke --size-mib 1
```

The portable entry point was executed successfully with the 1 MiB option and
produced a 1,048,894-byte file plus a warmup and manifest. That check verifies
the portable preparation entry point; it is not another large-file benchmark.
Preparation uses non-sparse deterministic synthetic bytes, does not execute a
model, and refuses an existing output directory. Mount the prepared directory
read-only at `/input` for the native performance harness.

Correctness mode creates small private temporary fixtures. Performance mode
requires `/input/manifest.json` prepared separately, including each retained
fixture's artifact descriptor, hash, size and the warmup descriptor. It does not
generate the large inputs or silently substitute files. The result is emitted
as a final `RESULT` JSON line on stdout; retain the process exit status and
complete log together. Daemon startup, small warmup and an identical
large-artifact warmup are excluded from the timed requests. OS cache is not
controlled. The paired-round order alternates for smaller inputs; GB inputs use
one ordered pair regardless of `--rounds`.

The full comparison must send the same content through the real Unix-socket
scanner protocol, with the same engine, complete rules snapshot, limits,
container resources and storage. Record baseline/candidate source hashes and
generation, rules manifest, fixture hash and size, round order, cold/warm state,
per-request wall time, reported scan time, result completeness and findings.
Keep complete pre/post SHA and ClamAV active in both variants.

The completed comparison contains three paired 128 MiB runs and one paired
1 GiB run. The latter is a bounded capacity observation, not a percentile,
stable latency guarantee or production throughput result. No full-application
deployment, UI or GB download result is implied by a scanner protocol benchmark.
Published v11/v12.1 results belong to their recorded source and environment and
are not retests of v12.2.

## Completed evidence and limitations

The baseline scanner SHA256 is
`ddc45b36c3d8cd100bc0c765242f0765b347d2c93cc5dcb03744184ebcb857b9`;
the candidate scanner SHA256 is
`f5d8262973ba972a350e0215277763f772c631ac58a5cb3a467280447851e8ad`.
Both used the same pinned engine image
`sha256:cb04c9cb4bf38236520bfd5ae3ec11495e98192a0727eb7bf4de4438bbfb2502`,
ClamAV 1.4.6 and Picklescan 1.0.5. Production rule-file hashes, run-specific
generations and fixture hashes are in the
[verified correctness facts](../../evidence/legacy-io-v12.2/verified-correctness-facts.json)
and [verified performance facts](../../evidence/legacy-io-v12.2/verified-performance-facts.json).
These summaries independently parse completed logs/receipts and check their
hashes; generating a summary is not another test execution.

| Evidence | Observed result | Interpretation |
| --- | --- | --- |
| Focused `legacy_io_tests` | 11 methods passed | Parser behavior, nested/default compatibility and deterministic integrity failures |
| Combined unit/prefix run | 85 methods discovered: 84 passed, 1 isolation check skipped | Includes the 11 focused methods, 59 original methods and 15 prefix methods; the skip is retained |
| Separate hardened-container isolation run | 1 method passed | Executes the previously skipped method with the required isolation flags |
| Real ClamAV protocol correctness | PASS, baseline/candidate semantic results equal | Each variant has 8 asserted outcomes, 1 recorded observation and 9 single/batch entries compared; separate test-only payload markers also pass |
| Real static-stage comparison | PASS, 4 fixtures, 3 measured pairs each | 128 MiB and 1 GiB, protocols 2 and 4; excludes AV, whole-file integrity and API |
| Full scanner 128 MiB | PASS, 3 paired rounds | Real AV, static inspection and complete-file pre/post SHA in both variants |
| Full scanner 1 GiB | PASS, 1 baseline-then-candidate pair | Bounded warm-request observation; no stable speedup claim |

Across the combined run and separate isolation run, **85 unique test methods
passed**. This does not rewrite the original run as 85/85 with no skip.
See [unit receipt](../../evidence/legacy-io-v12.2/unit-7983c5ed2947-receipt.json),
[unit log](../../evidence/legacy-io-v12.2/unit-7983c5ed2947.log),
[isolation receipt](../../evidence/legacy-io-v12.2/isolation-5a9712121142-receipt.json)
and [isolation log](../../evidence/legacy-io-v12.2/isolation-5a9712121142.log).

### Full scanner timing

The 128 MiB numeric payload occupies a 134,218,046-byte file; the 1 GiB payload
occupies 1,073,742,142 bytes. Each timed request followed a small warmup and a
warmup using the identical large artifact. Daemon startup and both warmups are
excluded. The full experiment took 606.737 seconds inside the harness; this is
distinct from the request timings below.

| Input / statistic | Baseline request | Candidate request | Observed change |
| --- | ---: | ---: | --- |
| 128 MiB, median of 3 measurements per variant | 12.88136 s | 12.14094 s | 0.74042 s between medians |
| 128 MiB, paired round 1 (baseline then candidate) | 12.37337 s | 12.14094 s | 1.878% lower |
| 128 MiB, paired round 2 (candidate then baseline) | 12.88136 s | 12.09998 s | 6.066% lower |
| 128 MiB, paired round 3 (baseline then candidate) | 13.01042 s | 12.68544 s | 2.498% lower |
| 1 GiB, one baseline-then-candidate pair | 81.75788 s | 71.94251 s | 9.81537 s lower in this observation |

The difference between the 128 MiB medians is 5.748%, while the median of the
paired percentage changes is 2.498%. These are different statistics, and neither
is a guaranteed speedup. OS cache and exclusive machine load were not
controlled. The 1 GiB pair cannot separate ordering/cache effects from the code
change or estimate a repeatable improvement. These are warm scanner Unix API
requests, not MatrixHub upload/download latency, cold-I/O results, throughput or
percentiles. Both variants returned complete results with no findings for these
synthetic benign inputs. See [performance receipt](../../evidence/legacy-io-v12.2/performance-3e88ad8dce80-receipt.json)
and [performance log](../../evidence/legacy-io-v12.2/performance-3e88ad8dce80.log).

### Static-stage timing and logical reads

The separate Linux static benchmark used real Picklescan and three measured
pairs after a warmup for each fixture. It passed source/fixture hash checks and
normalized proof-equivalence checks. The medians are:

| Numeric payload / protocol | Baseline static stage | Candidate static stage | Logical bytes read: baseline to candidate |
| --- | ---: | ---: | --- |
| 128 MiB / P2 | 784.206 ms | 2.137 ms | 134,218,996 to 1,268 |
| 1 GiB / P2 | 6,271.242 ms | 1.515 ms | 1,073,743,092 to 1,268 |
| 128 MiB / P4 | 782.473 ms | 1.736 ms | 134,219,012 to 1,284 |
| 1 GiB / P4 | 6,468.953 ms | 1.699 ms | 1,073,743,108 to 1,284 |

Each case removes exactly one numeric-payload-sized logical traversal; the
initial routing prefix still reads a few payload bytes. These counters measure
bytes returned to Python, not physical device reads. ClamAV, complete pre/post
hashes, worker startup, HTTP and admission are excluded, so the large static
stage reduction must not be described as full-scanner acceleration.
See [static benchmark](../../evidence/legacy-io-v12.2/static-benchmark.json),
[static receipt](../../evidence/legacy-io-v12.2/static-e7a8ffc758cf-receipt.json)
and [static log](../../evidence/legacy-io-v12.2/static-e7a8ffc758cf.log).

### Correctness, retained failure and detection scope

The successful native run used actual ClamAV and Picklescan through the scanner's
Unix HTTP API. Four small framework-generated PyTorch 2.8.0/2.9.1 protocol-2/4
files and a synthetic ByteStorage file remained complete with no findings;
truncated storage remained incomplete; dangerous metadata retained the dangerous
reference finding and incomplete coverage. A standalone EICAR test file matched
`clamav.Eicar-Test-Signature`. Single requests and the equivalent batch had the
same semantic results for both implementations.

An earlier run **failed** because the harness incorrectly required EICAR bytes
embedded inside numeric storage to match the official rules. The corrected
harness retains that fixture as an observation: **both baseline and candidate
returned complete results with no finding for that embedded EICAR fixture**.
It is not counted as a detection success. The scanner source did not change
between the failed and corrected correctness runs. The original
[failed receipt](../../evidence/legacy-io-v12.2/correctness-1d126745e949-receipt.json)
and [failed log](../../evidence/legacy-io-v12.2/correctness-1d126745e949.log) are
preserved alongside the successful
[correctness receipt](../../evidence/legacy-io-v12.2/correctness-38246ec2360c-receipt.json)
and [correctness log](../../evidence/legacy-io-v12.2/correctness-38246ec2360c.log).

To test the narrower claim that native AV still examines numeric payload bytes,
a separate, test-only NDB rule matched inert markers at offsets 131,397 and
262,399 in both variants; the no-marker control had no finding. This used a
distinct test rules generation and was not added to the production ruleset.
It establishes coverage of the exercised positions, not a production malware
detection rate, universal byte coverage proof or zero false negatives.

This iteration did not rerun full MatrixHub application E2E, KIND, browser UI or
large-file application upload/download tests. It did not build or validate a new
release image. Attack accuracy, false-positive rate, production throughput and
compatibility with arbitrary model families remain outside these measurements.
