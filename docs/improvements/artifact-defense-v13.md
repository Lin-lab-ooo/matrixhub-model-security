# v13 candidate: bounded artifact inspection and archive coverage

Status: development candidate based on commit
`6d936cab06206c877837068a52958ab07588816b`. The additions below have host-side
static regressions and source review. They are not a new complete application
release, Linux sandbox acceptance, real-antivirus result, or GB throughput claim.
The published v12.1 release and its historical evidence retain their identities.

## Problem and contribution

Model registries inspect attacker-controlled serialization and container bytes.
A correct download gate also needs an inspection result that accurately states
whether all supported content was covered within its budgets. Directory entries
and format metadata must not bypass those budgets or disguise uninspected data.

This change retains ClamAV and Picklescan as third-party engines. It adds bounded
archive preflight, directory-content validation, deterministic Safetensors
failure handling, and a local optimization for repeated static references. It
does not load a model, execute a reducer, create a new malware engine, or classify
resource-limit violations as malicious execution.

Implementation and tests:

- [Scanner](../../source/deploy/security-scanner/scanner.py):
  `bounded_zip_names`, `validate_zip_directory_member`, `validate_pax_records`,
  `bounded_tar_headers`, and the `StaticInspector` methods.
- [New format regressions](../../source/deploy/security-scanner/format_hardening_tests.py).
- [Static-parser microbenchmark](../../source/deploy/security-scanner/format_hardening_benchmark.py).

## Observed baseline gaps

Read-only, host-side probes compared the existing v12.2 candidate with the working
tree, using inert generated inputs. The baseline scanner SHA-256 was
`f5d8262973ba972a350e0215277763f772c631ac58a5cb3a467280447851e8ad`.

| Probe | Baseline observation | Implemented response |
| --- | --- | --- |
| Top-level ZIP with 257 empty directories | Already rejected by the top-level directory preflight | Retains rejection |
| Nested ZIP with 257 empty directories | Static inspector returned; only the containing ZIP file counted as a member | Preflight the nested central directory before `ZipFile` allocation and reject the excessive physical entry count |
| TAR with 257 empty directories | Static inspector returned with zero counted members | Count directories and preflight physical TAR headers |
| ZIP directory name carrying inert Pickle bytes | Directory branch returned without checking the payload | Reject nonempty directory payloads |
| ZIP directory name with symlink attributes | Directory branch skipped the symlink check | Check encryption, links and special-file attributes before the directory branch |
| TAR directory header carrying inert Pickle bytes | Directory branch returned without checking the payload | Reject nonzero directory size before constructing `TarFile` |

The local probe receipts are `astra-archive-budget-probe.json` and
`astra-directory-payload-probe.json` under
`runtime/optimization-v13-20261022/` in the development workspace. They are
static-only evidence, not native AV, container, or application acceptance.
The archive-budget receipt records an intermediate working-tree source identity;
it must not be relabeled as a final-source measurement.

An inspector returning here means its static function returned for that generated
input. It is not evidence that an entire deployed MatrixHub application approved
the file, or that a real malicious payload executed. Native ClamAV may independently
reject an archive before the static stage; those outcomes must be recorded
separately in native validation.

## ZIP preflight and directory coverage

`ZipFile` materializes its central directory eagerly. The scanner now validates
the directory before constructing that object at every nesting depth:

1. Locate and bound the end records and directory bytes.
2. Check the declared physical record count against the remaining global member
   budget, including directories.
3. Walk exactly that number of complete central-directory records and require
   exact consumption of the directory. A forged small EOCD count cannot conceal
   additional central records.
4. Continue through the existing member-content, CRC, expansion, ratio and depth
   checks. Preflight alone never produces a clean result.

The existing directory allocation ceiling remains 4 MiB. Nested archives share
one `StaticInspector` member and expansion budget. An archive containing another
archive consumes a member for the containing file as well as the child's entries.

Directory names are no longer an early escape from attribute or content checks:

- Encrypted and symlink entries are rejected before `is_dir()` can skip them.
- Directory type attributes must be consistent, and the declared uncompressed
  length and CRC must both be zero.
- Stored directories must have zero compressed bytes.
- Empty DEFLATE directories remain supported only when their compressed fragment
  is at most 32 bytes and bounded raw-DEFLATE decoding proves empty output,
  a completed stream, and no unused or unconsumed tail.
- The local header's method, flags, CRC and sizes must agree with the central
  entry, allowing the ordinary zero/declared placeholders for data-descriptor
  mode. Existing `ZipFile` local-name and overlap checks remain.

This preserves ordinary empty stored/DEFLATE directories while rejecting a
directory label used to hide data. Other directory compression methods are
outside this fixed supported profile and remain incomplete.

## TAR physical-header fence

Iterating final `TarInfo` objects is insufficient to budget TAR metadata: PAX and
GNU extension records are consumed internally before the library yields a logical
file. `bounded_tar_headers` now runs before `tarfile.open`:

- Inspect one fixed 512-byte header at a time, using `TarInfo.frombuf` only for
  that header and its checksum, without following extension records.
- Bound every physical header against the remaining global member count.
- Check payload length and padding against the actual remaining file size before
  advancing the cursor.
- Charge PAX local/global and GNU long-name/link extension headers to the member
  budget, and charge their bytes to the expansion budget. Ordinary files and
  directories are charged later, once, by the existing traversal.
- Bound a single extension payload to 64 KiB, all extension bytes to at most
  8 MiB and the remaining expansion allowance, and each PAX header to 256 fields.
- Parse PAX record lengths and `key=value` boundaries with bounded byte operations;
  no value is evaluated or used to extract a filesystem path.

The fixed profile supports ordinary uncompressed V7/USTAR, PAX path/timestamp
metadata, and GNU long names. Existing gzip traversal first performs bounded
expansion; the resulting TAR is subject to the same physical preflight.

The following inputs are deliberately incomplete:

- Nonzero directory payloads, links and special files.
- Sparse GNU headers and PAX layout-changing keys, including `size`,
  `GNU.sparse*`, `SCHILY.realsize` and `SCHILY.filetype`.
- Oversized or excessive extension metadata, malformed PAX records, bad checksums,
  truncated physical payloads, and extension records without a following entry.
- Missing two-zero-block termination, a single-zero EOF, and nonzero data after
  the terminator. Only zero record padding may follow it.

These conditions conservatively narrow the supported TAR profile. They are not
claims that every such archive is malware. In particular, sparse archives,
PAX `size` overrides, permissive single-zero endings and concatenated archives
that another TAR reader tolerates are intentionally not approved by this profile.

Physical and per-extension limits also bound cumulative PAX metadata, but do not
mean that no metadata map is ever allocated. With the current ceilings there can
be up to 256 physical entries and 256 fields per extension, further constrained
by total raw metadata bytes and the outer worker resource limits.

## Safetensors failure containment

The scanner retains duplicate-key rejection, dtype and shape validation, exact
offset coverage, and complete-artifact antivirus/integrity checks. The new fixed
profile adds:

- At most 64 dimensions per tensor.
- At most 65,536 tensor entries, excluding `__metadata__`.
- Local normalization of JSON/UTF-8/recursion failures to
  `invalid_safetensors_header`, rather than letting a deeply nested header become
  an unhandled interpreter recursion failure.

The existing 8 MiB header ceiling remains. Memory exhaustion and unrelated
resource failures are not converted into a clean result. Source changes and
fixed profile limits change the scanner generation; old approvals do not become
new-generation evidence.

## Repeated-reference optimization

Within one `inspect_pickle` invocation, the scanner memoizes the dangerous-reference
classification of each exact observed `(module, symbol)` pair. The pinned rules
are unchanged during that invocation, and the existing symbolic/global budget
bounds the memoized key count. The memo is not shared across requests.

Repeated safe references no longer repeat the same classifier lookup. A later
different dangerous reference is still classified. The complete final Picklescan
analysis, symbolic disagreement checks, opcode budgets and evidence production
remain. This is neither a threat-result cache across changing rules nor a bypass
of complete analysis.

An intermediate Windows development run used real Picklescan 1.0.5, one identical
520,002-byte inert stream containing 20,000 repeated `collections.OrderedDict`
references, one untimed warmup for each variant, and five alternating-order pairs:

| Static-only measurement | Baseline | Intermediate candidate |
| --- | ---: | ---: |
| Median seconds | 0.0952441 | 0.0814034 |
| Observed reduction of the medians | — | 14.53% |
| Parsed opcodes | 40,002 | 40,002 |
| Findings | Empty | Empty |

The candidate source for that run was
`1f32c4c16550af95e40fd17eb1d7b752759d6de98430861e46796664ebb71f22`;
further format-hardening edits followed. This is an intermediate observation,
not final-source release acceptance. Repeat after freezing the final source and
retain the emitted source/input identities and raw samples.

The microbenchmark excludes AV, rule loading, full snapshot hashes, HTTP,
application scheduling, upload and download. It is not an end-to-end speedup,
GB throughput result, production percentile, or malware-detection accuracy.

```bash
cd source/deploy/security-scanner
python format_hardening_benchmark.py \
  --baseline /immutable-baseline/scanner.py \
  --candidate ./scanner.py --references 20000 --rounds 5
```

Use the pinned Python/Picklescan environment. The benchmark never unpickles its
input and checks exact finding/opcode equivalence and unchanged source hashes.

## Completed static checks

The host run completed 103 distinct test methods, with zero failures and zero
skips in that selected suite:

| Suite | Methods |
| --- | ---: |
| New format-hardening regressions | 40 |
| Existing `StaticInspectionTests` | 42 |
| Existing `BatchProtocolTests` | 3 |
| Existing `PrefixProtocolTests` | 6 |
| Existing `PrefixMetadataTests` | 5 |
| Existing `LegacyLayoutTests` | 7 |
| Total selected host static suite | 103 |

Observed unittest elapsed time was 0.320 seconds; process startup and environment
preparation are not included. The new cases cover nested count/byte fences, lying
EOCD records, directory payload/mode/encryption ambiguity, exact empty DEFLATE,
shared nested budgets, PAX/GNU physical records, supported normal archives,
Safetensors ceilings, and exact-reference memo isolation.

On Windows, import-only shims allow pure parser tests to import the scanner.
They do not implement Linux process limits or Unix socket behavior. Some existing
prefix tests explicitly mock threat classification to verify metadata/control
flow. These results must not be labeled as real antivirus or sandbox tests, and
test methods must not be treated as an accuracy dataset denominator.

Reproduce the selected static suite inside the pinned Linux scanner environment:

```bash
cd source/deploy/security-scanner
python -m unittest -v \
  format_hardening_tests \
  tests.StaticInspectionTests tests.BatchProtocolTests \
  prefix_tests.PrefixProtocolTests prefix_tests.PrefixMetadataTests \
  legacy_io_tests.LegacyLayoutTests
```

## Integrity and remaining acceptance

All complete-artifact ClamAV coverage, pre/post full SHA-256 and `fstat` checks,
rule verification, generation binding, report completeness and download gates
remain required. The separate reusable-buffer SHA change still reads the full
stream; this document does not claim removal of any integrity traversal. A
proposal to skip repeated `_verify_fixed` full verification was not applied and
must not be described as an implemented improvement.

Before promoting this candidate, complete and retain separate receipts for:

1. Full Linux unit, process-isolation, timeout/cancellation and Unix-protocol
   regressions against the frozen scanner source.
2. Real ClamAV with the complete immutable rule snapshot: ordinary models,
   EICAR, inert dangerous-reference inputs, malformed containers and resource
   limits. Distinguish native-engine rejection from reaching the static branch.
3. Bounded GB full-scanner comparisons on identical inputs and environment,
   with raw timing, input/source/rule identities and cleanup evidence. Synthetic
   capacity fixtures must be separate from real trained model artifacts.
4. Complete fresh-application upload/version/report/download admission scenarios,
   including cache invalidation, interrupted work and snapshot identity failures.
5. New deployment/reproduction entry points, source-bound manifests and independent
   review. Historical v12.1 or v12.2 tests cannot substitute for these runs.

The threat boundary continues to trust the application writer, database, scanner
implementation and host. Static findings identify references/structures, not
proof that a callable ran. This project does not assess model accuracy, training
data poisoning, model-behavior backdoors or generated-content safety.
