# v12.1 Release Notes

English · [简体中文](RELEASE_NOTES.zh-CN.md) · [Project overview](README.md) · [Test report](TEST_REPORT.md)

Evidence finalized: **October 14, 2026 (Asia/Shanghai)**. This is an independent contribution derived from MatrixHub, not an official upstream release. Publication does not imply upstream acceptance or maintainer endorsement. Exact tested identities are recorded in [VERSION_LOCK.json](VERSION_LOCK.json).

This version binds complete model-inspection evidence to immutable repository revisions, scanner generations, and server-side download policy, and provides auditable human review.

## Changes in this iteration

- **Bounded legacy-prefix rejection.** An optional probe rejects known-invalid construction metadata while staging. Requests and responses bind the prefix digest and length, source length, and scanner generation. A prefix result cannot authorize a download.
- **Bounded cross-file pipelining.** Staging the next batch overlaps with complete inspection of the previous batch. Cancellation waits for worker termination before cleanup. Older scanners retain the complete-file path; upgrade the adapter before the new scanner.
- **Append-only human review.** Added API and UI support, plus migration 3 for SQLite and MySQL. The server determines permissions and reviewer identity; reviews and audit records are written in one transaction. Machine reports, cached results, and download decisions are unchanged by reviewer opinions.
- **PATCH connection handling.** Fixed initial protocol routing in cmux so PATCH requests receive an HTTP response instead of a connection reset, with regression tests on new TCP connections. PATCH still cannot edit a review record; the application route returns an explicit HTTP rejection.
- **Current application evidence.** Added multi-revision, trained BERT, synthetic GiB, permission API, desktop interaction, and recording evidence, while retaining failed runs and their source identities.

## Capabilities included in this cumulative snapshot

Isolated ClamAV and Picklescan inspection, restricted CPU legacy construction semantics, fail-closed completeness checks, content/generation evidence reuse, server-side admission, and auditing are part of the cumulative contribution. They were not all first introduced in this iteration. ClamAV and Picklescan are third-party engines; this project does not claim changes or improvements to the ClamAV detection core.

## Validation summary

The current application passed **794/794 business assertions**. A separate generation-transition scenario passed **17 + 23** assertions; the human-review API passed **55/55**, and the desktop browser passed **8/8**. **27 complete downloads**, totaling **1,180,190,711 bytes**, matched expected SHA256 values. The fresh backend build and selected security regressions passed. The real UI recording is **224.92 seconds** long.

The V7 repository report took **114.534 seconds with 8 cached files**; a subsequent README-only V8 report took **3.386 seconds with 12 cached files**. A separate production-component staging diagnostic rejected a GiB fixture with invalid header metadata after reading **64 KiB in approximately 2.281 seconds**. These measurements have different scopes and do not establish a general speedup. Full counts, historical KIND results, and the scope of reused evidence appear in [TEST_REPORT.md](TEST_REPORT.md).

## Deployment and remaining limitations

Configure the scanner, complete read-only rules, shared snapshots, Unix socket, admission policy, and required database migrations using the security deployment entrypoints. A standard upstream image does not automatically include this integration. Use a fresh dedicated environment and new test credentials. The default **64 MiB** limit differs from the GB profile and its resource requirements.

Current official E2E/KIND suites were not rerun for this candidate. Complete antivirus inspection during the initial upload, a full cold-cache deployment on a new machine, current security-enabled KIND acceptance, the 16-hour soak, and broad false-positive evaluation remain incomplete. The cause of earlier intermittent browser timeouts is unresolved. The parallel `pread` full-scan candidate was not merged, and full-file SHA checks before and after scanning remain in place. See [LIMITATIONS.md](LIMITATIONS.md).

## Archives and provenance

The original delivery archive, `MatrixHub-v12.1-source-evidence-demo.zip`, is **84,803,273 bytes**, with SHA256:

```text
dc28b6111c0f18312085ad1b685231485eb8e02abf51beb9ee3f9677ed02cdf6
```

Publication documentation is separate from that original archive. The upstream base is `84bb83043dc17b6cb3d1858620ac40c171bd8eff`; the source inventory contains **1,527 files** and **44 overlays**. The tested source's local DCO commit is `e22d87dd63b0789cad1d09573a5a9a6e46cde11e`. Five upstream test helpers were sanitized and require explicit credentials for a new test environment. Preserve the [upstream license](source/LICENSE) and third-party attributions.

## English documentation update

The GitHub default overview, test report, limitations, code map, publication notes, and release notes are now in English; Chinese copies remain available. This is a documentation-only update: it does not change the tested source, original evidence, or test outcomes.

The **`v12.1` tag and its five original assets remain attached to the initial publication commit `b48f4a93444393b41899ad31e73c6ae83bfba75a`**. The manifest attached to that release verifies the original tagged publication. A newer `main` checkout has its own updated `PUBLICATION_MANIFEST.json`; use the manifest supplied with the same checkout. GitHub's automatically generated source archives also differ from the original delivery ZIP. The original PDF report and recorded interface are in Chinese.
