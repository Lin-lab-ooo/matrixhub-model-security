# Publication Notes and Evidence Provenance

[English](PUBLICATION_NOTES.md) | [简体中文](PUBLICATION_NOTES.zh-CN.md)

Publication target: `Lin-lab-ooo/matrixhub-model-security`. This is an independent repository for MatrixHub security integration and evidence. It is not an official upstream release and does not imply maintainer endorsement. Gitee synchronization follows the GitHub publication; no Gitee remote is currently configured.

## File Layout

| Path | Contents |
| --- | --- |
| `source/` | 1527 sanitized source files verified with full SHA checks, preserving the upstream directory structure, attribution, and licenses |
| `reproduce/` | Source verification; Linux build, isolated deployment, and test entry points; a smoke test with a real small HF model |
| `reports/` | Original Chinese HTML / PDF reports |
| `evidence/` | Actual test receipts with version identities, and the original delivery manifest |
| `media/` | Actual desktop screenshots and a 224.92-second demonstration video |
| Root Markdown files | Public documentation, test summaries, limitations, and release notes added for this publication |
| `scripts/verify_publication.py` | Verifies the public file set, SHA values, and provenance consistency; does not execute the product or any model |

SHA256 of the original delivery ZIP:

```text
dc28b6111c0f18312085ad1b685231485eb8e02abf51beb9ee3f9677ed02cdf6
```

The ZIP is 84,803,273 bytes and is available as a GitHub Release asset; it is not duplicated in Git history. The video remains in `media/` to preserve the relative links in the offline reports and is also available as a Release asset. Every file is below GitHub's regular Git per-file limit, so this source snapshot does not require LFS. See [GitHub's official documentation on large files](https://docs.github.com/en/repositories/working-with-files/managing-large-files/about-large-files-on-github).

## English Documentation and the Frozen Release

The default GitHub documentation is in English, with Chinese versions linked from each document. The original Chinese reports, recorded interface, source, and evidence remain unchanged.

The `v12.1` tag and its five release assets remain pinned to initial publication commit `b48f4a93444393b41899ad31e73c6ae83bfba75a`. The attached `PUBLICATION_MANIFEST.json` describes that tagged publication tree and has SHA256 `7ba3f08b4bc5f609e0654097a383506f61d2a2db5f724886d4f9d0fd1a7d113e`. A later `main` checkout contains the English documentation update and its own manifest. Use each manifest only with its matching checkout; the attached manifest does not describe the later `main` tree or the original delivery ZIP.

GitHub's automatically generated source archives also represent the unchanged tag. To verify that snapshot, use a fresh checkout and confirm its commit before running the integrity scripts. These checks establish publication and source integrity; they do not rerun product tests.

## Frozen Source and Historical Documentation

The bytes of `source/` and the original delivery evidence are unchanged by this publication's formatting, project naming, or release process. The root `.gitattributes` disables automatic Git line-ending conversion. Five upstream test helpers previously sanitized for the new test environment use explicitly supplied test credentials rather than existing local accounts; the transformation identity is recorded in `VERSION_LOCK.json`.

The frozen files `source/docs/EVIDENCE_SUPPLEMENT.zh.md`, `source/docs/security/REPORT.zh.md`, `source/deploy/security/README.md`, and `source/THIRD_PARTY.md` contain historical commit, environment, quota, or image records. References to “current” in those files mean the time at which the original text was written. **For this publication, `VERSION_LOCK.json` defines the version identity; the root `TEST_REPORT.md`, final reports in `reports/`, and their corresponding receipts define the current acceptance results.** The old 64 MiB default quota is not the configuration used for GB-scale acceptance tests.

Workload and local experiment scripts in the older source may depend on Windows, fixed project names, or historical directories. The portable entry points are in the root `reproduce/` directory. These entry points have not yet completed an end-to-end run on a fresh machine with empty caches. Controlled local acceptance results therefore do not establish that portable deployment has passed. Read the [complete reproduction instructions (Chinese)](README.zh.txt) before use.

## Privacy and Credential Scope

The publication candidate comes from the original explicit source/evidence allowlist. It excludes live databases, Docker volumes, access tokens, SSH private keys, helpers for existing accounts, virus signature binaries, GB-scale samples, and SDK caches. Manual and pattern-based reviews found no private-key headers or common provider-token patterns; this is not a guarantee of exhaustive secret detection.

Some historical receipts and build logs retain non-secret local paths, including Windows user-directory names and the drive letters containing the project. These fields have not been silently rewritten, preserving the SHA values of the original receipts. They record execution provenance and are not instructions for use on another machine. Upstream fixed example passwords and synthetic test strings are also retained; none should be used as credentials for a real service. This publication package is not a fully anonymized dataset.

## What Verification and CI Establish

Run in a clean publication directory:

```bash
python3 scripts/verify_publication.py
python3 reproduce/verify_source.py
```

The first command checks the current public manifest, every file's bytes, the mapping to the original delivery, and unexpected extra files. The second checks the original 1527 listed source files. The optional [CI template](docs/ci-templates/release-integrity.yml) performs only these integrity checks. It is **not** the product security suite, official E2E, KIND, or deployment acceptance. The template is currently stored under the documentation directory and does not run. No GitHub Actions cloud-run results were available when this document was written.

The upstream workflows are preserved in full under `source/.github/` and do not run automatically as root GitHub Actions workflows in this publication repository. The initial release enables no root workflows and does not request the GitHub OAuth `workflow` scope. Enabling the optional template later requires separate explicit authorization and an updated public manifest. The template itself supports manual triggering only and grants read-only repository permissions.

`PUBLICATION_MANIFEST.json` lists the files in the public directory. `evidence/original-archive-manifest.json` is the original delivery manifest. The latter retains status fields from the time its creation was planned and is used only as the original manifest; the original delivery receipts establish that the ZIP was actually created and verified. Manifests and scripts cannot replace a trusted external ZIP SHA or a verified Git commit.
