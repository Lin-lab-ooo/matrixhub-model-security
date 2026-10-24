# 6062 source increment and 165 static-check reproduction

This is an outside-worktree source preparation, not an adoption, release, installed-source test or current full qualification. ROOT retains the existing worktree commit/source (`7bfea` / `7cd1...`). This preparation changes no worktree or historical test. The exported `source/deploy/security-scanner/scanner.py` is 205944 bytes, full SHA256 `6062a3f95ab822be816d6e84aa3cc32934490b60d85242f19162e2160b6f7bb3`. ROOT handles any later DCO/integration separately.

`allowlist.json` is the exact delivery inventory: only named source CODE, baseline CODE, fixture-generator/test source, documentation and bounded JSON metadata. It contains no model fixture, weights, raw logs, credentials, run directory or archive. `source-7cd-to-6062.patch` is a review aid against the included frozen7cd CODE; the full source SHA is authoritative. `qualification-pending.json` keeps native200/comparator and APP statuses PENDING; do not fill them from active or older-source results.

## Scope of the tests

The unchanged `repro/run_suite.py` and eleven dependency files come from preparation `dfd7ce5d24131453fb5ce02e1e9a828021ad7a04fdbcc8b32e053a5b6a815e9f` (all21 original leaves were verified). Groups remain separate:47 missing checks against7cd with exactly two declared exists-positive expectation deltas;84 P4 checks against5fa with its one prior missing-record delta;34 byte-exact ASCII checks against19aee with the explicit old7cd-to6062 target-pin adapter. Their exact source/function/assertion contract is in `repro-contract.json`. These are165 static assertions, not165 public models, fullAV, application approval or malware accuracy. The unchanged historical W118/35-tested runner is pinned to7cd; it is not an entry for testing6062. Historical84/ASCII files were not edited.

`known-165-receipts-index.json` identifies three already completed ROOT observations (47/84/34 PASS, cleanup/original-nine true). Raw receipts are referenced by path/fullSHA, not embedded. Their outer schemas do not embed the whole preparation digest; the index records that limitation and verifies their suite/candidate/baseline pins. These observations are not a test of a future installed checkout. Independent holdouts remain a separate cohort and do not inflate165.

## Verify source CODE without executing it

The following helper performs only source identity/metadata operations. It does not import the target source, launch Docker, create a fixture or run any suite. Default invocation reads no source. Verify the exact delivery inventory with:

    python -I -B verify_source6062.py --verify-package

After ROOT separately installs/adopts the source, ROOT must identify the actual installed plain `scanner.py` externally, not point this command at the exported package copy. First record full held-FD SHA256 plus path/FD fstat before/after reading:

    python -I -B verify_source6062.py --verify-source --source <ABSOLUTE_INSTALLED_scanner.py> --installed-source-confirmed

ROOT then creates a fresh isolated CODE directory containing only the verified `scanner.py`, with no model or other checkout file. Copy only that source; validate original and snapshot again before any test. Do not mount the worktree or its parent. The unchanged fixture guard requires a directory mount `/candidate:ro`, so this package adds no single-file guard and no Docker lifecycle driver.

    python -I -B verify_source6062.py --verify-source --source <ABSOLUTE_INSTALLED_scanner.py> --snapshot <ABSOLUTE_FRESH_CODE_DIR/scanner.py> --installed-source-confirmed

Save that bounded JSON as the pre-suite binding. After each suite and at the end, run the same command with `--previous-binding <PRE_SUITE_BINDING_JSON>`; original and snapshot full SHA and identity must still match. Keep all records and failures outside this locked package. On Windows, Python fd-stat may expose an unavailable ctime sentinel. The verifier records full FD-before/after and path-before/after stamps separately, compares each pair exactly, and cross-checks device/inode/size/mtime; path ctime is still checked before/after. Linux also requires cross-FD ctime equality. This metadata-only host verifier does not modify the frozen Linux fixture guard. The verifier cannot establish DCO/adoption; `--installed-source-confirmed` is ROOT's explicit statement about the external path. The actual Linux test uses the **verified snapshot of the installed source**, not a direct live-checkout mount. A package/archive source copy cannot stand in for the installed-source check.

## Existing Linux-only entry points; ROOT is sole executor

The old8d image supplies only the trusted Python environment; external6062 CODE is the component under test. This is not a production image/GEN attestation. No host fixture/VM execution is authorized by this preparation. After all current heavy work is terminal and cleaned, ROOT supplies three fresh sequential owned containers, one per group, using its existing reviewed host supervision and exact-CID cleanup. No concurrent groups, prune, broad removal or existing Docker-account configuration. ROOT verifies original-nine identity/StartedAt/running state before/after and keeps all failure records. Use fresh external deadlines at most120 seconds per group; no stale timer, no extending R24 window/freeze. This preparation itself creates no container and supplies no relaxed fallback.

Keep the exact original helper controls: existing trusted Python image `sha256:8d0ab03347b60084a30ec18dd9d4b7184b6e4abf595c9ff2f44fdf00c1345523`, read-only root; uid/gid65532, supplementary groups limited accordingly; network none/loopback only/no nonloopback routes; CPU1;512MiB; zero swap; PID64; cap-drop ALL/no-new-privileges; no GPU/device/socket access; private `/tmp`32MiB rw,noexec,nosuid,nodev. The helper sets CORE0/CPU30/FSIZE1MiB/NOFILE64 and gates every generator. Do not change guard thresholds.

Mount `repro` directory `/probe:ro`, its `baselines` directory `/baseline:ro`, and the fresh verified single-code snapshot directory `/candidate:ro`. Do not mount the package's exported source or the whole worktree as `/candidate`. Source CODE baselines are not executed as models. Fixtures are generated only after Linux/UID/mount/network/cgroup/source guards in private noexec RAM, aggregate<=1MiB, then inspected statically without unpickling/Torch loading.

Run these exact commands in separate fresh containers under ROOT's bounded supervisor, with a new Unix deadline for each:

    python3 -I -B /probe/run_suite.py --execute --suite missing47 --deadline <FRESH_UNIX_DEADLINE> --root-idle-confirmed
    python3 -I -B /probe/run_suite.py --execute --suite p4_84_delta --deadline <NEW_FRESH_UNIX_DEADLINE> --root-idle-confirmed
    python3 -I -B /probe/run_suite.py --execute --suite ascii34 --deadline <NEW_FRESH_UNIX_DEADLINE> --root-idle-confirmed

Preserve each bounded metadata JSON and stderr-byte count; no raw stderr export. Group PASS requires the real entrypoint exit0 and all exact47/84/34 assertions, expected baseline/candidate SHA, no model load/AV, source pre/post binding and actual owned-container cleanup. Any refusal, timeout, source change or failed cleanup is a failure, not a skipped sample or PASS. FullAV/public/native/APP qualification and any production adoption are separate ROOT gates.
