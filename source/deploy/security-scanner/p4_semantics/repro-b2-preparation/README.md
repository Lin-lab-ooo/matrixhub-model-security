# b2 archive-routing safety repair: source-only increment

Authors: Tianyi Lin (林天意), Jiaying Zou (邹佳颖). Local preparation only; no publication, installation, or adoption is performed by this packet.

The exported scanner is b2e80d9544f0c5dd313d3758107ea6069b0c0a742cd7f78030901aabea7ffda6 (206591 bytes), derived from qualified6062. Its bounded V7 TAR fallback runs only after the existing branches succeed without identifying content. Existing denials retain precedence; standalone raw V7 `.bin` still follows the old explicit Pickle refusal. The tar/gzip tests contain inert references and never deserialize or execute them. No new global allowlist, scanner limits, fullAV, pre/post fullSHA/fstat, native supervision, or application assertions are removed.

`qualification-pending.json` is a preparation-time snapshot: new b2 native200 and APP6 are PENDING and are not read here. Preparation files carrying PENDING remain historical records even if ROOT later attaches completed evidence. Current completed static40, existing47/84/34, independent12, public9 and structural6 receipts are indexed by explicit path, size and fullSHA in `known-current-receipts-index.json`; receipt bodies and runtime logs are not copied. The 217 static assertions are not217 models. Existing oracles are retained, including the previously declared two47 deltas and one84 delta. Public9 comprises seven public originals and two controlled derivatives: three author-normal inputs remain refused; this is not proof of broad public-model compatibility. APP6, if later qualified, is the independent application scenario suite, not a new official187 run.

Older6062 synthetic performance, ResNet, DistilBERT N07 and bomb results remain historical source-specific evidence. They do not become b2 PASS results. There is no attributable algorithm speedup claim; the previous performance sources also occupied different filesystem locations. GPU and training poisoning are outside this increment.

## Verify without executing a scanner

Default `python -I -B verify_source_b2.py` describes the verifier and reads no source or artifact. `--verify-package` verifies this closed explicit allowlist. No verifier path imports or executes the scanner.

ROOT must first confirm the actually installed external scanner path, then bind it and a fresh external snapshot directory containing only scanner.py:

```
python -I -B verify_source_b2.py --verify-source --installed-source-confirmed --source <ABSOLUTE_INSTALLED/scanner.py> --snapshot <ABSOLUTE_FRESH_SNAPSHOT/scanner.py>
```

Save that JSON outside this immutable packet and repeat with `--previous-binding <EXTERNAL_BINDING.json>` after all suites. Package source copies cannot substitute for installed source, and the verifier does not establish adoption. The original path and snapshot require fullSHA/fstat continuity before and after; ROOT creates the snapshot without changing installed source. No automatic copy/install or Docker launcher is included.

## Linux-only reproduction

Use five fresh sequential, ROOT-owned containers with the frozen guards and external hard cutoff from repro-contract.json: Python3.13.16, UID/GID65532, CPU1, memory512MiB/noSwap, PID64, networknone, read-only root, capdropALL, no-new-privileges/noGPU, private /tmp32MiB rw,noexec,nosuid,nodev; <=120s per group. Never generate fixture bytes on Windows or outside guarded private Linux RAM. Only three read-only data mounts are required per container: selected probe directory to /probe, selected baseline directory to /baseline, and the externally verified single-file snapshot directory to /candidate. Do not mount a worktree parent, model cache, dependencies, credentials, socket, or runtime runs directory.

* TAR40: mount repro40, baseline40, external snapshot; run `python3 -I -B /probe/linux_v7_tar_tests.py --execute --baseline /baseline/scanner.py --candidate /candidate/scanner.py --deadline <FRESH> --root-idle-confirmed`.
* Existing165: mount repro, repro/baselines, external snapshot; run `/probe/run_suite.py --execute --suite missing47 --deadline <FRESH> --root-idle-confirmed`, then fresh containers with p4_84_delta and ascii34. Add `python3 -I -B` to each invocation.
* Independent12: mount repro12, baseline12, external snapshot; run `python3 -I -B /probe/run_holdout.py --execute --deadline <FRESH> --root-idle-confirmed`.

ROOT must verify original-nine stability, actual resource/mount/network configuration, exact owned CID/process cleanup and no overlapping heavy work after every group. The inner entry is not a standalone safety launcher. Default suite descriptions generate no fixtures. All failures and unexpected operations must remain visible. Current receipt indexes establish past runs only; reproducing against a future installed source requires its own fresh receipts and before/after binding. No source-only or pure metadata check is fullAV, deployment or qualification evidence.
