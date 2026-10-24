# Bounded P4 and ASCII semantics regression tests

These are Linux container tests. Do not generate model or attack fixtures on the host. The guard requires an unprivileged user, read-only source mounts at `/probe`, `/baseline` and `/candidate`, no network, no GPU, a private noexec tmpfs, 512 MiB or less RAM, one CPU and at most 64 PIDs. A fresh deadline of at most 120 seconds is mandatory. No unpickling, Torch loading or callable execution is used.

`linux_p4_tests.py` preserves the frozen v22 baseline and checks P4 FRAME/memo/alias/Parameter/storage proofs. `linux_ascii_tests.py` compares the separate pre-ASCII candidate and checks the exact ASCII-only extension, including vendor-disagreement refusal. Baseline copies are test references, never production entrypoints. Test assertions are not independent trained models or malware accuracy measurements.

Public originals, derived structural controls and the historical 200-case suite must be scored separately. Component acceptance does not establish full AV, MatrixHub application, KIND or official E2E acceptance. Keep their separate, source-bound run evidence; a component PASS is not a release or general model-safety claim.

## Current R24 source qualification

The locally installed scanner source is `6062a3f95ab8...`, generation `199637ceef4c...`.
See [CURRENT_R24_QUALIFICATION.json](CURRENT_R24_QUALIFICATION.json) for exact identities and terminal evidence. This records a bounded local qualification, not an online publication or a general model-safety claim. ROOT controls the final DCO/commit.

`repro6062-preparation` is an immutable preparation snapshot. Its `qualification-pending.json` and README describe the earlier preparation time; their PENDING/not-installed statements are historical, not the current qualification status. Do not rewrite that packet. Its 47/84/34 Linux-only entries reproduce 165 controlled static assertions; the separate independent holdout has 12 assertions. These are not 177 real models. The declared two missing-record deltas and earlier 84-case delta remain explicit.

For source6062, the original 200-case fullAV run was technically PASS with **192/200 original oracles matched**. The same eight historical mismatches remain. Comparisons against both frozen baselines found no new semantic regression: all 100 benign controls allowed and all 100 prior denials retained. Fresh MatrixHub/KIND APP5 passed its three risk scenarios, six clean inputs, 36 full GET/SHA checks and four P4 structural controls. This is a separate application test, **not a new execution of the complete official 187-test suite**.

The two controlled masked-missing cases (positive storage absent together with zero-byte storage or an extra record) changed from old complete-allow observations to incomplete denial with `invalid_serialization`. In contrast, all three public normal artifacts, CUNI/SASRec/YOLO, still had incomplete/refused admission. No public-native-P4 false-rejection reduction or population accuracy claim follows.

No attributable algorithm speedup is established here. The synthetic SFT comparison measures overall scanning throughput under shared inputs/resources; A executes a G: host read-only source bind and B image-overlay source, so source placement is a confound. Product fullAV, pre/post SHA and rules checks remain inside request timing. Final observations are recorded separately in [r24_results/final-observations.json](r24_results/final-observations.json), with repeated requests, NOT_RUN derivatives and resource denials explicitly separated. The ResNet six-scan experiment remains FAIL; its original file passed. The single DistilBERT original passed three full scans. The ZIP-resource case reached its bounded rejection target; it is not completed AV or malware TP.

## Historical 7cd 118-check entry

The command below remains the frozen 7cd-only 84+34 entry. It must not be used as evidence for the current6062 source. Use the separately documented, ROOT-supervised `repro6062-preparation` 47/84/34 entries with externally verified installed-source and snapshot bindings instead; do not run fixture generators on the host.

## Run the component suite

The host runner defaults to Describe and reads no source or Docker state. With `--execute`, it uses a separate empty Docker configuration, starts only containers labeled with the new run ID, and removes only a container whose full ID, owner, name and image match. An ambiguous create or cleanup result is a failure. It never pulls an image or reads an existing Docker login.

Use a locally built scanner image with Python 3.13.16 and Picklescan 1.0.5. The native ClamAV service is not started by this suite. Keep the exact source bytes; the repository disables Git text conversion because the tests bind file hashes.

From `source/deploy/security-scanner`, a Windows example is:

```powershell
python p4_semantics/run_container_tests.py --execute --heavy-idle-confirmed --docker "C:\Program Files\Docker\Docker\resources\bin\docker.exe" --engine npipe:////./pipe/dockerDesktopLinuxEngine --image matrixhub-scanner:local --output "G:\semantic-component-run-001"
```

Use a fresh output directory. On Linux, use the absolute path to the Docker CLI and `--engine unix:///var/run/docker.sock`. Run `python -m unittest discover -s p4_semantics -p test_runner_contract.py` for the host lifecycle tests; those tests mock Docker and use harmless local child processes, not model artifacts.

The two container suites contain 84 P4 checks and 34 ASCII checks. These totals include assertions and controlled variants, not 118 independent model samples. Per-suite JSON receipts and the summary distinguish component acceptance from full AV, MatrixHub or KIND acceptance.

## Verified installation snapshot reproduction

After installation, ROOT verified the complete source SHA and held-file identity of the real checkout and a distinct, one-code-file snapshot before and after each fresh Linux container. The packaged 47/84/34 suites passed again using that verified snapshot; [r24_results/installed-source-repro.json](r24_results/installed-source-repro.json) records the three new receipts. These are reproduction checks of the same 165 assertions, not additional samples or a new fullAV/application run. The immutable preparation packet and earlier result references remain unchanged.
