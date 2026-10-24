# Bounded P4 and ASCII semantics regression tests

These are Linux container tests. Do not generate model or attack fixtures on the host. The guard requires an unprivileged user, read-only source mounts at `/probe`, `/baseline` and `/candidate`, no network, no GPU, a private noexec tmpfs, 512 MiB or less RAM, one CPU and at most 64 PIDs. A fresh deadline of at most 120 seconds is mandatory. No unpickling, Torch loading or callable execution is used.

`linux_p4_tests.py` preserves the frozen v22 baseline and checks P4 FRAME/memo/alias/Parameter/storage proofs. `linux_ascii_tests.py` compares the separate pre-ASCII candidate and checks the exact ASCII-only extension, including vendor-disagreement refusal. Baseline copies are test references, never production entrypoints. Test assertions are not independent trained models or malware accuracy measurements.

Public originals, derived structural controls and the historical 200-case suite must be scored separately. Component acceptance does not establish full AV, MatrixHub application, KIND or official E2E acceptance. Keep their separate, source-bound run evidence; a component PASS is not a release or general model-safety claim.

## Run the component suite

The host runner defaults to Describe and reads no source or Docker state. With `--execute`, it uses a separate empty Docker configuration, starts only containers labeled with the new run ID, and removes only a container whose full ID, owner, name and image match. An ambiguous create or cleanup result is a failure. It never pulls an image or reads an existing Docker login.

Use a locally built scanner image with Python 3.13.16 and Picklescan 1.0.5. The native ClamAV service is not started by this suite. Keep the exact source bytes; the repository disables Git text conversion because the tests bind file hashes.

From `source/deploy/security-scanner`, a Windows example is:

```powershell
python p4_semantics/run_container_tests.py --execute --heavy-idle-confirmed --docker "C:\Program Files\Docker\Docker\resources\bin\docker.exe" --engine npipe:////./pipe/dockerDesktopLinuxEngine --image matrixhub-scanner:local --output "G:\semantic-component-run-001"
```

Use a fresh output directory. On Linux, use the absolute path to the Docker CLI and `--engine unix:///var/run/docker.sock`. Run `python -m unittest discover -s p4_semantics -p test_runner_contract.py` for the host lifecycle tests; those tests mock Docker and use harmless local child processes, not model artifacts.

The two container suites contain 84 P4 checks and 34 ASCII checks. These totals include assertions and controlled variants, not 118 independent model samples. Per-suite JSON receipts and the summary distinguish component acceptance from full AV, MatrixHub or KIND acceptance.
