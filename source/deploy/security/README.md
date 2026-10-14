# MatrixHub artifact security contribution

This is a real MatrixHub fork with asynchronous ClamAV/Picklescan analysis,
immutable byte evidence and admission on supported download transports.
See [the design](../../docs/security/design.md),
[threat model](../../docs/security/threat-model.md), and
[scanner validation](../../docs/security/scanner-validation.md).

## Build from source

The tested target is Linux/amd64, including Docker Desktop's Linux engine.
Prerequisites are Go 1.26.8, GCC, Node.js (tested 24.15.0), pnpm 10.17.0,
Python for acceptance tests, and Docker Compose. Download Go and Node.js only
from their official distribution sites and verify the published checksums.
Do not use the host Windows binary as the Linux container executable.

From the repository root on Linux:

```sh
cd ui
pnpm install --frozen-lockfile
pnpm build
cd ..
mkdir -p bin
CGO_ENABLED=1 go build -trimpath -buildvcs=false -o bin/matrixhub-security ./cmd/matrixhub
docker build -f deploy/security/Dockerfile.runtime -t matrixhub-security:local .
docker build -t matrixhub-security-scanner:1.4.6 deploy/security-scanner
```

On exFAT, pnpm's default isolated linking is not supported. Use
`pnpm install --frozen-lockfile --config.node-linker=hoisted`; this does not
change dependency versions. The tested Go binary was compiled inside a Linux
container with a checksum-verified official Go archive and GCC.

## Start the isolated deployment

First download a **complete** versioned ClamAV rules snapshot using the trusted
updater described in [the scanner README](../security-scanner/README.md).
The scanner cannot update itself because it has no network. Set the absolute
directory containing `main.cvd`, `daily.cvd` and `bytecode.cvd`:

```sh
export SCAN_RULES_DIR=/absolute/path/to/rules-2026-10-08
docker compose -f deploy/security/compose.yaml config
docker compose -f deploy/security/compose.yaml up -d
curl --fail http://127.0.0.1:3002/healthz
```

PowerShell uses `$env:SCAN_RULES_DIR='C:\absolute\rules-2026-10-08'` instead.
The application UI/API listens on loopback port 3002; SSH listens on loopback
2223. The scanner has a Unix socket, no published port and no network.
The trusted init service initializes only this composition's three volumes.

Log in using your local MatrixHub administrator account and create a private
project/model. Upload succeeds immediately. Downloads remain denied while
analysis is pending/scanning or incomplete, then use verified snapshots after
complete approval. View the security card on the model detail page to inspect
findings, immutable history and audit decisions. Rescan/cancel require model
push permission; policy updates require model settings permission.

For a new deployment, follow MatrixHub's normal initial administrator setup
and change its bootstrap password. Test credentials are supplied only through
environment variables, never included in source release archives or reports.

## Test the actual application

Install the official Hugging Face client in a dedicated virtual environment.
The acceptance harness was tested with `huggingface_hub==2.1.1`; the exact
environment lock is included in the release evidence. It uses the real
`create_repo`, `upload_file`, `model_info` and `hf_hub_download` APIs.

```sh
export MATRIXHUB_E2E_PASSWORD='your-local-test-password'
python scripts/security/e2e.py --output-dir /tmp/matrix-security-e2e
python scripts/security/workload.py --mode benchmark --docker-observe \
  --output-dir /tmp/matrix-security-benchmark
python scripts/security/workload.py --mode soak --duration-hours 12 \
  --docker-observe --output-dir /tmp/matrix-security-soak
```

Use a new output directory for each execution. Tests create distinct private
projects and revoke their access tokens at the end. The EICAR standard test
string stays in memory; host antivirus settings are never changed. Dangerous
Pickle fixtures contain inert global references without invoking them. Nothing
is unpickled, imported, or loaded into a model framework.

The benchmark covers 8, 32 and 33 files; 1 MiB and 8 MiB files; and a file just
below the 64 MiB coverage cap. It measures upload time, queue-to-report time,
real cache reuse, force-rescan behavior and concurrent verified reads. Capacity
fixtures are inert ASCII `.txt` files; these measurements do not claim that
every large model format is supported. Container observations are sampled
resident usage, not a resettable per-case peak measurement.

Run domain/store/adapter checks and actual isolated engine checks as described
in the design and scanner validation documents. The existing upstream default
unit test selection excludes the HF package's incomplete legacy fixture setup;
the new HF security tests are run explicitly. Do not treat unrelated skipped
or failed upstream integration tests as passes.

## Limits

Defaults are 64 MiB/file, 256 MiB/task, 1,000 files/task, one worker,
two-minute task deadline, 150-second lease and 2 GiB retained logical content.
Staging additionally limits retained file/directory entries, including empty
snapshots. These application quotas are not a physical filesystem block quota.
Historical snapshots are retained; reaching the quota fails closed and requires
offline report-aware cleanup. One process owns a staging root.

Strict mode disables raw HTTP/SSH Git fetch, historic patches and global LFS
downloads because those entry points cannot filter every reachable object.
Supported HF/LFS/native file endpoints preserve HEAD and Range behavior.
Rules changes invalidate approvals. Errors remain denied even in audit mode.
ClamAV and the wrapper are trusted processes in one container; a compromised
scanner may forge verdicts within that boundary. This is not a microVM sandbox.

## Submission status

The source, design, deployment, tests and demo form the local submission.
Public upstream issue/design discussion and effective maintainer recognition
are separate competition requirements. No such recognition is claimed before
it actually happens, and no external publication is performed automatically.
