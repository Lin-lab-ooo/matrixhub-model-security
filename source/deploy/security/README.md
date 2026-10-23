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

## Start with verified rules and a preflight

Build the two local images above. Use Python 3.11+ and Docker Compose v2.
The setup wrapper never pulls an image, reads an existing account, or generates
an administrator password automatically. First initialization prompts for a new password
through getpass (or anonymous stdin), never a flag/environment value. Give each deployment a fresh state directory and a
unique `mh-sec-*` project name. From the source root:

```sh
python scripts/newsetup/setup.py start --initialize-admin \
  --rules-source /srv/downloaded-official-cvd \
  --rules-store /srv/matrixhub/rules \
  --state /srv/matrixhub/deploy-demo \
  --project mh-sec-demo
```

The source directory must contain complete official `main.cvd`, `daily.cvd` and
`bytecode.cvd` files. The tool verifies each CVD with the local ClamAV 1.4.6
`sigtool`, loads the complete ruleset with `clamscan`, hashes every byte, checks
freshness and rollback, seals a new versioned directory, and atomically publishes
an external manifest pointer. It then checks effective Compose permissions and
resources, initializes this deployment's three volumes, and waits for the API and
scanner Unix socket. The scanner receives an absolute expiry derived from the
verified daily database time. Expiry and rules changes fail closed.

The default freshness SLA is seven days; `rules_snapshot.py prepare
--max-age-days 1` can impose a stricter policy. A trusted host clock is required.
The unkeyed JSON manifest detects corruption; signature verification and complete
engine loading establish the official database provenance. Every start repeats
verification. A prepared directory is never updated in place.

The snapshot measured during v15 preparation expires at Unix `1793168749`
(2026-10-28 06:25:49 UTC). For an October 29 demonstration, perform a normal
update/prepare with all existing CDN cooldown state preserved, verify signatures
and age again, then test the new actual generation. Do not disable expiry or
reuse the earlier green result. This setup's fresh administrator path covers
SQLite Compose; Helm/MySQL retains its separate Secret/bootstrap requirements.

Use `check` instead of `start` to run preflight without starting long-running
services, and `status` to check the running deployment. Preflight uses temporary,
networkless verification containers and writes only public deployment metadata.
Temporary containers have unique ownership labels and are removed on failure.
A failed start stops only this deployment's owned services and retains its data.
The API/UI binds `127.0.0.1:3002` and SSH `127.0.0.1:2223`; choose unused ports
with `--http-port` and `--ssh-port` when another local deployment already exists.
The first command privately migrates only this new owned SQLite database, checks
the exact initial schema/seed/session state and empty user-content tables, then
sets the password and a deployment marker in one transaction. The API has no
published port until this succeeds. Native bcrypt in the target image must pass
a public known-answer probe and a random-salt self-check; passwords are limited
to 14–72 UTF-8 bytes and are not truncated. No host bcrypt/DPAPI/SDK dependency is
needed. Failure to disable terminal echo is a hard error.

Use `initialize` instead of `start --initialize-admin` to set the first password
and leave services stopped. A later `start` omits `--initialize-admin`: it verifies
the owned database marker and administrator metadata without reading the password
hash. Repeating initialization or finding an existing non-seed account is refused;
this command is not an account reset tool. A lost host checkpoint after a committed
DB initialization is recoverable with `start`, using the same password. For an
approved noninteractive secret provider, add `--password-stdin` only during first
initialization; do not put the password in arguments, shell history, environment,
configuration, logs or evidence. Keep persistent volumes across normal restarts.

Validation checkpoint: earlier45 offline/pure contracts passed; the resource-unit parser correction passed33 setup unit tests. The [actual fresh v2](../../../evidence/v15/fresh-init-typed-v2-initialized-start-failure-receipt.json) initialized a new72UTF8B Unicode password and reverified complete rules, but subsequentstart failed (whole56.906s, normalLoginfalse, ownedcleanup true). A new diagnostic-only attempt is separate. These commands are the implemented candidate path; full normal Go login/restart and a fresh-machine deployment PASS are not claimed. Existing instances are not reset to bypass this failure.

For a trusted network update, first inspect any existing CDN cooldown gate. Then
run **one** explicit updater attempt with that gate's Unix timestamp:

```sh
python scripts/newsetup/rules_snapshot.py update \
  --store /srv/matrixhub/rules --network-not-before UNIX_EPOCH_FROM_EXISTING_GATE
```

Use `0` only after checking that no earlier cooldown is active. This separate
non-root FreshClam job has network access; the deployed Compose scanner has none.
The updater preserves only its own SHA-bound `freshclam.dat`, imposes a 24-hour
minimum attempt interval, and retains FreshClam's longer cooldown state. A failed
or incomplete download cannot activate a snapshot. Never clear a CDN cooldown to
force a retry. Air-gapped installations can import the three official CVD files
with `rules_snapshot.py prepare --source ... --store ...` instead.

After preparing a new snapshot, rerun `setup.py start` with the same deployment
state and project to recreate the scanner. Changed rules/expiry change its
generation, so previous approvals cannot authorize a new scan. Old snapshots
remain for investigation; selecting an older ruleset is subject to freshness and
anti-rollback checks. No network updater runs inside the scanner.

The init service is the only UID 0 process, runs without network on a read-only
root filesystem, and receives only `CHOWN` and `FOWNER` for this composition's
three volumes. The API and scanner run as UID/GID 65532 with all capabilities
dropped. Rules are read-only; staging is writable only by the API; the scanner
socket has mode 0660. No privileged container or world-writable data directory is
used. The default budget is 3 GiB for the scanner, 4 GiB for the API, at least
8 GiB assigned to Docker and 10 GiB host free space. Keep one API/staging owner;
`--native-threads 2` or `4` gives the bounded clamd worker matching CPU resources.
This is internal parallelism, not permission to share staging across replicas.

See [the Chinese quickstart](QUICKSTART.zh-CN.md),
[the history UI acceptance guide](../../scripts/newsetup/UI_ACCEPTANCE.md), and
[the security Helm chart](helm/README.md). Large-repository profiles have separate
quota and physical-disk budgets; the standard defaults remain unchanged.

## Test the actual application

The older `scripts/security/e2e.py` and `workload.py` are historical source
acceptance harnesses. Their credential
interface is an explicitly named environment variable; it does not provide the
new stdin-only deployment bootstrap. Do not pass production credentials to it or
confuse it with the current owned-fixture receipts. Install the official Hugging
Face client in a dedicated virtual environment.
The v15 small-application and exact1GiB fixtures pinned
`huggingface_hub==1.29.0` and `httpx==0.28.1`, with four SDK source hashes checked
before credentials were created. The exact lock and public receipts identify
that runtime. Older harness environments retain their historical version labels. The real client uses
`create_repo`, `upload_file`, `model_info` and `hf_hub_download` APIs.

They are not the stdin-only first deployment command above. Consult their
explicit CLI contracts for a dedicated disposable test account; an omitted
credential setting is not a runnable acceptance recipe. Current public v15
receipts and their workload identities are linked from the repository evidence
index. No fresh-machine acceptance is inferred from these older harness files.

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

## Roadmap alignment

The [official roadmap](https://github.com/matrixhub-ai/matrixhub/blob/main/ROADMAP.md)
identifies malicious-content scanning, audit logging, model signatures and
controlled releases as governance work. This contribution focuses on complete
content evidence, recorded scan/download decisions, append-only human review,
and server-enforced access to immutable revisions. CVD verification authenticates
antivirus rules. The exported JSON manifests are unsigned integrity records;
model-producer signing, identity-key lifecycle and a full promotion/tag-locking
workflow remain separate work. This local contribution does not claim completion
of the roadmap's full platform audit or upstream maintainer recognition.
