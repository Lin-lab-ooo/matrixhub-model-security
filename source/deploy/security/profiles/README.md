# Large repository capacity profile

`large-repository.json` and `helm.large-repository.yaml` describe a **multi-shard
repository** with a 110 GiB task budget. They do not enable a 100 GiB single file.
Every file remains limited to 1280 MiB, must finish complete AV and format checks,
and retains complete pre/post SHA-256 and descriptor validation. Unsupported,
compressed-over-budget, damaged, canceled and incomplete inputs remain denied.

The acceptance workload's 100 GB means decimal **100,000,000,000 bytes in 373
files**, not 100 GiB. The current 1280 MiB scanner policy is also distinct from
ClamAV's technical 2,147,483,645-byte ceiling. Report `scannedBytes` includes
cached file sizes; claim actual native scanning only with zero-cache evidence
or the independent request-level native records.

| Budget | Value |
| --- | --- |
| Per file | 1280 MiB |
| Scanner complete scan cap | 1536 MiB |
| Expanded members | 128 MiB, depth 3, members 256, ratio 100 |
| API task | 110 GiB |
| Retained staging logical content | 120 GiB |
| Batch | up to 8 files and 5 GiB; actual advertised scanner limits still apply |
| Task deadline / lease | 1 hour / 1 hour 30 seconds |
| Active API claims | 1 |
| Native clamd workers | 2 by default; large profile permits 1 or 2 |
| Scanner / API resource ceilings | 8 GiB / 4 GiB |

At the 110 GiB task limit, the source LFS copy and sealed staging copy require
220 GiB together. The setup preflight additionally reserves 70 GiB: at least
290 GiB free on each target storage filesystem. This is deliberately conservative
when targets use separate filesystems. Public input downloads, filesystem
metadata, rules, temporary files and retained older source versions add storage
consumption. The 5 GiB batch limit is **not** a peak staging claim: immutable scan
snapshots remain retained, and staging's 120 GiB quota is logical content rather
than a filesystem block quota. Monitor real free blocks; quota/ENOSPC errors fail
closed. The standard 64 MiB/256 MiB task profile is unchanged.

Use a new deployment and dedicated, initially empty source and staging directories
on a POSIX filesystem. For a Linux machine with sufficient resources:

```sh
python scripts/newsetup/setup.py start --initialize-admin \
  --profile large-repository \
  --rules-store /srv/matrixhub/rules \
  --state /srv/matrixhub/deploy-large --project mh-sec-large \
  --data-dir /srv/matrixhub/data-large --staging-dir /srv/matrixhub/staging-large
```

The first invocation prompts for a new administrator password before publishing
the API. Later starts use the same state/project without `--initialize-admin`;
reinitialization never resets an existing account. Bind-based first initialization
must run on a Linux host, with the real filesystem probe below; Windows host
paths are not accepted as evidence of Linux ownership.

The wrapper records ownership and refuses another deployment's or a pre-existing
nonempty directory. It checks the effective bind source/target pair before the
limited init can touch it. A real container probe then initializes only those
owned roots, drops to UID/GID 65532, and tests mode 0750 directories, creation,
write/fsync, `fchmod(0440)`, full probe hashing and stable open/reopen identities.
Failure produces `posix-permissions-or-stable-fd-unavailable-use-linux-ext4`.
There is no permission-widening fallback and no Docker storage migration.

**Windows/exFAT boundary:** a G-drive bind path alone does not establish POSIX
semantics. The current host's actual low-privilege probe allowed write/fsync but
returned EPERM for `fchmod(0440)`. Do not use that host-bind route for this workload.
Use a Linux ext4 filesystem inside a separately owned VM disk stored on G instead,
and run the deployment inside that Linux environment. Do not move large data into
Docker Desktop's C-drive named volumes as a workaround. Path syntax is not proof
that a storage backend passes the contract.

The resource ceilings are capacity settings, not a promise that a host currently
has that much available memory. This machine had about 13 GiB free before the
large acceptance run; an 8 GiB scanner plus 4 GiB API leaves little overhead.
Run the large workload separately from the 8 GiB acceptance VM or other heavy
jobs. A smaller real pilot may explicitly use lower resource ceilings after
review; report actual OOM/timeout/ENOSPC failures, throughput and sampled usage.
Increasing a deadline is not evidence of faster scanning. No GPU acceleration is
claimed.

For Helm, merge `helm.large-repository.yaml` after the public values generated
from the verified rule snapshot. The cluster must provide 120 GiB dedicated data
and staging PVCs with the same filesystem contract. The chart uses one Pod with
Recreate; it does not authorize another API replica to share staging. A manifest
render or storage-class name alone does not prove that the bound CSI filesystem
implements the required permission and FD behavior.

The1280MiB single-file cap excludes a1,503,300,328-byte Qwen artifact. A future1920MiB profile would require a new generation and actual native/application validation; it is not enabled here. The real NeoX preparation selects native4/batch2 in its separate acceptance contract, with only two native scans active; it does not change this deployment profile default.

## medium-capacity

`medium-capacity.json` covers one file up to 512 MiB and one task up to 2 GiB on
either storage backend. Per-file limit, task limit, timeouts and every scanner
environment value come from this single file, and the file also carries the
`scannerEnvelope` it must stay inside; the wrapper refuses an inconsistent
profile before starting anything. The later startup phases use the standard
scanner memory ceiling of 4 GiB, so this profile does not need the large
deployment's 8 GiB scanner or 13 GiB Docker memory.

Typical use:

```sh
python scripts/newsetup/setup.py start --initialize-admin \
  --profile medium-capacity --storage volumes --rules-backend ram \
  --rules-source /srv/downloaded-official-cvd --rules-store /srv/matrixhub/rules \
  --state /srv/matrixhub/deploy-medium --project mh-sec-medium
```

The suite's coverage fixture (`--stage-limit-bytes`) must exceed the deployed
per-file limit; with this profile pass `--stage-limit-bytes 0` and use
`--large-clean-bytes` for the capacity case instead.

## capacity-ramp

`capacity-ramp.json` runs the same 1280 MiB per-file ceiling as
`large-repository` on Docker named volumes, so a multi-GiB chain can be executed
without a POSIX host bind. It is a bounded ramp profile, not a 100 GB
qualification: named-volume capacity is limited by the Docker disk image, and the
full 100 GB workload still needs a POSIX filesystem with two complete copies plus
reserve (about 290 GiB) under `large-repository`.

The scanner wall budget is fixed at 300 s per batch. Measured effective scan
throughput on this host is roughly 8 MiB/s per file, so this profile caps one
batch at 1 GiB and one file, while `large-repository` keeps the 5 GiB / 8-file
batch that assumes at least ~17 MiB/s sustained. A batch that cannot finish inside
the wall budget fails closed as `scan_timeout` instead of being reported as
approved; size the batch from the measured throughput of the deployment host.
