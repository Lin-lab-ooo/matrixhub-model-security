# Single-writer security Helm chart

This independent chart packages one API and one scanner in **one Pod**, retaining
the existing Unix-socket and immutable snapshot protocol. It does not modify the
upstream general-purpose chart. Use source-built candidate images containing the
candidate binary, migrations, UI assets and scanner code; cached old UI assets
cannot validate a new UI. The default pull policy is `Never` so offline image
provisioning is explicit.

**Network boundary:** containers in a Pod share its network namespace. The
scanner can reach the DNS and MySQL endpoints allowed for this Pod. This is not
the Compose scanner's `network_mode: none` isolation. The chart emits a default
Egress deny policy with only kube-system/kube-dns TCP+UDP 53 and an exact MySQL
namespace+pod selector on TCP 3306. It contains no broad namespace selector,
0.0.0.0/0 rule, hostNetwork, hostPath, NET_ADMIN or privileged workaround. A
NetworkPolicy object existing does not prove enforcement; validate the chosen
CNI's actual denied and permitted connections before a production claim.

Prepare complete, verified rules with `scripts/newsetup/rules_snapshot.py`.
Provision a dedicated rules PVC containing exactly the three CVD files from the
selected immutable snapshot, read-only to this Pod. Supply an **existing** Secret
with the MySQL DSN under `matrixhub.dsn`, and an existing MySQL workload. Secret
values stay out of chart values, rendered manifests and scanner environment.
The rule verification init re-hashes the actual PVC files, verifies every CVD
signature, loads the full ruleset to compare signed internal metadata, and checks
the absolute daily-derived expiry. The regular scanner receives that same expiry.

Generate public deployment values without typing a rule hash or expiry:

```sh
python scripts/newsetup/helm_values.py \
  --rules-store /srv/matrixhub/rules --rules-claim my-verified-rules \
  --database-secret my-database-dsn --database-namespace my-database \
  --database-label app=my-mysql --output /srv/matrixhub/security-values.json
helm lint deploy/security/helm -f /srv/matrixhub/security-values.json
helm template mh-sec-demo deploy/security/helm --namespace mh-sec-demo \
  -f /srv/matrixhub/security-values.json > /srv/matrixhub/security-rendered.yaml
```

The generator only references Secret names. It uses the verified manifest and
preserves the deployment ID when regenerating the same output for an upgrade.
Review public rendered resources, provision images and PVCs, then install into a
new owned namespace. Cluster credentials and Secret contents must be supplied
through the operator's approved setup channel, not checked into these files.
No hook creates or changes an existing account.

The chart fixes replicas to one and strategy to Recreate. API and scanner run as
UID/GID 65532, root filesystem read-only, all capabilities dropped, no privilege
escalation, RuntimeDefault seccomp, and no service account token mount. Staging
is API-RW/scanner-RO; rules are scanner-RO; the API's socket-directory mount is RO.
A deterministic root init only chowns/chmods the dedicated data, staging and
socket roots, with CHOWN/FOWNER; it never sees rules or Secret content. This init
requires an admission policy allowing that narrow initialization step; it is not
compatible with a policy that rejects all UID-0 init containers. Do not broaden
runtime capabilities to accommodate it. The scanner creates its socket as 0660.
A separate low-privilege init performs a real POSIX directory/file seal/hash/FD
probe on data and staging; a storage class that cannot implement it fails startup.
API readiness plus scanner bundle readiness gate the whole Pod.

Default dedicated data/staging PVCs are 8 GiB/4 GiB. Created PVCs have the Helm
`keep` policy, so uninstall retains model data and scan evidence. Reuse only this
deployment's dedicated existing claims; manually clean retained claims only after
report-aware review. The rules PVC must remain immutable while mounted. For an
update, provision a new verified rules PVC/snapshot, regenerate values and perform
a Recreate rollout. The new generation invalidates prior approvals. The chart's
job server is disabled for this controlled direct-upload profile; general proxy,
replication and platform scheduling need separate network and integration review.

For large multi-shard repositories, merge
`../profiles/helm.large-repository.yaml` after generated values and reserve the
physical two-copy/retention budget described in [the capacity guide](../profiles/README.md).
Do not equate a 100 GiB repository with a 100 GiB supported single file. Actual
filesystem semantics, CNI enforcement, application flows and cancellation must be
verified against the deployed cluster.

Local static check (requires the UI's locked `js-yaml` dependency and Helm 3.19):

```sh
node scripts/newsetup/test_helm.mjs /path/to/helm /existing/public/test-output
```

Its 14 contracts cover effective security fields and rejected unsafe values.
Those tests use dummy public rule metadata and never claim a real signature,
engine, cluster or business-flow PASS. The actual acceptance receipt is separate.

## ROOT candidate KIND integration

Use a fresh owned namespace and VM/ext4 storage. Load the candidate app/scanner
images into the already owned node, prepare the verified rules PVC and the
existing MySQL DSN Secret through the fresh RAM-secret channel, then generate
public values for their names. Match `database.namespace` and `podSelector` to
the actual new MySQL labels. For a local NodePort fixture, set `service.type` to
`NodePort` and `publicURL` to the actual owned node URL/port. The new chart expects
`/data`, `/input`, `/run/matrix-security` and `/rules`; it does not use the v14
external scanner's host socket or acceptance-only runtime hostPaths. If testing
an unchanged cached image with a public runtime overlay, first build a candidate
image or explicitly extend the fixture's reviewed immutable overlay mechanism.
Never describe a successful old external-scanner run as acceptance of this chart.
Record actual init, Ready, rules generation, app scenarios and cleanup outcomes.

The first actual candidate run `32be9` passed deployment (73.004666 s), fresh
rules identity and positive/negative network probes from both API and scanner.
Its overall result was FAIL after an auxiliary-Pod deletion timeout, before
application acceptance. This proves that run's observed shared-Pod network
boundary, not a complete chart/application pass. Subsequent typed v2/v3 runs retained APP18/CNI/ready component successes but still failed strict NodePortRSA readiness. The independent [typed v4 receipt](../../../../evidence/v15/typed-kind-v4-strict-pass-receipt.json) is actual **PASS461.484s**, source37d/freshGEN6b355: APP8+SDK10, real CNI allow/deny, same-Pod two ready/zero-restart checks, both SSH roles with matching canonicalRSA and cleanup. Hostname failure then exactowned IPv4 success is observed, without claiming a unique NSS cause. This is Pod-level isolation and unauthenticated SSH readiness; it does not prove per-container isolation, SSH authorization, complete original187 or41GB capacity. The public package does not include the same offline VM orchestrator; general MySQL Secret/bootstrap prerequisites above still apply.
