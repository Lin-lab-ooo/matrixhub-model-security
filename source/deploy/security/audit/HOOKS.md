# Hub integration: two calls, three boundaries

The audit package exposes exactly two functions (`hooks.py`). The Hub keeps its own
database as the authority; markers are a cache that must match the artifact.

## Boundary 1 - after the file scanner passes

Only when the revision is sealed and the scan row is `pass + complete` for the same
content, enqueue the audit **in the same transaction that stores the scan result**
(insert a `pending` audit row), then a small dispatcher writes the queue file:

```python
from hooks import enqueue_audit

# inside the "scan completed" handler, after the row is committed as pass+complete
audit_row = db.insert_audit(revision=rev, model_digest=manifest_digest,
                            state="pending", policy_version=POLICY_VERSION)
enqueue_audit("/srv/matrixhub/audit-queue", rev.id, rev.snapshot_path, rev.base_path)
```

Dispatcher (cron or loop) retries any `pending` audit row whose queue file is
missing, so a crash between commit and enqueue cannot lose the task.

## Boundary 2 - audit worker publishes the decision

`audit_worker.py` claims a queue item atomically (`rename` to
`.processing.<attempt>`), runs `audit_pair.py`, converts through `gate.py` (which
validates completeness and stamps the content binding), writes
`report/<revision>/status.json`, then the Hub copies `decision`, `binding`,
`policyVersion` and `reportDigest` into its audit row. A marker is written next to
the snapshot only as a compatibility projection; the database row stays authoritative.

Infrastructure failure (worker crash, OOM, timeout) sets `state=failed`, requeues
while retries remain, and finally moves the admission state to `review` - never to
`allow`, and never to `deny` as if a backdoor had been found.

## Boundary 3 - before any model byte is served

One common admit function, called before body bytes, before `206`, before `304`,
before LFS action links, before signed URLs and before archive streaming:

```python
from hooks import check_download
from gate_guard import AuditDenied

def admit(model_dir, audit_row):
    expected = {"modelDigest": audit_row.model_digest,
                "auditVersion": audit_row.audit_version,
                "policyVersion": audit_row.policy_version}
    try:
        check_download(model_dir, expected)
    except AuditDenied as error:
        return Response(status_code=403, json={"error": str(error)})
```

Admission state mapping:

| state | GET/HEAD/Range | status query |
|---|---|---|
| `pending` | 403 `audit_pending` | 200 `{state, progress}` |
| `deny` | 403 `audit_denied` | 200 `{state, evidence}` |
| `review` | 403 `audit_review` | 200 `{state, reason}` |
| `allow` | normal streaming, still subject to scanner and auth | 200 |

HEAD returns no body but must not bypass the check; conditional requests must not
turn a stale `ETag` into a `304` when the current decision is deny.

## Human review

Reviewers act through an authenticated Hub endpoint that appends a new decision
(reviewer, time, reason, evidence digest, policy version). The machine report is
never edited. The new decision is bound to the same content digest; a review cannot
override an AV failure, a broken report, or a digest mismatch.

## Local capability note

The laptop GPU (8 GiB) can only audit small models at full precision. 4B/8B require
the cloud worker or a separately validated quantised profile; a quantised profile is
a distinct identity with its own thresholds and must not inherit full-precision
conclusions.

## Minimum tests

1. missing / corrupted / foreign-digest marker -> 403
2. scanner pass + audit pending -> GET, HEAD, Range all 403
3. allow -> bytes match, Range returns correct 206
4. allow then decision revoked with ETag present -> no 304 bypass
5. worker killed mid-run -> item recovered, state not `allow`
6. old worker returns late -> does not overwrite the new attempt
7. base/tokenizer/audit-config change -> old marker/cache no longer authorises
8. LFS batch, archive, Git/SSH, signed URL -> no bypass; unsupported paths refused