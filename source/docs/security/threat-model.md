# Security analysis threat model

## Attacker capabilities

An authenticated uploader may control file names, Git blobs, LFS pointers,
archive members and serialized model bytes. A client may move branches, reuse
old LFS actions, request alternate content routes, trigger rescans or race
cancellation and policy changes. A scanner may become unavailable, hit a
resource limit, crash, or change its rule generation during a task.

The application database, trusted staging writer, container runtime and host
administrator are trusted. A compromised host or administrator that can alter
the process and rules is outside this boundary. Engine correctness is limited
to the selected engines and pinned rules; scanning is not a proof that arbitrary
code is safe to execute.

The scanner wrapper and selected engines are trusted to report their actual
results. Resource isolation is not a separate per-tenant security boundary:
the supervisor and parsing child currently share a container and UID. A fully
compromised scanner could forge future analysis responses. Read-only input and
rules, absent application credentials, blocked network, and dropped capabilities
limit its access to the main service and source repository; they do not prove
scanner-process integrity. Separate disposable containers or a microVM pool
would require an external orchestrator and new validation. The API does not
receive a Docker socket.

## Prevented failure classes and evidence

| Failure class | Control | Verification |
| --- | --- | --- |
| Clean pointer, different LFS content | Stream length and SHA256 comparison | Real Git/LFS adapter tamper tests |
| Ref changes between scan and download | Immutable commit and snapshot | Branch movement handler/adapter tests |
| File changed after report | Same-descriptor integrity check | Snapshot tamper rejection tests |
| Alternate route bypass | HF, native, LFS gate; strict raw Git/diff restrictions | Transport tests and planned client E2E |
| Partial engine coverage mistaken for clean | Complete manifest and generation requirements | Domain/DB tests plus scanner tests |
| Late worker overwrites new report | Lease token + monotonic attempt CAS | Expiry/cancel/rescan DB tests |
| Tenant evidence reuse | Stable project:model IDs and RBAC | Scope/recreation tests and planned E2E |
| Archive/resource exhaustion | Prechecks plus container/child limits | Actual limit/fault tests |
| Rules change during work | Bundle identity checked before and after work | Domain/scanner generation tests |
| Audit mode silently skips required engines | Incomplete content always denied | Domain and transport tests |

## Information handling

Reports contain paths, digests, sizes, findings, versions, timing and remediation.
They do not embed file payloads, pickle opcode content, request credentials,
scanner stderr or tokens. A scanner error returned to clients is a bounded
generic failure. REST responses are private and non-cacheable. All policy and
evidence access follows project authorization.

## Residual limits

Mature engines can miss novel threats. Archive limits and unsupported formats
may produce failed coverage. Raw Git fetch is restricted rather than filtered.
Initial large-file limits and single-writer staging are explicit. A report
states what was analyzed by which generation; it does not authorize executing a
model or promise absence of every possible malicious behavior.
