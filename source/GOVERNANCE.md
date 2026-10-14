# MatrixHub Governance

This document describes how the MatrixHub open source project is governed. It is intended to be lightweight and evolve with the community.

## Project scope

MatrixHub is an open-source, self-hosted model registry and distribution system for enterprise AI inference workloads. The project focuses on:

- Hugging Face–compatible access for inference clients (for example vLLM, SGLang)
- Private deployment, caching, governance, replication, and air-gapped workflows
- Cloud-native operation (Kubernetes, Helm, object storage)

Out of scope items are tracked in the [public roadmap](ROADMAP.md) and discussed in GitHub issues or [Discussions](https://github.com/matrixhub-ai/matrixhub/discussions); large changes should be discussed there before substantial implementation.

## Roles

### Contributors

Anyone may contribute via issues, documentation, and pull requests under the [Contributing Guidelines](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md).

### Maintainers

Maintainers are listed in [MAINTAINERS.md](MAINTAINERS.md). They hold merge authority and are responsible for:

- Reviewing and merging pull requests
- Cutting releases and publishing artifacts
- Triaging issues and security reports ([SECURITY.md](SECURITY.md))
- Upholding project quality, inclusivity, and technical direction

The [OWNERS](OWNERS) file defines GitHub review labels (`/approve`, `/lgtm`) for day-to-day pull requests. The maintainer list in [MAINTAINERS.md](MAINTAINERS.md) is the source of truth for project leadership; approvers and reviewers in `OWNERS` should stay aligned with active maintainers.

### Emeritus maintainers

Former maintainers who are no longer active may be listed as emeritus in [MAINTAINERS.md](MAINTAINERS.md). They are honored for past service and may be reinstated by maintainer consensus.

## Becoming a maintainer

There is no fixed quota. The bar is sustained, high-quality contribution and trust within the community.

Typical path:

1. Contribute regularly (code, reviews, docs, community support).
2. An existing maintainer proposes adding you in a pull request that updates [MAINTAINERS.md](MAINTAINERS.md).
3. At least **two-thirds of active maintainers** approve the PR (or no objection within **7 calendar days** on the PR).

Removal or emeritus status follows the same process when a maintainer is inactive or requests to step down.

## Decision making

- **Day-to-day:** Lazy consensus among maintainers on individual PRs and issues.
- **Significant changes** (architecture, breaking APIs, governance, license): Open an issue or discussion first; seek agreement among maintainers before merging.
- **Deadlock:** If maintainers cannot agree, the issue remains open until consensus or a majority vote among active maintainers (simple majority of those who vote within 14 days).

## Releases

- Releases are tagged from the default branch following project quality checks (CI, review).
- **Release notes are published only for official semver tags (`vX.Y.Z`).** RC and dev tags produce container images and Helm charts only; they do not create GitHub Releases or changelog entries.
- Contributors record user-visible changes in pull request `release-note` blocks; maintainers aggregate them at official release time (Kubernetes-style). See [Release process](docs/release-process.md).
- Maintainers decide release timing and versioning (semver where applicable).

## Vendor neutrality

MatrixHub is a community-led open source project. Technical direction, release priorities, and acceptance of contributions are decided in the interest of the project and its users—not to favor a single vendor, employer, or commercial offering.

- Maintainers and contributors may work for different organizations; affiliation is disclosed in [MAINTAINERS.md](MAINTAINERS.md) and does not confer special control.
- Commercial support, hosted services, or enterprise packaging built around MatrixHub are separate from the core repository. Features intended for the community are developed in public issues and pull requests on the default branch.
- No single company may block community consensus on project direction, governance, or CNCF participation.

## Code of Conduct

All participants must follow the [MatrixHub Code of Conduct](CODE_OF_CONDUCT.md), which adopts the [CNCF Code of Conduct](https://github.com/cncf/foundation/blob/main/code-of-conduct.md). Violations may be reported to the maintainers or to the CNCF Code of Conduct Committee at <conduct@cncf.io>. Maintainers may warn, moderate, or ban contributors for violations, consistent with that policy and platform rules (GitHub, CNCF Slack).

## Security

Security reporting and response are defined in [SECURITY.md](SECURITY.md). Maintainers must treat security reports as confidential until disclosure.

## Intellectual property

- Contributions are accepted under the project’s [Apache License 2.0](LICENSE) (inbound = outbound).
- Contributors must sign off their commits under the [Developer Certificate of Origin (DCO)](https://developercertificate.org/); see [CONTRIBUTING.md](CONTRIBUTING.md).
- Trademark and project asset policies may change if the project joins the CNCF; such changes will be announced to the community.

## Communication

- **Issues / PRs:** Primary development venue on GitHub.
- **Slack:** [CNCF Slack `#matrixhub`](https://cloud-native.slack.com/archives/C0A8UKWR8HG) for community discussion.
- **Public roadmap:** [ROADMAP.md](ROADMAP.md)

## Amending this document

Changes to `GOVERNANCE.md` require a pull request approved by at least **two-thirds of active maintainers**, with a **7-day** comment period for other maintainers and the community.
