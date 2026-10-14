# MatrixHub

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/matrixhub-ai/matrixhub)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13641/badge)](https://www.bestpractices.dev/projects/13641)

**MatrixHub** is an open-source, self-hosted AI model registry engineered for large-scale enterprise inference. It serves as a drop-in private replacement for Hugging Face, purpose-built to accelerate **vLLM** and **SGLang** workloads.

For target users, use cases, and current capabilities, see the [Overview](https://matrixhub.ai/docs/overview/).

## Artifact security contribution

This branch adds opt-in asynchronous ClamAV and Picklescan analysis, immutable
file evidence, permission-aware download admission, and a security console with
history, policy and audit controls. Incomplete analysis fails closed. The tested
deployment has explicit file, task and retention limits; strict mode disables
raw Git fetch and historical patches.

See the [source deployment guide](deploy/security/README.md),
[design and threat model](docs/security/design.md), and the
[Chinese implementation and test report](docs/security/REPORT.zh.md).

## 🌐 Live Demo

Try MatrixHub instantly at **[demo.matrixhub.ai](https://demo.matrixhub.ai/)** — no setup required.

Sign in with the public demo credentials:

| Username | Password |
| --- | --- |
| `admin` | `changeme` |

> The demo is for evaluation only and may be reset at any time.

## 🚀 Quick Start

Follow the [Getting Started guide](https://matrixhub.ai/docs/getting-started/) to deploy MatrixHub and cache your first model.

For Docker Compose and Helm commands, see [Installation](https://matrixhub.ai/docs/installation/).

For vLLM, SGLang, llm-d, Dynamo, and model distribution examples, see the [Integrations guide](https://matrixhub.ai/docs/integrations/).

## Contributing and Development

We welcome contributions. 

See [CONTRIBUTING.md](CONTRIBUTING.md) for issues, pull requests, reviews, DCO, and release note requirements.

See [Development Guide](docs/development.md) for local setup, testing, and generated code.

See [Technical Design Docs](docs/design/README.md) for architecture and feature designs.

## Community and Support

Join us in [GitHub Discussions](https://github.com/matrixhub-ai/matrixhub/discussions)
or the [CNCF Slack `#matrixhub`](https://cloud-native.slack.com/archives/C0A8UKWR8HG)
for questions, ideas, and support.

- [Documentation site](https://matrixhub.ai)
- [CNCF Landscape](https://landscape.cncf.io/?item=ai-native-infra--model-asset-and-registry--matrixhub)
- [Roadmap](ROADMAP.md)

## Security

Please report vulnerabilities according to [SECURITY.md](SECURITY.md).

## License

MatrixHub is licensed under the [Apache License 2.0](LICENSE).

## Validated security delivery notes (Chinese)

- [产品报告与实际测试范围](docs/REPORT_SUPPLEMENT.zh.md)
- [证据与版本范围](docs/EVIDENCE_SUPPLEMENT.zh.md)
- [公开复现配方](docs/REPRODUCTION_SUPPLEMENT.zh.md)
