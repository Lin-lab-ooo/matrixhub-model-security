# CHANGELOGs

MatrixHub release notes are maintained per minor version (Kubernetes-style). Official releases (`vX.Y.Z`) update these files and the [GitHub Releases](https://github.com/matrixhub-ai/matrixhub/releases) page. RC and dev tags do not update this directory.

- [CHANGELOG-0.1.md](./CHANGELOG-0.1.md)

For pull request metadata, see
[Release notes in pull requests](../CONTRIBUTING.md#release-notes-in-pull-requests).
For generating and reviewing a changelog PR, see
[Prepare release notes](../docs/release-process.md#prepare-release-notes).

For a local dry run:

```bash
GITHUB_TOKEN="$(gh auth token)" bash scripts/changelog.sh \
  --version v0.2.0 \
  --repo matrixhub-ai/matrixhub \
  --base-branch main \
  --dry-run
```
