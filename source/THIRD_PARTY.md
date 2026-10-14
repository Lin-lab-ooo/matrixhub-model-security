# Third-party components and redistribution notes

This integration retains MatrixHub's Apache License 2.0 in [LICENSE](LICENSE).
The model threat classifiers and their rules are third-party work. Do not
present them as original Apache-licensed detection engines.

This is a focused inventory of the contributed scanner, its runtime and test
client. It is not a complete transitive SBOM for every upstream Go / UI package.
For the full application graph retain `go.mod`, `go.sum`, `ui/package.json` and
`ui/pnpm-lock.yaml`, then inventory the final release image after it is rebuilt.

| Component | Version / provenance | License / source |
| --- | --- | --- |
| MatrixHub upstream and contributed integration | upstream commit `6890726abe272767d26ce1a6b0580b0718f232c0` | Apache-2.0; [official repository](https://github.com/matrixhub-ai/matrixhub) |
| ClamAV engine, separate process | 1.4.6 LTS official Linux x86_64 .deb | GPLv2; preserve bundled notices and supply corresponding source on redistribution; [release and source](https://github.com/Cisco-Talos/clamav/releases/tag/clamav-1.4.6) |
| Picklescan | 1.0.5 wheel, hash-pinned | MIT, copyright Matthieu Maitre; preserve MIT notice; [source](https://github.com/mmaitre314/picklescan), [license](https://github.com/mmaitre314/picklescan/blob/main/LICENSE) |
| CPython scanner runtime | official Python 3.13-slim-bookworm image | Python / bundled Debian package notices remain in the image; [Python license](https://docs.python.org/3/license.html), [official image source](https://github.com/docker-library/python) |
| ClamAV rule snapshot | main 63 / daily 28146 / bytecode 339 | Third-party rules retain their rights; keep the original CVD files, provenance and notices; [database documentation](https://docs.clamav.net/manual/Usage/SignatureManagement.html) |
| huggingface_hub test client | 2.1.1; development Python 3.12.14 | Apache-2.0; [official source and license](https://github.com/huggingface/huggingface_hub) |
| MySQL integration-test service | 8.4.11 | Separate test service; Oracle / upstream notices apply; not bundled into the source contribution |

Pinned scanner files:

- Official .deb: `d3ee9e401974855a1edc1761b1425417d126de618d5f0c91cd51209f69f6fcc2`.
- Picklescan wheel: `2abb3d4959a7ee9ccb1e1296db7c56f624bf6d345b93a0a9cf4185bc650dc2fd`.
- Python multi-platform index: `sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641`.
- Linux/amd64 manifest: `sha256:f040863673aea2570c3ff6a5c3fb4c673a016cbc5375005ad145915922b6b78a`.

The verified local daemon-load image has a different repacked image ID. Preserve
the verification lock and final built image ID; do not substitute a moving tag
for the pin without recording the verified provenance.

Redistributing only integration source does not redistribute the engine binary.
Redistributing a scanner image or offline binary bundle requires preserving the
engine's license notices, corresponding source obligations and third-party
package notices. The source release must not be relabeled Apache-2.0 simply
because the MatrixHub integration uses that license. The final delivery manifest
should distinguish application source, engine source, rules and image artifacts.
Do not package the ignored vendor .deb as original project code.

The development EICAR fixture is a harmless standard antivirus test string. Static
Pickle references are inert test bytes and are never imported, deserialized or
executed. They are not live malware. Test artifacts and optional report-generation
libraries are evidence tooling, separate from the deployed classifier.

Final release-image inventory, exact corresponding-source packaging and public
hosting are release tasks to confirm before redistributing a binary image; the
current report does not assert that a source link alone fulfills every release
obligation. See [the scanner ADR](docs/security/adr-scanner.md) and
[the submission checklist](docs/security/SUBMISSION_CHECKLIST.zh.md).

## Recorded final test images

The local final scanner test used image
`sha256:a4736049103ff53efff2374fcee5d40e2685f3590b8f7b9d33903308f62ce8d2`
and generation
`9acc748673c456930b9e9ab0fee574671b5d32a632cfbbb6e7b30c03e107e330`.
The application E2E used image
`sha256:cfd5e30afe82d2d077ef3012ac91327c94d03c4d284e1fa5fbcfdcd6bcd38357`.
These are tested local image identities, not public binary redistribution
artifacts or a complete release-image SBOM. The final source-only package
excludes vendor binaries, downloaded CVD rule binaries, dependency caches, credentials and live data.
Optional offline image distribution needs the license and corresponding-source
checks above before publication.
