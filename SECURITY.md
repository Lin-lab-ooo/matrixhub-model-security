# Security reporting and supported scope

This is an independent research and engineering contribution to MatrixHub.
It is not a general proof that a model is safe to execute, nor an officially
endorsed MatrixHub distribution. Read [LIMITATIONS.md](LIMITATIONS.md).

Never load untrusted Pickle models to reproduce a report. The supplied scanner
performs static inspection; test references are inert bytes.

Do not publish credentials, private model contents, or working exploit payloads
in public issues. Once this repository is published, use GitHub private
vulnerability reporting if the maintainer has enabled it. No private reporting
channel or response-time commitment is represented as already configured.

For upstream MatrixHub issues consult [upstream security guidance](source/SECURITY.md).
For this integration provide the release identity, scanner generation, format,
expected and observed admission result, and a minimal non-executing reproduction.
