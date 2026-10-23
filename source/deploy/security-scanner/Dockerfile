# Copyright The MatrixHub Authors. Licensed under the Apache License, Version 2.0.
ARG BASE_IMAGE=python:3.13-slim-bookworm@sha256:a1165e272e578941b84abc79e4ab38a0305cd12803a5c4247979ac7655f4d641
FROM ${BASE_IMAGE} AS engine
# An optional locally cached official asset avoids another network transfer.
# Its hard-coded release checksum is ALWAYS verified by fetch_engine.py.
COPY vendor/ /opt/vendor/
COPY fetch_engine.py /opt/fetch_engine.py
RUN python -I /opt/fetch_engine.py /opt/vendor/clamav-1.4.6.linux.x86_64.deb \
    && dpkg -i /opt/vendor/clamav-1.4.6.linux.x86_64.deb \
    && ldconfig \
    && /usr/local/bin/clamscan --version \
    && dpkg-query -W > /usr/local/share/scanner-packages.txt \
    && rm /usr/local/lib/libclamav_rust.a

FROM ${BASE_IMAGE}
COPY --from=engine /usr/local/ /usr/local/
RUN ldconfig

COPY requirements.lock /opt/scanner/requirements.lock
RUN python -m pip install --no-cache-dir --require-hashes --only-binary=:all: -r /opt/scanner/requirements.lock
COPY scanner.py /opt/scanner/scanner.py
COPY tests.py /opt/scanner/tests.py
COPY integration_tests.py /opt/scanner/integration_tests.py
COPY prefix_tests.py legacy_io_tests.py legacy_io_fixtures.py legacy_io_prepare.py legacy_io_benchmark.py legacy_io_native.py /opt/scanner/
COPY hash_io_tests.py format_hardening_tests.py format_hardening_benchmark.py operand_budget_tests.py v13_native_acceptance.py v13_native_contract_tests.py v13_candidate_probe_tests.py v13_legacy_zip_compat_tests.py /opt/scanner/
COPY benchmark.py /opt/scanner/benchmark.py
COPY capacity_tests.py /opt/scanner/capacity_tests.py
COPY parallel_tests.py text_candidate_tests.py benchmark_tests.py scale_fixtures.py scale_benchmark.py native_driver.py parallel_native_checks.py scale_curves.py /opt/scanner/
RUN mkdir -p /input /rules /run/matrix-security \
    && chown 65532:65532 /run/matrix-security \
    && chmod 0755 /opt/scanner/scanner.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER 65532:65532
ENTRYPOINT ["python", "-I", "/opt/scanner/scanner.py"]
