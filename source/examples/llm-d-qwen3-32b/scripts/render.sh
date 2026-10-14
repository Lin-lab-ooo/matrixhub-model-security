#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

preflight_local

direct_output="${ARTIFACTS_DIR}/direct-rendered.yaml"
matrixhub_output="${ARTIFACTS_DIR}/matrixhub-rendered.yaml"

kubectl kustomize "${EXAMPLE_ROOT}/overlays/direct" >"$direct_output"
kubectl kustomize "${EXAMPLE_ROOT}/overlays/matrixhub" >"$matrixhub_output"

grep -q -- 'Qwen/Qwen3-32B' "$direct_output"
grep -q -- '--tensor-parallel-size=4' "$direct_output"
grep -q -- 'nvidia.com/gpu: 4' "$direct_output"
grep -q -- 'replicas: 1' "$direct_output"
grep -q -- 'name: HF_ENDPOINT' "$direct_output"
grep -q -- 'value: https://hf.m.daocloud.io' "$direct_output"

grep -q -- 'name: HF_ENDPOINT' "$matrixhub_output"
grep -q -- 'name: matrixhub-hf-endpoint' "$matrixhub_output"

printf 'Rendered manifests:\n  %s\n  %s\n' "$direct_output" "$matrixhub_output"
