#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

preflight_local

mode="${1:-model}"
assert_experiment_namespace "$LLMD_NAMESPACE"

case "$mode" in
  model)
    remove_model_workload "$LLMD_NAMESPACE"
    ;;
  router)
    kubectl delete namespace "$LLMD_NAMESPACE" \
      --ignore-not-found --wait=true --timeout=10m
    ;;
  *)
    die "usage: $0 model|router"
    ;;
esac
