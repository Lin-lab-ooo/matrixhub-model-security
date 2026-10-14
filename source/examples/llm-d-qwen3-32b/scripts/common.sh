#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXAMPLE_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
ENV_FILE="${EXAMPLE_ROOT}/env.sh"
ARTIFACTS_DIR="${EXAMPLE_ROOT}/artifacts"

MODEL_DEPLOYMENT="optimized-baseline-nvidia-gpu-vllm-decode"
MODEL_SERVICE="qwen3-32b"
MODEL_ID="Qwen/Qwen3-32B"
EXPERIMENT_LABEL_KEY="matrixhub.ai/experiment"
EXPERIMENT_LABEL_VALUE="llm-d-qwen3-32b"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 1
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

validate_namespace() {
  local value="$1"
  local variable="$2"
  [[ "$value" =~ ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$ ]] || \
    die "${variable} must be a valid Kubernetes namespace name: ${value}"
}

load_env() {
  [[ -f "$ENV_FILE" ]] || die "${ENV_FILE} not found; run: cp env.example env.sh"

  # shellcheck disable=SC1090
  source "$ENV_FILE"

  : "${MATRIXHUB_ENDPOINT:?MATRIXHUB_ENDPOINT is required in env.sh}"
  : "${MATRIXHUB_NAMESPACE:?MATRIXHUB_NAMESPACE is required in env.sh}"
  : "${MATRIXHUB_DEPLOYMENT:?MATRIXHUB_DEPLOYMENT is required in env.sh}"
  : "${LLMD_NAMESPACE:?LLMD_NAMESPACE is required in env.sh}"
  : "${MODEL_NODE_SELECTOR:=}"
  : "${LLMD_ROUTER_CHART:=oci://ghcr.io/llm-d/charts/llm-d-router-standalone}"
  : "${LLMD_ROUTER_CHART_VERSION:=v0.9.0}"
  : "${LLMD_ROUTER_RELEASE:=optimized-baseline}"
  ROUTER_SERVICE="${LLMD_ROUTER_RELEASE}-epp"

  [[ "$MATRIXHUB_ENDPOINT" =~ ^https?:// ]] || \
    die "MATRIXHUB_ENDPOINT must start with http:// or https://"
  validate_namespace "$MATRIXHUB_NAMESPACE" MATRIXHUB_NAMESPACE
  validate_namespace "$LLMD_NAMESPACE" LLMD_NAMESPACE
  [[ "$LLMD_NAMESPACE" != "$MATRIXHUB_NAMESPACE" ]] || \
    die "LLMD_NAMESPACE must not be the MatrixHub namespace"
  if [[ -n "$MODEL_NODE_SELECTOR" ]]; then
    validate_namespace "$MODEL_NODE_SELECTOR" MODEL_NODE_SELECTOR
  fi
}

preflight_local() {
  require_command kubectl
  load_env
  mkdir -p "$ARTIFACTS_DIR"
}

preflight_cluster() {
  preflight_local
  kubectl cluster-info >/dev/null
  kubectl auth can-i create namespaces | grep -qx yes || \
    die "current Kubernetes identity cannot create namespaces"
  printf 'Configuration and Kubernetes access checks passed.\n'
}

create_experiment_namespace() {
  local namespace="$1"

  if kubectl get namespace "$namespace" >/dev/null 2>&1; then
    is_experiment_namespace "$namespace" || \
      die "refusing to use existing namespace ${namespace}: experiment ownership label is missing"
    return
  fi

  printf '%s\n' \
    'apiVersion: v1' \
    'kind: Namespace' \
    'metadata:' \
    "  name: ${namespace}" \
    '  labels:' \
    "    ${EXPERIMENT_LABEL_KEY}: ${EXPERIMENT_LABEL_VALUE}" | kubectl create -f - >/dev/null
}

install_router() {
  local namespace="$1"

  require_command helm
  kubectl api-resources --api-group=inference.networking.k8s.io -o name | \
    grep -qx inferencepools.inference.networking.k8s.io || \
    die "Gateway API Inference Extension CRD is missing; install inferencepools.inference.networking.k8s.io before running the experiment"

  helm upgrade --install "$LLMD_ROUTER_RELEASE" "$LLMD_ROUTER_CHART" \
    --version "$LLMD_ROUTER_CHART_VERSION" \
    --namespace "$namespace" \
    --wait --timeout 10m \
    -f "${EXAMPLE_ROOT}/router/base.values.yaml" \
    -f "${EXAMPLE_ROOT}/router/optimized-baseline.values.yaml"

  kubectl get service "$ROUTER_SERVICE" -n "$namespace" >/dev/null
}

require_router_prerequisite() {
  local namespace="$1"

  require_command helm
  is_experiment_namespace "$namespace" || \
    die "Router prerequisite is missing for namespace ${namespace}; run: make prepare-router"
  helm status "$LLMD_ROUTER_RELEASE" -n "$namespace" >/dev/null 2>&1 || \
    die "Router prerequisite is missing for namespace ${namespace}; run: make prepare-router"
  kubectl get service "$ROUTER_SERVICE" -n "$namespace" >/dev/null 2>&1 || \
    die "Router prerequisite is missing for namespace ${namespace}; run: make prepare-router"
}

remove_model_workload() {
  local namespace="$1"

  kubectl delete deployment "$MODEL_DEPLOYMENT" -n "$namespace" \
    --ignore-not-found --wait=true --timeout=10m >/dev/null
  kubectl delete service "$MODEL_SERVICE" -n "$namespace" \
    --ignore-not-found --wait=true >/dev/null
  kubectl delete serviceaccount optimized-baseline-nvidia-gpu-vllm-sa -n "$namespace" \
    --ignore-not-found --wait=true >/dev/null
  kubectl delete configmap matrixhub-hf-endpoint -n "$namespace" \
    --ignore-not-found --wait=true >/dev/null
}

is_experiment_namespace() {
  local namespace="$1"
  local owner

  owner="$(kubectl get namespace "$namespace" --ignore-not-found \
    -o go-template="{{ index .metadata.labels \"${EXPERIMENT_LABEL_KEY}\" }}")" || return 1
  [[ "$owner" == "$EXPERIMENT_LABEL_VALUE" ]]
}

assert_experiment_namespace() {
  local namespace="$1"
  local owner

  if ! owner="$(kubectl get namespace "$namespace" --ignore-not-found \
    -o go-template="{{ index .metadata.labels \"${EXPERIMENT_LABEL_KEY}\" }}")"; then
    die "refusing to delete namespace ${namespace}: ownership could not be verified"
  fi
  [[ -z "$owner" ]] && return 0
  [[ "$owner" == "$EXPERIMENT_LABEL_VALUE" ]] || \
    die "refusing to delete namespace ${namespace}: experiment ownership label is missing"
}

model_pod() {
  local namespace="$1"
  kubectl get pods -n "$namespace" \
    -l 'llm-d.ai/model=Qwen3-32B,llm-d.ai/role=decode' \
    -o jsonpath='{.items[0].metadata.name}'
}

iso_to_epoch() {
  python3 -c 'import datetime, sys; print(int(datetime.datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00")).timestamp()))' "$1"
}

collect_diagnostics() {
  local namespace="$1"
  local destination="$2"

  mkdir -p "$destination"
  kubectl get all -n "$namespace" -o wide >"${destination}/resources.txt" 2>&1 || true
  kubectl describe deployment "$MODEL_DEPLOYMENT" -n "$namespace" \
    >"${destination}/deployment-describe.txt" 2>&1 || true
  kubectl get events -n "$namespace" --sort-by=.lastTimestamp \
    >"${destination}/events.txt" 2>&1 || true
  helm status "$LLMD_ROUTER_RELEASE" -n "$namespace" \
    >"${destination}/router-status.txt" 2>&1 || true

  local pod
  pod="$(model_pod "$namespace" 2>/dev/null || true)"
  if [[ -n "$pod" ]]; then
    kubectl describe pod "$pod" -n "$namespace" >"${destination}/pod-describe.txt" 2>&1 || true
    kubectl logs "$pod" -n "$namespace" >"${destination}/modelserver.log" 2>&1 || true
  fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  preflight_cluster
fi
