#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "${SCRIPT_DIR}/common.sh"

preflight_cluster

create_experiment_namespace "$LLMD_NAMESPACE"
install_router "$LLMD_NAMESPACE"

printf 'Router prerequisite is ready in namespace %s. You can now run either scenario.\n' \
  "$LLMD_NAMESPACE"
