#!/usr/bin/env bash

# This script verifies that the OSS k/k build image (and corresponding Go version)
# hasn't changed since the last time we updated our corresponding internal build config.
#
# The high-level workflow is:
# 1. OSS changes go version (currently by modifying build/build-image/cross/VERSION)
# 2. GKE picks up the OSS change automatically
# 3. A periodic job running this verify script starts failing and opens a bug or sends
#    an email to the maintainers to update our internal go-boringcrypto compiler image
#    (potentially prodding the Go team to create a new release if necessary).

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_DIR="$(dirname "$(realpath "$0")")"
CONFIG_FILE="${SCRIPT_DIR}/config/common.yaml"
KUBE_ROOT="$(cd "${SCRIPT_DIR}" && git rev-parse --show-toplevel)"
OSS_KUBECROSS_VERSION_FILE="${KUBE_ROOT}/build/build-image/cross/VERSION"

# shellcheck source=./lib_assert.sh
source "${SCRIPT_DIR}/lib_assert.sh"

# shellcheck source=./lib_log.sh
source "${SCRIPT_DIR}/lib_log.sh"

function get_last_updated_val_from_config()
{
  local config_file=$1
  # Using `grep` and `sed` to avoid taking a dependency on `lib_yaml::_yq()`
  grep "last-updated-for-oss-kubecross-version" "${config_file}" | sed s/[[:space:]]*last-updated-for-oss-kubecross-version:[[:space:]]*//
}

log.info "Reading OSS kube-cross image version..."
assert_path_exists "${OSS_KUBECROSS_VERSION_FILE}"
oss_kubecross_version="$(cat "${OSS_KUBECROSS_VERSION_FILE}")"
log.info "OSS kube-cross version: \"${oss_kubecross_version}\""

last_updated_for_oss_kubecross_version="$(get_last_updated_val_from_config "${CONFIG_FILE}")"
log.info "golang_boringcrypto was last updated for version: \"${last_updated_for_oss_kubecross_version}\""

if [[ "${oss_kubecross_version}" != "${last_updated_for_oss_kubecross_version}" ]]; then
  log.fail "Golang version was last updated for ${last_updated_for_oss_kubecross_version}, OSS is currently at ${oss_kubecross_version}. See http://goto.google.com/gke-security-compliance#periodics-gob-kubernetes-verify-golang-version-failure-playbook for resolution instructions."
fi

log.info "OK!"

