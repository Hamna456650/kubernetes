#!/usr/bin/env bash

# Copyright 2021 The Kubernetes Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script checks coding style for go language files in each
# Kubernetes package by golint.
# Usage: `hack/verify-golangci-lint.sh`.

set -o errexit
set -o nounset
set -o pipefail

KUBE_ROOT=$(dirname "${BASH_SOURCE[0]}")/..
source "${KUBE_ROOT}/hack/lib/init.sh"
source "${KUBE_ROOT}/hack/lib/util.sh"

kube::golang::verify_go_version

# Ensure that we find the binaries we build before anything else.
export GOBIN="${KUBE_OUTPUT_BINPATH}"
PATH="${GOBIN}:${PATH}"

# Explicitly opt into go modules, even though we're inside a GOPATH directory
export GO111MODULE=on

# Install golangci-lint
echo 'installing golangci-lint '
pushd "${KUBE_ROOT}/hack/tools" >/dev/null
  go install github.com/golangci/golangci-lint/cmd/golangci-lint
popd >/dev/null

cd "${KUBE_ROOT}"

# The config is in ${KUBE_ROOT}/.golangci.yaml
res=0
if [[ "$#" -gt 0 ]]; then
    echo 'running golangci-lint' >&2
    golangci-lint run "$@" >&2 || res=$?
else
    echo "running golangci-lint for module $(go list -m)"
    golangci-lint run ./... >&2 || res=$?
    for d in staging/src/k8s.io/*; do
        MODPATH="staging/src/k8s.io/$(basename "${d}")"
        pushd "${KUBE_ROOT}/${MODPATH}" >/dev/null
            echo "running golangci-lint for module $(go list -m)"
            golangci-lint --path-prefix "${MODPATH}" run ./... >&2 || res=$?
        popd >/dev/null
    done
fi

# print a message based on the result
echo
if [ "$res" -eq 0 ]; then
  echo 'Congratulations! All files are passing lint :-)'
else
  {
    echo
    echo 'Please review the above warnings. You can test via "./hack/verify-golangci-lint.sh"'
    echo 'If the above warnings do not make sense, you can exempt this warning with a comment'
    echo '  (if your reviewer is okay with it).'
    echo 'In general please prefer to fix the error, we have already disabled specific lints'
    echo '  that the project chooses to ignore.'
    echo 'See: https://golangci-lint.run/usage/false-positives/'
  } >&2
  exit 1
fi

# preserve the result
exit "$res"
