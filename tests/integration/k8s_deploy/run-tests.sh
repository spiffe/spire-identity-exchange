#!/usr/bin/env bash
# shellcheck disable=SC2317

set -xeo pipefail

SCRIPT="$(readlink -f "$0")"
SCRIPTPATH="$(dirname "${SCRIPT}")"
TESTDIR="${SCRIPTPATH}/../../.github/tests"

if [ "x${GITHUB_JOB}" != "x" ]; then
  echo "Running in GitHub"
else
  echo "Do not run this script on your own box. For testing, it deploys a testing local spire ha setup using sudo. This is likely not what you want. Only use this script as a reference."
  exit 1
fi

. "${SCRIPTPATH}/../common/common.sh"

teardown() {
  echo ---------------------------
  echo "::group::Status Output"
  kubectl get pods -A
  kubectl get nodes
}

trap 'EC=$? && trap - SIGTERM && teardown $EC' SIGINT SIGTERM EXIT

helm upgrade --install -n spire-server spire-crds spire-crds --repo https://spiffe.github.io/helm-charts-hardened/ --create-namespace
helm upgrade --install -n spire-server spire spire --repo https://spiffe.github.io/helm-charts-hardened/ --wait

IMAGE_REF=$(ko build ./cmd/spire-credentialcomposer-identity-exchange/ --platform=linux/amd64 --local)
docker tag "$IMAGE_REF" ghcr.io/spiffe/spire-credentialcomposer-identity-exchange:dev
kind load docker-image ghcr.io/spiffe/spire-credentialcomposer-identity-exchange:dev --name chart-testing

IMAGE_REF=$(ko build ./cmd/spire-identity-exchange-server/ --platform=linux/amd64 --local)
docker tag "$IMAGE_REF" ghcr.io/spiffe/spire-identity-exchange-server:dev
kind load docker-image ghcr.io/spiffe/spire-identity-exchange-server:dev --name chart-testing
