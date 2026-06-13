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
  sudo journalctl -u spire-identity-exchange@main.service || true
  sudo journalctl -u k8s-spiffe-oidc-discovery-provider.service || true
  sudo systemctl status k8s-spiffe-oidc-discovery-provider.service 2>&1 || true
  sudo spire-server agent show -spiffeID spiffe://example.org/spire/agent/x509pop/spire-identity-exchange/node1 || true
  sudo systemctl status spire-identity-exchange@main.service -n 50 2>&1 || true
  sudo systemctl status spire-server@main -n 50 2>&1 || true
  sudo spire-server entry show 2>&1 || true
  sudo systemctl status spire-controller-manager@main 2>&1 || true
  sudo systemctl status spire-agent@main 2>&1 || true
  sudo systemctl status spire-agent@six 2>&1 || true
}

trap 'EC=$? && trap - SIGTERM && teardown $EC' SIGINT SIGTERM EXIT

deploy_credential_composer

sudo mkdir -p /etc/spire/server/main/manifests
sudo cp "${SCRIPTPATH}/manifests"/* /etc/spire/server/main/manifests/

# Common spire setup bits
setup_base_spire "${SCRIPTPATH}" "${SCRIPTPATH}/../common"

# Spiffe test specific tests
sudo apt-get install -y spiffe-oidc-discovery-provider k8s-spiffe-oidc-discovery-provider spiffe-helper
sudo cp "${SCRIPTPATH}/oidc.conf" /etc/spiffe/k8s-oidc-discovery-provider.conf
cat /etc/spiffe/k8s-oidc-discovery-provider.conf
sudo systemctl restart k8s-spiffe-oidc-discovery-provider

wait_for_oidc "http://localhost:8181"

# Common spire setup bits

setup_identity_exchange "${SCRIPTPATH}" "${SCRIPTPATH}/../common"

# Tests

# Github Tests

diff -u <(curl https://localhost:8444/api/v1/trustbundle/x509 --cacert /etc/spire/identity-exchange/main/certs/server.pem -s) <(sudo spire-server bundle show)
      
TOKEN=$(timeout 10 sudo systemd-run --wait --pipe --unit=spire-identity-exchange-job spire-agent spire-agent api fetch jwt -audience spiffe-identity-exchange -output json | jq -r '.[0].svids[0].svid')

curl -f -H "Authorization: Bearer ${TOKEN}" -X POST https://localhost:8444/api/v1/svid/spiffe/x509 --cacert /etc/spire/identity-exchange/main/certs/server.pem -sS

