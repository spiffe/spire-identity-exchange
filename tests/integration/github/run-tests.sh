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
  sudo journalctl -u spire-server-attestor-spiffe-workload-api@main.service || true
  sudo systemctl status spire-server-attestor-spiffe-workload-api@main.service || true
  sudo spire-server agent show -spiffeID spiffe://example.org/spire/agent/x509pop/spire-identity-exchange/node1 || true
  sudo systemctl status spire-identity-exchange@main.service -n 50 2>&1 || true
  sudo systemctl status spire-server@main -n 50 2>&1 || true
  sudo spire-server entry show 2>&1 || true
  sudo systemctl status spire-controller-manager@main 2>&1 || true
  sudo systemctl status spire-agent@main 2>&1 || true
  sudo systemctl status spire-agent@main-six 2>&1 || true
}

trap 'EC=$? && trap - SIGTERM && teardown $EC' SIGINT SIGTERM EXIT

deploy_credential_composer
deploy_server_attestor

# Setup github mock service. Consider moving this out to a systemd service
go build -o mock-github-oidc ${SCRIPTPATH}/../../../examples/mock-github-oidc/main.go
rm -f token
./mock-github-oidc -token token &
MAX_WAIT=30
ELAPSED=0
while true; do
  if [ -f token ]; then
    break
  fi
  if [ $ELAPSED -ge $MAX_WAIT ]; then
    echo "Timed out after ${MAX_WAIT} seconds."
    exit 1
  fi
  sleep 1
  ((ELAPSED++)) || true
done
export MOCKHUB_TOKEN="$(cat token)"
echo "::add-mask::${MOCKHUB_TOKEN}"
set -x

sudo mkdir -p /etc/spire/server/main/manifests
sudo cp "${SCRIPTPATH}/manifests"/* /etc/spire/server/main/manifests/

# Common spire setup bits
setup_base_spire "${SCRIPTPATH}" "${SCRIPTPATH}/../common"

setup_identity_exchange "${SCRIPTPATH}" "${SCRIPTPATH}/../common"

# Tests

# Github Tests

SPIFFE_ID="spiffe://example.org/spire-identity-exchange/github/cncf/spire-identity-exchange"

openssl req -new \
  -newkey rsa:2048 -nodes -keyout workload.key \
  -subj "/CN=workload" \
  -addext "subjectAltName=URI:${SPIFFE_ID}" \
  -out workload.csr

CSR_B64=$(openssl req -in workload.csr -outform DER | base64 | tr -d '\n')

go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

#~/go/bin/grpcurl -cacert /etc/spire/identity-exchange/main/certs/server.pem \
#  -d "{\"githubOIDC\":{\"githubToken\":\"${GITHUB_TOKEN}\"},\"mintX509SVIDRequest\":{\"csr\":\"${CSR_B64}\"}}" \
#  localhost:8443 \
#  proto.spiffe.spireidentityexchange.SpireIdentityExchangeApi/MintCertificate

~/go/bin/grpcurl -cacert /etc/spire/identity-exchange/main/certs/server.pem \
  -d '{"pluginAuthList": {"plugins": [{"pluginName": "mockhub", "token": "'"${MOCKHUB_TOKEN}"'"}]}, "mintJWTSVIDRequest": {"audiences": ["foo"]}}' \
  localhost:8443 \
  proto.spiffe.spireidentityexchange.SpireIdentityExchangeApi/MintCertificate

diff -u <(curl https://localhost:8444/api/v1/trustbundle/x509 --cacert /etc/spire/identity-exchange/main/certs/server.pem -s) <(sudo spire-server bundle show)

if [ -n "$GITHUB_TOKEN" ]; then
	curl -f -H "Authorization: Bearer ${GITHUB_TOKEN}" -X POST https://localhost:8444/api/v1/svid/github/x509 --cacert /etc/spire/identity-exchange/main/certs/server.pem -sS
fi

curl -f -H "Authorization: Bearer ${MOCKHUB_TOKEN}" -X POST https://localhost:8444/api/v1/svid/mockhub/x509 --cacert /etc/spire/identity-exchange/main/certs/server.pem -sS

