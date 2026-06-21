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
  sudo systemctl status spiffe-step-ssh-server@.service || true
  sudo systemctl status spiffe-step-ssh-fetchca@.service || true
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

# Setup step-ssh server
sudo apt-get update

STEP_VER="0.30.2"
wget https://dl.smallstep.com/gh-release/certificates/gh-release-header/v${STEP_VER}/step-ca_${STEP_VER}-1_amd64.deb
sudo apt-get install ./step-ca_${STEP_VER}-1_amd64.deb
sudo apt-get install -y spiffe-helper spiffe-step-ssh-server nginx
sudo mkdir -p /etc/spiffe/step-ssh/server/main
sudo setup-spiffe-step-ssh-server main
sudo systemctl start spiffe-step-ssh-server@main spiffe-step-ssh-fetchca@main nginx

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

curl -f -H "Authorization: Bearer ${MOCKHUB_TOKEN}" -X POST "https://localhost:8444/api/v1/svid/mockhub/x509?format=spiffe-fd-tar" --cacert /etc/spire/identity-exchange/main/certs/server.pem -qsS | tar -xvf -
openssl x509 -in x509/0/credential-bundle.pem -noout -text | grep 'spiffe://example.org/ssh/mockhub'

# SSH test setup
HIP="$(ip -4 addr show docker0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')"
echo "Picked IP ${HIP}"
echo "${HIP} test.example.org spiffe-step-ssh-fetchca.example.org spiffe-step-ssh.example.org" | sudo bash -c 'cat >> /etc/hosts'
sudo adduser spiffe-test
sudo -u spiffe-test mkdir -p /home/spiffe-test/.ssh
sudo chown spiffe-test --recursive /home/spiffe-test
sudo spiffe-step-ssh-get-cert-authority user main | sudo -u spiffe-test dd of=/home/spiffe-test/.ssh/authorized_keys

git clone https://github.com/spiffe/spiffe-step-ssh
cd spiffe-step-ssh
git checkout spiffe-fd
git build cmd/spiffe-step-ssh-user-agent
cd ../

export SPIFFE_ENDPOINT="file:///$(pwd)"
export SPIFFE_STEP_SSH_FETCHCA_URL="https://spiffe-step-ssh-fetchca.example.org:5443"
export SPIFFE_STEP_SSH_URL="https://spiffe-step-ssh.example.org:7443"
eval `./spiffe-step-ssh/spiffe-step-ssh-user-agent`

ssh -T -n spiffe-test@test.example.org hostname

