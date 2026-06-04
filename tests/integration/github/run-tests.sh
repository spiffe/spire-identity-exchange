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

teardown() {
  echo ---------------------------
  echo "::group::Status Output"
  sudo systemctl status spire-identity-exchange@main.service -n 50 2>&1 || true
  sudo systemctl status spire-server@main 2>&1 || true
  sudo spire-server entry show 2>&1 || true
  sudo systemctl status spire-controller-manager@main 2>&1 || true
  sudo systemctl status spire-agent@main 2>&1 || true
  sudo systemctl status spire-agent@six 2>&1 || true
}

trap 'EC=$? && trap - SIGTERM && teardown $EC' SIGINT SIGTERM EXIT

wait_for_healthcheck() {
  local app="$1"
  local socket="$2"
  local timeout=30
  local count=0
  while [ "$count" -lt "$timeout" ]; do
    rc=0
    sudo "$app" healthcheck -socketPath "$socket" || rc=$?
    if [ "$rc" -eq 0 ]; then
      return 0
    fi
    sleep 1
    ((count++)) || true
  done
  return 1
}

wait_for_trust_sync() {
  local socket="$1"
  local timeout=30
  local count=0
  while [ "$count" -lt "$timeout" ]; do
    entries=$(sudo spire-server bundle list -socketPath "$socket" | wc -l)
    if [ "$entries" -ne 0 ]; then
      return 0
    fi
    sleep 1
    ((count++)) || true
  done
  return 1
}

wait_for_jwt() {
  local socket="$1"
  local timeout=30
  local count=0
  while [ "$count" -lt "$timeout" ]; do
      rc=0
      sudo spire-agent api fetch jwt -audience test -socketPath "$socket" || rc=$?
      if [ "$rc" -eq 0 ]; then
        return 0
      fi
      sleep 1
      ((count++)) || true
  done
  return 1
}

# Get the package repo and install the packages
sudo curl -s -o /etc/apt/sources.list.d/spire-examples.list https://raw.githubusercontent.com/spiffe/spire-examples/refs/heads/main/examples/debs/amd64/spire-examples.list
sudo apt-get update
sudo apt-get install -y spire-common spire-agent spire-server spire-controller-manager

# register some workloads with the spire server using manifests
sudo mkdir -p /etc/spire/server/main/manifests/
sudo cp "${SCRIPTPATH}/manifests"/* /etc/spire/server/main/manifests/

# Startup server and make sure its ready
sudo cp "${SCRIPTPATH}/server.conf" /etc/spire/server/main.conf
sudo systemctl start spire-server@main spire-controller-manager@main
wait_for_healthcheck spire-server /run/spire/server/sockets/main/private/api.sock

# Configure our agents. For the test, create join token for the main agent. You should really use a node attestor other then join tokens such as tpm-direct, http_challenge, or a cloud provider one
JOIN_TOKEN=$(sudo spire-server token generate -spiffeID spiffe://example.org/agent/node1 | awk '{print "\""$2"\""}')
export JOIN_TOKEN
sudo /bin/bash -c "echo JOIN_TOKEN=${JOIN_TOKEN} > /etc/spire/agent/main.env"
sudo cp "${SCRIPTPATH}/six-agent.conf" /etc/spire/agent/six.conf

# Startup the agents
sudo systemctl start spire-agent@main spire-agent@six
wait_for_healthcheck spire-agent /var/run/spire/agent/sockets/main/public/api.sock
wait_for_healthcheck spire-agent /var/run/spire/agent/sockets/six/public/api.sock

make build

sudo mkdir -p /usr/libexec/spire/
sudo cp -a build/bin/spire-identity-exchange /usr/libexec/spire/

sudo mkdir -p /etc/spire/identity-exchange/main/certs
sudo openssl req -x509 -newkey rsa:2048 \
  -keyout /etc/spire/identity-exchange/main/certs/server.key \
  -out /etc/spire/identity-exchange/main/certs/server.pem -sha256 -days 365 -nodes \
  -subj "/CN=localhost" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"

sudo cp "${SCRIPTPATH}/default.json" /etc/spire/identity-exchange/
sudo cp "${SCRIPTPATH}/../../../systemd/spire-identity-exchange@.service" /etc/systemd/system
sudo systemctl daemon-reload
sudo systemctl start spire-identity-exchange@main.service

MAX_WAIT=30
ELAPSED=0
while true; do
  if curl -s -o /dev/null https://localhost:8443 -k; then
    break
  fi
  if [ $ELAPSED -ge $MAX_WAIT ]; then
    echo "Timed out after ${MAX_WAIT} seconds."
    exit 1
  fi
  sleep 1
  ((ELAPSED++)) || true
done

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
  -d "{\"githubOIDC\":{\"githubToken\":\"${GITHUB_TOKEN}\"},\"mintJWTSVIDRequest\":{\"audiences\":[\"foo\"]}}" \
  localhost:8443 \
  proto.spiffe.spireidentityexchange.SpireIdentityExchangeApi/MintCertificate

diff -u <(curl https://localhost:8444/api/v1/trustbundle/x509 --cacert /etc/spire/identity-exchange/main/certs/server.pem -s) <(sudo spire-server bundle show)

curl -H "Authorization: Bearer ${GITHUB_TOKEN}" -X POST https://localhost:8444/api/v1/svid/github/x509 --cacert /etc/spire/identity-exchange/main/certs/server.pem -sS
