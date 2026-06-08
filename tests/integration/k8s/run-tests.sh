#!/usr/bin/env bash
# shellcheck disable=SC2317

set -xeo pipefail

SCRIPT="$(readlink -f "$0")"
SCRIPTPATH="$(dirname "${SCRIPT}")"

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

# Setup mock k8s api server. Consider moving this out to a systemd service.
MOCK_DIR="$(pwd)/mock-k8s-materials"
rm -rf "${MOCK_DIR}" && mkdir -p "${MOCK_DIR}"
go build -o mock-k8s-api ${SCRIPTPATH}/../../../examples/mock-k8s-api/main.go
./mock-k8s-api -dir "${MOCK_DIR}" -port 9998 &
MAX_WAIT=30
ELAPSED=0
while true; do
  if [ -f "${MOCK_DIR}/token" ] && [ -f "${MOCK_DIR}/ca.pem" ]; then
    break
  fi
  if [ $ELAPSED -ge $MAX_WAIT ]; then
    echo "Timed out waiting for mock-k8s-api to write materials."
    exit 1
  fi
  sleep 1
  ((ELAPSED++)) || true
done
export K8S_SA_TOKEN="$(cat "${MOCK_DIR}/token")"
echo "::add-mask::${K8S_SA_TOKEN}"
set -x

# spire-identity-exchange's k8s validator reads CA/client cert from a fixed path
# in /etc/spire/identity-exchange/mock-k8s/ (referenced by default.json).
sudo mkdir -p /etc/spire/identity-exchange/mock-k8s
sudo cp "${MOCK_DIR}/ca.pem" "${MOCK_DIR}/client.pem" "${MOCK_DIR}/client.key" /etc/spire/identity-exchange/mock-k8s/

# Get the package repo and install the packages.
sudo curl -s -o /etc/apt/sources.list.d/spire-examples.list https://raw.githubusercontent.com/spiffe/spire-examples/refs/heads/main/examples/debs/amd64/spire-examples.list
sudo apt-get update
sudo apt-get install -y spire-common spire-agent spire-server spire-controller-manager

# Register some workloads with the spire server using manifests.
sudo mkdir -p /etc/spire/server/main/manifests/
sudo cp "${SCRIPTPATH}/manifests"/* /etc/spire/server/main/manifests/

# Startup server and make sure its ready.
sudo cp "${SCRIPTPATH}/server.conf" /etc/spire/server/main.conf
sudo systemctl start spire-server@main spire-controller-manager@main
wait_for_healthcheck spire-server /run/spire/server/sockets/main/private/api.sock

# Configure agents.
JOIN_TOKEN=$(sudo spire-server token generate -spiffeID spiffe://example.org/agent/node1 | awk '{print "\""$2"\""}')
export JOIN_TOKEN
sudo /bin/bash -c "echo JOIN_TOKEN=${JOIN_TOKEN} > /etc/spire/agent/main.env"
sudo cp "${SCRIPTPATH}/six-agent.conf" /etc/spire/agent/six.conf

# Startup agents.
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
    echo "Timed out waiting for spire-identity-exchange."
    exit 1
  fi
  sleep 1
  ((ELAPSED++)) || true
done

go install github.com/fullstorydev/grpcurl/cmd/grpcurl@latest

# gRPC path: MintCertificateByK8sSAToken via the legacy k8sSAToken block.
# Uses server-side key generation so we don't need a CSR.
~/go/bin/grpcurl -cacert /etc/spire/identity-exchange/main/certs/server.pem \
  -d "{\"k8sSA\":{\"k8sSAToken\":\"${K8S_SA_TOKEN}\"},\"mintJWTSVIDRequest\":{\"audiences\":[\"foo\"]}}" \
  localhost:8443 \
  proto.spiffe.spireidentityexchange.SpireIdentityExchangeApi/MintCertificate

# REST path: POST /api/v1/svid/k8s/x509 — uses cfg.Auth.Plugins → pkg/validator/k8s
# via the delegated identity API. The plugin instance is named "k8s" in default.json.
curl -H "Authorization: Bearer ${K8S_SA_TOKEN}" -X POST https://localhost:8444/api/v1/svid/k8s/x509 --cacert /etc/spire/identity-exchange/main/certs/server.pem -sS
