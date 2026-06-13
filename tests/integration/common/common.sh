#!/bin/bash

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

wait_for_oidc() {
  local socket="$1"
  local timeout=30
  local count=0
  local IP=$(ip -4 addr show docker0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
  while [ "$count" -lt "$timeout" ]; do
      rc=0
      curl --resolve k8ssodp.example.org:8181:$IP "https://k8ssodp.example.org:8181/.well-known/openid-configuration" -k || rc=$?
      if [ "$rc" -eq 0 ]; then
        return 0
      fi
      sleep 1
      ((count++)) || true
  done
  return 1
}

wait_for_oidc_local() {
  local socket="$1"
  local timeout=30
  local count=0
  local IP=$(ip -4 addr show docker0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
  while [ "$count" -lt "$timeout" ]; do
      rc=0
      curl --resolve k8ssodp.example.org:8181:$IP "http://k8ssodp.example.org:8181/.well-known/openid-configuration" || rc=$?
      if [ "$rc" -eq 0 ]; then
        return 0
      fi
      sleep 1
      ((count++)) || true
  done
  return 1
}

wait_for_kubectl() {
  local socket="$1"
  local timeout=30
  local count=0
  local IP=$(ip -4 addr show docker0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
  while [ "$count" -lt "$timeout" ]; do
      rc=0
      timeout 10 sudo systemd-run --wait --pipe --unit=spire-identity-exchange-job $(which kubectl) get --raw /.well-known/openid-configuration --kubeconfig /etc/spire/identity-exchange/spire-identity-exchange.kubeconfig || rc=$?
      if [ "$rc" -eq 0 ]; then
        return 0
      fi
      sleep 1
      ((count++)) || true
      sudo systemctl reset-failed spire-identity-exchange-job
  done
  return 1
}

wait_for_spire_identity_exchange() {
  local MAX_WAIT=30
  local ELAPSED=0
  while true; do
    if curl -s -o /dev/null https://localhost:8444 -k; then
      return 0
    fi
    if [ $ELAPSED -ge $MAX_WAIT ]; then
      echo "Timed out after ${MAX_WAIT} seconds."
      exit 1
    fi
    sleep 1
    ((ELAPSED++)) || true
  done
  return 1
}

deploy_credential_composer() {
  go build -o spire-credentialcomposer-identity-exchange cmd/spire-credentialcomposer-identity-exchange/main.go
  sudo mkdir -p /usr/libexec/spire/plugins
  sudo cp -a spire-credentialcomposer-identity-exchange /usr/libexec/spire/plugins/credentialcomposer-identity-exchange
  /usr/libexec/spire/plugins/credentialcomposer-identity-exchange || true
}

setup_base_spire() {
  local SCRIPTPATH="$1"
  local COMMONPATH="$2"

  # Get the package repo and install the packages
  sudo curl -s -o /etc/apt/sources.list.d/spire-examples.list https://raw.githubusercontent.com/spiffe/spire-examples/refs/heads/main/examples/debs/amd64/spire-examples.list
  sudo apt-get update
  sudo apt-get install -y spire-common spire-agent spire-server spire-controller-manager

  # register some workloads with the spire server using manifests
  sudo mkdir -p /etc/spire/server/main/manifests/
  sudo cp "${COMMONPATH}/manifests"/* /etc/spire/server/main/manifests/

  # Startup server and make sure its ready
  sudo cp "${COMMONPATH}/server.conf" /etc/spire/server/main/config
  sudo systemctl start spire-server@main spire-controller-manager@main
  wait_for_healthcheck spire-server /run/spire/server/sockets/main/private/api.sock

  # Configure our agents. For the test, create join token for the main agent. You should really use a node attestor other then join tokens such as tpm-direct, http_challenge, or a cloud provider one
  JOIN_TOKEN=$(sudo spire-server token generate -spiffeID spiffe://example.org/agent/node1 | awk '{print "\""$2"\""}')
  export JOIN_TOKEN
  sudo /bin/bash -c "echo JOIN_TOKEN=${JOIN_TOKEN} > /etc/spire/agent/main.env"
  sudo cp "${COMMONPATH}/six-agent.conf" /etc/spire/agent/six.conf

  # Startup the agents
  sudo systemctl start spire-agent@main spire-agent@six
  wait_for_healthcheck spire-agent /var/run/spire/agent/sockets/main/public/api.sock
  wait_for_healthcheck spire-agent /var/run/spire/agent/sockets/six/public/api.sock
}

setup_identity_exchange() {
  local SCRIPTPATH="$1"
  local COMMONPATH="$2"

  sudo mkdir -p /usr/libexec/spire/
  chmod +x spire-identity-exchange
  sudo cp -a spire-identity-exchange /usr/libexec/spire/

  sudo mkdir -p /etc/spire/identity-exchange/main/certs
  sudo openssl req -x509 -newkey rsa:2048 \
    -keyout /etc/spire/identity-exchange/main/certs/server.key \
    -out /etc/spire/identity-exchange/main/certs/server.pem -sha256 -days 365 -nodes \
    -subj "/CN=localhost" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "subjectAltName=DNS:localhost,DNS:spire-identity-exchange.example.org,IP:127.0.0.1"

  sudo cp "${SCRIPTPATH}/default.json" /etc/spire/identity-exchange/
  sudo cp "${COMMONPATH}/../../../systemd/spire-identity-exchange@.service" /etc/systemd/system
  sudo systemctl daemon-reload
  sudo systemctl restart spire-identity-exchange@main.service

  wait_for_spire_identity_exchange
}

