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
    if curl -s -o /dev/null https://localhost:8443 -k; then
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

deploy_credential_composer {
  go build -o spire-credentialcomposer-identity-exchange cmd/spire-credentialcomposer-identity-exchange/main.go
  sudo mkdir -p /usr/libexec/spire/plugins
  sudo cp -a spire-credentialcomposer-identity-exchange /usr/libexec/spire/plugins/credentialcomposer-identity-exchange
  /usr/libexec/spire/plugins/credentialcomposer-identity-exchange || true
}

