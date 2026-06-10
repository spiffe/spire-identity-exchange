#!/bin/bash

teardown() {
  echo ---------------------------
  echo "::group::Status Output"
  kubectl get pods -l job-name=test -o name | xargs kubectl describe || true
  kubectl logs job/test || true
  sudo journalctl -u spire-identity-exchange@main.service || true
  kubectl logs -n kube-system kube-apiserver-chart-testing-control-plane || true
  sudo systemctl status spire-identity-exchange-job -n 1000  2>&1 || true
  sudo systemctl status k8s-spiffe-workload-auth-config 2>&1 || true
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

