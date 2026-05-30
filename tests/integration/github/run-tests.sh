#!/usr/bin/env bash
# shellcheck disable=SC2317

set -xe

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
  sudo systemctl status spire-server@main || true
  sudo spire-server entry show || true
  sudo systemctl status spire-controller-manager@main || true
  sudo systemctl status spire-agent@main || true
  sudo systemctl status spire-agent@six || true
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
sudo cp "${SCRIPTPATH}/agent.conf" /etc/spire/server/main.conf
sudo systemctl start spire-server@main spire-controller-manager@main
wait_for_healthcheck spire-server /run/spire/server/sockets/main/private/api.sock

# Configure our agents. For the test, create join tokens for both agents. You should really use a node attestor other then join tokens such as tpm-direct, http_challenge, or a cloud provider one
JOIN_TOKEN=$(sudo spire-server token generate -spiffeID spiffe://example.org/agent/node1 -socketPath /run/spire/server/sockets/a/private/api.sock | awk '{print "\""$2"\""}')
export JOIN_TOKEN
sudo /bin/bash -c "echo JOIN_TOKEN=${JOIN_TOKEN} > /etc/spire/agent/main.env"
sudo cp "${SCRIPTPATH}/six-agent.conf" /etc/spire/agent/six.conf

# Startup the agents
sudo systemctl start spire-agent@main spire-agent@six
wait_for_healthcheck spire-agent /var/run/spire/agent/sockets/main/public/api.sock
wait_for_healthcheck spire-agent /var/run/spire/agent/sockets/six/public/api.sock

exit 1
