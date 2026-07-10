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
  kubectl get pods -l job-name=test -o name | xargs kubectl describe || true
  kubectl logs job/test || true
  sudo journalctl -u spire-identity-exchange-server@main.service || true
  kubectl logs -n kube-system kube-apiserver-chart-testing-control-plane || true
  sudo systemctl status spire-identity-exchange-job -n 1000  2>&1 || true
  sudo systemctl status k8s-spiffe-workload-auth-config 2>&1 || true
  sudo systemctl status k8s-spiffe-oidc-discovery-provider.service 2>&1 || true
  sudo spire-server agent show -spiffeID spiffe://example.org/spire/agent/x509pop/spire-identity-exchange/node1 || true
  sudo systemctl status spire-identity-exchange-server@main.service -n 50 2>&1 || true
  sudo systemctl status spire-server@main -n 50 2>&1 || true
  sudo spire-server entry show 2>&1 || true
  sudo systemctl status spire-controller-manager@main 2>&1 || true
  sudo systemctl status spire-agent@main 2>&1 || true
  sudo systemctl status spire-agent@main-six 2>&1 || true
  sudo cat /etc/kubernetes/pki/auth-config.yaml
}

trap 'EC=$? && trap - SIGTERM && teardown $EC' SIGINT SIGTERM EXIT

deploy_credential_composer
deploy_server_attestor

sudo mkdir -p /etc/spire/server/main/manifests
sudo cp "${SCRIPTPATH}/manifests"/* /etc/spire/server/main/manifests/

# Common spire setup bits
setup_base_spire "${SCRIPTPATH}" "${SCRIPTPATH}/../common"

sudo sed -i 's@jwt_issuer.*@jwt_issuer = "https://oidc-discovery-provider.example.org:8181"@' /etc/spire/server/default.conf
sudo systemctl restart spire-server@main
sudo systemctl restart spire-agent@main
sudo cat /etc/spire/server/default.conf

# Zot bits
git clone https://github.com/project-zot/zot
cd zot
make binary-minimal
sudo cp -a bin/zot-linux-amd64-minimal /usr/bin/zot
cd ..
sudo spire-server bundle show -format pem > /tmp/ca.pem
sudo zot serve "${SCRIPTPATH}/zot.yaml" &

# K8s specific bits
sudo apt-get install -y k8s-spiffe-workload-auth-config k8s-spiffe-workload-jwt-exec-auth spiffe-helper spiffe-oidc-discovery-provider k8s-spiffe-oidc-discovery-provider
sudo cp "${SCRIPTPATH}/auth-config.yaml" /etc/kubernetes/auth-config.yaml
IP=$(ip -4 addr show docker0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
sudo sed -i "s/127.0.0.1/$IP/" /etc/spiffe/k8s-oidc-discovery-provider.conf
sudo sed -i 's@"jwt_issuer".*@"jwt_issuer": "https://oidc-discovery-provider.example.org:8181",@' /etc/spiffe/k8s-oidc-discovery-provider.conf
sudo sed -i 's/"domains": \[/"domains": \[\n    "oidc-discovery-provider.example.org",/' /etc/spiffe/k8s-oidc-discovery-provider.conf
cat /etc/spiffe/k8s-oidc-discovery-provider.conf
sudo systemctl restart k8s-spiffe-oidc-discovery-provider

wait_for_oidc "https://k8ssodp.example.org:8181"

sudo systemctl restart k8s-spiffe-workload-auth-config

kubectl apply -f "${SCRIPTPATH}/../../../k8s/spire-identity-exchange-clusterrole.yaml"
kubectl create clusterrolebinding spire-identity-exchange --clusterrole=spire-identity-exchange --user="spiffe://example.org/service/spire-identity-exchange"

docker exec -i chart-testing-control-plane bash -c 'kubeadm kubeconfig user --client-name=spire-identity-exchange' > "spire-identity-exchange.kubeconfig"
yq -i '.users[] |= select(.name == "spire-identity-exchange").user |= (del(."client-certificate-data", ."client-key-data") | .exec = {"apiVersion": "client.authentication.k8s.io/v1", "command": "k8s-spiffe-workload-jwt-exec-auth", "interactiveMode": "Never", "env": [{"name": "SPIFFE_JWT_AUDIENCE", "value": "k8s-main"}, {"name": "SPIFFE_ENDPOINT_SOCKET", "value": "unix:///var/run/spire/agent/sockets/main/public/api.sock"}]})' spire-identity-exchange.kubeconfig
cat spire-identity-exchange.kubeconfig
sudo mkdir -p /etc/spire/identity-exchange
sudo mv spire-identity-exchange.kubeconfig /etc/spire/identity-exchange

wait_for_kubectl

docker exec -i chart-testing-control-plane bash -c 'cat /etc/kubernetes/pki/auth-config.yaml'
docker exec -i chart-testing-control-plane bash -c 'cat /etc/hosts'
docker exec -i chart-testing-control-plane bash -c 'curl -k https://k8ssodp.example.org:8181/.well-known/openid-configuration'

sudo cat /etc/kubernetes/manifests/kube-apiserver.yaml
sudo ls /etc/kubernetes/pki/

# Setup spire-identity-exchange
setup_identity_exchange "${SCRIPTPATH}" "${SCRIPTPATH}/../common"

# Tests

SPIFFE_TOKEN=$(timeout 10 sudo systemd-run --wait --pipe --unit=zot-job spire-agent api fetch jwt -audience spire-identity-exchange -output json | jq -r '.[0].svids[0].svid')

IP=$(ip -4 addr show docker0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
sed -i "s/127.0.0.1/$IP/" "${SCRIPTPATH}/test-job.yaml"
kubectl apply -f "${SCRIPTPATH}/test-job.yaml"
kubectl wait --for=condition=complete --timeout=60s job/test && \
K8S_TOKEN=$(kubectl logs job/test | tr -d '[:space:]')
#FIXME
echo foo
echo "${SPIFFE_TOKEN} ${K8S_TOKEN}" | base64
echo bar
FINALTOKEN=$(curl -k -X POST https://localhost:8444/api/v1/svid/zot/jwt \
  -H "Authorization: Bearer k8s_psat=${K8S_TOKEN}:spiffe=${SPIFFE_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{"audiences": ["zot"]}')

AUTH_STR=$(echo -n "zot:$FINALTOKEN" | base64 -w 0)

mkdir -p crane-config
cat <<EOF > crane-config/config.json
{
  "auths": {
    "zot.example.org:5000": {
      "registryToken": "${AUTH_STR}"
    }
  }
}
EOF
cat crane-config/config.json
docker pull docker.io/library/busybox:latest
docker tag docker.io/library/busybox:latest zot.example.org:5000/test/busybox:latest
docker save zot.example.org:5000/test/busybox:latest -o busybox.tar
DOCKER_CONFIG=./crane-config ~/go/bin/crane push busybox.tar zot.example.org:5000/test/busybox:latest --insecure

