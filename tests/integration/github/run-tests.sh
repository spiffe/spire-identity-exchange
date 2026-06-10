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

deploy_credential_composer

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

# K8s specific bits
sudo apt-get install -y k8s-spiffe-workload-auth-config k8s-spiffe-workload-jwt-exec-auth spiffe-helper spiffe-oidc-discovery-provider k8s-spiffe-oidc-discovery-provider
sudo cp "${SCRIPTPATH}/auth-config.yaml" /etc/kubernetes/auth-config.yaml
IP=$(ip -4 addr show docker0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
sudo sed -i "s/127.0.0.1/$IP/" /etc/spiffe/k8s-oidc-discovery-provider.conf
cat /etc/spiffe/k8s-oidc-discovery-provider.conf
sudo systemctl restart k8s-spiffe-oidc-discovery-provider

wait_for_oidc

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
  -d "{\"githubOIDC\":{\"githubToken\":\"${MOCKHUB_TOKEN}\"},\"mintJWTSVIDRequest\":{\"audiences\":[\"foo\"]}}" \
  localhost:8443 \
  proto.spiffe.spireidentityexchange.SpireIdentityExchangeApi/MintCertificate

diff -u <(curl https://localhost:8444/api/v1/trustbundle/x509 --cacert /etc/spire/identity-exchange/main/certs/server.pem -s) <(sudo spire-server bundle show)

if [ -n "$GITHUB_TOKEN" ]; then
	curl -f -H "Authorization: Bearer ${GITHUB_TOKEN}" -X POST https://localhost:8444/api/v1/svid/github/x509 --cacert /etc/spire/identity-exchange/main/certs/server.pem -sS
fi

curl -f -H "Authorization: Bearer ${MOCKHUB_TOKEN}" -X POST https://localhost:8444/api/v1/svid/mockhub/x509 --cacert /etc/spire/identity-exchange/main/certs/server.pem -sS

# K8s Tests
IP=$(ip -4 addr show docker0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}')
sed -i "s/127.0.0.1/$IP/" "${SCRIPTPATH}/test-job.yaml"
kubectl apply -f "${SCRIPTPATH}/test-job.yaml"
kubectl wait --for=condition=complete --timeout=60s job/test && \
kubectl logs job/test | base64 -d | tar -xvf -
openssl x509 -in x509/0/credential-bundle.pem -noout -text | grep 'spiffe://example.org/k8s-psat/test'
