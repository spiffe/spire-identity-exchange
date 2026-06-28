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
  kubectl get pods -n spire-server -l component=spire-identity-exchange -n spire-server -o name | xargs kubectl describe || true
  kubectl logs -n spire-server deploy/spire-identity-exchange -c spire-identity-exchange || true
  kubectl logs -n spire-server deploy/spire-identity-exchange -c spire-agent || true
  kubectl logs -n spire-server deploy/spire-identity-exchange -c spire-server-attestor || true
  kubectl describe pod -n spire-server spire-server-0 || true
  kubectl logs -n spire-server spire-server-0 -c spire-server || true
  kubectl exec -it -n spire-server spire-server-0 -c spire-server -- spire-server entry show || true
  kubectl get pods -A || true
  kubectl get nodes || true
  EXCHANGE_POD_NAME=$(kubectl get pods -n default -l app.kubernetes.io/name=spire-identity-exchange -o jsonpath='{.items[*].metadata.name}')
  kubectl describe pod "${EXCHANGE_POD_NAME}"
  kubectl logs "${EXCHANGE_POD_NAME}"
  NODE_NAME=$(kubectl get pod "${EXCHANGE_POD_NAME}" -n default -o jsonpath='{.spec.nodeName}')
  AGENT_POD=$(kubectl get pods -n spire-server -l app.kubernetes.io/name=agent --field-selector "spec.nodeName=${NODE_NAME}" -o jsonpath='{.items[0].metadata.name}')
  kubectl logs "${AGENT_POD}" -n spire-server
}

trap 'EC=$? && trap - SIGTERM && teardown $EC' SIGINT SIGTERM EXIT

IMAGE_REF=$(ko build ./cmd/spire-credentialcomposer-identity-exchange/ --platform=linux/amd64 --local)
CC_IMAGE_REF="${IMAGE_REF}"
docker tag "$IMAGE_REF" ghcr.io/spiffe/spire-credentialcomposer-identity-exchange:dev
kind load docker-image ghcr.io/spiffe/spire-credentialcomposer-identity-exchange:dev --name chart-testing

IMAGE_REF=$(ko build ./cmd/spire-server-attestor-spiffe-workload-api/ --platform=linux/amd64 --local)
docker tag "$IMAGE_REF" ghcr.io/spiffe/spire-server-attestor-spiffe-workload-api:dev
kind load docker-image ghcr.io/spiffe/spire-server-attestor-spiffe-workload-api:dev --name chart-testing

IMAGE_REF=$(ko build ./cmd/spire-identity-exchange-server/ --platform=linux/amd64 --local)
docker tag "$IMAGE_REF" ghcr.io/spiffe/spire-identity-exchange-server:dev
kind load docker-image ghcr.io/spiffe/spire-identity-exchange-server:dev --name chart-testing

helm upgrade --install -n spire-server spire-crds spire-crds --repo https://spiffe.github.io/helm-charts-hardened/ --create-namespace
#FIXME until release
#timeout 120 helm upgrade --install -n spire-server spire spire --repo https://spiffe.github.io/helm-charts-hardened/ -f "${SCRIPTPATH}/spire-values.yaml" --wait
git clone https://github.com/spiffe/helm-charts-hardened
cd helm-charts-hardened/charts/spire
git checkout spire-identity-exchange
helm dep up
cd -
cd helm-charts-hardened/charts/spire-identity-exchange
helm dep up
cd -

mkdir -p certs
openssl req -x509 -newkey rsa:2048 \
    -keyout certs/server.key \
    -out certs/server.pem -sha256 -days 365 -nodes \
    -subj "/CN=localhost" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "subjectAltName=DNS:localhost,DNS:spire-identity-exchange.example.org,IP:127.0.0.1"

kubectl create secret tls -n spire-server spire-identity-exchange --key=certs/server.key --cert=certs/server.pem

docker create --name temp "${CC_IMAGE_REF}"
docker cp temp:/ko-app/spire-credentialcomposer-identity-exchange /tmp/cc
SUM=$(sha256sum /tmp/cc | awk '{print $1}')
timeout 120 helm upgrade --install -n spire-server spire helm-charts-hardened/charts/spire -f "${SCRIPTPATH}/spire-values.yaml" --set "spire-server.credentialComposer.spireIdentityExchange.checksum=${SUM}" --wait

kubectl apply -f "${SCRIPTPATH}/test-job.yaml"
kubectl wait --for=condition=complete --timeout=60s job/test && \
kubectl logs job/test | base64 -d | tar -xvf -
openssl x509 -in x509/0/credential-bundle.pem -noout -text | grep 'spiffe://example.org/k8s-psat/test'

