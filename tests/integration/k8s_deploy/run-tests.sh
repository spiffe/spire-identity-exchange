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
  kubectl get pods -l app=spire-identity-exchange -o name | xargs kubectl describe || true
  kubectl logs deploy/spire-identity-exchange -c spire-identity-exchange || true
  kubectl logs deploy/spire-identity-exchange -c spire-agent || true
  kubectl describe pod -n spire-server spire-server-0 || true
  kubectl logs -n spire-server spire-server-0 -c install-custom-plugin || true
  kubectl logs -n spire-server spire-server-0 -c spire-server || true
  kubectl exec -it -n spire-server spire-server-0 -c spire-server -- spire-server entry show || true
  kubectl get pods -A || true
  kubectl get nodes || true
}

trap 'EC=$? && trap - SIGTERM && teardown $EC' SIGINT SIGTERM EXIT

IMAGE_REF=$(ko build ./cmd/spire-credentialcomposer-identity-exchange/ --platform=linux/amd64 --local)
docker tag "$IMAGE_REF" ghcr.io/spiffe/spire-credentialcomposer-identity-exchange:dev
kind load docker-image ghcr.io/spiffe/spire-credentialcomposer-identity-exchange:dev --name chart-testing

IMAGE_REF=$(ko build ./cmd/spire-identity-exchange-server/ --platform=linux/amd64 --local)
docker tag "$IMAGE_REF" ghcr.io/spiffe/spire-identity-exchange-server:dev
kind load docker-image ghcr.io/spiffe/spire-identity-exchange-server:dev --name chart-testing

helm upgrade --install -n spire-server spire-crds spire-crds --repo https://spiffe.github.io/helm-charts-hardened/ --create-namespace
timeout 120 helm upgrade --install -n spire-server spire spire --repo https://spiffe.github.io/helm-charts-hardened/ -f "${SCRIPTPATH}/spire-values.yaml" --wait

mkdir -p certs
openssl req -x509 -newkey rsa:2048 \
    -keyout certs/server.key \
    -out certs/server.pem -sha256 -days 365 -nodes \
    -subj "/CN=localhost" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "subjectAltName=DNS:localhost,DNS:spire-identity-exchange.example.org,IP:127.0.0.1"

kubectl create secret tls spire-identity-exchange --key=certs/server.key --cert=certs/server.pem
kubectl create configmap spire-identity-exchange --from-file="${SCRIPTPATH}/default.json" --from-file="${SCRIPTPATH}/six-agent.conf"
kubectl apply -f "${SCRIPTPATH}/service.yaml"
kubectl apply -f "${SCRIPTPATH}/deployment.yaml"
kubectl wait --for=condition=available --timeout=30s deployment/spire-identity-exchange

sleep 15

kubectl apply -f "${SCRIPTPATH}/test-job.yaml"
kubectl wait --for=condition=complete --timeout=60s job/test && \
kubectl logs job/test | base64 -d | tar -xvf -
openssl x509 -in x509/0/credential-bundle.pem -noout -text | grep 'spiffe://example.org/k8s-psat/test'
