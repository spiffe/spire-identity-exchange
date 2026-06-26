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
  kubectl logs deploy/spire-identity-exchange -c spire-server-attestor || true
  kubectl describe pod -n spire-server spire-server-0 || true
  kubectl logs -n spire-server spire-server-0 -c init-plugin-0 || true
  kubectl logs -n spire-server spire-server-0 -c spire-server || true
  kubectl exec -it -n spire-server spire-server-0 -c spire-server -- spire-server entry show || true
  kubectl get pods -A || true
  kubectl get nodes || true
  EXCHANGE_POD_NAME=$(kubectl get pods -n default -l app=spire-identity-exchange -o jsonpath='{.items[*].metadata.name}')
  NODE_NAME=$(kubectl get pod "${EXCHANGE_POD_NAME}" -n default -o jsonpath='{.spec.nodeName}')
  AGENT_POD=$(kubectl get pods -n spire-server -l app.kubernetes.io/name=agent --field-selector "spec.nodeName=${NODE_NAME}" -o jsonpath='{.items[0].metadata.name}')
  kubectl logs "${AGENT_POD}" -n spire-server
}

trap 'EC=$? && trap - SIGTERM && teardown $EC' SIGINT SIGTERM EXIT

IMAGE_REF=$(ko build ./cmd/spire-credentialcomposer-identity-exchange/ --platform=linux/amd64 --local)
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

timeout 120 helm upgrade --install -n spire-server spire helm-charts-hardened/charts/spire -f "${SCRIPTPATH}/spire-values.yaml" --wait

mkdir -p certs
openssl req -x509 -newkey rsa:2048 \
    -keyout certs/server.key \
    -out certs/server.pem -sha256 -days 365 -nodes \
    -subj "/CN=localhost" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "subjectAltName=DNS:localhost,DNS:spire-identity-exchange.example.org,IP:127.0.0.1"

kubectl create secret tls spire-identity-exchange --key=certs/server.key --cert=certs/server.pem
timeout 120 helm upgrade --install -n spire-server spire helm-charts-hardened/charts/spire -f "${SCRIPTPATH}/spire-values.yaml" --wait

cat > test-values.yaml <<EOF
tls:
  externalSecret:
    enabled: true
    secretName: spire-identity-exchange
auth:
  plugins:
    - plugin: k8s_psat
      config:
        audiences:
          - spire-identity-exchange
        allowedServiceAccounts:
          - default/default
image:
  tag: "dev"
  pullPolicy: Never
spireServerAttestorSPIFFEWorkloadAPI:
  image:
    tag: "dev"
  pullPolicy: Never
EOF

helm upgrade --install spire-identity-exchange helm-charts-hardened/charts/spire-identity-exchange -f test-values.yaml
kubectl wait --for=condition=available --timeout=30s deployment/spire-identity-exchange

sleep 15

kubectl apply -f "${SCRIPTPATH}/test-job.yaml"
kubectl wait --for=condition=complete --timeout=60s job/test && \
kubectl logs job/test | base64 -d | tar -xvf -
openssl x509 -in x509/0/credential-bundle.pem -noout -text | grep 'spiffe://example.org/k8s-psat/test'

