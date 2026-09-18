#!/usr/bin/env bash
# End-to-end demo against a real KMS key, with a stand-in for the third party.
#
# It mints a throwaway root and intermediate CA, has the intermediate sign a
# CSR produced by the KMS key, and puts an nginx behind it that refuses any
# client it cannot verify against that chain. A plain HTTP request to the proxy
# then has to come back through a real mutual TLS handshake, or it does not
# come back at all.
#
# The certificate is delivered the way a counterparty delivers one, leaf
# followed by their intermediate, through the same environment variable
# Fargate would use.
#
# Everything lives in a temp directory and two containers on their own network,
# all removed on exit. Nothing is created in AWS: the key must already exist.
set -euo pipefail

: "${KMS_KEY_ID:?set KMS_KEY_ID to a SIGN_VERIFY key, eg alias/mtls-<app>-<third-party>}"
AWS_REGION=${AWS_REGION:-}
AWS_PROFILE=${AWS_PROFILE:-}
# Which file under ~/.aws holds the profile, so a profile parked in a
# non-default file can be used without editing the default one.
AWS_CREDENTIALS_FILE=${AWS_CREDENTIALS_FILE:-credentials}
LISTEN_PORT=${LISTEN_PORT:-8443}

NETWORK=mtls-demo
UPSTREAM=third-party
work=$(mktemp -d)

cleanup() {
	docker rm -f "$UPSTREAM" mtls-demo-proxy >/dev/null 2>&1 || true
	docker network rm "$NETWORK" >/dev/null 2>&1 || true
	rm -rf "$work"
}
trap cleanup EXIT

step() { printf '\n== %s\n' "$1"; }

step "building the proxy image"
docker build -q -t mtls-proxy:demo . >/dev/null

# A root that signs an intermediate, which signs everything else. Real
# counterparties issue from an intermediate and hand back leaf plus chain, so a
# demo with a single self-signed CA would never exercise the multi-certificate
# path the proxy has to get right.
step "minting a throwaway root and intermediate CA"
openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
	-keyout "$work/root.key" -out "$work/root.pem" \
	-subj "/O=Demo CA/CN=demo-root" 2>/dev/null

openssl req -newkey rsa:2048 -nodes -days 1 \
	-keyout "$work/intermediate.key" -out "$work/intermediate.csr" \
	-subj "/O=Demo CA/CN=demo-intermediate" 2>/dev/null
openssl x509 -req -in "$work/intermediate.csr" -days 1 \
	-CA "$work/root.pem" -CAkey "$work/root.key" -CAcreateserial \
	-extfile <(printf 'basicConstraints=critical,CA:TRUE,pathlen:0\nkeyUsage=critical,keyCertSign,cRLSign\n') \
	-out "$work/intermediate.pem" 2>/dev/null

# What the proxy pins as the upstream roots, and what nginx verifies clients
# against: the root plus the intermediate that actually issued the leaf.
cat "$work/root.pem" "$work/intermediate.pem" >"$work/ca-bundle.pem"

step "issuing the third party's server certificate"
openssl req -newkey rsa:2048 -nodes -days 1 \
	-keyout "$work/server.key" -out "$work/server.csr" \
	-subj "/CN=$UPSTREAM" 2>/dev/null
openssl x509 -req -in "$work/server.csr" -days 1 \
	-CA "$work/intermediate.pem" -CAkey "$work/intermediate.key" -CAcreateserial \
	-extfile <(printf 'subjectAltName=DNS:%s\nextendedKeyUsage=serverAuth\n' "$UPSTREAM") \
	-out "$work/server-leaf.pem" 2>/dev/null
# Servers send leaf first, then the chain. Same rule as the client side.
cat "$work/server-leaf.pem" "$work/intermediate.pem" >"$work/server.pem"

step "asking KMS for a CSR (the private key never leaves it)"
docker run --rm -v "$HOME/.aws:/aws:ro" \
	-e AWS_SHARED_CREDENTIALS_FILE="/aws/$AWS_CREDENTIALS_FILE" \
	-e AWS_PROFILE="$AWS_PROFILE" -e AWS_REGION="$AWS_REGION" \
	-e KMS_KEY_ID="$KMS_KEY_ID" \
	-e CSR_COMMON_NAME=demo-client -e CSR_ORG="Demo" \
	mtls-proxy:demo csr >"$work/client.csr"

step "signing that CSR into a client certificate, issued by the intermediate"
openssl x509 -req -in "$work/client.csr" -days 1 \
	-CA "$work/intermediate.pem" -CAkey "$work/intermediate.key" -CAcreateserial \
	-extfile <(printf 'extendedKeyUsage=clientAuth\n') \
	-out "$work/client-leaf.pem" 2>/dev/null
# Exactly what a counterparty hands back: leaf first, then their intermediate.
cat "$work/client-leaf.pem" "$work/intermediate.pem" >"$work/client.pem"
openssl x509 -in "$work/client-leaf.pem" -noout -subject -issuer
printf 'chain delivered to the proxy: %s certificates\n' \
	"$(grep -c 'BEGIN CERTIFICATE' "$work/client.pem")"

cat >"$work/nginx.conf" <<NGINX
events {}
http {
  server {
    listen 443 ssl;
    ssl_certificate     /etc/demo/server.pem;
    ssl_certificate_key /etc/demo/server.key;

    # The whole point: no client certificate chaining to this CA, no reply.
    ssl_client_certificate /etc/demo/ca-bundle.pem;
    ssl_verify_client on;
    # The leaf is issued by the intermediate, so verification walks two links.
    ssl_verify_depth 2;

    location / {
      add_header Content-Type text/plain;
      return 200 "third party saw client: \$ssl_client_s_dn\n";
    }
  }
}
NGINX

step "starting the third party and the proxy"
docker network create "$NETWORK" >/dev/null
docker run -d --name "$UPSTREAM" --network "$NETWORK" \
	-v "$work:/etc/demo:ro" -v "$work/nginx.conf:/etc/nginx/nginx.conf:ro" \
	nginx:alpine >/dev/null

docker run -d --name mtls-demo-proxy --network "$NETWORK" \
	-p "$LISTEN_PORT:8443" \
	-v "$HOME/.aws:/aws:ro" -v "$work:/etc/demo:ro" \
	-e AWS_SHARED_CREDENTIALS_FILE="/aws/$AWS_CREDENTIALS_FILE" \
	-e AWS_PROFILE="$AWS_PROFILE" -e AWS_REGION="$AWS_REGION" \
	-e KMS_KEY_ID="$KMS_KEY_ID" \
	-e UPSTREAM_HOST="$UPSTREAM" \
	-e UPSTREAM_CA_PEM=/etc/demo/ca-bundle.pem \
	-e CLIENT_CERT_PEM_CONTENTS="$(cat "$work/client.pem")" \
	mtls-proxy:demo >/dev/null

for _ in $(seq 30); do
	curl -fsS "http://localhost:$LISTEN_PORT/healthz" >/dev/null 2>&1 && break
	sleep 1
done

step "plain HTTP in, mutual TLS out"
curl -fsS "http://localhost:$LISTEN_PORT/" || {
	echo "request failed; proxy log follows:" >&2
	docker logs mtls-demo-proxy >&2
	exit 1
}

step "signatures are per connection, not per request"
for _ in $(seq 10); do curl -fsS "http://localhost:$LISTEN_PORT/" >/dev/null; done
docker logs mtls-demo-proxy 2>&1 | grep -c 'kms:Sign' \
	| xargs printf '%s signing operation(s) for 11 requests\n'
curl -fsS "http://localhost:$LISTEN_PORT/metrics" | grep mtls_proxy_kms_sign_total

# The same check to run against a real counterparty before trusting any of the
# above, here against a real TLS server rather than a test double.
step "probing the third party for session resumption"
docker run --rm --network "$NETWORK" \
	-v "$HOME/.aws:/aws:ro" -v "$work:/etc/demo:ro" \
	-e AWS_SHARED_CREDENTIALS_FILE="/aws/$AWS_CREDENTIALS_FILE" \
	-e AWS_PROFILE="$AWS_PROFILE" -e AWS_REGION="$AWS_REGION" \
	-e KMS_KEY_ID="$KMS_KEY_ID" \
	-e UPSTREAM_HOST="$UPSTREAM" \
	-e UPSTREAM_CA_PEM=/etc/demo/ca-bundle.pem \
	-e CLIENT_CERT_PEM_CONTENTS="$(cat "$work/client.pem")" \
	mtls-proxy:demo probe 5
