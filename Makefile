.PHONY: test test-real cover bench vet fmt tidy build image push run csr probe demo clean

DEPLOY_VERSION ?= dev

# Fully qualified image repository, without a tag. Defaults to a bare name so
# a local build stays local. Set it to publish, eg:
#   IMAGE=<account>.dkr.ecr.<region>.amazonaws.com/mtls-proxy make push
IMAGE ?= mtls-proxy
# Which file under ~/.aws holds the profile used by `make test-real` and
# `make demo`. Override
# when the credentials live somewhere other than the default file.
AWS_CREDENTIALS_FILE ?= credentials
GOIMAGE ?= golang:1.25-alpine
GORUN ?= docker run --rm -v $(PWD):/src -w /src $(GOIMAGE)
GO ?= $(GORUN) go

# The client certificate the local proxy presents, read into the environment
# variable the proxy expects. Put the PEM at certs/client-cert.pem.
export CLIENT_CERT_PEM_CONTENTS ?= $(shell cat certs/client-cert.pem 2>/dev/null)

# run the unit tests
test:
	@$(GO) test ./...

# run the integration tests against the real KMS service. requires AWS
# credentials and MTLS_PROXY_REAL_KMS_KEY_ID; skipped by `make test`. eg:
#   AWS_PROFILE=x AWS_REGION=y \
#     MTLS_PROXY_REAL_KMS_KEY_ID=alias/y make test-real
test-real:
	@docker run --rm -v $(PWD):/src -w /src \
		-v $(HOME)/.aws:/aws:ro -e AWS_SHARED_CREDENTIALS_FILE=/aws/$(AWS_CREDENTIALS_FILE) \
		-e AWS_PROFILE -e AWS_REGION -e MTLS_PROXY_REAL_KMS_KEY_ID \
		$(GOIMAGE) go test -run RealKMS -v ./...

# run the unit tests and report coverage per function.
# tests is excluded from the measurement: it is test scaffolding, and
# counting it both inflates the denominator and hides the real figure.
cover:
	@$(GORUN) sh -c 'set -e; \
		pkgs=$$(go list ./... | grep -v /tests | paste -sd, -); \
		go test -coverpkg=$$pkgs -coverprofile=coverage.out ./...; \
		go tool cover -func=coverage.out'

# measure what the proxy adds, per request and per connection. no AWS needed:
# the fake signs locally, with an injected latency standing in for the round
# trip to KMS.
bench:
	@$(GO) test ./tests/proxy -bench . -benchtime 200x -run '^$$'

# run go vet
vet:
	@$(GO) vet ./...

# format the sources
fmt:
	@$(GO) fmt ./...

# tidy and pin dependencies (commit the result)
tidy:
	@$(GO) mod tidy

# build the binary locally, outside a container
build:
	@$(GO) build -trimpath -o mtls-proxy .

# build the container image
image:
	@docker build -t $(IMAGE):$(DEPLOY_VERSION) .

# build and push the container image. authenticate to the registry first, eg
# `aws ecr get-login-password | docker login --username AWS --password-stdin <registry>`
push:
	@docker build -t $(IMAGE):$(DEPLOY_VERSION) . \
		&& docker push $(IMAGE):$(DEPLOY_VERSION)

# run the proxy locally against .env and certs/client-cert.pem
run:
	@docker compose up --build

# generate a certificate signing request for the configured key
csr:
	@docker compose run --rm --no-deps mtls_proxy csr

# check that the third party issues session tickets, before trusting the cost
# model that assumes one signature per connection. eg:
#   UPSTREAM_HOST=api.third-party.example CONNECTIONS=10 make probe
CONNECTIONS ?= 5
probe:
	@docker compose run --rm --no-deps mtls_proxy probe $(CONNECTIONS)

# prove the whole path locally: a throwaway CA, a stand-in third party that
# demands a client certificate, and a real KMS key behind the handshake. eg:
#   AWS_PROFILE=x KMS_KEY_ID=alias/y make demo
demo:
	@AWS_CREDENTIALS_FILE=$(AWS_CREDENTIALS_FILE) ./dev/local-demo.sh

clean:
	@rm -f mtls-proxy coverage.out
