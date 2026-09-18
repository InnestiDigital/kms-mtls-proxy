# mtls-proxy

[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=InnestiDigital_kms-mtls-proxy&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=InnestiDigital_kms-mtls-proxy)

Outbound mutual TLS with a client certificate whose private key never leaves
AWS KMS. Your app sends plain HTTP to a sidecar; the sidecar handshakes,
authenticates and forwards.

```
application ──HTTP──> mtls-proxy ──mTLS──> third party
 (same ECS task)          │
                          └── kms:Sign  (one signature per TLS handshake)
```

Go's TLS stack accepts any `crypto.Signer`, so a KMS-backed signer is enough.
No key file, no PKCS#11 module, no CloudHSM.

## Setup

```bash
# 1. key
aws kms create-key --key-usage SIGN_VERIFY --key-spec RSA_4096
aws kms create-alias --alias-name alias/mtls-<app> --target-key-id <key-id>

# 2. task role: kms:GetPublicKey + kms:Sign on that key ARN.
#    Different account? The key policy must also name the role, and aliases
#    do not resolve across accounts.

# 3. CSR
cp .env.example .env
CSR_COMMON_NAME=<name they expect> CSR_ORG=<org> make csr > client.csr
openssl req -in client.csr -noout -subject -verify

# 4. send client.csr to the third party, get back leaf + intermediates
# 5. store it
aws secretsmanager create-secret --name app/mtls-client-cert \
  --secret-string file://client-cert-chain.pem

# 6. run: save the chain to certs/client-cert.pem
UPSTREAM_HOST=api.third-party.example KMS_KEY_ID=alias/... make run
```

Deploy as a sidecar in the same task, see
[`deploy/ecs-task-definition.example.json`](deploy/ecs-task-definition.example.json).
Under `awsvpc` the app reaches it at `http://127.0.0.1:8443`. Pass the chain as
`CLIENT_CERT_PEM_CONTENTS`, since ECS `secrets` inject env vars, not files.
`dependsOn` the proxy with `condition: HEALTHY`. One deployment per app per
third party: a shared proxy holds several identities and lends any of them to
any caller.

Rotation replaces key and certificate together. Repeat 1, 3, 4, 5, redeploy,
then schedule the old key for deletion. Startup warns 30 days before expiry.

## Cost

One signature per TLS connection, not per request. Warm requests add ~0.12 ms
and never touch KMS. $1 per key per month plus per-request charges; the RSA
crypto-operation quota is 1,000/second per account and region, adjustable.

`Sign` latency is dominated by the network. Measured over 25 calls per key,
subtracting a crypto-free `DescribeKey` on the same path:

| Key spec | Signing algorithm | Attributable to signing |
|---|---|---|
| `ECC_NIST_P384` | `ECDSA_SHA_384` | 0.9 ms |
| `ECC_NIST_P256` | `ECDSA_SHA_256` | 1.4 ms |
| `RSA_2048` | `RSASSA_PKCS1_V1_5_SHA_256` | 2.5 ms |
| `RSA_3072` | `RSASSA_PKCS1_V1_5_SHA_256` | 2.9 ms |
| `RSA_4096` | `RSASSA_PKCS1_V1_5_SHA_256` | 7.3 ms |

`RSA_4096` is what most counterparties expect. Where they take either, ECC
signs five to eight times cheaper. Both supported.

**Alert on the signature count tracking request volume.** That means session
resumption broke and every request now pays a handshake plus a signature.
`GET /metrics` exposes `mtls_proxy_kms_sign_total`.

Resumption is their server's property, not ours. Check it before trusting any
of the above:

```bash
UPSTREAM_HOST=api.third-party.example make probe
```

Opens connections, reports how many resumed, exits non-zero if none do. Reads
but never sends a request, so it has no side effects on them.

## Configuration

| Variable | Required for | Default | Meaning |
|---|---|---|---|
| `KMS_KEY_ID` | all | | Key id, ARN or alias of the `SIGN_VERIFY` CMK |
| `UPSTREAM_HOST` | `proxy` | | Host name of the third party |
| `CLIENT_CERT_PEM_CONTENTS` | `proxy` | | Leaf plus intermediates, inline |
| `UPSTREAM_CA_PEM` | | system roots | Pins the roots used to verify the upstream |
| `LISTEN` | | `:8443` | Listen address |
| `CSR_COMMON_NAME` | `csr` | | Subject common name |
| `CSR_ORG` | `csr` | | Subject organisation |
| `CSR_COUNTRY` | | omitted | Subject country, two-letter code |

Region and credentials come from the usual AWS chain.

| Subcommand | Purpose |
|---|---|
| `proxy` | Run the proxy. The default. |
| `probe` | Open connections to the third party and report whether they resume |
| `csr` | Print a certificate signing request signed by the CMK |
| `healthcheck` | Probe the local `/healthz`; used by the image `HEALTHCHECK` |

## Development

Docker is the only prerequisite; the Makefile wraps Go.

| Command | Needs AWS |
|---|---|
| `make test` / `cover` / `bench` / `vet` / `fmt` / `tidy` / `build` / `image` | no |
| `make csr` / `run` / `probe` / `demo` / `test-real` | yes |
| `make push` | registry |

The offline suite runs against an in-process fake KMS. It establishes that a
certificate whose private key exists only behind the KMS API completes a real
mutual TLS handshake, that 20 requests cost one signature, that an
`ENCRYPT_DECRYPT` key is refused at startup, that the CSR verifies against the
KMS public key, and that cancellation drains cleanly. `make test-real` confirms
the same against the service.

`make demo` runs the whole path against a stand-in counterparty: a throwaway
root signs an intermediate, the intermediate issues the server and client
certificates, and an nginx rejects any client it cannot verify two links up.
Needs a real key, creates nothing in AWS.

```
chain delivered to the proxy: 2 certificates
third party saw client: CN=demo-client,O=Demo
1 signing operation(s) for 11 requests
4/5 connections resumed: session resumption is working
```

```
main.go     wiring; the only file that knows the AWS SDK
src/        config, kms (crypto.Signer), proxy (TLS, forwarding, CSR, probe)
tests/      all test code, plus kmsfake, never linked into the binary
dev/        local-demo.sh
```

## KMS or CloudHSM?

Both are FIPS 140-3 Level 3 ([cert
4884](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/4884),
CloudHSM is 140-2 Level 3 on `hsm1.medium`). KMS costs you exclusive tenancy
and operational custody, not hardware protection or auditability. CloudHSM runs
$1.60 per HSM per hour and needs two for HA, so roughly $2,380 a month, plus a
vendor client in every container.

Choose CloudHSM when single-tenant hardware is contractually required, another
system needs the key through PKCS#11 or JCE, volume approaches KMS quotas, or
your threat model excludes trusting AWS operations. Compliance and
interoperability constraints, not performance ones.

## Status

Proof of concept. The cryptographic path is verified: a TLS 1.3 mutual
handshake against a real `SIGN_VERIFY` CMK, a verifying CSR, and `make demo`
end to end.

Nothing has touched a real counterparty. Their endpoint, their chain and
whether they resume sessions are unverified, as is the cross-account key policy
path and whether `UPSTREAM_CA_PEM` should pin their roots.

## Security and licence

[SECURITY.md](SECURITY.md) for reporting and scope. The proxy authenticates
none of its callers, so anything able to reach the listener can use the client
identity: keep it on loopback in a single task.

Apache Licence 2.0, see [LICENSE](LICENSE).

## Troubleshooting

| Symptom | Cause |
|---|---|
| `KMS_KEY_ID is required`, `UPSTREAM_HOST is required` | Missing variable; the message names it |
| `CMK ... has usage ENCRYPT_DECRYPT, want SIGN_VERIFY` | Wrong `--key-usage`; create a new key |
| `kms GetPublicKey: AccessDenied` | Task role policy missing or wrong ARN, or a cross-account key whose key policy omits the role |
| `upstream error: ... certificate` | Wrong client certificate, or `UPSTREAM_CA_PEM` excludes their CA |
| Signing count tracks requests | Resumption is not working; run `make probe` |
