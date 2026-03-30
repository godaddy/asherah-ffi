# HashiCorp Vault Transit KMS

Asherah supports [HashiCorp Vault](https://www.vaultproject.io/)'s
[Transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
as a key management backend. Vault Transit acts as an **encryption oracle** —
the master key never leaves Vault, and all encrypt/decrypt operations are
performed server-side via Vault's API.

This is the recommended KMS backend for on-premises deployments where AWS KMS
is not available.

## How It Works

Asherah's key hierarchy uses a **system key** at the top level, which is
encrypted by the KMS backend. With Vault Transit:

1. Asherah generates a system key (random AES-256 key)
2. Asherah sends the system key to Vault Transit for encryption
3. Vault encrypts it with a named key managed by Vault (the master key)
4. The encrypted system key is stored in the metastore (DynamoDB, MySQL, etc.)
5. On decrypt, Asherah sends the encrypted system key back to Vault
6. Vault decrypts and returns the plaintext system key

The master key inside Vault is **never exposed** — Asherah only sees ciphertext.
Vault handles key versioning, rotation, and access control.

## Prerequisites

1. A running [HashiCorp Vault](https://developer.hashicorp.com/vault/install) server
2. The [Transit secrets engine](https://developer.hashicorp.com/vault/docs/secrets/transit)
   enabled
3. A named encryption key created in Transit
4. An authentication method configured for your application

### Quick Setup (Development)

```bash
# Start Vault in dev mode (NOT for production)
docker run -d --name vault \
  --cap-add=IPC_LOCK \
  -e VAULT_DEV_ROOT_TOKEN_ID=dev-token \
  -p 8200:8200 \
  hashicorp/vault

# Enable Transit engine
export VAULT_ADDR=http://localhost:8200
export VAULT_TOKEN=dev-token
vault secrets enable transit

# Create a named key for Asherah
vault write transit/keys/asherah-master type=aes256-gcm96
```

### Production Setup

```bash
# Enable Transit (if not already enabled)
vault secrets enable transit

# Create a key with auto-rotation every 90 days
vault write transit/keys/asherah-master \
  type=aes256-gcm96 \
  auto_rotate_period=2160h

# Create a policy that only allows encrypt/decrypt (not key export)
vault policy write asherah-transit - <<EOF
path "transit/encrypt/asherah-master" {
  capabilities = ["update"]
}
path "transit/decrypt/asherah-master" {
  capabilities = ["update"]
}
EOF
```

## Configuration

Set `KMS=vault` (or `KMS=vault-transit`) and provide the following environment
variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `VAULT_ADDR` | Yes | Vault server URL (e.g., `https://vault.example.com:8200`) |
| `VAULT_TRANSIT_KEY` | Yes | Name of the Transit key (e.g., `asherah-master`) |
| `VAULT_TRANSIT_MOUNT` | No | Transit mount path (default: `transit`) |

### Authentication

Vault requires authentication to make API calls. Asherah supports four auth
methods, configured via environment variables:

#### 1. Token (Development / Simple)

Set `VAULT_TOKEN` directly. Simple but requires a long-lived token.

```bash
export VAULT_TOKEN=hvs.CAESIJ...
```

**When to use:** Development, testing, or when tokens are managed externally
(e.g., injected by a deployment pipeline).

**Not recommended for production** — tokens can expire, and storing them in
config has the same secret-zero problem as a static master key.

#### 2. Kubernetes (Pods)

Pods authenticate using their service account JWT, which is automatically
mounted by Kubernetes. No secrets to manage.

```bash
export VAULT_AUTH_METHOD=kubernetes
export VAULT_AUTH_ROLE=asherah-role
```

| Variable | Required | Description |
|----------|----------|-------------|
| `VAULT_AUTH_METHOD` | Yes | Set to `kubernetes` |
| `VAULT_AUTH_ROLE` | Yes | Vault role name bound to the service account |
| `VAULT_K8S_TOKEN_PATH` | No | Path to the SA token (default: `/var/run/secrets/kubernetes.io/serviceaccount/token`) |
| `VAULT_AUTH_MOUNT` | No | Auth method mount path (default: `kubernetes`) |

**Vault setup:**
```bash
# Enable Kubernetes auth
vault auth enable kubernetes

# Configure it with the cluster's CA and API server
vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc"

# Create a role bound to a service account
vault write auth/kubernetes/role/asherah-role \
  bound_service_account_names=asherah-sa \
  bound_service_account_namespaces=default \
  policies=asherah-transit \
  ttl=1h
```

**When to use:** Any Kubernetes deployment. This is the recommended auth method
for containerized workloads. No secret zero problem — the pod's identity is
its credential.

#### 3. AppRole (CI / Automation)

AppRole uses a role ID (public, baked into the app) and a secret ID (private,
delivered at deployment time, optionally single-use).

```bash
export VAULT_AUTH_METHOD=approle
export VAULT_APPROLE_ROLE_ID=db02de05-fa39-4855-059b-67221c5c2f63
export VAULT_APPROLE_SECRET_ID=6a174c20-f6de-a53c-74d2-6018fcceff64
```

| Variable | Required | Description |
|----------|----------|-------------|
| `VAULT_AUTH_METHOD` | Yes | Set to `approle` |
| `VAULT_APPROLE_ROLE_ID` | Yes | Role ID (can be baked into deployment config) |
| `VAULT_APPROLE_SECRET_ID` | No | Secret ID (delivered at deploy time) |
| `VAULT_AUTH_MOUNT` | No | Auth method mount path (default: `approle`) |

**Vault setup:**
```bash
# Enable AppRole auth
vault auth enable approle

# Create a role with the transit policy
vault write auth/approle/role/asherah \
  policies=asherah-transit \
  token_ttl=1h \
  token_max_ttl=4h \
  secret_id_ttl=10m \
  secret_id_num_uses=1

# Get the role ID (bake this into your deployment)
vault read auth/approle/role/asherah/role-id

# Generate a single-use secret ID (deliver this at deploy time)
vault write -f auth/approle/role/asherah/secret-id
```

**When to use:** CI/CD pipelines, VMs, or any environment where you can
separate role ID (public) from secret ID (private, short-lived). The secret ID
can be wrapped with Vault's response wrapping for additional security.

#### 4. TLS Certificate (Machine Identity)

Machines authenticate using a TLS client certificate, typically issued by
your organization's PKI or Active Directory Certificate Services.

```bash
export VAULT_AUTH_METHOD=cert
export VAULT_CLIENT_CERT=/etc/asherah/client.crt
export VAULT_CLIENT_KEY=/etc/asherah/client.key
```

| Variable | Required | Description |
|----------|----------|-------------|
| `VAULT_AUTH_METHOD` | Yes | Set to `cert` |
| `VAULT_CLIENT_CERT` | Yes | Path to PEM-encoded client certificate |
| `VAULT_CLIENT_KEY` | Yes | Path to PEM-encoded private key |
| `VAULT_AUTH_MOUNT` | No | Auth method mount path (default: `cert`) |

**Vault setup:**
```bash
# Enable TLS cert auth
vault auth enable cert

# Register your CA certificate
vault write auth/cert/certs/asherah-machines \
  display_name=asherah \
  policies=asherah-transit \
  certificate=@/path/to/ca.crt \
  ttl=1h
```

**When to use:** On-premises machines with certificates from AD CS or your
PKI. No secret zero problem — the machine's certificate is its credential.

## Feature Flag

The Vault Transit KMS requires the `vault` feature flag:

```toml
[dependencies]
asherah = { version = "0.1", features = ["vault"] }
```

The feature adds `reqwest` (with `rustls-tls`, no OpenSSL dependency) for
Vault HTTP API calls.

## Example

```bash
# Using Kubernetes auth with DynamoDB metastore
export KMS=vault
export VAULT_ADDR=https://vault.internal:8200
export VAULT_AUTH_METHOD=kubernetes
export VAULT_AUTH_ROLE=asherah-role
export VAULT_TRANSIT_KEY=asherah-master

export Metastore=dynamodb
export DDB_TABLE=EncryptionKey
export AWS_REGION=us-west-2

export SERVICE_NAME=my-service
export PRODUCT_ID=my-product
```

## Key Rotation

Vault Transit supports automatic key rotation. When a key is rotated:

- New encryptions use the latest key version
- Old ciphertexts can still be decrypted (Vault maintains all versions)
- No data migration required — Vault handles versioned decryption transparently

This is a significant advantage over the static KMS and Secrets Manager KMS,
which require re-encrypting all data to rotate the master key.

To rotate the key manually:
```bash
vault write -f transit/keys/asherah-master/rotate
```

To enable automatic rotation:
```bash
vault write transit/keys/asherah-master auto_rotate_period=2160h  # 90 days
```

## Troubleshooting

**"Vault Transit encrypt request failed: connection refused"**
- Verify `VAULT_ADDR` is correct and Vault is reachable
- Check firewall rules between your application and Vault

**"Vault kubernetes auth failed: permission denied"**
- Verify the service account name and namespace match the Vault role
- Check that the Kubernetes auth backend is configured with the correct
  cluster CA and API server URL

**"Vault Transit encrypt failed: 1 error occurred: permission denied"**
- The authenticated token doesn't have the `asherah-transit` policy
- Check `vault token capabilities transit/encrypt/asherah-master`

**"Vault Transit decrypt: blob is not valid UTF-8"**
- The ciphertext in the metastore is corrupted or was encrypted by a
  different KMS backend. Ensure all instances use the same KMS configuration.
