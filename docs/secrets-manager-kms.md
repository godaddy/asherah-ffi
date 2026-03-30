# AWS Secrets Manager KMS

Asherah supports [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/)
as a key management backend. This is **not a recommended production KMS** — it
is a **migration path** for teams moving from `KMS=static` to AWS, where the
master key is stored in a managed secret instead of an environment variable.

> **If you are deploying on AWS, use `KMS=aws` (AWS KMS).** AWS KMS provides
> hardware-backed key management, transparent key rotation, per-operation
> CloudTrail audit logging, and IAM access control. Secrets Manager KMS
> provides none of these — it is a static key in a managed secret store.

## When to Use This

This backend exists for **one specific scenario**: you have an existing
on-premises deployment using `KMS=static` with a hardcoded master key, and
you are migrating to AWS infrastructure. Secrets Manager lets you move the
key out of environment variables immediately (config-change-only migration,
no data re-encryption) while you plan the full migration to AWS KMS.

**Use this only when all of the following are true:**
- You currently use `KMS=static` with existing encrypted data
- You are migrating to AWS and need to stop storing the key in config
- You are not ready to re-encrypt your data for a full AWS KMS migration

**For all other cases:**
- **AWS deployments (new or existing):** Use `KMS=aws` — it is the strongly
  preferred backend on AWS
- **On-premises:** Use [Vault Transit](vault-transit-kms.md) (`KMS=vault`)
- **Testing/development:** Use `KMS=static`

## How It Works

1. At startup, Asherah fetches the secret value from AWS Secrets Manager
2. The secret is used as the AES-256 master key for the lifetime of the process
3. The key is stored in memory (same as `KMS=static`)
4. All encrypt/decrypt operations use this key identically to the static KMS

**The key is fetched once and never re-fetched.** If you update the secret in
Secrets Manager, running instances will continue using the old key until they
are restarted.

## Important Limitations

- **Not a true KMS** — this is a static master key stored in a managed secret.
  The key material is fetched and held in process memory, same as `KMS=static`.
  Asherah's intermediate keys (IKs) and system keys (SKs) still rotate on
  their normal policy schedule — only the **master key** at the top of the
  hierarchy is static.
- **No transparent master key rotation** — rotating the master key requires
  re-encrypting all system keys in the metastore (see [Key Rotation](#key-rotation)
  below). With AWS KMS or Vault Transit, master key rotation is transparent
  because the KMS service handles key versioning internally.
- **No audit trail on key usage** — Secrets Manager logs when the secret is
  *accessed*, but not when it's used for encryption/decryption. For per-operation
  audit logging, use AWS KMS or Vault Transit.

## Configuration

Set `KMS=secrets-manager` and provide the following environment variables:

| Variable | Required | Description |
|----------|----------|-------------|
| `SECRETS_MANAGER_SECRET_ID` | Yes | Secret ARN or name |
| `AWS_REGION` | Yes | AWS region for the Secrets Manager API |

Standard AWS credential resolution applies (environment variables, instance
profile, ECS task role, etc.).

### Secret Format

The secret in Secrets Manager must contain the master key in one of two formats:

**Option A: Hex-encoded string (SecretString)**

Create a secret with a hex-encoded 32-byte key (64 hex characters):

```bash
# Generate a random 32-byte key and hex-encode it
KEY_HEX=$(openssl rand -hex 32)

# Store in Secrets Manager
aws secretsmanager create-secret \
  --name asherah/master-key \
  --secret-string "$KEY_HEX"
```

**Option B: Raw binary (SecretBinary)**

Create a secret with raw 32-byte binary data:

```bash
# Generate a random 32-byte key
openssl rand 32 > /tmp/master-key.bin

# Store in Secrets Manager as binary
aws secretsmanager create-secret \
  --name asherah/master-key \
  --secret-binary fileb:///tmp/master-key.bin

# Clean up
rm /tmp/master-key.bin
```

### Migrating from KMS=static

If you're currently using `KMS=static` with `STATIC_MASTER_KEY_HEX`, you can
migrate to Secrets Manager without re-encrypting any data:

1. Store your existing key in Secrets Manager:

```bash
aws secretsmanager create-secret \
  --name asherah/master-key \
  --secret-string "$STATIC_MASTER_KEY_HEX"
```

2. Update your application config:

```bash
# Before
export KMS=static
export STATIC_MASTER_KEY_HEX=746869734973415374617469634d61737465724b6579466f7254657374696e67

# After
export KMS=secrets-manager
export SECRETS_MANAGER_SECRET_ID=asherah/master-key
export AWS_REGION=us-west-2
```

3. Remove `STATIC_MASTER_KEY_HEX` from your environment/config.

No data migration needed — the same key produces the same encryption.

## Key Rotation

**Key rotation with Secrets Manager KMS is a manual, multi-step process.**
This is fundamentally different from AWS KMS or Vault Transit, which handle
rotation transparently.

### Why Rotation Is Complex

Asherah's key hierarchy works like this:

```
Master Key (Secrets Manager)
  └── encrypts → System Key (stored in metastore)
        └── encrypts → Intermediate Keys (stored in metastore)
              └── encrypts → Data Row Keys (inline in each record)
                    └── encrypts → Your Data
```

If you change the master key, you can no longer decrypt the existing system
keys in the metastore. This means **all downstream keys become inaccessible**.

### Safe Rotation Procedure

To rotate the master key without data loss:

**Step 1: Re-encrypt all system keys with the new master key**

This requires a custom migration tool that:
1. Reads each system key from the metastore
2. Decrypts it with the OLD master key
3. Re-encrypts it with the NEW master key
4. Writes it back to the metastore

**Step 2: Update the secret in Secrets Manager**

```bash
aws secretsmanager update-secret \
  --secret-id asherah/master-key \
  --secret-string "$(openssl rand -hex 32)"
```

**Step 3: Restart all application instances**

Instances fetch the key once at startup. They need to restart to pick up the
new key.

**Step 4: Verify**

Confirm that all instances can still encrypt and decrypt data.

### Recommendation

If you need master key rotation, **migrate to AWS KMS or Vault Transit**
instead. Both handle master key versioning transparently — old ciphertexts are
decrypted with the old key version, new encryptions use the latest version, no
data migration required. Note that Asherah's intermediate and system key
rotation works normally regardless of KMS backend — it is only the master key
at the top of the hierarchy that requires this manual procedure.

## Feature Flag

The Secrets Manager KMS requires the `secrets-manager` feature flag:

```toml
[dependencies]
asherah = { version = "0.1", features = ["secrets-manager"] }
```

## Example

```bash
export KMS=secrets-manager
export SECRETS_MANAGER_SECRET_ID=arn:aws:secretsmanager:us-west-2:123456789:secret:asherah/master-key
export AWS_REGION=us-west-2

export Metastore=dynamodb
export DDB_TABLE=EncryptionKey

export SERVICE_NAME=my-service
export PRODUCT_ID=my-product
```

## Comparison with Other KMS Backends

| Feature | Static | Secrets Manager | AWS KMS | Vault Transit |
|---------|--------|----------------|---------|---------------|
| **Intended use** | Testing only | Legacy migration only | **Production (AWS)** | **Production (on-prem)** |
| Master key storage | Env var / config | AWS Secrets Manager | AWS KMS HSM | Vault server |
| Master key leaves service? | Yes (in memory) | Yes (in memory) | Never | Never |
| Master key rotation | Manual (re-encrypt SKs) | Manual (re-encrypt SKs) | Transparent | Transparent |
| IK/SK rotation | Automatic (policy-based) | Automatic (policy-based) | Automatic (policy-based) | Automatic (policy-based) |
| Per-operation audit | No | No | Yes (CloudTrail) | Yes (Vault audit) |
| Access control | None | IAM policies | IAM + key policies | Vault policies |
| Secret zero problem | Yes | No (IAM role) | No (IAM role) | Depends on auth |
| Migration from static | n/a | Config change only | Re-encrypt SKs | Re-encrypt SKs |
