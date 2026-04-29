# AWS production setup

End-to-end walkthrough for a production deployment using **AWS KMS**
for the master key and **DynamoDB** for the metastore.

## Prerequisites

1. An AWS account with permission to create KMS keys, DynamoDB tables,
   and IAM policies.
2. A way to deliver AWS credentials to your Node.js process — IAM role
   for ECS/EKS/EC2, AWS SSO profile for development, or environment
   variables (`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
   `AWS_SESSION_TOKEN`) for CI. **Asherah does not load credentials
   itself**; the AWS SDK for Rust (running in the native core) reads
   from the standard credential chain.

## Step 1: create KMS keys

Create one symmetric KMS key per region you want to operate in. The
key encrypts Asherah's per-product *system keys* — Asherah does not
pass user data to KMS. Encryption volume is small (~1 KMS call per
product per ~90 days under default rotation).

```bash
aws kms create-key \
    --region us-east-1 \
    --description "Asherah system-key encryption" \
    --tags TagKey=Application,TagValue=asherah \
    --query 'KeyMetadata.{Arn:Arn,KeyId:KeyId}'
```

Repeat for any other regions you want included in `regionMap`. Record
the ARNs.

## Step 2: create the DynamoDB metastore table

Schema is fixed: partition key `Id` (string), sort key `Created`
(number).

```bash
aws dynamodb create-table \
    --region us-east-1 \
    --table-name AsherahKeys \
    --attribute-definitions \
        AttributeName=Id,AttributeType=S \
        AttributeName=Created,AttributeType=N \
    --key-schema \
        AttributeName=Id,KeyType=HASH \
        AttributeName=Created,KeyType=RANGE \
    --billing-mode PAY_PER_REQUEST \
    --tags Key=Application,Value=asherah
```

Table size is small (one row per service+product+intermediate-key
generation); on-demand billing is fine. For multi-region, enable
[DynamoDB global tables](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GlobalTables.html).

## Step 3: IAM policy

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AsherahKms",
      "Effect": "Allow",
      "Action": ["kms:Encrypt", "kms:Decrypt"],
      "Resource": [
        "arn:aws:kms:us-east-1:111111111111:key/abc-123",
        "arn:aws:kms:us-west-2:111111111111:key/def-456"
      ]
    },
    {
      "Sid": "AsherahMetastore",
      "Effect": "Allow",
      "Action": ["dynamodb:GetItem", "dynamodb:Query", "dynamodb:PutItem"],
      "Resource": "arn:aws:dynamodb:us-east-1:111111111111:table/AsherahKeys"
    }
  ]
}
```

Attach to the IAM role/user the application runs as. Asherah doesn't
use `kms:GenerateDataKey` — system-key plaintext is generated locally
and only the encrypted form crosses the wire.

## Step 4: configure Asherah

```javascript
import { SessionFactory } from "asherah";

const factory = new SessionFactory({
  serviceName: "payments",      // your service identifier
  productId: "checkout",         // your product identifier within the service
  metastore: "dynamodb",
  dynamoDbTableName: "AsherahKeys",
  dynamoDbRegion: "us-east-1",
  kms: "aws",
  regionMap: {
    "us-east-1": "arn:aws:kms:us-east-1:111111111111:key/abc-123",
    "us-west-2": "arn:aws:kms:us-west-2:111111111111:key/def-456",
  },
  preferredRegion: "us-east-1",  // pick which region's KMS key to encrypt new system keys with
  enableSessionCaching: true,    // default; cache sessions per partition
  expireAfter: 90 * 24 * 60 * 60,        // intermediate-key rotation cadence in seconds
  checkInterval: 60 * 60,                 // revoke-check interval in seconds
});
```

`serviceName` and `productId` together form the prefix for generated
intermediate-key IDs. Pick stable identifiers — changing them later
makes existing envelope keys un-decryptable.

## Step 5: hook observability

```javascript
import asherah from "asherah";
import pino from "pino";
import { metrics } from "@opentelemetry/api";

const log = pino();

asherah.setLogHook((level, target, message) => {
  const fn = level === "error" ? "error"
           : level === "warn"  ? "warn"
           : level === "debug" ? "debug"
           : "info";
  log[fn]({ asherah_target: target }, message);
});

const meter = metrics.getMeter("asherah");
const histos = {
  encrypt: meter.createHistogram("asherah.encrypt.duration", { unit: "ms" }),
  decrypt: meter.createHistogram("asherah.decrypt.duration", { unit: "ms" }),
  store: meter.createHistogram("asherah.store.duration", { unit: "ms" }),
  load: meter.createHistogram("asherah.load.duration", { unit: "ms" }),
};
const counters = {
  cache_hit: meter.createCounter("asherah.cache.hits"),
  cache_miss: meter.createCounter("asherah.cache.misses"),
  cache_stale: meter.createCounter("asherah.cache.stale"),
};

asherah.setMetricsHook((eventType, durationNs, name) => {
  if (histos[eventType])  histos[eventType].record(durationNs / 1e6);
  if (counters[eventType]) counters[eventType].add(1, { cache: name });
});
```

## Step 6: verify with a smoke test

The first encrypt call:
1. Loads or creates a system key (1 KMS `Decrypt` to fetch, or 1
   `Encrypt` + 1 `PutItem` to create).
2. Loads or creates an intermediate key (1 `PutItem` if creating).
3. Encrypts the data row key under the IK and the data under the DRK.

Subsequent encrypts in the same partition reuse the cached IK — no
metastore round-trip — until expiry (default 90 days).

A successful smoke test produces:
- A row in `AsherahKeys` with `Id="_SK_payments"`.
- A row in `AsherahKeys` with `Id="_IK_<partition>_payments_checkout"`.
- A log record at info level reporting IK creation.

## Region routing details

`dynamoDbRegion`, `dynamoDbSigningRegion`, and `preferredRegion` are
three distinct knobs:

| Setting | What it controls |
|---|---|
| `dynamoDbRegion` | Endpoint region for the DynamoDB SDK client (`dynamodb.<region>.amazonaws.com`). |
| `dynamoDbSigningRegion` | SigV4 signing region. Defaults to the endpoint region; override only for cross-region signing. |
| `preferredRegion` | Which entry of `regionMap` AWS KMS uses to pick a key for *new* envelope encryption. Existing envelope keys from any region in the map are still decryptable. |

In a single-region deployment all three are equal. In multi-region
active/passive, all three on the active side are the active region;
the passive side switches `dynamoDbRegion` to its region but may keep
`preferredRegion` on the active KMS key until promotion.

## Common production pitfalls

- **`enableRegionSuffix: true`** is required when `regionMap` has
  multiple regions and you use DynamoDB global tables — otherwise IK
  IDs collide across regions. Set it to disambiguate
  (`_IK_..._us-east-1`).
- **Setting `STATIC_MASTER_KEY_HEX` in production.** It's accepted but
  it's the static-KMS test mode. Production must use `kms: "aws"`.
- **IAM role missing `kms:Encrypt`.** Encrypt is needed only for
  system-key creation (rare). First IK rotation surfaces the missing
  permission if your app started with the SK already cached.
- **Native binary not loading on Alpine / musl.** npm's optional-
  dependency resolution should pick `linux-musl-x64` /
  `linux-musl-arm64` automatically. If you see "module not found"
  errors after install, check `node -p "process.report.getReport().header.glibcVersionRuntime"` —
  if it reports `undefined`, you're on musl and need
  `npm install asherah --force --foreground-scripts` to refetch the
  right native binary.
- **Lambda cold-start config**. Build the `SessionFactory` at
  module-level (outside the handler), not inside. Cold starts already
  cost ~hundreds of ms; rebuilding the factory per invocation adds
  unnecessary KMS round-trips.
