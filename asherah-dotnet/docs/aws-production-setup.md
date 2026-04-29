# AWS production setup

End-to-end walkthrough for a production deployment using **AWS KMS** for
the master key and **DynamoDB** for the metastore. Adjust regions and
ARNs to match your environment.

## Prerequisites

1. An AWS account with permission to create KMS keys, DynamoDB tables,
   and IAM policies.
2. A way to deliver AWS credentials to your application — IAM role for
   ECS/EKS/EC2, AWS SSO profile for development, or environment
   variables for CI. **Asherah does not load credentials itself**; the
   AWS SDK for Rust (running in the native core) reads from the
   standard credential chain.

## Step 1: create KMS keys

Create one symmetric KMS key per region you want to operate in. The
key's purpose is to encrypt Asherah's per-product *system keys* —
Asherah does not pass user data to KMS. The encryption volume is small
(~1 KMS call per product per ~90 days under default rotation).

```bash
aws kms create-key \
    --region us-east-1 \
    --description "Asherah system-key encryption" \
    --tags TagKey=Application,TagValue=asherah \
    --query 'KeyMetadata.{Arn:Arn,KeyId:KeyId}'
```

Repeat for any other regions you want included in the `RegionMap`.
Record the ARNs — you'll plug them into `WithRegionMap` below.

For multi-region deployments, consider [AWS KMS multi-region
keys](https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html)
so encrypted system keys produced in one region can be decrypted in
another. Asherah's `RegionMap` then maps the same logical key across
all regions, and `PreferredRegion` selects which one to encrypt under.

## Step 2: create the DynamoDB metastore table

Schema is fixed: partition key `Id` (string), sort key `Created`
(number). Asherah opens the table by name; nothing else is required.

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

The table size is small (one row per service+product+intermediate-key
generation); on-demand billing is fine. For high-volume deployments
provisioned capacity is cheaper.

For multi-region deployments, enable [DynamoDB global
tables](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GlobalTables.html)
on `AsherahKeys` so envelope keys created in one region replicate to
the others.

## Step 3: IAM policy for the application

The application needs:
- `kms:Encrypt` and `kms:Decrypt` on the KMS key ARN(s).
- `dynamodb:GetItem`, `dynamodb:Query`, and `dynamodb:PutItem` on the
  metastore table ARN.

Minimal policy:

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
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:Query",
        "dynamodb:PutItem"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:111111111111:table/AsherahKeys"
    }
  ]
}
```

Attach the policy to the IAM role / user the application runs as.
Asherah does not use `kms:GenerateDataKey` — system-key plaintext is
generated locally and only the encrypted form crosses the wire.

## Step 4: configure Asherah

```csharp
using GoDaddy.Asherah.Encryption;

var regionMap = new Dictionary<string, string>
{
    ["us-east-1"] = "arn:aws:kms:us-east-1:111111111111:key/abc-123",
    ["us-west-2"] = "arn:aws:kms:us-west-2:111111111111:key/def-456",
};

var config = AsherahConfig.CreateBuilder()
    .WithServiceName("payments")          // your service identifier
    .WithProductId("checkout")             // your product identifier within the service
    .WithMetastore(MetastoreKind.DynamoDb)
    .WithDynamoDbTableName("AsherahKeys")
    .WithDynamoDbRegion("us-east-1")
    .WithKms(KmsKind.Aws)
    .WithRegionMap(regionMap)
    .WithPreferredRegion("us-east-1")     // pick which region's KMS key to encrypt new system keys with
    .WithEnableSessionCaching(true)        // default; cache sessions per partition
    .WithExpireAfter(TimeSpan.FromDays(90)) // intermediate-key rotation cadence
    .WithCheckInterval(TimeSpan.FromMinutes(60)) // revoke-check interval
    .Build();

using var factory = AsherahFactory.FromConfig(config);
```

`ServiceName` and `ProductId` together form the prefix for generated
intermediate-key IDs. Pick stable identifiers — changing them later
makes existing envelope keys un-decryptable (the old keys still exist
in the metastore but won't be looked up).

## Step 5: hook observability

Wire log records into your host's `ILogger` and metrics into a `Meter`
that's exported to your existing telemetry pipeline:

```csharp
using Microsoft.Extensions.Logging;
using System.Diagnostics.Metrics;

var loggerFactory = LoggerFactory.Create(b => b.AddConsole());
AsherahHooks.SetLogHook(loggerFactory);

var meter = new Meter("MyApp.Asherah");
AsherahHooks.SetMetricsHook(meter);
// Wire `meter` into OpenTelemetry / Prometheus / App Insights as you
// would any other Meter.
```

Once `SetMetricsHook(Meter)` is registered, the bridge creates standard
instruments (`asherah.encrypt.duration`, `asherah.decrypt.duration`,
`asherah.cache.hits`, etc.) on the `Meter` automatically.

## Step 6: verify with a smoke test

Once deployed, the first encrypt call:
1. Loads or creates a system key (1 KMS `Decrypt` call to fetch, or 1
   `Encrypt` + 1 `PutItem` to create).
2. Loads or creates an intermediate key (1 `PutItem` if creating, plus
   the cached system key — no extra KMS call).
3. Encrypts the data row key under the IK and the data under the DRK.

Subsequent encrypts in the same partition reuse the cached IK — no
metastore round-trip — until it expires (default 90 days).

A successful smoke test produces:
- A row in `AsherahKeys` with `Id="_SK_payments"` (the system key).
- A row in `AsherahKeys` with `Id="_IK_<partition>_payments_checkout"`
  (the intermediate key).
- A `LogEvent` at `Information` level reporting the IK creation.

## Region routing details

`WithDynamoDbRegion` and `WithDynamoDbSigningRegion` and
`WithPreferredRegion` are three distinct knobs:

| Setting | What it controls |
|---|---|
| `WithDynamoDbRegion` | Endpoint region for the DynamoDB SDK client. The HTTP request goes to `dynamodb.<region>.amazonaws.com`. |
| `WithDynamoDbSigningRegion` | SigV4 signing region. Defaults to the endpoint region; override only for cross-region signing scenarios. |
| `WithPreferredRegion` | Which entry of `RegionMap` AWS KMS uses to pick a key for *new* envelope encryption. Existing envelope keys from any region in the map are still decryptable. |

In a single-region deployment, all three are the same. In a multi-region
active/passive setup, all three on the active side are the active region;
on the passive side, `WithDynamoDbRegion` switches to the passive region
but `WithPreferredRegion` may stay on the active region's KMS key (so
both sides encrypt with the same key) until promotion.

## Common production pitfalls

- **Forgetting `WithEnableRegionSuffix(true)` in multi-region setups.**
  If `RegionMap` has multiple regions and you don't enable the suffix,
  intermediate keys with the same `_IK_<partition>_service_product` ID
  collide across regions in DynamoDB global tables. Set
  `WithEnableRegionSuffix(true)` to disambiguate (`_IK_..._us-east-1`).
- **Setting `STATIC_MASTER_KEY_HEX` in production.** It's accepted but
  it's the static-KMS test mode — production must use `KmsKind.Aws`.
  The `static` KMS path is rejected by review checks if a CI gate
  enforces production config.
- **IAM role missing `kms:Encrypt`.** Encrypt is needed only for
  system-key creation (rare). If your app started before deployment of
  the IAM policy update, the cached SK avoids the call — first
  rotation will surface the missing permission.
- **Native library not loading on Alpine / musl.** The NuGet package
  ships `linux-musl-x64` and `linux-musl-arm64` runtimes; if the host
  RID resolves to a glibc target instead, force the runtime with
  `<RuntimeIdentifier>linux-musl-x64</RuntimeIdentifier>` in your
  publish profile.
