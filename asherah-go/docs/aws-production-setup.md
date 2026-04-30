# AWS production setup

End-to-end walkthrough for a production deployment using **AWS KMS**
for the master key and **DynamoDB** for the metastore.

## Prerequisites

1. An AWS account with permission to create KMS keys, DynamoDB tables,
   and IAM policies.
2. A way to deliver AWS credentials to your Go process — IAM role for
   ECS/EKS/EC2/Lambda, AWS SSO profile (`aws sso login`) for
   development, or environment variables (`AWS_ACCESS_KEY_ID` /
   `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`) for CI. **Asherah
   does not load credentials itself** — the AWS SDK for Rust (running
   in the native FFI layer via purego) reads from the standard
   credential chain. The `aws-sdk-go-v2` SDK's credential cache is
   **not** consulted.
3. Optional: set `Config.AwsProfileName` so the Rust layer uses a named
   profile from `~/.aws/credentials` (or config) regardless of process
   `AWS_PROFILE`. Omit it to rely on the default chain.

## Step 1: create KMS keys

One symmetric KMS key per region. Asherah encrypts only its
per-product *system keys* with this key — user data never goes through
KMS.

```bash
aws kms create-key \
    --region us-east-1 \
    --description "Asherah system-key encryption" \
    --tags TagKey=Application,TagValue=asherah \
    --query 'KeyMetadata.{Arn:Arn,KeyId:KeyId}'
```

Repeat for each region in `RegionMap`. Record the ARNs.

## Step 2: create the DynamoDB metastore table

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

For multi-region, enable [DynamoDB global
tables](https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/GlobalTables.html).

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

Asherah doesn't use `kms:GenerateDataKey`.

## Step 4: configure Asherah

```go
import (
    asherah "github.com/godaddy/asherah-ffi/asherah-go"
)

config := asherah.Config{
    ServiceName: "payments",                 // your service identifier
    ProductID:   "checkout",                  // your product identifier within the service
    Metastore:   "dynamodb",
    DynamoDBTableName: "AsherahKeys",
    DynamoDBRegion:    "us-east-1",
    KMS:               "aws",
    RegionMap: map[string]string{
        "us-east-1": "arn:aws:kms:us-east-1:111111111111:key/abc-123",
        "us-west-2": "arn:aws:kms:us-west-2:111111111111:key/def-456",
    },
    PreferredRegion:      "us-east-1",       // KMS key for new envelope keys
    EnableSessionCaching: ptr(true),
    ExpireAfter:          ptr(int64(90 * 24 * 60 * 60)),  // IK rotation (seconds)
    CheckInterval:        ptr(int64(60 * 60)),             // revoke check (seconds)
}

func ptr[T any](v T) *T { return &v }

factory, err := asherah.NewFactory(config)
if err != nil { log.Fatal(err) }
defer factory.Close()
```

`ServiceName` and `ProductID` form the prefix for generated
intermediate-key IDs. Pick stable identifiers — changing them later
makes existing envelope keys un-decryptable.

## Step 5: hook observability

```go
import (
    "log/slog"
    "os"

    asherah "github.com/godaddy/asherah-ffi/asherah-go"
    "github.com/prometheus/client_golang/prometheus"
)

slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, nil)))
_ = asherah.SetSlogLogger(slog.Default())

encryptHist := prometheus.NewHistogram(prometheus.HistogramOpts{
    Name: "asherah_encrypt_duration_seconds",
})
decryptHist := prometheus.NewHistogram(prometheus.HistogramOpts{
    Name: "asherah_decrypt_duration_seconds",
})
cacheHits := prometheus.NewCounterVec(prometheus.CounterOpts{
    Name: "asherah_cache_hits_total",
}, []string{"cache"})
prometheus.MustRegister(encryptHist, decryptHist, cacheHits)

_ = asherah.SetMetricsHook(func(e asherah.MetricsEvent) {
    switch e.Type {
    case "encrypt":   encryptHist.Observe(float64(e.DurationNs) / 1e9)
    case "decrypt":   decryptHist.Observe(float64(e.DurationNs) / 1e9)
    case "cache_hit": cacheHits.WithLabelValues(e.Name).Inc()
    // store/load/cache_miss/cache_stale similarly
    }
})
```

## Step 6: smoke-test verification

The first encrypt produces:
- A row in `AsherahKeys` with `Id="_SK_payments"` (the system key).
- A row in `AsherahKeys` with `Id="_IK_<partition>_payments_checkout"`
  (the intermediate key).
- A log record at `slog.LevelInfo` reporting IK creation.

Subsequent encrypts in the same partition reuse the cached IK — no
metastore round-trip — until expiry (default 90 days).

## Region routing details

| Setting | What it controls |
|---|---|
| `AwsProfileName` | Optional named profile for the Rust AWS config (KMS/DynamoDB/Secrets Manager). Omit to use the default credential chain. |
| `DynamoDBRegion` | Endpoint region for DynamoDB SDK client. |
| `DynamoDBSigningRegion` | SigV4 signing region. Defaults to endpoint region. |
| `PreferredRegion` | Which entry of `RegionMap` AWS KMS uses for *new* envelope encryption. |

In single-region all three are equal. In multi-region active/passive,
all three on the active side are the active region; the passive side
switches `DynamoDBRegion` to its region but may keep
`PreferredRegion` on the active KMS key until promotion.

## Common production pitfalls

- **`EnableRegionSuffix: ptr(true)`** is required when using DynamoDB
  global tables and a multi-region `RegionMap` — otherwise IK IDs
  collide across regions.
- **Setting `STATIC_MASTER_KEY_HEX` in production.** It's accepted but
  it's the static-KMS test mode. Production must use `KMS: "aws"`.
- **IAM role missing `kms:Encrypt`.** Encrypt is needed only for
  system-key creation (rare). First IK rotation surfaces the missing
  permission if your app started with the SK already cached.
- **Native binary not in working directory.** The `install-native`
  command places the library in the working dir (or wherever
  `--output` pointed). Production deployments need to ship the
  library next to the binary, or set `ASHERAH_GO_NATIVE` to its
  location, or pre-bake into the container image.
- **Lambda cold-start cost.** Build the factory at `init()` time, not
  inside the handler. Use a package-level variable.
- **Static linking.** `purego` doesn't require CGO, but the native
  library is still a dynamic library. If you build a fully static
  binary (e.g. for distroless containers), the native `.so` must be
  next to the binary at runtime — static linking against the Asherah
  library isn't supported.
