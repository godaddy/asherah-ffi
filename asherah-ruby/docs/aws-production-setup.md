# AWS production setup

End-to-end walkthrough for a production deployment using **AWS KMS**
for the master key and **DynamoDB** for the metastore.

## Prerequisites

1. An AWS account with permission to create KMS keys, DynamoDB tables,
   and IAM policies.
2. A way to deliver AWS credentials to your Ruby process — IAM role
   for ECS/EKS/EC2/Lambda, AWS SSO profile (`aws sso login`) for
   development, or environment variables (`AWS_ACCESS_KEY_ID` /
   `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`) for CI. **Asherah
   does not load credentials itself** — the AWS SDK for Rust (running
   in the native FFI layer) reads from the standard credential chain.
   The `aws-sdk-ruby` gem's credential cache is **not** consulted.

## Step 1: create KMS keys

One symmetric KMS key per region you want to operate in. Asherah
encrypts only its per-product *system keys* — user data never goes
through KMS.

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

```ruby
require "asherah"
require "json"

config = {
  "ServiceName" => "payments",                  # your service identifier
  "ProductID" => "checkout",                     # your product identifier within the service
  "Metastore" => "dynamodb",
  "DynamoDBTableName" => "AsherahKeys",
  "DynamoDBRegion" => "us-east-1",
  "KMS" => "aws",
  "RegionMap" => {
    "us-east-1" => "arn:aws:kms:us-east-1:111111111111:key/abc-123",
    "us-west-2" => "arn:aws:kms:us-west-2:111111111111:key/def-456"
  },
  "PreferredRegion" => "us-east-1",             # KMS key for new envelope keys
  "EnableSessionCaching" => true,
  "ExpireAfter" => 90 * 24 * 60 * 60,           # IK rotation (seconds)
  "CheckInterval" => 60 * 60                     # revoke-check interval (seconds)
}

factory = Asherah::SessionFactory.new(
  Asherah::Native.asherah_factory_new_with_config(JSON.generate(config))
)
```

`ServiceName` and `ProductID` form the prefix for generated
intermediate-key IDs. Pick stable identifiers — changing them later
makes existing envelope keys un-decryptable.

## Step 5: hook observability

```ruby
require "statsd-ruby"

# Forward log records to Rails.logger (or any Logger-compatible object).
Asherah.set_log_hook(Rails.logger)

statsd = Statsd.new(ENV["STATSD_HOST"] || "localhost", 8125)

Asherah.set_metrics_hook do |event|
  case event[:type]
  when :encrypt, :decrypt, :store, :load
    statsd.timing("asherah.#{event[:type]}", event[:duration_ns] / 1_000_000.0)
  when :cache_hit, :cache_miss, :cache_stale
    statsd.increment("asherah.cache.#{event[:type]}", tags: ["cache:#{event[:name]}"])
  end
end
```

In Rails, wire the hook in an initializer that runs after
`Rails.logger` is available. See
[`framework-integration.md`](./framework-integration.md).

## Step 6: smoke-test verification

The first encrypt produces:
- A row in `AsherahKeys` with `Id="_SK_payments"` (the system key).
- A row in `AsherahKeys` with `Id="_IK_<partition>_payments_checkout"`
  (the intermediate key).
- A log event at `Logger::INFO` reporting IK creation.

Subsequent encrypts in the same partition reuse the cached IK — no
metastore round-trip — until expiry (default 90 days).

## Region routing details

| Setting | What it controls |
|---|---|
| `DynamoDBRegion` | Endpoint region for DynamoDB. |
| `DynamoDBSigningRegion` | SigV4 signing region. Defaults to endpoint region. |
| `PreferredRegion` | Which entry of `RegionMap` AWS KMS uses for *new* envelope encryption. |

In single-region all three are equal. In multi-region active/passive,
all three on the active side are the active region; the passive side
switches `DynamoDBRegion` to its region but may keep
`PreferredRegion` on the active KMS key until promotion.

## Common production pitfalls

- **`EnableRegionSuffix => true`** is required when using DynamoDB
  global tables and a multi-region `RegionMap` — otherwise IK IDs
  collide across regions.
- **Setting `STATIC_MASTER_KEY_HEX` in production.** It's accepted but
  it's the static-KMS test mode. Production must use `KMS => "aws"`.
- **IAM role missing `kms:Encrypt`.** Encrypt is needed only for
  system-key creation (rare). First IK rotation surfaces the missing
  permission if your app started with the SK already cached.
- **Native binary not loading on Alpine / musl.** The
  `asherah-x86_64-linux-musl` / `asherah-aarch64-linux-musl`
  platform gems should resolve automatically. If you see
  `LoadError: cannot open shared object file`, install
  `apk add libgcc libstdc++` in your Dockerfile.
- **Lambda cold-start cost.** Build the factory at top-level (not
  inside the handler) so warm invocations don't repay setup cost.
- **Bundler resolving the wrong platform gem.** Run `bundle lock
  --add-platform x86_64-linux-musl` (or the appropriate platform)
  in CI before deploying to ensure `Gemfile.lock` includes the
  prebuilt gem for your target.
