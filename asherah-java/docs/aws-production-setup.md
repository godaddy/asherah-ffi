# AWS production setup

End-to-end walkthrough for a production deployment using **AWS KMS**
for the master key and **DynamoDB** for the metastore.

## Prerequisites

1. An AWS account with permission to create KMS keys, DynamoDB tables,
   and IAM policies.
2. A way to deliver AWS credentials to your JVM — IAM role for
   ECS/EKS/EC2/Lambda, AWS SSO profile (`aws sso login`) for
   development, or environment variables (`AWS_ACCESS_KEY_ID` /
   `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`) for CI. **Asherah
   does not load credentials itself** — the AWS SDK for Rust (running
   in the native core via JNI) reads from the standard credential
   chain. The AWS Java SDK / `DefaultCredentialsProvider` is not
   consulted.

## Step 1: create KMS keys

One symmetric KMS key per region you want to operate in. Asherah
encrypts only its per-product *system keys* with this key — user data
never goes through KMS. Volume is small (~1 KMS call per product per
~90 days under default rotation).

```bash
aws kms create-key \
    --region us-east-1 \
    --description "Asherah system-key encryption" \
    --tags TagKey=Application,TagValue=asherah \
    --query 'KeyMetadata.{Arn:Arn,KeyId:KeyId}'
```

Repeat for each region in `regionMap`. Record the ARNs.

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

Asherah doesn't use `kms:GenerateDataKey` — system-key plaintext is
generated locally and only the encrypted form crosses the wire.

## Step 4: configure Asherah

```java
import com.godaddy.asherah.jni.*;
import java.util.Map;

AsherahConfig config = AsherahConfig.builder()
    .serviceName("payments")                    // your service identifier
    .productId("checkout")                       // your product identifier within the service
    .metastore("dynamodb")
    .dynamoDbTableName("AsherahKeys")
    .dynamoDbRegion("us-east-1")
    .kms("aws")
    .regionMap(Map.of(
        "us-east-1", "arn:aws:kms:us-east-1:111111111111:key/abc-123",
        "us-west-2", "arn:aws:kms:us-west-2:111111111111:key/def-456"
    ))
    .preferredRegion("us-east-1")               // KMS key for new envelope keys
    .enableSessionCaching(Boolean.TRUE)
    .expireAfter(90L * 24 * 60 * 60)            // IK rotation cadence (seconds)
    .checkInterval(60L * 60)                     // revoke-check interval (seconds)
    .build();

AsherahFactory factory = Asherah.factoryFromConfig(config);
```

`serviceName` and `productId` form the prefix for generated
intermediate-key IDs. Pick stable identifiers — changing them later
makes existing envelope keys un-decryptable.

## Step 5: hook observability

```java
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.micrometer.core.instrument.*;

Logger log = LoggerFactory.getLogger("asherah");

Asherah.setLogHook(evt ->
    log.atLevel(evt.getLevel())
       .addKeyValue("asherah_target", evt.getTarget())
       .log(evt.getMessage())
);

MeterRegistry registry = /* injected */;
Timer encrypt = Timer.builder("asherah.encrypt.duration").register(registry);
Timer decrypt = Timer.builder("asherah.decrypt.duration").register(registry);

Asherah.setMetricsHook(evt -> {
    switch (evt.getType()) {
        case ENCRYPT -> encrypt.record(evt.getDurationNs(), TimeUnit.NANOSECONDS);
        case DECRYPT -> decrypt.record(evt.getDurationNs(), TimeUnit.NANOSECONDS);
        case CACHE_HIT -> registry.counter("asherah.cache.hits", "cache", evt.getName()).increment();
        case CACHE_MISS -> registry.counter("asherah.cache.misses", "cache", evt.getName()).increment();
        default -> { /* store/load/cache_stale similarly */ }
    }
});
```

In Spring Boot / Micronaut / Quarkus, wire the hook in an event
listener that fires after the framework's logger / metrics
infrastructure is ready. See
[`framework-integration.md`](./framework-integration.md).

## Step 6: smoke-test verification

The first encrypt produces:
- A row in `AsherahKeys` with `Id="_SK_payments"` (the system key).
- A row in `AsherahKeys` with `Id="_IK_<partition>_payments_checkout"`
  (the intermediate key).
- A log event at `INFO` level reporting IK creation.

Subsequent encrypts in the same partition reuse the cached IK — no
metastore round-trip — until expiry (default 90 days).

## Region routing details

| Setting | What it controls |
|---|---|
| `dynamoDbRegion` | Endpoint region for DynamoDB SDK client. |
| `dynamoDbSigningRegion` | SigV4 signing region. Defaults to endpoint region. |
| `preferredRegion` | Which entry of `regionMap` AWS KMS uses for *new* envelope encryption. Existing envelope keys from any region in the map are still decryptable. |

In single-region all three are equal. In multi-region active/passive,
all three on the active side are the active region; the passive side
switches `dynamoDbRegion` to its region but may keep
`preferredRegion` on the active KMS key until promotion.

## Common production pitfalls

- **`enableRegionSuffix(true)`** is required when using DynamoDB
  global tables and a multi-region `regionMap` — otherwise IK IDs
  collide across regions. Set to disambiguate
  (`_IK_..._us-east-1`).
- **Setting `STATIC_MASTER_KEY_HEX` in production.** It's accepted but
  it's the static-KMS test mode. Production must use `kms("aws")`.
- **IAM role missing `kms:Encrypt`.** Encrypt is needed only for
  system-key creation (rare). First IK rotation surfaces the missing
  permission if your app started with the SK already cached.
- **Native binary not loading on Alpine / musl.** The published JAR
  bundles linux-musl-x64 and linux-musl-arm64 binaries; if you see
  `UnsatisfiedLinkError: ... cannot open shared object file` on
  Alpine, check `apk add libgcc libstdc++` is in your Dockerfile.
- **Lambda cold-start cost.** Build the factory at static init or
  in the handler class's constructor — not inside `handleRequest` —
  so warm invocations don't repay setup cost.
- **Conflicting AWS SDK versions.** Asherah's native core uses the
  AWS SDK for Rust internally — it doesn't share state with the AWS
  Java SDK. If your app uses both, they have separate credential
  caches; configure each independently.
