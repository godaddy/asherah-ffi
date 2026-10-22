# AWS KMS error messages

When an AWS KMS call fails (`KMS: "aws"`), Asherah reports the step that
failed, the region, a fixed label for the cause, the KMS error code when
KMS returned one, and the AWS request id when a response carried one.
This page explains those labels. How to receive the messages in each
language is covered by the binding guides:
[.NET](../asherah-dotnet/docs/troubleshooting.md#aws-specific-errors),
[Go](../asherah-go/docs/troubleshooting.md#aws-specific-errors),
[Java](../asherah-java/docs/troubleshooting.md#aws-specific-errors),
[Node.js](../asherah-node/docs/troubleshooting.md#aws-specific-errors),
[Python](../asherah-py/docs/troubleshooting.md#kms),
[Ruby](../asherah-ruby/docs/troubleshooting.md#aws-specific-errors).

## Message shapes

Encrypting a new key calls `GenerateDataKey` in the preferred region and
`Encrypt` in each other configured region; the first failure stops it:

```
KMS <Operation> failed in region <region>: <cause>
KMS <Operation> not sent: no region configured
KMS <Operation> returned no <field> in region <region>[, request id <id>]
```

Decrypting tries each configured region that has a KEK in the stored
envelope, preferred region first, and reports every attempt when all fail:

```
all KMS backends failed to decrypt (tried regions: <region> [<reason>]; <region> [<reason>])
all KMS backends failed to decrypt (no matching regions found; configured regions: <region>, …; envelope regions: <region>, …)
```

A `<reason>` is `Decrypt <cause>`, `Decrypt not sent: no region
configured`, `Decrypt returned no plaintext` or `data key failed envelope
authentication`, the last two with the request id when KMS returned one.
A `<cause>` reads `<kind>[ <code>][, request id <id>]`:

```
all KMS backends failed to decrypt (tried regions: us-west-2 [Decrypt service error AccessDeniedException, request id 4f6c8a1e-2b3d-4c5e-9f70-81a2b3c4d5e6])
KMS GenerateDataKey failed in region us-west-2: dispatch failure (other: no credentials available)
```

## Where the detail appears

The exception or error your code receives carries only the outermost
context. The detail is logged at error level: a failed decrypt by
`asherah::kms_aws_envelope` (`AwsKmsEnvelope decrypt_key: all backends
failed: …`), a failed encrypt by `asherah::session`. Each binding's log
hook delivers error and warn events by default; the binding guides above
name the hook and the call styles that also log the full error chain as
a warn event.

## Labels

Credentials: `dispatch failure (other: <label>)`. The SDK could not obtain
AWS credentials, so the request was not sent.

| Label | Meaning and next step |
| --- | --- |
| `no credentials available` | No source in the default chain (environment, shared config and credentials files, web identity, container, instance metadata) provided credentials. On EC2 it can also mean the instance metadata service could not be reached, where retrying can help. |
| `credentials provider error` | A configured credentials source failed. Check the source the active profile or environment selects. |
| `unexpected credentials provider failure` | A credentials source failed in a way it does not classify. Check it as for `credentials provider error`. |
| `invalid credentials configuration` | A credentials source is configured incorrectly. Check the active profile and the `AWS_*` variables. |
| `credentials provider timed out` | A credentials source reported that it took too long. A source that never answers can instead show as a bare `dispatch failure (other)`, with no label. |

Service errors: `service error <Code>`. KMS, or an endpoint answering as
KMS, returned this error code. Representative codes:

| Code | Meaning and next step |
| --- | --- |
| `AccessDeniedException` | The IAM or key policy does not allow `kms:GenerateDataKey`, `kms:Encrypt` or `kms:Decrypt` for the calling principal. |
| `DisabledException` | The key is disabled. Enable it. |
| `KMSInvalidStateException` | The key's state does not allow the call, for example it is pending deletion. Cancel the deletion in time. |
| `NotFoundException` | The configured key does not exist in that region or account. Check `KmsKeyId` or the region's `RegionMap` entry. |
| `IncorrectKeyException` | The stored KEK was encrypted under a different key. Asherah sends the configured key id with each Decrypt, so the region's `RegionMap` entry (or `KmsKeyId`) must name that key. |
| `InvalidCiphertextException` | KMS rejected the stored KEK: it is damaged or is not KMS ciphertext. |
| `ThrottlingException` | The KMS request rate quota was exceeded; transient. Retry with backoff or review the account's KMS quotas. |

Region, network, endpoint and envelope:

| Label | Meaning and next step |
| --- | --- |
| `not sent: no region configured` | No region was resolved, so nothing was sent. Set `AWS_REGION` (or the profile's region) or `RegionMap`. |
| `request construction failure (invalid endpoint parameters)` | The configured region cannot form an endpoint host name, for example a key ARN where `RegionMap` expects a region (`{"<region>": "<key ARN>"}`). |
| `no matching regions found; configured regions: …; envelope regions: …` | No configured region has a KEK in the stored envelope, so KMS was not called. Configure a region from `envelope regions` with its key. `configured regions: <unrecognized region>` means a configured region is empty (none resolved) or not region-shaped. At most eight envelope regions are listed, then `+<n> more`. |
| `dispatch failure (io: connection refused)` | Nothing accepted the connection at the KMS endpoint, VPC endpoint or proxy. Check VPC endpoints, network ACLs, `AWS_ENDPOINT_URL` and `AWS_REGION` agreement. A DNS failure can also appear as `dispatch failure (io: …)`; which kind it names is not fixed. |
| `dispatch failure (io: other error)` | An I/O failure with no more specific kind. It can indicate TLS trouble: a TLS-inspecting proxy, a VPC endpoint whose certificate comes from a private CA the client does not trust, or an endpoint that does not speak TLS. |
| `dispatch failure (timeout)` | The connection attempt timed out. |
| `dispatch failure (other: transient error)` | The SDK classed the connection failure as transient, for example the connection closed before a response arrived. |
| `response error (HTTP …, unexpected end of file)` | A response arrived but was cut off before it could be read. |
| `service error (no error code, HTTP …)` | The answer was an HTTP error without a KMS error code, for example an HTML page from a proxy. |
| `data key failed envelope authentication` | KMS decrypted the KEK, but the result does not authenticate the stored key: the envelope is corrupt or the KEK for that region was replaced out of band. |
| `Decrypt returned no plaintext`, `returned no <field>` | KMS answered without the field Asherah needs. |
| `timeout` | An SDK timeout elapsed before the call completed. |
| `unclassified SDK failure`, `credentials error` | A failure kind this version does not classify. |

## What is left out, and why

These messages and their log lines never include the AWS error message:
it embeds principal and key ARNs, and with them account ids. Nor do they
include the configured key ARN, the envelope's `arn` field,
credential-provider error text (which can carry the same) or the host
names, addresses and URLs in connection errors.
Three values do come from the server or from configuration, and each
passes only in a narrow shape; anything else prints as a placeholder:

- error codes: at most 64 letters, else `<unrecognized error code>`;
- request ids: the UUID form, else `<unrecognized request id>`;
- region names: `[a-z][a-z0-9-]{0,31}`, else `<unrecognized region>`.

None of these shapes admits `:` or `/`, so no ARN can pass. A value that
fits its shape is printed as is: a region-shaped name that contains an
account id is printed, and an endpoint answering as KMS chooses the code
and request id it returns. DynamoDB metastore errors are not filtered
this way; they carry the AWS SDK's message.

## Request ids

A request id appears only when a response carried one; credentials,
region and connection failures have none. Search CloudTrail for it to
see the full event, including the principal and key, or give it to AWS
Support so they can find the call.
