# asherah

Node.js bindings for the Asherah envelope encryption and key rotation library.

Prebuilt native binaries are published to npm for Linux (x64/arm64, glibc and
musl), macOS (x64/arm64), and Windows (x64/arm64). The correct binary is
selected automatically at install time.

## Features

- Synchronous and asynchronous encrypt/decrypt APIs
- Compatible with Go, Python, Ruby, Java, and .NET Asherah implementations
- SQLite, MySQL, PostgreSQL, and DynamoDB metastore support
- AWS KMS and static key management

## Installation

```bash
npm install asherah
```

## Quick start

```js
const asherah = require('asherah');

asherah.setup({
  kms: 'static',
  metastore: 'memory',
  serviceName: 'myservice',
  productId: 'myproduct',
});

const encrypted = asherah.encrypt('partition', Buffer.from('hello world'));
const decrypted = asherah.decrypt('partition', encrypted);

asherah.shutdown();
```

## License

Licensed under the Apache License, Version 2.0.
