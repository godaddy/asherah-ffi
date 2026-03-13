# asherah

Python bindings for the Asherah envelope encryption and key rotation library.

Prebuilt wheels are published to PyPI for Linux (x64/arm64, glibc and musl),
macOS (universal2), and Windows (x64/arm64). Python 3.8+ is supported via
stable ABI wheels.

## Features

- Session-based encrypt/decrypt API
- Compatible with Go, Node.js, Ruby, Java, and .NET Asherah implementations
- SQLite, MySQL, PostgreSQL, and DynamoDB metastore support
- AWS KMS and static key management

## Installation

```bash
pip install asherah
```

## Quick start

```python
import asherah_py as asherah

factory = asherah.SessionFactory()
session = factory.get_session("partition")

encrypted = session.encrypt_bytes(b"hello world")
decrypted = session.decrypt_bytes(encrypted)

factory.close()
```

## License

Licensed under the Apache License, Version 2.0.
