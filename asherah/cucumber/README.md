Dockerized Cross-Language Test Environment
=========================================

This setup runs Postgres, MySQL, and LocalStack KMS via Docker to support Cucumber tests that interoperate with Node’s Asherah SDK.

Services
- postgres:15 exposed on 54321

Usage
1) Start services
   - `cd asherah/cucumber`
   - `docker compose up -d`

2) Set DB URLs
   - Postgres: `export POSTGRES_URL=postgres://asherah:asherah@127.0.0.1:54321/asherah`
   - MySQL:    `export MYSQL_URL=mysql://asherah:asherah@127.0.0.1:33061/asherah`

3) Install Node deps for the interop helper
   - `cd asherah/cucumber/js && npm install`

4) Run the Cucumber tests with StaticKMS + Postgres/MySQL
   - Postgres: `cd asherah && cargo test --test cucumber --features cucumber_xlang,postgres`
   - MySQL:    `cd asherah && cargo test --test cucumber --features cucumber_xlang,mysql`

Notes
- The Node addon uses a Go backend; configuration is done through `asherah.setup(config)` with `KMS='static'` and `Metastore='rdbms'` for this test profile.
- Both Node and Rust use the same StaticKMS master key (provided via the Cucumber step) and share a Postgres/MySQL metastore to exchange SK/IK.
