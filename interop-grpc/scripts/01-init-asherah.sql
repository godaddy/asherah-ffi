-- Schema seed for the asherah metastore. MariaDB runs every *.sql file in
-- /docker-entrypoint-initdb.d/ on first container start, so this lands
-- before either gRPC server tries to query the table.
--
-- Lifted verbatim from godaddy/asherah `server/samples/metastore.sql`.

USE asherah;

CREATE TABLE IF NOT EXISTS encryption_key (
  id             VARCHAR(255) NOT NULL,
  created        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  key_record     TEXT         NOT NULL,
  PRIMARY KEY (id, created),
  INDEX (created)
);
