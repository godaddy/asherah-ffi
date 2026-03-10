#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//! Tests for builders: classify_connection_string, convert_go_mysql_dsn edge cases.

use asherah::builders::{classify_connection_string, DbKind};

// ──────────────────────────── MySQL Go DSN edge cases ────────────────────────────

#[test]
fn go_dsn_at_sign_in_password() {
    // rsplit_once('@') should handle @ in password correctly
    let dsn = "root:p@ss@tcp(localhost:3306)/db";
    match classify_connection_string(dsn) {
        DbKind::Mysql(url) => {
            assert!(url.starts_with("mysql://"), "got: {url}");
            assert!(url.contains("localhost:3306"), "got: {url}");
            assert!(url.contains("/db"), "got: {url}");
        }
        other => panic!("expected Mysql, got {other:?}"),
    }
}

#[test]
fn go_dsn_no_userinfo() {
    // No @ at all: tcp(host:port)/db
    let dsn = "tcp(myhost:3306)/mydb";
    match classify_connection_string(dsn) {
        DbKind::Mysql(url) => {
            assert_eq!(url, "mysql://myhost:3306/mydb");
        }
        other => panic!("expected Mysql, got {other:?}"),
    }
}

#[test]
fn go_dsn_only_user_no_pass() {
    let dsn = "user@tcp(host:3306)/db";
    match classify_connection_string(dsn) {
        DbKind::Mysql(url) => {
            assert_eq!(url, "mysql://user@host:3306/db");
        }
        other => panic!("expected Mysql, got {other:?}"),
    }
}

#[test]
fn go_dsn_default_port_no_port_specified() {
    let dsn = "root@tcp(myhost)/db";
    match classify_connection_string(dsn) {
        DbKind::Mysql(url) => {
            assert!(
                url.contains("myhost:3306"),
                "default port should be added: {url}"
            );
        }
        other => panic!("expected Mysql, got {other:?}"),
    }
}

#[test]
fn go_dsn_all_go_params_stripped() {
    let dsn = "u:p@tcp(h:3306)/db?tls=skip-verify&parseTime=true&loc=UTC&allowNativePasswords=true&charset=utf8";
    match classify_connection_string(dsn) {
        DbKind::Mysql(url) => {
            assert!(!url.contains("tls="), "tls should be stripped: {url}");
            assert!(
                !url.contains("parseTime="),
                "parseTime should be stripped: {url}"
            );
            assert!(!url.contains("loc="), "loc should be stripped: {url}");
            assert!(
                !url.contains("allowNativePasswords="),
                "param should be stripped: {url}"
            );
            assert!(
                !url.contains("charset="),
                "charset should be stripped: {url}"
            );
        }
        other => panic!("expected Mysql, got {other:?}"),
    }
}

#[test]
fn go_dsn_non_go_params_preserved() {
    let dsn = "u:p@tcp(h:3306)/db?custom=value&tls=skip-verify";
    match classify_connection_string(dsn) {
        DbKind::Mysql(url) => {
            assert!(
                url.contains("custom=value"),
                "custom params should be preserved: {url}"
            );
            assert!(!url.contains("tls="), "tls should be stripped: {url}");
        }
        other => panic!("expected Mysql, got {other:?}"),
    }
}

#[test]
fn go_dsn_with_mysql_prefix_and_tcp() {
    // mysql:// prefix on a Go DSN body
    let dsn = "mysql://u:p@tcp(h:3306)/db?tls=true";
    match classify_connection_string(dsn) {
        DbKind::Mysql(url) => {
            assert!(!url.contains("tcp("), "tcp() should be converted: {url}");
            assert!(url.contains("h:3306"), "host should be extracted: {url}");
        }
        other => panic!("expected Mysql, got {other:?}"),
    }
}

// ──────────────────────────── Standard URL formats ────────────────────────────

#[test]
fn standard_mysql_url_passthrough() {
    let url = "mysql://root:pass@localhost:3306/testdb?ssl-mode=REQUIRED";
    match classify_connection_string(url) {
        DbKind::Mysql(u) => assert_eq!(u, url),
        other => panic!("expected Mysql, got {other:?}"),
    }
}

#[test]
fn postgres_url() {
    let url = "postgres://user:pass@host:5432/db?sslmode=require";
    match classify_connection_string(url) {
        DbKind::Postgres(u) => assert_eq!(u, url),
        other => panic!("expected Postgres, got {other:?}"),
    }
}

#[test]
fn postgresql_scheme() {
    let url = "postgresql://user:pass@host/db";
    match classify_connection_string(url) {
        DbKind::Postgres(u) => assert_eq!(u, url),
        other => panic!("expected Postgres, got {other:?}"),
    }
}

#[test]
fn sqlite_url() {
    let url = "sqlite:///data/test.db";
    match classify_connection_string(url) {
        DbKind::Sqlite(path) => assert_eq!(path, "/data/test.db"),
        other => panic!("expected Sqlite, got {other:?}"),
    }
}

#[test]
fn unknown_connection_string() {
    let url = "some-random-string";
    match classify_connection_string(url) {
        DbKind::Unknown(s) => assert_eq!(s, url),
        other => panic!("expected Unknown, got {other:?}"),
    }
}

#[test]
fn case_insensitive_scheme_detection() {
    match classify_connection_string("POSTGRES://host/db") {
        DbKind::Postgres(_) => {}
        other => panic!("expected Postgres, got {other:?}"),
    }
    match classify_connection_string("MySQL://host/db") {
        DbKind::Mysql(_) => {}
        other => panic!("expected Mysql, got {other:?}"),
    }
    match classify_connection_string("SQLITE:///tmp/t.db") {
        DbKind::Sqlite(_) => {}
        other => panic!("expected Sqlite, got {other:?}"),
    }
}

// ──────────────────────────── Go DSN without tcp() ────────────────────────────

#[test]
fn go_dsn_no_tcp_just_host_db() {
    // user@host/db with no tcp() — if no tcp() and no scheme, falls to Unknown
    let dsn = "user:pass@somehost:3306/db";
    // This doesn't have tcp() and doesn't start with mysql://, so it's Unknown
    match classify_connection_string(dsn) {
        DbKind::Unknown(_) => {}
        other => panic!("expected Unknown (no tcp, no scheme), got {other:?}"),
    }
}

#[test]
fn empty_connection_string() {
    match classify_connection_string("") {
        DbKind::Unknown(s) => assert_eq!(s, ""),
        other => panic!("expected Unknown, got {other:?}"),
    }
}
