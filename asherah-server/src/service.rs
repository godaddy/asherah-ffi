use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::{mpsc, watch, Mutex};
use tokio::task::JoinSet;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status, Streaming};

use crate::convert::{drr_to_proto, proto_to_drr};
use crate::proto;
use crate::proto::app_encryption_server::AppEncryption;

pub type Factory = asherah::SessionFactory<
    asherah::aead::AES256GCM,
    asherah::builders::DynKms,
    asherah::builders::DynMetastore,
>;

type Session = asherah::Session<
    asherah::aead::AES256GCM,
    asherah::builders::DynKms,
    asherah::builders::DynMetastore,
>;

type SessionStream =
    Pin<Box<dyn tokio_stream::Stream<Item = Result<proto::SessionResponse, Status>> + Send>>;

/// Shared handle to the set of in-flight per-session tasks. `main.rs`
/// retains a clone so it can drain the set during graceful shutdown,
/// then force-cancel any stragglers that exceed the drain timeout.
pub type SessionTasks = Arc<Mutex<JoinSet<()>>>;

pub struct AppEncryptionService {
    factory: Arc<Factory>,
    shutdown_rx: watch::Receiver<bool>,
    tasks: SessionTasks,
    /// Held only when the service was constructed via `new()` (tests).
    /// `watch::Receiver::changed()` returns `Err` when every sender has
    /// been dropped, which would make the per-session task's `select!`
    /// arm fire immediately and break the loop before any request runs.
    /// Keeping a sender alive here turns the receiver into "never
    /// signals" semantics for the test path.
    _shutdown_keepalive: Option<watch::Sender<bool>>,
}

impl std::fmt::Debug for AppEncryptionService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppEncryptionService").finish()
    }
}

impl AppEncryptionService {
    /// Construct a service with no shutdown wiring — used by tests that
    /// build their own short-lived runtime. The watch channel created
    /// here never fires; the sender is retained inside the service so
    /// the receiver doesn't immediately read as "channel closed".
    pub fn new(factory: Factory) -> Self {
        let (tx, rx) = watch::channel(false);
        Self {
            factory: Arc::new(factory),
            shutdown_rx: rx,
            tasks: Arc::new(Mutex::new(JoinSet::new())),
            _shutdown_keepalive: Some(tx),
        }
    }

    /// Construct a service that participates in graceful shutdown. The
    /// `shutdown_rx` is observed by every spawned per-session task; when
    /// it flips, the task stops reading new requests, runs `close()` on
    /// the blocking pool, and exits. The `tasks` handle lets `main.rs`
    /// `join_next()` until empty (or until a drain deadline expires).
    pub fn with_lifecycle(
        factory: Factory,
        shutdown_rx: watch::Receiver<bool>,
        tasks: SessionTasks,
    ) -> Self {
        Self {
            factory: Arc::new(factory),
            shutdown_rx,
            tasks,
            _shutdown_keepalive: None,
        }
    }
}

#[tonic::async_trait]
impl AppEncryption for AppEncryptionService {
    type SessionStream = SessionStream;

    async fn session(
        &self,
        request: Request<Streaming<proto::SessionRequest>>,
    ) -> Result<Response<Self::SessionStream>, Status> {
        let factory = self.factory.clone();
        let mut shutdown_rx = self.shutdown_rx.clone();
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(16);

        let task = async move {
            let mut session: Option<Session> = None;
            // Partition ID stashed at GetSession so subsequent
            // encrypt/decrypt and the close path can name the tenant in
            // their per-request debug logs without re-validating it from
            // the request payload. Held only as long as `session`.
            let mut partition_id: Option<String> = None;

            loop {
                tokio::select! {
                    biased;
                    // On shutdown, stop reading new requests and drop into
                    // the close path. Without this, an idle stream that
                    // never sends a request would keep the task alive past
                    // the drain deadline.
                    //
                    // `Err` would mean every sender has been dropped, but
                    // `AppEncryptionService::new` retains a sender (see
                    // `_shutdown_keepalive`) and `with_lifecycle` keeps
                    // its sender alive in `main.rs` until after this set
                    // is drained. So Err is only possible during an
                    // already-cancelled tokio runtime teardown — break
                    // out so we still hit `close()`.
                    res = shutdown_rx.changed() => {
                        match res {
                            Ok(()) if *shutdown_rx.borrow() => break,
                            Ok(()) => continue,
                            Err(_) => break,
                        }
                    }
                    msg = inbound.message() => {
                        let req = match msg {
                            Ok(Some(req)) => req,
                            Ok(None) => break,
                            Err(e) => {
                                log::debug!("stream error: {e}");
                                break;
                            }
                        };
                        let response =
                            process_request(&factory, &mut session, &mut partition_id, req).await;
                        if tx.send(Ok(response)).await.is_err() {
                            break;
                        }
                    }
                }
            }

            // Drop the response sender before running `close()` so tonic
            // observes the stream as finished immediately and can return
            // from `serve_with_incoming_shutdown` while we run the
            // (potentially slow) close path on the blocking pool.
            drop(tx);

            if let Some(s) = session.take() {
                // Mirrors the Go reference's `closing session for <partition>`
                // log line, kept at debug to preserve the blessed
                // info-level happy-path silence (T-finding "verbose mode
                // emits per-request partition ID logs; tenant identifier
                // exposure" in `docs/review-2026-05-05-findings.md`).
                if let Some(pid) = partition_id.as_deref() {
                    log::debug!("closing session for {pid}");
                }
                // PublicSession::close walks IK and session caches, frees
                // memguard-locked pages (munlock syscalls), and acquires
                // parking_lot locks under the hood. Running it directly on
                // a Tokio worker would block the executor for the duration
                // of those syscalls — move it onto the blocking pool. T8 in
                // docs/review-2026-05-05-findings.md.
                let close_result = tokio::task::spawn_blocking(move || s.close())
                    .await
                    .unwrap_or_else(|join_err| {
                        Err(anyhow::anyhow!("close task panicked: {join_err}"))
                    });
                if let Err(e) = close_result {
                    log::warn!("session close error: {e}");
                }
            }
        };

        // Register the task so `main.rs` can await it during graceful
        // drain. `JoinSet::spawn` requires `&mut self`, so we serialize
        // through the Mutex; contention is bounded by stream-creation
        // rate (not per-message), so this is not on a hot path.
        self.tasks.lock().await.spawn(task);
        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
}

/// Maximum partition_id length accepted from clients. Partition IDs flow
/// into key IDs, log messages, and SQL bind parameters — accepting an
/// unbounded byte string lets a misbehaving client make the sidecar
/// allocate megabyte-scale envelope records and emit verbose log lines.
/// 256 bytes is generous; tighten if you control the call sites.
const MAX_PARTITION_ID_LEN: usize = 256;

fn validate_partition_id(id: &str) -> Result<(), &'static str> {
    if id.is_empty() {
        return Err("partition_id is empty");
    }
    if id.len() > MAX_PARTITION_ID_LEN {
        return Err("partition_id exceeds 256 bytes");
    }
    if id.bytes().any(|b| b < 0x20 || b == 0x7f) {
        return Err("partition_id contains a control character");
    }
    Ok(())
}

/// Build a client-facing error message that doesn't leak internal
/// metastore/KMS chain details. Logs the full chain at warn level so the
/// operator can debug; ships only the top-level summary over the wire.
/// T-finding "e.to_string() returns full anyhow chain over the wire" in
/// `docs/review-2026-05-05-findings.md`.
fn sanitize_error(op: &str, err: &anyhow::Error) -> String {
    log::warn!("{op} failed: {err:#}");
    format!("{op} failed: {err}")
}

async fn process_request(
    factory: &Factory,
    session: &mut Option<Session>,
    partition_id: &mut Option<String>,
    req: proto::SessionRequest,
) -> proto::SessionResponse {
    // Per-request log lines mirror the Go reference server's
    // `handling <op> for <partition>` wording but live at debug instead
    // of info. The Go reference emits these at info unconditionally; we
    // bless the incompatibility because the partition ID is a tenant
    // identifier and operators running this sidecar at default verbosity
    // should not inadvertently log per-tenant request activity. Set
    // `--verbose` / `ASHERAH_VERBOSE=true` to see them. T-finding
    // "verbose mode emits per-request partition ID logs; tenant
    // identifier exposure" in `docs/review-2026-05-05-findings.md`.
    match req.request {
        Some(proto::session_request::Request::GetSession(get)) => {
            if session.is_some() {
                return error_response("session has already been initialized");
            }
            if let Err(reason) = validate_partition_id(&get.partition_id) {
                return error_response(reason);
            }
            log::debug!("handling get-session for {}", get.partition_id);
            *partition_id = Some(get.partition_id.clone());
            *session = Some(factory.get_session(&get.partition_id));
            // GetSession success returns empty response (matching Go behavior)
            proto::SessionResponse { response: None }
        }
        Some(proto::session_request::Request::Encrypt(enc)) => {
            let Some(s) = session.as_ref() else {
                return error_response("session not yet initialized");
            };
            // partition_id is set in lockstep with `session` at GetSession,
            // so this branch is only reachable when both are populated.
            if let Some(pid) = partition_id.as_deref() {
                log::debug!("handling encrypt for {pid}");
            }
            match s.encrypt_async(&enc.data).await {
                Ok(drr) => proto::SessionResponse {
                    response: Some(proto::session_response::Response::EncryptResponse(
                        proto::EncryptResponse {
                            data_row_record: Some(drr_to_proto(drr)),
                        },
                    )),
                },
                Err(e) => error_response(&sanitize_error("encrypt", &e)),
            }
        }
        Some(proto::session_request::Request::Decrypt(dec)) => {
            let Some(s) = session.as_ref() else {
                return error_response("session not yet initialized");
            };
            if let Some(pid) = partition_id.as_deref() {
                log::debug!("handling decrypt for {pid}");
            }
            match dec.data_row_record {
                Some(proto_drr) => {
                    let drr = proto_to_drr(proto_drr);
                    match s.decrypt_async(drr).await {
                        Ok(data) => proto::SessionResponse {
                            response: Some(proto::session_response::Response::DecryptResponse(
                                proto::DecryptResponse { data },
                            )),
                        },
                        Err(e) => error_response(&sanitize_error("decrypt", &e)),
                    }
                }
                None => error_response("decrypt request missing data_row_record"),
            }
        }
        None => error_response("empty request"),
    }
}

fn error_response(msg: &str) -> proto::SessionResponse {
    proto::SessionResponse {
        response: Some(proto::session_response::Response::ErrorResponse(
            proto::ErrorResponse {
                message: msg.to_string(),
            },
        )),
    }
}
