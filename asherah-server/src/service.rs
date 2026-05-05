use std::pin::Pin;
use std::sync::Arc;

use tokio::sync::mpsc;
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

pub struct AppEncryptionService {
    factory: Arc<Factory>,
}

impl std::fmt::Debug for AppEncryptionService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppEncryptionService").finish()
    }
}

impl AppEncryptionService {
    pub fn new(factory: Factory) -> Self {
        Self {
            factory: Arc::new(factory),
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
        let mut inbound = request.into_inner();
        let (tx, rx) = mpsc::channel(16);

        tokio::spawn(async move {
            let mut session: Option<Session> = None;

            loop {
                let req = match inbound.message().await {
                    Ok(Some(req)) => req,
                    Ok(None) => break,
                    Err(e) => {
                        log::debug!("stream error: {e}");
                        break;
                    }
                };

                let response = process_request(&factory, &mut session, req).await;
                if tx.send(Ok(response)).await.is_err() {
                    break;
                }
            }

            if let Some(s) = session.take() {
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
        });

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
    req: proto::SessionRequest,
) -> proto::SessionResponse {
    match req.request {
        Some(proto::session_request::Request::GetSession(get)) => {
            if session.is_some() {
                return error_response("session has already been initialized");
            }
            if let Err(reason) = validate_partition_id(&get.partition_id) {
                return error_response(reason);
            }
            *session = Some(factory.get_session(&get.partition_id));
            // GetSession success returns empty response (matching Go behavior)
            proto::SessionResponse { response: None }
        }
        Some(proto::session_request::Request::Encrypt(enc)) => {
            let Some(s) = session.as_ref() else {
                return error_response("session not yet initialized");
            };
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
