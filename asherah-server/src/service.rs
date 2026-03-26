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
                if let Err(e) = s.close() {
                    log::warn!("session close error: {e}");
                }
            }
        });

        Ok(Response::new(Box::pin(ReceiverStream::new(rx))))
    }
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
                Err(e) => error_response(&e.to_string()),
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
                        Err(e) => error_response(&e.to_string()),
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
