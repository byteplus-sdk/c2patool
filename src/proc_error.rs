use crate::cloud_signer::{C2paErrorCode, CloudSignError};
use std::io;
use thiserror::Error;

#[derive(Debug, Error)]
#[allow(dead_code)]
pub enum ProcError {
    #[error("invalid usage: {0}")]
    InvalidUsage(anyhow::Error),

    #[error("io error: {0}: {1}")]
    IoError(String, io::Error),

    #[error("json error: {0}: {1}")]
    JsonError(String, serde_json::Error),

    #[error("c2pa error: {0}")]
    C2paError(#[from] c2pa::Error),

    #[error("signer error: {0}")]
    SignerError(#[from] CloudSignError),

    #[error("failed to get signer url")]
    FailedToGetSignerUrl,

    #[error("request error: {0}")]
    RequestError(#[from] reqwest::Error),
}

impl ProcError {
    pub fn exit_code(&self) -> i32 {
        match self {
            ProcError::InvalidUsage(_) => 1,
            ProcError::IoError(_, _) => 2,
            ProcError::JsonError(_, _) => 3,
            ProcError::FailedToGetSignerUrl => 4,
            ProcError::RequestError(_) => 5,
            ProcError::C2paError(e) => 100 + C2paErrorCode::from(e).get(),
            ProcError::SignerError(e) => 200 + e.error_code(),
        }
    }
}

#[macro_export]
macro_rules! proc_bail {
    ($err:expr) => {
        return Err($err);
    };
}
