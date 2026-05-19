use std::io;
use std::sync::Arc;
use std::sync::Mutex;

use base64::Engine;
use c2pa::{Signer, SigningAlg};
use openssl::hash::MessageDigest;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};

use ureq;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CloudSignError {
    #[error("send request error: {0}")]
    SendRequest(ureq::Error),
    #[error("response body is not valid json: {0}")]
    NotJsonResponseBody(ureq::Error),
    #[error("get cert from url {0} got error response: {1:?}")]
    FailedCertResponse(String, CertResponse),
    #[error("sign via url {0} got error response: {1:?}")]
    FailedSignResponse(String, SignResponse),
    #[error("failed to hash data: {0}")]
    HashDataFailed(openssl::error::ErrorStack),
    #[error("invalid certs data: {0}")]
    InvalidPemCert(openssl::error::ErrorStack),
    #[error("cert signature mismatch")]
    CertSignatureMismatch,
    #[error("invalid base64 signature: {0}")]
    InvalidBase64Signature(base64::DecodeError),
}

impl CloudSignError {
    pub fn error_code(&self) -> i32 {
        match self {
            CloudSignError::SendRequest(_) => 1,
            CloudSignError::NotJsonResponseBody(_) => 2,
            CloudSignError::FailedCertResponse(_, _) => 3,
            CloudSignError::FailedSignResponse(_, _) => 4,
            CloudSignError::HashDataFailed(_) => 5,
            CloudSignError::InvalidPemCert(_) => 6,
            CloudSignError::CertSignatureMismatch => 7,
            CloudSignError::InvalidBase64Signature(_) => 8,
        }
    }
}

impl From<&CloudSignError> for c2pa::Error {
    fn from(value: &CloudSignError) -> Self {
        match value {
            CloudSignError::CertSignatureMismatch => c2pa::Error::CoseNoCerts,
            _ => c2pa::Error::IoError(io::Error::other(value.to_string())),
        }
    }
}

pub struct C2paErrorCode(i32);

impl C2paErrorCode {
    pub fn get(&self) -> i32 {
        self.0
    }
}

impl From<&c2pa::Error> for C2paErrorCode {
    fn from(value: &c2pa::Error) -> Self {
        let code = match value {
            c2pa::Error::CoseTimeStampGeneration => 80,
            c2pa::Error::RemoteManifestFetch(_) => 81,
            _ => 0,
        };
        C2paErrorCode(code)
    }
}

#[derive(Deserialize, Debug)]
struct CertResponseData {
    cert_chain: String,
    cert_fingerprint: String,
}

#[derive(Deserialize, Debug)]
pub struct CertResponse {
    code: isize,
    #[allow(unused)]
    message: String,
    data: Option<CertResponseData>,
    #[allow(unused)]
    trace_id: Option<String>,
}

#[derive(Serialize)]
struct SignRequestData<'a> {
    app_id: &'a str,
    digest: String,
    signature_algorithm: &'static str,
}

#[derive(Deserialize, Debug)]
struct SignResponseData {
    signature: String,
    cert_fingerprint: String,
}

#[derive(Deserialize, Debug)]
pub struct SignResponse {
    code: isize,
    #[allow(unused)]
    message: String,
    data: Option<SignResponseData>,
    #[allow(unused)]
    trace_id: Option<String>,
}

pub struct CloudSigner {
    base_url: String,
    app_id: String,
    jwt_token: String,
    reserve_size: usize,
    certs: Vec<X509>,
    cert_fingerprint: String,
    use_time_authority: bool,
    time_authority_url: Option<String>,
    sign_error: Mutex<Option<CloudSignError>>,
}

impl CloudSigner {
    pub fn new(
        base_url: String,
        app_id: String,
        jwt_token: String,
        reserve_size: usize,
    ) -> Result<Self, CloudSignError> {
        let cert_url = format!("{base_url}/server/cert");
        let rsp = ureq::get(&cert_url)
            .query("app_id", &app_id)
            .header("X-JWT-Token", &jwt_token)
            .call()
            .map_err(CloudSignError::SendRequest)?
            .body_mut()
            .read_json::<CertResponse>()
            .map_err(CloudSignError::NotJsonResponseBody)?;
        if rsp.code != 0 {
            return Err(CloudSignError::FailedCertResponse(cert_url, rsp));
        }
        let Some(data) = rsp.data else {
            return Err(CloudSignError::FailedCertResponse(cert_url, rsp));
        };

        let certs = X509::stack_from_pem(data.cert_chain.as_bytes())
            .map_err(CloudSignError::InvalidPemCert)?;
        let cert_fingerprint = data.cert_fingerprint;

        Ok(CloudSigner {
            base_url,
            app_id,
            jwt_token,
            reserve_size,
            certs,
            cert_fingerprint,
            use_time_authority: false,
            time_authority_url: None,
            sign_error: Mutex::new(None),
        })
    }

    pub fn enable_time_authority(&mut self) {
        self.use_time_authority = true;
    }

    pub fn set_time_authority_url(&mut self, url: String) {
        self.time_authority_url = Some(url);
    }

    fn do_sign(&self, data: &[u8]) -> Result<Vec<u8>, CloudSignError> {
        let digest = openssl::hash::hash(MessageDigest::sha256(), data)
            .map_err(CloudSignError::HashDataFailed)?;

        let sign_data = SignRequestData {
            app_id: &self.app_id,
            digest: base64::engine::general_purpose::STANDARD.encode(digest),
            signature_algorithm: "SHA256_RSA_PSS",
        };

        let sign_url = format!("{}/server/sign", self.base_url);
        let rsp = ureq::post(&sign_url)
            .header("X-JWT-Token", &self.jwt_token)
            .send_json(sign_data)
            .map_err(CloudSignError::SendRequest)?
            .body_mut()
            .read_json::<SignResponse>()
            .map_err(CloudSignError::NotJsonResponseBody)?;

        if rsp.code != 0 {
            return Err(CloudSignError::FailedSignResponse(sign_url, rsp));
        }
        let Some(data) = rsp.data else {
            return Err(CloudSignError::FailedSignResponse(sign_url, rsp));
        };

        if data.cert_fingerprint != self.cert_fingerprint {
            return Err(CloudSignError::CertSignatureMismatch);
        }

        base64::engine::general_purpose::STANDARD
            .decode(data.signature.as_bytes())
            .map_err(CloudSignError::InvalidBase64Signature)
    }

    pub fn take_sign_error(&self) -> Option<CloudSignError> {
        self.sign_error.lock().unwrap().take()
    }
}

impl Signer for CloudSigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        match self.do_sign(data) {
            Ok(data) => Ok(data),
            Err(e) => {
                let c2pa_e = c2pa::Error::from(&e);
                let mut ec = self.sign_error.lock().unwrap();
                *ec = Some(e);
                Err(c2pa_e)
            }
        }
    }

    fn alg(&self) -> SigningAlg {
        SigningAlg::Ps256
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        let certs = self
            .certs
            .iter()
            .map(|v| v.to_der().unwrap())
            .collect::<Vec<_>>();
        Ok(certs)
    }

    fn reserve_size(&self) -> usize {
        self.reserve_size
    }

    fn time_authority_url(&self) -> Option<String> {
        if self.use_time_authority {
            let url = self
                .time_authority_url
                .clone()
                .unwrap_or(format!("{}/timestamp/get", self.base_url));
            Some(url)
        } else {
            None
        }
    }
}

/// `Arc<CloudSigner>` 包装，用于把 signer 同时给 builder（`Box<dyn Signer>`）
/// 使用并保留旁路句柄调用 `take_sign_error()`。孤儿规则不允许直接给
/// `Arc<CloudSigner>` 实现 `Signer`，所以用 newtype。
pub struct ArcCloudSigner(pub Arc<CloudSigner>);

impl Signer for ArcCloudSigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        (*self.0).sign(data)
    }

    fn alg(&self) -> SigningAlg {
        (*self.0).alg()
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        (*self.0).certs()
    }

    fn reserve_size(&self) -> usize {
        (*self.0).reserve_size()
    }

    fn time_authority_url(&self) -> Option<String> {
        (*self.0).time_authority_url()
    }
}
