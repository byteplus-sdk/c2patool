//! 火山引擎 C2PA ToB 云签 Signer 实现。
//!
//! 火山 OpenAPI 网关签名机制（HMAC-SHA256，类 AWS V4）：
//!   kSecret  = SK
//!   kDate    = HMAC(kSecret, ShortDate)
//!   kRegion  = HMAC(kDate, Region)
//!   kService = HMAC(kRegion, Service)
//!   kSigning = HMAC(kService, "request")
//!   StringToSign = "HMAC-SHA256\n{X-Date}\n{ShortDate}/{Region}/{Service}/request\n{Hex(Sha256(CanonicalRequest))}"
//!   Signature    = Hex(HMAC(kSigning, StringToSign))
//!
//! 文档：https://www.volcengine.com/docs/6638/173358
//!
//! ToB 接口（参考 swagger）：
//!   POST {Host}/?Action=GetC2PAInstance&Version={Version}   -> 取证书内容
//!   POST {Host}/?Action=C2PASign&Version={Version}          -> 远程签名（DIGEST/RSASSA_PSS_SHA_256 等）
//!
//! `Service` 默认 `c2pa_tob`，`Version` 默认 `1.0`，可由 CLI 覆盖。

use std::io;
use std::sync::Arc;
use std::sync::Mutex;

use base64::Engine;
use c2pa::{Signer, SigningAlg};
use chrono::Utc;
use openssl::hash::MessageDigest;
use openssl::pkey::PKey;
use openssl::sign::Signer as OpenSslSigner;
use openssl::x509::X509;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use thiserror::Error;
use ureq;

#[derive(Debug, Error)]
pub enum CloudSignError {
    #[error("send request error: {0}")]
    SendRequest(ureq::Error),
    #[error("non-2xx http response: status={0}, body={1}")]
    HttpStatus(u16, String),
    #[error("response body is not valid json: {0}")]
    NotJsonResponseBody(ureq::Error),
    #[error("get cert via {0} got error response: {1:?}")]
    FailedCertResponse(String, VolcResponse),
    #[error("sign via {0} got error response: {1:?}")]
    FailedSignResponse(String, VolcResponse),
    #[error("failed to hash data: {0}")]
    HashDataFailed(openssl::error::ErrorStack),
    #[error("invalid certs data: {0}")]
    InvalidPemCert(openssl::error::ErrorStack),
    #[error("missing certificate in GetC2PAInstance response")]
    MissingCertificate,
    #[error("invalid base64 signature: {0}")]
    InvalidBase64Signature(base64::DecodeError),
    #[error("hmac compute error: {0}")]
    HmacError(openssl::error::ErrorStack),
    #[error("invalid url: {0}")]
    InvalidUrl(String),
}

impl CloudSignError {
    pub fn error_code(&self) -> i32 {
        match self {
            CloudSignError::SendRequest(_) => 1,
            CloudSignError::HttpStatus(_, _) => 11,
            CloudSignError::NotJsonResponseBody(_) => 2,
            CloudSignError::FailedCertResponse(_, _) => 3,
            CloudSignError::FailedSignResponse(_, _) => 4,
            CloudSignError::HashDataFailed(_) => 5,
            CloudSignError::InvalidPemCert(_) => 6,
            CloudSignError::MissingCertificate => 7,
            CloudSignError::InvalidBase64Signature(_) => 8,
            CloudSignError::HmacError(_) => 9,
            CloudSignError::InvalidUrl(_) => 10,
        }
    }
}

impl From<&CloudSignError> for c2pa::Error {
    fn from(value: &CloudSignError) -> Self {
        match value {
            CloudSignError::MissingCertificate => c2pa::Error::CoseNoCerts,
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

/// 火山 OpenAPI 通用响应（除 Result 外的部分），用于错误展示。
#[derive(Deserialize, Debug, Default)]
pub struct VolcResponse {
    #[serde(rename = "ResponseMetadata")]
    pub response_metadata: Option<ResponseMetadata>,
    #[serde(rename = "Result")]
    pub result: Option<JsonValue>,
}

#[derive(Deserialize, Debug)]
pub struct ResponseMetadata {
    #[serde(rename = "RequestId", default)]
    pub request_id: String,
    #[serde(rename = "Action", default)]
    pub action: String,
    #[serde(rename = "Region", default)]
    pub region: String,
    #[serde(rename = "Service", default)]
    pub service: String,
    #[serde(rename = "Version", default)]
    pub version: String,
    #[serde(rename = "Error")]
    pub error: Option<TopError>,
}

#[derive(Deserialize, Debug)]
pub struct TopError {
    #[serde(rename = "Code", default)]
    pub code: serde_json::Value,
    #[serde(rename = "Message", default)]
    pub message: String,
}

#[derive(Serialize)]
struct GetC2PAInstanceRequest<'a> {
    #[serde(rename = "InstanceId")]
    instance_id: &'a str,
}

#[derive(Deserialize, Debug)]
struct GetC2PAInstanceResult {
    #[serde(rename = "Certificate", default)]
    certificate: String,
    #[serde(rename = "CertificateChain", default)]
    certificate_chain: String,
    #[allow(dead_code)]
    #[serde(rename = "Status", default)]
    status: String,
}

#[derive(Serialize)]
struct C2paSignRequest<'a> {
    #[serde(rename = "InstanceId")]
    instance_id: &'a str,
    #[serde(rename = "Message")]
    message: String,
    #[serde(rename = "MessageType")]
    message_type: &'static str,
    #[serde(rename = "SigningAlgorithm")]
    signing_algorithm: &'a str,
}

#[derive(Deserialize, Debug)]
struct C2paSignResult {
    #[serde(rename = "Signature")]
    signature: String,
    #[allow(dead_code)]
    #[serde(rename = "InstanceId", default)]
    instance_id: String,
    #[allow(dead_code)]
    #[serde(rename = "SigningAlgorithm", default)]
    signing_algorithm: String,
}

/// 火山 ToB 云签 Signer 配置。
pub struct VolcSignerConfig {
    pub host: String,         // 例：https://open.volcengineapi.com
    pub region: String,        // 例：cn-north-1
    pub service: String,       // 例：c2pa_tob
    pub version: String,       // 例：1.0
    pub access_key: String,    // AK
    pub secret_key: String,    // SK
    pub instance_id: String,   // 实例 ID（C2PA 证书实例）
    pub signing_algorithm: String, // 火山签名算法名，例：RSASSA_PSS_SHA_256
    pub reserve_size: usize,
}

pub struct CloudSigner {
    cfg: VolcSignerConfig,
    certs: Vec<X509>,
    sdk_alg: SigningAlg,
    digest: MessageDigest,
    use_time_authority: bool,
    time_authority_url: Option<String>,
    sign_error: Mutex<Option<CloudSignError>>,
}

impl CloudSigner {
    /// 启动时调用 GetC2PAInstance 拉取证书链；后续 sign() 复用。
    pub fn new(cfg: VolcSignerConfig) -> Result<Self, CloudSignError> {
        let (sdk_alg, digest) = map_sdk_alg(&cfg.signing_algorithm)?;
        let body = serde_json::to_vec(&GetC2PAInstanceRequest {
            instance_id: &cfg.instance_id,
        })
        .map_err(|e| CloudSignError::InvalidUrl(format!("serialize GetC2PAInstance: {e}")))?;

        let response = volc_call(&cfg, "GetC2PAInstance", &body)?;
        let result = response
            .result
            .as_ref()
            .ok_or_else(|| CloudSignError::FailedCertResponse(
                "GetC2PAInstance".to_string(),
                response.clone_meta(),
            ))?;
        let parsed: GetC2PAInstanceResult = serde_json::from_value(result.clone())
            .map_err(|_| CloudSignError::FailedCertResponse(
                "GetC2PAInstance".to_string(),
                response.clone_meta(),
            ))?;

        // 拼接证书 + 证书链。两者均为 PEM。
        let mut pem_buf = Vec::new();
        if !parsed.certificate.is_empty() {
            pem_buf.extend_from_slice(parsed.certificate.as_bytes());
            if !parsed.certificate.ends_with('\n') {
                pem_buf.push(b'\n');
            }
        }
        if !parsed.certificate_chain.is_empty() {
            pem_buf.extend_from_slice(parsed.certificate_chain.as_bytes());
        }
        if pem_buf.is_empty() {
            return Err(CloudSignError::MissingCertificate);
        }
        let certs = X509::stack_from_pem(&pem_buf).map_err(CloudSignError::InvalidPemCert)?;
        if certs.is_empty() {
            return Err(CloudSignError::MissingCertificate);
        }

        Ok(CloudSigner {
            cfg,
            certs,
            sdk_alg,
            digest,
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
        // 先按 SigningAlgorithm 对应的摘要算法计算 digest。
        let digest = openssl::hash::hash(self.digest, data)
            .map_err(CloudSignError::HashDataFailed)?;
        let req = C2paSignRequest {
            instance_id: &self.cfg.instance_id,
            message: base64::engine::general_purpose::STANDARD.encode(&digest),
            message_type: "DIGEST",
            signing_algorithm: &self.cfg.signing_algorithm,
        };
        let body = serde_json::to_vec(&req)
            .map_err(|e| CloudSignError::InvalidUrl(format!("serialize C2PASign: {e}")))?;

        let response = volc_call(&self.cfg, "C2PASign", &body)?;
        let result = response
            .result
            .as_ref()
            .ok_or_else(|| CloudSignError::FailedSignResponse(
                "C2PASign".to_string(),
                response.clone_meta(),
            ))?;
        let parsed: C2paSignResult = serde_json::from_value(result.clone())
            .map_err(|_| CloudSignError::FailedSignResponse(
                "C2PASign".to_string(),
                response.clone_meta(),
            ))?;

        base64::engine::general_purpose::STANDARD
            .decode(parsed.signature.as_bytes())
            .map_err(CloudSignError::InvalidBase64Signature)
    }

    pub fn take_sign_error(&self) -> Option<CloudSignError> {
        self.sign_error.lock().unwrap().take()
    }
}

impl Signer for CloudSigner {
    fn sign(&self, data: &[u8]) -> c2pa::Result<Vec<u8>> {
        match self.do_sign(data) {
            Ok(d) => Ok(d),
            Err(e) => {
                let c2pa_e = c2pa::Error::from(&e);
                *self.sign_error.lock().unwrap() = Some(e);
                Err(c2pa_e)
            }
        }
    }

    fn alg(&self) -> SigningAlg {
        self.sdk_alg
    }

    fn certs(&self) -> c2pa::Result<Vec<Vec<u8>>> {
        let mut out = Vec::with_capacity(self.certs.len());
        for c in &self.certs {
            let der = c
                .to_der()
                .map_err(|e| c2pa::Error::IoError(io::Error::other(e.to_string())))?;
            out.push(der);
        }
        Ok(out)
    }

    fn reserve_size(&self) -> usize {
        self.cfg.reserve_size
    }

    fn time_authority_url(&self) -> Option<String> {
        if self.use_time_authority {
            self.time_authority_url.clone()
        } else {
            None
        }
    }
}

/// `Arc<CloudSigner>` 的 newtype，用于把 signer 同时给 builder
/// （`Box<dyn Signer>`）使用并保留旁路句柄调用 `take_sign_error()`。
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

/// 把火山的 SigningAlgorithm 名称映射成 SDK SigningAlg + 摘要算法。
fn map_sdk_alg(name: &str) -> Result<(SigningAlg, MessageDigest), CloudSignError> {
    let pair = match name {
        "RSASSA_PSS_SHA_256" => (SigningAlg::Ps256, MessageDigest::sha256()),
        "RSASSA_PSS_SHA_384" => (SigningAlg::Ps384, MessageDigest::sha384()),
        "RSASSA_PSS_SHA_512" => (SigningAlg::Ps512, MessageDigest::sha512()),
        "ECDSA_SHA_256" => (SigningAlg::Es256, MessageDigest::sha256()),
        "ECDSA_SHA_384" => (SigningAlg::Es384, MessageDigest::sha384()),
        "ECDSA_SHA_512" => (SigningAlg::Es512, MessageDigest::sha512()),
        "ED25519_SHA_512" => (SigningAlg::Ed25519, MessageDigest::sha512()),
        _ => {
            return Err(CloudSignError::InvalidUrl(format!(
                "unsupported SigningAlgorithm: {name}"
            )))
        }
    };
    Ok(pair)
}

/// 实际向火山发起 OpenAPI 调用。Action 通过 query string 携带，
/// 请求体为 JSON，签名按火山 V4 规则计算。
fn volc_call(
    cfg: &VolcSignerConfig,
    action: &str,
    body: &[u8],
) -> Result<VolcResponseFull, CloudSignError> {
    // 解析 host -> scheme + host
    let (scheme, host) = split_scheme_host(&cfg.host)?;
    let canonical_uri = "/";
    // 火山要求 query 按参数名升序排列。两个固定参数 Action / Version：A < V，已升序。
    let canonical_query = format!(
        "Action={}&Version={}",
        url_encode(action),
        url_encode(&cfg.version)
    );

    let now = Utc::now();
    let x_date = now.format("%Y%m%dT%H%M%SZ").to_string();
    let short_date = now.format("%Y%m%d").to_string();

    let body_sha256_hex = hex_lower(
        &openssl::hash::hash(MessageDigest::sha256(), body)
            .map_err(CloudSignError::HashDataFailed)?,
    );

    // 参与签名的 header 与火山官方 JS 脚本保持一致：只签 x-content-sha256;x-date
    // （content-type / host 都在 JS 实现的 unsignableHeaders 黑名单里或者根本不会被加入），
    // 这样不依赖 HTTP 客户端实际写到线上的 Host header 形态，避免端口/大小写差异导致
    // SignatureDoesNotMatch。
    let signed_headers = "x-content-sha256;x-date";
    let canonical_headers = format!(
        "x-content-sha256:{body_sha256_hex}\nx-date:{x_date}\n"
    );

    let canonical_request = format!(
        "POST\n{canonical_uri}\n{canonical_query}\n{canonical_headers}\n{signed_headers}\n{body_sha256_hex}"
    );
    let canonical_request_hash = hex_lower(
        &openssl::hash::hash(MessageDigest::sha256(), canonical_request.as_bytes())
            .map_err(CloudSignError::HashDataFailed)?,
    );

    let credential_scope = format!(
        "{short_date}/{}/{}/request",
        cfg.region, cfg.service
    );
    let string_to_sign = format!(
        "HMAC-SHA256\n{x_date}\n{credential_scope}\n{canonical_request_hash}"
    );

    // kSigning = HMAC(HMAC(HMAC(HMAC(SK, ShortDate), Region), Service), "request")
    let k_date = hmac_sha256(cfg.secret_key.as_bytes(), short_date.as_bytes())?;
    let k_region = hmac_sha256(&k_date, cfg.region.as_bytes())?;
    let k_service = hmac_sha256(&k_region, cfg.service.as_bytes())?;
    let k_signing = hmac_sha256(&k_service, b"request")?;
    let signature = hex_lower(&hmac_sha256(&k_signing, string_to_sign.as_bytes())?);

    let authorization = format!(
        "HMAC-SHA256 Credential={ak}/{credential_scope}, SignedHeaders={signed_headers}, Signature={signature}",
        ak = cfg.access_key
    );

    let url = format!("{scheme}://{host}{canonical_uri}?{canonical_query}");

    // 调试日志：设置 C2PATOOL_DEBUG_VOLC=1 打开
    let debug_on = std::env::var("C2PATOOL_DEBUG_VOLC").ok().as_deref() == Some("1");
    if debug_on {
        eprintln!("[volc-debug] >>> POST {url}");
        eprintln!("[volc-debug] X-Date: {x_date}");
        eprintln!("[volc-debug] X-Content-Sha256: {body_sha256_hex}");
        eprintln!("[volc-debug] Region: {}", cfg.region);
        eprintln!("[volc-debug] ServiceName: {}", cfg.service);
        eprintln!("[volc-debug] Authorization: {authorization}");
        eprintln!("[volc-debug] CredentialScope: {credential_scope}");
        eprintln!("[volc-debug] CanonicalRequest:\n{canonical_request}");
        eprintln!("[volc-debug] StringToSign:\n{string_to_sign}");
        eprintln!(
            "[volc-debug] Body: {}",
            std::str::from_utf8(body).unwrap_or("<non-utf8>")
        );
    }

    let body_owned = body.to_vec();
    let mut http_resp = ureq::post(&url)
        .header("Content-Type", "application/json")
        .header("Host", host.as_str())
        .header("X-Date", &x_date)
        .header("X-Content-Sha256", &body_sha256_hex)
        .header("Authorization", &authorization)
        .header("Region", &cfg.region)
        .header("ServiceName", &cfg.service)
        .config()
        // 让 ureq 不要在 4xx/5xx 时直接返回 Err，从而我们可以读出 body 内容
        .http_status_as_error(false)
        .build()
        .send(&body_owned[..])
        .map_err(CloudSignError::SendRequest)?;

    let status = http_resp.status().as_u16();
    let body_text = http_resp
        .body_mut()
        .read_to_string()
        .unwrap_or_default();

    if debug_on {
        eprintln!("[volc-debug] <<< HTTP {status}");
        eprintln!("[volc-debug] ResponseBody: {body_text}");
    }

    if !(200..300).contains(&status) {
        return Err(CloudSignError::HttpStatus(status, body_text));
    }

    let resp: JsonValue = serde_json::from_str(&body_text).map_err(|e| {
        // 复用 NotJsonResponseBody 但传 ureq::Error 不方便，这里用 HttpStatus 把 body 带回去。
        CloudSignError::HttpStatus(
            status,
            format!("response is not valid json: {e}; body={body_text}"),
        )
    })?;

    // 解析公共结构 + 检查 Error
    let mut full = VolcResponseFull::from_value(resp);
    if let Some(meta) = &full.response_metadata {
        if let Some(err) = &meta.error {
            // 写回 url 上下文然后返回错误。
            return Err(match action {
                "C2PASign" => CloudSignError::FailedSignResponse(url, full.clone_meta_with_err(err)),
                _ => CloudSignError::FailedCertResponse(url, full.clone_meta_with_err(err)),
            });
        }
    }
    full.url = url;
    Ok(full)
}

/// 完整响应（保留 url 用于错误展示）
pub struct VolcResponseFull {
    pub url: String,
    pub response_metadata: Option<ResponseMetadata>,
    pub result: Option<JsonValue>,
}

impl VolcResponseFull {
    fn from_value(v: JsonValue) -> Self {
        let response_metadata = v
            .get("ResponseMetadata")
            .cloned()
            .and_then(|m| serde_json::from_value(m).ok());
        let result = v.get("Result").cloned();
        Self {
            url: String::new(),
            response_metadata,
            result,
        }
    }

    fn clone_meta(&self) -> VolcResponse {
        VolcResponse {
            response_metadata: self
                .response_metadata
                .as_ref()
                .map(|m| ResponseMetadata {
                    request_id: m.request_id.clone(),
                    action: m.action.clone(),
                    region: m.region.clone(),
                    service: m.service.clone(),
                    version: m.version.clone(),
                    error: m.error.as_ref().map(|e| TopError {
                        code: e.code.clone(),
                        message: e.message.clone(),
                    }),
                }),
            result: self.result.clone(),
        }
    }

    fn clone_meta_with_err(&self, err: &TopError) -> VolcResponse {
        let mut v = self.clone_meta();
        if let Some(meta) = v.response_metadata.as_mut() {
            meta.error = Some(TopError {
                code: err.code.clone(),
                message: err.message.clone(),
            });
        }
        v
    }
}

fn hmac_sha256(key: &[u8], data: &[u8]) -> Result<Vec<u8>, CloudSignError> {
    let pkey = PKey::hmac(key).map_err(CloudSignError::HmacError)?;
    let mut signer = OpenSslSigner::new(MessageDigest::sha256(), &pkey)
        .map_err(CloudSignError::HmacError)?;
    signer
        .update(data)
        .map_err(CloudSignError::HmacError)?;
    signer.sign_to_vec().map_err(CloudSignError::HmacError)
}

fn hex_lower(data: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// 严格按 RFC3986 unreserved 编码（火山要求 query 参数名/值都进行 URI 编码）。
fn url_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(*b as char);
            }
            _ => {
                out.push('%');
                out.push_str(&format!("{:02X}", b));
            }
        }
    }
    out
}

fn split_scheme_host(s: &str) -> Result<(String, String), CloudSignError> {
    let (scheme, rest) = if let Some(rest) = s.strip_prefix("https://") {
        ("https", rest)
    } else if let Some(rest) = s.strip_prefix("http://") {
        ("http", rest)
    } else {
        return Err(CloudSignError::InvalidUrl(s.to_string()));
    };
    // 去掉末尾路径 / query
    let host = rest
        .split(|c| c == '/' || c == '?')
        .next()
        .unwrap_or("")
        .trim_end_matches(':')
        .to_string();
    if host.is_empty() {
        return Err(CloudSignError::InvalidUrl(s.to_string()));
    }
    Ok((scheme.to_string(), host))
}
