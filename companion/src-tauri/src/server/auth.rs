//! Public-key authentication middleware for the Companion local API.

use super::errors::ApiError;
use super::AppState;
use axum::body::to_bytes;
use axum::extract::{Query, State};
use axum::http::{Request, Uri};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use base64::Engine;
use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use url::Url;

const KEY_HEADER: &str = "x-companion-key";
const SIGNATURE_HEADER: &str = "x-companion-signature";
const TIMESTAMP_HEADER: &str = "x-companion-timestamp";
const NONCE_HEADER: &str = "x-companion-nonce";
const BODY_HASH_HEADER: &str = "x-companion-body-sha256";
const MAX_TIMESTAMP_SKEW: u64 = 30;
pub(super) const AUTH_PROTOCOL_VERSION: u32 = 3;
pub(super) const AUTH_SIGNATURE_MISMATCH_CODE: &str = "companion_auth_signature_mismatch";
pub(super) const PAIRING_NOT_FOUND_CODE: &str = "companion_pairing_not_found";

pub(super) struct AuthLogContext<'a> {
    pub(super) method: &'a str,
}

pub(super) struct SignedRequestCredentials {
    pub(super) origin: String,
    pub(super) key: String,
    pub(super) signature: String,
    pub(super) timestamp: String,
    pub(super) nonce: String,
    pub(super) body_hash: String,
}
pub struct AuthState {}
impl AuthState {
    pub fn new() -> Self {
        Self {}
    }
}

#[derive(Deserialize, Default)]
struct AuthQueryParams {
    sig: Option<String>,
    ts: Option<String>,
    nonce: Option<String>,
    key: Option<String>,
    body_sha256: Option<String>,
    origin: Option<String>,
}

pub fn normalize_browser_origin(origin: &str) -> Option<String> {
    let url = Url::parse(origin).ok()?;
    match url.scheme() {
        "http" | "https" => Some(url.origin().ascii_serialization()),
        _ => None,
    }
}
pub fn is_loopback_dev_origin(origin: &str) -> bool {
    let Some(normalized) = normalize_browser_origin(origin) else {
        return false;
    };
    let Ok(url) = Url::parse(&normalized) else { return false };
    matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1" | "[::1]"))
}
pub fn is_allowed_browser_origin_for_cors(origin: &str) -> bool {
    is_loopback_dev_origin(origin) || normalize_browser_origin(origin).is_some()
}
pub fn require_normalized_browser_origin(origin: &str) -> Result<String, ApiError> {
    normalize_browser_origin(origin)
        .ok_or_else(|| ApiError::Forbidden("Origin is not allowed to access the companion bootstrap API".to_string()))
}

pub fn signature_payload(origin: &str, timestamp: &str, nonce: &str, method: &str, uri: &Uri, body_hash: &str) -> String {
    let mut parameters: Vec<(String, String)> = url::form_urlencoded::parse(uri.query().unwrap_or_default().as_bytes())
        .filter(|(key, _)| !matches!(key.as_ref(), "sig" | "ts" | "nonce" | "key" | "body_sha256" | "origin" | "hmac"))
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    parameters.sort();
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(parameters.iter().map(|(k, v)| (k, v)))
        .finish();
    let target = if query.is_empty() {
        uri.path().to_string()
    } else {
        format!("{}?{query}", uri.path())
    };
    format!("{origin}\n{timestamp}\n{nonce}\n{method}\n{target}\n{body_hash}")
}

pub async fn require_auth(State(state): State<Arc<AppState>>, request: Request<axum::body::Body>, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return ApiError::Forbidden("Request body is too large or unreadable".to_string()).into_response(),
    };
    let body_hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&bytes));
    let request = Request::from_parts(parts, axum::body::Body::from(bytes));
    let context = AuthLogContext {
        method: request.method().as_str(),
    };
    match extract_auth_credentials(&request)
        .and_then(|credentials| validate_signature(&state, credentials, request.uri(), &context, Some(&body_hash)))
    {
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    }
}

pub async fn require_auth_or_query(State(state): State<Arc<AppState>>, request: Request<axum::body::Body>, next: Next) -> Response {
    let (parts, body) = request.into_parts();
    let bytes = match to_bytes(body, 10 * 1024 * 1024).await {
        Ok(bytes) => bytes,
        Err(_) => return ApiError::Forbidden("Request body is too large or unreadable".to_string()).into_response(),
    };
    let body_hash = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&bytes));
    let request = Request::from_parts(parts, axum::body::Body::from(bytes));
    let context = AuthLogContext {
        method: request.method().as_str(),
    };
    if let Ok(credentials) = extract_auth_credentials(&request) {
        return match validate_signature(&state, credentials, request.uri(), &context, Some(&body_hash)) {
            Ok(()) => next.run(request).await,
            Err(error) => error.into_response(),
        };
    }
    let query: AuthQueryParams = Query::try_from_uri(request.uri()).map(|query| query.0).unwrap_or_default();
    let (Some(sig), Some(ts), Some(nonce), Some(key), Some(body_sha256), Some(origin)) =
        (query.sig, query.ts, query.nonce, query.key, query.body_sha256, query.origin)
    else {
        return ApiError::Forbidden("Missing authentication headers".to_string()).into_response();
    };
    let context = AuthLogContext {
        method: request.method().as_str(),
    };
    match validate_signature(
        &state,
        SignedRequestCredentials {
            origin,
            key,
            signature: sig,
            timestamp: ts,
            nonce,
            body_hash: body_sha256,
        },
        request.uri(),
        &context,
        Some(&body_hash),
    ) {
        Ok(()) => next.run(request).await,
        Err(error) => error.into_response(),
    }
}

fn extract_auth_credentials(request: &Request<axum::body::Body>) -> Result<SignedRequestCredentials, ApiError> {
    let origin = request
        .headers()
        .get("origin")
        .and_then(|value| value.to_str().ok())
        .and_then(normalize_browser_origin)
        .ok_or_else(|| ApiError::Forbidden("Missing Origin header".to_string()))?;
    let header = |name: &str, message: &str| {
        request
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
            .ok_or_else(|| ApiError::Forbidden(message.to_string()))
    };
    Ok(SignedRequestCredentials {
        origin,
        key: header(KEY_HEADER, "Missing X-Companion-Key header")?,
        signature: header(SIGNATURE_HEADER, "Missing X-Companion-Signature header")?,
        timestamp: header(TIMESTAMP_HEADER, "Missing X-Companion-Timestamp header")?,
        nonce: header(NONCE_HEADER, "Missing X-Companion-Nonce header")?,
        body_hash: header(BODY_HASH_HEADER, "Missing X-Companion-Body-SHA256 header")?,
    })
}

pub(super) fn validate_signed_request(
    state: &AppState,
    credentials: SignedRequestCredentials,
    uri: &Uri,
    context: &AuthLogContext,
) -> Result<(), ApiError> {
    validate_signature(state, credentials, uri, context, None)
}

fn validate_signature(
    state: &AppState,
    credentials: SignedRequestCredentials,
    uri: &Uri,
    context: &AuthLogContext,
    actual_body_hash: Option<&str>,
) -> Result<(), ApiError> {
    let SignedRequestCredentials {
        origin,
        key,
        signature,
        timestamp: timestamp_str,
        nonce,
        body_hash,
    } = credentials;
    let origin = require_normalized_browser_origin(&origin)?;
    let registered_key = state
        .pairing
        .get_public_key_for_origin(&origin)
        .ok_or_else(|| ApiError::forbidden_code("Not paired with this origin", PAIRING_NOT_FOUND_CODE))?;
    if key != registered_key {
        return Err(ApiError::forbidden_code("Invalid authentication", AUTH_SIGNATURE_MISMATCH_CODE));
    }
    let timestamp: u64 = timestamp_str
        .parse()
        .map_err(|_| ApiError::Forbidden("Invalid timestamp format".to_string()))?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    if now.abs_diff(timestamp) > MAX_TIMESTAMP_SKEW {
        return Err(ApiError::Forbidden("Request timestamp too old or too new".to_string()));
    }
    if let Some(actual_body_hash) = actual_body_hash {
        if body_hash != actual_body_hash {
            return Err(ApiError::Forbidden("Request body hash mismatch".to_string()));
        }
    }
    if !state.pairing.consume_request_nonce(&format!("{origin}\n{nonce}")) {
        return Err(ApiError::Forbidden("Request nonce has already been used".to_string()));
    }
    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(key)
        .map_err(|_| ApiError::Forbidden("Invalid public key".to_string()))?;
    let verifying_key = VerifyingKey::from_sec1_bytes(&key_bytes).map_err(|_| ApiError::Forbidden("Invalid public key".to_string()))?;
    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature)
        .map_err(|_| ApiError::Forbidden("Invalid signature".to_string()))?;
    let signature = Signature::from_slice(&signature_bytes).map_err(|_| ApiError::Forbidden("Invalid signature".to_string()))?;
    verifying_key
        .verify(
            signature_payload(&origin, &timestamp_str, &nonce, context.method, uri, &body_hash).as_bytes(),
            &signature,
        )
        .map_err(|_| ApiError::forbidden_code("Invalid authentication", AUTH_SIGNATURE_MISMATCH_CODE))?;
    if !state.pairing.is_origin_paired(&origin) {
        state.pairing.record_verified_origin(
            &origin,
            crate::server::pairing::VerifiedOriginRecordReason::RecoveredFromAuthenticatedRequest,
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn normalizes_browser_origins_exactly() {
        assert_eq!(
            normalize_browser_origin("https://Sambee.Example.com:8443").as_deref(),
            Some("https://sambee.example.com:8443")
        );
    }
    #[test]
    fn recognizes_loopback_dev_origins() {
        assert!(is_loopback_dev_origin("http://localhost:5173"));
        assert!(!is_loopback_dev_origin("https://sambee.example.com"));
    }
    #[test]
    fn excludes_auth_parameters_from_payload() {
        let uri: Uri = "/x?b=2&sig=s&a=1".parse().unwrap();
        assert_eq!(
            signature_payload("https://example.test", "1", "n", "GET", &uri, "h"),
            "https://example.test\n1\nn\nGET\n/x?a=1&b=2\nh"
        );
    }
}
