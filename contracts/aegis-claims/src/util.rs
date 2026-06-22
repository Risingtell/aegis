//! Shared helpers: secret reads, header building, placeholder-HTTP wrapper.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use crate::host::interfaces::http_with_placeholders as hwp;
use crate::host::interfaces::{kv_store, logging};
use crate::host::tenant::tenant_context;

/// Read a secret from the tenant's `z:<tid>:secrets` KV map.
pub fn secret(key: &str) -> Result<String, String> {
    let tid = tenant_context::tenant_did();
    let map = format!("z:{}:secrets", hex::encode(&tid));
    let bytes = kv_store::get(&map, key.as_bytes())
        .map_err(|e| format!("kv get {key}: {e}"))?
        .ok_or_else(|| format!("secret '{key}' not found in {map}"))?;
    String::from_utf8(bytes).map_err(|_| format!("secret '{key}' is not valid utf8"))
}

/// `Authorization: Bearer <token>` + JSON content-type headers.
pub fn bearer_json(token: &str) -> Vec<(String, String)> {
    vec![
        ("Authorization".to_string(), format!("Bearer {token}")),
        ("Content-Type".to_string(), "application/json".to_string()),
    ]
}

/// `Authorization: Bearer` + form content-type (Stripe expects form-encoding).
pub fn bearer_form(token: &str) -> Vec<(String, String)> {
    vec![
        ("Authorization".to_string(), format!("Bearer {token}")),
        (
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ),
    ]
}

fn fmt_hwp_err(e: hwp::HttpError) -> String {
    match e {
        hwp::HttpError::EgressDenied(s) => format!("egress denied: {s}"),
        hwp::HttpError::PlaceholderDenied(s) => format!("placeholder denied: {s}"),
        hwp::HttpError::PlaceholderUnknown(s) => format!("profile missing field: {s}"),
        hwp::HttpError::PlaceholderNoUserContext => "no user context bound".to_string(),
        hwp::HttpError::UpstreamError(s) => format!("upstream error: {s}"),
    }
}

/// POST a placeholder-bearing body through the TEE's http-with-placeholders.
/// On a non-2xx, the upstream body is logged inside the enclave and a generic
/// status error is returned — the resolved PII is never forwarded to the agent.
pub fn post_with_placeholders(
    url: &str,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
) -> Result<Vec<u8>, String> {
    let resp = hwp::call(&hwp::Request {
        method: hwp::Verb::Post,
        url: url.to_string(),
        headers: Some(headers),
        payload: Some(body),
    })
    .map_err(fmt_hwp_err)?;

    if (200..300).contains(&resp.code) {
        Ok(resp.payload)
    } else {
        let _ = logging::error(&format!("downstream {url} returned HTTP {}", resp.code));
        Err(format!("downstream rejected request (HTTP {})", resp.code))
    }
}
