//! `submit-claim` — file an insurance claim with PHI resolved in the TEE.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use serde_json::{json, Value};

use crate::host::interfaces::logging;
use crate::util;

pub fn submit_claim(input: &[u8]) -> Result<Vec<u8>, String> {
    let req: Value = serde_json::from_slice(input).map_err(|e| format!("bad input json: {e}"))?;
    let claim_id = req
        .get("claim_id")
        .and_then(Value::as_str)
        .ok_or("submit-claim: missing claim_id")?;
    let service_codes = req.get("service_codes").cloned().unwrap_or_else(|| json!([]));

    let api_key = util::secret("insurer_api_key")?;
    let url = util::secret("insurer_url")
        .unwrap_or_else(|_| String::from("https://api.insurer.example/v1/claims"));

    // PHI enters as placeholders only; the host substitutes inside the enclave.
    let body = json!({
        "claim_id": claim_id,
        "member_id": "{{profile.insurance_member_id}}",
        "patient": {
            "given_name":   "{{profile.first_name}}",
            "family_name":  "{{profile.last_name}}",
            "date_of_birth":"{{profile.date_of_birth}}"
        },
        "diagnoses": "{{profile.diagnosis_codes}}",
        "service_codes": service_codes
    });
    let payload = serde_json::to_vec(&body).map_err(|e| format!("encode claim: {e}"))?;

    let _ = logging::info("aegis: submitting insurance claim (PHI via placeholders)");
    let resp = util::post_with_placeholders(&url, util::bearer_json(&api_key), payload)?;

    let parsed: Value = serde_json::from_slice(&resp).unwrap_or_else(|_| json!({}));
    let claim_ref = parsed
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("CLAIM-ACCEPTED");

    let out = json!({ "claim_ref": claim_ref, "status": "submitted" });
    serde_json::to_vec(&out).map_err(|e| format!("encode response: {e}"))
}
