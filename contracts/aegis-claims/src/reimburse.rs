//! `execute-reimbursement` — disburse via Stripe (test mode), payout reference
//! resolved in the TEE.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use serde_json::Value;

use crate::host::interfaces::logging;
use crate::util;

const STRIPE_URL: &str = "https://api.stripe.com/v1/payment_intents";

pub fn execute_reimbursement(input: &[u8]) -> Result<Vec<u8>, String> {
    let req: Value = serde_json::from_slice(input).map_err(|e| format!("bad input json: {e}"))?;
    let claim_id = req
        .get("claim_id")
        .and_then(Value::as_str)
        .ok_or("execute-reimbursement: missing claim_id")?;
    let amount = req
        .get("amount_cents")
        .and_then(Value::as_u64)
        .ok_or("execute-reimbursement: missing/invalid amount_cents")?;
    let currency = req
        .get("currency")
        .and_then(Value::as_str)
        .unwrap_or("usd");

    let api_key = util::secret("stripe_api_key")?;

    // Stripe is form-encoded. The payout reference is templated as a
    // placeholder; the host substitutes it inside the enclave. Braces are
    // kept literal (no URL-encoding) so the host can match the marker.
    let form = format!(
        "amount={amount}&currency={currency}&payment_method_types[]=card\
         &description=Aegis%20reimbursement%20{claim_id}\
         &metadata[claim_id]={claim_id}\
         &metadata[payout_ref]={{{{profile.payout_ref}}}}"
    );

    let _ = logging::info("aegis: executing reimbursement (payout ref via placeholder)");
    let resp = util::post_with_placeholders(
        STRIPE_URL,
        util::bearer_form(&api_key),
        form.into_bytes(),
    )?;

    let parsed: Value = serde_json::from_slice(&resp).unwrap_or(Value::Null);
    let payment_ref = parsed
        .get("id")
        .and_then(Value::as_str)
        .unwrap_or("pi_unknown")
        .to_string();
    let status = parsed
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("created")
        .to_string();

    let out = serde_json::json!({ "payment_ref": payment_ref, "status": status });
    serde_json::to_vec(&out).map_err(|e| format!("encode response: {e}"))
}
