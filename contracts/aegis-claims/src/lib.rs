//! tee:aegis v0.1.0 — healthcare claims & reimbursement contract.
//!
//! Two functions run inside the Trinity TEE:
//!   - `submit-claim`: templates the patient's PHI as `{{profile.<field>}}`
//!     markers into the insurer claim body and POSTs it via the host's
//!     `http-with-placeholders` interface. The host resolves the markers from
//!     the calling user's profile at dispatch time — gated by the on-chain
//!     agent-auth grant — so plaintext PHI never enters WASM memory.
//!   - `execute-reimbursement`: templates `{{profile.payout_ref}}` into a
//!     Stripe (test mode) PaymentIntent and POSTs it the same way.
//!
//! Only opaque references (claim ref, payment ref) cross the WIT boundary back
//! to the agent. Upstream error bodies are logged inside the enclave and never
//! forwarded, so a downstream 4xx can't be used to exfiltrate resolved PII.
//!
//! Secrets (insurer + Stripe API keys) are read from the z: KV map
//! `z:<tid>:secrets`, populated out-of-band by the tenant operator.
//!
//! # Host-capability manifest
//! ```json
//! { "host_capabilities": ["kv_store", "logging", "tenant_context", "http", "http_with_placeholders"] }
//! ```
#![cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]

extern crate alloc;

pub const CONTRACT_VERSION: &str = "0.1.0";

wit_bindgen::generate!({
    world: "aegis-claims",
    path: "wit",
    additional_derives: [serde::Deserialize, serde::Serialize],
    generate_all,
});

mod claims;
mod reimburse;
mod util;

struct Component;

#[cfg(target_arch = "wasm32")]
impl exports::z::aegis_claims::contracts::Guest for Component {
    fn submit_claim(
        req: exports::z::aegis_claims::contracts::GenericInput,
    ) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        let input = req.input.ok_or("submit-claim: missing input")?;
        claims::submit_claim(&input)
    }

    fn execute_reimbursement(
        req: exports::z::aegis_claims::contracts::GenericInput,
    ) -> Result<alloc::vec::Vec<u8>, alloc::string::String> {
        let input = req.input.ok_or("execute-reimbursement: missing input")?;
        reimburse::execute_reimbursement(&input)
    }
}

#[cfg(target_arch = "wasm32")]
export!(Component);

#[cfg(test)]
mod tests {
    use super::CONTRACT_VERSION;

    #[test]
    fn contract_version_is_semver() {
        let parts: alloc::vec::Vec<&str> = CONTRACT_VERSION.split('.').collect();
        assert_eq!(parts.len(), 3);
        for p in parts {
            assert!(p.parse::<u32>().is_ok());
        }
    }
}
