/**
 * Wire shapes shared between the agent (which builds invocations) and the
 * TEE / mock node (which verifies and executes them).
 */
import type { Counterparty, PhiField } from "../domain/claim.js";
import type { AegisFunction } from "./policy.js";

/** The concrete action the agent asks the TEE to perform. */
export interface AegisRequest {
  function: AegisFunction;
  claim_id: string;
  /** Who the outbound call targets (drives selective disclosure). */
  counterparty?: Counterparty;
  /** Reimbursement target; checked against the credential's payee allowlist. */
  payee_id?: string;
  /** Reimbursement amount in integer cents; checked against the cap. */
  amount_cents?: number;
  /** PHI fields the agent requests be resolved for this counterparty. */
  disclose?: PhiField[];
  /**
   * The outbound request body. Contains `{{profile.*}}` placeholders only —
   * never plaintext PHI. The TEE resolves permitted placeholders at egress.
   */
  body: unknown;
}

/**
 * Per-call delegation envelope. Mirrors the SDK's DelegationEnvelope shape:
 * the user-signed credential plus a fresh agent signature binding this exact
 * request (via request_hash) and a single-use nonce.
 */
export interface AegisEnvelope {
  /** RFC 8785 JCS bytes of the credential, exactly as the patient signed. */
  credential_jcs: Uint8Array;
  /** 65-byte EIP-191 signature by the patient over `credential_jcs`. */
  user_sig: Uint8Array;
  /** 64-byte secp256k1 agent signature over the invocation pre-image. */
  agent_sig: Uint8Array;
  /** 16-byte single-use nonce. */
  nonce: Uint8Array;
  /** SHA-256 of the canonical request body. */
  request_hash: Uint8Array;
}

/** What the agent sends to the TEE: an authorized, signed action. */
export interface AegisInvocation {
  envelope: AegisEnvelope;
  request: AegisRequest;
}

/** The TEE's response. Carries NO plaintext PHI — only receipts + proof. */
export interface AegisReceipt {
  ok: true;
  function: AegisFunction;
  claim_id: string;
  /** Which PHI fields were disclosed to the counterparty (names only). */
  disclosed_fields: PhiField[];
  /** For reimbursements: the (masked) payee and the amount actually paid. */
  payee_id?: string;
  amount_cents?: number;
  /** Opaque settlement/claim reference returned by the downstream API. */
  downstream_ref: string;
  /** Host-stamped audit id for this action. */
  audit_id: string;
}

/** A typed authorization failure from the TEE. */
export class AuthzDenied extends Error {
  constructor(
    readonly code:
      | "bad_user_sig"
      | "bad_agent_sig"
      | "request_tampered"
      | "nonce_replayed"
      | "expired"
      | "revoked"
      | "function_not_authorized"
      | "payee_not_allowed"
      | "cap_exceeded"
      | "disclosure_not_allowed",
    message: string,
  ) {
    super(message);
    this.name = "AuthzDenied";
  }
}
