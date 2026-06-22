/**
 * The authorization policy a patient grants to the Aegis agent.
 *
 * This is the human-meaningful description of "what may this agent do on my
 * behalf, and within what limits". It is compiled into a Terminal 3
 * delegation credential (functions / scopes / metadata / validity window)
 * that the patient cryptographically signs. The TEE then enforces every
 * field at the action layer — the agent's own restraint is never trusted.
 */
import type { Counterparty, PhiField } from "../domain/claim.js";

/** The functions Aegis can be authorized to perform. */
export type AegisFunction = "submit-claim" | "execute-reimbursement" | "finalize-audit";

export const AEGIS_FUNCTIONS: readonly AegisFunction[] = [
  "execute-reimbursement",
  "finalize-audit",
  "submit-claim",
] as const; // sorted ascending — the credential requires sorted, deduped functions

/** Contract id the credential authorizes against. */
export const AEGIS_CONTRACT = "tee:aegis";

/** Data scope the contract may read on the patient's behalf. */
export const AEGIS_SCOPE = "claims/records";

export interface AegisPolicy {
  /** Functions the agent may invoke. */
  functions: AegisFunction[];
  /** Payee ids the agent may pay (reimbursement allowlist). */
  allowedPayees: string[];
  /** Hard cap on any single reimbursement, in integer cents. */
  maxReimbursementCents: number;
  /** Per-counterparty selective-disclosure allowlist of PHI fields. */
  disclosure: Record<Counterparty, PhiField[]>;
  /** Validity window in seconds from issuance. */
  ttlSecs: number;
}

/**
 * A sane default policy for a claims+reimbursement agent:
 *  - may submit claims and disburse reimbursements,
 *  - only to a single pre-approved payout reference,
 *  - capped at $500.00 per disbursement,
 *  - insurer sees only the minimum needed to adjudicate; the bank sees only
 *    the payout reference; nobody gets the SSN.
 */
export function defaultPolicy(opts: {
  allowedPayees: string[];
  maxReimbursementCents?: number;
  ttlSecs?: number;
}): AegisPolicy {
  return {
    functions: [...AEGIS_FUNCTIONS],
    allowedPayees: opts.allowedPayees,
    maxReimbursementCents: opts.maxReimbursementCents ?? 50_000,
    ttlSecs: opts.ttlSecs ?? 24 * 60 * 60,
    disclosure: {
      insurer: ["first_name", "last_name", "date_of_birth", "insurance_member_id", "diagnosis_codes"],
      pharmacy: ["first_name", "last_name", "date_of_birth"],
      bank: ["payout_ref"],
    },
  };
}

/**
 * Encode a policy's constraints into the credential's flat string metadata
 * map. The TEE reads these back to enforce limits. Kept as a stable,
 * greppable wire format (comma-joined lists, decimal cents).
 */
export function policyMetadata(policy: AegisPolicy): Record<string, string> {
  return {
    allowed_payees: policy.allowedPayees.join(","),
    max_reimbursement_cents: String(policy.maxReimbursementCents),
    disclose_insurer: policy.disclosure.insurer.join(","),
    disclose_pharmacy: policy.disclosure.pharmacy.join(","),
    disclose_bank: policy.disclosure.bank.join(","),
  };
}

/** Parse the disclosure allowlist for a counterparty back out of metadata. */
export function disclosureFromMetadata(
  metadata: Record<string, string>,
  counterparty: Counterparty,
): PhiField[] {
  const key = `disclose_${counterparty}` as const;
  const raw = metadata[key];
  if (!raw) return [];
  return raw.split(",").map((s) => s.trim()).filter(Boolean) as PhiField[];
}
