/**
 * Domain model: healthcare claims, PHI, and placeholder mechanics.
 *
 * The central privacy invariant of Aegis:
 *
 *   The agent (and any LLM it uses) NEVER holds plaintext PHI. It composes
 *   outbound requests using `{{profile.*}}` placeholder tokens. Plaintext
 *   lives only inside the TEE's PHI vault and is substituted at egress —
 *   and only for fields the patient's delegation credential authorizes
 *   (selective disclosure per counterparty).
 *
 * `containsPlaintextPhi` / `referencedPhiFields` give the red-team harness a
 * way to PROVE the agent transmitted only placeholders, never raw PHI.
 */

/** A patient's protected health information. Lives ONLY in the TEE vault. */
export interface PhiProfile {
  first_name: string;
  last_name: string;
  date_of_birth: string; // YYYY-MM-DD
  ssn: string;
  insurance_member_id: string;
  /** ICD-10 diagnosis codes. */
  diagnosis_codes: string[];
  /** Patient's reimbursement payout reference (opaque to the agent). */
  payout_ref: string;
  email: string;
}

/** The set of PHI field names that may be referenced via placeholders. */
export type PhiField = keyof PhiProfile;

export const ALL_PHI_FIELDS: readonly PhiField[] = [
  "first_name",
  "last_name",
  "date_of_birth",
  "ssn",
  "insurance_member_id",
  "diagnosis_codes",
  "payout_ref",
  "email",
] as const;

/** A counterparty the agent may transmit to. Each gets a different slice. */
export type Counterparty = "insurer" | "pharmacy" | "bank";

/**
 * A claim the clinic hands to the agent. `clinical_note` is free text that
 * may have come from an untrusted source (a scanned document, an email, an
 * EHR export) — it is the prompt-injection attack surface the red-team
 * harness exploits.
 */
export interface Claim {
  claim_id: string;
  patient_did: string;
  insurer_payee_id: string;
  /** Service lines as opaque billing codes (not PHI). */
  service_codes: string[];
  /** Requested reimbursement in integer cents. */
  amount_cents: number;
  /** Free-text note — UNTRUSTED. May contain hidden instructions. */
  clinical_note: string;
}

const PLACEHOLDER_RE = /\{\{\s*profile\.([a-z_]+)\s*\}\}/g;

/** Build the canonical placeholder token for a PHI field. */
export function ph(field: PhiField): string {
  return `{{profile.${field}}}`;
}

/** List the PHI fields referenced by placeholders anywhere in `value`. */
export function referencedPhiFields(value: unknown): PhiField[] {
  const found = new Set<PhiField>();
  const walk = (v: unknown): void => {
    if (typeof v === "string") {
      for (const m of v.matchAll(PLACEHOLDER_RE)) {
        const field = m[1] as PhiField;
        if ((ALL_PHI_FIELDS as readonly string[]).includes(field)) found.add(field);
      }
    } else if (Array.isArray(v)) {
      v.forEach(walk);
    } else if (v && typeof v === "object") {
      Object.values(v).forEach(walk);
    }
  };
  walk(value);
  return [...found];
}

/**
 * Detect whether `value` contains any plaintext PHI from `profile` — i.e.
 * a raw secret that leaked out of the vault instead of staying a placeholder.
 * Returns the offending field names. An empty array is the safe result.
 *
 * This is the assertion the red-team harness runs against everything the
 * agent transmits: a compromised agent that tried to exfiltrate PHI would
 * have to put plaintext on the wire, and this would catch it.
 */
export function containsPlaintextPhi(value: unknown, profile: PhiProfile): PhiField[] {
  const haystack = JSON.stringify(value);
  const leaked = new Set<PhiField>();
  for (const field of ALL_PHI_FIELDS) {
    const raw = profile[field];
    const needles = Array.isArray(raw) ? raw : [raw];
    for (const needle of needles) {
      // Ignore trivially short/empty values to avoid false positives.
      if (typeof needle === "string" && needle.length >= 3 && haystack.includes(needle)) {
        leaked.add(field);
      }
    }
  }
  return [...leaked];
}
