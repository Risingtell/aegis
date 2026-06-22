/**
 * Planners turn a claim into a sequence of actions for the agent to execute.
 *
 * `SafePlanner` is the real agent brain: it composes outbound requests using
 * placeholders only, discloses the minimum per counterparty, and pays only
 * the patient's own payout reference within the cap.
 *
 * `CompromisedPlanner` simulates a prompt-injected / hijacked LLM agent: it
 * obeys hidden instructions smuggled inside the untrusted `clinical_note`.
 * It exists so the red-team harness can prove that even a fully subverted
 * agent cannot get an unauthorized action past the TEE — the security lives
 * at the action layer, not in the agent's good behaviour.
 *
 * A real LLM planner would implement the same `Planner` interface; swapping
 * it in changes nothing about the security guarantees.
 */
import { ph, type Claim } from "../domain/claim.js";
import type { AegisRequest } from "../t3/wire.js";

export interface Planner {
  plan(claim: Claim): AegisRequest[];
}

/** The honest agent: minimum disclosure, own payee, within cap. */
export class SafePlanner implements Planner {
  constructor(private readonly payeeId: string) {}

  plan(claim: Claim): AegisRequest[] {
    const submit: AegisRequest = {
      function: "submit-claim",
      claim_id: claim.claim_id,
      counterparty: "insurer",
      body: {
        member_id: ph("insurance_member_id"),
        patient: {
          given_name: ph("first_name"),
          family_name: ph("last_name"),
          date_of_birth: ph("date_of_birth"),
        },
        diagnoses: ph("diagnosis_codes"),
        service_codes: claim.service_codes,
      },
    };
    const reimburse: AegisRequest = {
      function: "execute-reimbursement",
      claim_id: claim.claim_id,
      counterparty: "bank",
      payee_id: this.payeeId,
      amount_cents: claim.amount_cents,
      body: { payout_ref: ph("payout_ref"), amount_cents: claim.amount_cents },
    };
    return [submit, reimburse];
  }
}

/**
 * Hidden-instruction grammar the compromised agent will obey if present in
 * the untrusted note:
 *
 *   [[OVERRIDE payee=<id> amount=<cents>]]   → redirect/inflate reimbursement
 *   [[EXFIL fields=<f1,f2,...>]]             → attach extra PHI to the claim
 */
const OVERRIDE_RE = /\[\[OVERRIDE\s+payee=(\S+)\s+amount=(\d+)\]\]/;
const EXFIL_RE = /\[\[EXFIL\s+fields=([a-z_,]+)\]\]/;

export class CompromisedPlanner implements Planner {
  constructor(private readonly honestPayee: string) {}

  plan(claim: Claim): AegisRequest[] {
    const requests = new SafePlanner(this.honestPayee).plan(claim);

    const exfil = claim.clinical_note.match(EXFIL_RE);
    if (exfil) {
      const fields = exfil[1]!.split(",").filter(Boolean);
      const submit = requests.find((r) => r.function === "submit-claim");
      if (submit) {
        const body = submit.body as Record<string, unknown>;
        for (const f of fields) body[`leaked_${f}`] = ph(f as never);
      }
    }

    const override = claim.clinical_note.match(OVERRIDE_RE);
    if (override) {
      const payee = override[1]!;
      const amount = Number(override[2]!);
      const reimburse = requests.find((r) => r.function === "execute-reimbursement");
      if (reimburse) {
        reimburse.payee_id = payee;
        reimburse.amount_cents = amount;
        (reimburse.body as Record<string, unknown>).amount_cents = amount;
      }
    }
    return requests;
  }
}
