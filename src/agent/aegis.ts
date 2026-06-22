/**
 * The Aegis agent.
 *
 * Holds its own per-delegation signing key and the patient's signed
 * delegation credential. For each planned action it builds a signed
 * invocation and submits it to the executor (live TEE or mock). It only ever
 * handles placeholders and receipts — plaintext PHI never enters the agent.
 */
import type { Claim } from "../domain/claim.js";
import type { AgentSigningKey } from "../t3/identity.js";
import type { SignedDelegation } from "../t3/delegation.js";
import type { AegisExecutor } from "../t3/executor.js";
import { buildInvocation } from "../t3/invocation.js";
import { AuthzDenied, type AegisReceipt, type AegisRequest } from "../t3/wire.js";
import type { Planner } from "./planner.js";

export interface StepResult {
  request: AegisRequest;
  receipt?: AegisReceipt;
  denied?: { code: AuthzDenied["code"]; message: string };
}

export interface AgentRunResult {
  claim_id: string;
  steps: StepResult[];
  /** Convenience: every step that the TEE refused. */
  denials: StepResult[];
}

export class AegisAgent {
  constructor(
    private readonly executor: AegisExecutor,
    private readonly agentKey: AgentSigningKey,
    private readonly delegation: SignedDelegation,
    private readonly planner: Planner,
  ) {}

  /** Confirm the executor is a genuine TEE before trusting it with PHI. */
  async verifyExecutor(): Promise<boolean> {
    const att = await this.executor.attestation();
    return att.attested;
  }

  async run(claim: Claim): Promise<AgentRunResult> {
    const steps: StepResult[] = [];
    for (const request of this.planner.plan(claim)) {
      const inv = buildInvocation({
        delegation: this.delegation,
        request,
        agentSecret: this.agentKey.secret,
      });
      try {
        const receipt = await this.executor.execute(inv);
        steps.push({ request, receipt });
      } catch (err) {
        if (err instanceof AuthzDenied) {
          steps.push({ request, denied: { code: err.code, message: err.message } });
        } else {
          throw err;
        }
      }
    }
    return { claim_id: claim.claim_id, steps, denials: steps.filter((s) => s.denied) };
  }
}
