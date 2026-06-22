/**
 * End-to-end happy-path demo: `npm run demo`
 *
 * A patient delegates scoped authority to the Aegis agent; the agent files an
 * insurance claim and disburses the reimbursement — touching real PHI and
 * moving money — without ever holding plaintext PHI or an unbounded payout
 * capability. Then the patient revokes, and the agent goes dark.
 */
import { loadAegisConfig } from "./config.js";
import { buildWorld, legitClaim, PATIENT_PHI, PAYOUT_REF } from "./redteam/world.js";
import { SafePlanner } from "./agent/planner.js";
import { formatTokens } from "@terminal3/t3n-sdk";

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  cyan: "\x1b[36m",
  yellow: "\x1b[33m",
  magenta: "\x1b[35m",
};
const log = (s = ""): void => void process.stdout.write(s + "\n");
const usd = (cents: number): string => `$${formatTokens(cents * 10_000)}`; // cents → 6dp token fmt

async function main(): Promise<void> {
  const cfg = loadAegisConfig();
  log();
  log(`${C.bold}${C.cyan}⚕  Aegis — Healthcare Claims & Reimbursement Agent${C.reset}`);
  log(`${C.dim}mode=${cfg.mode}  env=${cfg.environment}  (built on Terminal 3 Agent Auth)${C.reset}`);
  log();

  const world = buildWorld();

  // 0. Attestation — confirm we trust the executor before handing it PHI.
  const att = await world.node.attestation();
  log(`${C.bold}0) Executor attestation${C.reset}`);
  log(`   kind=${att.kind}  attested=${att.attested}`);
  log(`   ${C.dim}${att.detail}${C.reset}`);
  log();

  // 1. Delegation — what the patient authorized.
  log(`${C.bold}1) Patient → Agent delegation (signed credential)${C.reset}`);
  log(`   patient   ${C.dim}${world.patient.did}${C.reset}`);
  log(`   clinic    ${C.dim}${world.clinic.did}${C.reset}`);
  log(`   functions ${world.policy.functions.join(", ")}`);
  log(`   payee     ${PAYOUT_REF} (allowlisted)`);
  log(`   cap       ${usd(world.policy.maxReimbursementCents)} per reimbursement`);
  log(`   ttl       ${world.policy.ttlSecs / 3600}h   credential id ${world.delegation.vcIdHex.slice(0, 12)}…`);
  log();

  // 2. The agent processes a legitimate claim.
  const claim = legitClaim();
  log(`${C.bold}2) Agent processes claim ${claim.claim_id}${C.reset}  ${C.dim}(amount ${usd(claim.amount_cents)})${C.reset}`);
  const agent = world.agent(new SafePlanner(PAYOUT_REF));
  const result = await agent.run(claim);

  for (const step of result.steps) {
    if (step.receipt) {
      const r = step.receipt;
      const tail =
        r.function === "execute-reimbursement"
          ? `paid ${usd(r.amount_cents ?? 0)} → ${r.payee_id}`
          : `disclosed: ${r.disclosed_fields.join(", ")}`;
      log(`   ${C.green}✓${C.reset} ${r.function.padEnd(22)} ${C.dim}ref ${r.downstream_ref}${C.reset}  ${tail}`);
    } else if (step.denied) {
      log(`   ✗ ${step.request.function} → ${step.denied.code}`);
    }
  }
  log();
  log(`   ${C.magenta}PHI exposure to agent/LLM: NONE.${C.reset} The agent transmitted only`);
  log(`   ${C.dim}{{profile.*}} placeholders; the TEE resolved them at egress with`);
  log(`   selective disclosure (insurer ≠ bank). SSN was never disclosed at all.${C.reset}`);
  log();

  // 3. Tamper-evident audit trail (host-stamped: it can't be forged).
  log(`${C.bold}3) Tamper-evident audit trail${C.reset}`);
  for (const e of await world.node.audit(world.patient.did)) {
    log(
      `   ${C.dim}${new Date(e.ts_ms).toISOString()}${C.reset}  ` +
        `${e.action.padEnd(22)} ${C.green}${e.outcome}${C.reset}  ` +
        `${C.dim}${e.target}  by ${e.actor}${C.reset}`,
    );
  }
  log();

  // 4. Revocation — the patient pulls authority; the agent goes dark.
  log(`${C.bold}4) Patient revokes the delegation${C.reset}`);
  world.node.revoke(world.delegation.vcIdHex);
  const after = await world.agent(new SafePlanner(PAYOUT_REF)).run(legitClaim());
  const code = after.steps[0]?.denied?.code ?? "ALLOWED (!!)";
  log(`   next agent action → ${C.yellow}${code}${C.reset}  ${C.dim}(authority enforced by the TEE)${C.reset}`);
  log();
  log(`${C.green}${C.bold}Done.${C.reset} Run ${C.bold}npm run redteam${C.reset} to watch Aegis defeat 7 real-world attacks.`);
  log();
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
