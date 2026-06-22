import { describe, it, expect, beforeEach } from "vitest";
import { MockTeeNode } from "../src/t3/mock-node.js";
import { generateAgentSigningKey, randomEthIdentity, type EthIdentity } from "../src/t3/identity.js";
import { issueDelegation, type SignedDelegation } from "../src/t3/delegation.js";
import { buildInvocation } from "../src/t3/invocation.js";
import { defaultPolicy } from "../src/t3/policy.js";
import { ph, type PhiProfile } from "../src/domain/claim.js";
import { AuthzDenied, type AegisRequest } from "../src/t3/wire.js";

const PAYEE = "PAYOUT-REF-001";

const PROFILE: PhiProfile = {
  first_name: "Ada",
  last_name: "Okeke",
  date_of_birth: "1990-04-12",
  ssn: "123-45-6789",
  insurance_member_id: "MEM-998877",
  diagnosis_codes: ["E11.9", "I10"],
  payout_ref: PAYEE,
  email: "ada@example.com",
};

function setup(opts?: { ttlSecs?: number; nowSecs?: number }) {
  const patient = randomEthIdentity();
  const clinic = randomEthIdentity();
  const agentKey = generateAgentSigningKey();
  const node = new MockTeeNode();
  const fixedNow = opts?.nowSecs ?? 1_000_000;
  node.nowSecs = () => fixedNow;
  node.seedProfile(patient.did, PROFILE);

  const policy = defaultPolicy({ allowedPayees: [PAYEE], maxReimbursementCents: 50_000 });
  if (opts?.ttlSecs) policy.ttlSecs = opts.ttlSecs;
  const delegation = issueDelegation({
    patient,
    orgDid: clinic.did,
    agentPubkey: agentKey.pubkey,
    policy,
    nowSecs: fixedNow,
  });
  return { patient, clinic, agentKey, node, delegation, fixedNow };
}

function claimRequest(overrides?: Partial<AegisRequest>): AegisRequest {
  return {
    function: "submit-claim",
    claim_id: "CLM-1",
    counterparty: "insurer",
    body: {
      member_id: ph("insurance_member_id"),
      patient: { given: ph("first_name"), family: ph("last_name"), dob: ph("date_of_birth") },
      diagnoses: ph("diagnosis_codes"),
    },
    ...overrides,
  };
}

describe("Aegis authorization (real crypto via MockTeeNode)", () => {
  let env: ReturnType<typeof setup>;
  beforeEach(() => {
    env = setup();
  });

  it("accepts a properly delegated, in-policy claim and stamps audit", async () => {
    const inv = buildInvocation({
      delegation: env.delegation,
      request: claimRequest(),
      agentSecret: env.agentKey.secret,
    });
    const receipt = await env.node.execute(inv);
    expect(receipt.ok).toBe(true);
    expect(receipt.downstream_ref).toMatch(/^CLAIM-/);
    expect(receipt.disclosed_fields.sort()).toEqual(
      ["date_of_birth", "diagnosis_codes", "first_name", "insurance_member_id", "last_name"].sort(),
    );
    const audit = await env.node.audit(env.patient.did);
    expect(audit[0]?.outcome).toBe("success");
    expect(audit[0]?.action).toBe("submit-claim");
  });

  it("authorizes an in-cap reimbursement to an allowlisted payee", async () => {
    const inv = buildInvocation({
      delegation: env.delegation,
      request: {
        function: "execute-reimbursement",
        claim_id: "CLM-1",
        counterparty: "bank",
        payee_id: PAYEE,
        amount_cents: 25_000,
        body: { payout_ref: ph("payout_ref"), amount_cents: 25_000 },
      },
      agentSecret: env.agentKey.secret,
    });
    const receipt = await env.node.execute(inv);
    expect(receipt.amount_cents).toBe(25_000);
    expect(receipt.downstream_ref).toMatch(/^PAY-/);
  });

  it("rejects a request tampered with after signing (request_tampered)", async () => {
    const inv = buildInvocation({
      delegation: env.delegation,
      request: claimRequest(),
      agentSecret: env.agentKey.secret,
    });
    // Attacker swaps in extra disclosure AFTER the agent signed.
    (inv.request.body as Record<string, unknown>).ssn = ph("ssn");
    await expect(env.node.execute(inv)).rejects.toMatchObject({ code: "request_tampered" });
  });

  it("blocks reimbursement to a non-allowlisted payee (payee_not_allowed)", async () => {
    const inv = buildInvocation({
      delegation: env.delegation,
      request: {
        function: "execute-reimbursement",
        claim_id: "CLM-1",
        counterparty: "bank",
        payee_id: "ATTACKER-IBAN",
        amount_cents: 10_000,
        body: { payout_ref: ph("payout_ref") },
      },
      agentSecret: env.agentKey.secret,
    });
    await expect(env.node.execute(inv)).rejects.toMatchObject({ code: "payee_not_allowed" });
  });

  it("blocks an over-cap reimbursement (cap_exceeded)", async () => {
    const inv = buildInvocation({
      delegation: env.delegation,
      request: {
        function: "execute-reimbursement",
        claim_id: "CLM-1",
        counterparty: "bank",
        payee_id: PAYEE,
        amount_cents: 5_000_000,
        body: { payout_ref: ph("payout_ref") },
      },
      agentSecret: env.agentKey.secret,
    });
    await expect(env.node.execute(inv)).rejects.toMatchObject({ code: "cap_exceeded" });
  });

  it("blocks PHI overreach to a counterparty (disclosure_not_allowed)", async () => {
    const inv = buildInvocation({
      delegation: env.delegation,
      request: claimRequest({
        body: { member_id: ph("insurance_member_id"), ssn: ph("ssn") },
      }),
      agentSecret: env.agentKey.secret,
    });
    await expect(env.node.execute(inv)).rejects.toMatchObject({ code: "disclosure_not_allowed" });
  });

  it("rejects a replayed nonce (nonce_replayed)", async () => {
    const req = claimRequest();
    const inv1 = buildInvocation({
      delegation: env.delegation,
      request: req,
      agentSecret: env.agentKey.secret,
    });
    await env.node.execute(inv1);
    const inv2 = buildInvocation({
      delegation: env.delegation,
      request: req,
      agentSecret: env.agentKey.secret,
      nonce: inv1.envelope.nonce,
    });
    await expect(env.node.execute(inv2)).rejects.toMatchObject({ code: "nonce_replayed" });
  });

  it("rejects a revoked credential (revoked)", async () => {
    env.node.revoke(env.delegation.vcIdHex);
    const inv = buildInvocation({
      delegation: env.delegation,
      request: claimRequest(),
      agentSecret: env.agentKey.secret,
    });
    await expect(env.node.execute(inv)).rejects.toMatchObject({ code: "revoked" });
  });

  it("rejects an expired credential (expired)", async () => {
    const e = setup({ ttlSecs: 100, nowSecs: 1_000_000 });
    e.node.nowSecs = () => 1_000_000 + 200; // past not_after
    const inv = buildInvocation({
      delegation: e.delegation,
      request: claimRequest(),
      agentSecret: e.agentKey.secret,
    });
    await expect(e.node.execute(inv)).rejects.toMatchObject({ code: "expired" });
  });

  it("rejects a forged agent signature (bad_agent_sig)", async () => {
    const wrongKey = generateAgentSigningKey();
    const inv = buildInvocation({
      delegation: env.delegation, // credential binds the real agent pubkey
      request: claimRequest(),
      agentSecret: wrongKey.secret, // but a different key signs
    });
    await expect(env.node.execute(inv)).rejects.toBeInstanceOf(AuthzDenied);
    await expect(env.node.execute(inv)).rejects.toMatchObject({ code: "bad_agent_sig" });
  });
});
