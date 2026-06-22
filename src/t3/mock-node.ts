/**
 * In-memory simulator of the Terminal 3 TEE node.
 *
 * This is NOT a stub that rubber-stamps requests. It performs the SAME
 * cryptographic authorization the real node performs, using the SDK's own
 * verification primitives:
 *
 *   1. user_sig must recover the credential's user_did (patient really signed)
 *   2. agent_sig must verify against the credential's bound agent_pubkey
 *   3. request_hash must match the canonical hash of the request (no tamper)
 *   4. nonce must be unused (no replay)
 *   5. now must be within the credential's validity window
 *   6. the credential must not be revoked
 *   7. the function must be authorized
 *   8. reimbursement payee must be on the allowlist; amount <= cap
 *   9. every PHI field referenced by the outbound body must be permitted by
 *      the credential's selective-disclosure list for that counterparty
 *
 * PHI plaintext lives ONLY here (the vault) and is substituted at egress.
 * The receipt returned to the agent carries no plaintext — only field names
 * disclosed, a downstream reference, and a host-stamped audit id.
 *
 * Because these are real signature checks, a fully compromised or
 * prompt-injected agent cannot push an unauthorized action through — which
 * is exactly what the red-team harness demonstrates.
 */
import { b64uDecodeStrict, buildInvocationPreimage, ethRecoverEip191 } from "@terminal3/t3n-sdk";
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import {
  ALL_PHI_FIELDS,
  referencedPhiFields,
  type Counterparty,
  type PhiField,
  type PhiProfile,
} from "../domain/claim.js";
import { disclosureFromMetadata } from "./policy.js";
import { addressBytesFromDid, bytesEqual, canonicalHash } from "./crypto.js";
import type { AegisExecutor, AttestationStatus, AuditEvent } from "./executor.js";
import { AuthzDenied, type AegisInvocation, type AegisReceipt } from "./wire.js";

interface ParsedCredential {
  user_did: string;
  org_did: string;
  contract: string;
  functions: string[];
  scopes: string[];
  metadata: Record<string, string>;
  not_before_secs: bigint;
  not_after_secs: bigint;
  agent_pubkey: Uint8Array;
  vc_id: Uint8Array;
  vc_id_hex: string;
}

function parseCredential(jcs: Uint8Array): ParsedCredential {
  const obj = JSON.parse(new TextDecoder().decode(jcs)) as Record<string, unknown>;
  const vc = b64uDecodeStrict(obj.vc_id as string);
  return {
    user_did: obj.user_did as string,
    org_did: obj.org_did as string,
    contract: obj.contract as string,
    functions: obj.functions as string[],
    scopes: obj.scopes as string[],
    metadata: (obj.metadata as Record<string, string>) ?? {},
    not_before_secs: BigInt(obj.not_before_secs as string),
    not_after_secs: BigInt(obj.not_after_secs as string),
    agent_pubkey: b64uDecodeStrict(obj.agent_pubkey as string),
    vc_id: vc,
    vc_id_hex: bytesToHex(vc),
  };
}

export class MockTeeNode implements AegisExecutor {
  private readonly vault = new Map<string, PhiProfile>();
  private readonly revokedCredentials = new Set<string>();
  private readonly revokedFunctions = new Map<string, Set<string>>();
  private readonly usedNonces = new Set<string>();
  private readonly auditLog: AuditEvent[] = [];
  private downstreamSeq = 0;

  /** Override "now" (seconds) for deterministic tests. */
  nowSecs: () => number = () => Math.floor(Date.now() / 1000);

  /** Seed a patient's PHI into the vault (this only ever lives in the TEE). */
  seedProfile(patientDid: string, profile: PhiProfile): void {
    this.vault.set(patientDid, profile);
  }

  /** Patient revokes the whole credential (or specific functions). */
  revoke(vcIdHex: string, functions?: string[]): void {
    if (!functions || functions.length === 0) {
      this.revokedCredentials.add(vcIdHex);
      return;
    }
    const set = this.revokedFunctions.get(vcIdHex) ?? new Set<string>();
    functions.forEach((f) => set.add(f));
    this.revokedFunctions.set(vcIdHex, set);
  }

  async attestation(): Promise<AttestationStatus> {
    return {
      attested: false,
      kind: "mock-simulator",
      detail: "in-memory simulator — no real TEE; use AEGIS_MODE=live for TDX attestation",
    };
  }

  async audit(piiDid?: string): Promise<AuditEvent[]> {
    const events = piiDid ? this.auditLog.filter((e) => e.subject === piiDid) : this.auditLog;
    return events.slice().reverse(); // newest first, matching the live API
  }

  async execute(inv: AegisInvocation): Promise<AegisReceipt> {
    const { envelope, request } = inv;
    const cred = parseCredential(envelope.credential_jcs);

    // 1. Patient actually signed this credential.
    const recovered = ethRecoverEip191(envelope.credential_jcs, envelope.user_sig);
    if (!bytesEqual(recovered, addressBytesFromDid(cred.user_did))) {
      throw new AuthzDenied("bad_user_sig", "credential signature does not match user_did");
    }

    // 2. Agent signature binds this exact request under the bound key.
    const preimage = buildInvocationPreimage(cred.vc_id, envelope.nonce, envelope.request_hash);
    if (!secp256k1.verify(envelope.agent_sig, preimage, cred.agent_pubkey)) {
      throw new AuthzDenied("bad_agent_sig", "agent signature invalid for bound agent_pubkey");
    }

    // 3. Request was not altered after signing.
    if (!bytesEqual(canonicalHash(request), envelope.request_hash)) {
      throw new AuthzDenied("request_tampered", "request_hash does not match the request body");
    }

    // 4. Replay protection.
    const nonceHex = bytesToHex(envelope.nonce);
    if (this.usedNonces.has(nonceHex)) {
      throw new AuthzDenied("nonce_replayed", "nonce already used");
    }

    // 5. Validity window.
    const now = BigInt(this.nowSecs());
    if (now < cred.not_before_secs || now > cred.not_after_secs) {
      throw new AuthzDenied("expired", "outside the credential validity window");
    }

    // 6. Revocation.
    if (this.revokedCredentials.has(cred.vc_id_hex)) {
      throw new AuthzDenied("revoked", "credential has been revoked");
    }
    if (this.revokedFunctions.get(cred.vc_id_hex)?.has(request.function)) {
      throw new AuthzDenied("revoked", `function ${request.function} revoked on this credential`);
    }

    // 7. Function authorization.
    if (!cred.functions.includes(request.function)) {
      throw new AuthzDenied(
        "function_not_authorized",
        `function ${request.function} not in credential`,
      );
    }

    // From here the request is authentic and authorized — commit the nonce.
    this.usedNonces.add(nonceHex);

    try {
      const receipt = this.runFunction(cred, request);
      this.stamp(cred, request, "success", receipt.downstream_ref);
      return receipt;
    } catch (err) {
      const reason = err instanceof AuthzDenied ? err.code : "error";
      this.stamp(cred, request, `denied:${reason}`);
      throw err;
    }
  }

  private runFunction(cred: ParsedCredential, request: AegisInvocation["request"]): AegisReceipt {
    const profile = this.vault.get(cred.user_did);
    if (!profile) throw new Error(`no PHI vault entry for ${cred.user_did}`);

    const counterparty: Counterparty =
      request.counterparty ?? (request.function === "execute-reimbursement" ? "bank" : "insurer");

    // 8. Reimbursement guardrails (action-layer, not agent self-restraint).
    if (request.function === "execute-reimbursement") {
      const allowed = (cred.metadata.allowed_payees ?? "").split(",").map((s) => s.trim());
      if (!request.payee_id || !allowed.includes(request.payee_id)) {
        throw new AuthzDenied("payee_not_allowed", `payee ${request.payee_id} not on allowlist`);
      }
      const cap = Number(cred.metadata.max_reimbursement_cents ?? "0");
      if ((request.amount_cents ?? 0) > cap) {
        throw new AuthzDenied(
          "cap_exceeded",
          `amount ${request.amount_cents} exceeds cap ${cap}`,
        );
      }
    }

    // 9. Selective disclosure — enforce on the ACTUAL placeholders in the body,
    //    not on the agent's self-declared `disclose` field.
    const requested = referencedPhiFields(request.body);
    const permitted = new Set<PhiField>(disclosureFromMetadata(cred.metadata, counterparty));
    const overreach = requested.filter((f) => !permitted.has(f));
    if (overreach.length > 0) {
      throw new AuthzDenied(
        "disclosure_not_allowed",
        `${counterparty} not permitted PHI fields: ${overreach.join(", ")}`,
      );
    }

    // Resolve placeholders INSIDE the TEE and hand off to the downstream API.
    const resolvedBody = this.resolvePlaceholders(request.body, profile, permitted);
    const downstreamRef = this.callDownstream(counterparty, resolvedBody);

    const receipt: AegisReceipt = {
      ok: true,
      function: request.function,
      claim_id: request.claim_id,
      disclosed_fields: requested,
      downstream_ref: downstreamRef,
      audit_id: `audit_${this.auditLog.length + 1}`,
    };
    if (request.function === "execute-reimbursement") {
      receipt.payee_id = request.payee_id;
      receipt.amount_cents = request.amount_cents;
    }
    return receipt;
  }

  /** Substitute `{{profile.*}}` placeholders for permitted fields only. */
  private resolvePlaceholders(
    value: unknown,
    profile: PhiProfile,
    permitted: Set<PhiField>,
  ): unknown {
    const sub = (v: unknown): unknown => {
      if (typeof v === "string") {
        const exact = v.match(/^\{\{\s*profile\.([a-z_]+)\s*\}\}$/);
        if (exact) {
          const field = exact[1] as PhiField;
          if (permitted.has(field) && (ALL_PHI_FIELDS as readonly string[]).includes(field)) {
            return profile[field];
          }
          return v;
        }
        return v.replace(/\{\{\s*profile\.([a-z_]+)\s*\}\}/g, (m, f: string) => {
          const field = f as PhiField;
          if (permitted.has(field) && (ALL_PHI_FIELDS as readonly string[]).includes(field)) {
            const raw = profile[field];
            return Array.isArray(raw) ? raw.join(",") : String(raw);
          }
          return m;
        });
      }
      if (Array.isArray(v)) return v.map(sub);
      if (v && typeof v === "object") {
        return Object.fromEntries(Object.entries(v).map(([k, val]) => [k, sub(val)]));
      }
      return v;
    };
    return sub(value);
  }

  /** Simulated downstream API (insurer / pharmacy / bank). */
  private callDownstream(counterparty: Counterparty, _resolvedBody: unknown): string {
    this.downstreamSeq += 1;
    const prefix = counterparty === "insurer" ? "CLAIM" : counterparty === "pharmacy" ? "RX" : "PAY";
    return `${prefix}-${String(this.downstreamSeq).padStart(6, "0")}`;
  }

  private stamp(
    cred: ParsedCredential,
    request: AegisInvocation["request"],
    outcome: string,
    downstreamRef?: string,
  ): void {
    const event: AuditEvent = {
      ts_ms: this.nowSecs() * 1000,
      subject: cred.user_did,
      actor: `agent:${bytesToHex(cred.agent_pubkey).slice(0, 16)}`,
      vc_id: cred.vc_id_hex,
      action: request.function,
      target: `claim:${request.claim_id}`,
      outcome,
      details: downstreamRef ? `ref=${downstreamRef}` : null,
    };
    this.auditLog.push(event);
  }
}
