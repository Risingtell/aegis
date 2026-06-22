/**
 * Agent Auth: issuing a delegation credential.
 *
 * The patient compiles an {@link AegisPolicy} into a Terminal 3 delegation
 * credential and signs it with their own key (EIP-191 over the RFC 8785 JCS
 * encoding). The result authorizes a SPECIFIC agent public key to invoke a
 * bounded set of functions, within a validity window, under explicit
 * spend/disclosure constraints. The patient can revoke it at any time.
 *
 * We build and canonicalize using the SDK's own functions so the bytes the
 * patient signs are identical to what the live TEE verifies.
 */
import {
  buildDelegationCredential,
  canonicaliseCredential,
  signCredential,
  type DelegationCredential,
} from "@terminal3/t3n-sdk";
import type { EthIdentity } from "./identity.js";
import { AEGIS_CONTRACT, AEGIS_SCOPE, policyMetadata, type AegisPolicy } from "./policy.js";
import { randomBytes, secretBytesFromPrivateKey } from "./crypto.js";

export interface SignedDelegation {
  credential: DelegationCredential;
  /** RFC 8785 JCS bytes of the credential, exactly as signed. */
  credentialJcs: Uint8Array;
  /** 65-byte EIP-191 signature by the patient. */
  userSig: Uint8Array;
  /** Hex of the credential id, for revocation bookkeeping. */
  vcIdHex: string;
}

export function issueDelegation(opts: {
  patient: EthIdentity;
  /** The clinic / organisation the claim belongs to. */
  orgDid: string;
  /** The agent's 33-byte compressed public key. */
  agentPubkey: Uint8Array;
  policy: AegisPolicy;
  /** Override issuance time (seconds) — used by tests for expiry cases. */
  nowSecs?: number;
}): SignedDelegation {
  const now = opts.nowSecs ?? Math.floor(Date.now() / 1000);
  const vcId = randomBytes(16);

  const credential = buildDelegationCredential({
    user_did: opts.patient.did,
    agent_pubkey: opts.agentPubkey,
    org_did: opts.orgDid,
    contract: AEGIS_CONTRACT,
    functions: opts.policy.functions,
    scopes: [AEGIS_SCOPE],
    metadata: policyMetadata(opts.policy),
    not_before_secs: now,
    not_after_secs: now + opts.policy.ttlSecs,
    vc_id: vcId,
  });

  const credentialJcs = canonicaliseCredential(credential);
  const { sig } = signCredential(credentialJcs, secretBytesFromPrivateKey(opts.patient.privateKey));

  return {
    credential,
    credentialJcs,
    userSig: sig,
    vcIdHex: Buffer.from(vcId).toString("hex"),
  };
}
