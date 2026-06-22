/**
 * Agent Auth: building a per-call invocation.
 *
 * For every action, the agent produces a fresh signature over
 * `sha256(DOMAIN || vc_id || nonce || request_hash)`. Because the agent
 * signs the request_hash, the TEE can detect ANY tampering with the request
 * after signing — a man-in-the-middle (or a prompt-injected agent that tries
 * to swap the payee) invalidates the signature. The single-use nonce blocks
 * replay.
 */
import { buildInvocationPreimage, signAgentInvocation } from "@terminal3/t3n-sdk";
import type { AegisInvocation, AegisRequest } from "./wire.js";
import type { SignedDelegation } from "./delegation.js";
import { canonicalHash, randomBytes } from "./crypto.js";

export function buildInvocation(opts: {
  delegation: SignedDelegation;
  request: AegisRequest;
  /** The agent's 32-byte secp256k1 secret. */
  agentSecret: Uint8Array;
  /** Override the nonce — used by the red-team harness to force a replay. */
  nonce?: Uint8Array;
}): AegisInvocation {
  const { delegation, request, agentSecret } = opts;
  const nonce = opts.nonce ?? randomBytes(16);
  const requestHash = canonicalHash(request);
  const vcId = delegation.credential.vc_id;

  const preimage = buildInvocationPreimage(vcId, nonce, requestHash);
  const agentSig = signAgentInvocation(preimage, agentSecret);

  return {
    request,
    envelope: {
      credential_jcs: delegation.credentialJcs,
      user_sig: delegation.userSig,
      agent_sig: agentSig,
      nonce,
      request_hash: requestHash,
    },
  };
}
