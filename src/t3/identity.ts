/**
 * Identity primitives for Aegis.
 *
 * Two kinds of identity participate:
 *
 *   - Principals (patient, clinic/org, the agent's own account): ETH-keyed
 *     Terminal 3 accounts. Their DID is `did:t3n:<40-hex>` derived from the
 *     20-byte ETH address. We reuse the SDK's own derivation so our DIDs
 *     match what the node computes.
 *
 *   - The agent's per-delegation signing key: a fresh secp256k1 keypair the
 *     agent uses to sign each invocation. Its 33-byte compressed public key
 *     is bound into the delegation credential, so only the holder of the
 *     matching secret can produce valid per-call signatures.
 */
import { secp256k1 } from "@noble/curves/secp256k1.js";
import { hexToBytes } from "@noble/hashes/utils.js";
import { compactDidFromBytes, eth_get_address } from "@terminal3/t3n-sdk";

export interface AgentSigningKey {
  /** 32-byte secp256k1 secret. Never leaves the agent process. */
  secret: Uint8Array;
  /** 33-byte compressed secp256k1 public key, bound into the credential. */
  pubkey: Uint8Array;
}

export interface EthIdentity {
  /** 0x-prefixed lowercase ETH private key. */
  privateKey: string;
  /** 0x-prefixed lowercase ETH address. */
  address: string;
  /** `did:t3n:<40-hex>`. */
  did: string;
}

/** Derive the 0x ETH address for a private key (delegates to the SDK). */
export function ethAddress(privateKey: string): string {
  return eth_get_address(privateKey);
}

/** Derive `did:t3n:<40-hex>` from a 0x ETH address. */
export function didFromAddress(address: string): string {
  const hex = address.startsWith("0x") ? address.slice(2) : address;
  return compactDidFromBytes(hexToBytes(hex));
}

/** Build a full {privateKey, address, did} identity from a private key. */
export function identityFromKey(privateKey: string): EthIdentity {
  const address = ethAddress(privateKey);
  return { privateKey, address, did: didFromAddress(address) };
}

/** Generate a fresh ETH identity (used for mock principals and tests). */
export function randomEthIdentity(): EthIdentity {
  const sk = secp256k1.utils.randomSecretKey();
  const privateKey = "0x" + Buffer.from(sk).toString("hex");
  return identityFromKey(privateKey);
}

/** Generate a fresh agent signing keypair (secp256k1, compressed pubkey). */
export function generateAgentSigningKey(): AgentSigningKey {
  const secret = secp256k1.utils.randomSecretKey();
  const pubkey = secp256k1.getPublicKey(secret, true);
  return { secret, pubkey };
}
