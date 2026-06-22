/**
 * Small crypto helpers shared by the delegation/invocation builders and the
 * TEE verification path. Deliberately thin wrappers over the same primitives
 * the Terminal 3 SDK uses (RFC 8785 JCS canonicalization, SHA-256, secp256k1)
 * so our hashes and signatures verify byte-for-byte against the real node.
 */
import canonicalize from "canonicalize";
import { sha256 } from "@noble/hashes/sha2.js";
import { hexToBytes } from "@noble/hashes/utils.js";

/** Cryptographically secure random bytes. */
export function randomBytes(n: number): Uint8Array {
  const out = new Uint8Array(n);
  globalThis.crypto.getRandomValues(out);
  return out;
}

/** 32-byte secret from a 0x-prefixed ETH private key. */
export function secretBytesFromPrivateKey(privateKey: string): Uint8Array {
  const hex = privateKey.startsWith("0x") ? privateKey.slice(2) : privateKey;
  return hexToBytes(hex.padStart(64, "0"));
}

/** 20-byte ETH address from `did:t3n:<40-hex>`. */
export function addressBytesFromDid(did: string): Uint8Array {
  const hex = did.replace(/^did:t3n:/, "");
  return hexToBytes(hex);
}

/** RFC 8785 (JCS) canonical bytes of an arbitrary JSON value. */
export function canonicalBytes(value: unknown): Uint8Array {
  const s = canonicalize(value);
  if (typeof s !== "string") {
    throw new Error("canonicalize produced no output for value");
  }
  return new TextEncoder().encode(s);
}

/** SHA-256 of bytes. */
export function sha256Bytes(b: Uint8Array): Uint8Array {
  return sha256(b);
}

/** SHA-256 of the canonical JSON encoding of a value. */
export function canonicalHash(value: unknown): Uint8Array {
  return sha256Bytes(canonicalBytes(value));
}

/** Constant-time-ish equality for short byte arrays. */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= (a[i] ?? 0) ^ (b[i] ?? 0);
  return diff === 0;
}
