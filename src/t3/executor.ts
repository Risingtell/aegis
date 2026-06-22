/**
 * The boundary between the agent and the TEE.
 *
 * Both the live Terminal 3 node and the offline mock implement
 * {@link AegisExecutor}. The agent only ever sees this interface, so the
 * exact same agent code + red-team harness run against either backend.
 */
import type { AegisInvocation, AegisReceipt } from "./wire.js";

/**
 * Host-stamped audit event. Mirrors the live `audit.get-mine` wire shape
 * (the SDK ships the same fields but does not export the type). On a
 * delegated call `actor` is the agent and `vc_id` is the delegation
 * credential; the host stamps `subject`/`actor` so a contract can never
 * forge who acted or on whom.
 */
export interface AuditEvent {
  ts_ms: number;
  subject: string;
  actor: string;
  vc_id?: string | null;
  action: string;
  target: string;
  outcome: string;
  details?: string | null;
}

export interface AttestationStatus {
  /** Whether the executor proved it runs in a genuine TEE. */
  attested: boolean;
  /** Backend kind for display. */
  kind: "live-tdx" | "mock-simulator";
  /** Human-readable detail (e.g. RTMR3 measurement, or "simulator"). */
  detail: string;
}

export interface AegisExecutor {
  /** Verify and (if authorized) execute a delegated action. */
  execute(inv: AegisInvocation): Promise<AegisReceipt>;
  /** Read the host-stamped, tamper-evident audit trail for a patient. */
  audit(piiDid?: string): Promise<AuditEvent[]>;
  /** Remote-attestation status of this executor. */
  attestation(): Promise<AttestationStatus>;
}
