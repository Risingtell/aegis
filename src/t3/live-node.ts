/**
 * Live executor: talks to a real Terminal 3 (T3N) node.
 *
 * Identity, attestation, and audit run against the documented, stable SDK
 * surface. The `execute` path dispatches the delegated invocation to the
 * `tee:aegis` TEE contract — registering that contract on testnet
 * (`TenantClient.contracts.register` + `becomeDevTenant`) is the remaining
 * step before end-to-end live runs; until it is deployed, `execute` surfaces
 * a clear, typed error rather than pretending to succeed.
 *
 * The agent and the entire red-team suite are executor-agnostic, so they run
 * unchanged against this backend once a key + contract are in place.
 */
import {
  T3nClient,
  eth_get_address,
  fetchDkgAttestation,
  fetchMlKemPublicKey,
  verifyDkgAttestation,
  getScriptVersion,
  b64uEncodeBytes,
  NODE_URLS,
} from "@terminal3/t3n-sdk";
import type { AegisExecutor, AttestationStatus, AuditEvent } from "./executor.js";
import { AuthzDenied, type AegisInvocation, type AegisReceipt } from "./wire.js";
import type { AegisConfig } from "../config.js";
import { connectT3n } from "./connect.js";

const AEGIS_SCRIPT_TAIL = "aegis";

export class LiveTeeExecutor implements AegisExecutor {
  private readonly baseUrl: string;
  private readonly address: string;
  private clientPromise?: Promise<T3nClient>;
  /** The opaque, node-assigned DID for this account (set after auth). */
  private authDid?: string;

  constructor(private readonly cfg: AegisConfig) {
    this.baseUrl = cfg.nodeUrl ?? NODE_URLS[cfg.environment];
    this.address = eth_get_address(cfg.apiKey);
  }

  private async client(): Promise<T3nClient> {
    if (!this.clientPromise) {
      this.clientPromise = (async () => {
        // The node assigns an opaque DID — capture it; never derive from the
        // address (the address-hex DID is NOT the account's real DID).
        const conn = await connectT3n(this.cfg);
        this.authDid = conn.did;
        return conn.client;
      })();
    }
    return this.clientPromise;
  }

  /** Ensure authenticated and return this account's node-assigned DID. */
  async whoami(): Promise<string> {
    await this.client();
    return this.authDid!;
  }

  async attestation(): Promise<AttestationStatus> {
    try {
      const [encapsKey, bundle] = await Promise.all([
        fetchMlKemPublicKey(this.baseUrl),
        fetchDkgAttestation(this.baseUrl),
      ]);
      if (!bundle) {
        return { attested: false, kind: "live-tdx", detail: "node published no attestation bundle" };
      }
      const res = await verifyDkgAttestation(
        encapsKey,
        bundle.attestation_msg,
        bundle.peer_ids,
        bundle.quotes,
      );
      const detail = res.valid
        ? `TDX verified: ${res.valid_count}/${res.expected_count} nodes`
        : (res.error ?? "attestation verification failed");
      return { attested: res.valid, kind: "live-tdx", detail };
    } catch (err) {
      return { attested: false, kind: "live-tdx", detail: `attestation error: ${String(err)}` };
    }
  }

  async audit(piiDid?: string): Promise<AuditEvent[]> {
    const c = await this.client();
    const page = await c.getAuditEvents(piiDid ? { pii_did: piiDid } : {});
    return page.batches.flatMap((b) => b.events as AuditEvent[]);
  }

  async execute(inv: AegisInvocation): Promise<AegisReceipt> {
    const c = await this.client();
    const scriptName = `tee:${AEGIS_SCRIPT_TAIL}`;
    let version: string;
    try {
      version = await getScriptVersion(this.baseUrl, scriptName);
    } catch {
      throw new AuthzDenied(
        "function_not_authorized",
        `${scriptName} is not registered on ${this.cfg.environment}. ` +
          "Deploy the tee:aegis contract (TenantClient.contracts.register) first.",
      );
    }

    const payload = {
      script_name: scriptName,
      script_version: version,
      function_name: inv.request.function,
      input: {
        envelope: {
          credential_jcs: b64uEncodeBytes(inv.envelope.credential_jcs),
          user_sig: b64uEncodeBytes(inv.envelope.user_sig),
          agent_sig: b64uEncodeBytes(inv.envelope.agent_sig),
          nonce: b64uEncodeBytes(inv.envelope.nonce),
          request_hash: b64uEncodeBytes(inv.envelope.request_hash),
        },
        request: inv.request,
      },
    };
    return c.executeAndDecode<AegisReceipt>(payload);
  }
}
