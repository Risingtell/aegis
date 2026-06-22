/**
 * Runtime configuration for Aegis.
 *
 * Aegis has two execution modes that share identical agent + security logic:
 *
 *   - "live": talks to a real Terminal 3 (T3N) node. Requires T3N_API_KEY
 *     (the ETH private key claimed at https://www.terminal3.io/claim-page).
 *   - "mock": runs against an in-memory simulator of the TEE node
 *     (see src/t3/mock-node.ts) that performs the SAME cryptographic
 *     authorization checks the real node does. Lets the full demo and the
 *     red-team harness run offline with zero credentials.
 *
 * Mode resolution (AEGIS_MODE): "auto" (default) picks live when a key is
 * present, otherwise mock. "live"/"mock" force the respective path.
 */
import { config as loadDotenv } from "dotenv";

loadDotenv();

export type AegisMode = "live" | "mock";
export type T3nEnvironment = "testnet" | "production";

export interface AegisConfig {
  mode: AegisMode;
  environment: T3nEnvironment;
  /** ETH private key used as the Terminal 3 API key. Empty in mock mode. */
  apiKey: string;
  /** Optional explicit node URL override. */
  nodeUrl?: string;
}

function resolveMode(apiKey: string): AegisMode {
  const raw = (process.env.AEGIS_MODE ?? "auto").toLowerCase();
  if (raw === "live") return "live";
  if (raw === "mock") return "mock";
  // auto
  return apiKey ? "live" : "mock";
}

export function loadAegisConfig(): AegisConfig {
  const apiKey = (process.env.T3N_API_KEY ?? "").trim();
  const mode = resolveMode(apiKey);
  const environment = (process.env.T3N_ENV ?? "testnet").toLowerCase() === "production"
    ? "production"
    : "testnet";

  if (mode === "live" && !apiKey) {
    throw new Error(
      "AEGIS_MODE=live but T3N_API_KEY is empty. Claim a key at " +
        "https://www.terminal3.io/claim-page or unset AEGIS_MODE to run in mock mode.",
    );
  }

  const cfg: AegisConfig = { mode, environment, apiKey };
  const nodeUrl = process.env.T3N_NODE_URL?.trim();
  if (nodeUrl) cfg.nodeUrl = nodeUrl;
  return cfg;
}
