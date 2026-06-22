/**
 * Deploy the tee:aegis contract: `npm run deploy:contract`
 *
 * 1. Authenticate to the live node.
 * 2. Claim/confirm tenant status (testnet self-admit).
 * 3. Register the compiled WASM contract under `z:<tid>:aegis`.
 *
 * Registering consumes testnet credits on the authenticated account.
 */
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";
import { TenantClient } from "@terminal3/t3n-sdk";
import { loadAegisConfig } from "./config.js";
import { connectT3n } from "./t3/connect.js";

const HERE = dirname(fileURLToPath(import.meta.url));
const WASM_PATH = resolve(
  HERE,
  "../contracts/aegis-claims/target/wasm32-wasip2/release/aegis_claims.wasm",
);
const CONTRACT_TAIL = "aegis";
const CONTRACT_VERSION = "0.1.0";

const log = (s = ""): void => void process.stdout.write(s + "\n");

async function main(): Promise<void> {
  const cfg = loadAegisConfig();
  if (cfg.mode !== "live") throw new Error("Set T3N_API_KEY to deploy (live mode required).");

  log(`\n🚀 Deploying tee:aegis  (env=${cfg.environment})`);
  const { client, did, baseUrl } = await connectT3n(cfg);
  log(`   authenticated as ${did}`);

  const tenant = new TenantClient({
    environment: cfg.environment,
    baseUrl,
    endpoint: baseUrl,
    t3n: client,
    tenantDid: did,
  });

  log("\n1) Claim / confirm tenant status…");
  try {
    const claimed = await tenant.tenant.claim();
    log(`   claim → ${JSON.stringify(claimed)}`);
  } catch (e) {
    log(`   claim skipped/failed (may already be a tenant): ${String(e).split("\n")[0]}`);
  }
  try {
    const me = await tenant.tenant.me();
    log(`   tenant.me → ${JSON.stringify(me)}`);
  } catch (e) {
    log(`   tenant.me unavailable: ${String(e).split("\n")[0]}`);
  }

  log("\n2) Register contract…");
  const wasm = await readFile(WASM_PATH);
  log(`   wasm ${WASM_PATH.split(/[\\/]/).pop()} (${wasm.length} bytes)`);
  const result = await tenant.contracts.register({
    tail: CONTRACT_TAIL,
    version: CONTRACT_VERSION,
    wasm: new Uint8Array(wasm),
  });
  log(`   ✓ registered → ${JSON.stringify(result)}`);
  log(`\n✅ tee:aegis live as z:${did.replace(/^did:t3n:/, "")}:${CONTRACT_TAIL}@${CONTRACT_VERSION}\n`);
}

main().catch((err) => {
  console.error("\n❌ Deploy failed:\n", err);
  process.exit(1);
});
