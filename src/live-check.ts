/**
 * Live connectivity check: `npm run live:check`
 *
 * Proves we can reach a real Terminal 3 node with the claimed key:
 *   1. resolve identity (DID) from the API key
 *   2. handshake + authenticate (exercised by the first audit read)
 *   3. verify the node's Intel TDX attestation
 *   4. read our audit trail
 *
 * Does NOT require the tee:aegis contract to be deployed.
 */
import { loadAegisConfig } from "./config.js";
import { ethAddress } from "./t3/identity.js";
import { LiveTeeExecutor } from "./t3/live-node.js";

const log = (s = ""): void => void process.stdout.write(s + "\n");

async function main(): Promise<void> {
  const cfg = loadAegisConfig();
  if (cfg.mode !== "live") {
    throw new Error("Not in live mode. Set T3N_API_KEY (and AEGIS_MODE=live or auto).");
  }
  log(`\n🔌 Terminal 3 live check  (env=${cfg.environment})`);
  log(`   my address  ${ethAddress(cfg.apiKey)}`);

  const exec = new LiveTeeExecutor(cfg);

  log("\n1) Attestation…");
  const att = await exec.attestation();
  log(`   attested=${att.attested}  kind=${att.kind}`);
  log(`   ${att.detail}\n`);

  log("2) Authenticate + resolve node-assigned DID…");
  const did = await exec.whoami();
  log(`   ✓ authenticated; DID ${did}\n`);

  log("3) Read own audit trail…");
  const audit = await exec.audit(); // no pii_did → own trail (all actors)
  log(`   audit events: ${audit.length}`);
  for (const e of audit.slice(0, 5)) {
    log(`     ${new Date(e.ts_ms).toISOString()}  ${e.action}  ${e.outcome}`);
  }
  log("\n✅ Live node reachable and session authenticated.\n");
}

main().catch((err) => {
  console.error("\n❌ Live check failed:\n", err);
  process.exit(1);
});
