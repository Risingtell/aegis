/**
 * Red-team CLI: `npm run redteam`
 *
 * Runs every attack scenario against Aegis and prints a verdict. Exits
 * non-zero if ANY defense fails — so this harness is itself the proof that
 * the agent cannot be made to leak PHI or move money it shouldn't.
 */
import { ALL_SCENARIOS, type ScenarioResult } from "./scenarios.js";

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  cyan: "\x1b[36m",
  yellow: "\x1b[33m",
};

function line(s = ""): void {
  process.stdout.write(s + "\n");
}

async function main(): Promise<void> {
  line();
  line(`${C.bold}${C.cyan}🛡  Aegis Red-Team Harness${C.reset}`);
  line(`${C.dim}Reproducing the agent-security incidents Terminal 3 cites — and defeating them.${C.reset}`);
  line();

  const results: ScenarioResult[] = [];
  for (const scenario of ALL_SCENARIOS) {
    const r = await scenario();
    results.push(r);

    const badge = r.passed ? `${C.green}✓ DEFENDED${C.reset}` : `${C.red}✗ BREACH${C.reset}`;
    line(`${C.bold}[${r.id}] ${r.title}${C.reset}  ${badge}`);
    line(`   ${C.dim}real-world incident:${C.reset} ${r.incident}`);
    line(`   ${C.yellow}attack:${C.reset} ${r.attempt}`);
    for (const e of r.evidence) line(`   ${C.dim}·${C.reset} ${e}`);
    line();
  }

  const passed = results.filter((r) => r.passed).length;
  const total = results.length;
  const allPass = passed === total;
  line(
    `${C.bold}Result: ${allPass ? C.green : C.red}${passed}/${total} attacks defended${C.reset}`,
  );
  line();
  if (!allPass) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
