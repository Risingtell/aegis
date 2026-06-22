/**
 * Presenter mode for the demo video: `npm run present`
 *
 * Runs the three showcase commands in order, pausing before each so you can
 * narrate. Just press Enter to advance.
 */
import { spawnSync } from "node:child_process";
import readline from "node:readline";

const dim = (s) => `\x1b[2m${s}\x1b[0m`;
const cyan = (s) => `\x1b[36m${s}\x1b[0m`;

function pause(msg) {
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    rl.question("\n" + dim(msg) + " ", () => {
      rl.close();
      resolve();
    });
  });
}

function run(label, cmd) {
  console.log("\n" + cyan("$ " + label) + "\n");
  spawnSync(cmd, { stdio: "inherit", shell: true });
}

const steps = [
  ["Press Enter to run the happy-path demo (claim, pay, audit, revoke)...", "npm run demo"],
  ["Press Enter to run the 7 red-team attacks...", "npm run redteam"],
  ["Press Enter to run the live Terminal 3 testnet check...", "npm run live:check"],
];

console.clear();
console.log(cyan("Aegis presenter") + dim("  —  press Enter to advance through each step"));
for (const [prompt, cmd] of steps) {
  await pause(prompt);
  run(cmd.replace("npm run ", ""), cmd);
}
console.log("\n" + cyan("Demo complete.") + dim("  Stop the recording here."));
