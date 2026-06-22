/**
 * Executor factory: returns the right backend for the resolved mode.
 *
 *   mock → in-memory TEE simulator (offline, real crypto checks)
 *   live → real Terminal 3 node (requires T3N_API_KEY)
 *
 * Everything above this line (agent, planners, red-team) is executor-agnostic.
 */
import type { AegisConfig } from "../config.js";
import type { AegisExecutor } from "./executor.js";
import { MockTeeNode } from "./mock-node.js";
import { LiveTeeExecutor } from "./live-node.js";

export function createExecutor(cfg: AegisConfig): AegisExecutor {
  return cfg.mode === "live" ? new LiveTeeExecutor(cfg) : new MockTeeNode();
}
