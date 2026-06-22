import { describe, it, expect } from "vitest";
import { ALL_SCENARIOS } from "../src/redteam/scenarios.js";

describe("Aegis red-team: every cited incident is defeated", () => {
  for (const scenario of ALL_SCENARIOS) {
    it(`defends: ${scenario.name}`, async () => {
      const r = await scenario();
      expect(r.passed, `${r.id} ${r.title}: ${r.evidence.join(" | ")}`).toBe(true);
    });
  }
});
