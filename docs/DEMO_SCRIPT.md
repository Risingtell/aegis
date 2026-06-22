# Demo video script (~2.5 min)

Record your terminal (and optionally a talking-head intro). Keep it tight.
Every command below is real and already works.

---

### 0:00 — Hook (15s)
> "AI agents today are handed your API keys, your card, your medical records.
> One prompt injection and they leak it or wire your money to an attacker.
> This is Aegis — a healthcare agent that handles PHI and moves real money,
> built on Terminal 3 Agent Auth, and it *cannot* be made to leak or steal.
> Let me prove it."

Show: `brand/cover.png` on screen for 2–3 seconds.

### 0:15 — The happy path (35s)
Run:
```bash
npm run demo
```
Narrate over the output:
> "A patient signs a delegation credential — scoping the functions, a payee
> allowlist, a $500 cap, and which PHI each party may see. The agent files the
> claim and pays the reimbursement… using only `{{placeholders}}`. The PHI is
> resolved inside the TEE — the agent and the LLM never see it. Insurer gets the
> minimum; the SSN is never disclosed. Every step is in a tamper-evident audit
> trail. Then the patient revokes — and the agent goes dark."

### 0:50 — The red team (the moment) (45s)
Run:
```bash
npm run redteam
```
Narrate:
> "Now we attack our own agent with the exact incidents the industry fears.
> EchoLeak — a poisoned claim rewrites the payee. The agent *obeys* — and the
> TEE blocks it: payee not allowed. A Replit-style runaway tries to wire a
> million dollars — cap exceeded. A prompt injection tries to exfiltrate the
> SSN — nothing but a placeholder ever hits the wire, and disclosure is denied.
> Tampering, replay, revocation, a stolen credential — seven attacks, seven
> defenses. The harness fails the build if even one gets through."

Hold on the final line: `Result: 7/7 attacks defended`.

### 1:35 — It's real, on the real TEE (35s)
Run:
```bash
npm run live:check
```
Narrate:
> "And this isn't a simulation. We're on Terminal 3's live testnet. We
> cryptographically verify the Intel TDX attestation across all three enclave
> nodes before we trust it with anything."

Then show the registered contract (from `npm run deploy:contract` output or a
screenshot):
> "Our custom Rust TEE contract is compiled and registered on-chain —
> `tee:aegis`, contract id 436 — resolving PHI placeholders and disbursing via
> Stripe, inside the enclave."

### 2:10 — Close (15s)
> "Aegis: an agent you can give real authority — over money and medical data —
> because the authority lives in the TEE, not in the agent's good behaviour.
> Built on Terminal 3 Agent Auth. Thank you."

Show: repo URL + `brand/logo-512.png`.

---

**Recording tips**
- Use a dark terminal, large font (≥16pt). The output uses color — keep it.
- If a live command hits a transient `fetch failed`, just re-run; the node
  status endpoint is occasionally flaky.
- Total target: 2:00–2:45.
