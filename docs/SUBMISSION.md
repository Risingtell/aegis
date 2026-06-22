# Aegis — Submission writeup

**Challenge:** Terminal 3 Agent Dev Kit Bounty Challenge
**Track:** Best Agent utilising the Terminal 3 Agent Auth SDK

---

## One line

Aegis is an autonomous healthcare claims & reimbursement agent that handles
PHI and moves money on a patient's behalf, yet is mathematically incapable of
leaking data or paying the wrong party — and we prove it by attacking it.

## The problem

AI agents are being given direct custody of secrets, payment rails, and PII.
Terminal 3's manifesto documents the consequences: **EchoLeak** (data
exfiltrated via a poisoned email), the **Replit agent** that deleted a
production database, **prompt-injected browser agents**, **poisoned GitHub
issues**. The shared root cause is the absence of *verifiable identity, scoped
permissions, and tamper-resistant audit at the action layer*.

Healthcare makes the stakes concrete: a claims agent must read maximally
sensitive PHI **and** trigger real reimbursements. Get it wrong and you leak a
patient's medical history or wire their money to an attacker.

## The solution

Aegis never holds the dangerous things. It operates entirely through Terminal
3 Agent Auth:

1. **The patient signs a delegation credential** that scopes exactly what the
   agent may do: which *functions*, which *payee* (allowlist), a *spend cap*, a
   *per-counterparty PHI disclosure* policy, and a *validity window*.
2. **The agent composes every outbound request with `{{profile.*}}`
   placeholders** — never plaintext PHI — and signs each call with a key bound
   into the credential (fresh nonce + hash of the exact request).
3. **The TEE verifies and enforces everything** before acting: both signatures,
   the request hash (anti-tamper), the nonce (anti-replay), the validity
   window, revocation, the function scope, the payee allowlist, the spend cap,
   and selective disclosure. Only then does it resolve placeholders *inside the
   enclave* and call the downstream insurer / bank.
4. **Every action is host-stamped into a tamper-evident audit trail**, and the
   patient can **revoke instantly**.

## What makes it win: we attack our own agent

Security is the heaviest-weighted judging criterion, so we don't assert it — we
*demonstrate* it. `npm run redteam` reproduces the exact incidents above and
proves each is defeated. The harness exits non-zero if any defense fails, so it
is a continuously-verified security claim, not a slide.

| # | Real-world incident | Attack against Aegis | TEE verdict |
|---|---|---|---|
| A1 | EchoLeak | Poisoned claim note rewrites the payee | `payee_not_allowed` |
| A2 | Replit runaway | Note inflates reimbursement to $999,999 | `cap_exceeded` |
| A3 | Prompt-injection exfil | Note tells agent to attach the SSN | no plaintext on wire **and** `disclosure_not_allowed` |
| A4 | MITM / poisoned tool call | Request edited after signing | `request_tampered` |
| A5 | Replay | Re-submit a captured invocation | `nonce_replayed` |
| A6 | Standing-grant abuse | Agent keeps acting after revocation | `revoked` |
| A7 | Leaked credential | Use credential with a different key | `bad_agent_sig` |

Crucially in A1/A2/A3 the **agent is fully compromised** — it *obeys* the
injected instructions — and the attack still fails, because authority lives at
the action layer, not in the agent's behaviour. (See `CompromisedPlanner`.)

## How it maps to the rubric

- **Stability & security (40%)** — All guarantees are enforced by real
  signature verification (EIP-191 recovery + secp256k1) in the executor, shared
  byte-for-byte with the live node via the SDK's own primitives. 17 unit tests
  cover every denial path; the red-team harness is wired into CI. Live mode
  verifies the node's Intel TDX attestation before trusting it with PHI.
- **Problem significance (30%)** — Agentic PHI handling + payments is a real,
  regulated, enterprise-scale problem squarely in Terminal 3's partner network
  (health, banks, government).
- **Creativity of SDK use (30%)** — We use the *full* Agent Auth surface
  (delegation credentials, per-call agent signatures, revocation, selective
  disclosure, placeholders, TDX attestation, host-stamped audit) and turn the
  security model into an executable adversarial proof — a novel way to evidence
  an agent's safety.

## Architecture & code

See [`../README.md`](../README.md) for the diagram, the file map, and run
instructions. Two interchangeable executors (live T3N node / offline simulator)
implement one interface, so the agent and the entire red-team suite run
identically with or without credentials.

## Status & roadmap

- ✅ Agent, delegation flow, selective disclosure, audit, revocation — working.
- ✅ Offline TEE simulator with real cryptographic verification.
- ✅ 7-attack red-team harness + 17 unit tests, all green.
- ✅ **Live on Terminal 3 testnet** — session auth + **Intel TDX attestation
  verified across 3/3 enclave nodes** (`npm run live:check`).
- ✅ **Custom Rust `tee:aegis` contract compiled and REGISTERED on testnet**
  (`z:6e3ed584…:aegis@0.1.0`, contract_id 436) via
  `TenantClient.contracts.register`. It templates PHI as `{{profile.*}}`
  placeholders and disburses via Stripe test mode — PHI never enters WASM.
- ⏭ Full live execute (claim → reimbursement) needs three operator steps on
  the tenant account: seed the `secrets` KV map (insurer + Stripe keys),
  populate a patient PHI profile, and set the agent-auth grant + Stripe egress
  allowlist. The contract is deployed and ready; these are configuration.
