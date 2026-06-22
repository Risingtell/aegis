# DoraHacks BUIDL — copy-paste submission fields

Paste these into the Terminal 3 Agent Dev Kit Bounty Challenge BUIDL form.

---

**Name:** Aegis

**Logo:** `brand/logo-512.png` (icon) · **Cover:** `brand/cover.png`

**Tagline (one line):**
The healthcare claims & reimbursement agent that moves money and touches PHI — yet cannot be made to leak or steal.

**Track:** Best Agent utilising the Terminal 3 Agent Auth SDK

---

## Short description (≈300 chars)

Aegis is an autonomous agent that files insurance claims and disburses patient
reimbursements — handling PHI and moving real money — without ever holding
plaintext PHI or an unbounded payout. Every action is authorized by a
patient-signed delegation credential and enforced inside the TEE. Then we
attack it: 7/7 real-world agent exploits defeated.

## Full description

**The problem.** AI agents are handed API keys, card numbers, and PII directly.
One prompt injection (EchoLeak), one poisoned document, one rogue tool result,
and the agent exfiltrates secrets or wires money to an attacker. Terminal 3's
manifesto names the root cause: *no verifiable identity, scoped permissions, or
tamper-resistant audit at the action layer.* Healthcare is the worst place for
this and the best place to prove a fix — PHI is maximally sensitive and
reimbursements are real money.

**The solution.** Aegis never holds the dangerous things. The patient signs a
Terminal 3 delegation credential scoping exactly what the agent may do —
functions, a payee allowlist, a spend cap, per-counterparty PHI disclosure, and
a validity window. The agent composes every request with `{{profile.*}}`
placeholders (never plaintext PHI) and signs each call with a key bound into
the credential. The TEE verifies both signatures, the request hash (anti-tamper),
the nonce (anti-replay), the validity window, revocation, the function scope,
the payee allowlist, the spend cap, and selective disclosure — then resolves
placeholders *inside the enclave* and calls the insurer / Stripe. Every action
is host-stamped into a tamper-evident audit trail; the patient can revoke
instantly.

**What makes it win — we attack our own agent.** `npm run redteam` reproduces
the exact incidents Terminal 3 cites and proves each is defeated. In A1–A3 the
agent is *fully compromised* (it obeys the injected instructions) and the attack
still fails, because authority lives at the action layer, not in the agent.

| # | Real incident | Attack | TEE verdict |
|---|---|---|---|
| A1 | EchoLeak | poisoned claim redirects payout | `payee_not_allowed` |
| A2 | Replit runaway | inflate reimbursement to $999,999 | `cap_exceeded` |
| A3 | Prompt-injection exfil | attach the SSN | no plaintext on wire + `disclosure_not_allowed` |
| A4 | MITM | edit request after signing | `request_tampered` |
| A5 | Replay | resubmit captured invocation | `nonce_replayed` |
| A6 | Standing-grant abuse | act after revocation | `revoked` |
| A7 | Leaked credential | use with a different key | `bad_agent_sig` |

## Live on Terminal 3 testnet

- Session auth + **Intel TDX attestation verified across 3/3 enclave nodes**.
- **Custom Rust `tee:aegis` TEE contract compiled and REGISTERED on testnet** —
  `z:6e3ed584…:aegis@0.1.0`, contract_id 436. It templates PHI placeholders and
  disburses via Stripe test mode; PHI never enters WASM.

## How it uses the Agent Auth SDK

`buildDelegationCredential`, `signCredential`, `buildInvocationPreimage`,
`signAgentInvocation`, `canonicaliseCredential`, `ethRecoverEip191`,
`revokeDelegation`, `getAuditEvents`, `verifyDkgAttestation`/`verifyTdxQuote`,
`TenantClient.contracts.register`, plus `http-with-placeholders` inside the
Rust contract.

## How to run (judges)

```bash
npm install
npm run demo       # delegate → claim → reimburse → audit → revoke
npm run redteam    # 7 attacks, all defeated (exits non-zero on any breach)
npm test           # 17 unit tests, real signatures
npm run live:check # live: TDX attestation 3/3 + session auth (needs T3N_API_KEY)
```

## Links

- **Repo:** https://github.com/Risingtell/aegis
- **Website:** <ADD LINK — deploy the `site/` folder (static; e.g. Vercel)>
- **Demo video:** <ADD LINK>
- **Tech writeup:** docs/SUBMISSION.md

## Team

Risingtell (Rising Technology)
