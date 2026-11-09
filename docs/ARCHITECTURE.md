# Architecture

## Data flow

```
Analyst request + scope form
        │
        ▼
 scope.Guard.New  ── rejects bad scope (no authorisation ref, public IPs in lab-only mode, wildcards, huge CIDR)
        │
        ▼
 agent.Start ── every host in the form AND every IP/URL mentioned in free text → guard.Check
        │                                   (refusals audited + listed under limitations)
        ▼
 ┌────────────── round loop (max 4) ────────────────────────────────────────────┐
 │ planRound: LLM (strict JSON) or rules planner  ──►  addStep                  │
 │            unknown tool / metasploit-from-model / out-of-scope target        │
 │            / duplicate ► blocked or skipped, with reason                     │
 │ analyst approves the plan (or auto-approve for in-scope scans)               │
 │ runStep: guard re-check ► adapter.Run (timeout, 1 retry on transient error)  │
 │          raw output saved + SHA-256 ► evidence items E-xxxx                  │
 │          out-of-scope hosts in imports discarded                             │
 │ recompute: correlate.Run ► risk.Score (all in code)                          │
 │ replan from what was *observed* (new open web port ► webcheck/nikto/zap)     │
 └──────────────────────────────────────────────────────────────────────────────┘
        │
        ▼
 analyse: model writes impact inferences + summary (or rules do) ► grounding gate
        │
        ▼
 Human review ► optional validation request ► approval (name, reason, retyped target)
        │                                         ► msfconsole `check` only ► outcome recorded
        ▼
 report.Build ► PDF sections 7.1–7.6 + integration matrix + evidence index + audit trace
```

Every arrow that changes state also appends to the audit chain (`internal/audit`): `entry.hash = SHA-256(entry without hash, including prev_hash)`. `Verify` detects edits, deletions and reordering; the console and PDF show the chain status and head hash.

## Components

| Component | Responsibility | Trust |
|---|---|---|
| `scope` | Allow/deny every action; the only authority on what may run | Deterministic code |
| `adapters` | Run tools, parse output into `Service` and `RawFinding`, keep verbatim excerpts and raw references | Parsers treat tool output as data; XML decoding does not resolve external entities |
| `correlate` | Identity (`NormalizeKey`, CVE overlap) ► merge keeping all assets/evidence ► confidence ► triage | Deterministic |
| `risk` | Score from CVSS or nominal severity, exposure, tool-reported exploitability, analyst criticality, confidence; factors recorded | Deterministic |
| `agent` | State machine, planner, approvals, chat explanations | Orchestrates; never trusts model output |
| `llm` | Anthropic, any OpenAI-compatible server, Ollama, or none | Untrusted proposer; chat answers are verified against stored state before use |
| `report` / `pdf` | Evidence-cited PDF; separate OBSERVED and AI INFERENCE labels | Deterministic |

## Confidence model

Each raw finding has a basis: `direct` (condition observed by our own probe, base 0.90), `tool-reported` (0.60), `version-inferred` (0.50). A tool's own confidence (ZAP, Burp, OpenVAS QoD) is averaged with the base. Independent tool reports combine as `1 − Π(1 − cᵢ)`, capped at 0.97. `confirmed` requires direct observation (or an approved validation that returned *vulnerable*); everything else is `suspected`.

Triage rules (all explained in the finding's notes): contradicted by our own probe (port seen closed) ► `likely_false_positive`, confidence ×0.4, risk ×0.3; version-only inference on a distribution-packaged banner ► confidence ×0.7 (back-ported patches); soft-404 detection stops catch-all pages from producing "exposed file" findings; a negative validation lowers confidence but is not treated as proof of absence.

## State and memory

`Assessment` holds the request, scope, steps (with rationale and guard decisions), services, evidence, raw findings, correlated findings, approvals, validations, inferences and limitations. It is the agent's memory across rounds: the planner receives the services observed so far and the signatures of steps already run, which is how it avoids repeated actions and decides what to investigate next.

## Security boundaries

1. The scope guard sits between every proposal and every execution.
2. Offensive validation is a separate action kind that requires scope permission **and** a recorded human approval, and the only implemented method is a module `check`.
3. Subprocesses use argv without a shell; host and module values are validated before use.
4. The console binds to loopback. Every `/api/` call needs a session from KAVACH's own sign-in (`internal/auth`, local accounts, PBKDF2-SHA-256, server-side sessions, roles admin/analyst/viewer), and state-changing calls also need the per-run token, which is only handed to a signed-in session.
5. Identity and scope are separate. `internal/auth` answers who the person is and what role they hold; it is not imported by `internal/scope` and grants no targets. The approver written to the audit chain is the session's account; request bodies cannot name one.
6. Account events (sign-in, failure, lock-out, password and role changes) go to their own hash-chained log under `data/auth/`, which never holds a password or token.
7. Data at rest (`data/<id>/`, `data/auth/`) is owner-only.

## Console and scope dry run

`POST /api/guard-check` asks the scope guard whether targets would be allowed and runs nothing. Without `assessment_id` it validates the scope posted from the form (so a bad scope is rejected before launch) and returns a verdict per target; with `assessment_id` it uses that assessment's guard and appends a `scope_probe` entry to the audit chain. `request` and `probe` are membership checks, so a tool allow-list does not block them; real tool runs are still checked against it.
