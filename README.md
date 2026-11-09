# VAPT Agent: evidence-driven AI assistant for authorised penetration tests

A conversational agent that takes an authorised lab scope and a plain-English request, plans which tools to use and **why**, runs them behind a deny-by-default scope guard, correlates the results into one evidence-backed finding list, and produces a client-ready PDF. A human approves scans and any active validation. Everything is written to a hash-chained audit trail.

Built for the DataOps Innovation Hackathon problem statement *AI Agent for Automated Penetration Testing*. Go standard library only: no third-party modules, no cloud service required.

## Quick start

Requirements: Go 1.22+ (`go version`). Optional: `nmap`, `nikto`, an OWASP ZAP daemon, `msfconsole` (each is detected at runtime; missing ones are reported honestly, never faked).

```powershell
# terminal 1: a deliberately weak LOCAL lab target (binds loopback only)
go run ./cmd/lab

# terminal 2: the analyst console
go run ./cmd/vapt            # http://127.0.0.1:8787
```

Open <http://127.0.0.1:8787>. `/` is the story page, `/console` the chat console, `/workbench` the tiling view. On first run the console asks you to create an account (see *Accounts and sign-in*). The default form is pre-filled for the local lab (`127.0.0.1`; the lab serves web ports 8081, 8000 and 8008 plus fake FTP and Telnet banners on 2121 and 2323). Or run the whole flow headless and regenerate the sample outputs: `bash scripts/demo.sh`.

### Choosing the model (optional)

The planner, the impact-reasoning step and the chat are swappable. With no model configured the agent uses its deterministic rules planner and rules answers, and says so everywhere.

| Setting | Effect |
|---|---|
| `ANTHROPIC_API_KEY` (+ optional `VAPT_MODEL`) | Anthropic Messages API (remote) |
| `VAPT_OPENAI_URL` + `VAPT_MODEL` (+ `VAPT_OPENAI_KEY`) | any OpenAI-compatible server: OpenRouter, Groq, LM Studio, vLLM, llama.cpp... |
| `OLLAMA_MODEL` (+ optional `OLLAMA_URL`) | local model through Ollama |
| none | rules-only mode |

`GET /api/config` reports `data_leaves_machine`: true when the configured model is a remote service (prompts then contain scan evidence), false for loopback servers and rules-only mode. Prefer a local model if scan data must not leave your machine.

**Grounded chat.** The model sees only this assessment's stored data and must cite finding, evidence and step IDs. Code checks every `F-`, `E-`, `S-` ID and every CVE in the reply against the assessment; one that does not exist discards the whole model answer, the rules answer is used, and the rejection is written to the audit log. Scope decisions are made by code, never by the model. The model cannot run tools or approve anything.

**Proof.** `GET /api/assessments/{id}/proof[?finding=F-001]` returns, per finding, the verbatim observed evidence (tool, raw file, raw-file SHA-256), the inferences kept separate from it, an evidence-strength percentage with the steps that produced it, and a list of what the record does *not* establish. The percentage is computed by code from how the condition was observed and how many independent tools agree. It is not a calibrated probability.

Optional tools: `ZAP_URL` (default `http://127.0.0.1:8090`) and `ZAP_API_KEY` for ZAP.

## The console

A tiling-window-manager style terminal UI (Arch-rice look: flat colours, 1px pane borders, JetBrains Mono, a bar with numbered workspaces and a real prompt). It is plain HTML/CSS/JS served from the Go binary, with Three.js vendored locally, so it works offline.

**The surface** (left pane) is a live 3D model of the assessment, driven only by real data:

| In the scene | Means |
|---|---|
| wireframe sphere | the authorised scope boundary (the shield) |
| octahedron nodes | hosts in scope; border colour = worst finding on that host |
| small cubes orbiting a host | real open services (red = cleartext Telnet/FTP, blue = web) |
| shards | findings; colour = severity, size = computed risk, pulsing = P1 |
| travelling dots from the core | a tool is running against that host (yellow dashed = waiting for approval) |
| ring of blocks underneath | the hash-chained audit log, one block per entry; tampering turns it red |
| red crosses outside the shield | targets the scope guard refused |

Hover anything for details. Click a shard to open its evidence (the camera flies to it); click a host to filter findings to it.

**Scope dry run.** While you edit the scope form, every host you list *or merely mention in the request text* is sent to a dry-run of the scope guard (`/api/guard-check`, nothing is sent to any target). Refused targets fly at the shield and bounce off live. After launch, `check <host>` at the prompt does the same through the assessment's guard and writes an audit entry.

**Keys.** `1`-`6` workspaces (scope, plan, findings, approvals, audit, tools), `/` prompt, `j`/`k` move, `Enter` open, `a` approve the waiting plan, `Esc` close. Prompt commands: `help`, `check <target>`, `approve`, `open F-001`, `goto <ws>`, `pdf`, `clear`; anything else goes to the agent ("why S-02?", "explain F-001").

Screenshots: [`docs/screens/`](docs/screens). Browser smoke test (Playwright): `python scripts/ui_smoke.py` against a running console. If WebGL is unavailable the console still works without the 3D pane.

Vendored front-end assets (all offline): Three.js r170 and its OrbitControls (MIT, `cmd/vapt/web/vendor/`), JetBrains Mono (SIL OFL 1.1, `cmd/vapt/web/fonts/`).

## Accounts and sign-in

KAVACH has its own sign-in; no third-party identity service is involved, and nothing leaves the machine.

- **First run.** While no account exists, the console offers "Create your account" (only from the machine itself). That account is the administrator. Scripted runs can set `KAVACH_ADMIN_USER` and `KAVACH_ADMIN_PASSWORD` instead (`scripts/demo.sh` does).
- **Passwords** are stored as salted PBKDF2-HMAC-SHA-256 (600,000 iterations) in `<data>/auth/users.json` (mode 0600). Minimum 10 characters, not the username, not a common word.
- **Sessions** are a random 256-bit token in an HttpOnly, SameSite=Strict cookie. The server keeps only a hash of it, in memory (restarting signs everyone out). 12 hours at most, 2 hours idle. Changing a password ends the account's other sessions.
- **Brute force.** Five wrong passwords for a name pause that name with a growing back-off (15 s doubling up to about 16 minutes). Unknown names are limited identically and return the same error after the same work, so the form does not reveal which names exist. This also means someone can briefly lock out a known name; that is the trade.
- **Roles.** `admin` runs and approves and manages people; `analyst` runs, approves and denies; `viewer` reads, asks the grounded chat questions and dry-runs the scope guard, and cannot run or approve anything.
- **Identity is not scope.** Signing in says who you are. It grants no targets and changes nothing in the scope guard; the scope form is still deny-by-default.
- **Attribution.** The approver recorded in the audit chain is the signed-in account. A name in a request body is ignored. Each assessment records which account opened it, and sign-ins, failures, lock-outs and account changes go to their own hash-chained log (`<data>/auth/auth-audit.jsonl`, admins can view and verify it in the Account dialog). Passwords and tokens are never logged.
- **Lost the only administrator password?** Stop the server, delete `<data>/auth/users.json` and start again to repeat first-run setup. Assessments and their audit logs are untouched.

What this does not do: it is not a multi-tenant service. There is no TLS (keep the console on loopback or put a TLS proxy in front), no email reset, no MFA, and sessions are not shared between machines.

## What the judges can check (live-demo checklist)

| # | Checklist item | Where to see it |
|---|---|---|
| 1 | Authorised target, request, scope validation | Setup form. The default request also names `8.8.8.8`: the guard refuses it, the refusal is audited and listed under Limitations |
| 2 | Plan with tool choices and reasoning | *Plan & runs* tab: every step has rationale, who proposed it, the evidence that triggered it, and the guard's decision |
| 3 | Genuine execution status, traceable output | Step status, duration, SHA-256 of the raw output, link to the raw file |
| 4 | Normalisation, cross-tool correlation, duplicates, false positives, uncertainty | *Findings* tab and drawer: merged assets and evidence, confidence reasoning, triage notes, confirmed / suspected / likely-false-positive |
| 5 | Risk ranking and the approval checkpoint | Risk factor breakdown per finding; *Approvals* tab (name + reason + retyped target) |
| 6 | Download the PDF, trace a finding to raw evidence | **Download PDF report**; evidence IDs `E-xxxx` link to the raw tool output |
| 7 | Safe failure and honest integration status | *Integrations* tab; missing tools show as unavailable and appear in the report's limitations |

A sample report produced by a real run is in [`samples/`](samples): the PDF, the full state JSON, the audit log and the raw tool output it cites.

## Integration status (truthful matrix)

| Tool | Status | How | Notes |
|---|---|---|---|
| Nmap | **Live** | CLI `-sV`, XML parsed | Needs `nmap` on PATH. Not installed in the sandbox the sample ran in |
| Nessus | **Import-only** | `.nessus` v2 file | Commercial product; Essentials is capped at 16 hosts per [Tenable docs](https://docs.tenable.com/nessus/10_10/Content/LicenseUtilization.htm). No live API |
| OpenVAS / Greenbone | **Import-only** | XML report | Live GMP session is *planned*, not implemented |
| Nikto | **Live** | CLI, XML parsed | Needs `nikto` on PATH. Nikto gives no severity, so its items carry a nominal `low` |
| OWASP ZAP | **Live** | REST API | Needs a running ZAP daemon. Active scan only if scope allows it and the request asks |
| Burp Suite | **Import-only** | XML issue export | [PortSwigger](https://portswigger.net/burp/dast/resources/enterprise-edition-vs-professional) documents a REST API for Professional and a GraphQL API for DAST; this project calls neither |
| Metasploit | **Live, approval-gated** | `msfconsole` module **`check` only** | Lab-only; never autonomous; never `exploit`/`run`, never payloads. Needs `msfconsole` |
| (built-in) port scan | Live | Go TCP connect + banner | Fallback recon when Nmap is absent; not one of the seven |
| (built-in) web checks | Live | Go read-only GET | Headers, cookies, banners, exposed `.git`/`.env`, directory listing, soft-404 aware |

**What was actually executed for the sample report:** only the two built-in checkers, because `nmap`, `nikto`, ZAP and Metasploit could not be installed in the development sandbox and no commercial exports were available. The Nmap, Nikto, ZAP and import code paths are covered by parser/unit tests on small fixtures, **not** by real scans. Before the demo, install them (`nmap`, `nikto`, ZAP daemon) and re-run `scripts/demo.sh` for a richer, genuinely multi-tool sample.

## How it keeps the model honest

- The model only **proposes** JSON plan steps. Each step is checked against the tool registry and the scope guard; the guard also re-checks at execution time. Model-proposed Metasploit steps are always blocked: validation is created only by a human.
- Severity, CVSS, CVE and CWE come only from tool output. **Risk scores are computed in code** from CVSS (or a nominal severity value, labelled as such), exposure, tool-reported exploit availability, analyst-set asset criticality and confidence. Every factor and its source is shown.
- Model-written impact statements ("AI inference") must cite evidence IDs belonging to that finding and may not contain a CVE or CVSS number absent from the tool output; otherwise they are rejected and the rejection is audited.
- Observed facts and AI inference are labelled separately in the console and the PDF.
- Text from targets is treated as untrusted data (banners could contain prompt injection): the model has no ability to run anything, and its output cannot widen scope.
- Secrets seen in evidence (`.env` values, cookie values) are redacted at capture.

## Safety and scope controls

Deny by default; targets, exclusions, optional port and tool allow-lists; lab-only addressing (loopback/private ranges, max /16) unless an organiser override is recorded; hostnames must resolve inside scope (blocks DNS rebinding to public IPs); expiry window; per-assessment rate limit; no shell is ever used for subprocesses (argv only, host values validated); imported results for out-of-scope hosts are discarded and logged; console binds loopback and every `/api/` call needs a signed-in session (plus a per-run token for state-changing calls); approvals are recorded under the signed-in account, never a name typed into a request; raw outputs and audit logs are written `0600`.

## Layout

```
cmd/vapt          console + API server (embedded web UI + 3D scene in cmd/vapt/web)
cmd/lab           deliberately weak loopback-only test target
internal/scope    deny-by-default guard, rate limiter
internal/audit    append-only hash-chained log + verifier
internal/adapters tool adapters (live, import-only, gated)
internal/correlate  normalisation, merge, confidence, false-positive triage
internal/risk     code-computed risk scoring
internal/agent    planner (LLM or rules), executor, approvals, analysis
internal/llm      Anthropic / Ollama / none
internal/report   PDF report + integration matrix; internal/pdf = tiny PDF writer
scripts/demo.sh   headless end-to-end run that regenerates samples/
```

Architecture, data flow and state: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md). Tests: `go test ./...` (scope, audit chain tamper detection, correlation and triage rules, parsers incl. XXE, web checks against a local server, planner guardrails, grounding gate, the approval gate end to end).

## Licensing assumptions and provenance

- This repository's code uses only the Go standard library. The tools it can drive keep their own licences: Nmap (NPSL), Nikto (GPL), ZAP (Apache-2.0), Metasploit Framework (BSD-3), OpenVAS/Greenbone (GPL/AGPL components); Nessus and Burp are commercial and only their exports are imported. The user supplies their own licences; nothing is bundled or redistributed.
- Standards referenced (NIST SP 800-115, OWASP Top 10, CVE, CVSS, CWE, MITRE ATT&CK, NIST CSF 2.0) are used for vocabulary only; using them does not establish compliance.
- **Provenance:** all code in this repository was written for this hackathon. If any code, design or assets are copied in from an earlier project, list them here before submitting and check the hackathon's rules on pre-existing work.

## Known limitations

Assessments are held in memory (state is also saved to `data/<id>/state.json`, but a restarted server does not reload them). Tools run sequentially. Built-in checks are shallow by design. ATT&CK and CSF mapping are not yet emitted in the report. Retesting/change comparison is not implemented.
