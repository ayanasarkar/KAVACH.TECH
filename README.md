# 🛡️ Kavach: VAPT Agent
> **Evidence-Driven AI Assistant for Authorised Penetration Testing**

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Stdlib%20Only)-success)](#licensing-assumptions-and-provenance)
[![Hackathon](https://img.shields.io/badge/Hackathon-DataOps%20Innovation-blue)](#about)
[![Team](https://img.shields.io/badge/Team-gh0st__1n__4he__sYstem-orange)](#team--author)

---

================================================================================

KAVACH (vapt-agent)

Evidence-Driven AI Assistant for Authorised Penetration Testing

================================================================================



Hackathon : DataOps Innovation Hackathon 2026 — AI-Powered Unified VAPT Agent

Team      : gh0st_1n_4he_sYstem

Author    : Ayana Sarkar (ayanasarkar31@gmail.com)

Runtime   : Go 1.22+ (100% Standard Library — Zero External Go Dependencies)



--------------------------------------------------------------------------------

1. EXECUTIVE SUMMARY

--------------------------------------------------------------------------------

KAVACH is a conversational, evidence-driven AI penetration testing assistant

built around one architectural rule: the LLM proposes; deterministic code

enforces.



Given an explicitly authorised target scope and a plain-English assessment

request, KAVACH plans adaptive reconnaissance and verification workflows,

enforces a deny-by-default scope guard at both plan time and connection time,

executes or ingests outputs from multiple security tools, correlates and

deduplicates findings with calibrated confidence ratings, records every action

in a SHA-256 hash-chained audit trail, and produces client-ready PDF and

SARIF 2.1.0 reports.



Built strictly with the Go standard library (with Three.js r170 and JetBrains

Mono vendored locally), KAVACH compiles to a single offline-capable binary with

zero third-party Go modules and no mandatory cloud services.



--------------------------------------------------------------------------------

2. KEY CAPABILITIES & FINALE SECURITY GUARANTEES

--------------------------------------------------------------------------------

* Deny-by-Default Scope Guard & DNS Rebinding Protection (internal/scope):

  Enforces authorised IP ranges (max /16 IPv4 for lab safety), exclusions, port

  allow-lists, and explicitly authorised domains. Public domain targets are

  permitted only while resolving to public addresses; private, loopback, and

  link-local resolutions are blocked at plan time and connect time (CheckDial).

  For Nmap subprocesses, KAVACH resolves and validates every DNS answer first

  and pins Nmap directly to the checked IP, failing closed.



* Prompt-Injection Immunity & Grounding Gate (internal/agent, internal/llm):

  Target HTTP headers, banners, and scan outputs are treated as untrusted data.

  The LLM can only propose structured JSON plans and impact narratives; it

  cannot execute commands, pass arbitrary CLI flags (unpermitted arguments are

  stripped and logged as option_dropped), or widen scope. Every F-, E-, S- ID,

  CVE, and CVSS value in model output is checked in code against raw evidence;

  ungrounded responses are rejected and logged to the audit chain.



* Centralized Secret Redaction:

  Credentials, API keys, .env values, and session cookies observed in live

  scans or imported XML reports are redacted centrally (<redacted>) before

  reaching the LLM context, UI, or PDF report, while raw evidence files and

  their SHA-256 hashes remain intact.



* Multi-Tool Correlation & Uncertainty Triage (internal/correlate):

  Normalizes multi-tool findings into a common schema with protocol-safe key

  normalization so distinct services never mis-merge. Merges genuine cross-tool

  duplicates while preserving all affected assets and raw file line references,

  and distinguishes confirmed findings from suspected / low-QoD version matches.

  Out-of-scope hosts inside imported XML files are discarded and logged.



* Deterministic Risk Scoring (internal/risk):

  Severity, CVSS, CVE, and CWE identifiers come exclusively from tool output.

  Risk scores (0-100) and P1-P4 priorities are computed deterministically in

  code from CVSS (or labelled nominal severity), exposure, exploitability,

  analyst-set asset criticality, and confidence weight.



* Human-in-the-Loop Approvals & Local Auth (internal/auth):

  Salted PBKDF2-HMAC-SHA-256 (600,000 iterations) local authentication with

  HttpOnly/SameSite=Strict session cookies, brute-force backoff, and role-based

  access control (admin, analyst, viewer, with admin SetRole support). Every

  plan requires hold-to-approve sign-off attributed to the signed-in account.

  Model-proposed Metasploit steps are always blocked; active validation is

  check-only and requires explicit human initiation and target re-entry.



* Tamper-Evident Audit Trail (internal/audit):

  Append-only SHA-256 hash-chained audit log (mode 0600) with built-in chain

  verification and an interactive tamper demonstration on the landing page.



* Client-Ready PDF & SARIF 2.1.0 Reporting (internal/report, internal/pdf):

  Generates a native Go PDF report covering all six required VAPT sections plus

  honest authorization attestation, Integration Status Matrix (Appendix A),

  Evidence Index (Appendix B), and verified Decision & Audit Trace (Appendix C).

  Includes OWASP Top 10, CVE, CVSS, CWE, MITRE ATT&CK tactic-level, and NIST

  CSF 2.0 category-level alignments. Also exports machine-readable SARIF 2.1.0

  via GET /api/assessments/{id}/report.sarif.



* Embedded Multi-View Interface (cmd/vapt/web):

  - /          : Editorial overview with live Hostile Banner prompt-injection

                 trap and interactive SHA-256 audit-chain tamper verifier.

  - /console   : Conversational analyst workspace with scoped assessment setup,

                 hold-to-approve cards, grounded chat, and PDF/SARIF downloads.

  - /workbench : Arch-rice tiling window manager with a live Three.js 3D scope

                 shield and automatic handoff of the active console assessment.



--------------------------------------------------------------------------------

3. ARCHITECTURE & REPOSITORY LAYOUT

--------------------------------------------------------------------------------

Workflow:

Analyst Request -> LLM / Rules Planner -> Deny-by-Default Scope Guard

-> Human Approval Gate -> IP-Pinned Execution / XML Import -> Secret Redaction

-> Normalization & Correlation -> Deterministic Risk Scoring

-> Grounded Impact Inference -> Unified PDF & SARIF Report + Hash-Chained Audit



Directory Layout:

  cmd/

    vapt/               Main server, REST API, auth handlers, embedded Web UI

    lab/                Deliberately vulnerable loopback-only test target

  internal/

    scope/              Deny-by-default guard, CheckDial, DNS pinning, rate limit

    auth/               PBKDF2 accounts, sessions, RBAC, auth audit chain

    audit/              Append-only SHA-256 hash-chained logger & verifier

    adapters/           Tool adapters (Nmap, Nikto, ZAP, Metasploit, XML imports)

    correlate/          Schema normalization, deduplication, confidence & triage

    risk/               Deterministic risk formula & priority ranking

    agent/              Planner, executor, approval gates, grounding validator

    llm/                OpenAI-compatible, Anthropic, Ollama, and rules drivers

    report/             PDF report builder, SARIF 2.1.0 exporter, framework maps

    pdf/                Zero-dependency native Go PDF writer

  docs/                 Architecture documentation & Render deployment notes

  samples/              Sample PDF/state outputs & synthetic judge-tests/ fixtures

  scripts/              demo.sh (headless end-to-end runner) & ui_smoke.py



--------------------------------------------------------------------------------

4. TRUTHFUL INTEGRATION STATUS MATRIX

--------------------------------------------------------------------------------

Tool                  Status                 Method / Notes

--------------------------------------------------------------------------------

Nmap                  Live                   CLI (-sV, XML parsed, IP-pinned).

                                             Requires nmap on PATH.

Nessus                Import-only            .nessus v2 XML (XXE-hardened).

                                             Commercial; user supplies own export.

OpenVAS / Greenbone   Import-only            Report XML (XXE-hardened).

                                             Live GMP session is planned.

Nikto                 Live                   CLI XML parsed. Requires nikto on

                                             PATH; nominal 'low' severity.

OWASP ZAP             Live                   REST API daemon (ZAP_URL /

                                             ZAP_API_KEY). Active scan gated.

Burp Suite            Import-only            XML issue export (XXE-hardened).

                                             Commercial; never calls paid APIs.

Metasploit            Live (approval-gated)  msfconsole module check only.

                                             Lab-only; never autonomous; never

                                             runs exploit/run or payloads.

Built-in port scan    Live (fallback)        Go TCP connect + banner grab.

                                             NOT one of the seven named tools.

Built-in web checks   Live (fallback)        Go read-only GET (headers, cookies,

                                             .git/.env, soft-404 aware).

                                             NOT one of the seven named tools.



Missing binaries or unreachable daemons are detected at runtime, reported

honestly in the Integrations tab, and listed under Assessment Limitations.



--------------------------------------------------------------------------------

5. QUICK START

--------------------------------------------------------------------------------

Prerequisites:

  - Go 1.22+ (go version)

  - Optional: nmap, nikto, msfconsole on PATH, or a running OWASP ZAP daemon



Step 1 — Start the local loopback-only lab target (Terminal 1):

  go run ./cmd/lab

  (Binds 127.0.0.1 only: HTTP ports 8081, 8000, 8008; mock banners 2121, 2323)



Step 2 — Configure an LLM backend (optional) and start KAVACH (Terminal 2):



  Windows PowerShell (OpenAI-compatible, e.g. Groq):

    $env:VAPT_OPENAI_URL = "https://api.groq.com/openai/v1"

    $env:VAPT_OPENAI_KEY = "your_api_key"

    $env:VAPT_MODEL      = "openai/gpt-oss-120b"

    go run ./cmd/vapt



  Linux / macOS (Anthropic or Local Ollama):

    export ANTHROPIC_API_KEY="your_api_key"

    # or for 100% air-gapped local inference:

    export OLLAMA_MODEL="llama3"

    go run ./cmd/vapt



  Offline Rules-Only Mode:

    Run `go run ./cmd/vapt` with no model environment variables set.

    GET /api/config reports data_leaves_machine: true for remote LLMs and

    false for loopback/Ollama or rules-only mode.



Step 3 — Open the Console:

  Visit http://127.0.0.1:8787

  First run prompts you to create the initial administrator account locally.



--------------------------------------------------------------------------------

6. TESTING & SYNTHETIC JUDGE FIXTURES

--------------------------------------------------------------------------------

Run the full Go test suite (scope guard, DNS pinning, tamper verification,

cross-protocol correlation, redaction, XXE protection, grounding, approvals):

  go test ./...



Synthetic Multi-Tool Test Fixtures (samples/judge-tests/):

  To verify multi-tool ingestion, cross-tool correlation, out-of-scope import

  discarding, secret redaction, uncertainty triage, and safe XML error handling

  without commercial licenses, KAVACH includes synthetic test fixtures clearly

  labelled as synthetic (never presented as real scans):

    - judge_test_nessus.nessus    (multi-tool merge, secret redaction, 8.8.8.8 drop)

    - judge_test_burp.xml         (tentative XSS triage, cookie redaction, OOS drop)

    - judge_test_openvas.xml      (Telnet merge, low-QoD FTP suspected, OOS drop)

    - judge_test_hostile_xxe.xml  (XXE safe-failure test; run in its own scan)

    - JUDGE_TEST_MANIFEST.txt     (expected verification outcomes)



--------------------------------------------------------------------------------

7. KNOWN LIMITATIONS & HONEST BOUNDARIES

--------------------------------------------------------------------------------

* Sequential Execution: Planned scan steps execute sequentially per round.

* Local Host Dependencies: Nikto, OWASP ZAP, and Metasploit require local

  binaries or a running daemon on the host machine.

* Commercial Tool Scope: Nessus and Burp Suite support XML import only; users

  supply their own exports under their own licenses.

* Single-Node Console: Designed for loopback or reverse-proxied deployment; no

  built-in TLS, MFA, email reset, or multi-tenant session sharing.

* Authorisation Attestation: KAVACH enforces the scope registered by the

  analyst, but cannot independently verify written permission for external

  targets; the operator remains responsible for legal authorisation.



--------------------------------------------------------------------------------

8. STANDARDS, LICENSING & PROVENANCE

--------------------------------------------------------------------------------

Standards Referenced (vocabulary & mapping only; does not establish compliance):

  NIST SP 800-115, OWASP Top 10, CVE, CVSS, CWE, MITRE ATT&CK (tactic-level),

  and NIST CSF 2.0 (category-level).



Licensing:

  - KAVACH core code: 100% Go standard library; written for this hackathon.

  - Vendored offline frontend assets: Three.js r170 (MIT), JetBrains Mono

    (SIL OFL 1.1).

  - External driven tools retain their own licenses (Nmap NPSL, Nikto GPL,

    OWASP ZAP Apache-2.0, Metasploit BSD-3-Clause, OpenVAS GPL/AGPL, Nessus and

    Burp Suite commercial). Nothing is bundled or redistributed.

================================================================================
