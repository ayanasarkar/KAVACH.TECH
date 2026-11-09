# 🛡️ Kavach: VAPT Agent
> **Evidence-Driven AI Assistant for Authorised Penetration Testing**

[![Go Version](https://img.shields.io/badge/Go-1.22%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![Dependencies](https://img.shields.io/badge/Dependencies-Zero%20(Stdlib%20Only)-success)](#licensing-assumptions-and-provenance)
[![Hackathon](https://img.shields.io/badge/Hackathon-DataOps%20Innovation-blue)](#about)
[![Team](https://img.shields.io/badge/Team-gh0st__1n__4he__sYstem-orange)](#team--author)

---

## 📌 Executive Summary

**Kavach** (`vapt-agent`) is an evidence-driven, safe AI assistant built for authorised penetration testing. It ingests an authorised target scope (IPs, CIDRs, or approved domain trees) and plain-English requests, plans executable scanning workflows using internal and external tools, enforces strict **deny-by-default scope boundaries**, correlates multi-tool output into deduplicated finding lists, and generates client-ready PDF reports.

Built strictly using the **Go standard library**, Kavach requires zero external Go modules or mandatory cloud services. It is designed to bridge the gap between AI autonomy and defensive control—guaranteeing that AI never executes out-of-scope actions, never invents unevidenced vulnerabilities, and never executes high-risk actions without explicit human approval.

---

## 👨‍💻 Team & Author

* **Team Name:** `gh0st_1n_4he_sYstem`
* **Author / Participant:** Ayana Sarkar
* **Hackathon:** DataOps Innovation Hackathon — *AI Agent for Automated Penetration Testing*

---

## ✨ Key Features

* **🛡️ Deny-by-Default Scope Guard:** Every planned step is checked at plan time *and* connect time. Supports IP ranges, subnets (max `/16` IPv4 for lab safety), exact hostnames, and explicitly approved DNS domain trees (`authorized_domains`). Prevents DNS rebinding and out-of-scope pivots.
* **🔐 Tamper-Evident Hash-Chained Audit Log:** Every request, scope validation decision, tool execution, output hash, and human approval is logged to an append-only, SHA-256 hash-chained log with instant verification tools.
* **🤖 Swappable Inference Backends:** Works seamlessly with **Anthropic Messages API**, local models via **Ollama**, or a completely offline **deterministic rules planner**.
* **⚙️ Multi-Tool Correlation Engine:** Merges overlapping findings across tools (Nmap, Nikto, OWASP ZAP, Metasploit, Nessus/Burp imports, built-in Go scanners), calculates unified confidence ratings, and flags suspected false positives.
* **👤 Human-in-the-Loop Approval Checkpoints:** Offensive actions (such as Metasploit modules) are blocked by default and require explicit human sign-off with target confirmation.
* **📊 Calculated Risk Scoring:** CVSS/CVE scores and risk levels are computed deterministically in code based on evidence—never fabricated by the LLM.
* **📄 Automated PDF Reporting:** Generates clean, executive-ready PDF reports linking every reported finding directly to raw SHA-256 verified evidence logs (`E-xxxx`).

---

## 🏗️ Architecture & Data Flow

```text
┌─────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│ Analyst Console │ ────> │ Planner (LLM /   │ ────> │ Deny-by-Default  │
│ (Web UI / CLI)  │       │ Rules Engine)    │       │ Scope Guard      │
└─────────────────┘       └──────────────────┘       └────────┬─────────┘
                                                              │
                                                        [ Approved ]
                                                              │
                                                              ▼
┌─────────────────┐       ┌──────────────────┐       ┌──────────────────┐
│ Client-Ready    │ <──── │ Findings         │ <──── │ Safe Tool        │
│ PDF Report      │       │ Correlation      │       │ Execution        │
└─────────────────┘       └──────────────────┘       └────────┬─────────┘
                                                              │
                                                     [ SHA-256 Logged ]
                                                              │
                                                              ▼
                                                     ┌──────────────────┐
                                                     │ Hash-Chained     │
                                                     │ Audit Trail      │
                                                     └──────────────────┘
```

### Module Layout

```text
vapt-agent/
├── cmd/
│   ├── vapt/             # Main console & REST API server (embedded web UI)
│   └── lab/              # Deliberately weak, loopback-only target lab
├── internal/
│   ├── adapters/         # Tool integrations (Nmap, Nikto, ZAP, Metasploit, imports)
│   ├── agent/            # Execution pipeline, LLM/Rules planner, approval gates
│   ├── audit/            # Hash-chained append-only audit logger & verifier
│   ├── correlate/        # Deduplication, finding normalization & triage
│   ├── llm/              # Anthropic, Ollama, and fallback rules drivers
│   ├── report/           # Native PDF generator & evidence link engine
│   ├── risk/             # Deterministic risk computation & CVSS parser
│   └── scope/            # Deny-by-default guard, rate-limiter, DNS validation
├── docs/                 # System architecture documentation
├── samples/              # Pre-generated sample outputs (PDF, State JSON, Audit Log)
└── scripts/
    └── demo.sh           # Headless end-to-end automated test runner
```

---

## 📊 Integration Matrix (Truthful Capabilities)

**Verified Live Execution Details:** Kavach dynamically executes **Nmap** (port, service, and version discovery) and **Go Built-in web checks** against authorized domains (e.g., `www.hackthecore.in`). The agent autonomously discovers vulnerabilities like exposed Git repositories, missing security headers, and open ports, while parsing live XML and HTTP responses in real-time.

| Tool | Status | Execution Method | Notes |
| :--- | :--- | :--- | :--- |
| **Go Built-in Recons** | 🟢 Live | Native TCP / HTTP GET | Default fallback; header analysis, banner grabs, `.env`/`.git` leaks. |
| **Nmap** | 🟢 Live | CLI (`-sV`, XML parsed) | Fully parsed live when `nmap` is present on PATH. |
| **Nikto** | 🟢 Live | CLI (XML parsed) | Parsed live when `nikto` is present on PATH. |
| **OWASP ZAP** | 🟢 Live | REST API Daemon | Requires ZAP daemon (`:8090`). Active scan runs only if scope permits. |
| **Metasploit** | 🟡 Gated | `msfconsole` module check | **Lab-only & Human Approval Gated**. Never autonomous. |
| **Nessus** | 🔵 Import | `.nessus` v2 XML | File import parser (Essentials capped at 16 hosts). |
| **Burp Suite** | 🔵 Import | XML issue export | File import parser for XML findings exports. |
| **OpenVAS / Greenbone** | 🔵 Import | Report XML | Report import parser. |

---

## 🔒 How Kavach Keeps the AI Honest

1. **Strict Plan Validation:** The LLM can only suggest structured JSON tool execution plans. Proposed actions are validated against the Scope Guard at planning *and* immediately prior to network socket execution (`CheckDial`).
2. **Grounding & Evidence Linking:** AI-generated impact narratives must cite specific evidence IDs (`E-xxxx`). If an AI narrative mentions a CVE or CVSS score missing from raw tool evidence, the narrative is rejected and logged as an audit failure.
3. **No Prompt Injection Risks:** All text returned from target HTTP headers or banners is marked as untrusted input. The LLM has zero capability to execute system shell commands (subprocess calls use strict `argv` arrays with no shell evaluation).
4. **Data Protection:** Potential secrets (e.g., API keys, session tokens, `.env` credentials) detected in execution outputs are automatically redacted at capture.

---

## 🚀 Quick Start

### Prerequisites
* **Go 1.22+** installed (`go version`).
* *(Optional)* `nmap`, `nikto`, `msfconsole`, or OWASP ZAP daemon running locally. Missing tools are safely reported as unavailable.

### 1. Run the Local Test Lab (Terminal 1)
Start the deliberately vulnerable target bound to loopback only (`127.0.0.1`):
```bash
go run ./cmd/lab
```
*(The lab listens on HTTP ports `8081`, `8000`, `8008`, and mock service banners on `2121` and `2323`)*.

### 2. Launch the Analyst Console (Terminal 2)
```bash
go run ./cmd/vapt
```
Open **`http://127.0.0.1:8787`** in your browser. The UI form is pre-filled for local testing.

### 3. Model Configuration (Optional)
Kavach automatically selects the best available engine:

```bash
# Option A: Use Anthropic Claude
export ANTHROPIC_API_KEY="your-api-key"
export VAPT_MODEL="claude-3-5-sonnet-20241022" # Optional

# Option B: Use Local Ollama
export OLLAMA_MODEL="llama3"
export OLLAMA_URL="http://localhost:11434"

# Option C: Offline Rules-Only Mode (Default if no key/URL provided)
# No environment variables needed.
```

---

## 🧪 Testing & Automated Verification

### Run Automated Headless Suite
To run an end-to-end headless assessment and regenerate standard test outputs:
```bash
bash scripts/demo.sh
```

### Run Unit & Security Guard Tests
```bash
# Run all unit tests (Scope guard, tamper detection, parsers, grounding, etc.)
go test ./...

# Test specific scope guard & DNS rebind protection
go test -v -count=1 ./internal/scope/...
```

---

## 🔍 Live-Demo Judging Checklist

| Checklist Item | Where to Verify in UI / Code |
| :--- | :--- |
| **1. Target & Scope Validation** | **Setup Form**: Try requesting `8.8.8.8` alongside lab targets. Scope guard refuses it, audits the refusal, and lists it under Limitations. |
| **2. Plan Rationale & Safety** | **Plan & Runs Tab**: Shows step-by-step reasoning, triggering evidence, and scope guard verdict for each step. |
| **3. Traceable Tool Output** | **Step Status**: View duration, execution status, and raw output SHA-256 file hashes. |
| **4. Multi-Tool Correlation** | **Findings Tab**: Merged asset vulnerabilities, confidence scores, and false-positive triage status. |
| **5. Approval Checkpoint** | **Approvals Tab**: Exploit-level actions require re-typing target name and analyst justification. |
| **6. Client-Ready PDF Report** | **PDF Download**: PDF report contains structured findings linked directly to raw evidence IDs (`E-xxxx`). |
| **7. Transparent Tooling** | **Integrations Tab**: Truthful status matrix showing live, imported, or unavailable scanners. |

---

## 📜 Licensing & Provenance

* **Project License:** Written using **100% Go Standard Library**.
* **Third-Party Utilities:** Driven tools maintain their respective licenses (Nmap - NPSL, Nikto - GPL, ZAP - Apache 2.0, Metasploit - BSD 3-Clause). No third-party binaries or proprietary modules are bundled into this repository.
* **Provenance:** All core code in this repository was authored specifically for the DataOps Innovation Hackathon.

---

<div align="center">
  <b>Kavach VAPT Agent</b> • Built for DataOps Innovation Hackathon by <code>gh0st_1n_4he_sYstem</code>
</div>
