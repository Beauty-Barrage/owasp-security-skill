# OWASP Security Skill

A reusable security code auditing skill and static analysis toolkit for Google Antigravity, Claude Code, and Gemini CLI environments.

This skill equips AI coding assistants to review source code against **OWASP Top 10 (Web)**, **OWASP API Security Top 10**, **OWASP Mobile Top 10**, and **OWASP ASVS (Level 2)** standards.

---

## What This Skill Does

* **Automated Static Heuristics:** Scans codebases using a fast POSIX shell script (`owasp_scan.sh`) to detect hardcoded secrets, weak hashes (MD5, SHA1), unparameterized SQL concatenation, missing authorization attributes, and unhandled auth exceptions.
* **Source-to-Sink Data Flow Analysis:** Guides the AI assistant to trace untrusted inputs (headers, params, cookies, payloads) down to sensitive operations (SQL queries, crypto, file writes, outbound HTTP requests).
* **Object-Level Authorization Verification:** Validates that endpoints assert user and tenant ownership boundaries (preventing IDOR / BOLA).
* **Mobile Client Auditing:** Audits React Native, iOS, and Android applications for secure keychain storage, TLS enforcement, and clean session invalidation.
* **Standardized Defect Reporting:** Generates audit findings mapped to CWE IDs, OWASP categories, and CVSS v3.1 severity scores with concrete code remediations.

---

## Directory Structure

```text
owasp-security-skill/
├── README.md                          # Documentation and usage guide
├── plugin.json                        # Antigravity plugin manifest
├── LICENSE                            # Apache 2.0
└── skills/
    └── owasp-security-skill/
        ├── SKILL.md                   # Core audit methodology, checklists, and scoring
        ├── scripts/
        │   └── owasp_scan.sh          # POSIX/macOS static heuristic scanner
        └── references/
            ├── web_api_top10.md       # OWASP Web & API Top 10 guidelines and code patterns
            ├── mobile_top10.md        # OWASP Mobile Top 10 (React Native / iOS / Android)
            └── asvs_checklist.md      # ASVS Level 2 verification checklist
```

---

## Installation Options

### Option 1: Per-Project Installation (Recommended for Teams)
Install directly into any project repository so any project manager, engineer, or agent working in that workspace automatically has access:

```bash
# From the root of your project:
mkdir -p .agents/skills
git clone https://github.com/Beauty-Barrage/owasp-security-skill.git .agents/skills/owasp-security-skill
```

### Option 2: Global Installation (Available across all local workspaces)
Clone once into your global Antigravity/Gemini plugins directory:

```bash
git clone https://github.com/Beauty-Barrage/owasp-security-skill.git ~/.gemini/config/plugins/owasp-security-plugin
```

---

## How to Use

### 1. In AI Agent Conversations
Once installed, ask your agent to audit any part of your code:

* *"Perform an OWASP Top 10 code audit on `src/Controllers/`."*
* *"Audit the authentication pipeline and session handling for OWASP A01 and A07 vulnerabilities."*
* *"Review this pull request against OWASP Mobile Top 10 standards."*
* *"Check our SQL queries and stored procedures for SQL injection risks."*

### 2. Standalone Terminal Scanner
Run the bundled heuristic static analysis scanner directly in any terminal:

```bash
# Run against a specific directory or the whole repo:
./skills/owasp-security-skill/scripts/owasp_scan.sh [path_to_code]
```

---

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
