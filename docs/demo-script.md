# QuantumGuard — 30-Second Product Demo Script

**Format:** Live narrated screen share  
**Audience:** Engineering lead, CISO, or technical evaluator  
**Goal:** Demonstrate time-to-insight and report quality in one uninterrupted flow

---

## Script (30 seconds)

> "QuantumGuard tells you exactly where your codebase is exposed to harvest-now-decrypt-later attacks — in under 30 seconds."

*[Paste a GitHub URL into the input field — use `github.com/OWASP/WebGoat` or a prepared internal example.]*

> "I'll paste a public repo and hit scan."

*[Click Run Scan. The terminal-style console fills with live scan logs.]*

> "You can see it cloning the repo, walking the file tree, and matching against 58 NIST-aligned cryptographic patterns in real time."

*[Results appear — risk score, finding count, severity breakdown.]*

> "This repo scores 42 out of 100 — two critical findings: RSA-2048 and ECC P-256, both quantum-vulnerable by 2030 under NIST's current deprecation timeline."

*[Click a finding to expand it.]*

> "Every finding shows you the exact file and line, the detection confidence, why it's flagged, the business impact, and the CRYSTALS-Kyber or CRYSTALS-Dilithium migration path."

*[Click Download PDF.]*

> "One click exports a board-ready PDF — risk score, findings table, executive summary, and a NIST-aligned remediation roadmap. No account required for public repos."

---

## Key talking points

- **No code retained** — repository is scanned in memory and discarded after the request
- **NIST FIPS 203/204/205 aligned** — patterns track the algorithms deprecated in NIST IR 8547
- **Actionable output** — every finding links directly to the specific file, line, and PQC migration path
- **Board-ready exports** — PDF, CSV, and CBOM JSON from a single scan
- **Zero setup** — no agents, no CI integration required for an initial assessment
