# ⚛ QuantumGuard

[![QuantumGuard](https://quantumguard-api.onrender.com/badge/cybersupe/quantumguard)](https://quantumguard.site)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![NIST](https://img.shields.io/badge/NIST-FIPS%20203%2F204%2F205-green)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Website](https://img.shields.io/badge/Website-quantumguard.site-16a34a)](https://quantumguard.site)
[![API](https://img.shields.io/badge/API-v2.9.0-22c55e)](https://quantumguard-api.onrender.com/health)
[![India NQM](https://img.shields.io/badge/India%20NQM-Aligned-orange)](https://dst.gov.in)

**The world's only free, self-serve post-quantum cryptography vulnerability scanner.**

> Aligned with India's National Quantum Mission (DST, February 2026) · NIST FIPS 203/204/205 · Built by Mangsri QuantumGuard LLC · Montgomery, AL

---

## Why This Exists

Quantum computers will break RSA, ECC, and DH encryption. NIST finalized post-quantum standards in August 2024. India's DST mandated cryptographic inventories across critical infrastructure by 2027. Companies must migrate — but most developers don't know where their vulnerabilities are.

QuantumGuard finds them in 30 seconds, for free.

---

## What QuantumGuard Does

- 🔍 **Code Scanner** — Scans Python, JS, Java, TS, Go, Rust, C, C++ for quantum-vulnerable crypto
- 📦 **Dependency Scanner** — Flags vulnerable libraries in requirements.txt, package.json, go.mod, pom.xml, Cargo.toml, Gemfile
- 🔐 **TLS Analyzer** — Checks any domain's TLS quantum readiness with A–F grading
- 🔬 **Crypto Agility Checker** — Scores how easy your crypto is to swap
- 🧠 **Unified Risk Engine** — One 0–100 score combining code, TLS, and agility
- 📊 **Enterprise Risk Layer** — P0/P1/P2 priority, business impact, exploitability per finding
- 🏛 **NIST SP 800-53 Reports** — PDF, CSV, and CBOM export
- ⚡ **AI Fix Suggestions** — One-click NIST-approved migration code
- 🔄 **GitHub Actions Gate** — Blocks PRs with CRITICAL findings automatically
- 🏢 **Org/Team Dashboard** — Multi-tenant with role-based access
- 💳 **Stripe Billing** — Free, Pro ($49/mo), Team ($199/mo)

---

## Live Results — pycrypto scan

```
Score:    0/100  ← correct, pycrypto is deliberately vulnerable
Findings: 265
Critical: MD4 (11), RSA (7), RC4 (5), DES (5)
High:     DSA (34)
Files:    177 scanned · 10 with issues · 1.4ms scan time
```

---

## Add a Badge to Your Repo

```markdown
[![QuantumGuard](https://quantumguard-api.onrender.com/badge/YOUR_USERNAME/YOUR_REPO)](https://quantumguard.site)
```

---

## Vulnerabilities Detected

### Code Scanner (15+ vulnerability types)

| Algorithm | Severity | PQC Replacement | NIST Standard |
|-----------|----------|-----------------|---------------|
| RSA | CRITICAL | ML-KEM (CRYSTALS-Kyber) | FIPS 203 |
| ECC / ECDSA | CRITICAL | ML-DSA (CRYSTALS-Dilithium) | FIPS 204 |
| Diffie-Hellman | HIGH | ML-KEM (CRYSTALS-Kyber) | FIPS 203 |
| DSA | HIGH | ML-DSA (CRYSTALS-Dilithium) | FIPS 204 |
| MD5 | HIGH | SHA-3-256 | FIPS 205 |
| SHA-1 | HIGH | SHA-3-256 | FIPS 205 |
| RC4 / ARC4 | CRITICAL | AES-256-GCM | — |
| DES / 3DES | CRITICAL | AES-256-GCM | — |
| ECB Mode | HIGH | AES-256-GCM | — |
| Weak TLS | HIGH | TLS 1.3 minimum | — |
| Hardcoded Secrets | HIGH | Secrets Manager | — |
| JWT None Algorithm | CRITICAL | HMAC-SHA256 minimum | — |
| MD4 | CRITICAL | SHA-3-256 | FIPS 205 |

### Dependency Scanner (30+ libraries across 6 ecosystems)

| Ecosystem | Flagged Libraries |
|-----------|-----------------|
| Python | pycrypto, pycryptodome, rsa, ecdsa, paramiko, pyopenssl, tlslite-ng |
| Node.js | node-rsa, node-forge, elliptic, jsencrypt, crypto-js, jsonwebtoken, ssh2 |
| Java | bcprov-jdk15on, bcprov-jdk18on, commons-codec |
| Go | golang.org/x/crypto (rsa/ecdsa sub-packages) |
| Rust | rsa crate, md5 crate |
| Ruby | openssl gem, bcrypt-ruby |

---

## Scan Any Repo in 30 Seconds

```bash
# Code scan
curl -X POST https://quantumguard-api.onrender.com/scan-github \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/your/repo"}'

# Dependency scan
curl -X POST https://quantumguard-api.onrender.com/scan-dependencies \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/your/repo"}'

# TLS analysis
curl -X POST https://quantumguard-api.onrender.com/analyze-tls \
  -H "Content-Type: application/json" \
  -d '{"domain": "yourdomain.com"}'
```

Or just go to **[quantumguard.site](https://quantumguard.site)** — no install, no signup.

---

## API Reference

| Method | Endpoint | Auth | Description |
|--------|----------|------|-------------|
| POST | `/scan-github` | Optional JWT | Scan any public GitHub repo |
| POST | `/scan-dependencies` | Optional JWT | Scan package manifests for vulnerable libraries |
| POST | `/public-scan-zip` | None | Upload ZIP file (max 10MB) |
| POST | `/analyze-tls` | None | Analyze domain TLS quantum readiness |
| POST | `/check-agility` | None | Check crypto agility score |
| POST | `/unified-risk` | Optional JWT | Combined code + TLS + agility score |
| POST | `/export-cbom` | Optional JWT | Cryptographic Bill of Materials (CBOM) |
| GET | `/badge/{owner}/{repo}` | None | Live SVG quantum safety badge |
| POST | `/auth/register` | None | Register account |
| POST | `/auth/login` | None | Login |
| GET | `/auth/me` | JWT | Current user + org + plan info |
| GET | `/auth/history` | JWT | Personal scan history |
| POST | `/org/create` | JWT | Create organisation |
| POST | `/org/invite` | JWT | Invite team member |
| GET | `/org/me` | JWT | Org details + member list |
| GET | `/org/scans` | JWT | Org-wide scan history |
| POST | `/billing/create-checkout` | JWT | Stripe checkout session |
| GET | `/billing/status` | JWT | Current plan + limits |
| GET | `/billing/portal` | JWT | Manage subscription |
| GET | `/health` | None | Health check — returns version |

---

## GitHub Actions — Security Gate

Add to `.github/workflows/quantumguard.yml`:

```yaml
name: QuantumGuard Pro CI/CD
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

env:
  SCORE_THRESHOLD: "60"
  CRITICAL_THRESHOLD: "10"

jobs:
  quantum-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.11"
      - run: pip install -r requirements.txt
      - name: QuantumGuard Security Gate
        run: |
          python -c "
          from scanner.scan import scan_directory, calculate_score
          findings = scan_directory('.')
          score = calculate_score(findings)
          critical = sum(1 for f in findings if f['severity']=='CRITICAL' and f.get('confidence')!='LOW')
          print(f'Score: {score}/100 | Critical: {critical}')
          exit(1) if critical > 10 or score < 60 else exit(0)
          "
```

This blocks any PR with more than 10 critical findings or score below 60.

---

## Enterprise Scanner — 7 Detection Phases

| Phase | Name | What It Does |
|-------|------|-------------|
| 1 | Context-aware detection | Classifies findings as auth / crypto / session / ui / test |
| 2 | Numeric confidence | 0–1 confidence score per finding (not just HIGH/MEDIUM/LOW) |
| 3 | Library noise elimination | Suppresses vendor/, dist/, node_modules/ false positives |
| 4 | Smart grouping | Collapses N findings → grouped view with root cause |
| 5 | Executive risk layer | P0/P1/P2 priority + business impact + exploitability |
| 6 | Score engine | Linear penalty: CRITICAL=−20, HIGH=−12, MEDIUM=−5 |
| 7 | Clean repo detection | Returns positive confirmation when no exploitable crypto found |

---

## Pricing

| Plan | Price | Scans/Day | Key Features |
|------|-------|-----------|-------------|
| Free | $0 | 20 | Code scan, TLS analyzer, PDF report, NIST guidance |
| Pro | $49/mo | 100 | Everything + dependency scanner, GitHub Actions gate, API access |
| Team | $199/mo | 500 | Everything + org dashboard, multi-repo, SSO/SAML |
| Enterprise | Custom | Unlimited | On-prem Docker, SLA 99.99%, dedicated CSM |

---

## India National Quantum Mission Alignment

QuantumGuard directly addresses India's DST February 2026 mandate:

- ✅ **Cryptographic inventory** — finds all RSA, ECC, DH usage across codebases
- ✅ **Dependency assessment** — flags quantum-vulnerable libraries in all package manifests
- ✅ **CBOM generation** — Cryptographic Bill of Materials export for compliance
- ✅ **Crypto agility scoring** — measures migration readiness
- ✅ **NIST FIPS 203/204/205 guidance** — exact replacement recommendations
- ✅ **Executive reports** — board-ready PDF reports with risk scoring

Critical sectors required to comply by 2027: defense, telecom, energy, banking, government systems.

---

## Security

- 🔒 Source code never stored — scanned in memory, deleted immediately after
- 🛡 ZIP path traversal protection at all extraction call sites  
- 🚫 SSRF guard — blocks all private IP ranges including AWS metadata
- 🔑 JWT authentication with sha256_crypt password hashing
- 📝 Token scrubbing — GitHub tokens, passwords never appear in logs
- ⚡ Rate limiting by plan — prevents abuse

---

## Stack

| Layer | Technology |
|-------|-----------|
| Scanner | Python 3.14 — AST + regex + flow analysis |
| API | FastAPI + SlowAPI + psycopg2 connection pool |
| Database | PostgreSQL — users, scan_history, organizations, org_members |
| Frontend | React 18 — single-file SPA, zero build framework |
| Auth | JWT (email/password) + Firebase (Google OAuth) |
| Billing | Stripe — checkout, webhooks, customer portal |
| CI/CD | GitHub Actions — frontend build + backend check + security gate |
| Deploy | Render (API) + Vercel (frontend) |
| Uptime | UptimeRobot — pings /health every 5 min |

---

## Self Hosting

```bash
git clone https://github.com/cybersupe/quantumguard
cd quantumguard
pip install -r requirements.txt

# Set environment variables
export DATABASE_URL=postgresql://...
export JWT_SECRET_KEY=your-secret-key
export STRIPE_SECRET_KEY=sk_...        # optional
export STRIPE_WEBHOOK_SECRET=whsec_... # optional

uvicorn api:app --reload --port 8000
```

Frontend:
```bash
cd dashboard
npm install
npm start
```

---

## Company

**Mangsri QuantumGuard LLC**
Montgomery, AL · Founded April 27, 2026
Website: [quantumguard.site](https://quantumguard.site)
GitHub: [github.com/cybersupe/quantumguard](https://github.com/cybersupe/quantumguard)

**Team**
- Pavansudheer Payyavula — Founder & CEO · MS Cybersecurity & CIS
- Manasa Sannidhi — Co-Founder · MS Computer Science
- Bharathwaj Goud Siga — Business · MS Business Analytics
- Vijendhar Reddy Muppidi — Advisor · MS MIS

---

## License

AGPL v3 — Free for everyone, forever.

---

*NIST FIPS 203 · FIPS 204 · FIPS 205 · India DST NQM Aligned · Zero Data Retention · SOC 2 Type II Roadmap*
