# ⚛ QuantumGuard

[![QuantumGuard](https://quantumguard-api.onrender.com/badge/cybersupe/quantumguard)](https://quantumguard.site)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![NIST](https://img.shields.io/badge/NIST-FIPS%20203%2F204%2F205-green)](https://csrc.nist.gov/projects/post-quantum-cryptography)
[![Website](https://img.shields.io/badge/Website-quantumguard.site-16a34a)](https://quantumguard.site)

**AI-powered quantum cryptography vulnerability scanner — free for every developer, forever.**

> Submitted to NIST NCCoE & NIST PQC Team · Built by Mangsri QuantumGuard LLC · Montgomery, AL

---

## The Problem

Quantum computers will break RSA, ECC, and DH encryption within this decade. NIST finalized post-quantum standards in 2024. Companies must migrate now — but most developers don't even know if their codebase is vulnerable.

## What QuantumGuard Does

- 🔍 Scans Python, JavaScript, Java, TypeScript, Go, Rust, C/C++ codebases
- ⚡ Detects RSA, ECC, DH, DSA, MD5, SHA-1 and 15+ vulnerabilities
- 📊 Gives every codebase a **Quantum Readiness Score 0 to 100**
- 🔄 Suggests NIST-approved PQC replacement for every finding
- 🏛 Generates NIST SP 800-53 compliance reports
- 🔐 Analyzes any domain's TLS quantum readiness
- 📄 Exports full JSON, CSV, and PDF reports

## Add a Badge to Your Repo

Show your quantum safety score in your README:

```markdown
[![QuantumGuard](https://quantumguard-api.onrender.com/badge/YOUR_USERNAME/YOUR_REPO)](https://quantumguard.site)
```

Replace `YOUR_USERNAME/YOUR_REPO` with your GitHub username and repo name.

## Vulnerabilities Detected

| Algorithm | Severity | PQC Replacement | NIST Standard |
|-----------|----------|-----------------|---------------|
| RSA | CRITICAL | CRYSTALS-Kyber | FIPS 203 |
| ECC / ECDSA | CRITICAL | CRYSTALS-Dilithium | FIPS 204 |
| Diffie-Hellman | HIGH | CRYSTALS-Kyber | FIPS 203 |
| DSA | HIGH | CRYSTALS-Dilithium | FIPS 204 |
| MD5 | MEDIUM | SHA-3 | FIPS 202 |
| SHA-1 | MEDIUM | SHA-3 | FIPS 202 |
| RC4 | CRITICAL | AES-256-GCM | — |
| DES / 3DES | CRITICAL | AES-256-GCM | — |
| Weak TLS | HIGH | TLS 1.3 minimum | — |
| Hardcoded Secrets | HIGH | Secrets Manager | — |

## Scan Any Repo in 30 Seconds

```bash
# Via API
curl -X POST https://quantumguard-api.onrender.com/scan-github \
  -H "Content-Type: application/json" \
  -d '{"github_url": "https://github.com/your/repo"}'
```

Or just go to **[quantumguard.site](https://quantumguard.site)** — no install, no signup required.

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/scan-github` | Scan any public GitHub repo |
| POST | `/public-scan-zip` | Upload ZIP file (max 10MB) |
| POST | `/analyze-tls` | Analyze domain TLS quantum readiness |
| POST | `/check-agility` | Check crypto agility score |
| GET | `/badge/{owner}/{repo}` | Live quantum safety badge |
| GET | `/health` | Health check |

## GitHub Action — Auto Scan on Every Push

Add this to `.github/workflows/quantum-scan.yml`:

```yaml
name: QuantumGuard Scan
on: [push, pull_request]
jobs:
  quantum-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Scan for quantum vulnerabilities
        run: |
          curl -X POST https://quantumguard-api.onrender.com/scan-github \
            -H "Content-Type: application/json" \
            -d '{"github_url": "https://github.com/${{ github.repository }}"}'
```

## Built With

- **Python 3.11** — Backend
- **FastAPI** — REST API
- **tree-sitter** — AST-based code parsing
- **React** — Frontend dashboard
- **Firebase** — Authentication & scan history
- **Anthropic Claude API** — AI fix suggestions
- **NIST FIPS 203, 204, 205** — Post-quantum standards

## Languages Supported

Python · JavaScript · Java · TypeScript · Go · Rust · C · C++

## Self Hosting

```bash
git clone https://github.com/cybersupe/quantumguard
cd quantumguard
pip install -r requirements.txt
uvicorn api:app --reload --port 8000
```

See [SELF_HOSTING.md](SELF_HOSTING.md) for full instructions.

## Company

**Mangsri QuantumGuard LLC**  
Montgomery, AL · Founded April 27, 2026 · EIN 42-2185776  
Website: [quantumguard.site](https://quantumguard.site)

## License

AGPL v3 — Free for everyone, forever.
