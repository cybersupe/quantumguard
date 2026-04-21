# QuantumGuard

AI-powered quantum cryptography vulnerability scanner for enterprises.

## The Problem

Quantum computers will break RSA, ECC, and DH encryption within this
decade. NIST finalized post-quantum standards in 2024. Companies must
migrate now.

## What QuantumGuard Does

- Scans Python, JavaScript, Java, TypeScript codebases
- Detects RSA, ECC, DH, DSA, MD5, SHA-1 vulnerabilities
- Gives every codebase a Quantum Readiness Score 0 to 100
- Suggests NIST-approved PQC replacement for every finding
- Saves a full JSON report for your security team

## Vulnerabilities Detected

| Algorithm | Severity | PQC Replacement |
|-----------|----------|-----------------|
| RSA | CRITICAL | CRYSTALS-Kyber |
| ECC / ECDSA | CRITICAL | CRYSTALS-Dilithium |
| Diffie-Hellman | HIGH | CRYSTALS-Kyber |
| DSA | HIGH | CRYSTALS-Dilithium |
| MD5 | MEDIUM | SHA-3 |
| SHA-1 | MEDIUM | SHA-3 |

## Built With

Python 3.11, tree-sitter, Click, Anthropic Claude API

## License

MIT