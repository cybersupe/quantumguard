# QuantumGuard — LinkedIn Technical Showcase Post

---

Most engineering teams don't know they have a harvest-now-decrypt-later problem. They will.

NIST finalised the first post-quantum cryptography standards in August 2024 (FIPS 203, 204, 205). The deprecation timeline for RSA, ECC, and DH is now official — not theoretical.

I built **QuantumGuard** to make the inventory step fast and actionable.

**What it does in ~15 seconds:**
→ Clones your GitHub repo into an isolated temporary directory  
→ Walks the AST across Python, JavaScript, TypeScript, Java, Go, Rust, and C  
→ Matches against 58 NIST-aligned patterns (RSA, ECC, DH, DSA, MD5, SHA-1, RC4, and more)  
→ Scores your quantum readiness from 0–100 using a weighted severity model  
→ Maps every finding to the CRYSTALS-Kyber / CRYSTALS-Dilithium migration path  
→ Exports a board-ready PDF, CSV, or CBOM JSON — no account required for public repos

**Architecture decisions I care about:**
- No code persistence. Repository content never touches a database. The temp directory is deleted in a `finally` block, even on exception.
- Detection confidence scores per finding — AST direct hits vs. heuristic matches are surfaced differently, so the risk score isn't inflated by uncertain detections.
- False-positive rate under 3% on the test corpus. Trust requires accuracy.

The NIST deprecation deadline for classical algorithms is 2030 for new systems, 2035 for existing. That sounds distant — until you factor in key lifetimes, migration lead times, and the fact that adversaries are already collecting encrypted traffic to decrypt later.

The inventory is step zero. Most teams haven't done it.

Try it on any public repo at **quantumguard.site** — no sign-up, no agents, no CI changes required for a first look.

---

*Tags: #PostQuantumCryptography #CyberSecurity #NIST #PQC #QuantumComputing #AppSec #CISO #CryptoAgility*
