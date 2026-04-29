# ============================================================
# QuantumGuard — JavaScript AST Scanner
# Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI
# Licensed under AGPL v3 — github.com/cybersupe/quantumguard
# Standards: NIST FIPS 203, FIPS 204, FIPS 205
# ============================================================
#
# Drop this file at: backend/scanner/js_ast_scanner.py
# It is automatically invoked by scan_directory() in scan.py
# when .js / .ts / .mjs / .cjs files are encountered.
#
# Requires: pyjsparser  (pip install pyjsparser)
# Fallback: regex-based scan when AST parse fails
# ============================================================

import re
import os
from typing import Any

# ── Try importing pyjsparser; fall back to regex-only mode ──
try:
    import pyjsparser
    AST_AVAILABLE = True
except ImportError:
    AST_AVAILABLE = False

JS_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}

# ─────────────────────────────────────────────────────────────
# RULE REGISTRY
# Each rule is a dict with:
#   id, name, severity, confidence, risk_explanation,
#   replacement, nist_ref
#   ast_patterns  — list of AST node matchers (used when AST available)
#   regex_pattern — fallback regex (always used as secondary pass)
# ─────────────────────────────────────────────────────────────

RULES = [
    # ── 1. Math.random() ─────────────────────────────────────
    {
        "id": "JS-RAND-001",
        "vulnerability": "Math.random() — Insecure PRNG",
        "severity": "HIGH",
        "confidence": "HIGH",
        "risk_explanation": (
            "Math.random() is not cryptographically secure. "
            "It must never be used for key generation, tokens, nonces, "
            "or any security-sensitive value. Quantum or classical attackers "
            "can predict output given enough samples."
        ),
        "replacement": "crypto.getRandomValues() or Node.js crypto.randomBytes()",
        "nist_ref": "NIST SP 800-90A Rev1 — DRBG",
        "regex_pattern": r'\bMath\.random\s*\(',
    },

    # ── 2. Web Crypto subtle.encrypt with RSA-OAEP ───────────
    {
        "id": "JS-RSA-001",
        "vulnerability": "RSA-OAEP — Quantum-Vulnerable Encryption",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "risk_explanation": (
            "RSA-OAEP is broken by Shor's Algorithm on a cryptographically relevant "
            "quantum computer. Any data encrypted today could be harvested and decrypted "
            "later ('Harvest Now, Decrypt Later' attack)."
        ),
        "replacement": "CRYSTALS-Kyber (ML-KEM) — NIST FIPS 203",
        "nist_ref": "NIST FIPS 203",
        "regex_pattern": r'["\']RSA-OAEP["\']|["\']RSA-PSS["\']|["\']RSASSA-PKCS1-v1_5["\']',
    },

    # ── 3. ECDH / ECDSA key generation ───────────────────────
    {
        "id": "JS-ECC-001",
        "vulnerability": "ECDH/ECDSA — Quantum-Vulnerable Key Exchange",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "risk_explanation": (
            "Elliptic-curve cryptography (ECDH, ECDSA, P-256, P-384, P-521) is broken "
            "by Shor's Algorithm. Key exchange and digital signatures using ECC provide "
            "no quantum resistance."
        ),
        "replacement": "ML-KEM (FIPS 203) for KEM, ML-DSA (FIPS 204) for signatures",
        "nist_ref": "NIST FIPS 203 / FIPS 204",
        "regex_pattern": r'["\']ECDH["\']|["\']ECDSA["\']|["\']P-256["\']|["\']P-384["\']|["\']P-521["\']|["\']Ed25519["\']',
    },

    # ── 4. MD5 via CryptoJS or direct string ─────────────────
    {
        "id": "JS-MD5-001",
        "vulnerability": "MD5 — Broken Hash Function",
        "severity": "HIGH",
        "confidence": "HIGH",
        "risk_explanation": (
            "MD5 is cryptographically broken and produces collision-prone 128-bit digests. "
            "Grover's Algorithm on a quantum computer effectively halves security to ~64 bits. "
            "Never use for passwords, signatures, or data integrity."
        ),
        "replacement": "SHA-3 (256 or 512) via SubtleCrypto or noble-hashes",
        "nist_ref": "NIST FIPS 202 — SHA-3",
        "regex_pattern": r'\bCryptoJS\.MD5\b|["\']md5["\']|\bmd5\s*\(|require\(["\']md5["\']\)',
    },

    # ── 5. SHA-1 ──────────────────────────────────────────────
    {
        "id": "JS-SHA1-001",
        "vulnerability": "SHA-1 — Deprecated Hash Function",
        "severity": "HIGH",
        "confidence": "HIGH",
        "risk_explanation": (
            "SHA-1 is deprecated by NIST since 2011 and fully broken for collision resistance. "
            "Grover's Algorithm reduces effective quantum security to ~80 bits."
        ),
        "replacement": "SHA-256 minimum; SHA-3-256 preferred for quantum resistance",
        "nist_ref": "NIST FIPS 202",
        "regex_pattern": r'["\']SHA-1["\']|\bCryptoJS\.SHA1\b|["\']sha1["\']|require\(["\']sha1["\']\)',
    },

    # ── 6. DES / 3DES ─────────────────────────────────────────
    {
        "id": "JS-DES-001",
        "vulnerability": "DES/3DES — Broken Symmetric Cipher",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "risk_explanation": (
            "DES uses a 56-bit key and is trivially broken. 3DES (112-bit effective) is "
            "deprecated by NIST as of 2023. Grover's Algorithm further halves effective "
            "key strength."
        ),
        "replacement": "AES-256-GCM via SubtleCrypto { name: 'AES-GCM', length: 256 }",
        "nist_ref": "NIST SP 800-131A Rev2",
        "regex_pattern": r'["\']DES-CBC["\']|["\']3DES["\']|\bCryptoJS\.DES\b|\bCryptoJS\.TripleDES\b',
    },

    # ── 7. AES-128 (flag, not block) ──────────────────────────
    {
        "id": "JS-AES-001",
        "vulnerability": "AES-128 — Insufficient Key Size for Quantum Era",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "risk_explanation": (
            "AES-128 is secure classically, but Grover's Algorithm reduces effective "
            "quantum security to ~64 bits. NIST recommends AES-256 for long-term "
            "quantum resistance."
        ),
        "replacement": "AES-256-GCM: { name: 'AES-GCM', length: 256 }",
        "nist_ref": "NIST SP 800-131A Rev2",
        "regex_pattern": r'length\s*:\s*128|["\']AES-128["\']',
    },

    # ── 8. Hardcoded crypto key / secret ─────────────────────
    {
        "id": "JS-HARDKEY-001",
        "vulnerability": "Hardcoded Cryptographic Key/Secret",
        "severity": "CRITICAL",
        "confidence": "MEDIUM",
        "risk_explanation": (
            "Hardcoded keys embedded in source code are trivially extracted from bundles, "
            "binaries, or version control history. Any adversary with repo access has "
            "permanent key compromise."
        ),
        "replacement": "Load keys from environment variables or a secrets manager (e.g. AWS Secrets Manager, Vault)",
        "nist_ref": "NIST SP 800-57 Part 1 Rev5",
        "regex_pattern": (
            r'(?:privateKey|secretKey|apiSecret|cryptoKey|aesKey|hmacSecret)\s*=\s*["\'][A-Za-z0-9+/=]{16,}["\']'
        ),
    },

    # ── 9. Node.js crypto.createCipher (deprecated) ──────────
    {
        "id": "JS-NODE-001",
        "vulnerability": "crypto.createCipher — Deprecated Node.js API",
        "severity": "HIGH",
        "confidence": "HIGH",
        "risk_explanation": (
            "crypto.createCipher() derives the key from a password without a salt using "
            "a single MD5 hash — trivially weak. It was deprecated in Node.js 10 and "
            "removed in Node.js 22."
        ),
        "replacement": "crypto.createCipheriv() with a securely generated random IV and AES-256-GCM",
        "nist_ref": "NIST SP 800-38D — GCM",
        "regex_pattern": r'\bcrypto\.createCipher\s*\(',
    },

    # ── 10. Node.js crypto with RC4 / RC2 ────────────────────
    {
        "id": "JS-RC4-001",
        "vulnerability": "RC4/RC2 — Broken Stream Cipher",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "risk_explanation": (
            "RC4 and RC2 are cryptographically broken with multiple known plaintext and "
            "statistical biases. They are banned by RFC 7465 and NIST."
        ),
        "replacement": "AES-256-GCM or ChaCha20-Poly1305",
        "nist_ref": "RFC 7465 / NIST SP 800-131A",
        "regex_pattern": r'["\']rc4["\']|["\']RC4["\']|["\']rc2["\']|["\']RC2["\']',
    },

    # ── 11. JWT with 'none' algorithm ────────────────────────
    {
        "id": "JS-JWT-001",
        "vulnerability": "JWT 'none' Algorithm — Authentication Bypass",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "risk_explanation": (
            "Signing JWTs with algorithm 'none' removes all signature verification, "
            "allowing any attacker to forge tokens with arbitrary claims."
        ),
        "replacement": "Use RS256/ES256 minimum; prefer EdDSA or ML-DSA (FIPS 204) for quantum safety",
        "nist_ref": "NIST FIPS 204",
        "regex_pattern": r'algorithm\s*:\s*["\']none["\']|alg\s*:\s*["\']none["\']',
    },

    # ── 12. HS256 JWT (symmetric, weak for distributed systems)
    {
        "id": "JS-JWT-002",
        "vulnerability": "JWT HS256 — Symmetric Signature (Quantum-Vulnerable)",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "risk_explanation": (
            "HMAC-SHA256 JWTs require sharing the secret key with all verifiers. "
            "Grover's Algorithm reduces effective security. Prefer asymmetric signatures "
            "for distributed systems."
        ),
        "replacement": "EdDSA or ML-DSA (FIPS 204) asymmetric signing",
        "nist_ref": "NIST FIPS 204",
        "regex_pattern": r'algorithm\s*:\s*["\']HS256["\']|alg\s*:\s*["\']HS256["\']',
    },

    # ── 13. Web Crypto importKey with extractable: true ──────
    {
        "id": "JS-WEBCRYPTO-001",
        "vulnerability": "SubtleCrypto importKey — extractable: true",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "risk_explanation": (
            "Setting extractable: true on a CryptoKey allows the raw key material "
            "to be exported from the browser, increasing the risk of key exfiltration "
            "via XSS or supply-chain attacks."
        ),
        "replacement": "Set extractable: false unless export is strictly required",
        "nist_ref": "NIST SP 800-57 Part 1 Rev5",
        "regex_pattern": r'extractable\s*:\s*true',
    },

    # ── 14. eval() with crypto context ───────────────────────
    {
        "id": "JS-EVAL-001",
        "vulnerability": "eval() — Dynamic Code Execution Risk",
        "severity": "HIGH",
        "confidence": "LOW",
        "risk_explanation": (
            "eval() executes arbitrary strings as code. When used near cryptographic "
            "operations, it can allow injection of attacker-controlled logic that "
            "bypasses or weakens crypto primitives."
        ),
        "replacement": "Remove eval(); use structured data parsing (JSON.parse) instead",
        "nist_ref": "OWASP A03:2021 — Injection",
        "regex_pattern": r'\beval\s*\(',
    },
]


# ─────────────────────────────────────────────────────────────
# AST WALKER  (pyjsparser)
# ─────────────────────────────────────────────────────────────

def _walk_ast(node: Any, findings_cb, source_lines: list[str]):
    """Recursively walk a pyjsparser AST dict and call findings_cb on matches."""
    if not isinstance(node, dict):
        return

    node_type = node.get("type", "")

    # ── CallExpression: foo.bar() or foo() ───────────────────
    if node_type == "CallExpression":
        callee = node.get("callee", {})
        # Math.random()
        if (callee.get("type") == "MemberExpression"
                and callee.get("object", {}).get("name") == "Math"
                and callee.get("property", {}).get("name") == "random"):
            loc = node.get("loc", {}).get("start", {})
            findings_cb("JS-RAND-001", loc.get("line", 0), "Math.random()")

        # crypto.createCipher()
        if (callee.get("type") == "MemberExpression"
                and callee.get("object", {}).get("name") == "crypto"
                and callee.get("property", {}).get("name") == "createCipher"):
            loc = node.get("loc", {}).get("start", {})
            findings_cb("JS-NODE-001", loc.get("line", 0), "crypto.createCipher()")

        # eval()
        if callee.get("name") == "eval":
            loc = node.get("loc", {}).get("start", {})
            findings_cb("JS-EVAL-001", loc.get("line", 0), "eval()")

    # ── Literal strings ───────────────────────────────────────
    if node_type == "Literal":
        val = str(node.get("value", ""))
        loc = node.get("loc", {}).get("start", {})
        line = loc.get("line", 0)

        checks = {
            "RSA-OAEP": "JS-RSA-001", "RSA-PSS": "JS-RSA-001",
            "RSASSA-PKCS1-v1_5": "JS-RSA-001",
            "ECDH": "JS-ECC-001", "ECDSA": "JS-ECC-001",
            "P-256": "JS-ECC-001", "P-384": "JS-ECC-001",
            "P-521": "JS-ECC-001", "Ed25519": "JS-ECC-001",
            "SHA-1": "JS-SHA1-001",
            "DES-CBC": "JS-DES-001",
            "rc4": "JS-RC4-001", "RC4": "JS-RC4-001",
            "none": None,  # checked below with context
        }
        for pattern, rule_id in checks.items():
            if val == pattern and rule_id:
                findings_cb(rule_id, line, f'"{val}"')

    # ── Property: algorithm: 'none' / 'HS256' ─────────────────
    if node_type == "Property":
        key = node.get("key", {})
        val_node = node.get("value", {})
        key_name = key.get("name") or key.get("value", "")
        val_str = str(val_node.get("value", ""))
        loc = node.get("loc", {}).get("start", {})
        line = loc.get("line", 0)

        if key_name in ("algorithm", "alg"):
            if val_str == "none":
                findings_cb("JS-JWT-001", line, f'algorithm: "{val_str}"')
            elif val_str == "HS256":
                findings_cb("JS-JWT-002", line, f'algorithm: "{val_str}"')

        if key_name == "extractable" and val_node.get("value") is True:
            findings_cb("JS-WEBCRYPTO-001", line, "extractable: true")

        if key_name == "length" and val_node.get("value") == 128:
            findings_cb("JS-AES-001", line, "length: 128")

    # Recurse into all child nodes
    for value in node.values():
        if isinstance(value, dict):
            _walk_ast(value, findings_cb, source_lines)
        elif isinstance(value, list):
            for item in value:
                _walk_ast(item, findings_cb, source_lines)


# ─────────────────────────────────────────────────────────────
# REGEX FALLBACK SCANNER
# ─────────────────────────────────────────────────────────────

def _regex_scan(source: str, rule_ids_seen: set) -> list[dict]:
    """
    Run all regex patterns and return raw hits as
    {"rule_id", "line_no", "code_snippet"} dicts.
    Skips rule IDs already found by AST walk.
    """
    hits = []
    lines = source.splitlines()
    for rule in RULES:
        if rule["id"] in rule_ids_seen:
            continue
        pattern = re.compile(rule["regex_pattern"])
        for i, line in enumerate(lines, start=1):
            if pattern.search(line):
                hits.append({
                    "rule_id": rule["id"],
                    "line_no": i,
                    "code_snippet": line.strip()[:200],
                })
    return hits


# ─────────────────────────────────────────────────────────────
# PUBLIC ENTRY POINT
# ─────────────────────────────────────────────────────────────

def scan_js_file(filepath: str) -> list[dict]:
    """
    Scan a single JS/TS file for quantum-vulnerable crypto patterns.
    Returns a list of finding dicts compatible with QuantumGuard's
    existing scan_directory() output format.
    """
    try:
        with open(filepath, "r", encoding="utf-8", errors="replace") as f:
            source = f.read()
    except OSError:
        return []

    if not source.strip():
        return []

    rule_map = {r["id"]: r for r in RULES}
    raw_hits: list[dict] = []          # {"rule_id", "line_no", "code_snippet"}
    ast_rule_ids_found: set = set()
    source_lines = source.splitlines()

    # ── 1. AST walk (best effort) ────────────────────────────
    if AST_AVAILABLE:
        try:
            tree = pyjsparser.parse(source)

            def on_finding(rule_id: str, line_no: int, snippet: str):
                ast_rule_ids_found.add(rule_id)
                raw_hits.append({
                    "rule_id": rule_id,
                    "line_no": line_no,
                    "code_snippet": snippet[:200],
                })

            _walk_ast(tree, on_finding, source_lines)
        except Exception:
            # Parse error — fall through to regex-only
            pass

    # ── 2. Regex pass (catches what AST misses / parse fails) ─
    regex_hits = _regex_scan(source, ast_rule_ids_found)
    raw_hits.extend(regex_hits)

    # ── 3. Deduplicate by (rule_id, line_no) ─────────────────
    seen = set()
    deduped = []
    for h in raw_hits:
        key = (h["rule_id"], h["line_no"])
        if key not in seen:
            seen.add(key)
            deduped.append(h)

    # ── 4. Build QuantumGuard finding dicts ──────────────────
    findings = []
    rel_path = os.path.basename(filepath)

    for hit in deduped:
        rule = rule_map.get(hit["rule_id"])
        if not rule:
            continue

        # Grab full source line for context
        line_no = hit["line_no"]
        code_line = ""
        if 0 < line_no <= len(source_lines):
            code_line = source_lines[line_no - 1].strip()[:300]

        findings.append({
            "file": filepath,
            "line": line_no,
            "code": code_line or hit["code_snippet"],
            "vulnerability": rule["vulnerability"],
            "severity": rule["severity"],
            "confidence": rule["confidence"],
            "risk_explanation": rule["risk_explanation"],
            "replacement": rule["replacement"],
            "nist_ref": rule["nist_ref"],
            "rule_id": rule["id"],
            "scanner": "js-ast" if rule["id"] in ast_rule_ids_found else "js-regex",
            "language": _detect_language(filepath),
        })

    return findings


def scan_js_directory(directory: str) -> list[dict]:
    """
    Walk a directory and scan all JS/TS files.
    Called by scan_directory() in scan.py.
    """
    findings = []
    for root, _, files in os.walk(directory):
        # Skip node_modules, dist, .next, build folders
        skip_dirs = {"node_modules", "dist", ".next", "build", ".git", "__pycache__", ".cache"}
        root_parts = set(root.replace("\\", "/").split("/"))
        if root_parts & skip_dirs:
            continue

        for fname in files:
            ext = os.path.splitext(fname)[1].lower()
            if ext in JS_EXTENSIONS:
                fpath = os.path.join(root, fname)
                findings.extend(scan_js_file(fpath))

    return findings


def _detect_language(filepath: str) -> str:
    ext = os.path.splitext(filepath)[1].lower()
    return {
        ".ts": "TypeScript", ".tsx": "TypeScript",
        ".jsx": "JavaScript (JSX)",
        ".mjs": "JavaScript (ESM)", ".cjs": "JavaScript (CJS)",
    }.get(ext, "JavaScript")
