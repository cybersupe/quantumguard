# ============================================================
# QuantumGuard — JavaScript AST Scanner v3.1
# Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI
# Licensed under AGPL v3 — github.com/cybersupe/quantumguard
# ============================================================
#
# v3.1 changes vs v3.0:
#   FIX-1  JS-SECRET-001: Tightened regex to require long values.
#          Previous pattern matched 'password: "required"' in Joi/Yup
#          validation schemas and 'secret: "must be set"' in error strings.
#          Now requires 16+ char values and excludes obvious non-secrets.
#   FIX-2  JS-JWT-001: Removed jwt.decode() without .verify() pattern.
#          This was firing on every jwt.decode() call in code, including
#          legitimate usage. The "no algorithms" check belongs in ast_scanner.
#   FIX-3  Added inline nosec/noqa suppression support.
#   FIX-4  Improved comment detection — multi-line block comment lines
#          starting with * are now correctly skipped.
# ============================================================

import re
import os
from typing import List, Dict, Any

JS_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", ".cache",
    "coverage", ".nyc_output", "vendor", "__pycache__",
    "bower_components", "jspm_packages",
}

TEST_PATH_INDICATORS = [
    "test", "tests", "spec", "mock", "mocks",
    "example", "examples", "fixture", "fixtures",
    "demo", "demos", "sample", "samples",
]

SECURITY_KEYWORDS = [
    "key", "token", "secret", "password", "auth", "jwt",
    "crypto", "encrypt", "decrypt", "hash", "sign", "nonce",
    "salt", "iv", "session", "otp", "csrf",
]

MAX_LINE_LENGTH = 500

# Suppression markers — skip lines with these comments
SUPPRESSION_MARKERS = ["// nosec", "// noqa", "/* nosec */", "/* noqa */"]


def is_security_context(line: str) -> bool:
    line_lower = line.lower()
    return any(k in line_lower for k in SECURITY_KEYWORDS)


def is_test_file(path: str) -> bool:
    path_lower = path.lower().replace("\\", "/")
    parts = path_lower.split("/")
    for part in parts:
        for indicator in TEST_PATH_INDICATORS:
            if indicator == part or part.startswith(indicator + "_") or part.endswith("_" + indicator):
                return True
    return False


def is_suppressed(line: str) -> bool:
    """FIX-3: Check if line has an inline suppression comment."""
    line_lower = line.lower()
    return any(marker in line_lower for marker in SUPPRESSION_MARKERS)


# ── Rules ──────────────────────────────────────────────────
# require_context=True  → only flag when line has crypto keyword
# require_context=False → always flag (these are always bad)

RULES = [
    # ── RSA ──────────────────────────────────────────────────
    {
        "id":             "JS-RSA-001",
        "vulnerability":  "RSA",
        "severity":       "CRITICAL",
        "confidence":     "HIGH",
        "replacement":    "Plan migration to hybrid PQC (ML-KEM FIPS 203)",
        "require_context": False,
        "regex": r"(?:new\s+NodeRSA\b|RSA\.generate\s*\(|generateKeyPairSync\s*\(\s*['\"]rsa['\"]|crypto\.publicEncrypt\s*\(|crypto\.privateDecrypt\s*\(|forge\.pki\.rsa\.|RSA-OAEP|RSA-PSS)",
    },
    # ── ECC ──────────────────────────────────────────────────
    {
        "id":             "JS-ECC-001",
        "vulnerability":  "ECC",
        "severity":       "CRITICAL",
        "confidence":     "HIGH",
        "replacement":    "Plan migration to hybrid PQC (ML-DSA FIPS 204)",
        "require_context": False,
        "regex": r"(?:createECDH\s*\(|generateKeyPairSync\s*\(\s*['\"]ec['\"]|elliptic\.ec\s*\(|secp256k1|prime256v1|\bECDSA\b|\bECDH\b)",
    },
    # ── MD5 ──────────────────────────────────────────────────
    {
        "id":             "JS-MD5-001",
        "vulnerability":  "MD5",
        "severity":       "MEDIUM",
        "confidence":     "HIGH",
        "replacement":    "Replace with SHA-256 or SHA-3",
        "require_context": False,
        "regex": r"(?:createHash\s*\(\s*['\"]md5['\"]|require\s*\(\s*['\"]md5['\"]|\bnew\s+MD5\s*\(|\.md5\s*\()",
    },
    # ── SHA-1 ─────────────────────────────────────────────────
    {
        "id":             "JS-SHA1-001",
        "vulnerability":  "SHA1",
        "severity":       "MEDIUM",
        "confidence":     "HIGH",
        "replacement":    "Replace with SHA-256 or SHA-3",
        "require_context": False,
        "regex": r"(?:createHash\s*\(\s*['\"]sha1['\"]|require\s*\(\s*['\"]sha1['\"]|\bnew\s+SHA1\s*\(|\.sha1\s*\()",
    },
    # ── DES ──────────────────────────────────────────────────
    {
        "id":             "JS-DES-001",
        "vulnerability":  "DES",
        "severity":       "CRITICAL",
        "confidence":     "HIGH",
        "replacement":    "Replace with AES-256-GCM or ChaCha20-Poly1305",
        "require_context": False,
        "regex": r"(?:createCipheriv\s*\(\s*['\"]des|CryptoJS\.DES\b|\bTripleDES\b|\bDESede\b)",
    },
    # ── RC4 ──────────────────────────────────────────────────
    {
        "id":             "JS-RC4-001",
        "vulnerability":  "RC4",
        "severity":       "CRITICAL",
        "confidence":     "HIGH",
        "replacement":    "Replace with AES-256-GCM or ChaCha20-Poly1305",
        "require_context": False,
        "regex": r"(?:createCipheriv\s*\(\s*['\"]rc4|CryptoJS\.RC4\b|\bARC4\b)",
    },
    # ── JWT none algorithm ────────────────────────────────────
    # FIX-2: Removed the "jwt.decode() without .verify()" pattern.
    # That pattern was firing on all legitimate jwt.decode() calls.
    # Only flag explicit algorithm=none or verify:false.
    {
        "id":             "JS-JWT-001",
        "vulnerability":  "JWT_NONE_ALG",
        "severity":       "CRITICAL",
        "confidence":     "HIGH",
        "replacement":    "Always verify JWT signature; never use algorithm=none",
        "require_context": False,
        "regex": r"(?:algorithm\s*:\s*['\"]none['\"]|algorithms\s*:\s*\[['\"]none['\"]|\bverify\s*:\s*false\b)",
    },
    # ── Weak TLS ─────────────────────────────────────────────
    {
        "id":             "JS-TLS-001",
        "vulnerability":  "WEAK_TLS",
        "severity":       "HIGH",
        "confidence":     "HIGH",
        "replacement":    "Use TLS 1.3 minimum; remove rejectUnauthorized:false",
        "require_context": False,
        "regex": r"(?:rejectUnauthorized\s*:\s*false|secureProtocol\s*:\s*['\"](?:SSLv2|SSLv3|TLSv1)['\"]|minVersion\s*:\s*['\"]TLSv1(?:\.0|\.1)?['\"])",
    },
    # ── Hardcoded secrets ─────────────────────────────────────
    # FIX-1: Require 16+ char values. Exclude obvious non-secrets.
    # This eliminates false positives from validation schemas and error messages.
    {
        "id":             "JS-SECRET-001",
        "vulnerability":  "HARDCODED_SECRET",
        "severity":       "HIGH",
        "confidence":     "MEDIUM",
        "replacement":    "Move secrets to environment variables or a secrets manager",
        "require_context": False,
        "regex": r"(?:(?:secret|password|api_key|apikey|private_key|signing_key|jwt_secret)\s*[:=]\s*['\"][^'\"]{16,}['\"])",
    },
    # PEM private key blocks — unambiguous
    {
        "id":             "JS-SECRET-002",
        "vulnerability":  "HARDCODED_SECRET",
        "severity":       "CRITICAL",
        "confidence":     "HIGH",
        "replacement":    "Move private keys to a secrets manager or HSM",
        "require_context": False,
        "regex": r"-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+)?PRIVATE\s+KEY-----",
    },
    # ── Weak random in crypto context ─────────────────────────
    {
        "id":             "JS-RAND-001",
        "vulnerability":  "WEAK_RANDOM",
        "severity":       "MEDIUM",
        "confidence":     "HIGH",
        "replacement":    "Use crypto.getRandomValues() or crypto.randomBytes()",
        "require_context": True,  # Only flag in crypto/auth context
        "regex": r"\bMath\.random\s*\(",
    },
]

# Values that look like secrets but are clearly placeholders
SECRET_ALLOWLIST = [
    r"(?i)(example|sample|test|fake|dummy|placeholder|your[-_]?|<[^>]+>|\.\.\.|xxx|required|invalid|wrong)",
    r"process\.env\.",
    r"(?i)process\.env",
]


def _is_allowlisted_secret(line: str) -> bool:
    for pattern in SECRET_ALLOWLIST:
        if re.search(pattern, line):
            return True
    return False


def _make_finding(filepath: str, line_no: int, code: str, rule: Dict, is_test: bool) -> Dict:
    severity   = rule["severity"]
    confidence = rule["confidence"]

    if is_test:
        if severity == "CRITICAL":
            severity = "HIGH"
        if confidence == "HIGH":
            confidence = "MEDIUM"

    return {
        "file":               filepath,
        "line":               line_no,
        "code":               code.strip(),
        "vulnerability":      rule["vulnerability"],
        "severity":           severity,
        "confidence":         confidence,
        "replacement":        rule["replacement"],
        "risk_explanation":   f"{rule['vulnerability']} detected in JavaScript/TypeScript code.",
        "recommended_fix":    rule["replacement"],
        "migration_priority": "URGENT — Fix within 30 days" if severity == "CRITICAL" else "HIGH — Fix within 90 days",
        "detection_method":   "JS_REGEX",
        "is_test_file":       is_test,
        "language":           "JavaScript",
    }


def scan_js_file(filepath: str) -> List[Dict]:
    findings  = []
    test_file = is_test_file(filepath)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return []

    seen = set()  # (line_no, vulnerability) — deduplicate

    for line_no, line in enumerate(lines, start=1):
        # Skip minified / very long lines
        if len(line) > MAX_LINE_LENGTH:
            continue

        stripped = line.strip()

        # FIX-4: Skip comment lines (single-line and block comment lines)
        if (stripped.startswith("//") or
                stripped.startswith("*") or
                stripped.startswith("/*") or
                stripped.startswith("*/")):
            continue

        # FIX-3: Skip suppressed lines
        if is_suppressed(line):
            continue

        for rule in RULES:
            # Apply context gate if required
            if rule["require_context"] and not is_security_context(line):
                continue

            try:
                if not re.search(rule["regex"], line, re.IGNORECASE):
                    continue

                # Allowlist check for secrets
                if rule["id"].startswith("JS-SECRET") and _is_allowlisted_secret(line):
                    continue

                key = (line_no, rule["vulnerability"])
                if key not in seen:
                    seen.add(key)
                    findings.append(_make_finding(filepath, line_no, line, rule, test_file))

            except re.error:
                continue

    return findings


def scan_js_directory(directory: str) -> List[Dict]:
    results = []

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for f in files:
            if os.path.splitext(f)[1].lower() in JS_EXTENSIONS:
                filepath = os.path.join(root, f)
                results.extend(scan_js_file(filepath))

    return results
