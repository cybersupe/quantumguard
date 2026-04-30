# ============================================================
# QuantumGuard — JavaScript AST Scanner v3.0
# Fixed: removed is_security_context() gate on crypto rules
# Math.random() still requires security context (too noisy otherwise)
# ============================================================

import re
import os
from typing import List, Dict, Any

try:
    import pyjsparser
    AST_AVAILABLE = True
except ImportError:
    AST_AVAILABLE = False

JS_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}

SKIP_DIRS = {
    "node_modules", ".git", "dist", "build", ".cache",
    "coverage", ".nyc_output", "vendor", "__pycache__",
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


# ── Rules ──────────────────────────────────────────────────
# require_context=True  → only flag when line has crypto keyword
# require_context=False → always flag (these are always bad)

RULES = [
    # ── Always flag (no context needed) ──
    {
        "id": "JS-RSA-001",
        "vulnerability": "RSA",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "replacement": "Plan migration to hybrid PQC (ML-KEM FIPS 203)",
        "require_context": False,
        "regex": r"(?:new\s+NodeRSA|RSA\.generate|generateKeyPairSync\s*\(\s*['\"]rsa['\"]|crypto\.publicEncrypt|crypto\.privateDecrypt|forge\.pki\.rsa|RSA-OAEP|RSA-PSS)",
    },
    {
        "id": "JS-ECC-001",
        "vulnerability": "ECC",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "replacement": "Plan migration to hybrid PQC (ML-DSA FIPS 204)",
        "require_context": False,
        "regex": r"(?:createECDH|generateKeyPairSync\s*\(\s*['\"]ec['\"]|elliptic\.ec|secp256k1|prime256v1|ECDH|ECDSA)",
    },
    {
        "id": "JS-MD5-001",
        "vulnerability": "MD5",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "replacement": "Replace with SHA-256 or SHA-3",
        "require_context": False,
        "regex": r"(?:createHash\s*\(\s*['\"]md5['\"]|require\s*\(\s*['\"]md5['\"]|new\s+MD5\s*\(|\.md5\s*\()",
    },
    {
        "id": "JS-SHA1-001",
        "vulnerability": "SHA1",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "replacement": "Replace with SHA-256 or SHA-3",
        "require_context": False,
        "regex": r"(?:createHash\s*\(\s*['\"]sha1['\"]|require\s*\(\s*['\"]sha1['\"]|new\s+SHA1\s*\(|\.sha1\s*\()",
    },
    {
        "id": "JS-DES-001",
        "vulnerability": "DES",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "replacement": "Replace with AES-256-GCM or ChaCha20-Poly1305",
        "require_context": False,
        "regex": r"(?:createCipheriv\s*\(\s*['\"]des|CryptoJS\.DES|TripleDES|DESede)",
    },
    {
        "id": "JS-RC4-001",
        "vulnerability": "RC4",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "replacement": "Replace with AES-256-GCM or ChaCha20-Poly1305",
        "require_context": False,
        "regex": r"(?:createCipheriv\s*\(\s*['\"]rc4|CryptoJS\.RC4|ARC4)",
    },
    {
        "id": "JS-JWT-001",
        "vulnerability": "JWT_NONE_ALG",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "replacement": "Always verify JWT signature; never use algorithm=none",
        "require_context": False,
        "regex": r"(?:algorithm\s*:\s*['\"]none['\"]|verify\s*:\s*false|jwt\.decode\s*\([^)]*\)(?!\s*\.\s*verify))",
    },
    {
        "id": "JS-TLS-001",
        "vulnerability": "WEAK_TLS",
        "severity": "HIGH",
        "confidence": "HIGH",
        "replacement": "Use TLS 1.3 minimum; remove rejectUnauthorized:false",
        "require_context": False,
        "regex": r"(?:rejectUnauthorized\s*:\s*false|secureProtocol\s*:\s*['\"](?:SSLv2|SSLv3|TLSv1)['\"]|minVersion\s*:\s*['\"]TLSv1(?:\.0|\.1)?['\"])",
    },
    {
        "id": "JS-SECRET-001",
        "vulnerability": "HARDCODED_SECRET",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "replacement": "Move secrets to environment variables or a secrets manager",
        "require_context": False,
        "regex": r"(?:(?:secret|password|api_key|apikey|private_key)\s*[:=]\s*['\"][^'\"]{8,}['\"])",
    },
    # ── Only flag in security context ──
    {
        "id": "JS-RAND-001",
        "vulnerability": "WEAK_RANDOM",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "replacement": "Use crypto.getRandomValues() or crypto.randomBytes()",
        "require_context": True,
        "regex": r"\bMath\.random\s*\(",
    },
]


def _make_finding(filepath: str, line_no: int, code: str, rule: Dict, is_test: bool) -> Dict:
    severity = rule["severity"]
    confidence = rule["confidence"]

    if is_test:
        if severity == "CRITICAL":
            severity = "HIGH"
        if confidence == "HIGH":
            confidence = "MEDIUM"

    return {
        "file": filepath,
        "line": line_no,
        "code": code.strip(),
        "vulnerability": rule["vulnerability"],
        "severity": severity,
        "confidence": confidence,
        "replacement": rule["replacement"],
        "risk_explanation": f"{rule['vulnerability']} detected in JavaScript/TypeScript code.",
        "recommended_fix": rule["replacement"],
        "migration_priority": "URGENT — Fix within 30 days" if severity == "CRITICAL" else "HIGH — Fix within 90 days",
        "detection_method": "JS_REGEX",
        "is_test_file": is_test,
        "language": "JavaScript",
    }


def scan_js_file(filepath: str) -> List[Dict]:
    findings = []
    test_file = is_test_file(filepath)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
    except Exception:
        return []

    seen = set()  # (line_no, vulnerability) — deduplicate

    for line_no, line in enumerate(lines, start=1):
        # Skip minified lines
        if len(line) > MAX_LINE_LENGTH:
            continue

        # Skip pure comment lines
        stripped = line.strip()
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            continue

        for rule in RULES:
            # Apply context gate if required
            if rule["require_context"] and not is_security_context(line):
                continue

            try:
                if re.search(rule["regex"], line, re.IGNORECASE):
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
        # Skip irrelevant dirs in-place
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for f in files:
            if os.path.splitext(f)[1] in JS_EXTENSIONS:
                filepath = os.path.join(root, f)
                results.extend(scan_js_file(filepath))

    return results
