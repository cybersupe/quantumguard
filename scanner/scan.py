# ============================================================
# QuantumGuard — Core Scanner v3.0  (Enterprise Edition)
# Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI
# Licensed under AGPL v3 — github.com/cybersupe/quantumguard
# Standards: NIST FIPS 203, FIPS 204, FIPS 205
# ============================================================
#
# v3.0 — Enterprise upgrade:
#   PHASE 1  Context-aware detection + variable data-flow tracking
#   PHASE 2  Numeric confidence scoring (0-1) replacing LOW/MEDIUM/HIGH
#   PHASE 3  Library noise elimination (vendor/, dist/, setup.py, etc.)
#   PHASE 4  Smart grouping by (rule_id + root_cause + file_group)
#   PHASE 5  Executive risk layer (business_impact, exploitability, priority)
#   PHASE 6  Score engine: linear deduction, unique findings, CRITICAL caps
#   PHASE 7  Clean repo detection with explicit message
# ============================================================

import os
import re
import math
import time
import json
from collections import defaultdict
from datetime import datetime
from typing import Dict, List, Any, Optional, Set, Tuple

from scanner.patterns import VULNERABLE_PATTERNS, SEVERITY_SCORE
from scanner.ast_scanner import scan_python_ast
from scanner.js_ast_scanner import scan_js_directory

# ── Directories always skipped ────────────────────────────────
SKIP_DIRS: Set[str] = {
    "venv", "node_modules", ".git", "__pycache__", ".tox",
    "dist", "build", ".eggs", "htmlcov", ".mypy_cache",
    "vendor", "third_party", "thirdparty", "extern", "external",
    "deps", "dependencies", ".cache", "coverage", ".nyc_output",
    "bower_components", "jspm_packages", "target", "out",
}

# PHASE 3: Library / generated / vendor path indicators
LIBRARY_PATH_INDICATORS: Set[str] = {
    "vendor", "vendors", "third_party", "thirdparty", "extern",
    "external", "deps", "dependencies", "node_modules",
    "dist", "build", "out", "target", "generated", "gen",
    "bower_components", "jspm_packages", "site-packages",
    "lib", "libs",
}

# PHASE 3: Library filenames
LIBRARY_FILENAMES: Set[str] = {
    "setup.py", "setup.cfg", "pyproject.toml",
    "webpack.config.js", "rollup.config.js", "vite.config.js",
    "babel.config.js", ".babelrc",
}

# Crypto implementation files — patterns suggesting the file IS a crypto library
CRYPTO_IMPL_PATTERNS = [
    r"This file is part of (OpenSSL|LibreSSL|BoringSSL|libsodium|PyCryptodome)",
    r"@license\s+(MIT|BSD|Apache)\s+crypto",
    r"Copyright\s+.*\s+(OpenSSL|RSA Security|PGP)",
    r"BEGIN CERTIFICATE|BEGIN RSA PRIVATE KEY",
]

TEST_PATH_INDICATORS: Set[str] = {
    "test", "tests", "spec", "docs", "documentation",
    "example", "examples", "fixture", "fixtures", "mock", "mocks",
    "sample", "samples", "demo", "demos", "tutorial", "tutorials",
}

# PHASE 1: Context classification keywords
AUTH_KEYWORDS    = {"auth", "login", "logout", "password", "passwd", "credential",
                    "session", "token", "jwt", "oauth", "bearer", "apikey", "api_key"}
CRYPTO_KEYWORDS  = {"encrypt", "decrypt", "cipher", "hash", "hmac", "sign", "verify",
                    "digest", "key", "nonce", "iv", "salt", "secret", "kdf", "pbkdf"}
SESSION_KEYWORDS = {"session", "cookie", "csrf", "otp", "2fa", "mfa", "totp"}
UI_KEYWORDS      = {"render", "component", "style", "animation", "css", "html",
                    "template", "view", "layout", "page", "ui", "display"}

# PHASE 5: Executive priority rules
PRIORITY_RULES = {
    "RC4":              {"priority": "P0", "exploitability": "EASY",     "business_impact": "HIGH"},
    "MD4":              {"priority": "P0", "exploitability": "EASY",     "business_impact": "HIGH"},
    "HARDCODED_SECRET": {"priority": "P0", "exploitability": "EASY",     "business_impact": "HIGH"},
    "JWT_NONE_ALG":     {"priority": "P0", "exploitability": "EASY",     "business_impact": "HIGH"},
    "DES":              {"priority": "P0", "exploitability": "EASY",     "business_impact": "HIGH"},
    "RSA":              {"priority": "P1", "exploitability": "MODERATE",  "business_impact": "HIGH"},
    "ECC":              {"priority": "P1", "exploitability": "MODERATE",  "business_impact": "HIGH"},
    "DH":               {"priority": "P1", "exploitability": "MODERATE",  "business_impact": "HIGH"},
    "DSA":              {"priority": "P1", "exploitability": "MODERATE",  "business_impact": "HIGH"},
    "WEAK_RANDOM":      {"priority": "P1", "exploitability": "MODERATE",  "business_impact": "MEDIUM"},
    "WEAK_TLS":         {"priority": "P1", "exploitability": "MODERATE",  "business_impact": "HIGH"},
    "ECB_MODE":         {"priority": "P1", "exploitability": "MODERATE",  "business_impact": "MEDIUM"},
    "WEAK_KEY_SIZE":    {"priority": "P1", "exploitability": "MODERATE",  "business_impact": "HIGH"},
    "BLOWFISH":         {"priority": "P1", "exploitability": "MODERATE",  "business_impact": "MEDIUM"},
    "MD5":              {"priority": "P2", "exploitability": "HARD",      "business_impact": "MEDIUM"},
    "SHA1":             {"priority": "P2", "exploitability": "HARD",      "business_impact": "MEDIUM"},
    "SHA256_SIGNED":    {"priority": "P2", "exploitability": "HARD",      "business_impact": "LOW"},
}

JS_EXTENSIONS  = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}
SUPPORTED_EXTENSIONS = (
    ".py", ".java", ".go",
    ".rs", ".c", ".cpp", ".cc", ".h", ".hpp",
)
MAX_FILES       = 200
MAX_LINE_LENGTH = 500

HARDCODED_SECRET_ALLOWLIST = [
    r"(?i)(example|sample|test|fake|dummy|placeholder|your[-_]?|<[^>]+>|\.\.\.|xxx)",
    r"(?i)password\s*=\s*['\"](?:password|pass|test|admin|secret|changeme|letmein|123|abc|required|invalid|wrong|correct|empty)['\"]",
    r"(?i)(?:os\.environ|process\.env|getenv|config\[|settings\.)",
    r"#\s*noqa", r"#\s*nosec", r"//\s*nosec",
]


# ══════════════════════════════════════════════════════════════
# PHASE 1: Context classification
# ══════════════════════════════════════════════════════════════

def classify_context(filepath: str, line: str, surrounding_lines: List[str]) -> str:
    """
    Classify the usage context of a finding.
    Returns: "auth" | "crypto" | "session" | "ui" | "test" | "unknown"
    """
    path_lower = filepath.lower().replace("\\", "/")
    combined   = (line + " ".join(surrounding_lines)).lower()

    # Test file → test context
    for part in path_lower.split("/"):
        if part in TEST_PATH_INDICATORS:
            return "test"

    # Path-based classification
    if any(k in path_lower for k in ("auth", "login", "session", "jwt", "token", "oauth")):
        return "auth"
    if any(k in path_lower for k in ("crypto", "cipher", "encrypt", "hash", "sign", "key")):
        return "crypto"
    if any(k in path_lower for k in ("session", "cookie", "otp", "csrf")):
        return "session"
    if any(k in path_lower for k in ("component", "view", "page", "ui", "layout", "style")):
        return "ui"

    # Line content-based classification
    if any(k in combined for k in AUTH_KEYWORDS):
        return "auth"
    if any(k in combined for k in CRYPTO_KEYWORDS):
        return "crypto"
    if any(k in combined for k in SESSION_KEYWORDS):
        return "session"
    if any(k in combined for k in UI_KEYWORDS):
        return "ui"

    return "unknown"


# ══════════════════════════════════════════════════════════════
# PHASE 2: Numeric confidence engine
# ══════════════════════════════════════════════════════════════

def compute_confidence_score(
    line: str,
    filepath: str,
    usage_context: str,
    is_test: bool,
    is_library: bool,
    is_comment: bool,
    is_used_in_sensitive_call: bool = False,
) -> Tuple[float, str]:
    """
    Compute a numeric confidence score (0.0 – 1.0).

    Formula:
      base_rule       = 0.5   (pattern matched)
      runtime_usage   = +0.3  (variable is actually used in a sensitive call)
      entropy_bonus   = +0.2  (auth/crypto/session context)
      test_penalty    = -0.3
      doc_penalty     = -0.4  (comment or docstring line)
      config_penalty  = -0.2  (setup.py / config file)

    Mapping:
      > 0.8  → HIGH
      0.5–0.8 → MEDIUM
      < 0.5  → LOW

    Returns (score: float, label: str)
    """
    score = 0.5  # base

    # Runtime usage bonus
    if is_used_in_sensitive_call:
        score += 0.3

    # Context entropy bonus
    if usage_context in ("auth", "crypto", "session"):
        score += 0.2
    elif usage_context == "ui":
        score -= 0.15

    # Penalties
    if is_test:
        score -= 0.3
    if is_comment:
        score -= 0.4
    if is_library:
        score -= 0.4

    # Config file penalty
    filename = os.path.basename(filepath).lower()
    if filename in LIBRARY_FILENAMES or filename.endswith((".cfg", ".ini", ".conf")):
        score -= 0.2

    score = max(0.0, min(1.0, score))

    if score > 0.8:
        label = "HIGH"
    elif score >= 0.5:
        label = "MEDIUM"
    else:
        label = "LOW"

    return round(score, 3), label


# ══════════════════════════════════════════════════════════════
# PHASE 3: Library detection
# ══════════════════════════════════════════════════════════════

def is_library_file(filepath: str, code: str = "") -> bool:
    """
    Return True if this file is part of a library, vendor bundle,
    generated output, or crypto implementation — not application code.
    """
    path_lower = filepath.lower().replace("\\", "/")
    parts      = path_lower.split("/")

    # Check directory components
    for part in parts:
        if part in LIBRARY_PATH_INDICATORS:
            return True

    # Check filename
    filename = os.path.basename(filepath).lower()
    if filename in LIBRARY_FILENAMES:
        return True

    # Check for .min.js / .bundle.js
    if re.search(r'\.(min|bundle|compiled|generated)\.(js|ts|css)$', filepath, re.I):
        return True

    # Check file content for library copyright headers
    if code:
        header = code[:1000]
        for pattern in CRYPTO_IMPL_PATTERNS:
            if re.search(pattern, header, re.IGNORECASE):
                return True

    return False


# ══════════════════════════════════════════════════════════════
# PHASE 1: Data-flow variable tracking
# ══════════════════════════════════════════════════════════════

SENSITIVE_CALL_PATTERNS = [
    # Auth/session usage
    r"\b(?:send|return|yield|response|reply|output|write|store|save|cache|set)\s*\(",
    r"\b(?:sign|encrypt|hash|digest|token|auth|session|cookie|header)\s*[\(=]",
    # Network/IO
    r"\b(?:requests?\.|fetch|http|socket|send_mail|smtp)\b",
    # Database
    r"\b(?:execute|query|insert|update|cursor)\s*\(",
]

def _line_uses_variable_sensitively(var_name: str, line: str) -> bool:
    """Return True if var_name appears in a sensitive call context on this line."""
    if var_name not in line:
        return False
    for pattern in SENSITIVE_CALL_PATTERNS:
        if re.search(pattern, line, re.IGNORECASE):
            return True
    return False


def build_variable_flow_map(lines: List[str], ext: str) -> Dict[str, Set[int]]:
    """
    Simple single-file data-flow: track variables assigned crypto values
    and return {var_name: set_of_line_numbers_where_used_sensitively}.

    Example:
      token = random.random()   → tracked
      send_token(token)         → sensitive use → HIGH risk
    """
    assigned: Dict[str, str] = {}   # {var_name: crypto_type}
    sensitive_uses: Dict[str, Set[int]] = defaultdict(set)

    CRYPTO_ASSIGNMENTS = {
        r"random\.random\s*\(\s*\)":      "WEAK_RANDOM",
        r"random\.randint\s*\(":          "WEAK_RANDOM",
        r"random\.choice\s*\(":           "WEAK_RANDOM",
        r"Math\.random\s*\(\s*\)":        "WEAK_RANDOM",
        r"hashlib\.md5\s*\(":             "MD5",
        r"hashlib\.sha1\s*\(":            "SHA1",
        r"RSA\.generate\s*\(":            "RSA",
        r"DES\.new\s*\(":                 "DES",
        r"ARC4\.new\s*\(":                "RC4",
    }

    # Simple assignment detection: var = <crypto_expr>
    assign_re = re.compile(r"^\s*(\w+)\s*=\s*(.+)$")

    for line_no, line in enumerate(lines, start=1):
        stripped = line.strip()
        m = assign_re.match(stripped)
        if m:
            var_name = m.group(1)
            rhs      = m.group(2)
            for pattern, crypto_type in CRYPTO_ASSIGNMENTS.items():
                if re.search(pattern, rhs, re.IGNORECASE):
                    assigned[var_name] = crypto_type
                    break

        # Check if any tracked variable is used sensitively on this line
        for var_name in list(assigned.keys()):
            if _line_uses_variable_sensitively(var_name, line):
                sensitive_uses[var_name].add(line_no)

    return sensitive_uses


# ══════════════════════════════════════════════════════════════
# PHASE 5: Executive risk layer
# ══════════════════════════════════════════════════════════════

def get_executive_risk(vuln_name: str, usage_context: str, confidence_label: str) -> Dict[str, str]:
    """Return business_impact, exploitability, priority for a finding."""
    # Exact match first, then prefix
    meta = PRIORITY_RULES.get(vuln_name)
    if not meta:
        for key in PRIORITY_RULES:
            if vuln_name.startswith(key):
                meta = PRIORITY_RULES[key]
                break
    if not meta:
        meta = {"priority": "P2", "exploitability": "HARD", "business_impact": "LOW"}

    # Upgrade priority if in auth/session context
    result = dict(meta)
    if usage_context in ("auth", "session") and result["priority"] == "P2":
        result["priority"] = "P1"
        result["business_impact"] = "HIGH"

    # LOW confidence → downgrade
    if confidence_label == "LOW":
        if result["priority"] == "P0":
            result["priority"] = "P1"
        result["business_impact"] = "LOW"

    return result


# ══════════════════════════════════════════════════════════════
# PHASE 4: Smart grouping
# ══════════════════════════════════════════════════════════════

ROOT_CAUSE_MAP = {
    "RSA":              "classical asymmetric key generation — quantum-vulnerable via Shor's algorithm",
    "ECC":              "elliptic curve key generation over NIST curves — quantum-vulnerable via Shor's algorithm",
    "DH":               "Diffie-Hellman key exchange — quantum-vulnerable via Shor's algorithm",
    "DSA":              "DSA signature scheme — quantum-vulnerable",
    "MD5":              "broken hash function — cryptographically compromised",
    "SHA1":             "deprecated hash function — collision attacks known",
    "RC4":              "broken stream cipher — multiple practical attacks",
    "DES":              "deprecated block cipher — insufficient key size",
    "ECB_MODE":         "ECB cipher mode — leaks plaintext patterns",
    "WEAK_TLS":         "outdated TLS/SSL version — known protocol vulnerabilities",
    "WEAK_KEY_SIZE":    "insufficient RSA key size — classically and quantum-breakable",
    "HARDCODED_SECRET": "secret credential in source code — exposed in version history",
    "WEAK_RANDOM":      "non-cryptographic RNG — predictable output",
    "JWT_NONE_ALG":     "JWT signature verification disabled — token forgery possible",
    "BLOWFISH":         "64-bit block cipher — birthday attack vulnerability",
    "MD4":              "completely broken hash function",
    "SHA256_SIGNED":    "SHA-256 with asymmetric signing — inherits quantum vulnerability",
}

def _get_root_cause(vuln_name: str) -> str:
    for key, cause in ROOT_CAUSE_MAP.items():
        if vuln_name == key or vuln_name.startswith(key):
            return cause
    return "cryptographic vulnerability requiring migration"


def _file_group(filepath: str) -> str:
    """Reduce a full path to its top-level application directory."""
    parts = filepath.replace("\\", "/").split("/")
    # Find the first non-trivial directory after common prefixes
    skip = {"", ".", "..", "src", "app", "lib", "main", "java", "python", "go"}
    for part in parts[:-1]:
        if part.lower() not in skip and not part.startswith("."):
            return part
    return parts[-1] if parts else "root"


def build_grouped_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    PHASE 4: Group findings by (vulnerability, root_cause, file_group).
    Returns a list of grouped finding dicts with occurrence counts.
    """
    groups: Dict[str, Dict[str, Any]] = {}

    for f in findings:
        # Skip LOW confidence from groups (too noisy)
        if f.get("confidence") == "LOW":
            continue

        vuln       = f.get("vulnerability", "UNKNOWN")
        root_cause = _get_root_cause(vuln)
        fg         = _file_group(f.get("file", ""))
        key        = f"{vuln}::{root_cause}::{fg}"

        if key not in groups:
            groups[key] = {
                "title":          f"{vuln} usage detected",
                "vulnerability":  vuln,
                "severity":       f.get("severity", "MEDIUM"),
                "confidence":     f.get("confidence", "MEDIUM"),
                "confidence_score": f.get("confidence_score", 0.5),
                "occurrences":    0,
                "affected_files": [],
                "root_cause":     root_cause,
                "replacement":    f.get("replacement", ""),
                "priority":       f.get("priority", "P2"),
                "business_impact": f.get("business_impact", "MEDIUM"),
                "exploitability":  f.get("exploitability", "MODERATE"),
            }

        g = groups[key]
        g["occurrences"] += 1
        fp = f.get("file", "")
        if fp and fp not in g["affected_files"]:
            g["affected_files"].append(fp)

        # Escalate severity to the highest seen in group
        sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
        if sev_rank.get(f.get("severity","LOW"), 1) > sev_rank.get(g["severity"], 1):
            g["severity"] = f.get("severity")

    return sorted(
        list(groups.values()),
        key=lambda x: {"CRITICAL":0,"HIGH":1,"MEDIUM":2,"LOW":3}.get(x["severity"],3)
    )


# ══════════════════════════════════════════════════════════════
# Helper: comment detection
# ══════════════════════════════════════════════════════════════

def _is_comment_line(line: str, ext: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return True
    if ext == ".py" and stripped.startswith("#"):
        return True
    if ext in (".js",".ts",".java",".go",".rs",".c",".cpp",".cc",".h",".hpp"):
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            return True
    if stripped.startswith("*") or stripped.startswith("*/"):
        return True
    if (stripped.startswith('"""') and stripped.endswith('"""') and len(stripped) > 6):
        return True
    return False


def _is_allowlisted_secret(line: str) -> bool:
    for pattern in HARDCODED_SECRET_ALLOWLIST:
        if re.search(pattern, line):
            return True
    return False


def _is_weak_random_in_crypto_context(line: str) -> bool:
    return any(kw in line.lower() for kw in (
        "key","token","secret","password","salt","nonce","iv","seed","session","auth","csrf","otp"
    ))


def _is_test_or_docs_path(filepath: str) -> bool:
    path_lower = filepath.lower().replace("\\", "/")
    for part in path_lower.split("/"):
        for indicator in TEST_PATH_INDICATORS:
            if indicator == part or part.startswith(indicator+"_") or part.endswith("_"+indicator):
                return True
    return False


def _get_risk_explanation(vuln_name: str) -> str:
    RISK_MAP = {
        "RSA":              "RSA will be broken by Shor's Algorithm on quantum computers. NIST deadline: 2030.",
        "ECC":              "Elliptic curve cryptography over NIST curves is vulnerable to Shor's Algorithm.",
        "DH":               "Diffie-Hellman key exchange is quantum-vulnerable via Shor's Algorithm.",
        "DSA":              "DSA signatures are broken by Shor's Algorithm on quantum hardware.",
        "MD5":              "MD5 is cryptographically broken. Grover's algorithm further weakens hash security.",
        "SHA1":             "SHA-1 is deprecated. Grover's algorithm halves effective security to ~80 bits.",
        "SHA256_SIGNED":    "SHA-256 with RSA/ECDSA signatures inherits the quantum vulnerability of the asymmetric component.",
        "RC4":              "RC4 is completely broken with multiple practical attacks.",
        "DES":              "DES/3DES are deprecated. Key sizes are insufficient even without quantum threats.",
        "ECB_MODE":         "ECB mode reveals patterns in encrypted data regardless of key strength.",
        "WEAK_TLS":         "Older TLS versions have known vulnerabilities. TLS 1.3 minimum is required.",
        "WEAK_KEY_SIZE":    "Small RSA/DH key sizes are breakable classically. Quantum computers accelerate this.",
        "HARDCODED_SECRET": "Hardcoded secrets are exposed in source code and version history.",
        "WEAK_RANDOM":      "Non-cryptographic random number generators are predictable.",
        "JWT_NONE_ALG":     "JWT with 'none' algorithm or disabled verification allows token forgery.",
        "BLOWFISH":         "Blowfish has a 64-bit block size making it vulnerable to birthday attacks.",
        "MD4":              "MD4 is completely broken and should never be used.",
    }
    for key in RISK_MAP:
        if vuln_name == key or vuln_name.startswith(key+"_") or vuln_name.startswith(key):
            return RISK_MAP[key]
    return "This algorithm is vulnerable to quantum or classical attacks. Migration required."


def _get_migration_priority(severity: str) -> str:
    return {
        "CRITICAL": "URGENT — Fix within 30 days",
        "HIGH":     "HIGH — Fix within 90 days",
        "MEDIUM":   "MEDIUM — Fix within 6 months",
    }.get(severity, "MEDIUM — Fix within 6 months")


def _deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen: Dict[tuple, Dict] = {}
    conf_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for f in findings:
        key = (f["file"], f["line"], f["vulnerability"])
        if key not in seen:
            seen[key] = f
        else:
            existing_score = seen[key].get("confidence_score", 0.5)
            new_score      = f.get("confidence_score", 0.5)
            if new_score > existing_score:
                seen[key] = f
    return list(seen.values())


# ══════════════════════════════════════════════════════════════
# Core file scanner
# ══════════════════════════════════════════════════════════════

def scan_file(filepath: str) -> List[Dict[str, Any]]:
    """
    Scan a single file for vulnerable crypto patterns.
    Applies all 7 phases per finding.
    """
    ext = os.path.splitext(filepath)[1].lower()
    if ext in JS_EXTENSIONS:
        return []   # handled by js_ast_scanner

    findings: List[Dict[str, Any]] = []
    is_test    = _is_test_or_docs_path(filepath)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines_raw = f.readlines()
        code = "".join(lines_raw)
        lines = [l.rstrip("\n") for l in lines_raw]
    except Exception as e:
        print(f"[QuantumGuard] Error reading {filepath}: {e}")
        return []

    # PHASE 3: Library detection
    is_lib = is_library_file(filepath, code)

    # PHASE 1: Build variable flow map for the file
    sensitive_uses = build_variable_flow_map(lines, ext)

    # ── Python AST scan ──────────────────────────────────────
    ast_lines_map: Dict[int, Set[str]] = {}
    if ext == ".py":
        ast_findings = scan_python_ast(code, filepath)
        for af in ast_findings:
            # Enrich AST findings with phase data
            lineno = af["line"]
            context_lines = lines[max(0,lineno-3):lineno+3]
            usage_ctx = classify_context(filepath, lines[lineno-1] if lineno<=len(lines) else "", context_lines)

            # Is this variable used sensitively?
            used_sensitively = any(
                lineno in lnos
                for var, lnos in sensitive_uses.items()
                if var in (lines[lineno-1] if lineno<=len(lines) else "")
            )

            conf_score, conf_label = compute_confidence_score(
                line=lines[lineno-1] if lineno<=len(lines) else "",
                filepath=filepath,
                usage_context=usage_ctx,
                is_test=is_test,
                is_library=is_lib,
                is_comment=False,
                is_used_in_sensitive_call=used_sensitively,
            )
            exec_risk = get_executive_risk(af["vulnerability"], usage_ctx, conf_label)

            af["confidence_score"]  = conf_score
            af["confidence"]        = conf_label
            af["usage_context"]     = usage_ctx
            af["priority"]          = exec_risk["priority"]
            af["business_impact"]   = exec_risk["business_impact"]
            af["exploitability"]    = exec_risk["exploitability"]
            af["is_library_file"]   = is_lib

            findings.append(af)
            ast_lines_map.setdefault(lineno, set()).add(af["vulnerability"])

    # ── Regex scan ───────────────────────────────────────────
    for line_no, line in enumerate(lines, start=1):
        if len(line) > MAX_LINE_LENGTH:
            continue

        is_comment = _is_comment_line(line, ext)

        # Get surrounding context for classification
        ctx_start = max(0, line_no - 4)
        ctx_end   = min(len(lines), line_no + 3)
        context_lines = lines[ctx_start:ctx_end]

        usage_ctx = classify_context(filepath, line, context_lines)

        # Check if this line number is a sensitive use of a tracked variable
        used_sensitively = any(line_no in lnos for lnos in sensitive_uses.values())

        for vuln_name, vuln_data in VULNERABLE_PATTERNS.items():
            # WEAK_RANDOM gates
            if vuln_name == "WEAK_RANDOM":
                if usage_ctx == "ui":
                    continue
                if not _is_weak_random_in_crypto_context(line):
                    continue

            patterns = vuln_data.get("patterns", [])
            for pattern in patterns:
                try:
                    if not re.search(pattern, line, re.IGNORECASE if "(?i)" not in pattern else 0):
                        continue

                    # Skip if already found by AST
                    if ext == ".py":
                        ast_vulns = ast_lines_map.get(line_no, set())
                        if vuln_name in ast_vulns:
                            break

                    if vuln_name == "HARDCODED_SECRET" and _is_allowlisted_secret(line):
                        break

                    severity = vuln_data["severity"]
                    if is_test and severity == "CRITICAL":
                        severity = "HIGH"

                    conf_score, conf_label = compute_confidence_score(
                        line=line,
                        filepath=filepath,
                        usage_context=usage_ctx,
                        is_test=is_test,
                        is_library=is_lib,
                        is_comment=is_comment,
                        is_used_in_sensitive_call=used_sensitively,
                    )

                    exec_risk = get_executive_risk(vuln_name, usage_ctx, conf_label)

                    findings.append({
                        "file":               filepath,
                        "line":               line_no,
                        "code":               line.strip(),
                        "snippet":            f">>> {line_no}: {line}",
                        "vulnerability":      vuln_name,
                        "severity":           severity,
                        "confidence":         conf_label,
                        "confidence_score":   conf_score,
                        "usage_context":      usage_ctx,
                        "replacement":        vuln_data["replacement"],
                        "risk_explanation":   _get_risk_explanation(vuln_name),
                        "recommended_fix":    f"Replace {vuln_name} with {vuln_data['replacement']}",
                        "migration_priority": _get_migration_priority(severity),
                        "detection_method":   "REGEX",
                        "is_test_file":       is_test,
                        "is_library_file":    is_lib,
                        "priority":           exec_risk["priority"],
                        "business_impact":    exec_risk["business_impact"],
                        "exploitability":     exec_risk["exploitability"],
                    })
                    break
                except re.error:
                    continue

    return _deduplicate_findings(findings)


# ══════════════════════════════════════════════════════════════
# Directory scanner
# ══════════════════════════════════════════════════════════════

def scan_directory(directory: str) -> List[Dict[str, Any]]:
    all_findings: List[Dict[str, Any]] = []
    file_count = 0

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for file in files:
            if file_count >= MAX_FILES:
                break
            ext = os.path.splitext(file)[1].lower()
            if ext in SUPPORTED_EXTENSIONS:
                filepath = os.path.join(root, file)
                try:
                    all_findings.extend(scan_file(filepath))
                    file_count += 1
                except Exception as e:
                    print(f"[QuantumGuard] Skipping {filepath}: {e}")
        if file_count >= MAX_FILES:
            break

    # JS/TS via dedicated scanner — enrich with phase data
    js_findings = scan_js_directory(directory)
    for f in js_findings:
        filepath  = f.get("file", "")
        line_no   = f.get("line", 1)
        is_lib    = is_library_file(filepath)
        is_test   = _is_test_or_docs_path(filepath)
        usage_ctx = classify_context(filepath, f.get("code", ""), [])

        conf_score, conf_label = compute_confidence_score(
            line=f.get("code", ""),
            filepath=filepath,
            usage_context=usage_ctx,
            is_test=is_test,
            is_library=is_lib,
            is_comment=False,
            is_used_in_sensitive_call=False,
        )
        exec_risk = get_executive_risk(f.get("vulnerability",""), usage_ctx, conf_label)

        f["confidence_score"] = conf_score
        f["confidence"]       = conf_label
        f["usage_context"]    = usage_ctx
        f["priority"]         = exec_risk["priority"]
        f["business_impact"]  = exec_risk["business_impact"]
        f["exploitability"]   = exec_risk["exploitability"]
        f["is_library_file"]  = is_lib

    all_findings.extend(js_findings)
    return _deduplicate_findings(all_findings)


# ══════════════════════════════════════════════════════════════
# PHASE 6: Score engine
# ══════════════════════════════════════════════════════════════

def calculate_score(findings: List[Dict[str, Any]]) -> int:
    """
    PHASE 6 scoring:
      Start at 100.
      Deduct per unique finding (ignoring LOW confidence):
        CRITICAL → -20
        HIGH     → -12
        MEDIUM   → -5
      Caps:
        CRITICAL >= 5  → score capped at 40
        CRITICAL >= 10 → score capped at 25
    PHASE 7: no HIGH/CRITICAL → score 95-100, clean message.
    """
    # Filter: only HIGH and MEDIUM confidence, non-LOW
    real_findings = [
        f for f in findings
        if f.get("confidence") != "LOW"
        and not f.get("is_library_file", False)
    ]

    if not real_findings:
        return 100

    # Deduplicate by (vulnerability, file) — count unique vulnerabilities per file
    unique: Dict[Tuple[str, str], Dict] = {}
    for f in real_findings:
        key = (f.get("vulnerability", ""), f.get("file", ""))
        if key not in unique:
            unique[key] = f
        else:
            # Keep higher severity
            sev_rank = {"CRITICAL":4,"HIGH":3,"MEDIUM":2,"LOW":1}
            if sev_rank.get(f.get("severity",""),0) > sev_rank.get(unique[key].get("severity",""),0):
                unique[key] = f

    deductions = {"CRITICAL": -20, "HIGH": -12, "MEDIUM": -5}
    score = 100.0
    critical_count = 0

    for f in unique.values():
        sev = f.get("severity", "MEDIUM")
        score += deductions.get(sev, -5)
        if sev == "CRITICAL":
            critical_count += 1

    # CRITICAL caps
    if critical_count >= 10:
        score = min(score, 25)
    elif critical_count >= 5:
        score = min(score, 40)

    return max(0, min(100, int(round(score))))


# ══════════════════════════════════════════════════════════════
# PHASE 7: Clean repo detection
# ══════════════════════════════════════════════════════════════

def is_clean_repo(findings: List[Dict[str, Any]]) -> bool:
    """Return True if there are no HIGH or CRITICAL confidence findings."""
    for f in findings:
        if f.get("confidence") in ("HIGH", "MEDIUM") and f.get("severity") in ("CRITICAL", "HIGH"):
            return False
    return True


# ══════════════════════════════════════════════════════════════
# Score explanation
# ══════════════════════════════════════════════════════════════

def generate_score_explanation(findings: List[Dict[str, Any]], score: int) -> List[str]:
    if not findings or is_clean_repo(findings):
        return ["Code appears clean. No exploitable crypto risks detected."]

    explanation = []
    vuln_counts: Dict[Tuple[str,str], int] = {}
    for f in findings:
        if f.get("confidence") == "LOW":
            continue
        if f.get("is_library_file"):
            continue
        key = (f.get("vulnerability","UNKNOWN"), f.get("severity","MEDIUM"))
        vuln_counts[key] = vuln_counts.get(key, 0) + 1

    severity_order = {"CRITICAL":0,"HIGH":1,"MEDIUM":2}
    sorted_vulns   = sorted(vuln_counts.items(), key=lambda x:(severity_order.get(x[0][1],3),-x[1]))

    VULN_DESCRIPTIONS = {
        "RSA":              "RSA encryption detected — quantum-vulnerable via Shor's algorithm",
        "ECC":              "Elliptic curve cryptography detected — quantum-vulnerable via Shor's algorithm",
        "DH":               "Diffie-Hellman key exchange detected — quantum-vulnerable",
        "DSA":              "DSA signatures detected — quantum-vulnerable",
        "MD5":              "MD5 hashing detected — cryptographically broken",
        "SHA1":             "SHA-1 hashing detected — deprecated and collision-broken",
        "RC4":              "RC4 cipher detected — completely broken",
        "DES":              "DES/3DES cipher detected — deprecated, insufficient key size",
        "ECB_MODE":         "ECB mode detected — reveals patterns in encrypted data",
        "WEAK_TLS":         "Weak TLS version detected — upgrade to TLS 1.3",
        "WEAK_KEY_SIZE":    "Weak RSA key size detected — minimum 3072-bit required",
        "HARDCODED_SECRET": "Hardcoded secrets detected — exposed in source code",
        "WEAK_RANDOM":      "Insecure random number generator in crypto context",
        "JWT_NONE_ALG":     "JWT signature verification disabled — token forgery risk",
        "BLOWFISH":         "Blowfish cipher detected — 64-bit block size, use AES-256-GCM",
        "MD4":              "MD4 hashing detected — completely broken",
        "SHA256_SIGNED":    "SHA-256 with asymmetric signing — inherits quantum vulnerability",
    }
    SEV_PREFIX = {"CRITICAL":"🔴 CRITICAL","HIGH":"🟡 HIGH","MEDIUM":"🟠 MEDIUM"}

    for (vuln, sev), count in sorted_vulns[:8]:
        desc = VULN_DESCRIPTIONS.get(vuln)
        if not desc:
            base = vuln.split("_")[0]
            desc = VULN_DESCRIPTIONS.get(base, f"{vuln} detected — migration required")
        prefix    = SEV_PREFIX.get(sev, "⚪")
        count_str = f" ({count} instance{'s' if count>1 else ''})" if count > 1 else ""
        explanation.append(f"{prefix}: {desc}{count_str}")

    if score <= 25:
        explanation.append("⚠️  Score is critically low — immediate remediation required before production use.")
    elif score <= 40:
        explanation.append("⚠️  Score indicates critical quantum risk — multiple CRITICAL findings require urgent action.")
    elif score <= 60:
        explanation.append("⚠️  Score indicates significant quantum risk — migration planning should begin now.")
    elif score <= 75:
        explanation.append("ℹ️  Score indicates moderate risk — some algorithms need upgrading.")
    else:
        explanation.append("✅  Score indicates good quantum posture — continue monitoring NIST PQC updates.")

    return explanation


# ══════════════════════════════════════════════════════════════
# Scan summary
# ══════════════════════════════════════════════════════════════

def generate_scan_summary(directory: str, findings: List[Dict[str, Any]], scan_start_time: float) -> Dict[str, Any]:
    total_files = files_scanned = 0
    languages: Set[str] = set()
    ext_map = {
        ".py":"Python", ".js":"JavaScript", ".ts":"TypeScript",
        ".java":"Java", ".go":"Go", ".rs":"Rust",
        ".c":"C", ".cpp":"C++", ".cc":"C++",
        ".h":"C/C++ Header", ".hpp":"C++ Header",
    }

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext in ext_map:
                total_files += 1
                if files_scanned < MAX_FILES:
                    files_scanned += 1
                    languages.add(ext_map[ext])

    elapsed = round(time.time() - scan_start_time, 1)
    scan_time_str = f"{elapsed}s" if elapsed < 60 else f"{round(elapsed/60,1)}m"

    real_findings = [f for f in findings if f.get("confidence") != "LOW"]
    files_with_issues = len({f["file"] for f in real_findings})

    high_conf = sum(1 for f in findings if f.get("confidence") == "HIGH")
    med_conf  = sum(1 for f in findings if f.get("confidence") == "MEDIUM")
    total_real = high_conf + med_conf

    if total_real == 0:
        overall_confidence, confidence_note = "High", "No findings — high confidence the codebase is clean."
    elif high_conf / max(total_real,1) >= 0.7:
        overall_confidence = "High"
        confidence_note = f"{high_conf} of {total_real} findings confirmed by AST or direct API call."
    elif high_conf / max(total_real,1) >= 0.4:
        overall_confidence, confidence_note = "Medium", "Mix of high and medium confidence findings. Review before fixing."
    else:
        overall_confidence, confidence_note = "Low", "Most findings are pattern-based. Manual review recommended."

    # Context breakdown
    ctx_counts: Dict[str,int] = defaultdict(int)
    for f in real_findings:
        ctx_counts[f.get("usage_context","unknown")] += 1

    # Library findings count
    library_count = sum(1 for f in findings if f.get("is_library_file"))

    return {
        "total_files":          total_files,
        "files_scanned":        files_scanned,
        "files_with_issues":    files_with_issues,
        "scan_time":            scan_time_str,
        "languages_detected":   sorted(list(languages)),
        "overall_confidence":   overall_confidence,
        "confidence_note":      confidence_note,
        "max_files_limit":      MAX_FILES,
        "truncated":            total_files > MAX_FILES,
        "context_breakdown":    dict(ctx_counts),
        "library_findings_suppressed": library_count,
        "clean_repo":           is_clean_repo(findings),
    }


# ══════════════════════════════════════════════════════════════
# Crypto agility checker
# ══════════════════════════════════════════════════════════════

def check_crypto_agility(directory: str) -> Dict[str, Any]:
    agility_findings: List[Dict[str, Any]] = []

    hardcoded_patterns = [
        (r'AES\.new\s*\([^,]+,\s*AES\.MODE_',     "Hardcoded AES mode",          'Move AES mode to config'),
        (r'RSA\.generate\s*\(\s*\d+\s*\)',          "Hardcoded RSA key size",       'Move key size to config or migrate to ML-KEM (FIPS 203)'),
        (r'key\s*=\s*b[\'"][^\'"]{4,}[\'"]',        "Hardcoded encryption key",     'Move to AWS Secrets Manager or environment variable'),
        (r'iv\s*=\s*b[\'"][^\'"]{4,}[\'"]',         "Hardcoded IV",                 'Generate IV randomly: iv = os.urandom(16)'),
        (r'salt\s*=\s*b[\'"][^\'"]{4,}[\'"]',       "Hardcoded salt",               'Generate salt randomly: salt = os.urandom(32)'),
        (r'hashlib\.(md5|sha1)\s*\(',               "Hardcoded weak hash algorithm", 'Replace with hashlib.sha3_256()'),
        (r'algorithms\s*=\s*\[[\'"][^\'"]+[\'"]\]', "Hardcoded JWT algorithm",      'Move JWT algorithm to config'),
        (r'cipher\s*=\s*[\'"][^\'"]*(?:AES|DES|RC4|RSA)[^\'"]*[\'"]', "Hardcoded cipher name", 'Move cipher to environment variable'),
    ]
    configurable_patterns = [
        (r'os\.environ\.get\s*\([\'"].*(?:ALGO|CIPHER|HASH|CRYPTO|KEY_SIZE)[\'"]', "Configurable algorithm via env var"),
        (r'config\[[\'"]\w*(?:algo|cipher|hash|crypto)\w*[\'"]\]',                 "Config-driven algorithm"),
        (r'settings\.\w*(?:algorithm|cipher|hash)\w*',                              "Settings-driven algorithm"),
        (r'getenv\s*\([\'"].*(?:ALGO|CIPHER|HASH)[\'"]',                            "Configurable algorithm via getenv"),
        (r'(?:ALGORITHM|CIPHER|HASH_FUNC)\s*=\s*os\.environ',                       "Environment-configured crypto"),
    ]
    supported = {".py",".js",".java",".ts"}

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for file in files:
            ext = os.path.splitext(file)[1].lower()
            if ext not in supported:
                continue
            filepath = os.path.join(root, file)
            if is_library_file(filepath):
                continue  # skip vendor/dist in agility too
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()
                for line_no, line in enumerate(lines, start=1):
                    if _is_comment_line(line, ext):
                        continue
                    for pattern, desc, fix in hardcoded_patterns:
                        if re.search(pattern, line):
                            agility_findings.append({
                                "file":line_no and filepath,"line":line_no,"code":line.strip(),
                                "type":"hardcoded","description":desc,"fix":fix,
                                "recommendation":"Move to environment variable or config file",
                                "impact":"Hardcoded crypto makes quantum migration expensive and error-prone",
                            })
                    for pattern, desc in configurable_patterns:
                        if re.search(pattern, line):
                            agility_findings.append({
                                "file":filepath,"line":line_no,"code":line.strip(),
                                "type":"configurable","description":desc,"fix":"Good practice — maintain this pattern",
                                "recommendation":"Ensure PQC algorithms are available as config options",
                                "impact":"Configurable crypto enables fast PQC migration",
                            })
            except Exception:
                continue

    hardcoded    = len([f for f in agility_findings if f["type"]=="hardcoded"])
    configurable = len([f for f in agility_findings if f["type"]=="configurable"])
    agility_score = max(0, min(100, 100-(hardcoded*5)+(configurable*3)))

    if agility_score>=90:   status,ease = "HIGH AGILITY","Very Easy"
    elif agility_score>=70: status,ease = "MODERATE AGILITY","Moderate"
    elif agility_score>=40: status,ease = "LOW AGILITY","Difficult"
    else:                   status,ease = "VERY LOW AGILITY","Very Difficult"

    return {
        "agility_score":agility_score,"hardcoded_count":hardcoded,
        "configurable_count":configurable,"status":status,"migration_ease":ease,
        "findings":agility_findings,
        "summary":{
            "total_files_with_issues":len({f["file"] for f in agility_findings}),
            "recommendation":"Excellent crypto agility — easy PQC migration" if agility_score>=90
                else "Move hardcoded algorithms to environment variables before PQC migration",
        },
    }


# ══════════════════════════════════════════════════════════════
# Main report generator
# ══════════════════════════════════════════════════════════════

def generate_report(directory: str) -> Dict[str, Any]:
    print(f"\n[QuantumGuard] Scanning: {directory}\n")
    start    = time.time()
    findings = scan_directory(directory)
    score    = calculate_score(findings)
    clean    = is_clean_repo(findings)

    severity_counts = {"CRITICAL":0,"HIGH":0,"MEDIUM":0,"LOW":0}
    for f in findings:
        sev = f.get("severity","MEDIUM")
        severity_counts[sev] = severity_counts.get(sev,0)+1

    # PHASE 4: grouped findings
    grouped = build_grouped_findings(findings)

    # Context breakdown for report
    context_breakdown: Dict[str,int] = defaultdict(int)
    for f in findings:
        if f.get("confidence") != "LOW":
            context_breakdown[f.get("usage_context","unknown")] += 1

    report = {
        "meta":{
            "tool":"QuantumGuard","version":"3.0",
            "company":"Mangsri QuantumGuard LLC",
            "website":"https://quantumguard.site",
            "standards":["NIST FIPS 203 (ML-KEM)","NIST FIPS 204 (ML-DSA)","NIST FIPS 205 (SLH-DSA)"],
            "scanned_at":datetime.now().isoformat(),"license":"AGPL v3",
        },
        "directory":               directory,
        "quantum_readiness_score": score,
        "clean_repo":              clean,
        "score_explanation":       generate_score_explanation(findings, score),
        "scan_summary":            generate_scan_summary(directory, findings, start),
        "total_findings":          len(findings),
        "severity_summary":        severity_counts,
        "context_breakdown":       dict(context_breakdown),
        "findings":                findings,
        "grouped_findings":        grouped,   # PHASE 4
    }

    output_path = os.path.join("reports","report.json")
    os.makedirs("reports", exist_ok=True)
    with open(output_path,"w") as f:
        json.dump(report, f, indent=2, default=str)

    print(f"[QuantumGuard] Score: {score}/100  |  Clean: {clean}")
    print(f"[QuantumGuard] Findings: {len(findings)}  |  Groups: {len(grouped)}")
    print(f"[QuantumGuard] Report: {output_path}\n")
    return report
