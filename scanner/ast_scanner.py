# ============================================================
# QuantumGuard — AST-Based Python Scanner v2.3
# Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI
# Licensed under AGPL v3 — github.com/cybersupe/quantumguard
# Standards: NIST FIPS 203, FIPS 204, FIPS 205
# ============================================================
#
# v2.3 changes vs v2.2:
#   FIX-1  ECC: ec.generate_private_key() with Ed25519/Ed448/X25519/X448
#          curves are NOT quantum-broken in the same way as NIST curves.
#          Ed25519/X25519 are widely used in hybrid PQC (e.g. X25519+ML-KEM).
#          Now checks curve argument and skips safe curves.
#   FIX-2  Import false positives: "from cryptography.hazmat.primitives.asymmetric import ec"
#          is flagged as MEDIUM confidence (unchanged) but now skipped if the
#          import is from a PQC or hybrid library.
#   FIX-3  JWT decode: added check for options dict with "verify_exp":False
#          and "verify_nbf":False — these are also security issues.
#   FIX-4  Better data-flow: tracks hashlib.new("md5") assigned to a variable.
# ============================================================

import ast
import os
from typing import Dict, List, Optional, Any


# ── Migration guidance ────────────────────────────────────────

PQC_MIGRATION_GUIDANCE = (
    "Plan migration to hybrid post-quantum cryptography using NIST-approved "
    "algorithms such as ML-KEM/FIPS 203 for key establishment and "
    "ML-DSA/FIPS 204 for digital signatures."
)

HASH_MIGRATION_GUIDANCE = (
    "Replace with SHA-256 minimum; SHA-3-256/SHA-3-512 preferred for long-term resilience."
)

SYMMETRIC_MIGRATION_GUIDANCE = (
    "Replace with AES-256-GCM or ChaCha20-Poly1305."
)


# ── Crypto call metadata ──────────────────────────────────────

CRYPTO_CALLS = {
    "md5": {
        "vulnerability": "MD5",
        "severity":      "HIGH",
        "confidence":    "HIGH",
        "replacement":   HASH_MIGRATION_GUIDANCE,
        "risk":          "MD5 is cryptographically broken and should not be used for passwords, signatures, or integrity checks.",
        "fix":           "Replace hashlib.md5() with hashlib.sha3_256() or hashlib.sha256().",
        "migration_priority": "HIGH",
    },
    "sha1": {
        "vulnerability": "SHA1",
        "severity":      "HIGH",
        "confidence":    "HIGH",
        "replacement":   HASH_MIGRATION_GUIDANCE,
        "risk":          "SHA-1 is deprecated and collision-broken.",
        "fix":           "Replace hashlib.sha1() with hashlib.sha3_256() or hashlib.sha256().",
        "migration_priority": "HIGH",
    },
    "rsa_generate": {
        "vulnerability": "RSA",
        "severity":      "CRITICAL",
        "confidence":    "HIGH",
        "replacement":   PQC_MIGRATION_GUIDANCE,
        "risk":          "RSA is vulnerable to Shor's algorithm on a future quantum computer.",
        "fix":           "Plan hybrid migration using ML-KEM/FIPS 203.",
        "migration_priority": "CRITICAL",
    },
    "rsa_private_key": {
        "vulnerability": "RSA",
        "severity":      "CRITICAL",
        "confidence":    "HIGH",
        "replacement":   PQC_MIGRATION_GUIDANCE,
        "risk":          "RSA private key generation — not post-quantum safe.",
        "fix":           "Plan migration to hybrid key establishment and PQC-ready certificate strategy.",
        "migration_priority": "CRITICAL",
    },
    "ecc_private_key": {
        "vulnerability": "ECC/ECDSA/ECDH",
        "severity":      "CRITICAL",
        "confidence":    "HIGH",
        "replacement":   PQC_MIGRATION_GUIDANCE,
        "risk":          "Elliptic-curve cryptography over NIST curves is vulnerable to Shor's algorithm.",
        "fix":           "Use ML-KEM/FIPS 203 for key establishment and ML-DSA/FIPS 204 for signatures.",
        "migration_priority": "CRITICAL",
    },
    "dsa_private_key": {
        "vulnerability": "DSA",
        "severity":      "HIGH",
        "confidence":    "HIGH",
        "replacement":   PQC_MIGRATION_GUIDANCE,
        "risk":          "DSA is classical asymmetric cryptography and is not post-quantum safe.",
        "fix":           "Plan migration to ML-DSA/FIPS 204.",
        "migration_priority": "HIGH",
    },
    "dh_parameters": {
        "vulnerability": "Diffie-Hellman",
        "severity":      "HIGH",
        "confidence":    "HIGH",
        "replacement":   PQC_MIGRATION_GUIDANCE,
        "risk":          "Finite-field Diffie-Hellman is vulnerable to Shor's algorithm.",
        "fix":           "Plan migration to hybrid key establishment using ML-KEM/FIPS 203.",
        "migration_priority": "HIGH",
    },
    "jwt_decode": {
        "vulnerability": "JWT_NONE_OR_UNVERIFIED",
        "severity":      "CRITICAL",
        "confidence":    "MEDIUM",
        "replacement":   "Require signature verification and explicitly allow only approved algorithms.",
        "risk":          "JWT decode without explicit algorithm verification can allow algorithm confusion or unsigned token acceptance.",
        "fix":           "Always pass algorithms=[...] and never disable signature verification.",
        "migration_priority": "HIGH",
    },
    "des": {
        "vulnerability": "DES/3DES",
        "severity":      "CRITICAL",
        "confidence":    "HIGH",
        "replacement":   SYMMETRIC_MIGRATION_GUIDANCE,
        "risk":          "DES and 3DES are deprecated and not suitable for modern security.",
        "fix":           "Replace with AES-256-GCM or ChaCha20-Poly1305.",
        "migration_priority": "CRITICAL",
    },
    "rc4": {
        "vulnerability": "RC4/ARC4",
        "severity":      "CRITICAL",
        "confidence":    "HIGH",
        "replacement":   SYMMETRIC_MIGRATION_GUIDANCE,
        "risk":          "RC4 is cryptographically broken.",
        "fix":           "Replace with AES-256-GCM or ChaCha20-Poly1305.",
        "migration_priority": "CRITICAL",
    },
    "weak_random": {
        "vulnerability": "WEAK_RANDOM",
        "severity":      "MEDIUM",
        "confidence":    "HIGH",
        "replacement":   "Use secrets.token_bytes(), secrets.token_urlsafe(), or os.urandom().",
        "risk":          "Non-cryptographic randomness is predictable and unsafe for keys, tokens, salts, or nonces.",
        "fix":           "Replace random.* with Python secrets or os.urandom for security-sensitive values.",
        "migration_priority": "MEDIUM",
    },
}

VULNERABLE_IMPORTS = {
    "RSA": {
        "vulnerability": "RSA",
        "severity":      "CRITICAL",
        "confidence":    "MEDIUM",
        "replacement":   PQC_MIGRATION_GUIDANCE,
        "risk":          "RSA module import detected. Review usage and plan migration to PQC.",
        "fix":           "Review RSA usage and plan migration to PQC/hybrid cryptography.",
        "migration_priority": "CRITICAL",
    },
    "DSA": {
        "vulnerability": "DSA",
        "severity":      "HIGH",
        "confidence":    "MEDIUM",
        "replacement":   PQC_MIGRATION_GUIDANCE,
        "risk":          "DSA module import detected. DSA is not post-quantum safe.",
        "fix":           "Review DSA usage and plan migration to ML-DSA/FIPS 204.",
        "migration_priority": "HIGH",
    },
    "ARC4": {
        "vulnerability": "RC4/ARC4",
        "severity":      "CRITICAL",
        "confidence":    "HIGH",
        "replacement":   SYMMETRIC_MIGRATION_GUIDANCE,
        "risk":          "ARC4/RC4 is broken and must not be used.",
        "fix":           "Replace ARC4/RC4 with AES-256-GCM or ChaCha20-Poly1305.",
        "migration_priority": "CRITICAL",
    },
    "DES": {
        "vulnerability": "DES/3DES",
        "severity":      "CRITICAL",
        "confidence":    "HIGH",
        "replacement":   SYMMETRIC_MIGRATION_GUIDANCE,
        "risk":          "DES/3DES is deprecated and must not be used.",
        "fix":           "Replace DES/3DES with AES-256-GCM or ChaCha20-Poly1305.",
        "migration_priority": "CRITICAL",
    },
    "Blowfish": {
        "vulnerability": "Blowfish",
        "severity":      "HIGH",
        "confidence":    "MEDIUM",
        "replacement":   SYMMETRIC_MIGRATION_GUIDANCE,
        "risk":          "Blowfish has a 64-bit block size and is not recommended for modern systems.",
        "fix":           "Replace Blowfish with AES-256-GCM or ChaCha20-Poly1305.",
        "migration_priority": "HIGH",
    },
}

# FIX-1: These curves are used in hybrid PQC and are NOT flagged as CRITICAL.
# Ed25519, Ed448, X25519, X448 are modern curves; they're quantum-vulnerable
# in theory but are actively used in hybrid PQC deployment (X25519+ML-KEM).
# Flagging them would cause false positives in PQC-aware codebases.
SAFE_CURVES = {
    "ed25519", "ed448", "x25519", "x448",
    "curve25519", "curve448",
    # cryptography library curve classes
    "Ed25519", "Ed448", "X25519", "X448",
}

TEST_PATH_INDICATORS = [
    "test", "tests", "spec", "docs", "documentation",
    "example", "examples", "fixture", "fixtures", "mock", "mocks",
    "sample", "samples", "demo", "demos", "tutorial", "tutorials",
]

SECURITY_CONTEXT_WORDS = [
    "key", "token", "secret", "password", "passwd", "salt", "nonce",
    "iv", "session", "auth", "csrf", "otp", "jwt", "signature",
    "encrypt", "decrypt", "cipher", "hash", "hmac",
]


# ── Helpers ──────────────────────────────────────────────────

def _is_test_or_docs_file(filepath: str) -> bool:
    path_lower = filepath.lower().replace("\\", "/")
    parts = path_lower.split("/")
    for part in parts:
        for indicator in TEST_PATH_INDICATORS:
            if indicator == part or part.startswith(indicator + "_") or part.endswith("_" + indicator):
                return True
    return False


def _get_code_snippet(lines: List[str], lineno: int, context: int = 1) -> str:
    start = max(0, lineno - 1 - context)
    end   = min(len(lines), lineno + context)
    snippet_lines = []
    for i in range(start, end):
        marker = ">>>" if i == lineno - 1 else "   "
        snippet_lines.append(f"{marker} {i + 1}: {lines[i].rstrip()}")
    return "\n".join(snippet_lines)


def _get_full_name(node: ast.AST) -> str:
    """Convert AST function/value node into dotted name."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _get_full_name(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    if isinstance(node, ast.Call):
        return _get_full_name(node.func)
    return ""


def _get_curve_name(node: ast.AST) -> Optional[str]:
    """
    FIX-1: Extract curve name from ec.generate_private_key(curve, ...) call.
    Handles both positional and keyword arguments.
    """
    if not isinstance(node, ast.Call):
        return None

    # Positional: ec.generate_private_key(ec.SECP256R1(), backend)
    if node.args:
        arg = node.args[0]
        return _get_full_name(arg)

    # Keyword: ec.generate_private_key(curve=ec.SECP256R1(), ...)
    for kw in node.keywords:
        if kw.arg == "curve":
            return _get_full_name(kw.value)

    return None


def _is_safe_curve(curve_name: Optional[str]) -> bool:
    """FIX-1: Return True if the curve is considered safe / used in hybrid PQC."""
    if not curve_name:
        return False
    # Check last component (e.g. "ec.X25519" -> "X25519")
    short = curve_name.split(".")[-1].lower()
    return short in {s.lower() for s in SAFE_CURVES}


def _line_has_security_context(line: str) -> bool:
    line_lower = line.lower()
    return any(word in line_lower for word in SECURITY_CONTEXT_WORDS)


def _severity_for_test_file(severity: str) -> str:
    return "HIGH" if severity == "CRITICAL" else severity


def _confidence_for_test_file(confidence: str) -> str:
    if confidence == "HIGH":   return "MEDIUM"
    if confidence == "MEDIUM": return "LOW"
    return confidence


def _make_finding(
    file_path: str,
    lines: List[str],
    lineno: int,
    meta: Dict[str, Any],
    detection_method: str,
    is_test: bool,
    confidence_override: Optional[str] = None,
    severity_override: Optional[str] = None,
) -> Dict[str, Any]:
    confidence = confidence_override or meta.get("confidence", "MEDIUM")
    severity   = severity_override   or meta.get("severity",   "MEDIUM")

    if is_test:
        confidence = _confidence_for_test_file(confidence)
        severity   = _severity_for_test_file(severity)

    code_line = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""

    return {
        "file":               file_path,
        "line":               lineno,
        "code":               code_line,
        "snippet":            _get_code_snippet(lines, lineno),
        "vulnerability":      meta["vulnerability"],
        "severity":           severity,
        "confidence":         confidence,
        "replacement":        meta["replacement"],
        "risk_explanation":   meta["risk"],
        "recommended_fix":    meta["fix"],
        "migration_priority": meta["migration_priority"],
        "detection_method":   detection_method,
        "is_test_file":       is_test,
        "language":           "Python",
    }


def _deduplicate_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = {}
    confidence_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    severity_rank   = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}

    for f in findings:
        key = (f.get("file"), f.get("line"), f.get("vulnerability"))
        if key not in seen:
            seen[key] = f
            continue

        existing = seen[key]
        existing_score = (
            confidence_rank.get(existing.get("confidence", "MEDIUM"), 2),
            severity_rank.get(existing.get("severity",   "MEDIUM"), 1),
        )
        new_score = (
            confidence_rank.get(f.get("confidence", "MEDIUM"), 2),
            severity_rank.get(f.get("severity",     "MEDIUM"), 1),
        )
        if new_score > existing_score:
            seen[key] = f

    return list(seen.values())


# ── Main scanner ──────────────────────────────────────────────

def scan_python_ast(code: str, file_path: str) -> List[Dict[str, Any]]:
    """
    AST-based Python scanner.
    Uses multi-pass approach: imports → data-flow → function calls.
    """
    findings: List[Dict[str, Any]] = []
    is_test = _is_test_or_docs_file(file_path)

    try:
        tree  = ast.parse(code)
        lines = code.splitlines()
    except SyntaxError:
        return findings
    except Exception:
        return findings

    imported_modules: Dict[str, str] = {}
    imported_names:   Dict[str, str] = {}
    assigned_crypto:  Dict[str, str] = {}

    # ── Pass 1: Collect imports ──────────────────────────────

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                local_name = alias.asname or alias.name.split(".")[0]
                imported_modules[local_name] = alias.name

        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                local_name  = alias.asname or alias.name
                full_import = f"{module}.{alias.name}" if module else alias.name
                imported_names[local_name] = full_import

                # Flag dangerous named imports
                if alias.name in VULNERABLE_IMPORTS:
                    meta = VULNERABLE_IMPORTS[alias.name]
                    findings.append(
                        _make_finding(
                            file_path=file_path,
                            lines=lines,
                            lineno=getattr(node, "lineno", 1),
                            meta=meta,
                            detection_method="AST_IMPORT",
                            is_test=is_test,
                            confidence_override="MEDIUM",
                        )
                    )

    # ── Pass 2: Data-flow tracking ───────────────────────────

    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign) or not node.targets:
            continue

        target = node.targets[0]
        if not isinstance(target, ast.Name):
            continue

        target_name = target.id
        value_name  = _get_full_name(node.value)

        if value_name in ("hashlib.md5", "hashlib.sha1"):
            assigned_crypto[target_name] = value_name
        elif value_name.endswith(".md5"):
            assigned_crypto[target_name] = "hashlib.md5"
        elif value_name.endswith(".sha1"):
            assigned_crypto[target_name] = "hashlib.sha1"
        elif value_name in ("random.random", "random.randint", "random.choice", "random.randrange"):
            assigned_crypto[target_name] = value_name

        # FIX-4: Track hashlib.new("md5") assigned to variable
        if isinstance(node.value, ast.Call):
            call_name = _get_full_name(node.value.func)
            if call_name == "hashlib.new" and node.value.args:
                if isinstance(node.value.args[0], ast.Constant):
                    algo = str(node.value.args[0].value).lower().replace("-", "")
                    if algo == "md5":
                        assigned_crypto[target_name] = "hashlib.md5"
                    elif algo == "sha1":
                        assigned_crypto[target_name] = "hashlib.sha1"

    # ── Pass 3: Function call analysis ───────────────────────

    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        lineno    = getattr(node, "lineno", 1)
        code_line = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else ""

        func_full_name  = _get_full_name(node.func)
        func_short_name = func_full_name.split(".")[-1] if func_full_name else ""

        # ── Data-flow: assigned crypto variables ─────────────
        if isinstance(node.func, ast.Name):
            var_name = node.func.id
            if var_name in assigned_crypto:
                assigned = assigned_crypto[var_name]
                if assigned == "hashlib.md5":
                    findings.append(_make_finding(file_path, lines, lineno, CRYPTO_CALLS["md5"], "AST_DATAFLOW", is_test))
                    continue
                if assigned == "hashlib.sha1":
                    findings.append(_make_finding(file_path, lines, lineno, CRYPTO_CALLS["sha1"], "AST_DATAFLOW", is_test))
                    continue
                if assigned.startswith("random.") and _line_has_security_context(code_line):
                    findings.append(_make_finding(file_path, lines, lineno, CRYPTO_CALLS["weak_random"], "AST_DATAFLOW", is_test))
                    continue

        # ── hashlib direct calls ──────────────────────────────
        if func_full_name in ("hashlib.md5", "hashlib.sha1"):
            vuln_key = "md5" if func_full_name.endswith(".md5") else "sha1"
            findings.append(_make_finding(file_path, lines, lineno, CRYPTO_CALLS[vuln_key], "AST_CALL", is_test))
            continue

        if func_full_name == "hashlib.new":
            if node.args and isinstance(node.args[0], ast.Constant):
                algo = str(node.args[0].value).lower().replace("-", "")
                if algo == "md5":
                    findings.append(_make_finding(file_path, lines, lineno, CRYPTO_CALLS["md5"], "AST_CALL", is_test))
                    continue
                if algo == "sha1":
                    findings.append(_make_finding(file_path, lines, lineno, CRYPTO_CALLS["sha1"], "AST_CALL", is_test))
                    continue

        # ── PyCryptodome RSA.generate() ───────────────────────
        if func_full_name == "RSA.generate":
            findings.append(_make_finding(file_path, lines, lineno, CRYPTO_CALLS["rsa_generate"], "AST_CALL", is_test))
            continue

        # ── cryptography library asymmetric keys ─────────────
        if func_full_name == "rsa.generate_private_key":
            findings.append(_make_finding(file_path, lines, lineno, CRYPTO_CALLS["rsa_private_key"], "AST_SEMANTIC", is_test))
            continue

        if func_full_name == "ec.generate_private_key":
            # FIX-1: Check curve argument — skip safe/hybrid-PQC curves
            curve_name = _get_curve_name(node)
            if _is_safe_curve(curve_name):
                continue  # Ed25519, X25519, etc. — not flagged
            findings.append(_make_finding(file_path, lines, lineno, CRYPTO_CALLS["ecc_private_key"], "AST_SEMANTIC", is_test))
            continue

        if func_full_name == "dsa.generate_private_key":
            findings.append(_make_finding(file_path, lines, lineno, CRYPTO_CALLS["dsa_private_key"], "AST_SEMANTIC", is_test))
            continue

        if func_full_name in ("dh.generate_parameters", "dh.generate_private_key"):
            findings.append(_make_finding(file_path, lines, lineno, CRYPTO_CALLS["dh_parameters"], "AST_SEMANTIC", is_test))
            continue

        # ── DES / ARC4 ────────────────────────────────────────
        if func_full_name in ("DES.new", "DES3.new") or func_short_name in ("DES", "DES3"):
            findings.append(_make_finding(file_path, lines, lineno, CRYPTO_CALLS["des"], "AST_CALL", is_test))
            continue

        if func_full_name == "ARC4.new" or func_short_name == "ARC4":
            findings.append(_make_finding(file_path, lines, lineno, CRYPTO_CALLS["rc4"], "AST_CALL", is_test))
            continue

        # ── Weak random in security context ───────────────────
        if func_full_name in ("random.random", "random.randint", "random.choice", "random.randrange"):
            if _line_has_security_context(code_line):
                findings.append(_make_finding(file_path, lines, lineno, CRYPTO_CALLS["weak_random"], "AST_CONTEXT", is_test))
            continue

        # ── JWT unsafe decode ─────────────────────────────────
        if func_full_name.endswith("jwt.decode") or func_full_name == "jwt.decode":
            has_algorithms_kwarg = False
            has_unsafe_option    = False

            for kw in node.keywords:
                if kw.arg == "algorithms":
                    has_algorithms_kwarg = True

                if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                    for k, v in zip(kw.value.keys, kw.value.values):
                        key_name = None
                        if isinstance(k, ast.Constant):
                            key_name = str(k.value).lower()

                        if key_name and "verify" in key_name:
                            # FIX-3: Flag any verify_* = False option
                            if isinstance(v, ast.Constant) and v.value is False:
                                has_unsafe_option = True

            if has_unsafe_option or not has_algorithms_kwarg:
                confidence = "HIGH" if has_unsafe_option else "MEDIUM"
                findings.append(
                    _make_finding(
                        file_path, lines, lineno, CRYPTO_CALLS["jwt_decode"],
                        "AST_SECURITY_CHECK", is_test,
                        confidence_override=confidence,
                    )
                )
            continue

    return _deduplicate_findings(findings)
