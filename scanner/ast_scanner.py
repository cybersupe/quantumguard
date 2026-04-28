# ============================================================
# QuantumGuard — AST-Based Python Scanner
# Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI
# Licensed under AGPL v3 — github.com/cybersupe/quantumguard
# Standards: NIST FIPS 203, FIPS 204, FIPS 205
# ============================================================

import ast
import os

# Maps function/method names to vulnerability metadata
CRYPTO_CALLS = {
    # MD5
    "md5": {
        "vulnerability": "MD5",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "replacement": "hashlib.sha3_256() — NIST FIPS 202",
        "risk": "MD5 is cryptographically broken. Quantum computers further weaken hash functions via Grover's algorithm.",
        "fix": "Replace hashlib.md5() with hashlib.sha3_256() or hashlib.sha3_512()",
        "migration_priority": "HIGH",
    },
    # SHA1
    "sha1": {
        "vulnerability": "SHA1",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "replacement": "hashlib.sha3_256() — NIST FIPS 202",
        "risk": "SHA-1 is deprecated and broken. Grover's algorithm halves effective security.",
        "fix": "Replace hashlib.sha1() with hashlib.sha3_256()",
        "migration_priority": "HIGH",
    },
    # RSA
    "generate": {
        "vulnerability": "RSA",
        "severity": "CRITICAL",
        "confidence": "MEDIUM",
        "replacement": "CRYSTALS-Kyber (ML-KEM FIPS 203)",
        "risk": "RSA is broken by Shor's Algorithm on quantum computers. Must migrate before 2030.",
        "fix": "Replace RSA key generation with CRYSTALS-Kyber via liboqs-python",
        "migration_priority": "CRITICAL",
    },
    "generate_private_key": {
        "vulnerability": "RSA/ECC",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "replacement": "CRYSTALS-Kyber (ML-KEM FIPS 203) or CRYSTALS-Dilithium (ML-DSA FIPS 204)",
        "risk": "Asymmetric key generation using quantum-vulnerable algorithms. Shor's Algorithm breaks these.",
        "fix": "Migrate to NIST PQC standards: ML-KEM for encryption, ML-DSA for signatures",
        "migration_priority": "CRITICAL",
    },
    # ECC
    "ECDSA": {
        "vulnerability": "ECC/ECDSA",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "replacement": "CRYSTALS-Dilithium (ML-DSA FIPS 204)",
        "risk": "ECDSA is vulnerable to Shor's Algorithm on quantum computers.",
        "fix": "Replace ECDSA with ML-DSA (CRYSTALS-Dilithium) for digital signatures",
        "migration_priority": "CRITICAL",
    },
    "ECDH": {
        "vulnerability": "ECC/ECDH",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "replacement": "CRYSTALS-Kyber (ML-KEM FIPS 203)",
        "risk": "ECDH key exchange is broken by Shor's Algorithm.",
        "fix": "Replace ECDH with ML-KEM (CRYSTALS-Kyber) for key exchange",
        "migration_priority": "CRITICAL",
    },
    # DES / 3DES
    "DES": {
        "vulnerability": "DES",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "replacement": "AES-256-GCM or ChaCha20-Poly1305",
        "risk": "DES/3DES are deprecated and broken for modern use.",
        "fix": "Replace with AES-256-GCM from the cryptography library",
        "migration_priority": "CRITICAL",
    },
    # RC4
    "ARC4": {
        "vulnerability": "RC4/ARC4",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "replacement": "AES-256-GCM or ChaCha20-Poly1305",
        "risk": "RC4 is completely broken with multiple practical attacks.",
        "fix": "Replace with AES-256-GCM",
        "migration_priority": "CRITICAL",
    },
    # JWT none algorithm
    "decode": {
        "vulnerability": "JWT_NONE_ALG",
        "severity": "CRITICAL",
        "confidence": "LOW",
        "replacement": "Use RS256 with quantum-safe keys",
        "risk": "JWT decode without algorithm verification allows algorithm confusion attacks.",
        "fix": "Always specify algorithms=['RS256'] or use PQC-safe signing",
        "migration_priority": "HIGH",
    },
}

# Import patterns to track what was imported
VULNERABLE_IMPORTS = {
    "RSA": {"vulnerability": "RSA", "severity": "CRITICAL", "confidence": "HIGH",
            "replacement": "CRYSTALS-Kyber (ML-KEM FIPS 203)",
            "risk": "RSA import detected — module used for quantum-vulnerable operations.",
            "fix": "Replace PyCryptodome RSA with liboqs-python ML-KEM",
            "migration_priority": "CRITICAL"},
    "DSA": {"vulnerability": "DSA", "severity": "HIGH", "confidence": "HIGH",
            "replacement": "CRYSTALS-Dilithium (ML-DSA FIPS 204)",
            "risk": "DSA is quantum-vulnerable via Shor's Algorithm.",
            "fix": "Replace with ML-DSA (CRYSTALS-Dilithium)",
            "migration_priority": "HIGH"},
    "ARC4": {"vulnerability": "RC4/ARC4", "severity": "CRITICAL", "confidence": "HIGH",
             "replacement": "AES-256-GCM",
             "risk": "RC4 is completely broken.",
             "fix": "Replace with AES-256-GCM",
             "migration_priority": "CRITICAL"},
    "DES": {"vulnerability": "DES/3DES", "severity": "CRITICAL", "confidence": "HIGH",
            "replacement": "AES-256-GCM",
            "risk": "DES/3DES are deprecated and broken.",
            "fix": "Replace with AES-256-GCM",
            "migration_priority": "CRITICAL"},
    "Blowfish": {"vulnerability": "Blowfish", "severity": "HIGH", "confidence": "HIGH",
                 "replacement": "AES-256-GCM",
                 "risk": "Blowfish has known weaknesses including birthday attacks.",
                 "fix": "Replace with AES-256-GCM",
                 "migration_priority": "HIGH"},
}

def _is_test_or_docs_file(filepath):
    """Returns True if file is test/docs — lower confidence for findings."""
    path_lower = filepath.lower()
    test_indicators = ["test", "tests", "spec", "docs", "documentation",
                       "example", "examples", "fixture", "fixtures", "mock"]
    parts = path_lower.replace("\\", "/").split("/")
    for part in parts:
        for indicator in test_indicators:
            if indicator in part:
                return True
    return False


def _get_code_snippet(lines, lineno, context=1):
    """Returns a code snippet around the given line number."""
    start = max(0, lineno - 1 - context)
    end = min(len(lines), lineno + context)
    snippet_lines = []
    for i in range(start, end):
        marker = ">>>" if i == lineno - 1 else "   "
        snippet_lines.append(f"{marker} {i+1}: {lines[i].rstrip()}")
    return "\n".join(snippet_lines)


def scan_python_ast(code, file_path):
    """
    AST-based Python scanner.
    Only flags ACTUAL function calls and imports — not comments or plain text.
    Returns findings with full metadata including confidence, risk, fix, migration_priority.
    """
    findings = []
    is_test = _is_test_or_docs_file(file_path)

    try:
        tree = ast.parse(code)
        lines = code.splitlines()
    except SyntaxError:
        return findings
    except Exception:
        return findings

    imported_modules = set()
    imported_names = set()

    # ── Pass 1: collect imports ──────────────────────────────
    for node in ast.walk(tree):
        # from X import Y
        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                imported_names.add(alias.asname or alias.name)
                # Flag dangerous imports directly
                for vuln_name, meta in VULNERABLE_IMPORTS.items():
                    if alias.name == vuln_name or alias.asname == vuln_name:
                        confidence = "MEDIUM" if is_test else meta["confidence"]
                        snippet = _get_code_snippet(lines, node.lineno)
                        findings.append({
                            "file": file_path,
                            "line": node.lineno,
                            "code": lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                            "snippet": snippet,
                            "vulnerability": meta["vulnerability"],
                            "severity": meta["severity"],
                            "confidence": confidence,
                            "replacement": meta["replacement"],
                            "risk_explanation": meta["risk"],
                            "recommended_fix": meta["fix"],
                            "migration_priority": meta["migration_priority"],
                            "detection_method": "AST_IMPORT",
                            "is_test_file": is_test,
                        })
        # import X
        elif isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.add(alias.asname or alias.name)

    # ── Pass 2: scan function calls ──────────────────────────
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue

        func_name = ""
        full_name = ""

        if isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            # Build full dotted name e.g. hashlib.md5
            if isinstance(node.func.value, ast.Name):
                full_name = f"{node.func.value.id}.{func_name}"
            elif isinstance(node.func.value, ast.Attribute):
                full_name = f"{node.func.value.attr}.{func_name}"

        elif isinstance(node.func, ast.Name):
            func_name = node.func.id
            full_name = func_name

        if not func_name:
            continue

        # ── hashlib.md5 / hashlib.sha1 ──────────────────────
        if full_name in ("hashlib.md5", "hashlib.sha1", "hashlib.new"):
            vuln_key = "md5" if "md5" in full_name else "sha1"
            if full_name == "hashlib.new":
                # Check first arg for algorithm name
                if node.args and isinstance(node.args[0], ast.Constant):
                    arg_val = str(node.args[0].value).lower()
                    if "md5" in arg_val:
                        vuln_key = "md5"
                    elif "sha1" in arg_val:
                        vuln_key = "sha1"
                    else:
                        continue
                else:
                    continue

            meta = CRYPTO_CALLS[vuln_key]
            confidence = "MEDIUM" if is_test else "HIGH"
            snippet = _get_code_snippet(lines, node.lineno)
            findings.append({
                "file": file_path,
                "line": node.lineno,
                "code": lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                "snippet": snippet,
                "vulnerability": meta["vulnerability"],
                "severity": meta["severity"],
                "confidence": confidence,
                "replacement": meta["replacement"],
                "risk_explanation": meta["risk"],
                "recommended_fix": meta["fix"],
                "migration_priority": meta["migration_priority"],
                "detection_method": "AST_CALL",
                "is_test_file": is_test,
            })

        # ── RSA.generate / rsa.generate_private_key ─────────
        elif func_name in ("generate", "generate_private_key") and any(
            mod in full_name for mod in ("RSA", "rsa", "ec", "EC", "dsa", "DSA", "dh", "DH")
        ):
            vuln_key = "generate_private_key" if func_name == "generate_private_key" else "generate"
            meta = CRYPTO_CALLS[vuln_key]
            confidence = "MEDIUM" if is_test else "HIGH"
            snippet = _get_code_snippet(lines, node.lineno)
            findings.append({
                "file": file_path,
                "line": node.lineno,
                "code": lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                "snippet": snippet,
                "vulnerability": meta["vulnerability"],
                "severity": meta["severity"],
                "confidence": confidence,
                "replacement": meta["replacement"],
                "risk_explanation": meta["risk"],
                "recommended_fix": meta["fix"],
                "migration_priority": meta["migration_priority"],
                "detection_method": "AST_CALL",
                "is_test_file": is_test,
            })

        # ── jwt.decode without algorithms ───────────────────
        elif func_name == "decode" and "jwt" in full_name.lower():
            # Only flag if options show verify=False or no algorithms specified
            has_unsafe = False
            for kw in node.keywords:
                if kw.arg == "options" and isinstance(kw.value, ast.Dict):
                    for k, v in zip(kw.value.keys, kw.value.values):
                        if isinstance(k, ast.Constant) and "verify" in str(k.value).lower():
                            if isinstance(v, ast.Constant) and v.value is False:
                                has_unsafe = True
                if kw.arg == "algorithms":
                    break
            else:
                has_unsafe = True  # no algorithms kwarg

            if has_unsafe:
                meta = CRYPTO_CALLS["decode"]
                confidence = "LOW" if is_test else "MEDIUM"
                snippet = _get_code_snippet(lines, node.lineno)
                findings.append({
                    "file": file_path,
                    "line": node.lineno,
                    "code": lines[node.lineno - 1].strip() if node.lineno <= len(lines) else "",
                    "snippet": snippet,
                    "vulnerability": meta["vulnerability"],
                    "severity": meta["severity"],
                    "confidence": confidence,
                    "replacement": meta["replacement"],
                    "risk_explanation": meta["risk"],
                    "recommended_fix": meta["fix"],
                    "migration_priority": meta["migration_priority"],
                    "detection_method": "AST_CALL",
                    "is_test_file": is_test,
                })

    return findings
