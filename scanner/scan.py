# ============================================================
# QuantumGuard — Core Scanner
# Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI
# Licensed under AGPL v3 — github.com/cybersupe/quantumguard
# Standards: NIST FIPS 203, FIPS 204, FIPS 205
# ============================================================

import os
import re
import json
from datetime import datetime
from scanner.patterns import VULNERABLE_PATTERNS, SEVERITY_SCORE
from scanner.ast_scanner import scan_python_ast

# Files/dirs to always skip
SKIP_DIRS = {"venv", "node_modules", ".git", "__pycache__", ".tox",
             "dist", "build", ".eggs", "htmlcov", ".mypy_cache"}

# These paths get confidence downgraded
TEST_PATH_INDICATORS = ["test", "tests", "spec", "docs", "documentation",
                        "example", "examples", "fixture", "fixtures", "mock", "mocks"]

SUPPORTED_EXTENSIONS = (".py", ".js", ".java", ".ts", ".go", ".rs", ".c", ".cpp", ".cc", ".h", ".hpp")

MAX_FILES = 200
MAX_LINE_LENGTH = 500  # skip minified lines


def _is_test_or_docs_path(filepath):
    path_lower = filepath.lower().replace("\\", "/")
    parts = path_lower.split("/")
    for part in parts:
        for indicator in TEST_PATH_INDICATORS:
            if indicator in part:
                return True
    return False


def _is_comment_line(line, ext):
    """Detect if a line is purely a comment."""
    stripped = line.strip()
    if not stripped:
        return True
    if ext in (".py", ".go", ".rs", ".c", ".cpp", ".cc", ".h", ".hpp"):
        if stripped.startswith("#") or stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            return True
    if ext in (".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp"):
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            return True
    return False


def _get_confidence(vuln_name, line, is_test, ext):
    """
    Determine confidence level for a regex finding.
    HIGH   = actual API/function call syntax
    MEDIUM = clear pattern match in real code
    LOW    = likely documentation or text reference
    """
    # Downgrade for test/docs files
    if is_test:
        return "LOW"

    # Downgrade for lines that look like comments or strings only
    stripped = line.strip()

    # If the match is only in a comment
    if _is_comment_line(line, ext):
        return "LOW"

    # If the line has actual function call syntax → HIGH
    if any(ch in stripped for ch in ["(", ".", "import", "require", "new "]):
        return "HIGH"

    return "MEDIUM"


def _get_risk_explanation(vuln_name):
    RISK_MAP = {
        "RSA": "RSA will be broken by Shor's Algorithm on quantum computers. NIST deadline: 2030.",
        "ECC": "Elliptic curve cryptography (ECDSA/ECDH) is vulnerable to Shor's Algorithm.",
        "DH": "Diffie-Hellman key exchange is quantum-vulnerable via Shor's Algorithm.",
        "DSA": "DSA signatures are broken by Shor's Algorithm on quantum hardware.",
        "MD5": "MD5 is cryptographically broken. Grover's algorithm further weakens hash security.",
        "SHA1": "SHA-1 is deprecated. Grover's algorithm halves effective security to ~80 bits.",
        "SHA256_SIGNED": "SHA-256 with RSA/ECDSA signatures inherits the quantum vulnerability of the asymmetric component.",
        "RC4": "RC4 is completely broken with multiple practical attacks. No quantum upgrade needed — just replace now.",
        "DES": "DES/3DES are deprecated. Key sizes are insufficient even without quantum threats.",
        "ECB_MODE": "ECB mode reveals patterns in encrypted data regardless of key strength.",
        "WEAK_TLS": "Older TLS versions have known vulnerabilities. TLS 1.3 minimum is required.",
        "WEAK_KEY_SIZE": "Small RSA/DH key sizes are breakable classically. Quantum computers accelerate this.",
        "HARDCODED_SECRET": "Hardcoded secrets are exposed in source code and version history.",
        "WEAK_RANDOM": "Non-cryptographic random number generators are predictable and unsuitable for security.",
        "JWT_NONE_ALG": "JWT with 'none' algorithm or disabled verification allows token forgery.",
        "BLOWFISH": "Blowfish has a 64-bit block size making it vulnerable to birthday attacks.",
        "MD4": "MD4 is completely broken and should never be used.",
    }
    # Handle compound names like RSA_GO, ECC_RUST, etc.
    for key in RISK_MAP:
        if vuln_name.startswith(key):
            return RISK_MAP[key]
    return "This algorithm is vulnerable to quantum or classical attacks. Migration required."


def _get_migration_priority(severity):
    return {
        "CRITICAL": "URGENT — Fix within 30 days",
        "HIGH": "HIGH — Fix within 90 days",
        "MEDIUM": "MEDIUM — Fix within 6 months",
    }.get(severity, "MEDIUM — Fix within 6 months")


def scan_file(filepath):
    findings = []
    ext = os.path.splitext(filepath)[1].lower()
    is_test = _is_test_or_docs_path(filepath)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        code = "".join(lines)

        # ── AST scan for Python (most accurate — no false positives from comments) ──
        if ext == ".py":
            ast_findings = scan_python_ast(code, filepath)
            findings.extend(ast_findings)
            # Track which lines were already caught by AST to avoid regex duplication
            ast_lines = {f["line"] for f in ast_findings}
        else:
            ast_lines = set()

        # ── Regex scan for all supported languages ──────────
        for line_num, line in enumerate(lines, start=1):
            # Skip AST-already-found lines for Python
            if ext == ".py" and line_num in ast_lines:
                continue

            # Skip very long lines (minified JS/CSS)
            if len(line) > MAX_LINE_LENGTH:
                continue

            # Skip pure comment lines
            if _is_comment_line(line, ext):
                continue

            for vuln_name, vuln_data in VULNERABLE_PATTERNS.items():
                patterns = vuln_data.get("patterns", [])
                for pattern in patterns:
                    try:
                        if re.search(pattern, line):
                            confidence = _get_confidence(vuln_name, line, is_test, ext)
                            severity = vuln_data["severity"]

                            # Downgrade severity for test files
                            if is_test and severity == "CRITICAL":
                                severity = "HIGH"

                            findings.append({
                                "file": filepath,
                                "line": line_num,
                                "code": line.strip(),
                                "snippet": f">>> {line_num}: {line.rstrip()}",
                                "vulnerability": vuln_name,
                                "severity": severity,
                                "confidence": confidence,
                                "replacement": vuln_data["replacement"],
                                "risk_explanation": _get_risk_explanation(vuln_name),
                                "recommended_fix": f"Replace {vuln_name} with {vuln_data['replacement']}",
                                "migration_priority": _get_migration_priority(severity),
                                "detection_method": "REGEX",
                                "is_test_file": is_test,
                            })
                            break  # one match per pattern group per line
                    except re.error:
                        continue

    except Exception as e:
        print(f"[QuantumGuard] Error reading {filepath}: {e}")

    return findings


def scan_directory(directory):
    """
    Scan all supported files in a directory.
    Returns list of findings with full metadata.
    """
    all_findings = []
    file_count = 0

    for root, dirs, files in os.walk(directory):
        # Skip irrelevant directories
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for file in files:
            if file_count >= MAX_FILES:
                break
            if file.endswith(SUPPORTED_EXTENSIONS):
                filepath = os.path.join(root, file)
                try:
                    file_findings = scan_file(filepath)
                    all_findings.extend(file_findings)
                    file_count += 1
                except Exception as e:
                    print(f"[QuantumGuard] Skipping {filepath}: {e}")

        if file_count >= MAX_FILES:
            break

    return all_findings


def calculate_score(findings):
    """
    Calculate quantum readiness score 0–100.
    - Only HIGH confidence findings get full penalty
    - MEDIUM confidence findings get 50% penalty
    - LOW confidence findings get 0% penalty (no score impact)
    - Test file findings get 25% penalty
    """
    if not findings:
        return 100

    total_penalty = 0
    for f in findings:
        base_penalty = SEVERITY_SCORE.get(f.get("severity", "MEDIUM"), 3)
        confidence = f.get("confidence", "MEDIUM")
        is_test = f.get("is_test_file", False)

        if confidence == "HIGH":
            multiplier = 1.0
        elif confidence == "MEDIUM":
            multiplier = 0.5
        else:  # LOW
            multiplier = 0.0

        if is_test:
            multiplier *= 0.25

        total_penalty += base_penalty * multiplier

    score = max(0, round(100 - total_penalty))
    return score


def check_crypto_agility(directory):
    """
    Improved crypto agility checker.
    Score = max(0, 100 - hardcoded_count * 5 + configurable_count * 3)
    Returns: agility_score, hardcoded_count, configurable_count, findings with fix field
    """
    agility_findings = []

    hardcoded_patterns = [
        (r'AES\.new\([^,]+,\s*AES\.MODE_', 'Hardcoded AES mode',
         'Move AES mode to config: CRYPTO_MODE = os.environ.get("CRYPTO_MODE", "GCM")'),
        (r'RSA\.generate\(\d+\)', 'Hardcoded RSA key size',
         'Move key size to config or migrate to ML-KEM (FIPS 203)'),
        (r'key\s*=\s*b[\'"][^\'"]{4,}[\'"]', 'Hardcoded encryption key',
         'Move to AWS Secrets Manager, HashiCorp Vault, or environment variable'),
        (r'iv\s*=\s*b[\'"][^\'"]{4,}[\'"]', 'Hardcoded IV',
         'Generate IV randomly: iv = os.urandom(16)'),
        (r'salt\s*=\s*b[\'"][^\'"]{4,}[\'"]', 'Hardcoded salt',
         'Generate salt randomly: salt = os.urandom(32)'),
        (r'hashlib\.(md5|sha1)\s*\(', 'Hardcoded weak hash algorithm',
         'Replace with hashlib.sha3_256() and make algorithm configurable'),
        (r'algorithms\s*=\s*\[[\'"][^\'"]+[\'"]\]', 'Hardcoded JWT algorithm',
         'Move JWT algorithm to config: JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "RS256")'),
        (r'cipher\s*=\s*[\'"][^\'"]*(AES|DES|RC4|RSA)[^\'\"]*[\'"]', 'Hardcoded cipher name',
         'Move cipher selection to environment variable'),
    ]

    configurable_patterns = [
        (r'os\.environ\.get\([\'"].*(?:ALGO|CIPHER|HASH|CRYPTO|KEY_SIZE)[\'"]', 'Configurable algorithm via env var'),
        (r'config\[[\'"]\w*(?:algo|cipher|hash|crypto)\w*[\'"]\]', 'Config-driven algorithm'),
        (r'settings\.\w*(?:algorithm|cipher|hash)\w*', 'Settings-driven algorithm'),
        (r'getenv\([\'"].*(?:ALGO|CIPHER|HASH)[\'"]', 'Configurable algorithm via getenv'),
        (r'(?:ALGORITHM|CIPHER|HASH_FUNC)\s*=\s*os\.environ', 'Environment-configured crypto'),
    ]

    supported = (".py", ".js", ".java", ".ts")

    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for file in files:
            if not file.endswith(supported):
                continue
            filepath = os.path.join(root, file)
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    lines = f.readlines()

                for line_num, line in enumerate(lines, start=1):
                    # Skip comment lines
                    ext = os.path.splitext(filepath)[1].lower()
                    if _is_comment_line(line, ext):
                        continue

                    for pattern, desc, fix in hardcoded_patterns:
                        if re.search(pattern, line):
                            agility_findings.append({
                                "file": filepath,
                                "line": line_num,
                                "code": line.strip(),
                                "type": "hardcoded",
                                "description": desc,
                                "fix": fix,
                                "recommendation": "Move to environment variable or config file",
                                "impact": "Hardcoded crypto makes quantum migration expensive and error-prone",
                            })

                    for pattern, desc in configurable_patterns:
                        if re.search(pattern, line):
                            agility_findings.append({
                                "file": filepath,
                                "line": line_num,
                                "code": line.strip(),
                                "type": "configurable",
                                "description": desc,
                                "fix": "Good practice — maintain this pattern",
                                "recommendation": "Ensure PQC algorithms are available as config options",
                                "impact": "Configurable crypto enables fast PQC migration",
                            })

            except Exception:
                continue

    hardcoded = len([f for f in agility_findings if f["type"] == "hardcoded"])
    configurable = len([f for f in agility_findings if f["type"] == "configurable"])

    # Improved formula — does not collapse to 0 on first hardcoded finding
    agility_score = max(0, min(100, 100 - (hardcoded * 5) + (configurable * 3)))

    # Determine status label
    if agility_score >= 90:
        status = "HIGH AGILITY"
        migration_ease = "Very Easy"
    elif agility_score >= 70:
        status = "MODERATE AGILITY"
        migration_ease = "Moderate"
    elif agility_score >= 40:
        status = "LOW AGILITY"
        migration_ease = "Difficult"
    else:
        status = "VERY LOW AGILITY"
        migration_ease = "Very Difficult"

    return {
        "agility_score": agility_score,
        "hardcoded_count": hardcoded,
        "configurable_count": configurable,
        "status": status,
        "migration_ease": migration_ease,
        "findings": agility_findings,
        "summary": {
            "total_files_with_issues": len({f["file"] for f in agility_findings}),
            "recommendation": (
                "Excellent crypto agility — easy PQC migration" if agility_score >= 90
                else "Move hardcoded algorithms to environment variables before PQC migration"
            ),
        }
    }


def generate_report(directory):
    """Generate a full JSON report and print summary."""
    print(f"\n[QuantumGuard] Scanning: {directory}\n")
    findings = scan_directory(directory)
    score = calculate_score(findings)

    # Summary by severity
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    report = {
        "meta": {
            "tool": "QuantumGuard",
            "version": "2.0",
            "company": "Mangsri QuantumGuard LLC",
            "website": "https://quantumguard.site",
            "standards": ["NIST FIPS 203 (ML-KEM)", "NIST FIPS 204 (ML-DSA)", "NIST FIPS 205 (SLH-DSA)"],
            "scanned_at": datetime.now().isoformat(),
            "license": "AGPL v3",
        },
        "directory": directory,
        "quantum_readiness_score": score,
        "total_findings": len(findings),
        "severity_summary": severity_counts,
        "findings": findings,
    }

    output_path = os.path.join("reports", "report.json")
    os.makedirs("reports", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[QuantumGuard] Quantum Readiness Score: {score}/100")
    print(f"[QuantumGuard] Total findings: {len(findings)}")
    print(f"[QuantumGuard] CRITICAL: {severity_counts['CRITICAL']} | HIGH: {severity_counts['HIGH']} | MEDIUM: {severity_counts['MEDIUM']}")
    print(f"[QuantumGuard] Report saved to: {output_path}\n")

    for f in findings:
        if f.get("confidence", "MEDIUM") != "LOW":
            print(f"[{f['severity']}][{f.get('confidence','?')}] {f['file']}:{f['line']}")
            print(f"  Vuln: {f['vulnerability']}")
            print(f"  Code: {f['code']}")
            print(f"  Fix:  {f.get('recommended_fix', f['replacement'])}\n")

    return report
