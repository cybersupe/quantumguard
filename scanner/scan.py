# ============================================================
# QuantumGuard — Core Scanner v2.4
# Copyright (c) 2026 Pavansudheer Payyavula / MANGSRI
# Licensed under AGPL v3 — github.com/cybersupe/quantumguard
# Standards: NIST FIPS 203, FIPS 204, FIPS 205
# ============================================================

import os
import re
import math
import time
import json
from datetime import datetime
from scanner.patterns import VULNERABLE_PATTERNS, SEVERITY_SCORE
from scanner.ast_scanner import scan_python_ast
from scanner.js_ast_scanner import scan_js_directory

# ── Directories to always skip ────────────────────────────
SKIP_DIRS = {
    "venv", "node_modules", ".git", "__pycache__", ".tox",
    "dist", "build", ".eggs", "htmlcov", ".mypy_cache",
    "vendor", "third_party", "thirdparty", "extern", "external",
    "deps", "dependencies", ".cache", "coverage", ".nyc_output",
    "bower_components", "jspm_packages", "target", "out",
}

TEST_PATH_INDICATORS = [
    "test", "tests", "spec", "docs", "documentation",
    "example", "examples", "fixture", "fixtures", "mock", "mocks",
    "sample", "samples", "demo", "demos", "tutorial", "tutorials",
]

SUPPORTED_EXTENSIONS = (
    ".py", ".js", ".java", ".ts", ".go",
    ".rs", ".c", ".cpp", ".cc", ".h", ".hpp"
)

MAX_FILES = 200
MAX_LINE_LENGTH = 500

FRONTEND_FILE_INDICATORS = ["component", "view", "page", "ui", "layout", "style", "animation"]

HARDCODED_SECRET_ALLOWLIST = [
    r"(?i)(example|sample|test|fake|dummy|placeholder|your[-_]?|<|>|\.\.\.|xxx)",
    r"(?i)(password\s*=\s*['\"](?:password|pass|test|admin|secret|changeme|letmein|123|abc)['\"])",
]


def _is_test_or_docs_path(filepath):
    path_lower = filepath.lower().replace("\\", "/")
    parts = path_lower.split("/")
    for part in parts:
        for indicator in TEST_PATH_INDICATORS:
            if indicator == part or part.startswith(indicator + "_") or part.endswith("_" + indicator):
                return True
    return False


def _is_frontend_file(filepath):
    name = os.path.basename(filepath).lower()
    for indicator in FRONTEND_FILE_INDICATORS:
        if indicator in name:
            return True
    return False


def _is_comment_line(line, ext):
    stripped = line.strip()
    if not stripped:
        return True
    if ext in (".py",):
        if stripped.startswith("#"):
            return True
    if ext in (".js", ".ts", ".java", ".go", ".rs", ".c", ".cpp", ".cc", ".h", ".hpp"):
        if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("/*"):
            return True
    if stripped.startswith("*") or stripped.startswith("*/"):
        return True
    return False


def _is_allowlisted_secret(line):
    for pattern in HARDCODED_SECRET_ALLOWLIST:
        if re.search(pattern, line):
            return True
    return False


def _is_weak_random_in_crypto_context(line):
    line_lower = line.lower()
    crypto_context = [
        "key", "token", "secret", "password", "salt", "nonce",
        "iv", "seed", "session", "auth", "csrf", "otp",
    ]
    return any(kw in line_lower for kw in crypto_context)


def _get_confidence(vuln_name, line, is_test, ext):
    if is_test:
        return "LOW"
    stripped = line.strip()
    if _is_comment_line(line, ext):
        return "LOW"
    if any(tok in stripped for tok in ["(", "import ", "require(", "new ", "getInstance"]):
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
        "RC4": "RC4 is completely broken with multiple practical attacks.",
        "DES": "DES/3DES are deprecated. Key sizes are insufficient even without quantum threats.",
        "ECB_MODE": "ECB mode reveals patterns in encrypted data regardless of key strength.",
        "WEAK_TLS": "Older TLS versions have known vulnerabilities. TLS 1.3 minimum is required.",
        "WEAK_KEY_SIZE": "Small RSA/DH key sizes are breakable classically. Quantum computers accelerate this.",
        "HARDCODED_SECRET": "Hardcoded secrets are exposed in source code and version history.",
        "WEAK_RANDOM": "Non-cryptographic random number generators are predictable — never use for keys, tokens, or salts.",
        "JWT_NONE_ALG": "JWT with 'none' algorithm or disabled verification allows token forgery.",
        "BLOWFISH": "Blowfish has a 64-bit block size making it vulnerable to birthday attacks.",
        "MD4": "MD4 is completely broken and should never be used.",
    }
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


def _deduplicate_findings(findings):
    seen = {}
    confidence_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    for f in findings:
        key = (f["file"], f["line"], f["vulnerability"])
        if key not in seen:
            seen[key] = f
        else:
            existing_rank = confidence_rank.get(seen[key].get("confidence", "MEDIUM"), 2)
            new_rank = confidence_rank.get(f.get("confidence", "MEDIUM"), 2)
            if new_rank > existing_rank:
                seen[key] = f
    return list(seen.values())


def scan_file(filepath):
    findings = []
    ext = os.path.splitext(filepath)[1].lower()
    is_test = _is_test_or_docs_path(filepath)
    is_frontend = _is_frontend_file(filepath)

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()

        code = "".join(lines)

        ast_lines_map = {}
        if ext == ".py":
            ast_findings = scan_python_ast(code, filepath)
            findings.extend(ast_findings)
            for af in ast_findings:
                key = af["line"]
                ast_lines_map.setdefault(key, set()).add(af["vulnerability"])

        for line_num, line in enumerate(lines, start=1):
            if len(line) > MAX_LINE_LENGTH:
                continue
            if _is_comment_line(line, ext):
                continue

            for vuln_name, vuln_data in VULNERABLE_PATTERNS.items():
                if vuln_name == "WEAK_RANDOM" and is_frontend:
                    continue
                if vuln_name == "WEAK_RANDOM" and not _is_weak_random_in_crypto_context(line):
                    continue

                patterns = vuln_data.get("patterns", [])
                for pattern in patterns:
                    try:
                        if re.search(pattern, line):
                            if ext == ".py":
                                ast_vulns = ast_lines_map.get(line_num, set())
                                base_vuln = vuln_name.split("_")[0]
                                if any(av.startswith(base_vuln) or base_vuln in av for av in ast_vulns):
                                    break

                            if vuln_name == "HARDCODED_SECRET" and _is_allowlisted_secret(line):
                                break

                            confidence = _get_confidence(vuln_name, line, is_test, ext)
                            severity = vuln_data["severity"]

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
                            break
                    except re.error:
                        continue

    except Exception as e:
        print(f"[QuantumGuard] Error reading {filepath}: {e}")

    return _deduplicate_findings(findings)


def scan_directory(directory):
    all_findings = []
    file_count = 0

    for root, dirs, files in os.walk(directory):
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

    all_findings += scan_js_directory(directory)
    return _deduplicate_findings(all_findings)


def calculate_score(findings):
    """
    Scoring v2.4 — exponential decay, never returns 0.
    Floor: 20. Clean repo: 100.
    """
    if not findings:
        return 100

    vuln_groups = {}
    for f in findings:
        vuln = f.get("vulnerability", "UNKNOWN")
        vuln_groups.setdefault(vuln, []).append(f)

    total_penalty = 0.0

    for vuln, group in vuln_groups.items():
        for i, f in enumerate(group):
            base_penalty = SEVERITY_SCORE.get(f.get("severity", "MEDIUM"), 3)
            confidence = f.get("confidence", "MEDIUM")
            is_test = f.get("is_test_file", False)

            if confidence == "HIGH":
                conf_mult = 1.0
            elif confidence == "MEDIUM":
                conf_mult = 0.5
            else:
                conf_mult = 0.0

            if is_test:
                conf_mult *= 0.25

            file_path = str(f.get("file", "")).lower()
            if any(x in file_path for x in ["auth", "crypto", "security", "jwt", "token", "config", "key"]):
                conf_mult *= 1.25

            if i == 0:
                repeat_mult = 1.0
            elif i == 1:
                repeat_mult = 0.8
            elif i == 2:
                repeat_mult = 0.6
            else:
                repeat_mult = 0.4

            total_penalty += base_penalty * conf_mult * repeat_mult

    raw_score = 100 * math.exp(-total_penalty / 80)
    score = max(20, round(raw_score))
    return max(0, min(100, score))


def generate_score_explanation(findings, score):
    """
    Generate human-readable bullet points explaining WHY the score is what it is.
    Returns a list of strings shown in the UI under "Why this score?"
    """
    if not findings:
        return ["No vulnerabilities detected — codebase appears quantum-safe."]

    explanation = []

    # Count by vuln type (HIGH confidence only, non-test)
    vuln_counts = {}
    for f in findings:
        if f.get("confidence") == "LOW":
            continue
        if f.get("is_test_file"):
            continue
        vuln = f.get("vulnerability", "UNKNOWN")
        sev = f.get("severity", "MEDIUM")
        key = (vuln, sev)
        vuln_counts[key] = vuln_counts.get(key, 0) + 1

    # Build explanation lines ordered by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    sorted_vulns = sorted(vuln_counts.items(), key=lambda x: (severity_order.get(x[0][1], 3), -x[1]))

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
        "WEAK_RANDOM":      "Insecure random number generator detected in crypto context",
        "JWT_NONE_ALG":     "JWT signature verification disabled — token forgery risk",
        "BLOWFISH":         "Blowfish cipher detected — 64-bit block size, use AES-256-GCM",
        "MD4":              "MD4 hashing detected — completely broken",
        "SHA256_SIGNED":    "SHA-256 with asymmetric signing — inherits quantum vulnerability",
    }

    SEV_PREFIX = {
        "CRITICAL": "🔴 CRITICAL",
        "HIGH":     "🟡 HIGH",
        "MEDIUM":   "🟠 MEDIUM",
    }

    for (vuln, sev), count in sorted_vulns[:8]:  # max 8 lines
        base_vuln = vuln.split("_")[0] if "_" in vuln else vuln
        desc = None
        for key in VULN_DESCRIPTIONS:
            if vuln.startswith(key) or key.startswith(base_vuln):
                desc = VULN_DESCRIPTIONS[key]
                break
        if not desc:
            desc = f"{vuln} detected — migration required"

        prefix = SEV_PREFIX.get(sev, "⚪")
        count_str = f" ({count} instance{'s' if count > 1 else ''})" if count > 1 else ""
        explanation.append(f"{prefix}: {desc}{count_str}")

    # Overall score context
    if score <= 25:
        explanation.append("⚠️  Score is critically low — immediate remediation required before production use.")
    elif score <= 50:
        explanation.append("⚠️  Score indicates significant quantum risk — migration planning should begin now.")
    elif score <= 75:
        explanation.append("ℹ️  Score indicates moderate risk — some algorithms need upgrading.")
    else:
        explanation.append("✅  Score indicates good quantum posture — continue monitoring NIST PQC updates.")

    return explanation


def generate_scan_summary(directory, findings, scan_start_time):
    """
    Generate scan metadata: files scanned, scan time, languages detected.
    """
    total_files = 0
    files_scanned = 0
    languages = set()
    ext_map = {
        ".py": "Python", ".js": "JavaScript", ".ts": "TypeScript",
        ".java": "Java", ".go": "Go", ".rs": "Rust",
        ".c": "C", ".cpp": "C++", ".cc": "C++",
        ".h": "C/C++ Header", ".hpp": "C++ Header",
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

    scan_time_seconds = round(time.time() - scan_start_time, 1)
    if scan_time_seconds < 60:
        scan_time_str = f"{scan_time_seconds}s"
    else:
        scan_time_str = f"{round(scan_time_seconds / 60, 1)}m"

    # Files with issues
    files_with_issues = len({f["file"] for f in findings if f.get("confidence") != "LOW"})

    # Overall confidence
    high_conf = sum(1 for f in findings if f.get("confidence") == "HIGH")
    med_conf  = sum(1 for f in findings if f.get("confidence") == "MEDIUM")
    total_real = high_conf + med_conf

    if total_real == 0:
        overall_confidence = "High"
        confidence_note = "No findings — high confidence the codebase is clean."
    elif high_conf / max(total_real, 1) >= 0.7:
        overall_confidence = "High"
        confidence_note = f"{high_conf} of {total_real} findings confirmed by AST or direct API call."
    elif high_conf / max(total_real, 1) >= 0.4:
        overall_confidence = "Medium"
        confidence_note = f"Mix of high and medium confidence findings. Review each finding before fixing."
    else:
        overall_confidence = "Low"
        confidence_note = "Most findings are pattern-based. Manual review recommended."

    return {
        "total_files": total_files,
        "files_scanned": files_scanned,
        "files_with_issues": files_with_issues,
        "scan_time": scan_time_str,
        "languages_detected": sorted(list(languages)),
        "overall_confidence": overall_confidence,
        "confidence_note": confidence_note,
        "max_files_limit": MAX_FILES,
        "truncated": total_files > MAX_FILES,
    }


def check_crypto_agility(directory):
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
                    ext = os.path.splitext(filepath)[1].lower()
                    if _is_comment_line(line, ext):
                        continue

                    for pattern, desc, fix in hardcoded_patterns:
                        if re.search(pattern, line):
                            agility_findings.append({
                                "file": filepath, "line": line_num,
                                "code": line.strip(), "type": "hardcoded",
                                "description": desc, "fix": fix,
                                "recommendation": "Move to environment variable or config file",
                                "impact": "Hardcoded crypto makes quantum migration expensive and error-prone",
                            })

                    for pattern, desc in configurable_patterns:
                        if re.search(pattern, line):
                            agility_findings.append({
                                "file": filepath, "line": line_num,
                                "code": line.strip(), "type": "configurable",
                                "description": desc, "fix": "Good practice — maintain this pattern",
                                "recommendation": "Ensure PQC algorithms are available as config options",
                                "impact": "Configurable crypto enables fast PQC migration",
                            })

            except Exception:
                continue

    hardcoded   = len([f for f in agility_findings if f["type"] == "hardcoded"])
    configurable = len([f for f in agility_findings if f["type"] == "configurable"])
    agility_score = max(0, min(100, 100 - (hardcoded * 5) + (configurable * 3)))

    if agility_score >= 90:
        status = "HIGH AGILITY"; migration_ease = "Very Easy"
    elif agility_score >= 70:
        status = "MODERATE AGILITY"; migration_ease = "Moderate"
    elif agility_score >= 40:
        status = "LOW AGILITY"; migration_ease = "Difficult"
    else:
        status = "VERY LOW AGILITY"; migration_ease = "Very Difficult"

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
    print(f"\n[QuantumGuard] Scanning: {directory}\n")
    start = time.time()
    findings = scan_directory(directory)
    score = calculate_score(findings)

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0}
    for f in findings:
        sev = f.get("severity", "MEDIUM")
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    report = {
        "meta": {
            "tool": "QuantumGuard", "version": "2.4",
            "company": "Mangsri QuantumGuard LLC",
            "website": "https://quantumguard.site",
            "standards": ["NIST FIPS 203 (ML-KEM)", "NIST FIPS 204 (ML-DSA)", "NIST FIPS 205 (SLH-DSA)"],
            "scanned_at": datetime.now().isoformat(),
            "license": "AGPL v3",
        },
        "directory": directory,
        "quantum_readiness_score": score,
        "score_explanation": generate_score_explanation(findings, score),
        "scan_summary": generate_scan_summary(directory, findings, start),
        "total_findings": len(findings),
        "severity_summary": severity_counts,
        "findings": findings,
    }

    output_path = os.path.join("reports", "report.json")
    os.makedirs("reports", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)

    print(f"[QuantumGuard] Score: {score}/100")
    print(f"[QuantumGuard] Findings: {len(findings)}")
    print(f"[QuantumGuard] Report saved to: {output_path}\n")
    return report
