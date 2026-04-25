import os
import re
import json
from datetime import datetime
from scanner.patterns import VULNERABLE_PATTERNS, SEVERITY_SCORE


def scan_file(filepath):
    findings = []
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        for line_num, line in enumerate(lines, start=1):
            for vuln_name, vuln_data in VULNERABLE_PATTERNS.items():
                for pattern in vuln_data["patterns"]:
                    if re.search(pattern, line):
                        findings.append({
                            "file": filepath,
                            "line": line_num,
                            "code": line.strip(),
                            "vulnerability": vuln_name,
                            "severity": vuln_data["severity"],
                            "replacement": vuln_data["replacement"],
                        })
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
    return findings


def scan_directory(directory):
    all_findings = []
    supported = (".py", ".js", ".java", ".ts", ".go", ".rs")
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in ["venv", "node_modules", ".git", "__pycache__"]]
        for file in files:
            if file.endswith(supported):
                filepath = os.path.join(root, file)
                findings = scan_file(filepath)
                all_findings.extend(findings)
    return all_findings


def calculate_score(findings):
    if not findings:
        return 100
    total_penalty = sum(SEVERITY_SCORE.get(f["severity"], 0) for f in findings)
    score = max(0, 100 - total_penalty)
    return score


def generate_report(directory):
    print(f"\nScanning: {directory}\n")
    findings = scan_directory(directory)
    score = calculate_score(findings)
    report = {
        "scanned_at": datetime.now().isoformat(),
        "directory": directory,
        "quantum_readiness_score": score,
        "total_findings": len(findings),
        "findings": findings,
    }
    output_path = os.path.join("reports", "report.json")
    os.makedirs("reports", exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"Quantum Readiness Score: {score}/100")
    print(f"Total vulnerabilities found: {len(findings)}")
    print(f"Report saved to: {output_path}\n")
    for f in findings:
        print(f"[{f['severity']}] {f['file']}:{f['line']}")
        print(f"  Code: {f['code']}")
        print(f"  Vulnerability: {f['vulnerability']}")
        print(f"  Fix: Replace with {f['replacement']}\n")
    return report


def check_crypto_agility(directory):
    agility_findings = []
    hardcoded_patterns = [
        (r'AES\.new\([^,]+,\s*AES\.MODE_', 'Hardcoded AES mode'),
        (r'RSA\.generate\(\d+\)', 'Hardcoded RSA key size'),
        (r'key\s*=\s*b[\'"][^\'"]+[\'"]', 'Hardcoded encryption key'),
        (r'iv\s*=\s*b[\'"][^\'"]+[\'"]', 'Hardcoded IV'),
        (r'salt\s*=\s*b[\'"][^\'"]+[\'"]', 'Hardcoded salt'),
        (r'hashlib\.\w+\(', 'Hardcoded hash algorithm'),
        (r'algorithms\s*=\s*\[[\'"][^\'"]+[\'"]\]', 'Hardcoded JWT algorithm'),
    ]
    configurable_patterns = [
        (r'os\.environ\.get\([\'"].*ALGO', 'Configurable algorithm'),
        (r'os\.environ\.get\([\'"].*KEY', 'Configurable key'),
        (r'config\[[\'"]\w*algo\w*[\'"]\]', 'Config-driven algorithm'),
        (r'settings\.\w*algorithm\w*', 'Settings-driven algorithm'),
    ]
    supported = (".py", ".js", ".java", ".ts")
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if d not in ["venv", "node_modules", ".git", "__pycache__"]]
        for file in files:
            if file.endswith(supported):
                filepath = os.path.join(root, file)
                try:
                    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                    for line_num, line in enumerate(lines, start=1):
                        for pattern, desc in hardcoded_patterns:
                            if re.search(pattern, line):
                                agility_findings.append({
                                    "file": filepath,
                                    "line": line_num,
                                    "code": line.strip(),
                                    "type": "hardcoded",
                                    "description": desc,
                                    "recommendation": "Move to environment variable or config file"
                                })
                        for pattern, desc in configurable_patterns:
                            if re.search(pattern, line):
                                agility_findings.append({
                                    "file": filepath,
                                    "line": line_num,
                                    "code": line.strip(),
                                    "type": "configurable",
                                    "description": desc,
                                    "recommendation": "Good practice - already configurable"
                                })
                except Exception:
                    pass
    hardcoded = len([f for f in agility_findings if f["type"] == "hardcoded"])
    configurable = len([f for f in agility_findings if f["type"] == "configurable"])
    total = hardcoded + configurable
    agility_score = round((configurable / total * 100) if total > 0 else 100)
    return {
        "agility_score": agility_score,
        "hardcoded_count": hardcoded,
        "configurable_count": configurable,
        "findings": agility_findings
    }
