# ============================================================
# QuantumGuard — JavaScript AST Scanner (Improved v2)
# ============================================================

import re
import os
from typing import Any

try:
    import pyjsparser
    AST_AVAILABLE = True
except ImportError:
    AST_AVAILABLE = False

JS_EXTENSIONS = {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"}

# ===================== CONTEXT FILTER =====================

SECURITY_KEYWORDS = [
    "key", "token", "secret", "password", "auth", "jwt",
    "crypto", "encrypt", "decrypt", "hash", "sign"
]

def is_security_context(line: str) -> bool:
    line = line.lower()
    return any(k in line for k in SECURITY_KEYWORDS)

def is_test_file(path: str) -> bool:
    return any(x in path.lower() for x in ["test", "spec", "mock", "example", "demo"])

# ===================== RULES =====================

RULES = [
    {
        "id": "JS-RAND-001",
        "vulnerability": "Math.random() — Insecure PRNG",
        "severity": "HIGH",
        "confidence": "HIGH",
        "replacement": "Use crypto.getRandomValues() or crypto.randomBytes()",
        "regex": r"\bMath\.random\s*\(",
    },
    {
        "id": "JS-RSA-001",
        "vulnerability": "RSA — Quantum-Vulnerable",
        "severity": "CRITICAL",
        "confidence": "HIGH",
        "replacement": "Plan migration to hybrid PQC (ML-KEM FIPS 203)",
        "regex": r"RSA|RSA-OAEP|RSA-PSS",
    },
    {
        "id": "JS-MD5-001",
        "vulnerability": "MD5 — Broken Hash",
        "severity": "HIGH",
        "confidence": "HIGH",
        "replacement": "Use SHA-256 or SHA-3",
        "regex": r"md5",
    },
    {
        "id": "JS-SHA1-001",
        "vulnerability": "SHA1 — Deprecated",
        "severity": "HIGH",
        "confidence": "HIGH",
        "replacement": "Use SHA-256 or SHA-3",
        "regex": r"sha1",
    },
]

# ===================== AST WALK =====================

def walk_ast(node: Any, findings, lines):
    if not isinstance(node, dict):
        return

    node_type = node.get("type")

    if node_type == "CallExpression":
        callee = node.get("callee", {})

        if (callee.get("type") == "MemberExpression"
                and callee.get("object", {}).get("name") == "Math"
                and callee.get("property", {}).get("name") == "random"):

            line = node.get("loc", {}).get("start", {}).get("line", 0)
            code_line = lines[line-1] if line else ""

            if is_security_context(code_line):
                findings.append(("JS-RAND-001", line, code_line))

    for value in node.values():
        if isinstance(value, dict):
            walk_ast(value, findings, lines)
        elif isinstance(value, list):
            for v in value:
                walk_ast(v, findings, lines)

# ===================== REGEX SCAN =====================

def regex_scan(source, seen):
    hits = []
    lines = source.splitlines()

    for rule in RULES:
        pattern = re.compile(rule["regex"], re.IGNORECASE)

        for i, line in enumerate(lines, 1):
            if pattern.search(line):
                if not is_security_context(line):
                    continue

                hits.append((rule["id"], i, line.strip()))

    return hits

# ===================== MAIN FUNCTION =====================

def scan_js_file(filepath: str):
    findings = []

    if is_test_file(filepath):
        return []

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
    except:
        return []

    lines = source.splitlines()
    raw = []

    # AST
    if AST_AVAILABLE:
        try:
            tree = pyjsparser.parse(source)
            walk_ast(tree, raw, lines)
        except:
            pass

    # Regex fallback
    raw.extend(regex_scan(source, set()))

    # Build final output
    final = []
    rule_map = {r["id"]: r for r in RULES}

    for rule_id, line_no, code in raw:
        rule = rule_map.get(rule_id)
        if not rule:
            continue

        final.append({
            "file": filepath,
            "line": line_no,
            "code": code,
            "vulnerability": rule["vulnerability"],
            "severity": rule["severity"],
            "confidence": rule["confidence"],
            "replacement": rule["replacement"],
            "scanner": "js-ast",
            "language": "JavaScript",
        })

    return final

# ===================== DIRECTORY SCAN =====================

def scan_js_directory(directory):
    results = []

    for root, _, files in os.walk(directory):
        if "node_modules" in root:
            continue

        for f in files:
            if os.path.splitext(f)[1] in JS_EXTENSIONS:
                results.extend(scan_js_file(os.path.join(root, f)))

    return results
