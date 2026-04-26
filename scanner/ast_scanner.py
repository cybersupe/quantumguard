import ast

def scan_python_ast(code, file_path):
    findings = []
    try:
        tree = ast.parse(code)
    except Exception:
        return findings

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = ""

            if hasattr(node.func, "attr"):
                name = node.func.attr
            elif hasattr(node.func, "id"):
                name = node.func.id

            if name == "md5":
                findings.append({
                    "file": file_path,
                    "line": node.lineno,
                    "code": "hashlib.md5(...)",
                    "vulnerability": "MD5 detected by AST",
                    "severity": "MEDIUM",
                    "replacement": "Use hashlib.sha256() or hashlib.sha3_256() instead"
                })

    return findings
