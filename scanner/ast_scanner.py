import ast

def scan_python_ast(code, file_path):
    findings = []
    try:
        tree = ast.parse(code)
    except:
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
                    "type": "MD5 (AST)",
                    "severity": "MEDIUM",
                    "fix": "Use sha256 instead"
                })

    return findings
