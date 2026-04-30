import ast

class QuantumASTScanner:
    def __init__(self):
        self.findings = []

    def scan_file(self, code, filename):
        try:
            tree = ast.parse(code)
            self.visit(tree, filename)
        except Exception:
            pass
        return self.findings

    def visit(self, node, filename):
        for child in ast.iter_child_nodes(node):
            self.check_node(child, filename)
            self.visit(child, filename)

    def check_node(self, node, filename):
        # Detect hashlib usage
        if isinstance(node, ast.Call):
            if hasattr(node.func, 'attr'):
                func_name = node.func.attr.lower()

                if func_name == "md5":
                    self.add_finding(filename, node.lineno, "MD5", "MEDIUM", "Use SHA-3 or SPHINCS+")

                if func_name == "sha1":
                    self.add_finding(filename, node.lineno, "SHA1", "MEDIUM", "Use SHA-3 or SPHINCS+")

        # Detect RSA usage
        if isinstance(node, ast.Call):
            if hasattr(node.func, 'id') and node.func.id == "RSA":
                self.add_finding(filename, node.lineno, "RSA", "CRITICAL", "Use CRYSTALS-Kyber")

    def add_finding(self, file, line, vuln, severity, fix):
        self.findings.append({
            "file": file,
            "line": line,
            "vulnerability": vuln,
            "severity": severity,
            "replacement": fix
        })
