from scanner.ast_engine.models import ASTFinding
from scanner.ast_engine.utils import get_node_text, get_line_snippet, walk_tree


def scan_javascript_ast(file_path: str, source: bytes, root_node) -> list[ASTFinding]:
    findings = []

    for node in walk_tree(root_node):
        if node.type not in ["call_expression", "new_expression"]:
            continue

        call_text = get_node_text(source, node)
        line = node.start_point[0] + 1
        col = node.start_point[1] + 1

        if "md5" in call_text:
            findings.append(ASTFinding(
                file_path=file_path,
                language="javascript",
                rule_id="JS-MD5",
                title="MD5 detected",
                severity="HIGH",
                algorithm="MD5",
                line=line,
                column=col,
                code_snippet=get_line_snippet(source, line),
                confidence="HIGH",
                recommendation="Use SHA-256"
            ))

        if "rsa" in call_text.lower():
            findings.append(ASTFinding(
                file_path=file_path,
                language="javascript",
                rule_id="JS-RSA",
                title="RSA detected",
                severity="CRITICAL",
                algorithm="RSA",
                line=line,
                column=col,
                code_snippet=get_line_snippet(source, line),
                confidence="MEDIUM",
                recommendation="Use quantum-safe crypto"
            ))

    return findings