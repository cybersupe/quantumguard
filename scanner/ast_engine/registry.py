from scanner.ast_engine.rules.python_crypto_rules import scan_python_ast
from scanner.ast_engine.rules.javascript_crypto_rules import scan_javascript_ast


RULES = {
    "python": [scan_python_ast],
    "javascript": [scan_javascript_ast],
}


def get_rules(language: str):
    return RULES.get(language, [])