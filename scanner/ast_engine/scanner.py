from pathlib import Path

from scanner.ast_engine.parsers import get_language_from_file, get_parser
from scanner.ast_engine.registry import get_rules


class QuantumASTScanner:
    def scan_file(self, file_path: str) -> list:
        language = get_language_from_file(file_path)

        if not language:
            return []

        path = Path(file_path)

        try:
            source = path.read_bytes()
        except Exception:
            return []

        parser = get_parser(language)
        tree = parser.parse(source)
        root_node = tree.root_node

        findings = []

        for rule in get_rules(language):
            findings.extend(rule(file_path, source, root_node))

        return findings

    def scan_directory(self, directory: str) -> list:
        all_findings = []

        for path in Path(directory).rglob("*"):
            if path.is_file():
                all_findings.extend(self.scan_file(str(path)))

        return all_findings
        from scanner.ast_engine.scanner import QuantumASTScanner

