from dataclasses import dataclass
from typing import Optional, Dict, Any


@dataclass
class ASTFinding:
    file_path: str
    language: str
    rule_id: str
    title: str
    severity: str
    algorithm: str
    line: int
    column: int
    code_snippet: str
    confidence: str
    recommendation: str
    metadata: Optional[Dict[str, Any]] = None