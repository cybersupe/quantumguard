from tree_sitter import Language, Parser

import tree_sitter_python as tspython
import tree_sitter_javascript as tsjavascript


LANGUAGES = {
    "python": Language(tspython.language()),
    "javascript": Language(tsjavascript.language()),
}


EXTENSION_MAP = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
}


def get_language_from_file(file_path: str):
    for ext, lang in EXTENSION_MAP.items():
        if file_path.endswith(ext):
            return lang
    return None


def get_parser(language: str) -> Parser:
    parser = Parser()
    parser.language = LANGUAGES[language]
    return parser