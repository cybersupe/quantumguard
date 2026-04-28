def get_node_text(source: bytes, node) -> str:
    return source[node.start_byte:node.end_byte].decode("utf-8", errors="ignore")


def get_line_snippet(source: bytes, line_number: int) -> str:
    lines = source.decode("utf-8", errors="ignore").splitlines()
    if 0 <= line_number - 1 < len(lines):
        return lines[line_number - 1].strip()
    return ""


def walk_tree(node):
    yield node
    for child in node.children:
        yield from walk_tree(child)