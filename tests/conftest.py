"""Keep executable scenario/demo scripts out of pytest collection.

Several historical ``test_*.py`` files are command-line demonstrations: they
run assertions, print scenario reports, or call Gemini at module import time,
but define no pytest test functions. Importing those files during collection
causes real API calls, quota exhaustion, and collection-time failures. They
remain runnable directly with ``python -m tests.<module>``; pytest collects
only modules that actually define pytest-style tests.
"""

import ast
from pathlib import Path


def _contains_pytest_tests(tree: ast.AST) -> bool:
    """Return True for module-level tests or tests inside pytest test classes."""
    for node in getattr(tree, "body", []):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_"):
            return True
        if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            if any(
                isinstance(member, (ast.FunctionDef, ast.AsyncFunctionDef))
                and member.name.startswith("test_")
                for member in node.body
            ):
                return True
    return False


def pytest_ignore_collect(collection_path: Path, config) -> bool | None:
    """Ignore only test-named scripts that contain no pytest test functions."""
    path = Path(collection_path)
    if path.suffix != ".py" or not path.name.startswith("test_"):
        return None
    if path.parent.name != "tests":
        return None

    try:
        tree = ast.parse(path.read_text(encoding="utf-8-sig"))
    except (OSError, SyntaxError, UnicodeError):
        # Do not hide a malformed Python file; let pytest report it.
        return None

    return not _contains_pytest_tests(tree)
