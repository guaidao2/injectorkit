"""Every module resolves the names it uses.

A NameError inside an action only surfaces when that action runs, and the
exploitation steps only run against a live target with `--exploit` - which is
exactly the shape the first report had: the scan looked fine and the last line
said `exploit.services: raised NameError: name 'Request' is not defined`.

A syntax check cannot see it and reading every file by hand is not a plan, so
this walks the package with the parser and reports names that are read but never
bound anywhere in their file. It does not try to be a type checker: a name that
is bound in the wrong scope still passes, and that is a deliberate limitation -
what is caught here is the whole-file mistake, which is what actually shipped.
"""

from __future__ import annotations

import ast
import builtins
import unittest
from pathlib import Path

PACKAGE = Path(__file__).resolve().parent.parent / "injectorkit"


def annotation_nodes(tree: ast.AST) -> set[int]:
    """Every node inside an annotation, which is not evaluated at run time.

    The package uses `from __future__ import annotations`, so a name that only
    appears in a signature needs no binding. Treating those as reads would fill
    the report with names that are not a problem.
    """
    marks: set[int] = set()
    for node in ast.walk(tree):
        for field in ("annotation", "returns"):
            value = getattr(node, field, None)
            if value is not None:
                for inner in ast.walk(value):
                    marks.add(id(inner))
    return marks


def bound_names(tree: ast.AST) -> set[str]:
    """Every name the file binds: imports, definitions, assignments, arguments."""
    names: set[str] = set(dir(builtins))
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add((alias.asname or alias.name).split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                names.add(alias.asname or alias.name)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(node.name)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            names.add(node.id)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            names.add(node.name)
        elif isinstance(node, (ast.Global, ast.Nonlocal)):
            names.update(node.names)
    return names


def unbound_reads(tree: ast.AST) -> list[tuple[str, int]]:
    """Names that are read but bound nowhere in the file, with their line."""
    marks = annotation_nodes(tree)
    bound = bound_names(tree)
    missing: dict[str, int] = {}
    for node in ast.walk(tree):
        if id(node) in marks:
            continue
        if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id not in bound:
                missing.setdefault(node.id, node.lineno)
    return sorted(missing.items(), key=lambda item: item[1])


class NoUnboundNames(unittest.TestCase):
    def test_the_package_has_no_file_local_name_errors(self):
        problems: list[str] = []
        for path in sorted(PACKAGE.rglob("*.py")):
            source = path.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(path))
            for name, line in unbound_reads(tree):
                where = path.relative_to(PACKAGE.parent).as_posix()
                problems.append(f"{where}:{line}: {name}")
        self.assertEqual(
            problems,
            [],
            "names read but never bound in their file:\n  " + "\n  ".join(problems),
        )


class TheCheckerItself(unittest.TestCase):
    """If it cannot catch the shape that shipped, it is not worth having."""

    def test_it_reports_a_name_that_was_never_imported(self):
        tree = ast.parse("def f(ctx):\n    return ctx.send(Request.from_url('x'))\n")
        self.assertEqual(unbound_reads(tree), [("Request", 2)])

    def test_a_plain_import_satisfies_it(self):
        tree = ast.parse("from a.b import Request\n\ndef f(ctx):\n    return Request.from_url('x')\n")
        self.assertEqual(unbound_reads(tree), [])

    def test_an_aliased_import_satisfies_it(self):
        tree = ast.parse("from a.b import Request as R\n\ndef f(ctx):\n    return R.from_url('x')\n")
        self.assertEqual(unbound_reads(tree), [])

    def test_a_module_import_satisfies_it(self):
        tree = ast.parse("import os\n\ndef f():\n    return os.getcwd()\n")
        self.assertEqual(unbound_reads(tree), [])

    def test_an_annotation_needs_no_binding(self):
        # The package imports annotations from the future, so a name in a
        # signature is never looked up.
        tree = ast.parse("def f(x: SomethingUndefined) -> AlsoUndefined:\n    return 1\n")
        self.assertEqual(unbound_reads(tree), [])

    def test_a_local_variable_satisfies_it(self):
        tree = ast.parse("def f():\n    total = 1\n    return total\n")
        self.assertEqual(unbound_reads(tree), [])

    def test_a_loop_variable_satisfies_it(self):
        tree = ast.parse("def f(items):\n    for item in items:\n        print(item)\n")
        self.assertEqual(unbound_reads(tree), [])

    def test_a_comprehension_variable_satisfies_it(self):
        tree = ast.parse("def f(items):\n    return [item for item in items]\n")
        self.assertEqual(unbound_reads(tree), [])

    def test_an_except_binding_satisfies_it(self):
        tree = ast.parse("def f():\n    try:\n        pass\n    except ValueError as error:\n        return error\n")
        self.assertEqual(unbound_reads(tree), [])


if __name__ == "__main__":
    unittest.main()
