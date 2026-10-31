"""The progress console sink must import on every Python the package supports.

Why this exists. ``core/progress.py`` defines ``_ConsoleSink``, a ``logging``
stream handler. A type-checking cleanup wrote its base as
``logging.StreamHandler[Any]`` so the checker could see the generic parameter.
The bases of a class statement are evaluated when the module is imported, and
``logging.StreamHandler`` only accepts a subscript at run time from Python 3.11
(it has no ``__class_getitem__`` on 3.10). The package declares
``requires-python >= 3.10``, so on 3.10 the import raised
``TypeError: 'type' object is not subscriptable``, and every module that imports
the progress display (the orchestrator, the execution engine, ``ash merge`` and
``ash scan``) failed to load. The type checker cannot see this, because the
typeshed stub declares ``StreamHandler`` generic on every version.

What is asserted. The first test reads the source and requires that no base of
``_ConsoleSink`` is a subscript expression. That check fails on every Python
version when the subscript is present, so it does not depend on which
interpreter runs the suite. The second test imports the module and requires the
class to be a real ``logging.StreamHandler`` subclass, which is the check that
fails with ``TypeError`` on 3.10 for the subscripted form.
"""

import ast
import logging
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

PROGRESS_SOURCE = (
    Path(__file__).resolve().parents[3]
    / "automated_security_helper"
    / "core"
    / "progress.py"
)


def _console_sink_bases() -> list[ast.expr]:
    tree = ast.parse(PROGRESS_SOURCE.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "_ConsoleSink":
            return list(node.bases)
    raise AssertionError("_ConsoleSink is not defined in core/progress.py")


def test_no_base_of_the_console_sink_is_a_subscript():
    subscripted = [
        ast.unparse(base)
        for base in _console_sink_bases()
        if isinstance(base, ast.Subscript)
    ]
    assert subscripted == []


def test_the_console_sink_is_a_stream_handler():
    from automated_security_helper.core.progress import _ConsoleSink

    assert issubclass(_ConsoleSink, logging.StreamHandler)
