# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""No bare ``importlib.invalidate_caches()`` call outside the one helper.

The stdlib call races against itself across threads (see
``test_import_cache_invalidation_is_serialized``), so every ASH call site
must go through ``utils.import_caches.invalidate_import_caches``, which
holds one lock. This scan keeps a new call site from reintroducing the
race: it parses every ``.py`` file of the installed package and fails on
any call of ``importlib.invalidate_caches`` (or a rebinding import of
``invalidate_caches`` from ``importlib``) outside the helper's own module.
A planted source string is the control that the scanner sees the pattern.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

import automated_security_helper
from automated_security_helper.utils import import_caches

pytestmark = pytest.mark.unit

_PACKAGE_ROOT = Path(automated_security_helper.__file__).resolve().parent
_HELPER_MODULE = Path(import_caches.__file__).resolve()


def _bare_invalidation_lines(source: str, filename: str) -> list[int]:
    """Line numbers of bare stdlib cache-invalidation uses in ``source``."""
    tree = ast.parse(source, filename=filename)
    lines: list[int] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if (
                isinstance(func, ast.Attribute)
                and func.attr == "invalidate_caches"
                and isinstance(func.value, ast.Name)
                and func.value.id == "importlib"
            ):
                lines.append(node.lineno)
        elif isinstance(node, ast.ImportFrom):
            # A rebinding import would let a bare-looking call hide behind
            # a plain name, so the import itself is refused too.
            if node.module == "importlib" and any(
                alias.name == "invalidate_caches" for alias in node.names
            ):
                lines.append(node.lineno)
    return lines


def test_the_scanner_sees_the_pattern() -> None:
    """Planted control: both spellings are found, a clean source is not."""
    planted = "import importlib\nimportlib.invalidate_caches()\n"
    assert _bare_invalidation_lines(planted, "<planted>") == [2]
    rebound = "from importlib import invalidate_caches\ninvalidate_caches()\n"
    assert _bare_invalidation_lines(rebound, "<rebound>") == [1]
    clean = "from automated_security_helper.utils.import_caches import (\n"
    clean += "    invalidate_import_caches,\n)\ninvalidate_import_caches()\n"
    assert _bare_invalidation_lines(clean, "<clean>") == []


def test_the_helper_module_holds_the_one_bare_call() -> None:
    """Second control: the helper's own serialized call is visible."""
    source = _HELPER_MODULE.read_text(encoding="utf-8")
    assert len(_bare_invalidation_lines(source, str(_HELPER_MODULE))) == 1


def test_no_bare_invalidation_outside_the_helper() -> None:
    offenders: dict[str, list[int]] = {}
    scanned = 0
    for path in sorted(_PACKAGE_ROOT.rglob("*.py")):
        resolved = path.resolve()
        if resolved == _HELPER_MODULE:
            continue
        scanned += 1
        lines = _bare_invalidation_lines(
            resolved.read_text(encoding="utf-8"), str(resolved)
        )
        if lines:
            offenders[str(resolved.relative_to(_PACKAGE_ROOT))] = lines
    # The denominator: an empty walk would pass vacuously.
    assert scanned > 100, f"only {scanned} files scanned under {_PACKAGE_ROOT}"
    assert offenders == {}, (
        "bare importlib.invalidate_caches() outside the helper; route it "
        f"through invalidate_import_caches instead: {offenders!r}"
    )
