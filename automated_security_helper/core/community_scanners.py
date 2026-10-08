# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which in-tree community plugin module provides each community scanner.

Why this exists
---------------
The community scanners that ship inside ASH (``plugin_modules/ash_*_plugins``)
are loaded only when their module is listed in ``ash_plugin_modules`` or passed
with ``--ash-plugin-modules``. A ``--scanners snyk-code`` run without
``ash_snyk_plugins`` listed names a scanner ASH has but did not load, and the
generic "no registered scanner matches" message reads as a typo. This module lets
the scan phase say which module to add instead.

How
---
The mapping is read from the scanner source files, not by importing the
modules: importing one runs its ``@ash_scanner_plugin`` registrations, which
would load the scanners this function exists to report as not loaded. A
scanner's selectable name is the ``name: Literal["..."]`` default of its config
class, a subclass of ``ScannerPluginConfigBase``.
"""

import ast
import functools
from pathlib import Path
from typing import Dict, Optional

_PLUGIN_MODULES = Path(__file__).resolve().parent.parent / "plugin_modules"
_PACKAGE = "automated_security_helper.plugin_modules"


def _scanner_config_names(source: str) -> list[str]:
    """``name`` defaults of every ``ScannerPluginConfigBase`` subclass in *source*."""
    names = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.ClassDef):
            continue
        bases = {
            b.id if isinstance(b, ast.Name) else getattr(b, "attr", None)
            for b in node.bases
        }
        if "ScannerPluginConfigBase" not in bases:
            continue
        for stmt in node.body:
            if (
                isinstance(stmt, ast.AnnAssign)
                and isinstance(stmt.target, ast.Name)
                and stmt.target.id == "name"
                and isinstance(stmt.value, ast.Constant)
                and isinstance(stmt.value.value, str)
            ):
                names.append(stmt.value.value)
    return names


@functools.lru_cache(maxsize=1)
def community_scanner_modules() -> Dict[str, str]:
    """``{scanner name, lowercased: dotted module path}`` for every in-tree module."""
    mapping: Dict[str, str] = {}
    for package in sorted(_PLUGIN_MODULES.glob("ash_*_plugins")):
        if package.name == "ash_builtin" or not (package / "__init__.py").is_file():
            continue
        for source in sorted(package.glob("*.py")):
            for name in _scanner_config_names(source.read_text(encoding="utf-8")):
                mapping.setdefault(name.lower(), f"{_PACKAGE}.{package.name}")
    return mapping


def community_module_for(scanner_name: str) -> Optional[str]:
    """The module that provides *scanner_name*, or None if no in-tree one does."""
    return community_scanner_modules().get(str(scanner_name).lower().strip())
