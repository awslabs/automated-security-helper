# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner universe the register tests enumerate, in one place.

The facets totality test, the operational-facets consistency test, the corpus
gate and the resource-id conformance test each need every scanner class the
in-repo plugin packages register. Each kept its own copy of the retry plus the
walk, and the totality test's own docstring names a hand-written second
inventory as the drift class that makes a register test vacuous: a fix to one
copy (a package filter, a retry) would leave the others enumerating a
different universe.
"""

from __future__ import annotations

import importlib
import pkgutil
from typing import Any

from automated_security_helper import plugin_modules
from automated_security_helper.plugin_modules import ash_builtin

#: How many scanners the in-repo plugin packages register, written out rather
#: than derived from them. It is the planted control each register gate checks
#: its enumeration against, so a walk that silently loses a plugin package fails
#: instead of passing over a smaller universe. One number for every gate: while
#: each gate kept its own copy, admissions bumped some copies and not others, and
#: a gate whose copy was left behind failed at the tip. Admitting or removing a
#: scanner changes this number and nothing else here.
SHIPPED_SCANNER_COUNT = 32


def registered_scanner_classes() -> list[type]:
    """Every scanner class the in-repo plugin packages register.

    Package order is alphabetical and classes keep each package's own order,
    so parametrized ids are stable run to run.
    """
    classes: list[type] = []
    seen: set[type] = set()
    modules = sorted(
        pkgutil.iter_modules(plugin_modules.__path__), key=lambda m: m.name
    )
    for info in modules:
        if not info.ispkg:
            continue
        package = importlib.import_module(f"{plugin_modules.__name__}.{info.name}")
        for cls in getattr(package, "ASH_SCANNERS", []):
            if cls not in seen:
                seen.add(cls)
                classes.append(cls)
    return classes


def load_scanner_universe() -> tuple[list[type], Any]:
    """Retry the plugin groups an import-order cycle can cost, then enumerate.

    Import-order cycles can cost ash_builtin a plugin group on first import
    (its own docstring measures which orders); the retry recovers every such
    order and returns what is still lost. Anything still lost belongs to the
    caller's enumeration-guard test, which fails rather than letting the
    universe shrink silently.

    Returns ``(scanner classes, load errors still outstanding)``.
    """
    remaining = ash_builtin.retry_failed_plugin_groups()
    return registered_scanner_classes(), remaining
