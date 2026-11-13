# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The package's modules, for a guard test that reads every one of them.

A guard that reads the package's source and finds nothing to refuse passes the
same way whether it read every module or none of them. A floor on the count of
modules caught a walk of the wrong directory, but not a part of the package that
left the walk: with ash_aws_plugins' seven modules gone, 222 were still above the
floor of 200, and with the reporters gone, 212. Path.rglob also skipped, without a
word, a directory it could not read and one reached through a link.

So the walk is os.walk, which raises on a directory it cannot read; a linked
directory or module is refused; and the directories that hold modules must be
exactly :data:`PACKAGE_DIRS`, in both directions: a part that left is a failure,
and so is a new one until it is named here. The floor stays for modules lost
from a part that is still there.
"""

from __future__ import annotations

import os
from pathlib import Path

#: The package, beside the tests.
PACKAGE = Path(__file__).resolve().parents[2] / "automated_security_helper"

#: Each directory of the package that holds a module, by its path in it ("" is the
#: package's own).
PACKAGE_DIRS = frozenset(
    {
        "",
        "assets",
        "base",
        "cli",
        "cli/inspect",
        "cli/mcp",
        "config",
        "core",
        "core/phases",
        "core/resource_management",
        "interactions",
        "models",
        "plugin_modules",
        "plugin_modules/ash_aws_plugins",
        "plugin_modules/ash_builtin",
        "plugin_modules/ash_builtin/converters",
        "plugin_modules/ash_builtin/event_handlers",
        "plugin_modules/ash_builtin/reporters",
        "plugin_modules/ash_builtin/scanners",
        "plugin_modules/ash_ferret_plugins",
        "plugin_modules/ash_guarddog_plugins",
        "plugin_modules/ash_hadolint_plugins",
        "plugin_modules/ash_snyk_plugins",
        "plugin_modules/ash_trivy_plugins",
        "plugins",
        "schemas",
        "schemas/cyclonedx_bom_1_6_schema",
        "schemas/gitlab",
        "schemas/ocsf",
        "utils",
        "utils/meta_analysis",
        "utils/sandbox",
        "workspace",
    }
)

#: The package held 231 modules when this was written.
MIN_MODULES = 200


def _unreadable(error: OSError) -> None:
    raise error


def package_sources(package: Path = PACKAGE) -> list[Path]:
    """Every module under *package*, refused unless the walk read all of it."""
    sources: list[Path] = []
    parts: set[str] = set()
    linked: list[str] = []
    for root, dirnames, filenames in os.walk(package, onerror=_unreadable):
        here = Path(root)
        part = here.relative_to(package).as_posix()
        part = "" if part == "." else part
        dirnames[:] = sorted(name for name in dirnames if name != "__pycache__")
        for name in dirnames:
            if (here / name).is_symlink():
                linked.append(f"{part}/{name}".lstrip("/"))
        modules = sorted(name for name in filenames if name.endswith(".py"))
        for name in modules:
            if (here / name).is_symlink():
                linked.append(f"{part}/{name}".lstrip("/"))
        if modules:
            parts.add(part)
        sources.extend(here / name for name in modules)
    assert not linked, (str(package), "linked", sorted(linked))
    missing = sorted(PACKAGE_DIRS - parts)
    assert not missing, (str(package), "missing", missing)
    unnamed = sorted(parts - PACKAGE_DIRS)
    assert not unnamed, (str(package), "not named in PACKAGE_DIRS", unnamed)
    assert len(sources) >= MIN_MODULES, (str(package), len(sources))
    return sorted(sources)
