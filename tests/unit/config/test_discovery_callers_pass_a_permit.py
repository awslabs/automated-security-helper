# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every config discovery call passes the caller's permit, or is listed with why it has none.

Discovery opens pyproject.toml, and a source it finds can be a symbolic link to
any file, so a caller with a permit predicate (an MCP session's
config_base_gate, a scan's config_base_gate) must hand it to discovery, which
checks every source before opening any. A call that drops it is the gap the
config cluster's S1 closed four times in run_ash_scan alone. This test finds
every call to the discovery functions in the package and requires a ``permit``
argument, except at the callers listed below, which have no permit to pass.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import List, Tuple

PACKAGE = Path(__file__).resolve().parents[3] / "automated_security_helper"

DISCOVERY_FUNCTIONS = {
    "discover_config_source",
    "find_config_file",
    "check_discovery_candidates",
    "_discovered_config_path",
}

#: Callers with no permit to pass, by module, with the reason.
NO_PERMIT = {
    # Operator CLI commands (config get/lint/validate/update, plugin list,
    # inspect): the operator runs them on their own tree, and no MCP tool
    # reaches them.
    "cli/config.py": "operator CLI",
    "cli/plugin.py": "operator CLI",
    "cli/inspect/inspect_findings_app.py": "operator CLI",
    # Workspace planning. Reached from MCP scan_workspace too; #800's
    # trustpaths lane threads the session's gate through resolve_workspace.
    "workspace/resolver.py": "gated on #800 (trustpaths)",
}


def calls_without_a_permit(source: str) -> List[Tuple[int, str]]:
    """(line, function) for each discovery call in ``source`` that passes no permit.

    ``check_discovery_candidates`` takes the permit as its second positional
    argument; the others as the keyword ``permit``.
    """
    found = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = (
            func.attr
            if isinstance(func, ast.Attribute)
            else func.id
            if isinstance(func, ast.Name)
            else None
        )
        if name not in DISCOVERY_FUNCTIONS:
            continue
        keywords = {kw.arg for kw in node.keywords}
        positional_permit = name == "check_discovery_candidates" and len(node.args) >= 2
        if "permit" not in keywords and not positional_permit:
            found.append((node.lineno, name))
    return found


class TestEveryDiscoveryCallPassesAPermit:
    def test_no_caller_drops_the_permit(self):
        offenders = []
        for path in sorted(PACKAGE.rglob("*.py")):
            relative = path.relative_to(PACKAGE).as_posix()
            if relative in NO_PERMIT:
                continue
            for line, name in calls_without_a_permit(path.read_text(encoding="utf-8")):
                offenders.append(f"{relative}:{line} {name}(...)")

        assert offenders == [], (
            "pass the caller's permit predicate to discovery (permit=...), or list "
            "the module in NO_PERMIT with the reason it has none:\n"
            + "\n".join(offenders)
        )

    def test_control_a_call_without_a_permit_is_found(self):
        source = (
            "discover_config_source(d)\n"
            "x.find_config_file(search_dir=d)\n"
            "_discovered_config_path(d, log_selection=True)\n"
            "check_discovery_candidates(d)\n"
            "discover_config_source(d, permit=p)\n"
            "check_discovery_candidates(d, p)\n"
        )

        assert calls_without_a_permit(source) == [
            (1, "discover_config_source"),
            (2, "find_config_file"),
            (3, "_discovered_config_path"),
            (4, "check_discovery_candidates"),
        ]

    def test_control_each_listed_module_still_discovers(self):
        """A listed module that stopped calling discovery should leave the list."""
        for relative in NO_PERMIT:
            assert calls_without_a_permit(
                (PACKAGE / relative).read_text(encoding="utf-8")
            ), relative
