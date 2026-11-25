# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The fail-closed gate on where the manifest's enablement and tier facts are read.

A plugin's loading default (``default_enabled``) and its maturity (``tier``) are
fields of its manifest, and the maintainer's budget is that consulting them
happens in at most five places. Before the manifests landed the same facts lived
in four parallel carriers and were consulted at nine product sites; this gate is
what stops that regrowth, the way ``tests/unit/test_no_core_to_cli_imports.py``
stops layering regrowth. Everything else asks ``plugins.enablement`` (loading) or
iterates the merged plugin surface and consults nothing.

One AST pass over ``automated_security_helper/``, ``scripts/`` and ``.github/``
Python files flags:

* a read of an attribute named ``default_enabled`` (the loading fact);
* a comparison against a ``PluginTier`` member (branching on the tier), with
  aliased imports followed by binding, not by spelling.

A keyword argument ``default_enabled=...`` is data (the manifest modules declare
it), and a read of some other object's ``.tier`` (a conformance report's) is not
the manifest's tier: neither is flagged.

Fail-closed in both directions: a hit outside the allowlist fails naming the file
and line; an allowlisted file with zero hits fails too (a stale allowlist is also
drift); an allowlist larger than five fails; and the scanner is proven live by
planted controls, a smuggled consultation that must flag and a clean source that
must pass, so a dead scanner reads red, never green.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCANNED_ROOTS = ("automated_security_helper", "scripts", ".github")

#: The admitted files, each with why it consults the fact.
ADMITTED_FILES = {
    "automated_security_helper/base/plugin_manifest.py": (
        "the definition: the manifest model's own validation reads its tier "
        "(only a deprecated manifest names a successor)"
    ),
    "automated_security_helper/plugin_manifests/__init__.py": (
        "the registry: the retirement-shape rules read the tier, and the "
        "opt-in selector reads default_enabled"
    ),
    "automated_security_helper/plugins/enablement.py": (
        "the one loading policy: turns default_enabled into the module sets the "
        "loader and the hints read"
    ),
    "scripts/_plugin_reference.py": (
        "the docs generator: groups plugins by the manifest's tier label"
    ),
}

#: The maintainer's budget: "at most five places". The lower end is enforced by
#: the stale-allowlist check, not by a minimum count.
SITE_LIMIT = 5


class _Consultations(ast.NodeVisitor):
    def __init__(self) -> None:
        self.hits: list[tuple[int, str]] = []
        self._tier_names = {"PluginTier"}

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        for alias in node.names:
            if alias.name == "PluginTier":
                self._tier_names.add(alias.asname or alias.name)
        self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        if node.attr == "default_enabled" and isinstance(node.ctx, ast.Load):
            self.hits.append((node.lineno, "reads default_enabled"))
        self.generic_visit(node)

    def _is_tier_member(self, node: ast.AST) -> bool:
        return (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id in self._tier_names
        )

    def visit_Compare(self, node: ast.Compare) -> None:
        if any(self._is_tier_member(n) for n in (node.left, *node.comparators)):
            self.hits.append((node.lineno, "branches on a PluginTier member"))
        self.generic_visit(node)


def consultations(source: str) -> list[tuple[int, str]]:
    """``(line, reason)`` for every consultation of the manifest's loading or tier fact."""
    visitor = _Consultations()
    visitor.visit(ast.parse(source))
    return sorted(visitor.hits)


def _scanned_files() -> list[Path]:
    files = [
        path
        for root in SCANNED_ROOTS
        for path in sorted((REPO_ROOT / root).rglob("*.py"))
    ]
    assert len(files) > 100, "the package tree went missing from the scan"
    return files


def test_loading_and_tier_are_consulted_only_at_the_admitted_sites() -> None:
    offenders: list[str] = []
    hit_files: set[str] = set()
    for path in _scanned_files():
        rel = path.relative_to(REPO_ROOT).as_posix()
        hits = consultations(path.read_text(encoding="utf-8"))
        if not hits:
            continue
        hit_files.add(rel)
        if rel in ADMITTED_FILES:
            continue
        offenders.extend(f"{rel}:{line}: {reason}" for line, reason in hits)
    assert not offenders, (
        "the manifest's loading or tier fact is consulted outside the admitted "
        "sites; either convert the site (ask plugins.enablement for loading, "
        "iterate the merged surface for the rest) or, if it is genuinely a new "
        "admitted site, add it to ADMITTED_FILES with its justification and keep "
        "the count within the budget:\n" + "\n".join(offenders)
    )
    stale = set(ADMITTED_FILES) - hit_files
    assert not stale, (
        "allowlisted files with no consultation; a stale allowlist is also "
        f"drift, remove them: {sorted(stale)}"
    )


def test_the_admitted_site_count_stays_inside_the_budget() -> None:
    assert 1 <= len(ADMITTED_FILES) <= SITE_LIMIT, (
        f"{len(ADMITTED_FILES)} admitted files: the maintainer's budget is "
        f"{SITE_LIMIT} places at most; adding a site changes this list only with "
        "that budget re-argued"
    )
    missing = [rel for rel in ADMITTED_FILES if not (REPO_ROOT / rel).is_file()]
    assert not missing, f"allowlisted files that do not exist: {missing}"


# ---------------------------------------------------------------------------
# Planted controls: the scanner is proven live in both directions, so a zero from
# a dead scanner cannot read as a pass.
# ---------------------------------------------------------------------------

_SMUGGLED_LOADING_READ = """
from automated_security_helper.plugin_manifests import scanner_manifests

def opt_in() -> list[str]:
    return [m.name for m in scanner_manifests() if not m.default_enabled]
"""

_SMUGGLED_TIER_BRANCH = """
from automated_security_helper.base.plugin_manifest import PluginTier

def is_alpha(manifest) -> bool:
    return manifest.tier is PluginTier.ALPHA
"""

_SMUGGLED_ALIASED_TIER_BRANCH = """
from automated_security_helper.base.plugin_manifest import PluginTier as T

def is_alpha(manifest) -> bool:
    return manifest.tier == T.ALPHA
"""

_CLEAN_DATA_AND_UNRELATED_TIER = """
from automated_security_helper.base.plugin_manifest import PluginTier, ScannerManifest

MANIFEST = ScannerManifest(tier=PluginTier.ALPHA, default_enabled=False)

def label(report) -> str:
    return f"{report.scanner} ({report.tier})"
"""


def test_a_planted_loading_read_is_flagged() -> None:
    hits = consultations(_SMUGGLED_LOADING_READ)
    assert [reason for _, reason in hits] == ["reads default_enabled"]


def test_a_planted_tier_branch_is_flagged() -> None:
    hits = consultations(_SMUGGLED_TIER_BRANCH)
    assert [reason for _, reason in hits] == ["branches on a PluginTier member"]


def test_a_planted_aliased_tier_branch_is_flagged_by_binding() -> None:
    hits = consultations(_SMUGGLED_ALIASED_TIER_BRANCH)
    assert [reason for _, reason in hits] == ["branches on a PluginTier member"]


def test_planted_data_and_an_unrelated_tier_read_pass() -> None:
    assert consultations(_CLEAN_DATA_AND_UNRELATED_TIER) == []
