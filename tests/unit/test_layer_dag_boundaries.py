"""Architectural guard: the import graph between top-level packages follows the layer order.

The design's libraries (contract, results, config, engine, cli, plus the plugin
packages) are import-boundary-enforced top-level packages in one wheel, held by this
test. It generalizes the earlier ``core`` must not import ``cli`` test to the whole
graph.

The layers, lowest first. A package may import its own layer and any layer below it:

    0  contract    base, schemas, plugin_manifests
    1  results     models, utils          (utils is split later: results, engine,
                                           and plugin residue; one layer until then)
    2  config      config
    3  engine      core, plugins, workspace, interactions, assets, express
    4  cli         cli

``plugin_modules`` sits beside the stack, not in it: a plugin may import the
contract, the shared result shapes, ``utils`` and the plugin decorators, and
nothing above them, and only ``cli`` (the entrypoint) may import a plugin package
by name. The kernel reaches a plugin through its manifest (``resolve_ref``), which
is data, not an import statement.

Every import statement counts, including the ones inside functions (lazy imports)
and under ``TYPE_CHECKING``: a lazy import is the usual way a reverse edge hides.

Two kinds of edge fail here:

* a violating edge that is not in ``KNOWN_VIOLATIONS``, or one whose statement count
  grew past it. This is the hard part: the edges that do not exist today (and the
  ones removed since) can never come back. ``config`` -> ``cli`` and ``config`` ->
  ``plugin_modules`` are among them.
* a ``KNOWN_VIOLATIONS`` row for an edge that no longer exists. Delete the row, so
  the edge is hard from then on.

``KNOWN_VIOLATIONS`` is the debt measured when this test landed, as statement counts.
Each row is an edge the layer order forbids and a later unit removes (the contract
reading ``config``/``core``/``utils``, ``config`` reading ``core``, a plugin reading
``config``/``core``, and the single stray edges into ``cli``); counts only go down.
"""

import ast
from collections import Counter
from pathlib import Path
from typing import Dict, Iterator, Tuple

import pytest

pytestmark = pytest.mark.unit

PACKAGE_ROOT = Path(__file__).parent.parent.parent / "automated_security_helper"
PACKAGE = "automated_security_helper"

LAYER: Dict[str, int] = {
    "base": 0,
    "schemas": 0,
    "plugin_manifests": 0,
    "models": 1,
    "utils": 1,
    "config": 2,
    "core": 3,
    "plugins": 3,
    "workspace": 3,
    "interactions": 3,
    "assets": 3,
    "express": 3,
    "cli": 4,
}

PLUGINS = "plugin_modules"
#: What a plugin package may import by package name.
PLUGIN_MAY_IMPORT = frozenset(
    {"base", "schemas", "plugin_manifests", "models", "utils", "plugins"}
)
#: The only package that may import a plugin package by name.
PLUGIN_IMPORTER = "cli"

KNOWN_VIOLATIONS: Dict[Tuple[str, str], int] = {
    ("base", "config"): 10,
    ("base", "core"): 11,
    ("base", "models"): 5,
    ("base", "plugins"): 5,
    ("base", "utils"): 90,
    ("config", "core"): 37,
    ("config", "plugins"): 5,
    ("express", "cli"): 1,
    ("interactions", "cli"): 1,
    ("models", "config"): 12,
    ("models", "core"): 10,
    # 68 -> 69: the one plugin -> cli edge (the grep scanner base asking whether a
    # config file is client-supplied) now reads the rule where it moved to, in config.
    # 69 -> 70: npm_audit_scanner reads config.default_config (landed on main with
    # the flat-frame/facets work this branch was rebased onto).
    ("plugin_modules", "config"): 70,
    ("plugin_modules", "core"): 70,
    ("plugin_modules", "interactions"): 2,
    ("plugin_modules", "workspace"): 1,
    ("schemas", "config"): 2,
    ("schemas", "models"): 2,
    ("schemas", "utils"): 8,
    ("utils", "config"): 27,
    ("utils", "core"): 35,
    # 2 -> 3: utils/scan_history reads interactions.run_ash_scan (landed on main
    # with the scan trend/history work this branch was rebased onto).
    ("utils", "interactions"): 3,
    ("utils", "plugin_modules"): 2,
}


def forbidden(source: str, target: str) -> bool:
    """Whether the layer order forbids ``source`` importing ``target``."""
    if source == PLUGINS:
        return target not in PLUGIN_MAY_IMPORT
    if target == PLUGINS:
        return source != PLUGIN_IMPORTER
    if source in LAYER and target in LAYER:
        return LAYER[target] > LAYER[source]
    return False


def _imported_modules(tree: ast.Module) -> Iterator[str]:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            yield node.module


def import_edges(root: Path = PACKAGE_ROOT) -> Counter:
    """``{(source package, target package): import statements}`` between top-level packages.

    A module directly under the package root is not a layer, so its imports are
    not counted. A relative import is ignored: the code base writes absolute ones.
    """
    edges: Counter = Counter()
    for py_file in root.rglob("*.py"):
        relative = py_file.relative_to(root).parts
        if len(relative) < 2:
            continue
        source = relative[0]
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except SyntaxError:
            continue
        for module in _imported_modules(tree):
            parts = module.split(".")
            if parts[0] != PACKAGE or len(parts) < 2 or parts[1] == source:
                continue
            edges[(source, parts[1])] += 1
    return edges


def test_every_package_has_a_layer():
    """A new top-level package is placed in the layer order, or in the plugin set."""
    placed = set(LAYER) | {PLUGINS}
    found = {
        p.name
        for p in PACKAGE_ROOT.iterdir()
        if p.is_dir() and (p / "__init__.py").exists()
    }
    assert found <= placed, (
        f"top-level packages with no layer in tests/unit/test_layer_dag_boundaries.py: "
        f"{sorted(found - placed)}"
    )


def test_no_new_reverse_import_edges():
    edges = import_edges()
    problems = []
    for (source, target), count in sorted(edges.items()):
        if not forbidden(source, target):
            continue
        allowed = KNOWN_VIOLATIONS.get((source, target), 0)
        if count > allowed:
            problems.append(
                f"{source} -> {target}: {count} import statement(s), "
                f"{allowed} known; the layer order forbids this edge"
            )
    assert not problems, (
        "Import edges against the layer order (contract < results < config < "
        "engine < cli; plugins import only the contract and shared shapes):\n"
        + "\n".join(problems)
    )


def test_known_violations_name_edges_that_still_exist():
    """A removed edge leaves the debt table, so it is a hard rule from then on."""
    edges = import_edges()
    stale = [
        f"{source} -> {target}"
        for (source, target) in sorted(KNOWN_VIOLATIONS)
        if edges.get((source, target), 0) == 0
    ]
    not_violations = [
        f"{source} -> {target}"
        for (source, target) in sorted(KNOWN_VIOLATIONS)
        if not forbidden(source, target)
    ]
    assert not stale, (
        "KNOWN_VIOLATIONS rows for edges that no longer exist (delete them): "
        + ", ".join(stale)
    )
    assert not not_violations, (
        "KNOWN_VIOLATIONS rows for edges the layer order allows (delete them): "
        + ", ".join(not_violations)
    )


@pytest.mark.parametrize(
    "source,target",
    [
        ("core", "cli"),
        ("config", "cli"),
        ("config", "plugin_modules"),
        ("base", "cli"),
        ("models", "cli"),
        ("utils", "cli"),
        ("plugins", "cli"),
        ("core", "plugin_modules"),
        ("workspace", "plugin_modules"),
        ("workspace", "cli"),
        ("plugin_modules", "cli"),
    ],
)
def test_removed_edges_stay_removed(source: str, target: str):
    """The edges the refactor has already removed, named, so a change to the
    debt table cannot quietly bring one back."""
    assert (source, target) not in KNOWN_VIOLATIONS
    assert import_edges().get((source, target), 0) == 0, (
        f"{source} must not import {target}"
    )


def test_the_test_sees_a_planted_reverse_edge(tmp_path):
    """Control: the edge counter finds a reverse import in a lazy, nested position."""
    package = tmp_path / "config"
    package.mkdir()
    (package / "__init__.py").write_text("")
    (package / "late.py").write_text(
        "def f():\n"
        "    if True:\n"
        "        from automated_security_helper.cli.mcp import sandbox\n"
        "        return sandbox\n"
    )
    edges = import_edges(tmp_path)
    assert edges[("config", "cli")] == 1
    assert forbidden("config", "cli")
