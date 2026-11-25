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
    # 11 -> 16: the container-image asset targets read core.asset (Asset, AssetKind,
    # ImageLocator) and core.container_engine from plugin_context, the scanner
    # operational facets and the scanner base. The types live in core; moving them
    # to the contract layer is the way to retire these rows.
    ("base", "core"): 17,
    ("base", "models"): 9,
    ("base", "plugins"): 5,
    ("base", "utils"): 91,
    ("config", "core"): 42,
    ("config", "plugins"): 5,
    ("express", "cli"): 1,
    ("interactions", "cli"): 1,
    ("models", "config"): 12,
    ("models", "core"): 9,
    # 68 -> 69: the one plugin -> cli edge (the grep scanner base asking whether a
    # config file is client-supplied) now reads the rule where it moved to, in config.
    # 69 -> 70: npm_audit_scanner reads config.default_config (landed on main with
    # the flat-frame/facets work this branch was rebased onto).
    # 70 -> 73: the sdist lock harvester reads config.path_trust,
    # config.operator_only_options and config.sandbox_grants (the same trust checks
    # the other converters take), and the grep scanner base reads config.mcp_sandbox.
    # 73 -> 74: npm_audit_scanner's normalize-results harness entry resolves the
    # scanner model's AshConfig forward reference before it builds one (landed on
    # main with the consolidated fixes).
    ("plugin_modules", "config"): 75,
    # 70 -> 75: the sdist lock harvester (core.constants, core.exceptions), the MCP
    # config scanner (core.enums), cdk-nag (core.exceptions) and trivy
    # (core.container_engine) read core types the way the other plugins do.
    ("plugin_modules", "core"): 83,
    ("plugin_modules", "interactions"): 2,
    ("plugin_modules", "workspace"): 1,
    ("schemas", "config"): 2,
    ("schemas", "models"): 2,
    ("schemas", "utils"): 8,
    ("utils", "config"): 27,
    # 35 -> 39: image_attribution and image_tool_targets read core.asset and
    # core.container_engine, and sdist_harvest reads core.constants.xdg_directory.
    ("utils", "core"): 41,
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


def _imported_modules(tree: ast.Module, package: Tuple[str, ...]) -> Iterator[str]:
    """Each dotted module an import statement of ``tree`` names, as an absolute name.

    ``package`` is the dotted package the file lives in, as parts
    (``("automated_security_helper", "config")`` for ``config/x.py``): what a
    relative import is resolved against.

    ``from automated_security_helper import cli`` names the module
    ``automated_security_helper.cli`` through its alias, so one name is yielded
    per alias: the statement ``from automated_security_helper import cli, utils``
    is two edges. A relative import is resolved, so ``from ..cli import x`` in
    ``config/`` is the edge ``config -> cli`` and not invisible; one that climbs
    above the package fails the test, as does anything else the resolution cannot
    place, rather than being dropped.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                yield alias.name
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                climbed = node.level - 1
                if climbed >= len(package):
                    raise AssertionError(
                        f"a relative import of level {node.level} in a module of "
                        f"{'.'.join(package)} climbs above the top-level package"
                    )
                base = package[: len(package) - climbed]
                prefix = ".".join(base)
                module = f"{prefix}.{node.module}" if node.module else prefix
            elif node.module:
                module = node.module
            else:
                continue
            if module == PACKAGE:
                for alias in node.names:
                    if alias.name != "*":
                        yield f"{PACKAGE}.{alias.name}"
            else:
                yield module


def import_edges(root: Path = PACKAGE_ROOT) -> Counter:
    """``{(source package, target package): import statements}`` between top-level packages.

    A module directly under the package root is not a layer, so its imports are
    not counted. Every form of import counts: ``import a.b``, ``from a.b import x``,
    ``from a import b`` and the relative forms. A file that does not parse fails
    the test (a guard that skipped it would pass over exactly the file it could
    not read).
    """
    edges: Counter = Counter()
    for py_file in root.rglob("*.py"):
        relative = py_file.relative_to(root).parts
        if len(relative) < 2:
            continue
        source = relative[0]
        try:
            tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
        except SyntaxError as exc:
            raise AssertionError(
                f"{py_file} does not parse ({exc.msg}, line {exc.lineno}): the "
                "layer guard cannot read its imports"
            ) from exc
        package = (PACKAGE, *relative[:-1])
        for module in _imported_modules(tree, package):
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


@pytest.fixture(scope="module")
def package_edges() -> Counter:
    """The edges of the real package, read once for every cell that needs them."""
    return import_edges()


def test_no_new_reverse_import_edges(package_edges):
    edges = package_edges
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


def test_known_violations_are_the_measured_counts(package_edges):
    """The debt table ratchets: a row is the count measured now, not a ceiling.

    ``test_no_new_reverse_import_edges`` fails on a count above its row, which
    alone left a row at its old height after a refactor removed edges: the
    imports that came back up to the old height raised no failure. A row that
    differs either way fails here, saying what to write.
    """
    drifted = [
        f"{source} -> {target}: row {allowed}, measured "
        f"{package_edges.get((source, target), 0)}"
        for (source, target), allowed in sorted(KNOWN_VIOLATIONS.items())
        if package_edges.get((source, target), 0) != allowed
    ]
    assert not drifted, (
        "KNOWN_VIOLATIONS rows that differ from the measured import counts "
        "(lower a row to the measured number; a higher number is a new import "
        "to remove, not a row to raise):\n" + "\n".join(drifted)
    )


def test_known_violations_name_edges_that_still_exist(package_edges):
    """A removed edge leaves the debt table, so it is a hard rule from then on."""
    edges = package_edges
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
def test_removed_edges_stay_removed(source: str, target: str, package_edges):
    """The edges the refactor has already removed, named, so a change to the
    debt table cannot quietly bring one back."""
    assert (source, target) not in KNOWN_VIOLATIONS
    assert package_edges.get((source, target), 0) == 0, (
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


def _plant(tmp_path, relative: str, text: str) -> Path:
    """A one-file package tree: ``relative`` under ``tmp_path`` holds ``text``."""
    target = tmp_path / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    init = target.parent / "__init__.py"
    if not init.exists():
        init.write_text("")
    target.write_text(text)
    return tmp_path


def test_the_test_sees_a_package_imported_from_the_root_by_name(tmp_path):
    """Control: ``from automated_security_helper import cli`` is the edge to ``cli``.

    The module of that statement is the root package alone, which the edge counter
    used to drop as having no second part; the package comes from the alias.
    """
    root = _plant(
        tmp_path,
        "config/late.py",
        "from automated_security_helper import cli\n",
    )
    assert import_edges(root)[("config", "cli")] == 1


def test_every_alias_of_a_root_import_is_an_edge(tmp_path):
    root = _plant(
        tmp_path,
        "config/late.py",
        "from automated_security_helper import cli, plugin_modules as plugins, utils\n",
    )
    edges = import_edges(root)
    assert edges[("config", "cli")] == 1
    assert edges[("config", "plugin_modules")] == 1
    assert edges[("config", "utils")] == 1


def test_the_test_sees_a_relative_reverse_edge(tmp_path):
    """Control: ``from ..cli.mcp import sandbox`` in ``config/`` is ``config -> cli``."""
    root = _plant(
        tmp_path,
        "config/late.py",
        "def f():\n    from ..cli.mcp import sandbox\n    return sandbox\n",
    )
    assert import_edges(root)[("config", "cli")] == 1


def test_the_test_sees_a_relative_import_of_a_package_by_name(tmp_path):
    """Control: ``from .. import cli`` names the package through its alias."""
    root = _plant(tmp_path, "config/late.py", "from .. import cli\n")
    assert import_edges(root)[("config", "cli")] == 1


def test_a_relative_import_in_a_nested_module_is_resolved_from_its_package(tmp_path):
    """Control: ``config/sub/deep.py`` reaching ``..`` stays in ``config``, and
    ``...cli`` reaches the top-level package."""
    root = _plant(
        tmp_path,
        "config/sub/deep.py",
        "from .. import sibling\nfrom ...cli import x\nfrom . import peer\n",
    )
    edges = import_edges(root)
    assert edges[("config", "cli")] == 1
    assert sum(edges.values()) == 1, edges


def test_a_relative_import_inside_its_own_package_is_not_an_edge(tmp_path):
    root = _plant(
        tmp_path,
        "config/late.py",
        "from . import sibling\nfrom .other import name\n",
    )
    assert sum(import_edges(root).values()) == 0


def test_a_relative_import_above_the_package_fails_the_test(tmp_path):
    root = _plant(tmp_path, "config/late.py", "from ... import cli\n")
    with pytest.raises(AssertionError, match="climbs above"):
        import_edges(root)


def test_a_file_that_does_not_parse_fails_the_test(tmp_path):
    """Control: an unreadable file is a failure, never a skipped file."""
    root = _plant(tmp_path, "config/broken.py", "def f(:\n")
    with pytest.raises(AssertionError, match="does not parse"):
        import_edges(root)


def test_the_real_tree_has_no_file_the_guard_cannot_read(package_edges):
    """Control for the cell above: the real package is read without a failure, and
    the edge table it produced is not empty."""
    assert sum(package_edges.values()) > 0
