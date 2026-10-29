# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The unfindable-module check judges what it can without importing anything.

``refuse_unfindable_plugin_imports`` is the check surfaces' half of the import
refusal: it locates each configured name level by level, importing nothing,
and refuses exactly what the scan's import would refuse with
ModuleNotFoundError. Two edges the walk cannot judge are left to the import:
a pkgutil-style namespace parent fills its ``__path__`` only when imported,
so a portion in a second directory is findable to the scan but not to a
static walk; and the import system caches a miss for a sys.path entry, so a
module installed after the first answer is findable only after the same
cache invalidation the scan's loader does.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

from automated_security_helper.plugins.loader import (
    PluginModuleImportError,
    refuse_unfindable_plugin_imports,
)

pytestmark = pytest.mark.unit


def _package(root: Path, name: str, init: str = "") -> Path:
    directory = root / name
    directory.mkdir(parents=True)
    (directory / "__init__.py").write_text(init, encoding="utf-8")
    return directory


@pytest.fixture
def forgetting(monkeypatch):
    """Undo this test's import-system state: planted names and path caches."""

    def plant(path: Path, *names: str):
        monkeypatch.syspath_prepend(str(path))
        for name in names:
            monkeypatch.delitem(sys.modules, name, raising=False)

    yield plant
    for name in list(sys.modules):
        if name.startswith("zqwalk"):
            del sys.modules[name]
    importlib.invalidate_caches()


def test_a_missing_child_of_a_regular_package_is_refused(tmp_path, forgetting):
    """The control for the namespace cell below: a plain parent's search
    locations are complete, so a child not found there is the miss the scan's
    import would raise."""
    _package(tmp_path / "site", "zqwalkreg_ash_plugins")
    forgetting(tmp_path / "site", "zqwalkreg_ash_plugins")

    with pytest.raises(PluginModuleImportError) as caught:
        refuse_unfindable_plugin_imports(["zqwalkreg_ash_plugins.nope"])

    assert "No module named 'zqwalkreg_ash_plugins.nope'" in str(caught.value)
    assert "zqwalkreg_ash_plugins" not in sys.modules


def test_a_pkgutil_namespace_portion_in_a_second_directory_is_accepted(
    tmp_path, forgetting
):
    """The walk finds the first portion's directory only; the parent's import
    extends its __path__ to the second. The scan imports this module, so the
    check must not refuse it: a parent that fills its __path__ on import is
    documented as left to the import."""
    init = "__path__ = __import__('pkgutil').extend_path(__path__, __name__)\n"
    _package(tmp_path / "one", "zqwalkpk_ash_plugins", init)
    two = _package(tmp_path / "two", "zqwalkpk_ash_plugins", init)
    (two / "mod_b.py").write_text("ASH_REPORTERS = []\n", encoding="utf-8")
    # one before two on sys.path: the walk locates one's portion, and mod_b
    # lives only in two's.
    forgetting(tmp_path / "two")
    forgetting(tmp_path / "one", "zqwalkpk_ash_plugins")

    refuse_unfindable_plugin_imports(["zqwalkpk_ash_plugins.mod_b"])

    # Accepted without importing: judging the parent read its __init__'s
    # text, never ran it.
    assert "zqwalkpk_ash_plugins" not in sys.modules
    # The scan's import agrees: the module is importable.
    module = importlib.import_module("zqwalkpk_ash_plugins.mod_b")
    assert module.ASH_REPORTERS == []


def test_a_module_installed_after_the_first_answer_is_found_by_the_next(
    tmp_path, forgetting
):
    """A long-lived process (the MCP server) answers again after the operator
    installs the module. The import system cached the first answer's miss, so
    without the loader's own invalidation the check keeps refusing what the
    scan now imports."""
    late = tmp_path / "late-site"
    forgetting(late, "zqwalklate_ash_plugins")

    with pytest.raises(PluginModuleImportError):
        refuse_unfindable_plugin_imports(["zqwalklate_ash_plugins"])

    _package(late, "zqwalklate_ash_plugins", "ASH_REPORTERS = []\n")

    refuse_unfindable_plugin_imports(["zqwalklate_ash_plugins"])


@pytest.mark.parametrize(
    "init",
    [
        "# pkgutil.extend_path was used here once\n",
        "NOTE = 'never call extend_path in this package'\n",
        "def my_extend_paths():\n    return None\n",
        '"""Not a namespace: no declare_namespace here."""\n',
    ],
    ids=["comment", "string", "longer-name", "docstring"],
)
def test_a_mention_that_is_not_a_call_still_refuses_a_missing_child(
    tmp_path, forgetting, init
):
    """A comment, a string, a longer name or a docstring that only mentions
    extend_path or declare_namespace is no namespace parent: judging by an
    identifier token, not a substring, keeps the check refusing exactly what
    the scan's import refuses."""
    _package(tmp_path / "site", "zqwalkmention_ash_plugins", init)
    forgetting(tmp_path / "site", "zqwalkmention_ash_plugins")

    with pytest.raises(PluginModuleImportError) as caught:
        refuse_unfindable_plugin_imports(["zqwalkmention_ash_plugins.absent"])

    assert "No module named 'zqwalkmention_ash_plugins.absent'" in str(caught.value)
    assert "zqwalkmention_ash_plugins" not in sys.modules


@pytest.mark.parametrize(
    "init",
    [
        'X = f"{extend_path}" if False else None\n',
        'X = f"call extend_path here {1}"\n',
        "class _Holder:\n    pass\n_holder = _Holder()\n_holder.extend_path = 1\n",
        "def extend_path():\n    return None\n",
    ],
    ids=["f-string-expression", "f-string-literal", "attribute-target", "own-function"],
)
def test_an_identifier_that_is_no_call_still_refuses_a_missing_child(
    tmp_path, forgetting, init
):
    """The judgment is of calls, not of identifiers: an f-string expression
    (whose names are identifier tokens on 3.12+), an attribute assignment
    target and the parent's own function named extend_path never extend the
    parent's path, so its missing child is the miss the scan's import would
    raise."""
    _package(tmp_path / "site", "zqwalkident_ash_plugins", init)
    forgetting(tmp_path / "site", "zqwalkident_ash_plugins")

    with pytest.raises(PluginModuleImportError) as caught:
        refuse_unfindable_plugin_imports(["zqwalkident_ash_plugins.absent"])

    assert "No module named 'zqwalkident_ash_plugins.absent'" in str(caught.value)
    assert "zqwalkident_ash_plugins" not in sys.modules


def test_an_unparsable_parent_is_left_to_the_import(tmp_path, forgetting):
    """A source the parser rejects cannot be judged, so its missing child is
    left to the import, whose own failure names the real problem (a syntax
    error, not a miss)."""
    # Balanced brackets, so this is a parse failure, never a tokenize one.
    _package(tmp_path / "site", "zqwalkbroken_ash_plugins", "def broken(:)\n")
    forgetting(tmp_path / "site", "zqwalkbroken_ash_plugins")

    refuse_unfindable_plugin_imports(["zqwalkbroken_ash_plugins.absent"])

    assert "zqwalkbroken_ash_plugins" not in sys.modules


def test_a_parent_that_overflows_the_parser_is_left_to_the_import(tmp_path, forgetting):
    """A deeply nested source makes the parser raise MemoryError ("Parser
    stack overflowed"), not SyntaxError: the check leaves such a parent to the
    import instead of crashing, so validate answers exit 3 or 0 like the scan,
    never an internal error."""
    _package(
        tmp_path / "site",
        "zqwalkdeep_ash_plugins",
        "x = " + "-" * 200_000 + "1\n",
    )
    forgetting(tmp_path / "site", "zqwalkdeep_ash_plugins")

    refuse_unfindable_plugin_imports(["zqwalkdeep_ash_plugins.absent"])

    assert "zqwalkdeep_ash_plugins" not in sys.modules


def test_a_declare_namespace_alias_is_accepted(tmp_path, forgetting):
    """The pkg_resources spelling, through an alias: the check reads the
    parent's source only, so whether pkg_resources is installed never
    matters, and the parent is left to the import that would run it."""
    init = "from pkg_resources import declare_namespace as dn\ndn(__name__)\n"
    _package(tmp_path / "site", "zqwalkdecl_ash_plugins", init)
    forgetting(tmp_path / "site", "zqwalkdecl_ash_plugins")

    refuse_unfindable_plugin_imports(["zqwalkdecl_ash_plugins.absent"])

    assert "zqwalkdecl_ash_plugins" not in sys.modules


def test_a_missing_child_of_a_zipped_package_is_refused(tmp_path, forgetting):
    """A zipped parent's source comes through its loader, so a missing child
    under it is judged like a directory package's, not left to the import
    because the __init__ is no file to open."""
    import zipfile

    archive = tmp_path / "plugins.zip"
    with zipfile.ZipFile(archive, "w") as zipped:
        zipped.writestr("zqwalkzip_ash_plugins/__init__.py", "")
    forgetting(archive, "zqwalkzip_ash_plugins")

    with pytest.raises(PluginModuleImportError) as caught:
        refuse_unfindable_plugin_imports(["zqwalkzip_ash_plugins.absent"])

    assert "No module named 'zqwalkzip_ash_plugins.absent'" in str(caught.value)
    assert "zqwalkzip_ash_plugins" not in sys.modules


def test_an_aliased_import_of_extend_path_is_accepted(tmp_path, forgetting):
    """The control for the identifier test's reach: the name appears as an
    import alias, not a dotted call, and the parent still extends its path."""
    init = "from pkgutil import extend_path as e\n__path__ = e(__path__, __name__)\n"
    _package(tmp_path / "one", "zqwalkalias_ash_plugins", init)
    two = _package(tmp_path / "two", "zqwalkalias_ash_plugins", init)
    (two / "mod_b.py").write_text("ASH_REPORTERS = []\n", encoding="utf-8")
    forgetting(tmp_path / "two")
    forgetting(tmp_path / "one", "zqwalkalias_ash_plugins")

    refuse_unfindable_plugin_imports(["zqwalkalias_ash_plugins.mod_b"])

    assert "zqwalkalias_ash_plugins" not in sys.modules


def test_a_sourceless_parent_is_left_to_the_import(tmp_path, forgetting):
    """A .pyc-only parent has no source to judge from, so its missing child
    is left to the import, as an unreadable source is."""
    import py_compile

    package = _package(tmp_path / "site", "zqwalkpyc_ash_plugins", "")
    source = package / "__init__.py"
    py_compile.compile(str(source), cfile=str(source.with_suffix(".pyc")), doraise=True)
    source.unlink()
    forgetting(tmp_path / "site", "zqwalkpyc_ash_plugins")

    refuse_unfindable_plugin_imports(["zqwalkpyc_ash_plugins.absent"])

    assert "zqwalkpyc_ash_plugins" not in sys.modules


def test_the_walk_imports_nothing_while_judging(tmp_path, forgetting):
    """Locating a dotted name must not run the parent's __init__ (the scan's
    import does that later, under the loader's recording): a walk that
    resolves the child with a plain find_spec imports the parent as a side
    effect."""
    marker = tmp_path / "imported-marker"
    init = (
        "import pathlib\n"
        f"pathlib.Path({str(marker)!r}).write_text('imported', encoding='utf-8')\n"
    )
    package = _package(tmp_path / "site", "zqwalkplant_ash_plugins", init)
    (package / "mod.py").write_text("ASH_REPORTERS = []\n", encoding="utf-8")
    forgetting(tmp_path / "site", "zqwalkplant_ash_plugins")

    refuse_unfindable_plugin_imports(["zqwalkplant_ash_plugins.mod"])
    with pytest.raises(PluginModuleImportError):
        refuse_unfindable_plugin_imports(["zqwalkplant_ash_plugins.absent"])

    assert not marker.exists(), "the check imported the parent package"
    assert "zqwalkplant_ash_plugins" not in sys.modules

    # The control: the marker mechanism works when something does import it.
    importlib.import_module("zqwalkplant_ash_plugins")
    assert marker.exists()
