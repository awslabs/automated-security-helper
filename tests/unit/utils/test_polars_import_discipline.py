# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""polars is imported lazily, except in the modules named below.

Importing polars costs more than the rest of ASH's import path put together, and
the models sit on that path. ``utils/frame_text.py``, ``utils/frame_ops.py``,
``severity_ladder`` and the other frame helpers import it inside the function
that uses it, so a process that never builds a frame never loads it. One
module-scope ``import polars`` in the import closure of the models undoes all of
that quietly: ``config/ash_config.py`` imported ``models/core.py``, which
imported ``utils/suppression_frame.py``, which imported polars at module scope,
so polars loaded whenever the config layer did.

This gate reads the source (no polars import, no ASH import) and asserts:

* the only modules in the package with a module-scope ``import polars`` are the
  ones on :data:`MODULE_SCOPE_ALLOWLIST`, each with its reason;
* no module in the import closure of ``models/core.py`` has one;
* the closure of ``config/ash_config.py`` loads polars only through the modules
  named on :data:`CONFIG_CLOSURE_EAGER` (none today).

The walker is itself checked against planted positives: a source with a
module-scope import must be flagged, so a walker that stopped looking would
fail here rather than pass everything.
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Set

import pytest

from tests.utils.helpers import importing_this_checkout

pytestmark = pytest.mark.unit

PACKAGE = "automated_security_helper"
PACKAGE_ROOT = Path(__file__).resolve().parents[3] / PACKAGE

#: Modules that import polars at module scope, and why that is accepted. A
#: module added here needs a reason; a module whose import moves into a function
#: comes off.
MODULE_SCOPE_ALLOWLIST: Dict[str, str] = {
    f"{PACKAGE}.plugin_modules.ash_builtin.reporters._junitxml_frame": (
        "reporter helper, loaded when the JUnit reporter runs"
    ),
    f"{PACKAGE}.plugin_modules.ash_builtin.reporters._report_frames": (
        "reporter helper, loaded when a report emitter runs"
    ),
    f"{PACKAGE}.plugin_modules.ash_builtin.reporters.gitlab_cyclonedx_reporter": (
        "reporter plugin, loaded at plugin discovery"
    ),
    f"{PACKAGE}.plugin_modules.ash_builtin.reporters.ocsf_reporter": (
        "reporter plugin, loaded at plugin discovery"
    ),
    f"{PACKAGE}.plugin_modules.ash_builtin.reporters.report_content_emitter": (
        "reporter base for the report emitters, loaded with them"
    ),
    f"{PACKAGE}.utils.finding_diff": "loaded on the diff and baseline commands' paths",
    f"{PACKAGE}.utils.finding_trend": "loaded on the trend command's path",
    f"{PACKAGE}.utils.sbom_merge": "loaded on the SBOM merge path",
}

#: Modules whose module-scope polars import is reachable from
#: ``config/ash_config.py``. The reporters' config classes no longer pull a
#: reporter that imports polars into the config layer, so the set is empty: a
#: module-scope polars import that becomes reachable from the config layer
#: again fails this gate and is either moved into a function or listed here
#: with the reason it must load with the config.
CONFIG_CLOSURE_EAGER: Set[str] = set()


def _is_polars(name: str) -> bool:
    return name == "polars" or name.startswith("polars.")


def _is_type_checking(test: ast.expr) -> bool:
    if isinstance(test, ast.Name):
        return test.id == "TYPE_CHECKING"
    return isinstance(test, ast.Attribute) and test.attr == "TYPE_CHECKING"


def _module_scope_statements(body: List[ast.stmt]) -> Iterator[ast.stmt]:
    """The statements that run when the module is imported.

    Every child statement is walked, whatever compound statement holds it (``try``,
    ``try``/``except*``, ``match`` cases, the ``else`` of a loop, ...), so a form
    this walker does not name is still read. The walk stops at a function body
    (which does not run at import; a lambda holds no statement) and at the body of
    an ``if TYPE_CHECKING``.
    """
    for node in body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        yield node
        for child in ast.iter_child_nodes(node):
            if isinstance(node, ast.If) and _is_type_checking(node.test):
                if child in node.body:
                    continue
            if isinstance(child, ast.stmt):
                yield from _module_scope_statements([child])
            elif isinstance(child, (ast.ExceptHandler, ast.match_case)):
                yield from _module_scope_statements(child.body)


def module_scope_imports(source: str, module: str, is_package: bool) -> Set[str]:
    """Absolute dotted names *source* imports when it is imported as *module*."""
    tree = ast.parse(source)
    package = module if is_package else module.rpartition(".")[0]
    names: Set[str] = set()
    for node in _module_scope_statements(tree.body):
        if isinstance(node, ast.Import):
            names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                base_parts = package.split(".")
                base_parts = base_parts[: len(base_parts) - (node.level - 1)]
                base = ".".join(base_parts)
                target = f"{base}.{node.module}" if node.module else base
            else:
                target = node.module or ""
            names.add(target)
            # ``from pkg import sub`` imports the submodule ``pkg.sub`` when it is one.
            names.update(f"{target}.{alias.name}" for alias in node.names)
    return names


def has_module_scope_polars(source: str, module: str = "m", is_package: bool = False):
    return any(_is_polars(n) for n in module_scope_imports(source, module, is_package))


def _module_file(module: str) -> Optional[Path]:
    """The source file of an in-package *module*, or None for any other name."""
    if module != PACKAGE and not module.startswith(PACKAGE + "."):
        return None
    relative = Path(*module.split(".")[1:]) if module != PACKAGE else Path()
    base = PACKAGE_ROOT / relative
    if (base / "__init__.py").is_file():
        return base / "__init__.py"
    candidate = base.with_suffix(".py")
    return candidate if candidate.is_file() else None


def _all_modules() -> Dict[str, Path]:
    modules: Dict[str, Path] = {}
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        relative = path.relative_to(PACKAGE_ROOT.parent).with_suffix("")
        parts = list(relative.parts)
        if parts[-1] == "__init__":
            parts = parts[:-1]
        modules[".".join(parts)] = path
    return modules


def _parent_packages(module: str) -> Iterator[str]:
    parts = module.split(".")
    for end in range(1, len(parts)):
        yield ".".join(parts[:end])


def _imports_of(module: str, path: Path) -> Set[str]:
    is_package = path.name == "__init__.py"
    return module_scope_imports(path.read_text(encoding="utf-8"), module, is_package)


def import_closure(start: str) -> Set[str]:
    """Every in-package module imported, directly or not, at module scope."""
    seen: Set[str] = set()
    pending = [start]
    while pending:
        module = pending.pop()
        if module in seen or _module_file(module) is None:
            continue
        seen.add(module)
        pending.extend(_parent_packages(module))
        path = _module_file(module)
        assert path is not None
        pending.extend(_imports_of(module, path))
    return seen


def eager_polars_modules(modules: Set[str]) -> Set[str]:
    out = set()
    for module in modules:
        path = _module_file(module)
        if path is not None and any(_is_polars(n) for n in _imports_of(module, path)):
            out.add(module)
    return out


# ---------------------------------------------------------------------------
# the walker itself: planted positives and negatives
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "source",
    [
        "import polars as pl\n",
        "import polars\n",
        "from polars import DataFrame\n",
        "import polars.selectors as cs\n",
        "try:\n    import polars as pl\nexcept ImportError:\n    pl = None\n",
        "if True:\n    import polars as pl\n",
        "try:\n    pass\nexcept* ImportError:\n    import polars as pl\n",
        "match 1:\n    case 1:\n        import polars as pl\n",
        "for _ in ():\n    pass\nelse:\n    import polars as pl\n",
        "while False:\n    pass\nelse:\n    import polars as pl\n",
        "class K:\n    import polars as pl\n",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    pass\nelse:\n    import polars as pl\n",
    ],
)
def test_walker_flags_a_module_scope_polars_import(source):
    assert has_module_scope_polars(source)


@pytest.mark.parametrize(
    "source",
    [
        "def f():\n    import polars as pl\n",
        "async def f():\n    import polars as pl\n",
        "from typing import TYPE_CHECKING\nif TYPE_CHECKING:\n    import polars as pl\n",
        "import typing\nif typing.TYPE_CHECKING:\n    import polars as pl\n",
        "import json\nfrom os import path\n",
    ],
)
def test_walker_passes_a_lazy_or_type_only_import(source):
    assert not has_module_scope_polars(source)


def test_walker_resolves_a_relative_import():
    imports = module_scope_imports("from . import b\nfrom .c import d\n", "p.a", False)
    assert {"p.b", "p.c", "p.c.d"} <= imports
    imports = module_scope_imports("from .. import b\n", "p.q.a", False)
    assert "p.b" in imports


def test_control_a_module_known_to_import_polars_at_module_scope_is_flagged():
    """The gate pointed at finding_diff must go red, or it can pass anything."""
    module = f"{PACKAGE}.utils.finding_diff"
    assert module in eager_polars_modules({module})


def test_control_the_fixed_suppression_frame_passes():
    module = f"{PACKAGE}.utils.suppression_frame"
    assert module not in eager_polars_modules({module})


def test_the_scan_finds_the_package():
    assert len(_all_modules()) > 100


# ---------------------------------------------------------------------------
# the gate
# ---------------------------------------------------------------------------


def test_module_scope_polars_is_confined_to_the_allowlist():
    found = eager_polars_modules(set(_all_modules()))
    assert found == set(MODULE_SCOPE_ALLOWLIST), (
        f"module-scope polars outside the allowlist: {sorted(found - set(MODULE_SCOPE_ALLOWLIST))}; "
        f"allowlisted but lazy now: {sorted(set(MODULE_SCOPE_ALLOWLIST) - found)}"
    )


def test_the_models_import_closure_does_not_load_polars():
    closure = import_closure(f"{PACKAGE}.models.core")
    assert f"{PACKAGE}.utils.suppression_frame" in closure
    assert eager_polars_modules(closure) == set()


def test_the_named_reporters_are_allowlisted_modules():
    assert CONFIG_CLOSURE_EAGER <= set(MODULE_SCOPE_ALLOWLIST)


def test_importing_the_models_loads_no_polars_in_a_fresh_interpreter():
    # the source scan cannot see an import-time call that imports polars inside a
    # helper (frame_schema(...) at module scope, a decorator, importlib)
    code = importing_this_checkout(
        "import sys; import automated_security_helper.models.core; "
        "assert 'polars' not in sys.modules, 'polars loaded with models.core'"
    )
    result = subprocess.run(
        [sys.executable, "-B", "-c", code],  # -c puts the cwd on sys.path
        capture_output=True,
        text=True,
        cwd=PACKAGE_ROOT.parent,
        env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        timeout=300,
    )
    assert result.returncode == 0, result.stderr[-2000:]


def test_the_config_layer_loads_polars_only_through_the_named_reporters():
    closure = import_closure(f"{PACKAGE}.config.ash_config")
    assert f"{PACKAGE}.models.core" in closure
    assert eager_polars_modules(closure) == CONFIG_CLOSURE_EAGER
