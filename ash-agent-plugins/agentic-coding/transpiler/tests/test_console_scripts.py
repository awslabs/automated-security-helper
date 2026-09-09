"""Every console script in `[project.scripts]` must resolve to a callable.

A `[project.scripts]` entry is a string. Nothing at build or install time checks
that the module it names is importable or that the attribute after the colon
exists -- the wrapper is generated either way, and the import only happens when
a user runs the command. A stale entry therefore installs cleanly, passes CI,
and fails with ImportError for whoever follows the documentation.

This project shipped exactly that: `transpile = "transpiler.cli:transpile_compat"`
outlived the shim it pointed at, and four other places told users to run it.
Importing each target here is the cheapest check that would have caught it, and
it covers entry points added later without anyone remembering to test them.
"""
from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

import pytest

PYPROJECT = Path(__file__).resolve().parent.parent / "pyproject.toml"


def _declared_scripts() -> dict[str, str]:
    with PYPROJECT.open("rb") as fh:
        return tomllib.load(fh).get("project", {}).get("scripts", {})


def test_pyproject_declares_console_scripts():
    """Positive control: without it, an empty table would make the parametrized
    test below collect nothing and report success."""
    assert _declared_scripts(), f"no [project.scripts] table found in {PYPROJECT}"


@pytest.mark.parametrize(("script", "target"), sorted(_declared_scripts().items()))
def test_declared_console_script_resolves_to_a_callable(script: str, target: str):
    module_path, sep, attr_path = target.partition(":")
    assert sep and attr_path, (
        f"console script {script} = {target!r} names no attribute; an entry point "
        "must be 'module:callable'"
    )

    module = importlib.import_module(module_path)

    # PEP 621 allows a dotted attribute (`module:Class.method`), so walk it.
    obj = module
    walked = module_path
    for part in attr_path.split("."):
        assert hasattr(obj, part), (
            f"console script {script} = {target!r} does not resolve: {walked} "
            f"defines no {part!r}. Running `{script}` would raise ImportError in "
            "the generated wrapper."
        )
        obj = getattr(obj, part)
        walked = f"{walked}.{part}"

    assert callable(obj), (
        f"console script {script} = {target!r} resolves to {obj!r}, which is not "
        f"callable, so `{script}` would fail at invocation"
    )
