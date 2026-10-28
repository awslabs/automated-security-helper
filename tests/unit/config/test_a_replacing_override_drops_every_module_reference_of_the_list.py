# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An override that replaces ``ash_plugin_modules`` leaves none of the old references.

A config file can read an ``ash_plugin_modules`` entry from the environment.
The load records that read as references and record rewrites, each naming its
entry by index, from the file's own document, and ``--config-overrides`` is
applied to the model before they are attached.

Dropping the references past the end of the list is not enough: a replacing
override that lands on the index of the environment-read entry keeps that
reference, so the operator's literal is shown as ``<value>`` in the confinement
warnings, ``ash config get`` and the MCP ``get_config`` still mark it
environment-read, and the stale record rewrite survives. The cells here put the
environment-read entry at index 0 and replace the list with one of the same
length, a shorter one and a longer one; an appending override is the control
that keeps the references.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

REPLACED = "replkept_ash_plugins"
REPLACED_TWO = "replkept_two_ash_plugins"
FIRST = "replfirst_ash_plugins"
FROM_ENV = "replenv_ash_plugins"
MODULES = (REPLACED, REPLACED_TWO, FIRST, FROM_ENV)
REFERENCE_LISTS = (
    "_environment_references",
    "_displayed_environment_references",
    "_written_references",
)


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Path]:
    """A working directory, and a config file outside it that reads the entry
    at INDEX 0 of ``ash_plugin_modules`` from the environment."""
    work = tmp_path / "work"
    work.mkdir()
    site = tmp_path / "site"
    for name in MODULES:
        (site / name).mkdir(parents=True)
        (site / name / "__init__.py").write_text("PLANTED = 1\n", encoding="utf-8")
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.setenv("ASH_REPL_ENV", FROM_ENV)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    monkeypatch.chdir(work)
    config = tmp_path / "operator" / "config.yaml"
    config.parent.mkdir()
    config.write_text(
        f"project_name: demo\nash_plugin_modules:\n  - ${{ASH_REPL_ENV}}\n  - {FIRST}\n",
        encoding="utf-8",
    )
    yield {"work": work, "config": config}
    for name in MODULES:
        sys.modules.pop(name, None)


def _module_references(config) -> List[Any]:
    found = []
    for attribute in REFERENCE_LISTS:
        for reference in getattr(config, attribute, ()) or ():
            if tuple(reference.path[:1]) == ("ash_plugin_modules",):
                found.append((attribute, tuple(reference.path)))
    return found


def _loaded(layout: Dict[str, Path], overrides: List[str]):
    from automated_security_helper.config.resolve_config import resolve_config

    return resolve_config(config_path=str(layout["config"]), config_overrides=overrides)


def _second_application(layout: Dict[str, Path], overrides: List[str]):
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    return apply_config_overrides(_loaded(layout, []), overrides)


def _run_load(layout: Dict[str, Path], overrides: List[str]):
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    return load_config_file_for_run(layout["config"], config_overrides=overrides)[1]


#: Each: how the config is built, the override, and the list it ends with.
SHAPES = {
    "same-length-on-the-read-entrys-index-resolve": (
        _loaded,
        [f"ash_plugin_modules=[{REPLACED}, {REPLACED_TWO}]"],
        [REPLACED, REPLACED_TWO],
    ),
    "same-length-on-the-read-entrys-index-load": (
        _run_load,
        [f"ash_plugin_modules=[{REPLACED}, {REPLACED_TWO}]"],
        [REPLACED, REPLACED_TWO],
    ),
    "shorter-keeping-index-zero-resolve": (
        _loaded,
        [f"ash_plugin_modules=[{REPLACED}]"],
        [REPLACED],
    ),
    "shorter-keeping-index-zero-load": (
        _run_load,
        [f"ash_plugin_modules=[{REPLACED}]"],
        [REPLACED],
    ),
    "longer-resolve": (
        _loaded,
        [f"ash_plugin_modules=[{REPLACED}, {REPLACED_TWO}, {FIRST}]"],
        [REPLACED, REPLACED_TWO, FIRST],
    ),
    "second-application-same-length": (
        _second_application,
        [f"ash_plugin_modules=[{REPLACED}, {REPLACED_TWO}]"],
        [REPLACED, REPLACED_TWO],
    ),
    # The dash spelling of the key lands on the same field: every path that
    # builds a config must read it as the replace it is.
    "dash-spelling-resolve": (
        _loaded,
        [f"ash-plugin-modules=[{REPLACED}, {REPLACED_TWO}]"],
        [REPLACED, REPLACED_TWO],
    ),
    "dash-spelling-load": (
        _run_load,
        [f"ash-plugin-modules=[{REPLACED}, {REPLACED_TWO}]"],
        [REPLACED, REPLACED_TWO],
    ),
    "dash-spelling-second-application": (
        _second_application,
        [f"ash-plugin-modules=[{REPLACED}, {REPLACED_TWO}]"],
        [REPLACED, REPLACED_TWO],
    ),
}

#: The operator writes the module the file read from the environment
#: literally, so the new list holds the same text at the same index. Each: how
#: the config is built, and the override.
LITERAL_SHAPES = {
    "literal-resolve": (_loaded, [f"ash_plugin_modules=[{FROM_ENV}]"]),
    "literal-load": (_run_load, [f"ash_plugin_modules=[{FROM_ENV}]"]),
    "literal-dash-load": (_run_load, [f"ash-plugin-modules=[{FROM_ENV}]"]),
    "literal-second-application": (
        _second_application,
        [f"ash_plugin_modules=[{FROM_ENV}]"],
    ),
}


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_a_replaced_list_keeps_no_reference_of_the_old_entries(
    layout: Dict[str, Path], shape: str
):
    build, overrides, expected = SHAPES[shape]
    config = build(layout, overrides)
    assert list(config.ash_plugin_modules) == expected, config.ash_plugin_modules
    assert not _module_references(config), _module_references(config)


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_a_replaced_list_shows_the_operators_literal_and_records_no_env_value(
    layout: Dict[str, Path], shape: str
):
    from automated_security_helper.config.config_validator import record_of_config
    from automated_security_helper.config.plugin_module_trust import (
        config_module_names,
    )

    """The same shapes as the cell above, with the operator writing the module
    the file read from the environment literally at index 0 instead of
    ``REPLACED``. Both views key on a reference's resolved value: a stale
    reference marks an entry only where the entry equals that value, so a
    list that never holds the environment's text (the first form of this
    cell) can neither show ``<value>`` nor draw a record rewrite whether or
    not the references were dropped, and the cell could not fail."""
    build, overrides, expected = SHAPES[shape]
    overrides = [override.replace(REPLACED, FROM_ENV) for override in overrides]
    expected = [FROM_ENV if name == REPLACED else name for name in expected]
    config = build(layout, overrides)
    assert list(config.ash_plugin_modules) == expected, config.ash_plugin_modules
    shown = config_module_names(config)
    for name in expected:
        assert shown.get(name, name) == name, (name, shown)
    record = record_of_config(config, config.model_dump(mode="json"))
    assert record["ash_plugin_modules"] == expected, record["ash_plugin_modules"]
    assert "${ASH_REPL_ENV}" not in json.dumps(record, default=str), record


@pytest.mark.parametrize("shape", sorted(LITERAL_SHAPES))
def test_a_literal_spelling_of_the_read_module_is_recorded_as_the_literal(
    layout: Dict[str, Path], shape: str
):
    """The record rewrites a string only where it equals a reference's resolved
    value, so only an override that spells the environment's own value can
    show a reference left behind: the stale index-0 rewrite then matches the
    operator's literal and would write ``${ASH_REPL_ENV}`` over it. The
    cells above never put the environment value in the new list, so their
    record assertion holds with or without the drop."""
    from automated_security_helper.config.config_validator import record_of_config

    build, overrides = LITERAL_SHAPES[shape]
    config = build(layout, overrides)
    assert list(config.ash_plugin_modules) == [FROM_ENV], config.ash_plugin_modules
    assert not _module_references(config), _module_references(config)
    record = record_of_config(config, config.model_dump(mode="json"))
    assert record["ash_plugin_modules"] == [FROM_ENV], record["ash_plugin_modules"]
    assert "${ASH_REPL_ENV}" not in json.dumps(record, default=str), record


def test_the_dash_spelling_leaves_the_same_config_on_every_path(
    layout: Dict[str, Path],
):
    """The load path and the resolve path agree for the dash spelling: the same
    list, and no module reference on either."""
    overrides = [f"ash-plugin-modules=[{REPLACED}, {REPLACED_TWO}]"]
    resolved = _loaded(layout, overrides)
    loaded = _run_load(layout, overrides)
    assert list(resolved.ash_plugin_modules) == list(loaded.ash_plugin_modules)
    assert _module_references(resolved) == _module_references(loaded) == []


def test_an_override_that_is_not_a_replace_of_the_list_keeps_every_reference(
    layout: Dict[str, Path],
):
    """``ash_plugin_modules.0=x`` turns the list into a mapping and fails
    validation, so it is refused and no config comes of it. The model it was
    applied to keeps every reference: nothing is dropped for an override that
    did not land. The load refuses it too."""
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    base = _loaded(layout, [])
    before = sorted(_module_references(base))
    assert ("_environment_references", ("ash_plugin_modules", 0)) in before
    with pytest.raises(ASHConfigValidationError):
        apply_config_overrides(base, ["ash_plugin_modules.0=x"])
    assert sorted(_module_references(base)) == before
    assert list(base.ash_plugin_modules) == [FROM_ENV, FIRST]
    with pytest.raises(ASHConfigValidationError):
        _run_load(layout, ["ash_plugin_modules.0=x"])


def test_the_load_reads_whether_the_list_was_replaced_from_the_apply_not_the_text(
    layout: Dict[str, Path], monkeypatch: pytest.MonkeyPatch
):
    """One reader of the override key decides replace or append: the apply. A
    resolver that reports an override as an append (here forced, for a key whose
    text reads as a replace) leaves the load keeping the references its list
    still has an index for. A load that re-read the override text would
    drop them, and would drop every reference while the environment-read entry
    stayed in the list."""
    from automated_security_helper.config import resolve_config as module

    real = module._apply_config_override

    def reports_an_append(*args, **kwargs):
        keys, value, _ = real(*args, **kwargs)
        return keys, value, True

    monkeypatch.setattr(module, "_apply_config_override", reports_an_append)
    config = _run_load(layout, [f"ash_plugin_modules=[{FROM_ENV}, {FIRST}]"])
    assert list(config.ash_plugin_modules) == [FROM_ENV, FIRST]
    assert ("_environment_references", ("ash_plugin_modules", 0)) in [
        (attribute, path[:2]) for attribute, path in _module_references(config)
    ]


def test_control_an_appending_override_keeps_the_read_entrys_references(
    layout: Dict[str, Path],
):
    """Nothing is dropped when the list keeps the entry the reference names:
    an append leaves the read entry at index 0, in all three lists."""
    config = _loaded(layout, [f"ash_plugin_modules+=[{REPLACED}]"])
    assert list(config.ash_plugin_modules) == [FROM_ENV, FIRST, REPLACED]
    for attribute in REFERENCE_LISTS:
        paths = [
            tuple(reference.path[:2])
            for reference in getattr(config, attribute, ()) or ()
            if tuple(reference.path[:1]) == ("ash_plugin_modules",)
        ]
        assert ("ash_plugin_modules", 0) in paths, (attribute, paths)


def test_control_an_override_of_another_key_keeps_the_read_entrys_references(
    layout: Dict[str, Path],
):
    config = _loaded(layout, ["project_name=other"])
    assert list(config.ash_plugin_modules) == [FROM_ENV, FIRST]
    assert ("_environment_references", ("ash_plugin_modules", 0)) in [
        (attribute, path[:2]) for attribute, path in _module_references(config)
    ]
