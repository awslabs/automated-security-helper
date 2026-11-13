# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config override that shortens ``ash_plugin_modules`` leaves no reference past it.

A config file can read an ``ash_plugin_modules`` entry from the environment.
The load records that read as references and record rewrites, each naming its
entry by index, from the file's own document. ``--config-overrides`` is applied
to the model before those are attached, so an override that replaces the list
with a shorter one leaves a reference at an index the list no longer has.

``ash plugin list`` always renumbers the list it prints (its comma split) and
moves the references with it (``reindex_plugin_module_references``), which
refuses a reference past the entries it is told about. Before the load
dropped such references, a shortening override made the command exit with a
traceback instead of listing the plugins.

The cells here run the three shapes that carry a stale index (an override
applied during the load, one that empties the list, and a second application
to a loaded model), read all three reference lists, and run the command. The
last two cells hold the refusal itself: it is not a ``ValueError``, and the
confinement changes nothing when it fires.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

KEPT = "shortkept_ash_plugins"
FIRST = "shortfirst_ash_plugins"
FROM_ENV = "shortenv_ash_plugins"
DROPPED = "shortdropped_ash_plugins"
MODULES = (KEPT, FIRST, FROM_ENV)
REFERENCE_LISTS = (
    "_environment_references",
    "_displayed_environment_references",
    "_written_references",
)


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Path]:
    """A working directory, and a config file outside it that reads one entry
    of ``ash_plugin_modules`` from the environment."""
    work = tmp_path / "work"
    work.mkdir()
    site = tmp_path / "site"
    for name in MODULES:
        (site / name).mkdir(parents=True)
        (site / name / "__init__.py").write_text("PLANTED = 1\n", encoding="utf-8")
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.setenv("ASH_SHORT_ENV", FROM_ENV)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(work)
    config = tmp_path / "operator" / "config.yaml"
    config.parent.mkdir()
    config.write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {FIRST}\n  - ${{ASH_SHORT_ENV}}\n",
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
                found.append((attribute, reference))
    return found


def _past_the_list(config) -> List[Any]:
    entries = len(config.ash_plugin_modules)
    return [
        (attribute, tuple(reference.path))
        for attribute, reference in _module_references(config)
        if isinstance(reference.path[1], int) and reference.path[1] >= entries
    ]


def _loaded(layout: Dict[str, Path], overrides: List[str]):
    from automated_security_helper.config.resolve_config import resolve_config

    return resolve_config(config_path=str(layout["config"]), config_overrides=overrides)


def _second_application(layout: Dict[str, Path], overrides: List[str]):
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    return apply_config_overrides(_loaded(layout, []), overrides)


SHAPES = {
    "override-during-the-load": (
        lambda layout: _loaded(layout, [f"ash_plugin_modules=[{KEPT}]"]),
        [KEPT],
    ),
    "override-emptying-the-list": (
        lambda layout: _loaded(layout, ["ash_plugin_modules=[]"]),
        [],
    ),
    "second-application-to-a-loaded-model": (
        lambda layout: _second_application(layout, [f"ash_plugin_modules=[{KEPT}]"]),
        [KEPT],
    ),
}


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_a_shortened_list_has_no_reference_past_its_end(
    layout: Dict[str, Path], shape: str
):
    build, expected = SHAPES[shape]
    config = build(layout)
    assert list(config.ash_plugin_modules) == expected, config.ash_plugin_modules
    assert not _past_the_list(config), _past_the_list(config)


@pytest.mark.parametrize("shape", sorted(SHAPES))
def test_a_shortened_list_record_holds_no_environment_value(
    layout: Dict[str, Path], shape: str
):
    from automated_security_helper.config.config_validator import record_of_config

    build, _ = SHAPES[shape]
    config = build(layout)
    record = record_of_config(config, config.model_dump(mode="json"))
    assert FROM_ENV not in json.dumps(record, default=str), record["ash_plugin_modules"]


def test_control_an_appending_override_keeps_the_read_entrys_references(
    layout: Dict[str, Path],
):
    """Nothing is dropped when the list keeps the entry the reference names:
    an append leaves the read entry at index 1, in all three lists."""
    config = _loaded(layout, [f"ash_plugin_modules+=[{KEPT}]"])
    assert list(config.ash_plugin_modules) == [FIRST, FROM_ENV, KEPT]
    for attribute in REFERENCE_LISTS:
        paths = [
            tuple(reference.path[:2])
            for reference in getattr(config, attribute, ()) or ()
            if tuple(reference.path[:1]) == ("ash_plugin_modules",)
        ]
        assert ("ash_plugin_modules", 1) in paths, (attribute, paths)
    assert not _past_the_list(config)


@pytest.mark.parametrize(
    "override, listed",
    [(f"ash_plugin_modules=[{KEPT}]", KEPT), ("ash_plugin_modules=[]", None)],
    ids=["shortened-to-one", "emptied"],
)
def test_plugin_list_with_a_shortening_override_lists_the_plugins(
    layout: Dict[str, Path], override: str, listed: Any
):
    """The command's own split-and-reindex step runs over the post-override
    list: it must not meet a reference recorded for an entry the override
    replaced."""
    result = CliRunner().invoke(
        app,
        [
            "plugin",
            "list",
            "--config",
            str(layout["config"]),
            "--config-overrides",
            override,
        ],
    )

    assert result.exception is None, (repr(result.exception), result.output)
    assert result.exit_code == 0, result.output
    if listed is not None:
        assert listed in sys.modules
    assert FIRST not in sys.modules and FROM_ENV not in sys.modules


def _config_with_a_stale_reference(layout: Dict[str, Path]):
    """A loaded config whose list a caller then swapped for one entry,
    moving no references: the read entry's reference now points past it."""
    config = _loaded(layout, [])
    assert list(config.ash_plugin_modules) == [FIRST, FROM_ENV]
    config.ash_plugin_modules = [DROPPED]
    assert _past_the_list(config)
    return config


def test_a_move_past_the_entries_is_not_a_value_error(layout: Dict[str, Path]):
    """A reference past the entries a caller described is a caller bug, not an
    invalid configuration: an ``except ValueError`` that reports an invalid
    configuration (every config-validation error is a ``ValueError``) must not
    catch it."""
    from automated_security_helper.config.plugin_module_trust import (
        reindex_plugin_module_references,
    )

    config = _config_with_a_stale_reference(layout)
    with pytest.raises(Exception, match=r"past the 1 entr") as caught:
        reindex_plugin_module_references(config, [DROPPED], [DROPPED])
    assert not isinstance(caught.value, ValueError), type(caught.value).__mro__


def test_a_refused_move_leaves_the_confined_list_as_it_was(
    layout: Dict[str, Path],
):
    """The confinement renumbers the references after it drops an entry. When
    the move refuses, the list has to be as it was: the new list beside the
    old indices is the mismatch that leaves a moved entry's value in a record
    in clear."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_module_trust import (
        confine_plugin_modules,
    )

    config = _config_with_a_stale_reference(layout)
    before = {
        attribute: tuple(getattr(config, attribute, ()) or ())
        for attribute in REFERENCE_LISTS
    }
    with pytest.raises(Exception, match=r"past the 1 entr"):
        confine_plugin_modules(
            config,
            AshConfig(),
            [],
            layout["work"],
            [layout["config"]],
            frozenset(),
            no_scanned_tree=False,
            checkout_membership=False,
            mixed_membership=False,
            given_root_membership=False,
            undecided_membership=False,
        )
    assert list(config.ash_plugin_modules) == [DROPPED]
    for attribute, kept in before.items():
        assert tuple(getattr(config, attribute, ()) or ()) == kept, attribute
