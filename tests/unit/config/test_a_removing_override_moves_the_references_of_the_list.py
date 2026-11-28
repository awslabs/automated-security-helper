"""A removing override moves the environment references of the entries it keeps.

``KEY-=VALUE`` takes every occurrence of each item out of the list at KEY. The
load records each value a file read from the environment at the index the file
wrote it, and attaches those records after the overrides were applied. An entry
after a removed one moves to a lower index; its records must move with it, or
the view prints the entry in clear and the record writes its value into the
results file. A removed entry's records are dropped, so an operator literal
that later lands on its index is not marked as read from the environment.

At the base ``-=`` is no operator: the trailing ``-`` stays on the key, which is
refused as a respelling of the field (config_sources.py:579-653), so every
removal cell fails there, and the helper module is absent. The values the
environment gives here are text no other part of the configuration holds, so a
cell that finds one in the output has found it in clear.
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

FIELD = "external_reports_to_include"
KEPT_VARIABLE = "ASH_W1S8_KEPT"
KEPT_VALUE = "w1s8-env-kept.sarif"
KEPT_REFERENCE = "${ASH_W1S8_KEPT}"
TAIL_VARIABLE = "ASH_W1S8_TAIL"
TAIL_VALUE = "w1s8-env-tail.sarif"
TAIL_REFERENCE = "${ASH_W1S8_TAIL}"
FIRST = "w1s8-file-first.sarif"
MIDDLE = "w1s8-file-mid.sarif"
OPERATOR = "w1s8-operator.sarif"
MODULE_VARIABLE = "ASH_W1S8_MODULE"
MODULE_REFERENCE = "${ASH_W1S8_MODULE}"
MODULE_FIRST = "s8movefirst_ash_plugins"
MODULE_FROM_ENV = "s8moveenv_ash_plugins"
REFERENCE_LISTS = (
    "_environment_references",
    "_displayed_environment_references",
    "_written_references",
)


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Dict[str, Path]:
    """A working directory, and the operator's config file outside it."""
    work = tmp_path / "work"
    work.mkdir()
    config = tmp_path / "operator" / "config.yaml"
    config.parent.mkdir()
    monkeypatch.setenv(KEPT_VARIABLE, KEPT_VALUE)
    monkeypatch.setenv(TAIL_VARIABLE, TAIL_VALUE)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(work)
    return {"work": work, "config": config}


@pytest.fixture
def module_layout(
    layout: Dict[str, Path], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Dict[str, Path]:
    """The layout, with a config file that reads the module at INDEX 1 of
    ``ash_plugin_modules`` from the environment, and both modules importable."""
    site = tmp_path / "site"
    for name in (MODULE_FIRST, MODULE_FROM_ENV):
        (site / name).mkdir(parents=True)
        (site / name / "__init__.py").write_text("PLANTED = 1\n", encoding="utf-8")
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(str(site))
    monkeypatch.setenv(MODULE_VARIABLE, MODULE_FROM_ENV)
    layout["config"].write_text(
        f"project_name: demo\nash_plugin_modules:\n  - {MODULE_FIRST}\n"
        f"  - {MODULE_REFERENCE}\n",
        encoding="utf-8",
    )
    yield layout
    for name in (MODULE_FIRST, MODULE_FROM_ENV):
        sys.modules.pop(name, None)


def _write_reports(config: Path, entries: List[str]) -> None:
    lines = "".join(f"  - {entry}\n" for entry in entries)
    config.write_text(f"project_name: demo\n{FIELD}:\n{lines}", encoding="utf-8")


def _config_get(config: Path, overrides: List[str]) -> str:
    arguments = ["config", "get", "--config", str(config)]
    for override in overrides:
        arguments += ["--config-overrides", override]
    result = CliRunner().invoke(app, arguments)
    assert result.exit_code == 0, result.output
    return result.output


def _resolved(config: Path, overrides: List[str]):
    from automated_security_helper.config.resolve_config import resolve_config

    return resolve_config(config_path=str(config), config_overrides=overrides)


def _record(config) -> Dict[str, Any]:
    from automated_security_helper.config.config_validator import record_of_config

    return record_of_config(config, config.model_dump(mode="json"))


def _reference(*path: Any, length=None, index_at=None, key: bool = False):
    from automated_security_helper.config.environment_record import (
        EnvironmentReference,
    )

    return EnvironmentReference(
        path=tuple(path),
        written="${ASH_W1S8_UNIT}",
        resolved="w1s8-unit",
        value="w1s8-unit",
        key=key,
        length=length,
        index_at=index_at,
    )


def _rewrite(*path: Any):
    from automated_security_helper.config.config_validator import EnvironmentRewrite

    return EnvironmentRewrite(
        kind="value",
        path=tuple(path),
        resolved="w1s8-unit",
        written="${ASH_W1S8_UNIT}",
        environment_part="w1s8-unit",
        reference="${ASH_W1S8_UNIT}",
    )


#: Each: what the file writes, the overrides, the list they leave, and the
#: record of it (each environment-read entry as its reference).
REMOVALS = {
    "remove-before-it": (
        [FIRST, KEPT_REFERENCE],
        [f"{FIELD}-=[{FIRST}]"],
        [KEPT_VALUE],
        [KEPT_REFERENCE],
    ),
    "remove-before-it-then-append": (
        [FIRST, KEPT_REFERENCE],
        [f"{FIELD}-=[{FIRST}]", f"{FIELD}+=[{OPERATOR}]"],
        [KEPT_VALUE, OPERATOR],
        [KEPT_REFERENCE, OPERATOR],
    ),
    "remove-between-two-reads-then-append": (
        [KEPT_REFERENCE, MIDDLE, TAIL_REFERENCE],
        [f"{FIELD}-=[{MIDDLE}]", f"{FIELD}+=[{OPERATOR}]"],
        [KEPT_VALUE, TAIL_VALUE, OPERATOR],
        [KEPT_REFERENCE, TAIL_REFERENCE, OPERATOR],
    ),
}


@pytest.mark.parametrize("shape", sorted(REMOVALS), ids=sorted(REMOVALS))
def test_config_get_shows_a_moved_entrys_reference_not_its_value(
    layout: Dict[str, Path], shape: str
):
    """The entry the file read from the environment survives the removal at a
    lower index, and ``ash config get`` writes its reference there, never its
    value. A record left at its old index names the operator's literal or
    nothing: the append shapes keep the list's length, so the view places each
    record by its index (environment_record.py:741-749) and the moved entry
    would print in clear."""
    entries, overrides, _, _ = REMOVALS[shape]
    _write_reports(layout["config"], entries)
    out = _config_get(layout["config"], overrides)
    assert KEPT_REFERENCE in out, out
    assert KEPT_VALUE not in out, out
    assert TAIL_VALUE not in out, out
    if TAIL_REFERENCE in entries:
        assert TAIL_REFERENCE in out, out


def test_a_removed_entrys_reference_does_not_mark_the_operators_literal(
    layout: Dict[str, Path],
):
    """The removal takes out the entry the file read from the environment, and
    the operator appends the same text as a literal at the same index. The
    entry's records went with it, so the view shows the literal as written."""
    _write_reports(layout["config"], [FIRST, KEPT_REFERENCE])
    out = _config_get(
        layout["config"], [f"{FIELD}-=[{KEPT_VALUE}]", f"{FIELD}+=[{KEPT_VALUE}]"]
    )
    assert KEPT_REFERENCE not in out, out
    assert KEPT_VALUE in out, out


@pytest.mark.parametrize("shape", sorted(REMOVALS), ids=sorted(REMOVALS))
def test_the_record_writes_each_moved_entry_as_its_reference(
    layout: Dict[str, Path], shape: str
):
    """The results file's record writes an entry back as the reference the file
    wrote only at the place its record names (config_validator.py:3209-3225),
    so a record that did not move leaves the moved entry's value in clear."""
    entries, overrides, expected, recorded = REMOVALS[shape]
    _write_reports(layout["config"], entries)
    config = _resolved(layout["config"], overrides)
    assert config.external_reports_to_include == expected
    record = _record(config)
    assert record[FIELD] == recorded, record[FIELD]
    dumped = json.dumps(record, default=str)
    assert KEPT_VALUE not in dumped, record[FIELD]
    assert TAIL_VALUE not in dumped, record[FIELD]


def test_the_results_file_holds_no_moved_value(layout: Dict[str, Path]):
    """The configuration a results file carries is its record
    (asharp_model.py:1478-1481), so it holds the moved entry's reference and not
    its value."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    entries, overrides, _, _ = REMOVALS["remove-before-it-then-append"]
    _write_reports(layout["config"], entries)
    config = _resolved(layout["config"], overrides)
    written = AshAggregatedResults(ash_config=config).model_dump_json(by_alias=True)
    assert KEPT_REFERENCE in written, written
    assert KEPT_VALUE not in written, written


def test_a_second_application_moves_the_references_its_model_carries(
    layout: Dict[str, Path],
):
    """A model that already carries its records (a resolved one, given the
    overrides by ``apply_config_overrides``) has them moved by that application:
    the exact view (the MCP get_config's, ``exact_indices``) marks the moved
    entry at its new index, the messages' view hides it there, and the record
    writes it back as its reference."""
    from automated_security_helper.config.environment_record import (
        environment_marker,
        record_environment_references,
        with_environment_values_shown,
    )
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    entries, overrides, expected, recorded = REMOVALS["remove-before-it-then-append"]
    _write_reports(layout["config"], entries)
    config = apply_config_overrides(_resolved(layout["config"], []), overrides)
    assert config.external_reports_to_include == expected
    dumped = config.model_dump(mode="json", by_alias=True)
    view = record_environment_references(
        dumped,
        config._displayed_environment_references,
        mark=environment_marker,
        exact_indices=True,
    )
    assert view[FIELD] == [f"<from {KEPT_REFERENCE}>", OPERATOR], view[FIELD]
    shown = with_environment_values_shown(
        dumped, config._environment_references, exact_indices=True
    )
    assert shown[FIELD] == ["<value>", OPERATOR], shown[FIELD]
    assert _record(config)[FIELD] == recorded


def test_a_removal_from_the_module_list_moves_the_read_modules_references(
    module_layout: Dict[str, Path],
):
    """``ash_plugin_modules`` follows the same rule: the module the file read
    from the environment moves from index 1 to index 0 and its references move
    with it, so the confinement messages show it as ``<value>`` and the record
    writes it back as the reference."""
    from automated_security_helper.config.plugin_module_trust import (
        config_module_names,
    )

    config = _resolved(
        module_layout["config"], [f"ash_plugin_modules-=[{MODULE_FIRST}]"]
    )
    assert list(config.ash_plugin_modules) == [MODULE_FROM_ENV]
    assert config_module_names(config).get(MODULE_FROM_ENV) == "<value>"
    assert _record(config)["ash_plugin_modules"] == [MODULE_REFERENCE]
    for attribute in REFERENCE_LISTS:
        paths = {
            tuple(reference.path[:2])
            for reference in getattr(config, attribute, ()) or ()
            if tuple(reference.path[:1]) == ("ash_plugin_modules",)
        }
        assert paths == {("ash_plugin_modules", 0)}, (attribute, paths)


def test_a_removal_that_matches_nothing_keeps_each_reference_where_it_was(
    layout: Dict[str, Path],
):
    """A removal of an item the list does not hold keeps every entry where it
    was, so each record stays at its index: the change maps every index to
    itself."""
    _write_reports(layout["config"], [FIRST, KEPT_REFERENCE])
    overrides = [f"{FIELD}-=[w1s8-absent.sarif]"]
    out = _config_get(layout["config"], overrides)
    assert KEPT_REFERENCE in out, out
    assert KEPT_VALUE not in out, out
    record = _record(_resolved(layout["config"], overrides))
    assert record[FIELD] == [FIRST, KEPT_REFERENCE], record[FIELD]


def test_control_config_get_shows_the_references_without_an_override(
    layout: Dict[str, Path],
):
    """Stays green: with no override the file's records are the list's own, and
    the view writes each reference, never a value."""
    _write_reports(layout["config"], [KEPT_REFERENCE, MIDDLE, TAIL_REFERENCE])
    out = _config_get(layout["config"], [])
    assert KEPT_REFERENCE in out, out
    assert TAIL_REFERENCE in out, out
    assert KEPT_VALUE not in out, out
    assert TAIL_VALUE not in out, out


def test_a_replacement_drops_every_record_at_or_under_its_key():
    """A replacement drops a record at its key and under it, in either key
    spelling, and keeps a sibling whose key only starts the same, a key record
    of the mapping above, and every other place."""
    from automated_security_helper.config.list_references import (
        ListChange,
        reconciled_list_references,
    )
    from automated_security_helper.utils.override_key import REPLACE

    options = ("scanners", "detect-secrets", "options")
    at_the_key = _reference(*options, "exclude")
    under_it = _reference(*options, "exclude", 1, length=2, index_at=4)
    rewritten = _rewrite(*options, "exclude", 0)
    sibling = _reference(*options, "exclude_more", 0, length=1, index_at=4)
    key_above = _reference(*options, key=True)
    elsewhere = _reference("project_name")
    change = ListChange(
        path=("scanners", "detect_secrets", "options", "exclude"), op=REPLACE
    )
    held = [at_the_key, under_it, rewritten, sibling, key_above, elsewhere]
    assert reconciled_list_references(held, [change]) == [
        sibling,
        key_above,
        elsewhere,
    ]


def test_a_removal_moves_each_kept_entrys_records_and_drops_a_removed_ones():
    """A removal moves a record under a kept entry to the entry's new index,
    whatever lies under the entry (a mapping key, a key record, a list inside
    it, a record rewrite), and drops one under a removed entry. A record
    written as an entry of the list gets its new length; one in a list inside
    the entry keeps its own. Another list is not touched."""
    from automated_security_helper.config.list_references import (
        ListChange,
        reconciled_list_references,
    )
    from automated_security_helper.utils.override_key import REMOVE

    listed = ("global_settings", "ignore_paths")
    removed = _reference(*listed, 0, "path", length=4, index_at=2)
    kept_one = _reference(*listed, 1, "reason", length=4, index_at=2)
    key_of_an_entry = _reference(*listed, 3, key=True)
    inner = _reference(*listed, 3, "tags", 2, length=5, index_at=4)
    rewritten = _rewrite(*listed, 3, "path")
    other_list = _reference("global_settings", "ignore_more", 1, length=2, index_at=2)
    change = ListChange(path=listed, op=REMOVE, old_length=4, kept=(1, 3))
    held = [removed, kept_one, key_of_an_entry, inner, rewritten, other_list]
    assert reconciled_list_references(held, [change]) == [
        _reference(*listed, 0, "reason", length=2, index_at=2),
        _reference(*listed, 1, key=True),
        _reference(*listed, 1, "tags", 2, length=5, index_at=4),
        _rewrite(*listed, 1, "path"),
        other_list,
    ]


def test_a_removal_leaves_alone_what_names_no_entry_it_saw():
    """A removal changes only a record under an entry it saw: a record at the
    any-index marker (found later by its value), a patch append not yet placed
    (``-``, which ``placed_at_appends`` places against the list as the overrides
    left it), an index past the list's old length and the list itself stay as
    they are."""
    from automated_security_helper.config.environment_record import UNKNOWN_INDEX
    from automated_security_helper.config.list_references import (
        ListChange,
        reconciled_list_references,
    )
    from automated_security_helper.utils.override_key import REMOVE

    listed = ("global_settings", "ignore_paths")
    held = [
        _reference(*listed, UNKNOWN_INDEX, "path"),
        _rewrite(*listed, "-", "path"),
        _reference(*listed, 7),
        _reference(*listed),
    ]
    change = ListChange(path=listed, op=REMOVE, old_length=4, kept=(1, 3))
    assert reconciled_list_references(held, [change]) == held


def test_changes_apply_in_override_order():
    """Two removals compose: the second reads the indices of the list the first
    left. A replacement drops what it finds whatever came before, and a removal
    after it finds nothing of the file's left to move."""
    from automated_security_helper.config.list_references import (
        ListChange,
        reconciled_list_references,
    )
    from automated_security_helper.utils.override_key import REMOVE, REPLACE

    entry = _reference(FIELD, 3, length=4, index_at=1)
    first = ListChange(path=(FIELD,), op=REMOVE, old_length=4, kept=(1, 2, 3))
    second = ListChange(path=(FIELD,), op=REMOVE, old_length=3, kept=(0, 2))
    replaced = ListChange(path=(FIELD,), op=REPLACE)
    assert reconciled_list_references([entry], [first, second]) == [
        _reference(FIELD, 1, length=2, index_at=1)
    ]
    assert reconciled_list_references([entry], [first, replaced]) == []
    assert reconciled_list_references([entry], [replaced, first]) == []


@pytest.mark.parametrize(
    "shape", ["append", "remove", "replace"], ids=["append", "remove", "replace"]
)
def test_the_apply_stamps_what_each_override_did_to_a_list(shape: str):
    """``apply_config_overrides`` stamps one change for each replacement and
    each removal, read from the operator the apply returned, and none for an
    append. A removal names the old length and the old index of each entry it
    kept: every occurrence of the item goes. The input model is not stamped."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.list_references import ListChange
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )
    from automated_security_helper.utils.override_key import REMOVE, REPLACE

    base = AshConfig(
        project_name="w1s8",
        external_reports_to_include=["w1s8-a", "w1s8-b", "w1s8-a", "w1s8-c"],
    )
    override, held, stamped = {
        "append": (
            f"{FIELD}+=[w1s8-d]",
            ["w1s8-a", "w1s8-b", "w1s8-a", "w1s8-c", "w1s8-d"],
            (),
        ),
        "remove": (
            f"{FIELD}-=[w1s8-a]",
            ["w1s8-b", "w1s8-c"],
            (ListChange(path=(FIELD,), op=REMOVE, old_length=4, kept=(1, 3)),),
        ),
        "replace": (
            f"{FIELD}=[w1s8-d]",
            ["w1s8-d"],
            (ListChange(path=(FIELD,), op=REPLACE),),
        ),
    }[shape]
    config = apply_config_overrides(base, [override])
    assert config.external_reports_to_include == held
    assert config._override_list_changes == stamped
    assert base._override_list_changes == ()


def test_a_second_application_stamps_its_changes_after_the_first():
    """A later application keeps the stamp of the earlier ones and adds its own
    after them, and leaves the model it was given as it was."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.list_references import ListChange
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )
    from automated_security_helper.utils.override_key import REMOVE, REPLACE

    base = AshConfig(
        project_name="w1s8", external_reports_to_include=["w1s8-a", "w1s8-b"]
    )
    first = apply_config_overrides(base, [f"{FIELD}-=[w1s8-a]"])
    second = apply_config_overrides(first, ["project_name=w1s8-two"])
    removal = ListChange(path=(FIELD,), op=REMOVE, old_length=2, kept=(1,))
    assert first._override_list_changes == (removal,)
    assert second._override_list_changes == (
        removal,
        ListChange(path=("project_name",), op=REPLACE),
    )
