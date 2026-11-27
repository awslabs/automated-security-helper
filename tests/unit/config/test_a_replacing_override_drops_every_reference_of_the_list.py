"""A replacing override leaves no environment reference of the value it replaced.

A config file can read a list entry, or any value, from the environment. The
load records each read at the place the file wrote it, a list entry by its
index, and ``--config-overrides`` is applied to the model before those records
are attached. ``KEY=VALUE`` replaces what KEY holds, so no record at KEY or
under it describes it any more. At the base only ``ash_plugin_modules`` drops
its records when it is replaced (resolve_config.py:1102-1108 and 1505-1507);
for every other value a record kept at an index the new list still has marks
the operator's own literal as read from the environment: ``ash config get``
writes the reference over it, and the results-file record writes it back as
the reference.

The cells use ``external_reports_to_include``, a top-level list of strings, and
trivy's ``scanners`` option, a typed plugin list. The operator writes the text
the environment gave at the index the file read it, the one spelling a record
left behind can mark (the view and the record match a record by its resolved
value), so each red cell can fail. An append, an override of another key, a
literal at another index and a list of other text are the controls.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

FIELD = "external_reports_to_include"
REPORT_VARIABLE = "ASH_W1S8_REPORT"
REPORT_VALUE = "w1s8-env-report.sarif"
REPORT_REFERENCE = "${ASH_W1S8_REPORT}"
TRIVY_VARIABLE = "ASH_W1S8_TRIVY"
TRIVY_REFERENCE = "${ASH_W1S8_TRIVY}"
FIRST = "w1s8-file-first.sarif"
SECOND = "w1s8-file-second.sarif"
OPERATOR = "w1s8-operator.sarif"
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
    monkeypatch.setenv(REPORT_VARIABLE, REPORT_VALUE)
    monkeypatch.setenv(TRIVY_VARIABLE, "secret")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_PLUGIN_MODULES", raising=False)
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(work)
    return {"work": work, "config": config}


def _write_reports(config: Path, entries: List[str]) -> None:
    lines = "".join(f"  - {entry}\n" for entry in entries)
    config.write_text(f"project_name: demo\n{FIELD}:\n{lines}", encoding="utf-8")


def _write_trivy(config: Path) -> None:
    config.write_text(
        "project_name: demo\nscanners:\n  trivy:\n    options:\n      scanners:\n"
        f"        - {TRIVY_REFERENCE}\n        - vuln\n",
        encoding="utf-8",
    )


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


def _run_load(config: Path, overrides: List[str]):
    from automated_security_helper.config.resolve_config import (
        load_config_file_for_run,
    )

    return load_config_file_for_run(config, config_overrides=overrides)[1]


def _second_application(config: Path, overrides: List[str]):
    from automated_security_helper.config.resolve_config import (
        apply_config_overrides,
    )

    return apply_config_overrides(_resolved(config, []), overrides)


def _record(config) -> Dict[str, Any]:
    from automated_security_helper.config.config_validator import record_of_config

    return record_of_config(config, config.model_dump(mode="json"))


def _records_of(config, field: str) -> List[Any]:
    """Each record of the three lists whose place starts at ``field``."""
    return [
        (attribute, tuple(reference.path))
        for attribute in REFERENCE_LISTS
        for reference in getattr(config, attribute, ()) or ()
        if tuple(reference.path[:1]) == (field,)
    ]


#: Each: what the file writes, and the replacing override. The operator writes
#: the environment's text at index 0, where the file read it.
REPLACED = {
    "same-length": (
        [REPORT_REFERENCE, SECOND],
        f"{FIELD}=[{REPORT_VALUE}, {OPERATOR}]",
    ),
    "shorter": ([REPORT_REFERENCE, SECOND], f"{FIELD}=[{REPORT_VALUE}]"),
}

#: Each way a configuration is built with the overrides applied.
BUILDS = {
    "load": _run_load,
    "resolve": _resolved,
    "second-application": _second_application,
}


@pytest.mark.parametrize("shape", sorted(REPLACED), ids=sorted(REPLACED))
def test_config_get_shows_the_operators_literal_for_a_replaced_list(
    layout: Dict[str, Path], shape: str
):
    """The new list holds the operator's literal where the file read the
    environment. A record kept from the file marks it: at the same length by its
    index (environment_record.py:741-749), at a new length by its text (the
    fallback ``_moved``, 698-713). Once the list is replaced neither may happen,
    and the view shows the literal as the operator wrote it."""
    entries, override = REPLACED[shape]
    _write_reports(layout["config"], entries)
    out = _config_get(layout["config"], [override])
    assert REPORT_REFERENCE not in out, out
    assert REPORT_VALUE in out, out


def test_config_get_shows_no_reference_for_a_replaced_plugin_option_list(
    layout: Dict[str, Path],
):
    """The same for a typed plugin option: trivy's ``scanners`` read ``secret``
    from the environment at index 0, and the operator replaces the list with
    one that holds ``secret`` there as its own literal."""
    _write_trivy(layout["config"])
    out = _config_get(
        layout["config"], ["scanners.trivy.options.scanners=[secret, license]"]
    )
    assert TRIVY_REFERENCE not in out, out


def test_the_record_of_a_replaced_list_holds_the_operators_literal(
    layout: Dict[str, Path],
):
    """The results file's record of the configuration (record_of_config) writes
    a record back where the configuration holds its resolved value at its
    place (config_validator.py:3209-3225). After a replace that is the
    operator's literal, which stays as the operator wrote it."""
    _write_reports(layout["config"], [REPORT_REFERENCE, SECOND])
    config = _resolved(layout["config"], [f"{FIELD}=[{REPORT_VALUE}, {OPERATOR}]"])
    assert config.external_reports_to_include == [REPORT_VALUE, OPERATOR]
    record = _record(config)
    assert record[FIELD] == [REPORT_VALUE, OPERATOR], record[FIELD]
    assert REPORT_REFERENCE not in json.dumps(record, default=str), record[FIELD]


@pytest.mark.parametrize("build", sorted(BUILDS), ids=sorted(BUILDS))
def test_a_replaced_list_keeps_no_record_of_the_files_entries(
    layout: Dict[str, Path], build: str
):
    """Every path that builds a configuration drops the list's records: the
    load attaches them after the overrides (load_config_file_for_run), the
    resolve goes through the load, and a second application finds them on the
    model it is given."""
    _write_reports(layout["config"], [REPORT_REFERENCE, SECOND])
    config = BUILDS[build](layout["config"], [f"{FIELD}=[{OPERATOR}, {SECOND}]"])
    assert config.external_reports_to_include == [OPERATOR, SECOND]
    assert not _records_of(config, FIELD), _records_of(config, FIELD)


def test_control_config_get_shows_the_files_reference_without_an_override(
    layout: Dict[str, Path],
):
    """Stays green: with no override the file's record is the list's own, and
    the view writes the reference, never the value."""
    _write_reports(layout["config"], [REPORT_REFERENCE, SECOND])
    out = _config_get(layout["config"], [])
    assert REPORT_REFERENCE in out, out
    assert REPORT_VALUE not in out, out


def test_control_an_append_keeps_the_files_reference(layout: Dict[str, Path]):
    """Stays green: an append moves no entry, so the read entry keeps its
    record at index 0 and the view still writes the reference."""
    _write_reports(layout["config"], [REPORT_REFERENCE, SECOND])
    out = _config_get(layout["config"], [f"{FIELD}+=[{OPERATOR}]"])
    assert REPORT_REFERENCE in out, out
    assert REPORT_VALUE not in out, out
    assert OPERATOR in out, out


def test_control_an_override_of_another_key_keeps_the_files_reference(
    layout: Dict[str, Path],
):
    """Stays green: a replacement drops the records at the key it landed on
    and under it, and ``project_name`` is no part of the list."""
    _write_reports(layout["config"], [REPORT_REFERENCE, SECOND])
    out = _config_get(layout["config"], ["project_name=other"])
    assert REPORT_REFERENCE in out, out
    assert REPORT_VALUE not in out, out


def test_control_a_literal_at_another_index_is_shown_as_written(
    layout: Dict[str, Path],
):
    """Stays green: the file read the environment at index 1 and the operator
    writes that text at index 0, beside the file's own literal. At an unchanged
    length the view places a record by its index only, so index 0 shows the
    operator's text at the base too; at the tip the record is gone."""
    _write_reports(layout["config"], [FIRST, REPORT_REFERENCE])
    out = _config_get(layout["config"], [f"{FIELD}=[{REPORT_VALUE}, {FIRST}]"])
    assert REPORT_REFERENCE not in out, out
    assert REPORT_VALUE in out, out


def test_control_the_record_of_a_shortened_list_holds_no_reference(
    layout: Dict[str, Path],
):
    """Stays green: the operator's list holds other text than the environment
    gave, so a record left behind matches nothing in it, and the record is the
    operator's list at the base too."""
    _write_reports(layout["config"], [REPORT_REFERENCE, SECOND])
    config = _resolved(layout["config"], [f"{FIELD}=[{OPERATOR}]"])
    assert _record(config)[FIELD] == [OPERATOR]
