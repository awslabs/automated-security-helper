"""``output_formats+=`` while the list is empty, and ``output_formats-=``.

An empty ``output_formats`` (a config file that leaves it unset, or writes null,
``[]`` or ``""``) has every enabled reporter write its report. ``+=`` onto the empty
list writes only the formats it lists, as it does before this change; from 4.0 it
adds them to every enabled reporter's format instead, so until then the run's own
application says that this is deprecated, once in a run. ``+=`` onto a list a file
wrote adds to that list, with no word.

``-=`` takes a format out of a list a file wrote. The empty list means every format,
so there is no list to take one out of, and a removal that would leave the list
empty would turn the reports the file chose into every report: both are refused,
naming the replace form to write instead.

Each configuration is built as a scan builds it, with ``build_config``, which
applies the overrides as the run's own configuration.
"""

from __future__ import annotations

import importlib
import logging
from typing import Any

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import build_config
from automated_security_helper.core.enums import ExportFormat
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.utils.log import current_run_log_scope, run_log_scope

pytestmark = pytest.mark.unit

FIELD = "output_formats"
#: The config file each case adds its own ``output_formats`` to.
_FILE: dict[str, Any] = {"project_name": "append-window"}
#: The ways a config file holds an empty ``output_formats``.
_EMPTY = [
    pytest.param({}, id="unset"),
    pytest.param({FIELD: None}, id="null"),
    pytest.param({FIELD: []}, id="empty-list"),
    pytest.param({FIELD: ""}, id="empty-string"),
]
#: A key whose ``+=`` lands in a section no plugin ASH ships reads, which the run's
#: own application warns of. A test that finds no warning for its own key applies it
#: in the same capture, so the empty result is a measurement.
_CONTROL = "reporters.acme-capture-exporter.options.destinations"


def _resolve_config_module():
    """The module itself, whose sets of notices given the fixture below resets."""
    return importlib.import_module("automated_security_helper.config.resolve_config")


@pytest.fixture(autouse=True)
def _each_test_starts_with_no_notice_given(monkeypatch):
    """Each test starts with no override notice given and no unread-section append
    warned of, and the module's own sets are put back after it. ``raising=False``
    for the notice set, which the removal form adds: without it the tests still run
    to what they check."""
    module = _resolve_config_module()
    monkeypatch.setattr(module, "_OVERRIDE_NOTICES_GIVEN", set(), raising=False)
    monkeypatch.setattr(module, "_APPEND_TO_UNREAD_SECTION_WARNED", set())


def _built(written: dict[str, Any], *overrides: str) -> AshConfig:
    """The configuration a scan builds from a config file that holds *written*, with
    *overrides* as its ``--config-overrides``."""
    return build_config({**_FILE, **written}, list(overrides))


def _warnings_naming(caplog, key: str) -> list[str]:
    """The texts of the warnings the test captured that name *key*."""
    return [
        record.getMessage()
        for record in caplog.records
        if record.levelno >= logging.WARNING and key in record.getMessage()
    ]


@pytest.mark.parametrize("written", _EMPTY)
def test_an_append_to_an_empty_output_formats_writes_only_its_formats_and_says_it_is_deprecated(
    caplog, written
):
    """The append writes only the format it lists, as before, and gives one warning
    that names the field: the deprecation of an append to the empty list."""
    assert _built(written).output_formats == [], "control: the file's list is empty"

    with caplog.at_level("WARNING", logger="ash"):
        config = _built(written, f'{FIELD}+=["sarif"]')

    assert config.output_formats == [ExportFormat.SARIF]
    named = _warnings_naming(caplog, FIELD)
    assert len(named) == 1, named
    assert "Deprecated:" in named[0], named
    assert "output_formats is empty" in named[0], named
    assert "from 4.0" in named[0], named


def test_the_output_formats_deprecation_is_said_once_per_run(caplog):
    """A run builds its configuration more than once (a workspace scan builds one for
    each project): the line is said once in a run, and said again in the next run in
    the same process."""
    with caplog.at_level("WARNING", logger="ash"):
        with run_log_scope():
            first_run = current_run_log_scope()
            _built({}, f'{FIELD}+=["sarif"]')
            _built({}, f'{FIELD}+=["markdown"]')
            within_the_first_run = len(_warnings_naming(caplog, FIELD))
        with run_log_scope():
            second_run = current_run_log_scope()
            _built({}, f'{FIELD}+=["sarif"]')

    assert first_run is not None and second_run is not None, "control: in a run"
    assert first_run != second_run, "control: two runs are two scopes"
    assert within_the_first_run == 1
    assert len(_warnings_naming(caplog, FIELD)) == 2


def test_an_append_to_a_written_output_formats_adds_to_it_and_says_nothing(caplog):
    """Control: the file chose its formats, and ``+=`` adds to them with no word,
    before the change and after it."""
    with caplog.at_level("WARNING", logger="ash"):
        config = _built({FIELD: ["markdown"]}, f'{FIELD}+=["sarif"]')
        _built({}, f'{_CONTROL}+=["x"]')

    assert config.output_formats == [ExportFormat.MARKDOWN, ExportFormat.SARIF]
    assert _warnings_naming(caplog, FIELD) == []
    assert len(_warnings_naming(caplog, _CONTROL)) == 1, "control: the capture works"


def test_a_removal_from_a_written_output_formats_takes_the_format_out():
    config = _built({FIELD: ["markdown", "sarif"]}, f'{FIELD}-=["sarif"]')

    assert config.output_formats == [ExportFormat.MARKDOWN]


@pytest.mark.parametrize("written", _EMPTY)
def test_a_removal_from_an_empty_output_formats_is_refused(written):
    """The empty list means every format, so there is no list to take one out of. The
    refusal says so and names the replace form, which writes the formats to keep."""
    with pytest.raises(ASHConfigValidationError) as refused:
        _built(written, f'{FIELD}-=["sarif"]')

    text = str(refused.value)
    assert "which means every item" in text, text
    assert f"'{FIELD}=[...]'" in text, text
    assert "would leave" not in text, text


def test_a_removal_that_would_empty_output_formats_is_refused():
    """Taking out the last format would leave the list empty, which means every
    format, so the file's one report would become every report. The removal is
    refused."""
    with pytest.raises(ASHConfigValidationError) as refused:
        _built({FIELD: ["sarif"]}, f'{FIELD}-=["sarif"]')

    text = str(refused.value)
    assert "would leave" in text, text
    assert "which means every item" in text, text
