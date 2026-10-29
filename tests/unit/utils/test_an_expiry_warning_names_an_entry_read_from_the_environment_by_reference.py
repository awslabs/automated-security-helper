# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The warnings for an expired suppression and for an ignore path that expires
or has expired name an entry the config read from the environment by its
references.

At the start of a scan the expiration check warns about each ignore path that
expires within 30 days, and once about every ignore path and suppression that
has expired. Each warning line names the entry by its path (a suppression by
its rule id and path too), gives the date it expires or expired, and quotes its
reason. A field the config file read from the environment (``${VAR}``, or
``!ENV ${VAR}``) is named as the file wrote it, as the results file's
``ash_config`` records it, and never as the value. Each cell sets the variables
to canaries made for the run, which no assertion prints, and checks that the
canaries are absent and the references are there. A date canary is a valid
date drawn for the run inside the days its warning lists (2 to 28 days ahead
for an entry that expires, 2 to 400 days back for one that has expired), and
its cell first checks that the warning lists the entry, so it cannot pass by
leaving the entry out. Fields the file wrote as text are named as they are.

The warning for a suppression that expires within 30 days, and the reason it
quotes, are covered by
test_a_suppression_reason_read_from_the_environment_is_quoted_by_reference.py.
"""

from __future__ import annotations

import logging
import secrets
from datetime import date, timedelta
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.plugin_modules.ash_builtin.event_handlers.suppression_expiration_checker import (
    handle_suppression_expiration_check,
)

pytestmark = pytest.mark.unit

FORMS = {
    "plain": "${{{}}}",
    "tagged": "!ENV ${{{}}}",
}
VARIABLES = {"rule": "ASH_GATE_RULE", "path": "ASH_GATE_FILE", "reason": "ASH_GATE_WHY"}
DATE_VARIABLE = "ASH_GATE_DATE"
SOON = (date.today() + timedelta(days=5)).isoformat()
PAST = (date.today() - timedelta(days=5)).isoformat()


class _Canary(str):
    """The canary's text, shown as ``<canary>`` where pytest shows a test's
    arguments."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "'<canary>'"


@pytest.fixture
def canaries(monkeypatch) -> dict:
    values = {
        name: _Canary(f"ash-canary-{name}-" + secrets.token_hex(8))
        for name in VARIABLES
    }
    for name, value in values.items():
        monkeypatch.setenv(VARIABLES[name], str(value))
    return values


def _written(form: str) -> dict:
    return {name: FORMS[form].format(variable) for name, variable in VARIABLES.items()}


def _date_in(monkeypatch, first: int, last: int) -> _Canary:
    """A valid expiration date ``first`` to ``last`` days from today, drawn for
    the run and set as the date variable."""
    days = first + secrets.randbelow(last - first + 1)
    value = _Canary((date.today() + timedelta(days=days)).isoformat())
    monkeypatch.setenv(DATE_VARIABLE, str(value))
    return value


def _expiration(expiration: str) -> str:
    """``expiration`` as the config file writes it: a date quoted, so YAML keeps
    it text, and a reference as it is, since ``!ENV`` is a tag."""
    return expiration if "${" in expiration else f"'{expiration}'"


def _messages(tmp_path: Path, caplog, global_settings: str) -> list:
    source = tmp_path / "src"
    source.mkdir()
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        "project_name: demo\nglobal_settings:\n" + global_settings, encoding="utf-8"
    )
    output = tmp_path / "out"
    output.mkdir()
    context = PluginContext(
        source_dir=source, output_dir=output, config=resolve_config(config_file)
    )
    with caplog.at_level(logging.WARNING):
        handle_suppression_expiration_check(plugin_context=context)
    return [record.getMessage() for record in caplog.records]


def _suppression(written: dict, expiration: str) -> str:
    return (
        "  suppressions:\n"
        f"    - rule_id: {written['rule']}\n"
        f"      path: {written['path']}\n"
        f"      reason: {written['reason']}\n"
        f"      expiration: {_expiration(expiration)}\n"
    )


def _ignore_path(written: dict, expiration: str) -> str:
    return (
        "  ignore_paths:\n"
        f"    - path: {written['path']}\n"
        f"      reason: {written['reason']}\n"
        f"      expiration: {_expiration(expiration)}\n"
    )


def _redacted(texts, canaries: dict) -> list:
    """``texts`` for an assertion message, with each canary replaced."""
    shown = []
    for text in texts:
        text = str(text)
        for value in canaries.values():
            text = text.replace(value, "<canary>")
        shown.append(text)
    return shown


def _check(messages: list, canaries: dict, expected: str) -> None:
    held = [
        name
        for name, value in canaries.items()
        if any(value in message for message in messages)
    ]
    assert held == [], "the warning holds a value"
    named = any(expected in message for message in messages)
    assert named, _redacted([m for m in messages if " - " in m], canaries)


@pytest.mark.parametrize("form", list(FORMS))
def test_the_expired_suppression_warning_names_the_entry_by_its_references(
    tmp_path, caplog, canaries, form
) -> None:
    written = _written(form)

    messages = _messages(tmp_path, caplog, _suppression(written, PAST))

    _check(
        messages,
        canaries,
        f"  - Suppression of rule '{written['rule']}' for '{written['path']}' "
        f"expired on {PAST}. Reason: {written['reason']}",
    )


@pytest.mark.parametrize("form", list(FORMS))
def test_the_expiring_ignore_path_warning_names_the_entry_by_its_references(
    tmp_path, caplog, canaries, form
) -> None:
    written = _written(form)

    messages = _messages(tmp_path, caplog, _ignore_path(written, SOON))

    _check(
        messages,
        canaries,
        f"  - Ignore path '{written['path']}' expires on {SOON}. "
        f"Reason: {written['reason']}",
    )


@pytest.mark.parametrize("form", list(FORMS))
def test_the_expired_ignore_path_warning_names_the_entry_by_its_references(
    tmp_path, caplog, canaries, form
) -> None:
    written = _written(form)

    messages = _messages(tmp_path, caplog, _ignore_path(written, PAST))

    _check(
        messages,
        canaries,
        f"  - Ignore path '{written['path']}' expired on {PAST}. "
        f"Reason: {written['reason']}",
    )


#: For each warning: the days from today its entries are drawn from, the entry
#: as the config writes it, and the start of the warning's line for the entry,
#: which the date follows.
DATED = {
    "expired suppression": (
        (-400, -2),
        _suppression,
        lambda w: (
            f"  - Suppression of rule '{w['rule']}' for '{w['path']}' expired on "
        ),
    ),
    "expiring ignore path": (
        (2, 28),
        _ignore_path,
        lambda w: f"  - Ignore path '{w['path']}' expires on ",
    ),
    "expired ignore path": (
        (-400, -2),
        _ignore_path,
        lambda w: f"  - Ignore path '{w['path']}' expired on ",
    ),
}


@pytest.mark.parametrize("form", list(FORMS))
@pytest.mark.parametrize("warning", list(DATED))
def test_the_warning_names_a_date_read_from_the_environment_by_its_reference(
    tmp_path, caplog, monkeypatch, canaries, warning, form
) -> None:
    (first, last), entry, start = DATED[warning]
    when = _date_in(monkeypatch, first, last)
    written = _written(form)
    written_date = FORMS[form].format(DATE_VARIABLE)
    hidden = {**canaries, "date": when}

    messages = _messages(tmp_path, caplog, entry(written, written_date))

    listed = [
        line
        for message in messages
        for line in message.splitlines()
        if line.startswith(start(written))
    ]
    # The guard: the warning lists the entry, so the cell cannot pass by
    # leaving it out.
    assert listed, _redacted([m for m in messages if " - " in m], hidden)
    assert not any(when in message for message in messages), (
        "the warning holds the date's value"
    )
    named = any(line.startswith(start(written) + written_date) for line in listed)
    assert named, _redacted(listed, hidden)


def test_control_fields_written_as_text_are_named_as_they_are(tmp_path, caplog) -> None:
    text = {"rule": "B101", "path": "vendor/**", "reason": "test fixture only"}

    messages = _messages(
        tmp_path, caplog, _suppression(text, PAST) + _ignore_path(text, SOON)
    )

    joined = "\n".join(messages)
    assert (
        "  - Suppression of rule 'B101' for 'vendor/**' expired on "
        f"{PAST}. Reason: test fixture only"
    ) in joined
    assert (
        f"  - Ignore path 'vendor/**' expires on {SOON}. Reason: test fixture only"
    ) in joined
