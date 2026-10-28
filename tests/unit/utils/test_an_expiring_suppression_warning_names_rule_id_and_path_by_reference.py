# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The warning for a suppression that expires within 30 days names one whose
rule id and path the config read from the environment by their references.

The expiration check warns, at the start of a scan, about each suppression that
expires within 30 days, naming it by its rule id and path and quoting its
reason. A rule id or path the config file read from the environment
(``${VAR}``, or ``!ENV ${VAR}``) is named as the file wrote it, as the results
file's ``ash_config`` records it, and never as the value. Each cell sets the
variables to canaries made for the run, which no assertion prints, and checks
that the canaries are absent and the references are there. A rule id and path
the file wrote as text are named as they are. The reason is covered by
test_a_suppression_reason_read_from_the_environment_is_quoted_by_reference.py.

The date it expires on is named by its reference too. Its canary is a valid
date drawn for the run 2 to 28 days ahead, inside the 30 days the warning
lists, and the cell first checks that the warning lists the suppression, so it
cannot pass by leaving it out.
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

FORMS = {
    "plain": ("${ASH_GATE_RULE}", "${ASH_GATE_FILE}"),
    "tagged": ("!ENV ${ASH_GATE_RULE}", "!ENV ${ASH_GATE_FILE}"),
}
SOON = (date.today() + timedelta(days=5)).isoformat()


class _Canary(str):
    """The canary's text, shown as ``<canary>`` where pytest shows a test's
    arguments."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "'<canary>'"


@pytest.fixture
def canaries(monkeypatch) -> tuple:
    rule = _Canary("ash-canary-rule-" + secrets.token_hex(8))
    path = _Canary("ash-canary-file-" + secrets.token_hex(8))
    monkeypatch.setenv("ASH_GATE_RULE", str(rule))
    monkeypatch.setenv("ASH_GATE_FILE", str(path))
    return rule, path


def _messages(
    tmp_path: Path, caplog, rule_id: str, path: str, expiration: str = f"'{SOON}'"
) -> list:
    source = tmp_path / "src"
    source.mkdir()
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        "project_name: demo\nglobal_settings:\n  suppressions:\n"
        f"    - rule_id: {rule_id}\n      path: {path}\n      reason: kept\n"
        f"      expiration: {expiration}\n",
        encoding="utf-8",
    )
    output = tmp_path / "out"
    output.mkdir()
    context = PluginContext(
        source_dir=source, output_dir=output, config=resolve_config(config_file)
    )
    with caplog.at_level(logging.WARNING):
        handle_suppression_expiration_check(plugin_context=context)
    return [record.getMessage() for record in caplog.records]


def _redacted(texts, canaries) -> list:
    """``texts`` for an assertion message, with each canary replaced."""
    shown = []
    for text in texts:
        text = str(text)
        for canary in canaries:
            text = text.replace(canary, "<canary>")
        shown.append(text)
    return shown


@pytest.mark.parametrize("form", list(FORMS))
def test_the_warning_names_the_rule_id_and_path_by_their_references(
    tmp_path, caplog, canaries, form
) -> None:
    rule_id, path = FORMS[form]

    messages = _messages(tmp_path, caplog, rule_id, path)

    leaked = [
        name
        for name, canary in zip(("rule_id", "path"), canaries)
        if any(canary in message for message in messages)
    ]
    assert leaked == [], "the expiry warning holds a value"
    expected = f"  - Rule '{rule_id}' for '{path}' expires on {SOON}."
    named = any(message.startswith(expected) for message in messages)
    assert named, _redacted([m for m in messages if "expires on" in m], canaries)


@pytest.mark.parametrize(
    "form", ["${ASH_GATE_DATE}", "!ENV ${ASH_GATE_DATE}"], ids=["plain", "tagged"]
)
def test_the_warning_names_a_date_read_from_the_environment_by_its_reference(
    tmp_path, caplog, monkeypatch, form
) -> None:
    days = 2 + secrets.randbelow(27)
    when = _Canary((date.today() + timedelta(days=days)).isoformat())
    monkeypatch.setenv("ASH_GATE_DATE", str(when))

    messages = _messages(tmp_path, caplog, "B101", "app.py", expiration=form)

    start = "  - Rule 'B101' for 'app.py' expires on "
    listed = [message for message in messages if message.startswith(start)]
    # The guard: the warning lists the suppression, so the cell cannot pass by
    # leaving it out.
    assert listed, _redacted([m for m in messages if "expires on" in m], (when,))
    assert not any(when in message for message in messages), (
        "the expiry warning holds the date's value"
    )
    named = any(message.startswith(f"{start}{form}.") for message in listed)
    assert named, _redacted(listed, (when,))


def test_control_a_rule_id_and_path_written_as_text_are_named_as_they_are(
    tmp_path, caplog
) -> None:
    messages = _messages(tmp_path, caplog, "B101", "app.py")

    expected = f"  - Rule 'B101' for 'app.py' expires on {SOON}."
    assert any(message.startswith(expected) for message in messages)
