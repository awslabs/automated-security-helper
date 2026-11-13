# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Each suppression field the config read from the environment is shown by its
reference.

The unused-suppressions report (JSON and markdown) and the warning for a
suppression about to expire show a suppression's path, rule id, lines, reason,
expiration, package fields and symbol. Each one the config file read from the
environment (``${VAR}``, or ``!ENV ${VAR}``) is shown as the file wrote it, as the
results file's ``ash_config`` records it, and never as the value. Each cell reads
one field from a variable set to a canary made for the run, which no assertion
shows, and checks that the canary is absent and the reference is there. A canary
is a value its field accepts: a date within 30 days for the expiration, an
identifier for the symbol, and text for the rest. A line number is not read from
the environment: the config refuses a variable there as not an integer, and the
refusal does not quote the value. Fields written as text are shown as they are.
The reason is covered by
test_a_suppression_reason_read_from_the_environment_is_quoted_by_reference.py.
"""

from __future__ import annotations

import json
import logging
import secrets
import traceback
from datetime import date, timedelta
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.exceptions import ASHConfigValidationError
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.event_handlers.suppression_expiration_checker import (
    handle_suppression_expiration_check,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
    UnusedSuppressionsReporter,
)

pytestmark = pytest.mark.unit

REFERENCE = "${ASH_GATE_FIELD}"
#: The two spellings a config file reads the environment with; each is shown as
#: written, the tag included.
FORMS = {"plain": REFERENCE, "tagged": f"!ENV {REFERENCE}"}
#: Each field, how the markdown report shows it, and the fields written as text
#: beside it.
FIELDS = {
    "path": ("### 1. {}", {"rule_id": "B101"}),
    "rule_id": ("- **Rule ID**: `{}`", {"path": "app.py"}),
    "expiration": ("- **Expiration**: {}", {"path": "app.py"}),
    "package_name": ("- **Package**: `{}`", {"path": "app.py"}),
    "package_version": ("- **Package version**: `{}`", {"path": "app.py"}),
    "package_path": ("- **Package path**: `{}`", {"path": "app.py"}),
    "symbol": ("- **Symbol**: `{}`", {"path": "app.py"}),
}
#: The fields the expiry warning names.
WARNED = ("path", "rule_id", "expiration")
#: The line fields, and the fields written as text beside each.
LINES = {"line_start": {}, "line_end": {"line_start": "1"}}
#: The fields as text, for the control.
TEXT = {
    "path": "app.py",
    "rule_id": "B101",
    "line_start": 3,
    "line_end": 4,
    "reason": "text",
    "expiration": "2099-01-02",
    "package_name": "left-pad",
    "package_version": "1.3.0",
    "package_path": "node_modules/left-pad",
    "symbol": "Demo.run",
}


class _Canary(str):
    """The canary's text, shown as ``<canary>`` where pytest shows a test's
    arguments."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "'<canary>'"


def _canary(monkeypatch, field: str) -> _Canary:
    """Set ``ASH_GATE_FIELD`` to a canary made for the run that ``field`` accepts,
    or for a line, a number."""
    if field in LINES:
        text = str(10**11 + secrets.randbelow(9 * 10**11))
    elif field == "expiration":
        text = (date.today() + timedelta(days=2 + secrets.randbelow(27))).isoformat()
    elif field == "symbol":
        text = "ash_canary_" + secrets.token_hex(8)
    else:
        text = f"ash-canary-{field.replace('_', '-')}-" + secrets.token_hex(8)
    monkeypatch.setenv("ASH_GATE_FIELD", text)
    return _Canary(text)


def _redacted(texts, canary: str) -> list:
    """``texts`` for an assertion message, with the canary replaced."""
    return [str(text).replace(canary, "<canary>") for text in texts]


def _context(tmp_path: Path, entry: dict) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    lines = "".join(f"      {key}: {value}\n" for key, value in entry.items())
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        "project_name: demo\nglobal_settings:\n  suppressions:\n"
        f"    - {lines.lstrip()}",
        encoding="utf-8",
    )
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(
        source_dir=source, output_dir=output, config=resolve_config(config_file)
    )


def _entry(field: str, extra: dict | None = None, written: str = REFERENCE) -> dict:
    return {
        field: written,
        **FIELDS[field][1],
        "reason": "test fixture only",
        **(extra or {}),
    }


def _report(context: PluginContext) -> tuple:
    reporter = UnusedSuppressionsReporter(context=context)
    reporter.config.options.output_format = "both"
    written = reporter.report(AshAggregatedResults())
    markdown = (
        context.output_dir / "reports" / UnusedSuppressionsReporter.MARKDOWN_FILE_NAME
    ).read_text(encoding="utf-8")
    return written, markdown


@pytest.mark.parametrize("form", list(FORMS))
@pytest.mark.parametrize("field", list(FIELDS))
def test_the_unused_suppressions_report_shows_the_field_by_its_reference(
    tmp_path, monkeypatch, field, form
) -> None:
    reference = FORMS[form]
    canary = _canary(monkeypatch, field)
    context = _context(tmp_path, _entry(field, written=reference))
    # The control: the config holds the value.
    assert str(getattr(context.config.global_settings.suppressions[0], field)) == canary

    written, markdown = _report(context)

    leaked = canary in written or canary in markdown
    assert not leaked, "the field's value is in the unused-suppressions report"
    shown = [entry[field] for entry in json.loads(written)["unused_suppressions"]]
    assert shown == [reference], _redacted(shown, canary)
    assert FIELDS[field][0].format(reference) in markdown.splitlines(), _redacted(
        [line for line in markdown.splitlines() if line.startswith(("###", "- **"))],
        canary,
    )


@pytest.mark.parametrize("form", list(FORMS))
@pytest.mark.parametrize("field", WARNED)
def test_the_expiry_warning_shows_the_field_by_its_reference(
    tmp_path, monkeypatch, caplog, field, form
) -> None:
    reference = FORMS[form]
    canary = _canary(monkeypatch, field)
    soon = (date.today() + timedelta(days=5)).isoformat()
    extra = {} if field == "expiration" else {"expiration": f"'{soon}'"}
    context = _context(tmp_path, _entry(field, extra, written=reference))

    with caplog.at_level(logging.WARNING):
        handle_suppression_expiration_check(plugin_context=context)

    messages = [record.getMessage() for record in caplog.records]
    leaked = any(canary in message for message in messages)
    assert not leaked, "the field's value is in the expiry warning"
    assert any(reference in message for message in messages), _redacted(
        [m for m in messages if "expires on" in m], canary
    )


@pytest.mark.parametrize("field", list(LINES))
def test_a_line_read_from_the_environment_is_refused_without_its_value(
    tmp_path, monkeypatch, field
) -> None:
    canary = _canary(monkeypatch, field)
    entry = {field: REFERENCE, "path": "app.py", **LINES[field], "reason": "kept"}

    with pytest.raises(ASHConfigValidationError) as refused:
        _context(tmp_path, entry)

    message = str(refused.value)
    printed = "".join(traceback.format_exception(refused.value))
    assert canary not in printed, "the refusal or its cause quotes the value"
    # The entry's location, in either line's notation: pydantic's
    # (suppressions.0.line_start), or the config-path form
    # (suppressions[0].line_start).
    named = (
        f"suppressions.0.{field}" in message or f"suppressions[0].{field}" in message
    )
    assert named, message
    assert "valid integer" in message


def test_control_fields_written_as_text_are_shown_as_they_are(tmp_path) -> None:
    entry = {
        key: f"'{value}'" if key == "expiration" else value
        for key, value in TEXT.items()
    }
    context = _context(tmp_path, entry)

    written, markdown = _report(context)

    listed = json.loads(written)["unused_suppressions"][0]
    assert {key: listed[key] for key in TEXT} == TEXT
    lines = markdown.splitlines()
    assert "### 1. app.py" in lines
    assert "- **Rule ID**: `B101`" in lines
    assert "- **Lines**: 3-4" in lines
    assert "- **Expiration**: 2099-01-02" in lines
    assert "- **Package**: `left-pad`" in lines
    assert "- **Package version**: `1.3.0`" in lines
    assert "- **Package path**: `node_modules/left-pad`" in lines
    assert "- **Symbol**: `Demo.run`" in lines
