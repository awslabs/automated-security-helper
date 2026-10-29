# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An unused suppression whose rule id and path the config read from the
environment is listed by their references.

The unused-suppressions report lists each suppression that matched nothing,
in JSON and in markdown, with its path, rule id and reason. A rule id or a path
the config file read from the environment (``${VAR}``, or ``!ENV ${VAR}``) is
listed as the file wrote it, as the results file's ``ash_config`` records it,
and never as the value. Each cell sets the variables to canaries made for the
run, which no assertion prints, and checks that the canaries are absent and the
references are there. A rule id and a path the file wrote as text are listed as
they are. The reason is covered by
test_a_suppression_reason_read_from_the_environment_is_quoted_by_reference.py.
"""

from __future__ import annotations

import json
import secrets
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
    UnusedSuppressionsReporter,
)

pytestmark = pytest.mark.unit

FORMS = {
    "plain": ("${ASH_GATE_RULE}", "${ASH_GATE_FILE}"),
    "tagged": ("!ENV ${ASH_GATE_RULE}", "!ENV ${ASH_GATE_FILE}"),
}
MARKDOWN = "ash.unused-suppressions.md"


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


def _context(tmp_path: Path, rule_id: str, path: str) -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        "project_name: demo\nglobal_settings:\n  suppressions:\n"
        f"    - rule_id: {rule_id}\n      path: {path}\n      reason: unused\n",
        encoding="utf-8",
    )
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(
        source_dir=source, output_dir=output, config=resolve_config(config_file)
    )


def _report(context: PluginContext) -> tuple:
    reporter = UnusedSuppressionsReporter(context=context)
    reporter.config.options.output_format = "both"
    written = reporter.report(AshAggregatedResults())
    markdown = (context.output_dir / "reports" / MARKDOWN).read_text(encoding="utf-8")
    return written, markdown


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
def test_the_json_lists_the_rule_id_and_path_by_their_references(
    tmp_path, canaries, form
) -> None:
    rule_id, path = FORMS[form]
    context = _context(tmp_path, rule_id, path)
    # The control: the config holds the values.
    entry = context.config.global_settings.suppressions[0]
    assert (entry.rule_id, entry.path) == canaries

    written, _ = _report(context)

    leaked = [
        name for name, canary in zip(("rule_id", "path"), canaries) if canary in written
    ]
    assert leaked == [], "the unused-suppressions JSON holds a value"
    listed = json.loads(written)["unused_suppressions"]
    shown = [(item["rule_id"], item["path"]) for item in listed]
    assert shown == [(rule_id, path)], _redacted(shown, canaries)


@pytest.mark.parametrize("form", list(FORMS))
def test_the_markdown_lists_the_rule_id_and_path_by_their_references(
    tmp_path, canaries, form
) -> None:
    rule_id, path = FORMS[form]
    context = _context(tmp_path, rule_id, path)

    _, markdown = _report(context)

    leaked = [
        name
        for name, canary in zip(("rule_id", "path"), canaries)
        if canary in markdown
    ]
    assert leaked == [], "the unused-suppressions markdown holds a value"
    lines = markdown.splitlines()
    named = {
        "heading": f"### 1. {path}" in lines,
        "rule id": f"- **Rule ID**: `{rule_id}`" in lines,
    }
    assert [line for line, ok in named.items() if not ok] == [], _redacted(
        [line for line in lines if line.startswith(("###", "- **Rule ID**"))], canaries
    )


def test_control_a_rule_id_and_path_written_as_text_are_listed_as_they_are(
    tmp_path,
) -> None:
    context = _context(tmp_path, "B101", "app.py")

    written, markdown = _report(context)

    listed = json.loads(written)["unused_suppressions"]
    assert [(item["rule_id"], item["path"]) for item in listed] == [("B101", "app.py")]
    assert "### 1. app.py" in markdown.splitlines()
    assert "- **Rule ID**: `B101`" in markdown.splitlines()
