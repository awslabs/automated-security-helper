# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression reason the config read from the environment is quoted by its
reference.

A suppression's reason is quoted in its SARIF justification, which the results
file and every finding-level report carry, in the unused-suppressions report,
and in the warning for a suppression about to expire. A reason the config file
read from the environment (``${VAR}``, or ``!ENV ${VAR}``) is quoted as the file
wrote it, as the results file's ``ash_config`` records it, and never as the
value. Each cell sets the variable to a canary made for the run, which no
assertion prints, and checks that the canary is absent and the reference is
there. A reason the file wrote as text is quoted as it is.
"""

from __future__ import annotations

import json
import logging
import secrets
from datetime import date, timedelta
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_builtin.event_handlers.suppression_expiration_checker import (
    handle_suppression_expiration_check,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.unused_suppressions_reporter import (
    UnusedSuppressionsReporter,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

pytestmark = pytest.mark.unit

FORMS = ["${ASH_GATE_REASON}", "!ENV ${ASH_GATE_REASON}"]


class _Canary(str):
    """The canary's text, shown as ``<canary>`` where pytest shows a test's
    arguments."""

    __slots__ = ()

    def __repr__(self) -> str:
        return "'<canary>'"


@pytest.fixture
def canary(monkeypatch) -> str:
    value = _Canary("ash-canary-reason-" + secrets.token_hex(8))
    monkeypatch.setenv("ASH_GATE_REASON", str(value))
    return value


def _context(tmp_path: Path, reason: str, extra: str = "") -> PluginContext:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    config_file = tmp_path / ".ash.yaml"
    config_file.write_text(
        "project_name: demo\nglobal_settings:\n  suppressions:\n"
        f"    - rule_id: B101\n      path: app.py\n      reason: {reason}\n{extra}",
        encoding="utf-8",
    )
    output = tmp_path / "out"
    output.mkdir()
    return PluginContext(
        source_dir=source, output_dir=output, config=resolve_config(config_file)
    )


def _report() -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "bandit"}},
                    "results": [
                        {
                            "ruleId": "B101",
                            "message": {"text": "assert used"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "app.py"},
                                        "region": {"startLine": 1, "endLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )


def _redacted(texts, canary: str) -> list:
    """``texts`` for an assertion message, with the canary replaced."""
    return [str(text).replace(canary, "<canary>") for text in texts]


def _justifications(report: SarifReport) -> list:
    return [
        suppression.justification
        for result in report.runs[0].results or []
        for suppression in result.suppressions or []
    ]


@pytest.mark.parametrize("form", FORMS)
def test_the_justification_quotes_the_reason_by_its_reference(
    tmp_path, canary, form
) -> None:
    context = _context(tmp_path, form)
    # The control: the config holds the value.
    assert context.config.global_settings.suppressions[0].reason == canary

    suppressed = apply_suppressions_to_sarif(_report(), context)

    justifications = _justifications(suppressed)
    assert len(justifications) == 1, len(justifications)
    leaked = canary in suppressed.model_dump_json(by_alias=True)
    assert not leaked, "the reason's value is in the SARIF"
    assert justifications[0].endswith(f"with reason: {form}"), _redacted(
        justifications, canary
    )


def test_control_a_reason_written_as_text_is_quoted_as_it_is(tmp_path) -> None:
    context = _context(tmp_path, "test fixture only")

    suppressed = apply_suppressions_to_sarif(_report(), context)

    assert _justifications(suppressed)[0].endswith("with reason: test fixture only")


@pytest.mark.parametrize("form", FORMS)
def test_the_unused_suppressions_report_quotes_the_reason_by_its_reference(
    tmp_path, canary, form
) -> None:
    context = _context(tmp_path, form)
    reporter = UnusedSuppressionsReporter(context=context)
    reporter.config.options.output_format = "both"

    written = reporter.report(AshAggregatedResults())

    markdown = (
        context.output_dir / "reports" / UnusedSuppressionsReporter.MARKDOWN_FILE_NAME
    ).read_text(encoding="utf-8")
    leaked = canary in written or canary in markdown
    assert not leaked, "the reason's value is in the unused-suppressions report"
    reasons = [entry["reason"] for entry in json.loads(written)["unused_suppressions"]]
    assert reasons == [form], _redacted(reasons, canary)
    assert f"- **Reason**: {form}" in markdown


@pytest.mark.parametrize("form", FORMS)
def test_the_expiry_warning_quotes_the_reason_by_its_reference(
    tmp_path, canary, form, caplog
) -> None:
    soon = (date.today() + timedelta(days=5)).isoformat()
    context = _context(tmp_path, form, extra=f"      expiration: '{soon}'\n")

    with caplog.at_level(logging.WARNING):
        handle_suppression_expiration_check(plugin_context=context)

    messages = [record.getMessage() for record in caplog.records]
    leaked = any(canary in message for message in messages)
    assert not leaked, "the reason's value is in the expiry warning"
    assert any(message.endswith(f"Reason: {form}") for message in messages), _redacted(
        [m for m in messages if "expires on" in m], canary
    )
