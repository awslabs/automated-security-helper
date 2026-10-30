# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What npm-audit writes to ash.log about an audit's response.

The whole runner response (stdout, stderr and error text) of every npm, yarn
and pnpm audit was logged at INFO as it came back. The runner returns that
text unredacted for the caller to redact, and every other excerpt the scanner
prints goes through the env-value redaction first, so a token the tool echoed
on stderr reached the log as it was, and the report on stdout was logged twice
(it is written beside the results). The log line is now one redacted summary.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    npm_audit_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.npm_audit_reports import NPM_CLEAN

pytestmark = pytest.mark.unit

STDOUT_MARKER = "stdout-marker-4d1f"
TOKEN = "Zq7Kx9Lm2Pw4Nv"


class _Messages(logging.Handler):
    """What a file handler writes: the message, not Rich's rendering of it."""

    def __init__(self):
        super().__init__(level=logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    def emit(self, record):
        self.records.append(record)


@pytest.fixture
def messages():
    handler = _Messages()
    saved = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        yield handler
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(saved)


@pytest.fixture
def context(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for d in (context.source_dir, context.output_dir, context.work_dir):
        d.mkdir(parents=True)
    monkeypatch.setattr(
        npm_audit_scanner, "find_executable", lambda name: str(tmp_path / name)
    )
    return context


def _package(root: Path) -> None:
    root.mkdir(parents=True, exist_ok=True)
    (root / "package.json").write_text('{"name": "app"}\n', encoding="utf-8")
    (root / "package-lock.json").write_text("{}\n", encoding="utf-8")


def _scan(context, stdout: str, stderr: str):
    scanner = NpmAuditScanner(context=context, config=NpmAuditScannerConfig())
    _package(context.work_dir)

    def respond(self, command, **kwargs):
        if "--version" in command:
            return {"stdout": "10.9.4\n", "stderr": "", "returncode": 0}
        response = {"stdout": stdout, "stderr": stderr, "returncode": 0}
        self._process_command_response(response)
        return response

    with (
        patch.object(
            NpmAuditScanner, "_run_subprocess", autospec=True, side_effect=respond
        ),
        patch.object(NpmAuditScanner, "_values_to_redact", return_value=(TOKEN,)),
    ):
        scanner.scan(target=context.work_dir, target_type="converted")
    return scanner


def test_the_raw_response_is_not_logged(context, messages):
    """A report whose stdout holds a marker, with an env-read value on stderr:
    neither reaches any log record."""
    report = json.loads(NPM_CLEAN)
    report["marker"] = STDOUT_MARKER
    stderr = (
        f"npm WARN registry at https://user:{TOKEN}@registry.example/ answered slowly\n"
    )

    _scan(context, json.dumps(report), stderr)

    texts = [record.getMessage() for record in messages.records]
    assert not any(STDOUT_MARKER in text for text in texts), texts
    assert not any(TOKEN in text for text in texts), texts
    assert not any("registry.example" in text and "user:" in text for text in texts)
    # The audit ran and was summarized exactly once (the absences above would
    # also hold for a scan that never ran), and the summary's excerpt shows
    # the registry URL with its credentials masked, not an excerpt cut short
    # of them.
    summaries = [text for text in texts if "npm audit responded" in text]
    assert len(summaries) == 1, texts
    assert (
        "stderr starts: npm WARN registry at https://***@registry.example/"
        in (summaries[0])
    ), summaries[0]


def test_the_summary_masks_a_registry_urls_credentials():
    """The contract the test above rests on: a registry URL's userinfo on the
    first stderr line is masked whole, the user part included, although the
    user part is not one of the env-read values. The 200-character excerpt cap
    plays no part: the line is short."""
    summary = NpmAuditScanner._response_summary(
        "npm",
        {
            "stdout": "",
            "stderr": f"npm WARN https://user:{TOKEN}@registry.example/ answered slowly\n",
            "returncode": 0,
        },
        (),
    )

    assert "stderr starts: npm WARN https://***@registry.example/ answered" in summary
    assert "user:" not in summary
    assert TOKEN not in summary


def test_an_audit_errors_reason_masks_a_registry_urls_credentials():
    """npm quotes the registry URL in the error document's message, and the
    reason went into the failure record with only the env-read values
    redacted, so the URL's user part stayed in the report. The userinfo is
    masked whole, as the debug summary's excerpt already was."""
    reason = NpmAuditScanner._audit_failure(
        "npm",
        {"returncode": 1},
        {
            "message": f"request to https://user:{TOKEN}@registry.example/ failed",
            "error": {"code": "E503", "summary": "the registry answered 503"},
        },
        (TOKEN,),
    )

    assert reason is not None
    assert "https://***@registry.example/" in reason
    assert "user:" not in reason
    assert TOKEN not in reason
    assert "E503" in reason


@pytest.mark.parametrize(
    "text",
    [
        pytest.param(
            '{"type":"error","data":"Error: request to '
            f'https://user:{TOKEN}@registry.example/ failed"}}\n',
            id="a yarn 1 error event",
        ),
        pytest.param(
            f"Error: request to https://user:{TOKEN}@registry.example/ failed\n"
            "    at fetch (/node_modules/yarn/lib/cli.js:1:2)\n",
            id="a plain error line",
        ),
    ],
)
def test_the_yarn_error_detail_masks_a_registry_urls_credentials(text):
    """Both arms of the detail (an error event's data, a plain error line)
    print the tool's text into the failure record; the URL's userinfo is
    masked whole on each."""
    detail = NpmAuditScanner._yarn_error_detail(text, (TOKEN,))

    assert "https://***@registry.example/" in detail
    assert "user:" not in detail
    assert TOKEN not in detail


def test_the_response_is_summarized_redacted_at_debug(context, messages):
    stderr = f"npm WARN token {TOKEN} rejected\nsecond line\n"

    _scan(context, NPM_CLEAN, stderr)

    summaries = [
        record
        for record in messages.records
        if "npm audit responded" in record.getMessage()
    ]
    assert len(summaries) == 1, [r.getMessage() for r in messages.records]
    (record,) = summaries
    assert record.levelno == logging.DEBUG
    text = record.getMessage()
    assert "exit 0" in text
    assert f"stdout {len(NPM_CLEAN)} chars" in text
    assert f"stderr {len(stderr)} chars" in text
    assert "stderr starts: npm WARN token" in text
    assert TOKEN not in text
    assert "second line" not in text


def test_the_summary_unit():
    """The error text is not part of the summary at all: a token in it (the
    runner quotes the failing command, credentials included) is never on the
    line, and the second stderr line is not either."""
    summary = NpmAuditScanner._response_summary(
        "pnpm",
        {
            "stdout": "",
            "stderr": f"ERR_PNPM_AUDIT_BAD_RESPONSE {TOKEN}\nsecond-line-marker-9b2e",
            "returncode": 1,
            "timed_out": True,
            "error": f"the command was stopped: pnpm --token {TOKEN}",
        },
        (TOKEN,),
    )

    assert summary.startswith("pnpm audit responded: exit 1; stdout 0 chars; ")
    assert "timed_out" in summary
    assert "post_run_error" not in summary
    assert "stderr starts: ERR_PNPM_AUDIT_BAD_RESPONSE" in summary
    assert TOKEN not in summary
    assert "the command was stopped" not in summary
    assert "second-line-marker-9b2e" not in summary


def test_the_summary_drops_the_excerpt_when_the_values_hook_raised():
    """``values`` None means the hook raised: the excerpt cannot be redacted, so
    it is dropped rather than printed against an empty value set."""
    summary = NpmAuditScanner._response_summary(
        "yarn", {"stdout": "x", "stderr": f"Error: {TOKEN}", "returncode": 1}, None
    )

    assert summary == "yarn audit responded: exit 1; stdout 1 chars; stderr 21 chars"
