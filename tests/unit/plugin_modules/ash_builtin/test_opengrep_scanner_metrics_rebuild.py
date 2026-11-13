# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Opengrep's one-time ``--metrics`` decision survives the per-target argument resolution.

Construction builds the arguments without ``--metrics`` and leaves the decision for
the first scan. The decision used to be made inside ``_resolve_arguments``, which the
base's ``_resolve_scan_arguments`` calls between saving ``extra_args`` and restoring
the saved list: the rebuild inside it was thrown away, so every later target lost
``--metrics``, and the rebuilt list replaced the output-directory excludes the base
had just added, so the first target's command lost those. The decision now runs
before the base saves the list.

No opengrep runs here: the version answer is stood in for, and only the arguments
are read.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
    OpengrepScanner,
    OpengrepScannerConfig,
    OpengrepScannerConfigOptions,
)

pytestmark = pytest.mark.unit


def _context(tmp_path: Path) -> PluginContext:
    source = tmp_path / "repo"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    output = source / ".ash" / "ash_output"
    output.mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )


def _old_opengrep(
    context, monkeypatch, decisions: list | None = None
) -> OpengrepScanner:
    """An online scanner against an opengrep older than 1.7.0, which takes --metrics.

    ``decisions`` records each call of the version-gated decision, so a test can
    assert it is made once.
    """
    monkeypatch.delenv("OPENGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.setattr(OpengrepScanner, "_scanner_offline", lambda self: False)
    recorded = decisions if decisions is not None else []

    def decide(self) -> bool:
        recorded.append(True)
        return True

    monkeypatch.setattr(OpengrepScanner, "_should_use_metrics_flag", decide)
    return OpengrepScanner(
        context=context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=False, metrics="auto")
        ),
    )


def _exclude_values(command: list[str]) -> list[str]:
    """Every ``--exclude`` value of the command, in the split form (``--exclude
    <value>``) and in the joined form (``--exclude=<value>``) alike, so a move of
    one set of excludes between the two spellings does not read as their loss."""
    values = [
        command[index + 1]
        for index, word in enumerate(command[:-1])
        if word == "--exclude"
    ]
    values.extend(
        word[len("--exclude=") :] for word in command if word.startswith("--exclude=")
    )
    return values


def test_metrics_is_on_every_targets_command(tmp_path, monkeypatch):
    """Fails at the base: the first resolution carried --metrics and the saved,
    metrics-less list was restored after it, so the second did not.

    The decision is one-time: made once across both resolutions (a version probe
    and a cache re-check per target would be two), and ``--metrics`` appears once
    per command and once in the configured arguments (appended once, not per
    resolution).
    """
    context = _context(tmp_path)
    decisions: list = []
    scanner = _old_opengrep(context, monkeypatch, decisions)
    results = Path(scanner.results_dir) / "source" / "results_sarif.sarif"

    first = scanner._resolve_scan_arguments(context.source_dir, results)
    second = scanner._resolve_scan_arguments(context.source_dir, results)

    assert first.count("--metrics") == 1, first
    assert second.count("--metrics") == 1, second
    assert len(decisions) == 1, decisions
    assert [arg.key for arg in scanner.args.extra_args].count("--metrics") == 1


def test_the_first_command_keeps_the_output_directory_excludes(tmp_path, monkeypatch):
    """Fails at the base: the rebuild replaced the list the base had just added
    the output-directory excludes to, so the first command had none."""
    context = _context(tmp_path)
    scanner = _old_opengrep(context, monkeypatch)
    results = Path(scanner.results_dir) / "source" / "results_sarif.sarif"

    first = scanner._resolve_scan_arguments(context.source_dir, results)
    second = scanner._resolve_scan_arguments(context.source_dir, results)

    assert any("ash_output" in value for value in _exclude_values(first)), first
    assert any("ash_output" in value for value in _exclude_values(second)), second


def test_a_current_opengrep_takes_no_metrics_on_any_command(tmp_path, monkeypatch):
    """The control: 1.7.0 and later get no --metrics, first command or later."""
    context = _context(tmp_path)
    monkeypatch.delenv("OPENGREP_RULES_CACHE_DIR", raising=False)
    monkeypatch.setattr(OpengrepScanner, "_scanner_offline", lambda self: False)
    monkeypatch.setattr(OpengrepScanner, "_should_use_metrics_flag", lambda self: False)
    scanner = OpengrepScanner(
        context=context,
        config=OpengrepScannerConfig(
            options=OpengrepScannerConfigOptions(offline=False)
        ),
    )
    results = Path(scanner.results_dir) / "source" / "results_sarif.sarif"

    first = scanner._resolve_scan_arguments(context.source_dir, results)
    second = scanner._resolve_scan_arguments(context.source_dir, results)

    assert "--metrics" not in first
    assert "--metrics" not in second
