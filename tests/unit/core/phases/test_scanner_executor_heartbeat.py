# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A running scanner has to be visible, and a killed one has to be named (#628).

Scanner subprocesses run buffered, so before this a scanner that hung until the
CI job was killed left no line naming it at any log level. The executor now
logs a heartbeat at INFO while each scanner runs, and when a scanner that
overrides ``scan()`` fails after its tool was killed at the timeout, the
executor reports the timeout rather than the missing-file error it caused.
"""

import sys
import time
from unittest.mock import MagicMock, patch

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.core.phases import scanner_executor
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class _Config(ScannerPluginConfigBase):
    name: str = "slowpoke"


class _SleepingScanner(ScannerPluginBase):
    """Overrides scan(), as syft, trivy, ferret and snyk do."""

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self, target, target_type=None, global_ignore_paths=None, config=None, *a, **k
    ):
        self._run_subprocess(
            command=[
                sys.executable,
                "-c",
                f"import time; time.sleep({self.sleep_for})",
            ],
            results_dir=self.results_dir,
            timeout=self.tool_timeout,
        )
        if self.fail_after:
            # What the overriding scanners do next: read the results file the
            # killed tool never wrote.
            raise ScannerError(
                "Slowpoke scan failed: [Errno 2] No such file or directory: 'out.sarif'"
            )
        return {"severity_counts": {}}


def _context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("print('x')\n")
    output = tmp_path / "output"
    output.mkdir()
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=tmp_path / "work",
        config=AshConfig(project_name="test"),
    )


def _scanner(context, sleep_for, tool_timeout=None, fail_after=False):
    scanner = _SleepingScanner(config=_Config(), context=context)
    scanner.sleep_for = sleep_for
    scanner.tool_timeout = tool_timeout
    scanner.fail_after = fail_after
    return scanner


def _run(context, scanner):
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    return executor._execute_scanner(
        "slowpoke", scanner, [{"path": context.source_dir, "type": "source"}]
    )


def _heartbeats(logger):
    return [
        call.args[0]
        for call in logger.info.call_args_list
        if "still running" in str(call.args[0])
    ]


class TestHeartbeat:
    def test_a_running_scanner_is_announced_at_info(self, tmp_path):
        context = _context(tmp_path)
        logger = MagicMock()
        with (
            patch.object(scanner_executor, "SCANNER_HEARTBEAT_INTERVAL_SECONDS", 0.1),
            patch.object(scanner_executor, "ASH_LOGGER", logger),
        ):
            _run(context, _scanner(context, sleep_for=1.0))

        beats = _heartbeats(logger)
        assert beats, "no heartbeat was logged while the scanner ran"
        assert beats[0].startswith("slowpoke still running on source (")
        assert beats[0].endswith("s elapsed)")

    def test_the_heartbeat_stops_when_the_scanner_returns(self, tmp_path):
        context = _context(tmp_path)
        logger = MagicMock()
        with (
            patch.object(scanner_executor, "SCANNER_HEARTBEAT_INTERVAL_SECONDS", 0.1),
            patch.object(scanner_executor, "ASH_LOGGER", logger),
        ):
            _run(context, _scanner(context, sleep_for=0.5))
            after_return = len(_heartbeats(logger))
            time.sleep(0.5)

        assert len(_heartbeats(logger)) == after_return

    def test_the_heartbeat_stops_when_the_scanner_raises(self, tmp_path):
        context = _context(tmp_path)
        logger = MagicMock()
        with (
            patch.object(scanner_executor, "SCANNER_HEARTBEAT_INTERVAL_SECONDS", 0.1),
            patch.object(scanner_executor, "ASH_LOGGER", logger),
        ):
            _run(context, _scanner(context, sleep_for=0.3, fail_after=True))
            after_return = len(_heartbeats(logger))
            time.sleep(0.5)

        assert len(_heartbeats(logger)) == after_return

    def test_a_fast_scanner_logs_no_heartbeat_at_the_default_interval(self, tmp_path):
        context = _context(tmp_path)
        logger = MagicMock()
        with patch.object(scanner_executor, "ASH_LOGGER", logger):
            _run(context, _scanner(context, sleep_for=0))

        assert _heartbeats(logger) == []


class TestTimeoutIsNamedForOverridingScanners:
    def test_the_error_leads_with_the_timeout(self, tmp_path):
        context = _context(tmp_path)
        scanner = _scanner(context, sleep_for=30, tool_timeout=1, fail_after=True)

        started = time.monotonic()
        (container,) = _run(context, scanner)
        assert time.monotonic() - started < 20, "the tool was not killed at its timeout"

        assert container.status == ScannerStatus.ERROR
        first = container.raw_results["errors"][0]
        assert first.startswith("slowpoke timed out after 1.0s on source"), first
        # The original error is kept after it, not replaced.
        assert "No such file or directory" in first

    def test_a_timeout_on_one_target_is_not_charged_to_the_next(self, tmp_path):
        context = _context(tmp_path)
        scanner = _scanner(context, sleep_for=30, tool_timeout=1, fail_after=True)
        _run(context, scanner)
        assert scanner.scan_timed_out_after == 1.0

        scanner.sleep_for = 0
        (container,) = _run(context, scanner)

        assert scanner.scan_timed_out_after is None
        assert not any(
            "timed out" in line for line in container.raw_results["errors"][:1]
        )
