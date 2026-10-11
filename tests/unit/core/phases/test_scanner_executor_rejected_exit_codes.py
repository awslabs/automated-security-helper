"""A tool that exits with a code its scanner does not accept is recorded as ERROR.

``success_exit_codes`` names the codes a scanner's tool uses for a run that completed:
0, and the code some tools use for "completed, with findings". Any other code is the
tool saying it failed -- semgrep exits 7 when it cannot read a rule configuration, and
grype exits 1 when it cannot load its database. A failed tool can still leave a results
file behind: semgrep writes SARIF that holds only error notifications, grype a zero-byte
report. What that file holds must not decide the verdict, because "the tool found
nothing" and "the tool never scanned" look the same in it.

So the scanner's row is ERROR whenever the exit code is outside the set, whatever the
results file holds, and the exit code is kept on the row. The tool here is a real
process that copies a prepared results file into place and exits with a chosen code, so
the code reaches the scanner by the same route a scanner binary's does.

The controls run the same tool with an accepted code and must keep grading on findings:
PASSED with none, FAILED with one above the threshold.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import ClassVar, Literal
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import (
    OfflineStrategy,
    ScannerStatus,
    ScannerToolType,
)
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.subprocess_utils import SPAWN_FAILURE_RETURNCODE

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

SCANNER_NAME = "exit-code-tool"

# Copies argv[1] to argv[2] unless argv[1] is "-", then exits with argv[3].
TOOL_SOURCE = (
    "import shutil, sys\n"
    "source, destination, code = sys.argv[1:4]\n"
    "if source != '-':\n"
    "    shutil.copyfile(source, destination)\n"
    "sys.exit(int(code))\n"
)


def _sarif(results: list, notifications: list | None = None) -> dict:
    invocation = {"executionSuccessful": True}
    if notifications:
        invocation["toolExecutionNotifications"] = [
            {"level": "error", "message": {"text": text}} for text in notifications
        ]
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "exit-code-tool", "rules": []}},
                "results": results,
                "invocations": [invocation],
            }
        ],
    }


A_FINDING = {
    "ruleId": "tool-rule",
    "level": "error",
    "message": {"text": "a finding"},
    "locations": [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": "app.py"},
                "region": {"startLine": 2},
            }
        }
    ],
}

#: What a failed tool can leave behind, by name. "absent" writes nothing.
RESULTS_FILES = {
    # semgrep's output when it cannot read its rule configuration (measured: exit 7).
    "sarif holding only error notifications": json.dumps(
        _sarif(
            [],
            [
                "unable to find a config; path `/rules` does not exist",
                "invalid configuration file found (1 configs were invalid)",
            ],
        )
    ),
    "sarif with a finding": json.dumps(_sarif([A_FINDING])),
    # grype's output when it cannot load its database (measured: exit 1).
    "zero-byte file": "",
    "json that is not sarif": json.dumps({"errors": ["database does not exist"]}),
}


class _ToolConfig(ScannerPluginConfigBase):
    name: Literal["exit-code-tool"] = SCANNER_NAME


def _scanner_class(success_codes: set):
    class ExitCodeToolScanner(ScannerPluginBase):
        offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
        success_exit_codes: ClassVar[set] = set(success_codes)

        def model_post_init(self, context):
            self.command = "exit-code-tool"
            self.tool_type = ScannerToolType.SAST
            super().model_post_init(context)

        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            results_dir = self.results_dir / target_type
            results_dir.mkdir(parents=True, exist_ok=True)
            results_file = results_dir / "results.sarif"
            command = [
                sys.executable,
                "-c",
                TOOL_SOURCE,
                self.prepared_results,
                str(results_file),
                str(self.tool_exit_code),
            ]
            return command, results_file, None

    return ExitCodeToolScanner


@pytest.fixture
def plugin_context(tmp_path):
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("total = 1 + 1\nprint(total)\n")
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    work_dir = output_dir / ASH_WORK_DIR_NAME
    work_dir.mkdir()
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="test"),
    )


def _run(plugin_context, tmp_path, *, success_codes, exit_code, results):
    """One target through ScannerExecutor; returns the scanner's row."""
    prepared = "-"
    if results is not None:
        prepared_file = tmp_path / "prepared-results"
        prepared_file.write_text(results, encoding="utf-8")
        prepared = str(prepared_file)
    config = _ToolConfig()
    config.options.severity_threshold = "MEDIUM"
    scanner = _scanner_class(success_codes)(config=config, context=plugin_context)
    scanner.prepared_results = prepared
    scanner.tool_exit_code = exit_code
    executor = ScannerExecutor(
        plugin_context=plugin_context,
        progress_display=MagicMock(),
        scanner_tasks=[],
    )
    (container,) = executor._execute_scanner(
        SCANNER_NAME,
        scanner,
        [{"path": plugin_context.source_dir, "type": "source"}],
    )
    return container


def _names_the_code(errors, code) -> bool:
    return any(re.search(rf"\b{code}\b", str(error)) for error in errors)


class TestARejectedExitCodeIsAnError:
    @pytest.mark.parametrize("results", sorted(RESULTS_FILES))
    @pytest.mark.parametrize(
        "success_codes, exit_code",
        [
            pytest.param({0, 1}, 7, id="semgrep-shaped-set-exit-7"),
            pytest.param({0, 1}, 2, id="semgrep-shaped-set-exit-2"),
            pytest.param({0, 2}, 1, id="grype-shaped-set-exit-1"),
        ],
    )
    def test_the_row_is_error_whatever_the_results_file_holds(
        self, plugin_context, tmp_path, success_codes, exit_code, results
    ):
        container = _run(
            plugin_context,
            tmp_path,
            success_codes=success_codes,
            exit_code=exit_code,
            results=RESULTS_FILES[results],
        )

        assert container.status == ScannerStatus.ERROR, (
            f"the tool exited {exit_code}, outside success_exit_codes="
            f"{sorted(success_codes)}, and left {results!r}; the row was graded "
            f"{container.status.value} with {container.finding_count} findings"
        )
        assert container.exit_code == exit_code
        assert _names_the_code(container.errors, exit_code), (
            "the ERROR row says why: its errors name the exit code; got "
            f"{container.errors!r}"
        )

    def test_a_tool_that_wrote_no_results_file_is_an_error(
        self, plugin_context, tmp_path
    ):
        """Control: with no file to read, the run already fails, and must stay ERROR."""
        container = _run(
            plugin_context,
            tmp_path,
            success_codes={0, 1},
            exit_code=7,
            results=None,
        )

        assert container.status == ScannerStatus.ERROR


class TestAnAcceptedExitCodeIsGradedOnFindings:
    """Controls: the same tool and harness, with codes the scanner accepts."""

    @pytest.mark.parametrize(
        "success_codes, exit_code",
        [
            pytest.param({0, 1}, 0, id="exit-0"),
            pytest.param({0, 1}, 1, id="findings-code-1"),
            pytest.param({0, 2}, 2, id="findings-code-2"),
        ],
    )
    def test_no_findings_is_passed(
        self, plugin_context, tmp_path, success_codes, exit_code
    ):
        container = _run(
            plugin_context,
            tmp_path,
            success_codes=success_codes,
            exit_code=exit_code,
            results=json.dumps(_sarif([])),
        )

        assert container.status == ScannerStatus.PASSED
        assert container.exit_code == exit_code

    def test_a_finding_above_the_threshold_is_failed(self, plugin_context, tmp_path):
        container = _run(
            plugin_context,
            tmp_path,
            success_codes={0, 1},
            exit_code=1,
            results=json.dumps(_sarif([A_FINDING])),
        )

        assert container.status == ScannerStatus.FAILED
        assert container.finding_count == 1


#: Copies argv[1] to argv[2], then kills itself with signal argv[3].
SIGNAL_TOOL_SOURCE = (
    "import os, shutil, signal, sys\n"
    "source, destination, signum = sys.argv[1:4]\n"
    "shutil.copyfile(source, destination)\n"
    "signal.signal(int(signum), signal.SIG_DFL)\n"
    "os.kill(os.getpid(), int(signum))\n"
)


class TestAToolKilledByASignalIsAnError:
    """A tool a signal ended has not completed, whatever number the signal has.

    Python reports such a child as ``-N``. Taking the absolute value put signals 1,
    2 and 3 inside common success sets: a tool killed by SIGHUP read as exit 1,
    "findings found", for a ``{0, 1}`` scanner. It is recorded the way a shell
    reports it, ``128 + N``, which no scanner accepts.
    """

    @pytest.mark.parametrize(
        "success_codes, signum",
        [
            pytest.param({0, 1}, 1, id="SIGHUP-against-0-1"),
            pytest.param({0, 2}, 2, id="SIGINT-against-0-2"),
            pytest.param({0, 3}, 3, id="SIGQUIT-against-0-3"),
        ],
    )
    def test_the_row_is_error(
        self, plugin_context, tmp_path, monkeypatch, success_codes, signum
    ):
        monkeypatch.setattr(sys.modules[__name__], "TOOL_SOURCE", SIGNAL_TOOL_SOURCE)

        container = _run(
            plugin_context,
            tmp_path,
            success_codes=success_codes,
            exit_code=signum,
            results=json.dumps(_sarif([])),
        )

        assert container.status == ScannerStatus.ERROR, (
            f"a tool killed by signal {signum} was graded {container.status.value} "
            f"with exit code {container.exit_code}"
        )
        assert container.exit_code == 128 + signum

    def test_an_accumulated_code_is_recorded_the_same_way(self, plugin_context):
        """``_process_command_response``, which overriding scanners rely on, agrees."""
        scanner = _scanner_class({0, 1})(config=_ToolConfig(), context=plugin_context)

        scanner._process_command_response({"returncode": -1})

        assert scanner.exit_code == 129
        assert not scanner._exit_code_accepted()


def test_each_target_is_judged_by_its_own_run(plugin_context, tmp_path):
    """The converted target's exit 1 is not hidden by the source target's exit 2.

    ``_process_command_response`` keeps the largest code any run returned, and with
    grype's ``{0, 2}`` a 2 from one target used to accept a 1 from the next.
    """
    prepared = tmp_path / "prepared"
    prepared.write_text(json.dumps(_sarif([])), encoding="utf-8")
    converted = plugin_context.work_dir
    (converted / "converted.py").write_text("y = 2\n")
    scanner = _scanner_class({0, 2})(config=_ToolConfig(), context=plugin_context)
    scanner.prepared_results = str(prepared)
    codes = iter([2, 1])
    original = scanner._execute_scan

    def execute(target, target_type, global_ignore_paths):
        scanner.tool_exit_code = next(codes)
        return original(target, target_type, global_ignore_paths)

    object.__setattr__(scanner, "_execute_scan", execute)
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )

    source_row, converted_row = executor._execute_scanner(
        SCANNER_NAME,
        scanner,
        [
            {"path": plugin_context.source_dir, "type": "source"},
            {"path": converted, "type": "converted"},
        ],
    )

    assert (source_row.status, source_row.exit_code) == (ScannerStatus.PASSED, 2)
    assert (converted_row.status, converted_row.exit_code) == (ScannerStatus.ERROR, 1)


class TestTheRunnersOwnFailureIsAnError:
    """ASH failing to run the tool is not an accepted exit code.

    ``_run_subprocess`` catches an exception from its own runner and used to record
    exit code 1, which ``{0, 1}`` accepts. With a results file already in place the
    template then graded it. It is recorded as ``SPAWN_FAILURE_RETURNCODE``, as a
    command the OS could not start is, and the row says what failed.
    """

    def test_the_row_is_error_even_with_a_results_file_in_place(
        self, plugin_context, tmp_path, monkeypatch
    ):
        from automated_security_helper.utils import subprocess_utils

        def broken_runner(command, **kwargs):
            # The results file the command would have produced, then the failure.
            Path(command[4]).write_text(json.dumps(_sarif([])), encoding="utf-8")
            raise RuntimeError("the runner could not read its own output")

        # _run_subprocess imports the runner from this module when it runs.
        monkeypatch.setattr(
            subprocess_utils, "run_command_with_output_handling", broken_runner
        )

        container = _run(
            plugin_context,
            tmp_path,
            success_codes={0, 1},
            exit_code=0,
            results=json.dumps(_sarif([])),
        )

        assert container.status == ScannerStatus.ERROR, (
            f"the runner failed and the row was graded {container.status.value} "
            f"with exit code {container.exit_code}"
        )
        assert container.exit_code == SPAWN_FAILURE_RETURNCODE
        assert any(
            "the runner could not read its own output" in str(e)
            for e in container.errors
        ), container.errors

    def test_the_response_carries_the_code(self, plugin_context, monkeypatch):
        """So a scanner that judges each target by its own run sees it too."""
        from automated_security_helper.utils import subprocess_utils

        def broken_runner(command, **kwargs):
            raise RuntimeError("boom")

        # _run_subprocess imports the runner from this module when it runs.
        monkeypatch.setattr(
            subprocess_utils, "run_command_with_output_handling", broken_runner
        )
        scanner = _scanner_class({0, 1})(config=_ToolConfig(), context=plugin_context)

        response = scanner._run_subprocess([sys.executable, "-c", "pass"])

        assert response["returncode"] == SPAWN_FAILURE_RETURNCODE
        assert scanner.exit_code == SPAWN_FAILURE_RETURNCODE
        assert not scanner._exit_code_accepted()
