"""Every way the scan phase grades a scanner ERROR records a short reason for it.

A scanner's row said ERROR and left the cause to the first sentence of an error
line, which is whatever the scanner's own exception said: a results file it could
not read, a path, a traceback's last line. The executor and the scan phase now file
a reason on the container (``record_error_reason``: a code and one sentence with no
path in it) at each place they grade or record an ERROR, and the reports show it.

The cases below drive one path each through the real executor with a scripted
scanner, and the scan phase through its own recorders:

- the failure handler, in the order its headline reads the run's recorded facts: a
  timeout, a tool that never started, an output ASH could not record, the reason a
  raise site recorded (on the error or on what it was raised from), the flag of a
  run that did not finish, an exit code the scanner does not accept, a plugin that
  called ``sys.exit``; and nothing, when nothing says;
- the results the executor refuses to grade, the absent and the stale content
  databases, the targets no rule was evaluated against, and a timeout that was
  recorded after ``scan()`` returned;
- what stops a scanner before its tool runs: the sandbox, an image task with no
  image;
- a scanner's whole run failing, in the sequential and the parallel loop;
- the scan phase: a name the tracker refuses or another scanner holds, a check
  that raised, a scanner that could not be built (with the reason its constructor's
  own error carries, when it carries one), a module that did not import.

Every reason recorded is a sentence ``is_short_reason`` accepts, with a code the
vocabulary defines. The controls at the end take away the one thing a case rests on
and show that the case then fails.
"""

from __future__ import annotations

from datetime import datetime
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.client_scanner_exclusions import (
    ClientScannerExclusion,
)
from automated_security_helper.core.asset import Asset, ImageLocator
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.exceptions import (
    DEFAULT_SENTENCES,
    FailureReason,
    ReasonCode,
    ScannerError,
)
from automated_security_helper.core.phases import scanner_executor
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.core.phases.scanner_executor import (
    ResultsProcessingFailed,
    ScannerExecutor,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.scanner_validation import (
    ScannerValidationManager,
)
from automated_security_helper.plugins.loader import PluginLoadFailure
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.sandbox.scope import (
    SandboxBackendUnavailable,
    SandboxUnavailable,
)
from automated_security_helper.utils.short_reason import is_short_reason
from automated_security_helper.utils.subprocess_utils import COULD_NOT_STOP_ENDING

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

CANARY = "ENVCANARY-error-reason-quoted-value"


class _ScannerConfig(ScannerPluginConfigBase):
    name: str = "scripted"


class _Scripted(ScannerPluginBase):
    """A real ScannerPluginBase whose scan() records what ``after_scan`` says a
    tool run recorded on the plugin (a timeout, an exit code, unevaluated targets)
    and then replays the scripted outcome: raised when it is an exception, returned
    otherwise."""

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(
        self,
        target,
        target_type=None,
        global_ignore_paths=None,
        config=None,
        *args,
        **kwargs,
    ):
        hook = getattr(self, "after_scan", None)
        if callable(hook):
            hook(self)
        outcome = self.scripted_result
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class _Wrapping(_Scripted):
    """A scanner that re-raises what its tool step raised under its own text, as the
    scan template's wrapper does: the reason is on the error it caught, which the
    new error keeps as its ``__context__``."""

    def scan(
        self,
        target,
        target_type=None,
        global_ignore_paths=None,
        config=None,
        *args,
        **kwargs,
    ):
        try:
            raise ScannerError(
                "the tool step failed",
                reason=FailureReason(
                    ReasonCode.RESULTS_UNREADABLE,
                    "its results file is not SARIF ASH can read",
                ),
            )
        except ScannerError:
            raise ScannerError("the wrapper's own text, which has no reason")


def _context(tmp_path) -> PluginContext:
    source_dir = tmp_path / "source"
    source_dir.mkdir(exist_ok=True)
    (source_dir / "app.py").write_text("print('x')\n", encoding="utf-8")
    output_dir = tmp_path / "output"
    output_dir.mkdir(exist_ok=True)
    work_dir = tmp_path / "work"
    work_dir.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source_dir,
        output_dir=output_dir,
        work_dir=work_dir,
        config=AshConfig(project_name="error-reasons"),
    )


def _scanner(context, scripted_result=None, after_scan=None, cls=_Scripted):
    config = _ScannerConfig()
    config.options.severity_threshold = "MEDIUM"
    scanner = cls(config=config, context=context)
    scanner.scripted_result = scripted_result
    scanner.after_scan = after_scan
    scanner.exit_code = 0
    return scanner


def _executor(context, tasks=None, **kwargs):
    return ScannerExecutor(
        plugin_context=context,
        progress_display=MagicMock(),
        scanner_tasks=tasks or [],
        **kwargs,
    )


def _targets(context):
    return [{"path": context.source_dir, "type": "source"}]


def _one_row(context, scanner, name="scripted"):
    (row,) = _executor(context)._execute_scanner(name, scanner, _targets(context))
    return row


def _sarif() -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "tool"}}, "results": []}],
        }
    )


def _checkov_finding() -> SarifReport:
    """What checkov returns: one finding in a file a client's exclusion names."""
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "checkov"}},
                    "results": [
                        {
                            "ruleId": "CKV_1",
                            "message": {"text": "finding"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {"uri": "vendor/x.tf"},
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                            "properties": {"scanner_name": "checkov"},
                        }
                    ],
                }
            ],
        }
    )


def _delivers_a_checkov_skip_path(context, scan_timeout) -> None:
    """Give *context*'s config the checkov ``skip_path`` pattern a client delivered.

    The entry sits where the scan puts one it moved out of the scanner's options
    (``AshConfig._client_scanner_exclusions``), and the suppression pass reads it
    for every finding checkov reports. ``vend.r`` is a regular expression, so the
    pass searches it under the pattern time limit: ``scan_timeout`` seconds for the
    whole pass.
    """
    context.config._client_scanner_exclusions = [
        ClientScannerExclusion(
            scanner="checkov",
            option="skip_path",
            kind="checkov",
            pattern="vend.r",
            reason="the client's own",
            scan_timeout=scan_timeout,
        )
    ]


def _records(**attributes):
    """An ``after_scan`` hook that sets *attributes* on the plugin, as a tool run
    would record them while ``scan()`` ran."""

    def hook(plugin):
        for name, value in attributes.items():
            setattr(plugin, name, value)

    return hook


def _why(row):
    return row.error_reason_code, row.error_reason


def _assert_reason(row, code, sentence):
    """The row is ERROR for *code*, said as *sentence*, which is fit to show."""
    assert row.status == ScannerStatus.ERROR, (row.status, row.errors)
    assert _why(row) == (code, sentence), _why(row)
    assert code in DEFAULT_SENTENCES, code
    assert is_short_reason(sentence), sentence


def _plugin_values(monkeypatch, *values):
    monkeypatch.setattr(_Scripted, "_environment_values", lambda self: tuple(values))


def _refuse_sandbox(monkeypatch, refusal, grades_missing):
    def _refuse(*args, **kwargs):
        raise refusal

    monkeypatch.setattr(scanner_executor, "scanner_sandbox_scope", _refuse)
    monkeypatch.setattr(
        scanner_executor, "sandbox_refusal_grades_missing", lambda _: grades_missing
    )


class TestAFailureTheHandlerCatches:
    def test_a_recorded_timeout_is_the_reason(self, tmp_path):
        context = _context(tmp_path)
        scanner = _scanner(
            context,
            ScannerError("the results file does not exist"),
            after_scan=_records(_scan_timed_out_after=30.0),
        )

        row = _one_row(context, scanner)

        _assert_reason(
            row, ReasonCode.TIMED_OUT, "it timed out after '30' s and was killed"
        )

    def test_a_tool_ash_could_not_stop_is_said_so(self, tmp_path):
        context = _context(tmp_path)
        scanner = _scanner(
            context,
            ScannerError("the results file does not exist"),
            after_scan=_records(
                _scan_timed_out_after=30.0,
                _scan_could_not_stop="the tool (pid 7), which may still be running",
                _scan_could_not_stop_runs={"timed_out": "the tool (pid 7)"},
            ),
        )

        row = _one_row(context, scanner)

        _assert_reason(
            row,
            ReasonCode.COULD_NOT_STOP,
            f"it timed out after '30' s{COULD_NOT_STOP_ENDING}",
        )

    def test_a_timeout_outranks_a_reason_naming_a_missing_file(self, tmp_path):
        """The missing results file is what the killed tool left behind."""
        context = _context(tmp_path)
        missing_file = ScannerError(
            "could not read the results file",
            reason=FailureReason(ReasonCode.RESULTS_UNREADABLE),
        )
        scanner = _scanner(
            context, missing_file, after_scan=_records(_scan_timed_out_after=30.0)
        )

        row = _one_row(context, scanner)

        assert row.error_reason_code == ReasonCode.TIMED_OUT, _why(row)

    def test_control_without_a_timeout_the_recorded_reason_stands(self, tmp_path):
        context = _context(tmp_path)
        missing_file = ScannerError(
            "could not read the results file",
            reason=FailureReason(ReasonCode.RESULTS_UNREADABLE),
        )

        row = _one_row(context, _scanner(context, missing_file))

        _assert_reason(
            row,
            ReasonCode.RESULTS_UNREADABLE,
            DEFAULT_SENTENCES[ReasonCode.RESULTS_UNREADABLE],
        )

    def test_a_tool_that_never_started_is_the_reason(self, tmp_path):
        context = _context(tmp_path)
        scanner = _scanner(
            context,
            ScannerError("the results file does not exist"),
            after_scan=_records(_scan_spawn_failure="no such file or directory"),
        )

        row = _one_row(context, scanner)

        _assert_reason(
            row,
            ReasonCode.COULD_NOT_START,
            DEFAULT_SENTENCES[ReasonCode.COULD_NOT_START],
        )

    def test_an_output_ash_could_not_record_is_the_reason(self, tmp_path):
        context = _context(tmp_path)
        scanner = _scanner(
            context,
            ScannerError("the results file does not exist"),
            after_scan=_records(_scan_post_run_error="the log could not be written"),
        )

        row = _one_row(context, scanner)

        _assert_reason(
            row,
            ReasonCode.OUTPUT_NOT_RECORDED,
            DEFAULT_SENTENCES[ReasonCode.OUTPUT_NOT_RECORDED],
        )

    @pytest.mark.parametrize(
        "flag, code, sentence",
        [
            (
                "cancelled",
                ReasonCode.CANCELLED,
                DEFAULT_SENTENCES[ReasonCode.CANCELLED],
            ),
            (
                "result_rejected",
                ReasonCode.RESULT_REJECTED,
                DEFAULT_SENTENCES[ReasonCode.RESULT_REJECTED],
            ),
            (
                "signaled",
                ReasonCode.DID_NOT_FINISH,
                "its tool was ended by a signal ASH did not send",
            ),
        ],
    )
    def test_a_run_that_did_not_finish_says_how_it_ended(
        self, tmp_path, flag, code, sentence
    ):
        """A flag is led over the record failure a killed tool commonly adds."""
        context = _context(tmp_path)
        scanner = _scanner(
            context,
            _sarif(),
            after_scan=_records(
                _scan_kept_flag=(flag, "the run was ended"),
                _scan_post_run_error="the output file could not be written",
            ),
        )

        row = _one_row(context, scanner)

        _assert_reason(row, code, sentence)

    def test_the_reason_a_raise_site_recorded_is_the_reason(self, tmp_path):
        context = _context(tmp_path)
        recorded = ScannerError(
            "could not read /somewhere/results.sarif",
            reason=FailureReason(
                ReasonCode.RESULTS_UNREADABLE,
                "its results file is not SARIF ASH can read",
            ),
        )

        row = _one_row(context, _scanner(context, recorded))

        _assert_reason(
            row,
            ReasonCode.RESULTS_UNREADABLE,
            "its results file is not SARIF ASH can read",
        )
        assert "/somewhere" not in row.error_reason

    def test_a_reason_on_what_the_error_was_raised_from_is_found(self, tmp_path):
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, cls=_Wrapping))

        _assert_reason(
            row,
            ReasonCode.RESULTS_UNREADABLE,
            "its results file is not SARIF ASH can read",
        )

    def test_a_recorded_sentence_is_redacted_with_the_runs_values(
        self, tmp_path, monkeypatch
    ):
        _plugin_values(monkeypatch, CANARY)
        context = _context(tmp_path)
        recorded = ScannerError(
            "refused",
            reason=FailureReason(
                ReasonCode.RESULTS_UNREADABLE, f"its option {CANARY} was refused"
            ),
        )

        row = _one_row(context, _scanner(context, recorded))

        assert row.error_reason_code == ReasonCode.RESULTS_UNREADABLE, _why(row)
        assert row.error_reason and CANARY not in row.error_reason, row.error_reason

    def test_a_sentence_that_names_a_path_is_never_the_reason_shown(self, tmp_path):
        context = _context(tmp_path)
        recorded = ScannerError(
            "refused",
            reason=FailureReason(
                ReasonCode.RESULTS_UNREADABLE, "could not read /home/someone/x.sarif"
            ),
        )

        row = _one_row(context, _scanner(context, recorded))

        _assert_reason(
            row,
            ReasonCode.RESULTS_UNREADABLE,
            DEFAULT_SENTENCES[ReasonCode.RESULTS_UNREADABLE],
        )

    def test_a_recorded_reason_outranks_an_exit_code(self, tmp_path):
        context = _context(tmp_path)
        recorded = ScannerError(
            "refused", reason=FailureReason(ReasonCode.RESULTS_UNREADABLE)
        )
        scanner = _scanner(context, recorded, after_scan=_records(exit_code=2))

        row = _one_row(context, scanner)

        assert row.error_reason_code == ReasonCode.RESULTS_UNREADABLE, _why(row)

    def test_an_exit_code_the_scanner_does_not_accept_is_the_reason(self, tmp_path):
        """A scanner that overrides scan() and reads the results file of a tool that
        failed raises the file's absence; the cause is the tool's exit code."""
        context = _context(tmp_path)
        scanner = _scanner(
            context,
            ScannerError("the results file does not exist"),
            after_scan=_records(exit_code=2),
        )

        row = _one_row(context, scanner)

        _assert_reason(
            row,
            ReasonCode.EXIT_CODE_REJECTED,
            "its tool exited with code 2, which this scanner does not accept as a "
            "completed run, so its results file is not graded",
        )

    def test_control_an_accepted_exit_code_is_no_reason(self, tmp_path):
        context = _context(tmp_path)
        scanner = _scanner(
            context,
            ScannerError("the results file does not exist"),
            after_scan=_records(exit_code=1),
        )

        row = _one_row(context, scanner)

        assert row.status == ScannerStatus.ERROR
        assert _why(row) == (None, None), _why(row)

    def test_a_plugin_that_called_sys_exit_has_exited(self, tmp_path):
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, SystemExit(3)))

        _assert_reason(
            row,
            ReasonCode.SCANNER_EXITED,
            "it called sys.exit instead of returning a result",
        )

    def test_nothing_that_says_why_leaves_no_reason_and_the_error_as_it_was(
        self, tmp_path
    ):
        """No reason is made up: the reports read the first sentence of the error."""
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, ValueError("an unforeseen failure")))

        assert row.status == ScannerStatus.ERROR
        assert _why(row) == (None, None), _why(row)
        assert any("an unforeseen failure" in error for error in row.errors), row.errors

    def test_a_result_that_never_came_back_is_the_reason(self, tmp_path):
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, None))

        _assert_reason(
            row, ReasonCode.NO_RESULT, DEFAULT_SENTENCES[ReasonCode.NO_RESULT]
        )

    def test_the_reason_is_in_the_dump_the_processor_writes(self, tmp_path):
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, None))

        dumped = row.model_dump(exclude_unset=True, exclude_none=True)
        assert dumped["error_reason_code"] == ReasonCode.NO_RESULT
        assert dumped["error_reason"] == DEFAULT_SENTENCES[ReasonCode.NO_RESULT]


class TestAResultTheExecutorRefusesToGrade:
    @pytest.mark.parametrize(
        "result, code, sentence",
        [
            pytest.param(
                lambda: SarifReport.model_validate({"version": "2.1.0", "runs": []}),
                ReasonCode.RESULT_UNGRADABLE,
                "its SARIF result holds no run, so there is nothing to grade",
                id="a SARIF log with no run",
            ),
            pytest.param(
                lambda: {"status": "an odd status the plugin made up"},
                ReasonCode.RESULT_UNGRADABLE,
                "its result's status does not say its tool completed, so it was "
                "not graded",
                id="a status that does not say the tool completed",
            ),
            pytest.param(
                lambda: {"status": "failed"},
                ReasonCode.RUN_FAILED,
                "it reported that its run failed without saying why",
                id="a failed run with no error anywhere",
            ),
            pytest.param(
                dict,
                ReasonCode.RESULT_UNGRADABLE,
                "its result is not SARIF and carries no status, severity_counts "
                "or findings",
                id="a dict with nothing to grade",
            ),
            pytest.param(
                list,
                ReasonCode.RESULT_UNGRADABLE,
                "its result is not SARIF, CycloneDX or a dict",
                id="a list",
            ),
            pytest.param(
                lambda: {"severity_counts": {"high": "many"}},
                ReasonCode.RESULT_UNGRADABLE,
                DEFAULT_SENTENCES[ReasonCode.RESULT_UNGRADABLE],
                id="a count that is not a number",
            ),
        ],
    )
    def test_each_refusal_names_what_was_wrong_with_the_result(
        self, tmp_path, result, code, sentence
    ):
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, result()))

        _assert_reason(row, code, sentence)

    def test_the_plugins_own_words_are_not_in_the_reason(self, tmp_path):
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, {"status": "odd secret status"}))

        assert row.error_reason and "secret" not in row.error_reason, row.error_reason


class TestAGradingStepThatRecordedItsOwnReason:
    """A step of grading that fails for a cause it knows says so on the row.

    The grading steps run on what the scanner returned, inside one handler: the
    levels, the path sanitizing, the suppression pass. A step can fail for a reason of
    its own (the suppression pass, when a pattern a client delivered runs past its
    time limit), and the handler filed "could not be graded" over it, so the reason
    the raising code recorded never reached a row. It files that reason now, and the
    generic one only for a step that recorded none.
    """

    def test_the_suppression_pass_that_ran_out_of_time_says_so(self, tmp_path):
        """The real pass, with a pattern time limit of nothing: the first search of the
        client's pattern finds the limit spent and raises its own reason."""
        context = _context(tmp_path)
        _delivers_a_checkov_skip_path(context, scan_timeout=0.0)

        row = _one_row(context, _scanner(context, _checkov_finding()), name="checkov")

        assert row.status == ScannerStatus.ERROR, (row.status, row.errors)
        assert row.error_reason_code == ReasonCode.PATTERN_TIME_LIMIT, _why(row)
        assert row.error_reason and "pattern time limit" in row.error_reason
        assert is_short_reason(row.error_reason), row.error_reason

    def test_the_row_keeps_the_failure_as_its_record(self, tmp_path):
        """The reason changes what the row says, not what it holds: the refusal is
        still in its errors, and the half-processed report is still replaced."""
        context = _context(tmp_path)
        _delivers_a_checkov_skip_path(context, scan_timeout=0.0)

        row = _one_row(context, _scanner(context, _checkov_finding()), name="checkov")

        assert any("could not be graded" in error for error in row.errors), row.errors
        assert not isinstance(row.raw_results, SarifReport), type(row.raw_results)

    @pytest.mark.parametrize(
        "chained", [False, True], ids=["on the error", "on what it was raised from"]
    )
    def test_a_reason_a_grading_step_recorded_is_the_reason(
        self, tmp_path, monkeypatch, chained
    ):
        context = _context(tmp_path)
        recorded = ScannerError(
            "the step failed on /somewhere/x",
            reason=FailureReason(
                ReasonCode.PATTERN_TIME_LIMIT,
                "a pattern from the configuration ran out of time",
            ),
        )

        def failing(**kwargs):
            if chained:
                raise RuntimeError("the pass wrapped what failed") from recorded
            raise recorded

        monkeypatch.setattr(scanner_executor, "apply_suppressions_to_sarif", failing)

        row = _one_row(context, _scanner(context, _sarif()))

        _assert_reason(
            row,
            ReasonCode.PATTERN_TIME_LIMIT,
            "a pattern from the configuration ran out of time",
        )
        assert "/somewhere" not in row.error_reason

    def test_a_recorded_sentence_is_redacted_with_the_runs_values(
        self, tmp_path, monkeypatch
    ):
        _plugin_values(monkeypatch, CANARY)
        context = _context(tmp_path)
        recorded = ScannerError(
            "refused",
            reason=FailureReason(
                ReasonCode.PATTERN_TIME_LIMIT, f"its option {CANARY} ran out of time"
            ),
        )

        def failing(**kwargs):
            raise recorded

        monkeypatch.setattr(scanner_executor, "apply_suppressions_to_sarif", failing)

        row = _one_row(context, _scanner(context, _sarif()))

        assert row.error_reason_code == ReasonCode.PATTERN_TIME_LIMIT, _why(row)
        assert row.error_reason and CANARY not in row.error_reason, row.error_reason

    def test_control_a_step_that_recorded_no_reason_is_ungradable(
        self, tmp_path, monkeypatch
    ):
        context = _context(tmp_path)

        def failing(**kwargs):
            raise ValueError("the pass failed on /somewhere/x")

        monkeypatch.setattr(scanner_executor, "apply_suppressions_to_sarif", failing)

        row = _one_row(context, _scanner(context, _sarif()))

        _assert_reason(
            row,
            ReasonCode.RESULT_UNGRADABLE,
            DEFAULT_SENTENCES[ReasonCode.RESULT_UNGRADABLE],
        )
        assert "/somewhere" not in row.error_reason


class TestWhatTheRowRecordsAfterTheScan:
    def test_an_absent_content_database_is_the_reason(self, tmp_path, monkeypatch):
        record = SimpleNamespace(
            absent=True, enforced=False, name="vuln-db", message=lambda: "db absent"
        )
        monkeypatch.setattr(
            ScannerExecutor, "_assess_content_databases", lambda *a: [record]
        )
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, _sarif()))

        _assert_reason(
            row,
            ReasonCode.CONTENT_DATABASE_ABSENT,
            DEFAULT_SENTENCES[ReasonCode.CONTENT_DATABASE_ABSENT],
        )

    def test_several_absent_databases_are_counted(self, tmp_path, monkeypatch):
        records = [
            SimpleNamespace(
                absent=True, enforced=False, name=name, message=lambda: "db absent"
            )
            for name in ("one", "two", "three")
        ]
        monkeypatch.setattr(
            ScannerExecutor, "_assess_content_databases", lambda *a: records
        )
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, _sarif()))

        _assert_reason(
            row,
            ReasonCode.CONTENT_DATABASE_ABSENT,
            "3 of its content databases are absent",
        )

    def test_a_clean_result_from_a_stale_database_is_the_reason(
        self, tmp_path, monkeypatch
    ):
        record = SimpleNamespace(
            absent=False, enforced=True, name="vuln-db", message=lambda: "db stale"
        )
        monkeypatch.setattr(
            ScannerExecutor, "_assess_content_databases", lambda *a: [record]
        )
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, _sarif()))

        _assert_reason(
            row,
            ReasonCode.CONTENT_DATABASE_STALE,
            DEFAULT_SENTENCES[ReasonCode.CONTENT_DATABASE_STALE],
        )

    def test_targets_no_rule_was_evaluated_against_are_counted_and_never_named(
        self, tmp_path
    ):
        def _unevaluated(plugin):
            plugin.record_unevaluated_target("secret-name.yaml")
            plugin.record_unevaluated_target("other.yaml")

        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, _sarif(), after_scan=_unevaluated))

        _assert_reason(
            row,
            ReasonCode.NOT_EVALUATED,
            "no rule was evaluated against 2 of its target(s)",
        )
        assert "secret-name" not in row.error_reason

    def test_a_row_already_error_for_another_cause_keeps_that_reason(self, tmp_path):
        context = _context(tmp_path)

        row = _one_row(
            context,
            _scanner(
                context,
                {"status": "odd"},
                after_scan=lambda plugin: plugin.record_unevaluated_target("a.yaml"),
            ),
        )

        assert row.error_reason_code == ReasonCode.RESULT_UNGRADABLE, _why(row)
        assert any("a.yaml" in error for error in row.errors), row.errors

    def test_a_timeout_recorded_after_scan_returned_is_the_reason(self, tmp_path):
        context = _context(tmp_path)
        scanner = _scanner(
            context, _sarif(), after_scan=_records(_scan_timed_out_after=7.0)
        )

        row = _one_row(context, scanner)

        _assert_reason(
            row, ReasonCode.TIMED_OUT, "it timed out after '7' s and was killed"
        )

    def test_a_timed_out_target_the_scanner_recorded_itself_is_the_reason(
        self, tmp_path
    ):
        """It returned the other target's report and kept the timeout flag, with no
        limit recorded: the flag alone makes the row ERROR."""
        context = _context(tmp_path)
        scanner = _scanner(
            context,
            {"findings": []},
            after_scan=_records(
                targets_attempted=2,
                targets_failed=1,
                _scan_kept_flag=("timed_out", "the tool was killed"),
            ),
        )

        row = _one_row(context, scanner)

        _assert_reason(row, ReasonCode.TIMED_OUT, "it timed out and was killed")


class TestWhatStopsAScannerBeforeItsToolRuns:
    def test_a_backend_the_operator_named_that_is_unavailable(
        self, tmp_path, monkeypatch
    ):
        refusal = SandboxBackendUnavailable("bwrap is not available", "bwrap")
        _refuse_sandbox(monkeypatch, refusal, grades_missing=False)
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, _sarif()))

        _assert_reason(
            row,
            ReasonCode.SANDBOX_UNAVAILABLE,
            DEFAULT_SENTENCES[ReasonCode.SANDBOX_UNAVAILABLE],
        )

    def test_a_sandbox_that_was_refused_for_another_reason(self, tmp_path, monkeypatch):
        refusal = SandboxUnavailable("the results directory is a link")
        _refuse_sandbox(monkeypatch, refusal, grades_missing=False)
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, _sarif()))

        _assert_reason(
            row,
            ReasonCode.SANDBOX_REFUSED,
            DEFAULT_SENTENCES[ReasonCode.SANDBOX_REFUSED],
        )

    def test_control_a_missing_scanner_has_no_error_reason(self, tmp_path, monkeypatch):
        refusal = SandboxUnavailable("no backend works")
        _refuse_sandbox(monkeypatch, refusal, grades_missing=True)
        context = _context(tmp_path)

        row = _one_row(context, _scanner(context, _sarif()))

        assert row.status == ScannerStatus.MISSING
        assert _why(row) == (None, None), _why(row)

    def test_an_image_task_with_no_image_asset(self, tmp_path):
        context = _context(tmp_path)
        scanner = _scanner(context, _sarif())

        (row,) = _executor(context)._execute_scanner(
            "scripted", scanner, [{"path": context.source_dir, "type": "image"}]
        )

        _assert_reason(
            row,
            ReasonCode.NO_IMAGE_ASSET,
            DEFAULT_SENTENCES[ReasonCode.NO_IMAGE_ASSET],
        )

    def test_a_plugin_with_no_context_says_so(self):
        stand_in = SimpleNamespace(context=None)

        with pytest.raises(ScannerError, match="No context provided") as raised:
            PluginBase._require_context(stand_in)

        assert raised.value.reason == FailureReason(ReasonCode.NO_PLUGIN_CONTEXT)


class TestAScannersWholeRunFailing:
    def _failure_of(self, tmp_path, error):
        context = _context(tmp_path)
        executor = _executor(context)

        def _raising(*args):
            raise error

        executor._execute_scanner = _raising  # type: ignore[method-assign]
        (container,), succeeded = executor._safe_execute_scanner(
            "scripted", _scanner(context), _targets(context)
        )
        assert succeeded is False
        return container

    def test_a_reason_a_raise_site_recorded(self, tmp_path):
        error = ScannerError(
            "the scan failed", reason=FailureReason(ReasonCode.NO_PLUGIN_CONTEXT)
        )

        container = self._failure_of(tmp_path, error)

        assert _why(container) == (
            ReasonCode.NO_PLUGIN_CONTEXT,
            DEFAULT_SENTENCES[ReasonCode.NO_PLUGIN_CONTEXT],
        )

    def test_results_that_could_not_be_merged(self, tmp_path):
        error = ResultsProcessingFailed("source", ValueError("a report"))

        container = self._failure_of(tmp_path, error)

        assert _why(container) == (
            ReasonCode.RESULTS_NOT_MERGED,
            DEFAULT_SENTENCES[ReasonCode.RESULTS_NOT_MERGED],
        )

    def test_a_plugin_that_called_sys_exit(self, tmp_path):
        container = self._failure_of(tmp_path, SystemExit(2))

        assert container.error_reason_code == ReasonCode.SCANNER_EXITED

    def test_a_failure_nothing_explains_has_no_reason(self, tmp_path):
        container = self._failure_of(tmp_path, RuntimeError("an unforeseen failure"))

        assert _why(container) == (None, None), _why(container)

    @pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
    def test_a_run_that_returned_no_results_at_all(self, tmp_path, parallel):
        context = _context(tmp_path)
        seen: list = []

        def process(container, aggregated):
            seen.append(container)
            return aggregated

        tasks = [
            (name, _scanner(context), _targets(context)) for name in ("one", "two")
        ]
        executor = _executor(context, tasks, process_results_fn=process)
        executor._execute_scanner = lambda *args: None  # type: ignore[method-assign]

        if parallel:
            executor.run_parallel(AshAggregatedResults())
        else:
            executor.run_sequential(AshAggregatedResults())

        assert len(seen) == 2, seen
        for container in seen:
            assert _why(container) == (
                ReasonCode.NO_RESULT,
                DEFAULT_SENTENCES[ReasonCode.NO_RESULT],
            )

    @pytest.mark.parametrize("parallel", [False, True], ids=["sequential", "parallel"])
    def test_a_target_whose_results_could_not_be_merged_names_it_on_every_row_filed(
        self, tmp_path, parallel
    ):
        """The merge raises on both targets, so each target's own row is filed again
        and, since the processor raises on that too, a fresh row follows it: all of
        them say the results were not merged."""
        context = _context(tmp_path)
        (tmp_path / "converted").mkdir()
        seen: list = []

        def process(container, aggregated):
            seen.append(container)
            raise RuntimeError("the report could not be read")

        scanner = _scanner(context, {"findings": []})
        other = _scanner(context, {"findings": []})
        targets = [
            {"path": context.source_dir, "type": "source"},
            {"path": tmp_path / "converted", "type": "converted"},
        ]
        executor = _executor(
            context,
            [("scripted", scanner, targets), ("other", other, targets[:1])],
            process_results_fn=process,
        )

        if parallel:
            executor.run_parallel(AshAggregatedResults())
        else:
            executor.run_sequential(AshAggregatedResults())

        assert len(seen) >= 6, [(row.scanner_name, row.target_type) for row in seen]
        for row in seen:
            assert row.status == ScannerStatus.ERROR, (row.scanner_name, row.status)
            assert _why(row) == (
                ReasonCode.RESULTS_NOT_MERGED,
                DEFAULT_SENTENCES[ReasonCode.RESULTS_NOT_MERGED],
            ), (row.scanner_name, row.target_type, _why(row))


@pytest.fixture
def phase_context(tmp_path):
    """The context stub the scan-phase suites build."""
    context = MagicMock()
    source_dir = tmp_path / "source"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('hello')")
    work_dir = tmp_path / "work"
    work_dir.mkdir()
    output_dir = tmp_path / "output"
    output_dir.mkdir()
    context.source_dir = source_dir
    context.work_dir = work_dir
    context.output_dir = output_dir
    context.config = MagicMock()
    context.config.get_plugin_config.return_value = None
    context.config.global_settings.ignore_paths = []
    context.ignore_suppressions = False
    context.cached_source_files = []
    context.asset = None
    return context


@pytest.fixture
def scan_phase(phase_context):
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerValidationManager"
    ) as manager_class:
        manager = MagicMock(spec=ScannerValidationManager)
        manager.validate_registered_scanners.return_value = None
        manager.validate_scanner_enablement.return_value = None
        checkpoint = MagicMock()
        checkpoint.get_missing_scanners.return_value = []
        checkpoint.get_unexpected_scanners.return_value = []
        checkpoint.has_issues.return_value = False
        checkpoint.checkpoint_name = "test"
        checkpoint.timestamp = datetime(2024, 1, 1)
        checkpoint.expected_scanners = []
        checkpoint.actual_scanners = []
        checkpoint.discrepancies = []
        checkpoint.errors = []
        checkpoint.metadata = {}
        manager.validate_task_queue.return_value = checkpoint
        manager.validate_execution_completion.return_value = checkpoint
        manager.ensure_complete_results.return_value = checkpoint
        manager.report_execution_discrepancies.return_value = {}
        manager.report_result_completeness.return_value = {}
        manager_class.return_value = manager
        progress = MagicMock()
        progress.add_task.return_value = 1
        phase = ScanPhase(
            plugin_context=phase_context, plugins=[], progress_display=progress
        )
        phase.validation_manager = manager
        yield phase


def _phase_scanner(name="bandit"):
    """A scanner double: it constructs, passes its checks and runs nothing."""
    plugin_class = MagicMock()
    plugin_class.__name__ = name
    instance = MagicMock()
    instance.__class__ = plugin_class
    config = MagicMock()
    config.name = name
    config.enabled = True
    config.options.severity_threshold = "HIGH"
    instance.config = config
    instance.validate_plugin_dependencies.return_value = True
    instance.dependencies_satisfied = True
    instance.is_python_only.return_value = True
    instance.errors = []
    instance.output = []
    instance.exit_code = 0
    instance.start_time = datetime(2024, 1, 1, 10, 0, 0)
    instance.end_time = datetime(2024, 1, 1, 10, 0, 5)
    instance.context = None
    plugin_class.return_value = instance
    return plugin_class, instance


def _capture_writes(scan_phase, monkeypatch) -> list:
    """The containers the phase files for a scanner that did not run."""
    written: list = []

    def capture(display_name, container, aggregated_results):
        written.append(container)
        return aggregated_results

    monkeypatch.setattr(scan_phase, "_write_results_guarded", capture)
    return written


class TestTheScanPhasesOwnFailures:
    def _assert_filed(self, results, written, name, code, sentence):
        row = results.scanner_results[name]
        assert row.status == ScannerStatus.ERROR
        assert _why(row) == (code, sentence), _why(row)
        assert is_short_reason(sentence), sentence
        (container,) = [c for c in written if c.scanner_name == name]
        assert _why(container) == (code, sentence), _why(container)

    def test_a_name_the_tracker_refuses(self, scan_phase, monkeypatch):
        written = _capture_writes(scan_phase, monkeypatch)

        results = scan_phase._record_refused_scanner_name(
            "NotAName", object(), ValueError("empty"), AshAggregatedResults()
        )

        self._assert_filed(
            results,
            written,
            "NotAName",
            ReasonCode.NAME_REFUSED,
            DEFAULT_SENTENCES[ReasonCode.NAME_REFUSED],
        )

    def test_a_name_another_scanner_already_holds(self, scan_phase, monkeypatch):
        class _First:
            pass

        class _Later:
            pass

        written = _capture_writes(scan_phase, monkeypatch)

        results = scan_phase._record_duplicate_scanner_name(
            "shared", _Later(), _First(), AshAggregatedResults()
        )

        (row_name,) = results.scanner_results
        self._assert_filed(
            results,
            written,
            row_name,
            ReasonCode.NAME_TAKEN,
            DEFAULT_SENTENCES[ReasonCode.NAME_TAKEN],
        )

    def test_a_check_that_raised(self, scan_phase, monkeypatch):
        written = _capture_writes(scan_phase, monkeypatch)
        plugin_class, instance = _phase_scanner("bandit")
        instance.is_python_only.side_effect = RuntimeError("the check broke")
        scan_phase.plugins = [plugin_class]

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(),
            parallel=False,
            python_based_plugins_only=True,
        )

        self._assert_filed(
            results,
            written,
            "bandit",
            ReasonCode.CHECK_RAISED,
            DEFAULT_SENTENCES[ReasonCode.CHECK_RAISED],
        )

    def test_a_scanner_that_could_not_be_built_names_the_kind_of_error_only(
        self, scan_phase, monkeypatch
    ):
        written = _capture_writes(scan_phase, monkeypatch)
        plugin_class, _ = _phase_scanner("bandit")
        plugin_class.side_effect = RuntimeError("could not read /home/someone/x.cfg")
        scan_phase.plugins = [plugin_class]

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        self._assert_filed(
            results,
            written,
            "bandit",
            ReasonCode.CONSTRUCTION_FAILED,
            "it could not be constructed (RuntimeError)",
        )

    def test_a_scanner_that_could_not_be_built_for_an_image_says_the_same(
        self, scan_phase, monkeypatch
    ):
        written = _capture_writes(scan_phase, monkeypatch)
        plugin_class, _ = _phase_scanner("bandit")
        plugin_class.side_effect = RuntimeError("constructor broke")
        scan_phase.plugins = [plugin_class]
        scan_phase.plugin_context.asset = Asset.for_image(
            ImageLocator(ref="registry.example.com/team/app:1.2.3")
        )

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        self._assert_filed(
            results,
            written,
            "bandit",
            ReasonCode.CONSTRUCTION_FAILED,
            "it could not be constructed (RuntimeError)",
        )

    def test_a_constructor_that_raised_with_a_reason_keeps_that_reason(
        self, scan_phase, monkeypatch
    ):
        """The scanner's own words say more than the kind of exception."""
        written = _capture_writes(scan_phase, monkeypatch)
        plugin_class, _ = _phase_scanner("opengrep")
        plugin_class.side_effect = ScannerError(
            "scanners.opengrep.options.patterns names 2 patterns; see /home/me/x",
            reason=FailureReason(
                ReasonCode.OPTION_REFUSED, "its patterns option is refused"
            ),
        )
        scan_phase.plugins = [plugin_class]

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        self._assert_filed(
            results,
            written,
            "opengrep",
            ReasonCode.OPTION_REFUSED,
            "its patterns option is refused",
        )

    def test_a_constructor_that_raised_a_scanner_error_with_no_reason_is_the_kind_only(
        self, scan_phase, monkeypatch
    ):
        written = _capture_writes(scan_phase, monkeypatch)
        plugin_class, _ = _phase_scanner("opengrep")
        plugin_class.side_effect = ScannerError("it broke at /home/me/x")
        scan_phase.plugins = [plugin_class]

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        self._assert_filed(
            results,
            written,
            "opengrep",
            ReasonCode.CONSTRUCTION_FAILED,
            "it could not be constructed (ScannerError)",
        )

    def test_a_module_that_did_not_import(self, scan_phase, monkeypatch):
        written = _capture_writes(scan_phase, monkeypatch)
        failed = "automated_security_helper.plugin_modules.ash_x_plugins.scanners"
        scan_phase.plugin_context.plugin_load_record = {
            failed: PluginLoadFailure(recorded="ImportError: no module named 'x'")
        }

        results = scan_phase._execute_phase(
            aggregated_results=AshAggregatedResults(), parallel=False
        )

        self._assert_filed(
            results,
            written,
            failed,
            ReasonCode.MODULE_IMPORT_FAILED,
            DEFAULT_SENTENCES[ReasonCode.MODULE_IMPORT_FAILED],
        )


class _TargetByTarget(_Scripted):
    """A scanner whose own ``scan()`` never resets ``exit_code``, as an override of
    the template's does not: each call plays the next scripted step, which may set
    the code the way a tool run does and then return or raise."""

    def scan(
        self,
        target,
        target_type=None,
        global_ignore_paths=None,
        config=None,
        *args,
        **kwargs,
    ):
        return self.steps.pop(0)(self)


def _the_tool_exits_with(code, then):
    """A step: the tool's exit code is recorded, then *then* returns or raises."""

    def step(plugin):
        plugin.exit_code = code
        if isinstance(then, BaseException):
            raise then
        return then

    return step


def _fails_before_its_tool_starts(plugin):
    raise ScannerError("it could not set the target up")


def _two_targets(context):
    converted = context.work_dir / "converted"
    converted.mkdir(exist_ok=True)
    return [
        {"path": context.source_dir, "type": "source"},
        {"path": converted, "type": "converted"},
    ]


class TestAPreviousTargetsExitCodeIsNotThisTargets:
    """The failure reason reads the plugin's ``exit_code``, which a scan() that does
    not reset it carries from the target before, so a target that failed before its
    tool started was reported as having exited with the last target's code."""

    def _rows(self, context, steps):
        scanner = _scanner(context, cls=_TargetByTarget)
        scanner.steps = list(steps)
        rows = _executor(context)._execute_scanner(
            "scripted", scanner, _two_targets(context)
        )
        assert len(rows) == 2, rows
        return rows

    def test_a_target_that_fails_before_its_tool_starts_is_not_charged_the_last_code(
        self, tmp_path
    ):
        context = _context(tmp_path)

        _, second = self._rows(
            context,
            [_the_tool_exits_with(2, _sarif()), _fails_before_its_tool_starts],
        )

        assert second.status == ScannerStatus.ERROR
        assert second.error_reason_code != ReasonCode.EXIT_CODE_REJECTED, _why(second)
        assert _why(second) == (None, None), _why(second)

    def test_the_second_targets_row_does_not_carry_the_first_targets_code(
        self, tmp_path
    ):
        context = _context(tmp_path)

        _, second = self._rows(
            context,
            [_the_tool_exits_with(2, _sarif()), _fails_before_its_tool_starts],
        )

        assert second.exit_code != 2, second.exit_code

    def test_control_a_target_whose_own_tool_exits_with_a_rejected_code_is_charged_it(
        self, tmp_path
    ):
        context = _context(tmp_path)

        _, second = self._rows(
            context,
            [
                _the_tool_exits_with(2, _sarif()),
                _the_tool_exits_with(3, ScannerError("the results file is missing")),
            ],
        )

        _assert_reason(
            second,
            ReasonCode.EXIT_CODE_REJECTED,
            "its tool exited with code 3, which this scanner does not accept as a "
            "completed run, so its results file is not graded",
        )

    def test_control_the_first_target_is_charged_its_own_code(self, tmp_path):
        context = _context(tmp_path)

        first, _ = self._rows(
            context,
            [
                _the_tool_exits_with(2, ScannerError("the results file is missing")),
                _the_tool_exits_with(0, _sarif()),
            ],
        )

        assert first.error_reason_code == ReasonCode.EXIT_CODE_REJECTED, _why(first)

    def test_the_plugin_is_reset_by_the_method_the_executor_calls(self, tmp_path):
        """``clear_scan_exit_code`` puts the code back to the value a plugin starts
        with, and the executor calls it beside the other ``clear_*`` methods."""
        plugin = _scanner(_context(tmp_path))
        plugin.exit_code = 7

        plugin.clear_scan_exit_code()

        assert plugin.exit_code == 0

    def test_without_the_reset_the_stale_code_is_read(self, tmp_path, monkeypatch):
        """The control for the cases above: take the reset away, and the row of the
        target that never started its tool names the last target's code."""
        context = _context(tmp_path)
        monkeypatch.setattr(PluginBase, "clear_scan_exit_code", lambda self: None)

        _, second = self._rows(
            context,
            [_the_tool_exits_with(2, _sarif()), _fails_before_its_tool_starts],
        )

        assert second.error_reason_code == ReasonCode.EXIT_CODE_REJECTED, _why(second)


class TestTheControls:
    """Each takes away what a case above rests on, and the case then fails."""

    def test_without_the_walk_over_what_an_error_was_raised_from_the_wrapped_reason_is_lost(
        self, tmp_path, monkeypatch
    ):
        context = _context(tmp_path)
        assert _why(_one_row(context, _scanner(context, cls=_Wrapping)))[0] == (
            ReasonCode.RESULTS_UNREADABLE
        )

        monkeypatch.setattr(
            scanner_executor, "reason_of", lambda error: getattr(error, "reason", None)
        )
        row = _one_row(context, _scanner(context, cls=_Wrapping))

        assert row.status == ScannerStatus.ERROR
        assert _why(row) == (None, None), _why(row)

    def test_without_the_exit_code_reading_the_failed_tool_has_no_reason(
        self, tmp_path, monkeypatch
    ):
        context = _context(tmp_path)

        def failed_tool():
            return _scanner(
                context,
                ScannerError("the results file does not exist"),
                after_scan=_records(exit_code=2),
            )

        assert _one_row(context, failed_tool()).error_reason_code == (
            ReasonCode.EXIT_CODE_REJECTED
        )

        monkeypatch.setattr(
            scanner_executor, "_rejected_exit_code", lambda plugin: None
        )
        row = _one_row(context, failed_tool())

        assert row.status == ScannerStatus.ERROR
        assert _why(row) == (None, None), _why(row)

    def test_without_the_timeout_first_the_missing_file_would_lead(
        self, tmp_path, monkeypatch
    ):
        context = _context(tmp_path)

        def killed_tool():
            return _scanner(
                context,
                ScannerError(
                    "could not read the results file",
                    reason=FailureReason(ReasonCode.RESULTS_UNREADABLE),
                ),
                after_scan=_records(_scan_timed_out_after=30.0),
            )

        assert _one_row(context, killed_tool()).error_reason_code == (
            ReasonCode.TIMED_OUT
        )

        monkeypatch.setattr(scanner_executor, "_timed_out_after", lambda plugin: None)
        row = _one_row(context, killed_tool())

        assert row.error_reason_code == ReasonCode.RESULTS_UNREADABLE, _why(row)

    def test_without_the_grading_handlers_reading_of_the_reason_the_row_is_ungradable(
        self, tmp_path, monkeypatch
    ):
        context = _context(tmp_path)
        _delivers_a_checkov_skip_path(context, scan_timeout=0.0)

        def spent_pass():
            return _one_row(
                context, _scanner(context, _checkov_finding()), name="checkov"
            )

        assert spent_pass().error_reason_code == ReasonCode.PATTERN_TIME_LIMIT

        monkeypatch.setattr(
            scanner_executor, "_recorded_reason", lambda error, values: None
        )
        row = spent_pass()

        assert row.status == ScannerStatus.ERROR
        assert row.error_reason_code == ReasonCode.RESULT_UNGRADABLE, _why(row)

    def test_the_path_check_is_what_keeps_a_path_out_of_a_reason(self, monkeypatch):
        from automated_security_helper.core import exceptions

        path_sentence = "could not read /home/someone/x.sarif"
        assert (
            FailureReason(ReasonCode.RESULTS_UNREADABLE, path_sentence).sentence
            != path_sentence
        )

        monkeypatch.setattr(exceptions, "is_short_reason", lambda text: True)

        assert (
            FailureReason(ReasonCode.RESULTS_UNREADABLE, path_sentence).sentence
            == path_sentence
        )
