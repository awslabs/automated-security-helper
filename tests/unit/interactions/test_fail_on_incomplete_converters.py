# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A converter that did not run has to be able to reach the exit code.

Why these tests exist
---------------------
Conversion is what produces the second set of targets the scanners are given:
notebooks become Python, archives become their contents. A converter that crashed
or whose tool was absent therefore costs scan coverage, and it did so with no
effect on the exit code at all -- ``_compute_exit_code`` read only
``scanner_results``. The scanners that ran reported PASSED on the targets they
were given, so a run that silently skipped every notebook in the repository was
indistinguishable from one that scanned them and found nothing.

The gate this rides on
----------------------
``fail_on_incomplete_scanners``, the existing opt-in, rather than a new flag with
a new default. Two reasons. The question is the same question -- "did what I asked
for actually run" -- and an operator who has asked to be told about an incomplete
scan has not asked to be told about only half of it. And converters are more
likely than scanners to be legitimately absent on a given host, so adding a
default-on gate for them would turn currently-passing runs red without an operator
having opted in anywhere. With the flag off, which is the shipped default, these
inputs still exit 0.

``ash merge`` inherits this for free: ``cli.merge._merged_exit_code`` delegates to
``_compute_exit_code`` precisely so the union is held to the same completeness
rules as a single scan.

What does not trip it
---------------------
``excluded`` is the converter-side counterpart of a SKIPPED scanner: work the run
was never meant to do. A config-disabled converter, and one dropped by
``--python-based-plugins-only``, are recorded excluded and must stay exit 0, for
the same reason ``test_skipped_scanners_never_trip_the_gate`` exists on the
scanner side.
"""

from __future__ import annotations

import logging
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.interactions.run_ash_scan import (
    IncompleteConverter,
    ScanIncompleteness,
    ScanOptions,
    _compute_exit_code,
    incomplete_converters,
    print_incompleteness_message,
)
from automated_security_helper.models.asharp_model import (
    ConverterStatusInfo,
    FailedInputInfo,
)

pytestmark = pytest.mark.unit

_MODULE = "automated_security_helper.interactions.run_ash_scan"


def _healthy_scanner():
    """One scanner that ran and found nothing, so only converters can gate."""
    metric = MagicMock()
    metric.scanner_name = "bandit"
    metric.status = ScannerStatus.PASSED.value
    metric.actionable = 0
    metric.targets_attempted = 0
    metric.targets_failed = 0
    return metric


def _results(**converter_results):
    results = MagicMock()
    results.sarif = None
    results.converter_results = dict(converter_results)
    return results


def _opts(tmp_path, **kwargs) -> ScanOptions:
    return ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        **kwargs,
    )


def _exit_code(results, opts) -> int:
    with patch(
        f"{_MODULE}.get_unified_scanner_metrics", return_value=[_healthy_scanner()]
    ):
        return _compute_exit_code(results, opts)


class TestIncompleteConvertersAreListed:
    """``incomplete_converters`` selects on the row, not on the phase's logs."""

    def test_a_crashed_converter_is_listed_with_its_failure(self, tmp_path):
        results = _results(
            jupyter=ConverterStatusInfo(
                converted_paths=[], failure="RuntimeError: nbconvert is not on PATH"
            )
        )

        assert incomplete_converters(results) == [
            IncompleteConverter("jupyter", "RuntimeError: nbconvert is not on PATH")
        ]

    def test_a_converter_with_unsatisfied_dependencies_is_listed(self, tmp_path):
        results = _results(
            jupyter=ConverterStatusInfo(
                dependencies_satisfied=False, converted_paths=[]
            )
        )

        listed = incomplete_converters(results)
        assert [row[0] for row in listed] == ["jupyter"]
        assert "dependencies" in listed[0][1]

    def test_a_converter_with_failed_inputs_is_listed_with_them(self):
        """It ran, but some inputs the scanners never saw in converted form."""
        results = _results(
            jupyter=ConverterStatusInfo(
                converted_paths=["converted/ok.py"],
                failed_inputs=[
                    FailedInputInfo(
                        path="[x].ipynb", reason="nbconvert exited with code 1"
                    )
                ],
            )
        )

        assert [(row.name, row.reason) for row in incomplete_converters(results)] == [
            ("jupyter", "could not convert 1 input: [x].ipynb")
        ]

    def test_a_crash_is_reported_ahead_of_its_failed_inputs(self):
        results = _results(
            archive=ConverterStatusInfo(
                failure="OSError: disk full",
                failed_inputs=[FailedInputInfo(path="a.zip", reason="BadZipFile")],
            )
        )

        assert [(row.name, row.reason) for row in incomplete_converters(results)] == [
            ("archive", "OSError: disk full")
        ]

    def test_failed_inputs_read_back_from_a_results_file_still_count(self):
        """A merged or reloaded row carries plain data; the gate reads it the same."""
        row = ConverterStatusInfo.model_validate(
            {"failed_inputs": [{"path": "b.tar", "reason": "ReadError: truncated"}]}
        )

        assert [
            (listed.name, listed.reason)
            for listed in incomplete_converters(_results(archive=row))
        ] == [("archive", "could not convert 1 input: b.tar")]

    def test_failed_inputs_fail_the_exit_code(self, tmp_path):
        results = _results(
            jupyter=ConverterStatusInfo(
                failed_inputs=[FailedInputInfo(path="nb.ipynb", reason="timeout")]
            )
        )

        gate_on = _opts(tmp_path, fail_on_incomplete_scanners=True)
        gate_off = _opts(tmp_path, fail_on_incomplete_scanners=False)
        assert _exit_code(results, gate_on) == 1
        assert _exit_code(results, gate_off) == 0

    @pytest.mark.parametrize(
        "row",
        [
            ConverterStatusInfo(converted_paths=["converted/a.py"]),
            ConverterStatusInfo(converted_paths=[]),
            ConverterStatusInfo(excluded=True, converted_paths=[]),
        ],
        ids=["produced-paths", "nothing-to-convert", "excluded"],
    )
    def test_a_converter_that_ran_or_was_excluded_is_not_listed(self, row):
        assert incomplete_converters(_results(archive=row)) == []

    def test_an_excluded_converter_with_unsatisfied_dependencies_is_not_listed(self):
        """Excluded wins: the run never intended to use it, so its tool is moot."""
        row = ConverterStatusInfo(
            excluded=True, dependencies_satisfied=False, converted_paths=[]
        )

        assert incomplete_converters(_results(jupyter=row)) == []

    def test_no_converter_results_is_not_incomplete(self):
        """A model from a version that recorded nothing must not read as broken."""
        assert incomplete_converters(_results()) == []
        assert incomplete_converters(None) == []


class TestAnUnknownKindReadsAsTool:
    """A results shard can carry a record this version did not write, and a
    converter plugin outside this repository can pass its own kind. Neither may
    turn into a failed load of the whole results: an unknown kind reads as
    "tool", which is never accepted, so it can never waive the completeness
    gate either."""

    def test_a_record_with_an_unknown_kind_validates_as_tool(self):
        from automated_security_helper.models.asharp_model import FailedInputInfo

        record = FailedInputInfo(path="a.ipynb", reason="refused", kind="parse")

        assert record.kind == "tool"

    def test_a_shard_with_an_unknown_kind_loads_and_counts_against_the_gate(self):
        row = ConverterStatusInfo.model_validate(
            {
                "converted_paths": [],
                "failed_inputs": [
                    # accepted rides in from the shard, and must not waive the
                    # gate: only kind "input" can be accepted, and this kind
                    # is not known to be one.
                    {
                        "path": "a.ipynb",
                        "reason": "x",
                        "kind": "zzz",
                        "accepted": True,
                    }
                ],
            }
        )

        (listed,) = incomplete_converters(_results(jupyter=row))
        assert listed.kinds == ("tool",)

    @pytest.mark.parametrize("made", ["constructed", "assigned"])
    def test_a_record_that_never_passed_validation(self, made, capsys):
        """A record can skip the validator: built with model_construct, or with
        its kind assigned after it was made, and ``ash merge`` can carry such
        records. Its unknown kind reads as "tool" in the row, the payload and
        the advice, as the validator reads it."""
        if made == "constructed":
            record = FailedInputInfo.model_construct(
                path="a.ipynb", reason="x", kind="weird", accepted=False
            )
        else:
            record = FailedInputInfo(path="a.ipynb", reason="x")
            record.kind = "weird"  # type: ignore[assignment]
        # The control: the record holds the unknown kind as given.
        assert record.kind == "weird"
        row = ConverterStatusInfo.model_construct(
            converted_paths=[], failed_inputs=[record]
        )

        rows = incomplete_converters(_results(jupyter=row))

        (listed,) = rows
        assert listed.kinds == ("tool",)
        payload = ScanIncompleteness(converters=tuple(rows)).to_payload()
        (entry,) = payload["incomplete_converters"]
        assert entry["failed_input_kinds"] == ["tool"]
        print_incompleteness_message([], rows)
        out = " ".join(capsys.readouterr().out.split())
        assert _TOOL_INPUTS_ADVICE in out, out


class TestTheExitCodeSeesAConverterFailure:
    """The gate, end to end, through ``_compute_exit_code``."""

    def test_a_crashed_converter_exits_one_when_the_gate_is_on(self, tmp_path):
        results = _results(
            jupyter=ConverterStatusInfo(
                converted_paths=[], failure="RuntimeError: boom"
            )
        )

        code = _exit_code(results, _opts(tmp_path, fail_on_incomplete_scanners=True))

        assert code == 1, (
            "every notebook in the repository went unscanned; exit 0 would report "
            "the tree clean on targets that were never produced"
        )

    def test_a_missing_converter_tool_exits_one_when_the_gate_is_on(self, tmp_path):
        results = _results(
            jupyter=ConverterStatusInfo(
                dependencies_satisfied=False, converted_paths=[]
            )
        )

        code = _exit_code(results, _opts(tmp_path, fail_on_incomplete_scanners=True))

        assert code == 1

    def test_the_default_now_fails_a_crashed_converter(self, tmp_path):
        """Inverted by the default flip, and this inversion is the point.

        This asserted exit 0 with the docstring "the shipped default is off, so no
        currently-passing run changes". That premise is what the flip removes.

        The inversion is worth reading rather than skimming, because it is the
        clearest evidence of a blast radius the flip's own diff does not show. The
        converter arm is nested inside ``fail_on_incomplete_scanners``, so flipping
        that default turns converter incompleteness into a non-zero exit **in the
        same commit** -- without the flip touching ``convert_phase.py``, reading
        ``converter_results``, or mentioning converters anywhere. A reader of that
        diff alone would not know this changed.

        ``test_opting_out_explicitly_leaves_the_verdict_alone`` below is the control
        that keeps this honest: the escape hatch still works, so what changed is the
        default and not the mechanism.
        """
        results = _results(
            jupyter=ConverterStatusInfo(
                converted_paths=[], failure="RuntimeError: boom"
            )
        )

        assert _exit_code(results, _opts(tmp_path)) == 1

    def test_opting_out_explicitly_leaves_the_verdict_alone(self, tmp_path):
        results = _results(
            jupyter=ConverterStatusInfo(
                converted_paths=[], failure="RuntimeError: boom"
            )
        )

        code = _exit_code(results, _opts(tmp_path, fail_on_incomplete_scanners=False))

        assert code == 0

    def test_an_excluded_converter_does_not_trip_the_gate(self, tmp_path):
        """The negative control, and the one that keeps the gate usable.

        Every converter is excluded on a run that disabled them all, which is a
        supported configuration; a gate that failed there would make the flag
        unusable for anyone who turned conversion off.

        The jupyter row carries ``dependencies_satisfied=False`` alongside
        ``excluded``, which is what a host with conversion turned off and no nbconvert
        installed actually records. Without that second signal this assertion holds
        for a gate that ignores ``excluded`` entirely, and so would not notice it
        being dropped.
        """
        results = _results(
            jupyter=ConverterStatusInfo(
                excluded=True, dependencies_satisfied=False, converted_paths=[]
            ),
            archive=ConverterStatusInfo(excluded=True, converted_paths=[]),
        )

        code = _exit_code(results, _opts(tmp_path, fail_on_incomplete_scanners=True))

        assert code == 0

    def test_a_healthy_conversion_does_not_trip_the_gate(self, tmp_path):
        results = _results(
            jupyter=ConverterStatusInfo(converted_paths=["converted/nb.py"]),
            archive=ConverterStatusInfo(converted_paths=[]),
        )

        code = _exit_code(results, _opts(tmp_path, fail_on_incomplete_scanners=True))

        assert code == 0

    def test_the_gate_is_independent_of_fail_on_findings(self, tmp_path):
        """An operator who turned findings-gating off still gets told this.

        ``_compute_exit_code`` returns early once ``fail_on_findings`` is false, so
        a check placed after that return would be silently dead for exactly the
        people who run with it off.
        """
        results = _results(
            jupyter=ConverterStatusInfo(
                converted_paths=[], failure="RuntimeError: boom"
            )
        )
        opts = _opts(tmp_path, fail_on_incomplete_scanners=True, fail_on_findings=False)

        assert _exit_code(results, opts) == 1

    def test_the_failure_reaches_the_log(self, tmp_path, caplog):
        """The exit code says "something", the log has to say which converter."""
        results = _results(
            jupyter=ConverterStatusInfo(
                converted_paths=[], failure="RuntimeError: nbconvert is not on PATH"
            )
        )

        with caplog.at_level(logging.ERROR):
            _exit_code(results, _opts(tmp_path, fail_on_incomplete_scanners=True))

        assert "jupyter" in caplog.text
        assert "nbconvert is not on PATH" in caplog.text


class TestAnUnavailableConverterWithNothingToConvert:
    """An absent tool costs coverage only if there was something for it to do.

    WHAT THIS FIXES, MEASURED
    -------------------------
    ``--mode nix`` supplies scanner binaries through the flake's dev shell and exports
    ``ASH_OFFLINE=YES``, which correctly refuses ``uv tool install nbconvert``. So the
    jupyter converter is unavailable on every Nix-mode run. Both nix CI legs on #654
    therefore exited 1 -- on a fixture holding one CloudFormation template, one Python
    file and one package.json, and **no notebooks at all**. Nothing went unscanned and
    the run still failed.

    That is the same defect shape as a scanner counting a file it was never going to
    evaluate: a completeness gate firing over a file class that is not present.

    WHY THIS IS NOT THE CARVE-OUT THAT WAS REJECTED
    ----------------------------------------------
    Exempting converters from the gate was the other option and would let ASH report
    success on a tree whose notebooks were never scanned -- the precise defect the gate
    exists to catch. So the exemption is not "converters", it is "nothing to convert",
    and it turns on a positive claim rather than on missing information:
    ``candidate_input_count`` is answered WITHOUT the converter's tool, which is what
    makes it available for a converter that never ran.

    ``test_the_gate_still_fires_when_notebooks_go_unconverted`` is the control that keeps
    this honest, and it is the one to read first.
    """

    def test_nothing_to_convert_is_not_incomplete_conversion(self, tmp_path):
        """The measured CI case: unavailable converter, zero candidate inputs."""
        results = _results(
            jupyter=ConverterStatusInfo(
                dependencies_satisfied=False,
                candidate_inputs=0,
                converted_paths=[],
            )
        )

        assert incomplete_converters(results) == []
        assert (
            _exit_code(results, _opts(tmp_path, fail_on_incomplete_scanners=True)) == 0
        )

    def test_the_gate_still_fires_when_notebooks_go_unconverted(self, tmp_path):
        """The control. Inputs existed and none were converted, so coverage was lost.

        Without this the test above could be satisfied by exempting converters wholesale,
        which is the carve-out that was considered and rejected.
        """
        results = _results(
            jupyter=ConverterStatusInfo(
                dependencies_satisfied=False,
                candidate_inputs=2,
                converted_paths=[],
            )
        )

        listed = incomplete_converters(results)
        assert [row[0] for row in listed] == ["jupyter"]
        assert (
            _exit_code(results, _opts(tmp_path, fail_on_incomplete_scanners=True)) == 1
        )

    def test_a_converter_reporting_no_count_is_still_incomplete(self, tmp_path):
        """Missing information must not exempt anything.

        ``None`` covers three real cases at once: a converter that has not implemented
        the count, one whose count raised, and a results file written by a version
        predating the field -- ``ash merge`` reads shard results from whatever ASH wrote
        each one. All three keep the strict answer, so adding the field cannot have
        quietly relaxed any converter that did not opt in.
        """
        results = _results(
            jupyter=ConverterStatusInfo(
                dependencies_satisfied=False,
                candidate_inputs=None,
                converted_paths=[],
            )
        )

        listed = incomplete_converters(results)
        assert [row[0] for row in listed] == ["jupyter"]
        assert (
            _exit_code(results, _opts(tmp_path, fail_on_incomplete_scanners=True)) == 1
        )

    def test_a_boolean_count_does_not_exempt_an_unvalidated_row(self, tmp_path):
        """``bool`` is an ``int`` subclass and ``False == 0``, so the check excludes it.

        Not reachable through ``ConverterStatusInfo``: the field is ``int | None`` and
        pydantic coerces ``False`` to ``0`` on validation, which legitimately means "no
        candidates". This measures the un-validated path instead --
        ``incomplete_converters`` reads rows with ``getattr``, so what it is handed is
        whatever the caller assembled, and ``ash merge`` assembles from shard files.

        An earlier version of this test asserted the bool survived validation. It did
        not, and the test failed for that reason rather than finding a defect, so it is
        written against the path where the guard is actually load-bearing.
        """
        row = SimpleNamespace(
            excluded=False,
            failure=None,
            dependencies_satisfied=False,
            candidate_inputs=False,
            converted_paths=[],
        )
        results = _results(jupyter=row)

        listed = incomplete_converters(results)
        assert [row[0] for row in listed] == ["jupyter"], (
            "a boolean count must not exempt a row; bool is an int subclass so a bare "
            "`== 0` would read False as 'nothing to convert'"
        )

    def test_a_row_that_converted_paths_is_not_exempted_by_a_zero_count(self):
        """ "Never ran" is the gate's inference, not the writer's promise.

        ``ash merge`` reads rows from any producer, and a row's fields are what it
        says about its own run, not what this phase's dependency check would have
        said. A row with converted paths describes a converter that ran; a count of
        0 beside it answers a question that was not asked, so the row keeps the
        strict answer it had before the count existed.
        """
        results = _results(
            jupyter=ConverterStatusInfo(
                dependencies_satisfied=False,
                candidate_inputs=0,
                converted_paths=["converted/one.py"],
            )
        )

        assert [row[0] for row in incomplete_converters(results)] == ["jupyter"]

    @pytest.mark.parametrize(
        "sign",
        [
            pytest.param(
                {"failed_inputs": [SimpleNamespace(kind="input", accepted=True)]},
                id="an-accepted-failed-input",
            ),
            pytest.param(
                {"refused_inputs": [SimpleNamespace(limit=None)]},
                id="a-refusal-without-a-limit",
            ),
        ],
    )
    def test_a_row_with_another_sign_of_a_run_is_not_exempted_either(self, sign):
        """The two records that do not list a row by themselves (an accepted input
        loss, a refusal that names no limit) still show the converter ran."""
        # The sign replaces the empty default of its own field: passing both to
        # SimpleNamespace named the keyword twice and raised before the gate ran.
        fields = {
            "excluded": False,
            "failure": None,
            "dependencies_satisfied": False,
            "candidate_inputs": 0,
            "converted_paths": [],
            "failed_inputs": [],
            "refused_inputs": [],
        }
        fields.update(sign)
        row = SimpleNamespace(**fields)

        assert [row[0] for row in incomplete_converters(_results(jupyter=row))] == [
            "jupyter"
        ]


class TestAnUnavailableConverterIsListedWithItsOwnReason:
    """The row carries ``dependency_unavailable_reason`` (the convert phase writes it
    on every row whose dependencies are unsatisfied); the gate used to print a fixed
    line in its place, so the console named the loss and not its cause."""

    def test_the_rows_own_reason_is_listed(self):
        results = _results(
            jupyter=ConverterStatusInfo(
                dependencies_satisfied=False,
                candidate_inputs=2,
                converted_paths=[],
                dependency_unavailable_reason=(
                    "nbconvert could not be installed through uv"
                ),
            )
        )

        assert incomplete_converters(results) == [
            IncompleteConverter(
                "jupyter", "nbconvert could not be installed through uv"
            )
        ]

    def test_a_row_without_a_reason_keeps_the_fixed_line(self):
        """Control: a row written before the field existed, or assembled without it."""
        results = _results(
            jupyter=ConverterStatusInfo(
                dependencies_satisfied=False, candidate_inputs=2, converted_paths=[]
            )
        )

        assert incomplete_converters(results) == [
            IncompleteConverter("jupyter", "dependencies unavailable, so it never ran")
        ]


class TestTheConverterArmHasItsOwnExitMessage:
    """The converter arm used to print "Exiting due to exception during ASH scan".

    Nothing had raised. The message selector handled the scanner arm and fell through to
    an exception line for everything else, so both nix legs exited 1 claiming an exception
    that did not exist -- and a reader went through 1572 log lines looking for a traceback.
    The only record of the real cause was a ``logger.error`` call seventy lines earlier.
    """

    def test_the_message_names_the_converter_and_not_an_exception(self, capsys):
        print_incompleteness_message(
            [], [("jupyter", "dependencies unavailable, so it never ran")]
        )
        out = capsys.readouterr().out

        assert "conversion was incomplete" in out
        assert "jupyter" in out
        assert "exception" not in out.lower(), (
            "the converter arm must not claim an exception occurred; nothing raised, and "
            "that wording sent a reader hunting a traceback that was never there"
        )

    def test_the_scanner_arm_keeps_precedence_when_both_are_present(self, capsys):
        """Both lists non-empty prints the scanner message, not the converter one.

        A scanner that did not run is the more specific finding, and an environment
        missing a scanner's tool is often missing a converter's too, so the converter
        line would bury the more serious one.
        """
        print_incompleteness_message(
            [("cdk-nag", "MISSING")],
            [("jupyter", "dependencies unavailable, so it never ran")],
        )
        out = capsys.readouterr().out

        assert "the scan was incomplete" in out
        assert "cdk-nag" in out
        assert "conversion was incomplete" not in out

    def test_neither_list_still_reports_an_exception(self, capsys):
        """The arm that was over-reported must stay reachable for its real case.

        Exit 1 with no incompleteness recorded genuinely is a crash, and that is the one
        situation where this wording is correct.
        """
        print_incompleteness_message([], [])
        out = capsys.readouterr().out

        assert "exception" in out.lower()


def test_a_bracketed_file_name_is_printed_as_it_is(monkeypatch):
    """Rich reads ``[x]`` as markup; a converter row names files like that."""
    import io

    from rich.console import Console

    from automated_security_helper.interactions import run_ash_scan

    buffer = io.StringIO()
    console = Console(file=buffer, width=200, color_system=None)
    monkeypatch.setattr(run_ash_scan, "print", lambda *args, **_: console.print(*args))

    run_ash_scan.print_incompleteness_message(
        [], [("jupyter", "could not convert 1 input: notebooks/[x].ipynb")]
    )

    assert "jupyter: could not convert 1 input: notebooks/[x].ipynb" in (
        buffer.getvalue()
    )


def test_the_advice_covers_files_that_could_not_be_converted(monkeypatch):
    """A corrupt archive is not fixed by installing a tool."""
    from automated_security_helper.interactions import run_ash_scan

    printed: list = []
    monkeypatch.setattr(
        run_ash_scan, "print", lambda *args, **_: printed.append(" ".join(args))
    )

    run_ash_scan.print_incompleteness_message(
        [], [("archive", "could not convert 1 input: data.zip")]
    )

    advice = " ".join(printed)
    assert (
        "fix the files it could not convert or exclude them with ignore_paths" in advice
    )


_INPUTS_ADVICE = "fix the listed inputs or add them to ignore_paths"
_TOOL_ADVICE = "Install the converter's tool"


def _failed_inputs_row() -> ConverterStatusInfo:
    from automated_security_helper.models.asharp_model import FailedInputInfo

    return ConverterStatusInfo(
        converted_paths=["converted/b.py"],
        failed_inputs=[
            FailedInputInfo(path="a.ipynb", reason="nbconvert exited with code 1")
        ],
    )


class TestTheAdviceFitsWhatWentWrong:
    """A converter that ran and could not convert some of its inputs is listed
    too, and its tool is installed: the advice for it is to fix those inputs or
    ignore them, not to install the tool. The advice for a converter that never
    ran stays as it is."""

    def _printed(self, capsys, **rows) -> str:
        print_incompleteness_message([], incomplete_converters(_results(**rows)))
        return " ".join(capsys.readouterr().out.split())

    def test_failed_inputs_are_not_told_to_install_the_tool(self, capsys):
        """The row's records are tool failures, and those come two ways: the
        tool never ran (uv could not run it, the launch failed), or it ran and
        failed on that input (an exit code, a timeout, no output written) -- as
        the structure check leaves structurally broken notebooks to nbconvert.
        Each printed reason says which, so the advice names both remedies and
        never claims that fixing or ignoring the files does nothing: for a
        rejected input, fixing it or ignoring it is exactly what clears the
        gate."""
        out = self._printed(capsys, jupyter=_failed_inputs_row())

        assert "a.ipynb" in out, out
        assert _TOOL_INPUTS_ADVICE in out, out
        assert "fix that input or add it to ignore_paths" in out, out
        assert "does not scan" not in out, out
        assert _INPUTS_ADVICE not in out, out
        assert _TOOL_ADVICE not in out, out

    @pytest.mark.parametrize(
        "row",
        [
            ConverterStatusInfo(dependencies_satisfied=False, converted_paths=[]),
            ConverterStatusInfo(converted_paths=[], failure="RuntimeError: gone"),
        ],
        ids=["unavailable", "failed"],
    )
    def test_a_converter_that_did_not_run_is_told_to_install_its_tool(
        self, capsys, row
    ):
        out = self._printed(capsys, jupyter=row)

        assert _TOOL_ADVICE in out, out
        assert _INPUTS_ADVICE not in out, out

    def test_a_ran_converter_and_an_absent_one_get_their_own_advice(self, capsys):
        out = self._printed(
            capsys,
            jupyter=_failed_inputs_row(),
            archive=ConverterStatusInfo(
                dependencies_satisfied=False, converted_paths=[]
            ),
        )

        assert _TOOL_INPUTS_ADVICE in out, out
        assert _TOOL_ADVICE in out, out

    def test_a_long_list_names_five_and_counts_the_rest(self):
        from automated_security_helper.models.asharp_model import FailedInputInfo

        row = ConverterStatusInfo(
            converted_paths=[],
            failed_inputs=[
                FailedInputInfo(
                    path=f"n{i}.ipynb", reason="nbconvert exited with code 1"
                )
                for i in range(7)
            ],
        )

        (listed,) = incomplete_converters(_results(jupyter=row))

        assert listed[1] == (
            "could not convert 7 inputs: n0.ipynb, n1.ipynb, n2.ipynb, n3.ipynb, "
            "n4.ipynb and 2 more"
        )

    def test_a_failure_wins_over_failed_inputs(self, capsys):
        """A row with both lists the failure, the cause of the rest, and gets
        the advice for a converter that did not run."""
        row = _failed_inputs_row()
        row.failure = "RuntimeError: the converter raised"

        (listed,) = incomplete_converters(_results(jupyter=row))
        out = self._printed(capsys, jupyter=row)

        assert listed[1] == "RuntimeError: the converter raised"
        assert _TOOL_ADVICE in out, out
        assert _INPUTS_ADVICE not in out, out

    def test_a_listed_reason_is_still_the_text_it_was(self):
        """The row carries its kinds beside the reason, and the reason is the
        same text: the MCP replies and every caller that prints it read a str."""
        (listed,) = incomplete_converters(_results(jupyter=_failed_inputs_row()))

        assert listed[0] == "jupyter"
        assert listed[1] == "could not convert 1 input: a.ipynb"
        assert isinstance(listed[1], str)


_SUPPRESSION_ADVICE = "ash-unconverted-input"
_TOOL_INPUTS_ADVICE = "make the converter's tool able to run"


class TestTheAdviceNamesEachRecordKind:
    """A row carries the kinds of its non-accepted failed inputs, as data
    rather than as the reason's type: any string operation or JSON round trip
    keeps it, and the MCP payload can pass it to clients. The advice is chosen
    per kind. A converter whose tool failed on its inputs ("uv could not run
    nbconvert", say) is not told to fix the inputs, and the input-error advice
    names the acceptance a reviewed file can take."""

    def _row(self, **record_fields) -> ConverterStatusInfo:
        return ConverterStatusInfo(
            converted_paths=[],
            failed_inputs=[
                FailedInputInfo(path="a.ipynb", reason="it failed", **record_fields)
            ],
        )

    def test_rows_carry_the_kinds_of_their_failed_inputs(self):
        rows = incomplete_converters(
            _results(
                jupyter=self._row(kind="input"),
                bundle=self._row(kind="tool"),
                archive=ConverterStatusInfo(
                    converted_paths=[], failure="RuntimeError: gone"
                ),
            )
        )

        kinds = {row[0]: tuple(getattr(row, "kinds", None) or ()) for row in rows}
        assert kinds == {"jupyter": ("input",), "bundle": ("tool",), "archive": ()}

    def test_input_errors_advice_names_the_acceptance(self, capsys):
        print_incompleteness_message(
            [], incomplete_converters(_results(jupyter=self._row(kind="input")))
        )
        out = " ".join(capsys.readouterr().out.split())

        assert _INPUTS_ADVICE in out, out
        assert _SUPPRESSION_ADVICE in out, out
        assert _TOOL_ADVICE not in out, out

    def test_tool_failures_on_inputs_are_not_told_to_fix_the_inputs(self, capsys):
        """The tool ran against the input and failed, or could not be run on
        it: fixing the file or ignoring it does not scan it, and a suppression
        cannot accept it, so the advice is about the tool."""
        print_incompleteness_message(
            [], incomplete_converters(_results(jupyter=self._row(kind="tool")))
        )
        out = " ".join(capsys.readouterr().out.split())

        assert _INPUTS_ADVICE not in out, out
        assert _SUPPRESSION_ADVICE not in out, out
        assert _TOOL_INPUTS_ADVICE in out, out

    def test_a_mix_of_kinds_gets_both_pieces_of_advice(self, capsys):
        row = ConverterStatusInfo(
            converted_paths=[],
            failed_inputs=[
                FailedInputInfo(path="a.ipynb", reason="x", kind="input"),
                FailedInputInfo(path="b.ipynb", reason="y", kind="tool"),
            ],
        )
        print_incompleteness_message([], incomplete_converters(_results(jupyter=row)))
        out = " ".join(capsys.readouterr().out.split())

        assert _INPUTS_ADVICE in out, out
        assert _TOOL_INPUTS_ADVICE in out, out

    def test_the_payload_carries_each_rows_kinds(self):
        """A JSON round trip of the payload keeps the kind, so an MCP client
        can choose its own advice the way the console does."""
        incompleteness = ScanIncompleteness(
            converters=tuple(
                incomplete_converters(_results(jupyter=self._row(kind="input")))
            )
        )

        payload = incompleteness.to_payload()
        (entry,) = payload["incomplete_converters"]
        assert entry["converter"] == "jupyter"
        assert entry["failed_input_kinds"] == ["input"]

    def test_the_gate_does_not_trust_accepted_on_a_tool_failure(self):
        """A results file can come from any producer (ash merge reads shard
        files from whatever ASH wrote them), so accepted waives the gate only
        together with kind "input": the writer never accepts a tool failure,
        and the reader does not either."""
        row = self._row(kind="tool", accepted=True)

        listed = incomplete_converters(_results(jupyter=row))

        assert listed != [], "an accepted tool failure passed the completeness gate"
