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
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
    incomplete_converters,
)
from automated_security_helper.models.asharp_model import ConverterStatusInfo

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
            ("jupyter", "RuntimeError: nbconvert is not on PATH")
        ]

    def test_a_converter_with_unsatisfied_dependencies_is_listed(self, tmp_path):
        results = _results(
            jupyter=ConverterStatusInfo(
                dependencies_satisfied=False, converted_paths=[]
            )
        )

        listed = incomplete_converters(results)
        assert [name for name, _ in listed] == ["jupyter"]
        assert "dependencies" in listed[0][1]

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
