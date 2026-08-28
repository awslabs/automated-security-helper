# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``fail_on_incomplete_scanners``: the exit code has to be able to say "nothing was checked".

Why these tests exist
---------------------
``_compute_exit_code`` derived the verdict from finding counts alone. A run where
every selected scanner failed to start therefore exited 0 -- the same code as a
clean scan -- because zero scanners produced zero findings. Measured on this
tree: ``ash scan --scanners bandit`` against a one-file fixture reports
``cdk-nag``, ``cfn-nag``, ``grype`` and ``syft`` as MISSING and still exits 0, and
a deployed run with five of ten scanners MISSING or ERROR exited 0 on a
repository that a working scan flags at HIGH.

The distinction that makes the fix correct
------------------------------------------
``ScannerStatus`` has five members and only two of them mean "selected and did
not complete":

* ``ERROR``   -- ran and failed.
* ``MISSING`` -- was selected, its dependencies were unavailable, never ran.
* ``SKIPPED`` -- was not selected at all. **Must stay exit 0.** This is the
  mechanism sharding itself uses: ``core.sharding.exclusions_for_shard`` excludes
  every scanner another shard owns, and those land as SKIPPED in this shard's
  results. A check that treated SKIPPED as incomplete would fail every shard of
  every sharded scan, which is why ``test_skipped_scanners_never_trip_the_gate``
  is here and not merely implied.
* ``PASSED`` / ``FAILED`` -- ran to completion, verdict already carried by the
  finding count.

Independence from ``fail_on_findings`` is asserted directly. The two knobs answer
different questions -- "was anything found" versus "did what I asked for run" --
and ``_compute_exit_code`` returns early when ``fail_on_findings`` is false, so a
check placed after that early return would be silently disabled for every
operator who runs with findings-gating off. That is the one wiring mistake that
would leave the defect in place while every other test still passed.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.enums import RunMode, ScannerStatus
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _compute_exit_code,
)

_MODULE = "automated_security_helper.interactions.run_ash_scan"


def _metric(scanner_name: str, status: str, actionable: int = 0):
    """One entry as ``get_unified_scanner_metrics`` would return it.

    A MagicMock rather than a real ``ScannerMetrics`` so a test can pin a status
    string that the calculator would never derive together with that finding
    count -- the point is to exercise the exit-code rule, not the calculator.
    """
    metric = MagicMock()
    metric.scanner_name = scanner_name
    metric.status = status
    metric.actionable = actionable
    return metric


def _opts(tmp_path, **kwargs) -> ScanOptions:
    return ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        **kwargs,
    )


class TestIncompleteScannersTripTheGate:
    """A selected scanner that did not complete must not read as a clean scan."""

    @pytest.mark.parametrize(
        "status", [ScannerStatus.MISSING.value, ScannerStatus.ERROR.value]
    )
    def test_incomplete_scanner_with_no_findings_exits_one(self, tmp_path, status):
        """Zero findings plus one incomplete scanner is exit 1, not exit 0.

        This is the defect in its smallest form: nothing was found because
        nothing ran.
        """
        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[_metric("cdk-nag", status)],
        ):
            code = _compute_exit_code(results, opts)

        assert code == 1, (
            f"a scanner in {status} means the scan is incomplete; exit 0 would be "
            f"indistinguishable from a clean run"
        )

    def test_default_leaves_incomplete_scanners_at_exit_zero(self, tmp_path):
        """Default off. Flipping it would redden every CI run that lacks a tool.

        Four of this tree's ten default scanners are MISSING on a stock
        workstation, so the default has to stay as it was.
        """
        opts = _opts(tmp_path)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[
                _metric("cdk-nag", ScannerStatus.MISSING.value),
                _metric("grype", ScannerStatus.ERROR.value),
            ],
        ):
            code = _compute_exit_code(results, opts)

        assert code == 0

    def test_skipped_scanners_never_trip_the_gate(self, tmp_path):
        """SKIPPED is "not selected", which is how a shard excludes its siblings.

        Every shard of an n-way split records n-1 scanner sets as SKIPPED. If
        SKIPPED counted as incomplete, turning the knob on would fail all n
        shards of a healthy sharded scan.
        """
        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[
                _metric("bandit", ScannerStatus.PASSED.value),
                _metric("semgrep", ScannerStatus.SKIPPED.value),
                _metric("checkov", ScannerStatus.SKIPPED.value),
            ],
        ):
            code = _compute_exit_code(results, opts)

        assert code == 0, "SKIPPED means deliberately not selected, not incomplete"

    def test_all_scanners_complete_exits_zero(self, tmp_path):
        """The knob on, nothing incomplete, nothing found: still a clean scan."""
        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[
                _metric("bandit", ScannerStatus.PASSED.value),
                _metric("semgrep", ScannerStatus.PASSED.value),
            ],
        ):
            code = _compute_exit_code(results, opts)

        assert code == 0


class TestIndependenceFromFailOnFindings:
    """The two knobs answer different questions and must not gate each other."""

    def test_fail_on_findings_false_still_reports_an_incomplete_scan(self, tmp_path):
        """``fail_on_findings: false`` must not disable the completeness gate.

        ``_compute_exit_code`` returns 0 early when findings-gating is off. A
        completeness check placed after that return would be dead for exactly
        the operators who set it.
        """
        opts = _opts(tmp_path, fail_on_findings=False, fail_on_incomplete_scanners=True)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[_metric("grype", ScannerStatus.ERROR.value, actionable=0)],
        ):
            code = _compute_exit_code(results, opts)

        assert code == 1, (
            "fail_on_findings governs findings, not whether the scan ran; the "
            "completeness gate has to be checked before the early return"
        )

    def test_incomplete_scan_outranks_actionable_findings(self, tmp_path):
        """Both conditions true reports 1, not 2.

        1 is ASH's "error during execution" code and the honest verdict: the
        findings that were reported are real, but the set is known to be
        partial. Reporting 2 would tell a reviewer that fixing the listed
        findings clears the scan, when several scanners never ran.
        """
        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[
                _metric("bandit", ScannerStatus.FAILED.value, actionable=7),
                _metric("cdk-nag", ScannerStatus.MISSING.value),
            ],
        ):
            code = _compute_exit_code(results, opts)

        assert code == 1

    def test_findings_alone_still_exit_two_with_the_knob_on(self, tmp_path):
        """Turning the knob on must not disturb the existing findings verdict."""
        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[_metric("bandit", ScannerStatus.FAILED.value, actionable=3)],
        ):
            code = _compute_exit_code(results, opts)

        assert code == 2


class TestResolutionPrecedence:
    """CLI beats config beats off, mirroring ``fail_on_findings``."""

    def test_config_value_applies_when_cli_unset(self, tmp_path):
        opts = _opts(tmp_path)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[_metric("syft", ScannerStatus.MISSING.value)],
        ):
            code = _compute_exit_code(
                results, opts, config_fail_on_incomplete_scanners=True
            )

        assert code == 1

    def test_cli_false_overrides_config_true(self, tmp_path):
        """An operator who passes ``--no-fail-on-incomplete-scanners`` wins."""
        opts = _opts(tmp_path, fail_on_incomplete_scanners=False)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[_metric("syft", ScannerStatus.MISSING.value)],
        ):
            code = _compute_exit_code(
                results, opts, config_fail_on_incomplete_scanners=True
            )

        assert code == 0

    def test_cli_true_overrides_config_false(self, tmp_path):
        """``--fail-on-incomplete-scanners`` beats ``: false`` in the config."""
        opts = _opts(tmp_path, fail_on_incomplete_scanners=True)
        results = MagicMock()
        results.sarif = None

        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[_metric("syft", ScannerStatus.MISSING.value)],
        ):
            code = _compute_exit_code(
                results, opts, config_fail_on_incomplete_scanners=False
            )

        assert code == 1


class TestIncompleteScannerReport:
    """The failure has to name which scanners and which status.

    "exit 1" on its own sends an operator to the wrong place: the generic exit-1
    message in ``run_ash_scan`` says an exception occurred, which is not what
    happened.
    """

    def test_helper_lists_only_incomplete_scanners_with_statuses(self):
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_scanners,
        )

        results = MagicMock()
        with patch(
            f"{_MODULE}.get_unified_scanner_metrics",
            return_value=[
                _metric("bandit", ScannerStatus.PASSED.value),
                _metric("cdk-nag", ScannerStatus.MISSING.value),
                _metric("semgrep", ScannerStatus.SKIPPED.value),
                _metric("grype", ScannerStatus.ERROR.value),
            ],
        ):
            listed = incomplete_scanners(results)

        assert listed == [
            ("cdk-nag", ScannerStatus.MISSING.value),
            ("grype", ScannerStatus.ERROR.value),
        ]

    def test_helper_is_empty_for_no_results(self):
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_scanners,
        )

        assert incomplete_scanners(None) == []


class TestConfigFileResolution:
    """The YAML field has to be readable without building the orchestrator."""

    def test_reads_fail_on_incomplete_scanners_from_config_file(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            _resolve_config_fail_on_incomplete_scanners,
        )

        source = tmp_path / "src"
        source.mkdir()
        (source / ".ash.yaml").write_text(
            "project_name: gate-test\nfail_on_incomplete_scanners: true\n",
            encoding="utf-8",
        )

        opts = ScanOptions(source_dir=source, output_dir=tmp_path / "out")
        assert _resolve_config_fail_on_incomplete_scanners(opts) is True

    def test_absent_field_resolves_to_the_models_default(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            _resolve_config_fail_on_incomplete_scanners,
        )

        source = tmp_path / "src"
        source.mkdir()
        (source / ".ash.yaml").write_text("project_name: gate-test\n", encoding="utf-8")

        opts = ScanOptions(source_dir=source, output_dir=tmp_path / "out")
        assert _resolve_config_fail_on_incomplete_scanners(opts) is False

    def test_no_config_file_resolves_to_none(self, tmp_path):
        from automated_security_helper.interactions.run_ash_scan import (
            _resolve_config_fail_on_incomplete_scanners,
        )

        source = tmp_path / "src"
        source.mkdir()
        opts = ScanOptions(source_dir=source, output_dir=tmp_path / "out")
        assert _resolve_config_fail_on_incomplete_scanners(opts) is None


class TestConfigModelAndValidator:
    """The field has to exist on the model and be accepted by ``ash config``."""

    def test_config_field_defaults_to_false(self):
        from automated_security_helper.config.ash_config import AshConfig

        assert AshConfig(project_name="x").fail_on_incomplete_scanners is False

    def test_validator_accepts_the_new_top_level_field(self):
        from automated_security_helper.config.config_validator import ConfigValidator

        assert (
            "fail_on_incomplete_scanners" in ConfigValidator.VALID_TOP_LEVEL_FIELDS
        ), (
            "an unlisted top-level field makes 'ash config validate' reject a "
            "config that 'ash scan' accepts"
        )


class TestContainerModeForwarding:
    """The container runs this same CLI, so the flag has to reach it."""

    @pytest.mark.parametrize(
        "value,expected_flag",
        [
            (True, "--fail-on-incomplete-scanners"),
            (False, "--no-fail-on-incomplete-scanners"),
        ],
    )
    def test_flag_is_forwarded_into_the_container(self, tmp_path, value, expected_flag):
        from automated_security_helper.core.enums import ExecutionStrategy
        from automated_security_helper.interactions.run_ash_container import (
            _assemble_run_command,
        )

        cmd = _assemble_run_command(
            oci_command_prefix=[],
            resolved_oci_runner="finch",
            image_name="ash:latest",
            source_dir=tmp_path / "src",
            output_dir=tmp_path / "out",
            offline=False,
            debug=False,
            color=False,
            quiet=True,
            progress=False,
            verbose=False,
            simple=False,
            python_based_plugins_only=False,
            cleanup=False,
            inspect=False,
            fail_on_findings=None,
            fail_on_incomplete_scanners=value,
            phases=[],
            scanners=[],
            exclude_scanners=[],
            output_formats=[],
            config=None,
            config_overrides=[],
            existing_results=None,
            ash_plugin_modules=[],
            strategy=ExecutionStrategy.PARALLEL,
            ctx=None,
        )

        assert expected_flag in cmd

    def test_unset_forwards_neither_flag(self, tmp_path):
        from automated_security_helper.core.enums import ExecutionStrategy
        from automated_security_helper.interactions.run_ash_container import (
            _assemble_run_command,
        )

        cmd = _assemble_run_command(
            oci_command_prefix=[],
            resolved_oci_runner="finch",
            image_name="ash:latest",
            source_dir=tmp_path / "src",
            output_dir=tmp_path / "out",
            offline=False,
            debug=False,
            color=False,
            quiet=True,
            progress=False,
            verbose=False,
            simple=False,
            python_based_plugins_only=False,
            cleanup=False,
            inspect=False,
            fail_on_findings=None,
            fail_on_incomplete_scanners=None,
            phases=[],
            scanners=[],
            exclude_scanners=[],
            output_formats=[],
            config=None,
            config_overrides=[],
            existing_results=None,
            ash_plugin_modules=[],
            strategy=ExecutionStrategy.PARALLEL,
            ctx=None,
        )

        assert "--fail-on-incomplete-scanners" not in cmd
        assert "--no-fail-on-incomplete-scanners" not in cmd


class TestRunAshScanPlumbing:
    """``run_ash_scan`` has to hand the resolved value to ``_compute_exit_code``."""

    def test_config_value_reaches_compute_exit_code(self, tmp_path):
        from automated_security_helper.interactions import run_ash_scan as mod
        from automated_security_helper.models.asharp_model import AshAggregatedResults

        results = MagicMock(spec=AshAggregatedResults)
        results.sarif = None
        captured: dict = {}

        def spy(results_arg, opts_arg, *args, **kwargs):
            captured["kwargs"] = kwargs
            captured["args"] = args
            return 0

        with patch.object(
            mod, "_resolve_config_fail_on_incomplete_scanners", return_value=True
        ):
            with patch.object(
                mod, "_resolve_config_fail_on_findings", return_value=None
            ):
                with patch.object(mod, "_run_container_mode", return_value=results):
                    with patch.object(mod, "_compute_exit_code", side_effect=spy):
                        with patch.object(
                            mod, "_setup_logger", return_value=MagicMock()
                        ):
                            mod.run_ash_scan(
                                source_dir=tmp_path / "src",
                                output_dir=tmp_path / "out",
                                mode=RunMode.container,
                                show_summary=False,
                            )

        assert (
            captured["kwargs"].get("config_fail_on_incomplete_scanners") is True
            or True in captured["args"]
        ), (
            "the resolved config value must reach _compute_exit_code, or a YAML "
            f"setting is silently ignored; got args={captured['args']} "
            f"kwargs={captured['kwargs']}"
        )
