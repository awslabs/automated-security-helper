# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--shard-index``/``--shard-count`` from the command line to the scan phase.

What these tests are for
------------------------
The partition itself is covered by ``tests/unit/core/test_sharding.py``, and its
application inside the phase by
``tests/unit/core/phases/test_scan_phase_sharding.py``. Neither touches the four
hops between the CLI and ``ScanPhase._execute_phase``, and a break in any one of
them fails in the worst available way: the flags are accepted, the scan runs and
exits 0, every shard runs every scanner, and because merging deliberately does
not deduplicate, the merged report counts each finding once per shard. Nothing in
the output says so.

So the central test here drives the real chain -- ``cli.scan`` ->
``interactions.run_ash_scan`` -> ``core.orchestrator`` ->
``core.execution_engine`` -> ``ScanPhase`` -- with only ``_execute_phase``
replaced, and asserts on the keyword arguments that method actually received.
Asserting against a mock of any intermediate layer would agree with a chain that
dropped the pair at any hop below it.

Refusals assert on the message as well as the exit code. An exit code alone would
also pass for a scan that failed for an unrelated reason, and the point of
refusing is that the operator learns which of the five ways their matrix is wrong.

The provenance tests read the results file back off disk rather than inspecting
the in-memory model. ``ash merge`` has only the file, and a field that serialises
but does not deserialise would leave merge with no provenance -- which
``verify_shard_coverage`` cannot distinguish from a scan that was never sharded.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import typer
from typer.testing import CliRunner

from automated_security_helper.cli.scan import run_ash_scan_cli_command
from automated_security_helper.core.enums import ExecutionPhase, RunMode
from automated_security_helper.core.sharding import ShardAssignment
from automated_security_helper.interactions.run_ash_scan import run_ash_scan
from automated_security_helper.models.asharp_model import AshAggregatedResults


# Every way a shard selection can be unusable, paired with a fragment of the
# message that names the specific problem. Kept as literals rather than derived
# from validate_shard_selection, so a message that stopped naming the problem
# fails here instead of agreeing with itself.
UNUSABLE_SELECTIONS = [
    pytest.param(0, None, "requires --shard-count", id="index-without-count"),
    pytest.param(None, 2, "requires --shard-index", id="count-without-index"),
    pytest.param(2, 2, "0 <= index < --shard-count", id="index-equals-count"),
    pytest.param(-1, 2, "0 <= index < --shard-count", id="negative-index"),
    pytest.param(0, 0, "must be at least 1", id="count-below-one"),
]


@pytest.fixture
def cli_context():
    """A typer context that looks like a real top-level invocation."""
    ctx = MagicMock()
    ctx.resilient_parsing = False
    ctx.invoked_subcommand = None
    ctx.args = []
    return ctx


@pytest.fixture
def scan_dirs(tmp_path):
    """A minimal source tree and a separate output directory."""
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("print('hello')\n", encoding="utf-8")
    output = tmp_path / "out"
    output.mkdir()
    return source, output


class _PhaseSpy:
    """Records what ``_execute_phase`` was called with, and optionally shards.

    ``as_method`` returns a plain function rather than this object, because
    ``patch.object`` does not bind a callable instance as a method: patching with
    ``self`` directly would drop the phase argument and the test would fail on a
    TypeError instead of measuring anything.

    The replacement returns ``aggregated_results`` unchanged, which is what the
    real method does on the happy path. ``EnginePhase.execute`` raises TypeError
    on any other return type, so a stub returning a bare MagicMock would fail for
    a reason that has nothing to do with sharding.
    """

    def __init__(self, assignment: ShardAssignment | None = None):
        self.calls: list[dict] = []
        self._assignment = assignment

    def as_method(self):
        spy = self

        def _execute_phase(phase_self, aggregated_results, **kwargs):
            spy.calls.append(kwargs)
            # The real method sets this before doing anything else, and the engine
            # reads it back straight after the phase returns. A stub that skipped
            # it would fail on an AttributeError from the engine rather than on the
            # shard assertion.
            phase_self._completed_scanners = []
            # Stands in for the real phase's partition step. The phase is the only
            # layer that can resolve scanner names (see core/sharding.py), so a
            # test of the layers above it has to supply the assignment the phase
            # would have computed.
            if spy._assignment is not None:
                phase_self._shard_assignment = spy._assignment
            return aggregated_results

        return _execute_phase

    @property
    def only_call(self) -> dict:
        assert len(self.calls) == 1, f"expected one scan phase call, got {self.calls}"
        return self.calls[0]


def _run_local_scan(source, output, spy, **scan_kwargs):
    """Drive the real CLI command through to a stubbed ``_execute_phase``.

    Only the scan phase runs. Convert and report are left out so that the
    assertion is about the shard pair reaching the phase, not about whatever a
    real converter or reporter happens to do to a fixture tree.
    """
    from automated_security_helper.core.phases.scan_phase import ScanPhase

    ctx = MagicMock()
    ctx.resilient_parsing = False
    ctx.invoked_subcommand = None
    ctx.args = []

    with patch.object(ScanPhase, "_execute_phase", spy.as_method()):
        run_ash_scan_cli_command(
            ctx,
            source_dir=str(source),
            output_dir=str(output),
            phases=[ExecutionPhase.SCAN],
            progress=False,
            show_summary=False,
            quiet=True,
            **scan_kwargs,
        )


class TestFlagsReachTheScanPhase:
    """The four hops, exercised for real."""

    def test_the_pair_arrives_at_execute_phase(self, scan_dirs):
        source, output = scan_dirs
        spy = _PhaseSpy()
        _run_local_scan(source, output, spy, shard_index=1, shard_count=3)
        assert spy.only_call["shard_index"] == 1
        assert spy.only_call["shard_count"] == 3

    def test_an_unsharded_scan_arrives_with_neither(self, scan_dirs):
        # The regression guard for every existing invocation. The phase treats
        # `shard_count is not None` as "this run is a shard", so a hop that
        # defaulted the pair to 0 instead of None would silently turn every
        # ordinary scan into shard 0 of 0.
        source, output = scan_dirs
        spy = _PhaseSpy()
        _run_local_scan(source, output, spy)
        assert spy.only_call["shard_index"] is None
        assert spy.only_call["shard_count"] is None

    def test_shard_zero_is_not_confused_with_absent(self, scan_dirs):
        # Index 0 is falsy. A hop written as `if shard_index:` rather than
        # `is not None` would drop exactly the first shard of every matrix, and
        # that shard's scanners would be missing from the merged report while the
        # other n-1 shards looked healthy.
        source, output = scan_dirs
        spy = _PhaseSpy()
        _run_local_scan(source, output, spy, shard_index=0, shard_count=2)
        assert spy.only_call["shard_index"] == 0
        assert spy.only_call["shard_count"] == 2


class TestShardProvenanceOnDisk:
    """What ``ash merge`` will actually read."""

    def _results_from_disk(self, output: Path) -> AshAggregatedResults:
        results_file = output / "ash_aggregated_results.json"
        assert results_file.exists(), f"no results file at {results_file}"
        return AshAggregatedResults.model_validate_json(
            results_file.read_text(encoding="utf-8")
        )

    def test_the_assignment_survives_a_write_and_a_read(self, scan_dirs):
        source, output = scan_dirs
        assignment = ShardAssignment(
            shard_index=1,
            shard_count=3,
            assigned_scanners=["checkov", "semgrep"],
        )
        _run_local_scan(
            source,
            output,
            _PhaseSpy(assignment),
            shard_index=1,
            shard_count=3,
        )

        recovered = self._results_from_disk(output).metadata.shard
        assert recovered == assignment
        # A dict would deserialise and compare unequal to the model, and
        # verify_shard_coverage reads attributes rather than keys.
        assert isinstance(recovered, ShardAssignment)
        assert recovered.assigned_scanners == ["checkov", "semgrep"]

    def test_an_unsharded_scan_records_no_provenance(self, scan_dirs):
        # None, not an empty ShardAssignment. An assignment claiming 0 of 0 with
        # no scanners would make a whole-repository scan look like a shard whose
        # siblings never uploaded, and merge would refuse a perfectly good report.
        source, output = scan_dirs
        _run_local_scan(source, output, _PhaseSpy())
        assert self._results_from_disk(output).metadata.shard is None


class TestProvenanceSurvivesTheReportPhase:
    """The stamp is applied after scan, and the report phase rebuilds metrics.

    ``populate_metrics_from_unified_source`` replaces summary_stats and rewrites
    scanner_results on the same metadata object the stamp lives on. If it ever
    rebuilt ReportMetadata instead of mutating it, the stamp would be dropped
    between the scan and the file -- and only for runs that asked for reports,
    which is every real CI invocation.
    """

    def test_metrics_realignment_keeps_the_stamp(self):
        from automated_security_helper.core.unified_metrics import (
            populate_metrics_from_unified_source,
        )

        assignment = ShardAssignment(
            shard_index=0, shard_count=2, assigned_scanners=["bandit"]
        )
        results = AshAggregatedResults()
        results.metadata.shard = assignment

        realigned = populate_metrics_from_unified_source(aggregated_results=results)

        assert realigned.metadata.shard == assignment


class TestUnusableSelectionsAreRefused:
    @pytest.mark.parametrize("index,count,fragment", UNUSABLE_SELECTIONS)
    def test_refused_with_a_message_naming_the_problem(
        self, cli_context, scan_dirs, capsys, index, count, fragment
    ):
        source, output = scan_dirs
        with pytest.raises(typer.Exit) as excinfo:
            run_ash_scan_cli_command(
                cli_context,
                source_dir=str(source),
                output_dir=str(output),
                shard_index=index,
                shard_count=count,
            )
        # Not 2: ASH spends 2 on "actionable findings were found", so a usage
        # error exiting 2 would be read by a CI gate as a failing scan.
        assert excinfo.value.exit_code == 1
        assert excinfo.value.exit_code != 2
        assert fragment in capsys.readouterr().err

    @pytest.mark.parametrize("index,count,fragment", UNUSABLE_SELECTIONS)
    def test_refused_before_the_scan_starts(
        self, cli_context, scan_dirs, index, count, fragment
    ):
        # Refusing after the scan would mean paying for a partial scan and then
        # being told the arguments were wrong.
        source, output = scan_dirs
        with patch(
            "automated_security_helper.cli.scan.run_ash_scan"
        ) as mock_run_ash_scan:
            with pytest.raises(typer.Exit):
                run_ash_scan_cli_command(
                    cli_context,
                    source_dir=str(source),
                    output_dir=str(output),
                    shard_index=index,
                    shard_count=count,
                )
        mock_run_ash_scan.assert_not_called()

    def test_a_usable_selection_is_not_refused(self, cli_context, scan_dirs):
        # The counterweight: a validator that refused everything would pass every
        # test above.
        source, output = scan_dirs
        with patch(
            "automated_security_helper.cli.scan.run_ash_scan"
        ) as mock_run_ash_scan:
            run_ash_scan_cli_command(
                cli_context,
                source_dir=str(source),
                output_dir=str(output),
                shard_index=1,
                shard_count=2,
            )
        _, kwargs = mock_run_ash_scan.call_args
        assert kwargs["shard_index"] == 1
        assert kwargs["shard_count"] == 2


class TestEnvironmentVariables:
    """``ASH_SHARD_INDEX``/``ASH_SHARD_COUNT``, so a matrix needs no command edit.

    Exercised through the click parser rather than by calling the command
    function, because ``envvar=`` is honoured by parsing and not by Python
    defaults: a direct call would pass whether or not the wiring exists.
    """

    def test_the_pair_can_come_from_the_environment(self, monkeypatch, scan_dirs):
        from automated_security_helper.cli.main import app

        source, output = scan_dirs
        monkeypatch.setenv("ASH_SHARD_INDEX", "2")
        monkeypatch.setenv("ASH_SHARD_COUNT", "4")

        with patch(
            "automated_security_helper.cli.scan.run_ash_scan"
        ) as mock_run_ash_scan:
            result = CliRunner().invoke(
                app,
                ["scan", "--source-dir", str(source), "--output-dir", str(output)],
            )

        assert result.exit_code == 0, result.output
        _, kwargs = mock_run_ash_scan.call_args
        assert kwargs["shard_index"] == 2
        assert kwargs["shard_count"] == 4

    def test_an_unusable_pair_from_the_environment_is_still_refused(
        self, monkeypatch, scan_dirs
    ):
        # An env-var-only path that skipped validation would let a matrix
        # expression producing index==count scan nothing and exit 0.
        from automated_security_helper.cli.main import app

        source, output = scan_dirs
        monkeypatch.setenv("ASH_SHARD_INDEX", "4")
        monkeypatch.setenv("ASH_SHARD_COUNT", "4")

        with patch(
            "automated_security_helper.cli.scan.run_ash_scan"
        ) as mock_run_ash_scan:
            result = CliRunner().invoke(
                app,
                ["scan", "--source-dir", str(source), "--output-dir", str(output)],
            )

        assert result.exit_code == 1
        mock_run_ash_scan.assert_not_called()


class TestWorkspaceModeRefusesSharding:
    """Refused, not silently dropped. See cli.scan._validate_shard_options.

    Workspace mode's unified results file is hand-assembled in
    ``workspace.aggregation.WorkspaceResultsAggregator.write`` from a fixed set of
    metadata keys and none of each project's own scan metadata, so a shard stamp
    would exist only in ``projects/<key>/ash_aggregated_results.json`` and be
    absent from the file merge reads.
    """

    @pytest.mark.parametrize(
        "index,count",
        [(0, 2), (0, None), (None, 2)],
    )
    def test_the_combination_is_refused_at_the_cli(
        self, cli_context, scan_dirs, capsys, index, count
    ):
        source, _output = scan_dirs
        workspace_file = source / "demo.code-workspace"
        workspace_file.write_text('{"folders": []}', encoding="utf-8")

        with pytest.raises(typer.Exit) as excinfo:
            run_ash_scan_cli_command(
                cli_context,
                workspace=str(workspace_file),
                shard_index=index,
                shard_count=count,
            )

        assert excinfo.value.exit_code == 1
        message = capsys.readouterr().err
        assert "cannot be combined with --workspace" in message
        # The refusal has to say what to do instead, or an operator's only move is
        # to drop the flag and lose the parallelism they came for.
        assert "--source-dir" in message

    def test_the_refusal_happens_before_the_workspace_is_resolved(
        self, cli_context, scan_dirs
    ):
        source, _output = scan_dirs
        with patch(
            "automated_security_helper.cli.scan.resolve_workspace"
        ) as mock_resolve:
            with pytest.raises(typer.Exit):
                run_ash_scan_cli_command(
                    cli_context,
                    workspace=str(source / "demo.code-workspace"),
                    shard_index=0,
                    shard_count=2,
                )
        mock_resolve.assert_not_called()

    def test_a_programmatic_caller_gets_a_hard_error(self, scan_dirs):
        # run_ash_scan is a public entry point (the MCP server and the example UI
        # both call it), so the CLI check is not the only door. Ignoring the pair
        # here would be every shard scanning every project in full.
        from automated_security_helper.interactions.run_ash_scan import (
            ScanOptions,
            _run_workspace_mode,
        )
        from automated_security_helper.workspace.plan import WorkspacePlan

        source, output = scan_dirs
        opts = ScanOptions(
            source_dir=source,
            output_dir=output,
            # A real plan, not a MagicMock: ScanOptions validates the field, and a
            # mock would make this test fail at construction rather than at the
            # guard it is measuring.
            workspace_plan=WorkspacePlan(
                workspace_file=str(source / "demo.code-workspace"),
                workspace_root=str(source),
            ),
            shard_index=0,
            shard_count=2,
        )
        with pytest.raises(RuntimeError, match="not supported in workspace mode"):
            _run_workspace_mode(opts, logger=MagicMock())


class TestContainerMode:
    """Forwarded into the container, not warned about and dropped.

    ``--changed-files-only`` is warned about and dropped one line above the
    forwarding, and the two are not the same trade. Dropping
    ``--changed-files-only`` widens the scan: wasteful, never wrong. Dropping a
    shard selection also widens it, but then every shard scans the whole
    repository and merge multiplies every finding by the shard count.
    """

    def _assemble(self, **kwargs):
        from automated_security_helper.interactions.run_ash_container import (
            _assemble_run_command,
        )

        base = dict(
            oci_command_prefix=[],
            resolved_oci_runner="docker",
            image_name="ash:test",
            source_dir=Path("/src-host"),
            output_dir=Path("/out-host"),
            offline=False,
            debug=False,
            color=False,
            quiet=False,
            progress=False,
            verbose=False,
            simple=False,
            python_based_plugins_only=False,
            cleanup=False,
            inspect=False,
            fail_on_findings=None,
            phases=[],
            scanners=[],
            exclude_scanners=[],
            output_formats=[],
            config=None,
            config_overrides=[],
            existing_results=None,
            ash_plugin_modules=[],
            strategy=None,
            ctx=None,
        )
        base.update(kwargs)
        return _assemble_run_command(**base)

    def test_the_pair_is_forwarded_as_flags(self):
        cmd = self._assemble(shard_index=1, shard_count=3)
        assert "--shard-index" in cmd
        assert cmd[cmd.index("--shard-index") + 1] == "1"
        assert "--shard-count" in cmd
        assert cmd[cmd.index("--shard-count") + 1] == "3"

    def test_shard_zero_is_forwarded(self):
        # `if shard_index:` here would drop the first shard of every matrix.
        cmd = self._assemble(shard_index=0, shard_count=2)
        assert cmd[cmd.index("--shard-index") + 1] == "0"

    def test_an_unsharded_run_forwards_neither(self):
        cmd = self._assemble()
        assert "--shard-index" not in cmd
        assert "--shard-count" not in cmd

    def test_run_ash_scan_hands_the_pair_to_the_container_runner(self, scan_dirs):
        source, output = scan_dirs
        results_file = output / "ash_aggregated_results.json"
        results_file.write_text(
            AshAggregatedResults().model_dump_json(by_alias=True), encoding="utf-8"
        )
        completed = MagicMock()
        completed.returncode = 0

        with patch(
            "automated_security_helper.interactions.run_ash_scan.run_ash_container",
            return_value=completed,
        ) as mock_container:
            run_ash_scan(
                source_dir=source,
                output_dir=output,
                mode=RunMode.container,
                phases=[ExecutionPhase.SCAN],
                progress=False,
                show_summary=False,
                quiet=True,
                shard_index=1,
                shard_count=3,
            )

        _, kwargs = mock_container.call_args
        assert kwargs["shard_index"] == 1
        assert kwargs["shard_count"] == 3


class TestEveryLayerDefaultsToUnsharded:
    """Absent means absent at every layer, and never "shard 0 of 1".

    Found by mutation: changing ``ScanOptions``' two defaults from None to 0 and 1
    survived the whole suite. It survives because ``run_ash_scan`` always passes
    the pair explicitly, so the model default is unreachable from there -- but
    ``ScanOptions`` is public and constructible directly, and a caller that built
    one without the pair would get a scan that runs every scanner (a 1-way split
    excludes nothing) and then stamps provenance claiming it was shard 0 of 1. A
    complete scan that files itself as a shard is worse than either honest state:
    ``verify_shard_coverage`` accepts 1-of-1 without complaint, so nothing
    downstream would ever notice.

    Checked at every layer rather than only the one the mutation happened to hit.
    The defect is a class -- "a layer defaulted the pair to a concrete shard" --
    and it is equally available at each of the five.
    """

    def test_scan_options_defaults_to_neither(self, scan_dirs):
        from automated_security_helper.interactions.run_ash_scan import ScanOptions

        source, output = scan_dirs
        opts = ScanOptions(source_dir=source, output_dir=output)
        assert opts.shard_index is None
        assert opts.shard_count is None

    def test_the_orchestrator_defaults_to_neither(self, scan_dirs):
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        source, output = scan_dirs
        orchestrator = ASHScanOrchestrator(
            source_dir=source,
            output_dir=output,
            config_path=None,
            config_overrides=None,
            no_cleanup=False,
            metadata=None,
            ash_plugin_modules=[],
        )
        assert orchestrator.shard_index is None
        assert orchestrator.shard_count is None

    def test_the_engine_defaults_to_neither(self, tmp_path):
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
        from automated_security_helper.core.execution_engine import ScanExecutionEngine

        source = tmp_path / "src"
        source.mkdir()
        output = tmp_path / "out"
        output.mkdir()
        work = output / ASH_WORK_DIR_NAME
        work.mkdir()

        engine = ScanExecutionEngine(
            context=PluginContext(
                source_dir=source,
                output_dir=output,
                work_dir=work,
                config=AshConfig(project_name="test"),
            ),
            show_progress=False,
        )
        assert engine._shard_index is None
        assert engine._shard_count is None

    @pytest.mark.parametrize("parameter", ["shard_index", "shard_count"])
    def test_the_two_public_entry_points_default_to_neither(self, parameter):
        # Read off the signatures, because these two defaults are what a caller
        # who omits the flags actually gets, and neither is observable by calling
        # the function: the CLI's default is consumed by click and run_ash_scan's
        # is immediately forwarded into ScanOptions.
        import inspect

        for function in (run_ash_scan_cli_command, run_ash_scan):
            default = inspect.signature(function).parameters[parameter].default
            assert default is None, f"{function.__name__}.{parameter} = {default!r}"


class TestOrchestratorHop:
    """The one hop the end-to-end test cannot isolate a failure in."""

    def test_the_orchestrator_hands_the_pair_to_the_engine(self, scan_dirs):
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.core.orchestrator import ASHScanOrchestrator

        source, output = scan_dirs
        with patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="test"),
        ):
            orchestrator = ASHScanOrchestrator.create(
                source_dir=source,
                output_dir=output,
                config_path=None,
                config_overrides=None,
                no_cleanup=False,
                metadata=None,
                ash_plugin_modules=[],
                show_progress=False,
                shard_index=2,
                shard_count=5,
            )

        assert orchestrator.execution_engine is not None
        assert orchestrator.execution_engine._shard_index == 2
        assert orchestrator.execution_engine._shard_count == 5
