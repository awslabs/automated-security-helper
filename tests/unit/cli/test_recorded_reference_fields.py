# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A recorded reference in a field that cannot hold one.

A results file keeps each value its scan read from the environment as the
reference the file wrote. A fixed-choice field such as
``global_settings.severity_threshold`` cannot hold the reference text, so the
record is read with the field's default and the field is named
(config/recorded_config.py). Then:

- a reader that computes nothing from it keeps the default, with a warning
  naming the field and the reference;
- ``ash merge`` and ``ash report`` refuse, exit 3, naming both, unless this
  invocation's own configuration supplies the field, whose value they then use;
- the outer process of a container or Nix scan, and ``ash scan --use-existing``,
  use their own resolved value, as the scan did, so the exit code is computed
  with the scan's threshold.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.cli.merge import stamp_shard_assignment
from automated_security_helper.config.ash_config import (
    AshConfig,
    resolve_env_references,
)
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.core.sharding import ShardAssignment
from automated_security_helper.interactions import run_ash_scan as module
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _run_container_mode,
    _run_nix_mode,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerStatusInfo,
)
from automated_security_helper.schemas.sarif_schema_model import Result
from automated_security_helper.utils.inner_run_outcome import mark_run_completed
from automated_security_helper.utils.subprocess_utils import create_completed_process

pytestmark = pytest.mark.unit

REFERENCE = "${ASH_PROBE_SEV:LOW}"
FIELD = "global_settings.severity_threshold"
RESULTS = "ash_aggregated_results.json"
# The variable's value where merge and report run. Neither reads it, so it
# appears in nothing they print.
CANARY = "ash-canary-7f3e-0123456789"


def _assert_no_value(text: str) -> None:
    """Whitespace and box-drawing characters removed, so a value wrapped across
    lines or a panel border still counts; and its leading part, so a truncated
    one does too."""
    squeezed = re.sub(r"[\s─-╿]", "", text)
    assert CANARY not in squeezed and CANARY[:12] not in squeezed, text


@pytest.fixture
def value_where_merge_runs(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ASH_PROBE_SEV", CANARY)
    # Control: the reference does resolve to the canary in this process.
    assert resolve_env_references(REFERENCE) == CANARY


def _record(scanner: str = "bandit", run_id: "str | None" = None) -> str:
    """One shard's results, as a scan whose config read severity_threshold from
    the environment writes them.

    *scanner* is the one scanner the shard ran. bandit has a threshold of its
    own (ALL), which the summary table shows in place of the global one.

    *run_id* is the outer run's id for a file an inner (container or nix) run
    writes: the host reads a file back only when it records that this run
    completed (utils/inner_run_outcome.py). None writes no such record."""
    model = AshAggregatedResults()
    model.ash_config = AshConfig(project_name="demo")
    model.scanner_results[scanner] = ScannerStatusInfo(
        status=ScannerStatus.PASSED, excluded=False, dependencies_satisfied=True
    )
    stamp_shard_assignment(
        model,
        ShardAssignment(shard_index=0, shard_count=1, assigned_scanners=[scanner]),
    )
    mark_run_completed(model, run_id)
    data = json.loads(model.model_dump_json(by_alias=True))
    data["ash_config"]["global_settings"]["severity_threshold"] = REFERENCE
    return json.dumps(data)


@pytest.fixture
def shard(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setenv("ASH_PROBE_SEV", "LOW")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.chdir(tmp_path)
    directory = tmp_path / "shard0"
    directory.mkdir()
    (directory / RESULTS).write_text(_record(), encoding="utf-8")
    return directory


def test_a_display_reader_keeps_the_default_and_names_the_field(shard):
    with patch("automated_security_helper.models.asharp_model.ASH_LOGGER") as log:
        loaded = AshAggregatedResults.model_validate_json(
            (shard / RESULTS).read_text(encoding="utf-8")
        )
    assert loaded.ash_config.global_settings.severity_threshold == "MEDIUM"
    assert loaded.ash_config._unreadable_references == [(FIELD, REFERENCE)]
    warned = " ".join(str(call) for call in log.warning.mock_calls)
    assert FIELD in warned and REFERENCE in warned, warned


def _merge(shard: Path, *extra: str):
    return CliRunner().invoke(
        app,
        ["merge", "--results", str(shard), "--output-dir", "merged", *extra],
        env={"COLUMNS": "300"},
    )


def test_merge_refuses_without_the_operator_s_value(shard, value_where_merge_runs):
    result = _merge(shard)
    printed = " ".join(f"{result.stdout} {result.stderr}".split())
    assert result.exit_code == 3, printed
    assert FIELD in printed and REFERENCE in printed, printed
    assert "--config" in printed, printed
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    assert not (Path("merged") / RESULTS).exists()


def test_merge_takes_the_operator_s_value(shard, tmp_path, value_where_merge_runs):
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        "project_name: operator\nglobal_settings:\n  severity_threshold: HIGH\n",
        encoding="utf-8",
    )
    result = _merge(shard, "--config", str(operator), "--no-fail-on-findings")
    assert result.exit_code != 3, result.output
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    written = (Path("merged") / RESULTS).read_text(encoding="utf-8")
    _assert_no_value(written)
    merged = json.loads(written)
    assert merged["ash_config"]["global_settings"]["severity_threshold"] == "HIGH"


def _report(shard: Path, *extra: str):
    return CliRunner().invoke(
        app,
        ["report", "--format", "markdown", "--output-dir", str(shard), *extra],
        env={"COLUMNS": "300"},
    )


def test_report_refuses_without_the_operator_s_value(shard, value_where_merge_runs):
    result = _report(shard)
    printed = " ".join(f"{result.stdout} {result.stderr}".split())
    assert result.exit_code == 3, printed
    assert FIELD in printed and REFERENCE in printed, printed
    assert "--config-overrides" in printed, printed
    _assert_no_value(f"{result.stdout}\n{result.stderr}")


def test_report_takes_the_operator_s_value(shard, value_where_merge_runs):
    result = _report(
        shard, "--config-overrides", "global_settings.severity_threshold=HIGH"
    )
    assert result.exit_code == 0, result.output
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    # The summary table's threshold column; the legend names every threshold.
    assert "HIGH (global)" in result.stdout, result.stdout


# One LOW finding: actionable at the scan's threshold, LOW, and not at the field's
# default, MEDIUM, so the two readings give different exit codes.
_FINDING = {
    "ruleId": "B101",
    "level": "note",
    "message": {"text": "assert used"},
    "properties": {"scanner_name": "bandit", "issue_severity": "LOW"},
}
_SARIF = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "bandit"}}, "results": [_FINDING]}],
}


def _scan_record(threshold: str) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = AshConfig(project_name="demo")
    model.ash_config.global_settings.severity_threshold = threshold
    model.scanner_results["bandit"] = ScannerStatusInfo(
        status=ScannerStatus.PASSED, excluded=False, dependencies_satisfied=True
    )
    model.sarif.runs[0].results = [Result.model_validate(_FINDING)]
    return model


def _container_source(tmp_path: Path) -> ScanOptions:
    source = tmp_path / "src"
    (source / ".ash").mkdir(parents=True)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    (source / ".ash" / ".ash.yaml").write_text(
        f"project_name: demo\nglobal_settings:\n  severity_threshold: {REFERENCE}\n",
        encoding="utf-8",
    )
    return ScanOptions(source_dir=source, output_dir=tmp_path / "out")


@pytest.mark.parametrize("mode", ["container", "nix"])
def test_an_outer_scan_reads_the_record_with_its_own_value(tmp_path, monkeypatch, mode):
    monkeypatch.setenv("ASH_PROBE_SEV", "LOW")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    opts = _container_source(tmp_path)

    def inner(*args, **kwargs):
        opts.output_dir.mkdir(parents=True, exist_ok=True)
        (opts.output_dir / RESULTS).write_text(
            _record(run_id=kwargs.get("outer_run_id")), encoding="utf-8"
        )
        return create_completed_process(args=[], returncode=0, stdout="", stderr="")

    if mode == "container":
        with patch.object(module, "run_ash_container", side_effect=inner):
            results = _run_container_mode(opts, MagicMock())
    else:
        with (
            patch.object(module, "run_ash_nix", side_effect=inner),
            patch.object(module, "nix_preflight", lambda: None),
        ):
            results = _run_nix_mode(opts, MagicMock())

    assert results.ash_config.global_settings.severity_threshold == "LOW"


@pytest.mark.parametrize("mode", ["container", "nix"])
def test_an_outer_scan_records_its_own_value_as_the_reference(
    tmp_path, monkeypatch, mode
):
    """The value the outer process takes is the operator's, read from the
    environment by its own config file: the results it writes keep that
    reference, as ``ash merge`` and ``--use-existing`` keep theirs."""
    monkeypatch.setenv("ASH_PROBE_SEV", "CRITICAL")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    opts = _container_source(tmp_path)

    def inner(*args, **kwargs):
        opts.output_dir.mkdir(parents=True, exist_ok=True)
        (opts.output_dir / RESULTS).write_text(
            _record(run_id=kwargs.get("outer_run_id")), encoding="utf-8"
        )
        return create_completed_process(args=[], returncode=0, stdout="", stderr="")

    runner = _run_container_mode if mode == "container" else _run_nix_mode
    target = "run_ash_container" if mode == "container" else "run_ash_nix"
    with (
        patch.object(module, target, side_effect=inner),
        patch.object(module, "nix_preflight", lambda: None),
    ):
        results = runner(opts, MagicMock())

    # The control: the run uses the operator's value.
    assert results.ash_config.global_settings.severity_threshold == "CRITICAL"
    recorded = json.loads(results.model_dump_json(by_alias=True))["ash_config"]
    assert recorded["global_settings"]["severity_threshold"] == REFERENCE


def test_a_report_over_existing_results_reads_the_record_with_its_own_value(
    tmp_path, monkeypatch
):
    """``ash scan --use-existing``: the orchestrator's configuration supplies it."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    existing = tmp_path / "previous" / RESULTS
    existing.parent.mkdir()
    existing.write_text(_record(), encoding="utf-8")
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    own = AshConfig(project_name="demo")
    own.global_settings.severity_threshold = "LOW"
    engines = []

    def engine(**kwargs):
        engines.append(kwargs)
        return MagicMock()

    orchestrator = ASHScanOrchestrator(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config_path=None,
        config_overrides=None,
        no_cleanup=True,
        metadata=None,
        ash_plugin_modules=[],
        existing_results_path=existing,
    )
    with (
        patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=own,
        ),
        patch(
            "automated_security_helper.core.orchestrator.ScanExecutionEngine",
            side_effect=engine,
        ),
    ):
        orchestrator.initialize()

    record = engines[0]["asharp_model"].ash_config
    assert record.global_settings.severity_threshold == "LOW"


def test_a_container_scan_exits_as_a_local_scan_does(tmp_path, monkeypatch):
    """``ash scan --mode container``: the host recomputes the verdict from the
    record the inner scan wrote, and gets the code a local scan computes."""
    monkeypatch.setenv("ASH_PROBE_SEV", "LOW")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    opts = _container_source(tmp_path)
    output = opts.output_dir

    def write_the_inner_scan_s_files(run_id: "str | None" = None) -> None:
        (output / "reports").mkdir(parents=True, exist_ok=True)
        (output / "reports" / "ash.sarif").write_text(
            json.dumps(_SARIF), encoding="utf-8"
        )
        model = _scan_record("LOW")
        # The marker the in-container run writes when it completes.
        mark_run_completed(model, run_id)
        data = json.loads(model.model_dump_json(by_alias=True))
        data["ash_config"]["global_settings"]["severity_threshold"] = REFERENCE
        (output / RESULTS).write_text(json.dumps(data), encoding="utf-8")

    # What a local scan computes over the same files, with the threshold its own
    # configuration resolves to; and, as the control, with the field's default.
    write_the_inner_scan_s_files()
    local = module._compute_exit_code(
        _scan_record("LOW"), opts, report_sarif_written_this_run=True
    )
    defaulted = module._compute_exit_code(
        _scan_record("MEDIUM"), opts, report_sarif_written_this_run=True
    )
    assert (local, defaulted) == (2, 0)
    (output / "reports" / "ash.sarif").unlink()
    (output / RESULTS).unlink()

    def inner(**kwargs):
        write_the_inner_scan_s_files(kwargs.get("outer_run_id"))
        return create_completed_process(args=[], returncode=local, stdout="", stderr="")

    with patch.object(module, "run_ash_container", side_effect=inner):
        try:
            module.run_ash_scan(
                source_dir=str(opts.source_dir),
                output_dir=str(output),
                mode=module.RunMode.container,
                progress=False,
                show_summary=False,
                quiet=True,
            )
            host = 0
        except SystemExit as exited:
            host = exited.code

    assert host == local


def _repair_warnings(tmp_path: Path, monkeypatch, extra_field: bool) -> list[str]:
    """Run the record repair for a container scan whose image may hold another
    revision; the warnings it logs. With *extra_field*, the operator's selected
    file carries a field this tree's model does not declare."""
    monkeypatch.setenv("ASH_PROBE_SEV", "LOW")
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    opts = _container_source(tmp_path).model_copy(
        update={"mode": module.RunMode.container, "build": False}
    )
    if extra_field:
        (opts.source_dir / ".ash" / ".ash.yaml").write_text(
            f"project_name: demo\nglobal_settings:\n  severity_threshold: {REFERENCE}\n"
            "  zz_option_a_later_schema_declares: true\n",
            encoding="utf-8",
        )
    assert module._image_schema_may_differ(opts)
    results = AshAggregatedResults.model_validate_json(_record())
    assert results.ash_config._unreadable_references == [(FIELD, REFERENCE)]
    with patch.object(module, "ASH_LOGGER") as log:
        module._take_own_values_for_record(results, opts)
    # The repair still ran.
    assert results.ash_config.global_settings.severity_threshold in {"LOW", "MEDIUM"}
    return [str(call) for call in log.warning.mock_calls]


def test_a_repair_from_the_base_configuration_says_so(tmp_path, monkeypatch):
    warned = " ".join(_repair_warnings(tmp_path, monkeypatch, extra_field=True))
    assert "repaired from the operator's base configuration" in warned, warned
    assert "image's own revision" in warned, warned


def test_a_repair_from_the_selected_file_does_not_warn(tmp_path, monkeypatch):
    assert _repair_warnings(tmp_path, monkeypatch, extra_field=False) == []


def test_the_configuration_has_one_attribute_for_a_field_it_could_not_read():
    """The loader lists the fields it read as their defaults on one attribute.
    A second attribute for the same fact is one that nothing sets, and a guard
    that reads it never fires."""
    names = [name for name in AshConfig.__private_attributes__ if "unread" in name]
    assert names == ["_unreadable_references"], names


def test_merge_refuses_under_an_unrelated_override(shard, value_where_merge_runs):
    """An override that names another key does not supply the field, so the
    refusal holds as it does with no override at all."""
    result = _merge(shard, "--config-overrides", "project_name=other")
    printed = " ".join(f"{result.stdout} {result.stderr}".split())
    assert result.exit_code == 3, printed
    assert FIELD in printed and REFERENCE in printed, printed
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    assert not (Path("merged") / RESULTS).exists()


def test_merge_takes_an_override_that_names_the_field(shard, value_where_merge_runs):
    """The override's value is the one merged, and reading the field from the
    operator does not put the operator's configuration, which does not write
    the field here, in its place."""
    result = _merge(
        shard, "--config-overrides", f"{FIELD}=HIGH", "--no-fail-on-findings"
    )
    assert result.exit_code != 3, result.output
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    written = (Path("merged") / RESULTS).read_text(encoding="utf-8")
    _assert_no_value(written)
    merged = json.loads(written)
    assert merged["ash_config"]["global_settings"]["severity_threshold"] == "HIGH"


def test_report_takes_the_operator_s_config_file(
    shard, tmp_path, value_where_merge_runs
):
    # semgrep has no threshold of its own, so its row shows the global one. A
    # bandit row would read "ALL (config)" whatever the operator supplies.
    (shard / RESULTS).write_text(_record("semgrep"), encoding="utf-8")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        "project_name: operator\nglobal_settings:\n  severity_threshold: HIGH\n",
        encoding="utf-8",
    )
    result = _report(shard, "--config", str(operator))
    assert result.exit_code == 0, result.output
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    # The control: the row is there, so a missing threshold is not a missing row.
    assert "| semgrep |" in result.stdout, result.stdout
    # The summary table's threshold column, as value and source.
    assert "HIGH (global)" in result.stdout, result.stdout


# A configuration reads only the environment variables whose names begin with
# ASH_ and three exact names (core/constants.py, is_readable_environment_name);
# any other reference is left as written, so the operator's variable has the prefix.
OPERATOR_REFERENCE = "${ASH_OP_SEV}"


def _operator_that_reads_the_threshold_from_the_environment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Path:
    monkeypatch.setenv("ASH_OP_SEV", "CRITICAL")
    # Control: the operator's reference does resolve, to a value the field holds.
    assert resolve_env_references(OPERATOR_REFERENCE) == "CRITICAL"
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        "project_name: operator\n"
        f"global_settings:\n  severity_threshold: {OPERATOR_REFERENCE}\n",
        encoding="utf-8",
    )
    return operator


@pytest.mark.parametrize(
    "extra",
    [(), ("--config-overrides", "project_name=other")],
    ids=["no-override", "unrelated-override"],
)
def test_merge_records_the_operator_s_value_as_the_reference_it_read(
    shard, tmp_path, monkeypatch, value_where_merge_runs, extra
):
    """The value the merge takes is the operator's, read from the environment by
    the operator's own file: the merged results keep that reference, as the
    results of a container or Nix scan keep theirs, and not the value."""
    operator = _operator_that_reads_the_threshold_from_the_environment(
        tmp_path, monkeypatch
    )
    result = _merge(shard, "--config", str(operator), "--no-fail-on-findings", *extra)
    assert result.exit_code != 3, result.output
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    written = (Path("merged") / RESULTS).read_text(encoding="utf-8")
    _assert_no_value(written)
    merged = json.loads(written)
    threshold = merged["ash_config"]["global_settings"]["severity_threshold"]
    assert threshold == OPERATOR_REFERENCE, threshold


def test_merge_takes_the_value_from_the_file_ash_config_names(
    shard, tmp_path, monkeypatch, value_where_merge_runs
):
    """``--config`` reads ASH_CONFIG when it is not given, so the file that
    variable names supplies the field as the option's own file does."""
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        "project_name: operator\nglobal_settings:\n  severity_threshold: HIGH\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    result = _merge(shard, "--no-fail-on-findings")
    assert result.exit_code != 3, result.output
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    written = (Path("merged") / RESULTS).read_text(encoding="utf-8")
    merged = json.loads(written)
    assert merged["ash_config"]["global_settings"]["severity_threshold"] == "HIGH"


@pytest.mark.parametrize("location", [".ash/.ash.yaml", ".ash.yaml"])
def test_merge_does_not_take_the_value_from_a_config_file_it_finds(
    shard, tmp_path, value_where_merge_runs, location
):
    """A config file in the working directory is one a scan would find; merge
    reads the file ``--config`` or ASH_CONFIG names and no other, so this one
    does not supply the field and the refusal holds."""
    found = tmp_path / location
    found.parent.mkdir(exist_ok=True)
    found.write_text(
        "project_name: found\nglobal_settings:\n  severity_threshold: HIGH\n",
        encoding="utf-8",
    )
    result = _merge(shard)
    printed = " ".join(f"{result.stdout} {result.stderr}".split())
    assert result.exit_code == 3, printed
    assert FIELD in printed and REFERENCE in printed, printed
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    assert not (Path("merged") / RESULTS).exists()


def test_report_takes_the_value_from_the_file_ash_config_names(
    shard, tmp_path, monkeypatch, value_where_merge_runs
):
    """``--config`` reads ASH_CONFIG when it is not given, so the file that
    variable names supplies the field to ``ash report`` as it does to ``ash
    merge``."""
    # semgrep has no threshold of its own, so its row shows the global one.
    (shard / RESULTS).write_text(_record("semgrep"), encoding="utf-8")
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        "project_name: operator\nglobal_settings:\n  severity_threshold: HIGH\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("ASH_CONFIG", str(operator))
    result = _report(shard)
    assert result.exit_code == 0, result.output
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
    # The control: the row is there, so a missing threshold is not a missing row.
    assert "| semgrep |" in result.stdout, result.stdout
    assert "HIGH (global)" in result.stdout, result.stdout


@pytest.mark.parametrize(
    ("where", "location"),
    [
        ("working directory", ".ash/.ash.yaml"),
        ("working directory", ".ash.yaml"),
        ("results directory", ".ash/.ash.yaml"),
        ("results directory", ".ash.yaml"),
    ],
)
def test_report_does_not_take_the_value_from_a_config_file_it_finds(
    shard, tmp_path, value_where_merge_runs, where, location
):
    """``ash report`` reads the file ``--config`` or ASH_CONFIG names and no
    other. A config file a scan would find in the working directory does not
    supply the field, and neither does one beside the results (the directory
    ``resolve_config`` is told is also scanned), so the refusal holds."""
    root = tmp_path if where == "working directory" else shard
    found = root / location
    found.parent.mkdir(exist_ok=True)
    found.write_text(
        "project_name: found\nglobal_settings:\n  severity_threshold: HIGH\n",
        encoding="utf-8",
    )
    result = _report(shard)
    printed = " ".join(f"{result.stdout} {result.stderr}".split())
    assert result.exit_code == 3, printed
    assert FIELD in printed and REFERENCE in printed, printed
    assert "--config-overrides" in printed, printed
    _assert_no_value(f"{result.stdout}\n{result.stderr}")
