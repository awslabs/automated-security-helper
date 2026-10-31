# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Pins for the low-severity defects fixed at run_ash_scan's edges.

Each test names the behavior it holds and is red at the base by reading: the
assertion fails on the code before the fix, for the reason the fix's commit
message gives. Everything runs in-process: the runtimes, the Nix shell and the
orchestrator are stand-ins, and nothing here starts a process.
"""

from __future__ import annotations

import json
import os
import re
import time
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, List
from unittest.mock import MagicMock

import pytest
from pydantic import BaseModel, ValidationError

from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.enums import RunMode, ScannerStatus
from automated_security_helper.core.previous_results import (
    RESTORED_MARKER_NAME,
    RESTORING_DIR_NAME,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    ScanRefusedExit,
    _container_config_to_parse,
    _discard_prior_run_artifacts,
    _in_scanned_tree_from_arguments,
    _print_invalid_config,
    _print_summary,
    _read_back_inner_results,
    _run_container_mode,
    _run_local_mode,
    _run_nix_mode,
    _setup_logger,
    print_incompleteness_message,
    run_ash_scan,
    scan_incompleteness,
    unevaluated_rules,
)
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import (
    Invocation,
    Kind,
    Kind1,
    Level,
    Message,
    Message1,
    Notification,
    PropertyBag,
    ReportingDescriptorReference,
    ReportingDescriptorReference3,
    Result,
    Run,
    SarifReport,
    Suppression,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.subprocess_utils import create_completed_process
from tests.utils.helpers import mark_inner_run_completed, sarif_report_written

pytestmark = pytest.mark.unit

_ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")

_NEEDS_PERMISSION_BITS = pytest.mark.skipif(
    os.name == "nt" or (hasattr(os, "geteuid") and os.geteuid() == 0),
    reason="a privileged user reads through permission bits",
)


def _plain(text: str) -> str:
    """Rich styles inside a phrase, so assertions read the text without the codes."""
    return _ANSI_ESCAPE.sub("", text)


class _Logger:
    """Records what the production code logged, per level; nothing else."""

    def __init__(self) -> None:
        self.records: Dict[str, List[str]] = {
            "verbose": [],
            "debug": [],
            "info": [],
            "warning": [],
            "error": [],
        }

    def verbose(self, message, **kwargs):
        self.records["verbose"].append(str(message))

    def debug(self, message, **kwargs):
        self.records["debug"].append(str(message))

    def info(self, message, **kwargs):
        self.records["info"].append(str(message))

    def warning(self, message, **kwargs):
        self.records["warning"].append(str(message))

    def error(self, message, **kwargs):
        self.records["error"].append(str(message))

    def exception(self, message, **kwargs):
        self.records["error"].append(str(message))


def _opts(tmp_path: Path, **overrides) -> ScanOptions:
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    return ScanOptions(source_dir=source, output_dir=tmp_path / "out", **overrides)


def _quiet_container_side_effects(monkeypatch) -> None:
    """Stand-ins for what a container run does beside the runtime itself.

    The sweeps of an earlier run's leftovers read the state directory and may ask
    a container runtime; the record repair after the read-back asks the image's
    revision; the sandbox report resolves the config. None of that is under test
    here, and none of it may start a process on the test host.
    """
    monkeypatch.setattr(ras, "sweep_leftovers_before_run", lambda runner: [])
    monkeypatch.setattr(ras, "sweep_env_dirs", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        ras, "_take_own_values_for_record", lambda *args, **kwargs: None
    )
    monkeypatch.setattr(ras, "_sandbox_modes_requested", lambda opts: [])


# ---------------------------------------------------------------------------
# _print_summary: a config_warning checkpoint without a message
# ---------------------------------------------------------------------------


def test_a_config_warning_without_a_message_is_printed_not_raised(tmp_path, capsys):
    """The summary runs after the exit code is computed; a checkpoint read back
    from a results file another version wrote must not raise KeyError there."""
    results = SimpleNamespace(validation_checkpoints=[{"type": "config_warning"}])

    _print_summary(results, _opts(tmp_path), time.time(), actionable_findings=0)

    out = _plain(capsys.readouterr().out)
    assert "CONFIGURATION WARNING" in out
    assert "no message recorded" in out


# ---------------------------------------------------------------------------
# unevaluated_rules: a result that names its rule through ``rule.id``
# ---------------------------------------------------------------------------


def _rule_reference(rule_id: str) -> ReportingDescriptorReference:
    return ReportingDescriptorReference(root=ReportingDescriptorReference3(id=rule_id))


def _model_with(notifications: list, results: list) -> AshAggregatedResults:
    sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="ash-cdk-nag-wrapper")),
                results=results,
                invocations=[
                    Invocation(
                        executionSuccessful=True,
                        toolExecutionNotifications=notifications,
                    )
                ],
            )
        ],
    )
    model = AshAggregatedResults(ash_config=get_default_config())
    model.sarif = sarif
    return model


def _not_evaluated_by_reference(suppressed: bool) -> Result:
    return Result(
        rule=_rule_reference("AwsSolutions-EC26"),
        kind=Kind.notApplicable,
        level=Level.none,
        message=Message(root=Message1(text="raised while evaluating")),
        properties=PropertyBag(),
        suppressions=(
            [Suppression(kind=Kind1.external, justification="reviewed")]
            if suppressed
            else []
        ),
    )


def _could_not_evaluate(rule_id: str) -> Notification:
    return Notification(
        level=Level.error,
        message=Message(root=Message1(text="could not be evaluated")),
        associatedRule=_rule_reference(rule_id),
    )


def test_a_suppressed_result_naming_its_rule_by_reference_reaches_the_gate():
    """SARIF names a result's rule by ``ruleId`` or by ``rule.id``; a suppression
    on a result written the second way must reach the gate as the first does."""
    model = _model_with(
        [_could_not_evaluate("AwsSolutions-EC26")],
        [_not_evaluated_by_reference(suppressed=True)],
    )

    assert unevaluated_rules(model) == []


def test_control_an_unsuppressed_result_by_reference_keeps_the_gate():
    model = _model_with(
        [_could_not_evaluate("AwsSolutions-EC26")],
        [_not_evaluated_by_reference(suppressed=False)],
    )

    assert unevaluated_rules(model) == ["AwsSolutions-EC26"]


# ---------------------------------------------------------------------------
# scan_incompleteness: a negative counter is no partial audit
# ---------------------------------------------------------------------------


def _metric(attempted: int, failed: int) -> SimpleNamespace:
    return SimpleNamespace(
        scanner_name="cdk-nag",
        status=ScannerStatus.ERROR.value,
        actionable=0,
        targets_attempted=attempted,
        targets_failed=failed,
        counters_unusable=False,
    )


def test_a_negative_failed_counter_is_not_read_as_a_partial_audit(monkeypatch):
    """incomplete_scanners lists such a row as unreadable counters; the same row
    must not also be claimed as a partial audit of some of its targets."""
    monkeypatch.setattr(
        ras, "get_unified_scanner_metrics", lambda *args, **kwargs: [_metric(5, -1)]
    )
    model = AshAggregatedResults(ash_config=get_default_config())

    assert "cdk-nag" not in scan_incompleteness(model, gate=True).partial_coverage


def test_control_a_real_partial_loss_is_a_partial_audit(monkeypatch):
    monkeypatch.setattr(
        ras, "get_unified_scanner_metrics", lambda *args, **kwargs: [_metric(5, 2)]
    )
    model = AshAggregatedResults(ash_config=get_default_config())

    assert "cdk-nag" in scan_incompleteness(model, gate=True).partial_coverage


# ---------------------------------------------------------------------------
# _read_back_inner_results: a file that exists but cannot be read
# ---------------------------------------------------------------------------


@_NEEDS_PERMISSION_BITS
def test_a_results_file_that_cannot_be_read_exits_one_with_a_reason(tmp_path):
    output_file = tmp_path / "ash_aggregated_results.json"
    output_file.write_text("{}", encoding="utf-8")
    output_file.chmod(0)
    logger = _Logger()
    try:
        with pytest.raises(SystemExit) as exited:
            _read_back_inner_results(output_file, logger)
    finally:
        output_file.chmod(0o644)

    assert exited.value.code == 1
    assert any(
        "Could not read results file" in message for message in logger.records["error"]
    ), logger.records


# ---------------------------------------------------------------------------
# _setup_logger: existing_results is read for truth, as everywhere else
# ---------------------------------------------------------------------------


def test_an_empty_existing_results_value_starts_a_fresh_log(tmp_path, monkeypatch):
    seen: Dict[str, object] = {}

    def fake_get_logger(**kwargs):
        seen.update(kwargs)
        return MagicMock()

    monkeypatch.setattr(
        "automated_security_helper.utils.log.get_logger", fake_get_logger
    )

    _setup_logger(_opts(tmp_path, existing_results=""))
    assert seen["truncate_log"] is True

    _setup_logger(_opts(tmp_path, existing_results=str(tmp_path / "old.json")))
    assert seen["truncate_log"] is False


# ---------------------------------------------------------------------------
# _discard_prior_run_artifacts: the restoring set, and the marker under
# --use-existing
# ---------------------------------------------------------------------------


def test_a_failed_discard_that_left_a_restoring_set_refuses_the_scan(
    tmp_path, monkeypatch
):
    """A half-restored set is as indistinguishable from this scan's output as the
    held set is, so a discard that failed on it fails the scan closed."""
    opts = _opts(tmp_path)
    opts.output_dir.mkdir()
    (opts.output_dir / RESTORING_DIR_NAME).mkdir()

    class _FailingDiscard:
        def __init__(self, output_dir):
            pass

        def discard(self):
            raise OSError("busy")

    monkeypatch.setattr(ras, "PreviousResults", _FailingDiscard)

    with pytest.raises(ScanRefusedExit) as refused:
        _discard_prior_run_artifacts(opts, _Logger())

    assert refused.value.code == 1


def _plant_a_put_back_set(tmp_path) -> ScanOptions:
    """A put-back results set with its marker, named by --use-existing."""
    out = tmp_path / "out"
    out.mkdir()
    results = out / "ash_aggregated_results.json"
    results.write_text(AshAggregatedResults().model_dump_json(), encoding="utf-8")
    (out / RESTORED_MARKER_NAME).write_text("restored\n", encoding="utf-8")
    return _opts(
        tmp_path, mode=RunMode.container, build=False, existing_results=str(results)
    )


def test_use_existing_keeps_the_results_and_the_marker_through_the_discard(tmp_path):
    """The marker says the results were put back; until the inner run has accepted
    results of its own over them, that is still true, so the discard that keeps
    the file for --use-existing keeps the marker too."""
    opts = _plant_a_put_back_set(tmp_path)

    _discard_prior_run_artifacts(opts, _Logger())

    assert (opts.output_dir / "ash_aggregated_results.json").exists()
    assert (opts.output_dir / RESTORED_MARKER_NAME).exists()


def test_a_run_that_never_starts_under_use_existing_leaves_the_marker(
    tmp_path, monkeypatch
):
    """A build that fails or a container that never starts leaves the put-back
    set as it was, marker included, so no reader takes it for this run's."""
    from automated_security_helper.interactions import run_ash_container as rac

    opts = _plant_a_put_back_set(tmp_path)
    monkeypatch.setattr(
        ras,
        "run_ash_container",
        lambda **kwargs: rac._not_started(
            create_completed_process(
                args=["docker", "build"], returncode=125, stdout="", stderr="no build"
            )
        ),
    )
    _quiet_container_side_effects(monkeypatch)

    with pytest.raises(SystemExit) as exited:
        _run_container_mode(opts, _Logger())

    assert exited.value.code == 125
    assert (opts.output_dir / RESTORED_MARKER_NAME).exists()


def test_a_completed_use_existing_run_is_read_back_and_drops_the_marker(
    tmp_path, monkeypatch
):
    """Control: the inner run completed over the kept file, so the read-back is
    accepted (the marker refuses nothing for a --use-existing run) and the
    marker, no longer true, goes."""
    opts = _plant_a_put_back_set(tmp_path)
    monkeypatch.setattr(ras, "run_ash_container", _fake_completed_container_run)
    _quiet_container_side_effects(monkeypatch)

    results = _run_container_mode(opts, _Logger())

    assert isinstance(results, AshAggregatedResults)
    assert not (opts.output_dir / RESTORED_MARKER_NAME).exists()


# ---------------------------------------------------------------------------
# _container_config_to_parse: is_file under an unsearchable directory
# ---------------------------------------------------------------------------


def test_a_config_under_an_unsearchable_directory_is_left_to_the_run(
    tmp_path, monkeypatch
):
    """Before Python 3.14 is_file raises for the path; the parse check stands
    aside (None) as it does for a missing path, and the run's own refusal speaks."""
    named = tmp_path / "locked" / "ash.yaml"
    real_is_file = Path.is_file

    def is_file(self, *args, **kwargs):
        if os.fspath(self) == os.fspath(named):
            raise PermissionError(13, "Permission denied")
        return real_is_file(self, *args, **kwargs)

    monkeypatch.setattr(Path, "is_file", is_file)
    opts = SimpleNamespace(config=str(named), source_dir=str(tmp_path))

    assert _container_config_to_parse(opts) is None


# ---------------------------------------------------------------------------
# _run_container_mode: the second input check, and a findings exit
# ---------------------------------------------------------------------------


def _fake_completed_container_run(**kwargs):
    """A runtime stand-in: the inner run wrote its results and completed, exit 0."""
    output_dir = Path(kwargs["output_dir"])
    output_dir.mkdir(parents=True, exist_ok=True)
    results_file = output_dir / "ash_aggregated_results.json"
    results_file.write_text(AshAggregatedResults().model_dump_json(), encoding="utf-8")
    mark_inner_run_completed(results_file, kwargs["outer_run_id"])
    return create_completed_process(
        args=["docker", "run"], returncode=0, stdout="", stderr=""
    )


def test_the_container_input_check_runs_once_before_the_discard_with_the_reads(
    tmp_path, monkeypatch
):
    """One check of the scan's inputs per container run, carrying the scan's
    record of the operator's config reads, and before the previous run's output
    is cleared, so a refused scan deletes nothing."""
    opts = _opts(tmp_path, mode=RunMode.container, build=False)
    order: List[tuple] = []

    def recording_refusal(*args):
        order.append(("inputs", args))
        return None

    real_discard = ras._discard_prior_run_artifacts

    def recording_discard(opts, logger):
        order.append(("discard", ()))
        return real_discard(opts, logger)

    monkeypatch.setattr(ras, "container_input_refusal", recording_refusal)
    monkeypatch.setattr(ras, "_discard_prior_run_artifacts", recording_discard)
    monkeypatch.setattr(ras, "run_ash_container", _fake_completed_container_run)
    _quiet_container_side_effects(monkeypatch)

    results = _run_container_mode(opts, _Logger())

    assert isinstance(results, AshAggregatedResults)
    assert [step for step, _ in order] == ["inputs", "discard"], order
    (inputs,) = [args for step, args in order if step == "inputs"]
    assert len(inputs) == 6, inputs
    assert isinstance(inputs[5], ras.OperatorConfigReads)


def test_a_refused_container_input_shows_one_line_and_clears_nothing(
    tmp_path, monkeypatch, capsys
):
    opts = _opts(tmp_path, mode=RunMode.container, build=False)
    opts.output_dir.mkdir()
    prior = opts.output_dir / "reports" / "ash.sarif"
    prior.parent.mkdir()
    prior.write_text('{"runs": []}\n', encoding="utf-8")
    monkeypatch.setattr(
        ras, "container_input_refusal", lambda *args: "refused\nsecond line"
    )
    monkeypatch.setattr(
        ras,
        "run_ash_container",
        lambda **kwargs: pytest.fail("the runtime was reached"),
    )
    _quiet_container_side_effects(monkeypatch)

    with pytest.raises(SystemExit) as exited:
        _run_container_mode(opts, _Logger())

    assert exited.value.code == 3
    assert "refused\\x0asecond line" in capsys.readouterr().err
    assert prior.exists(), "the previous run's output was cleared before the refusal"


def test_a_findings_exit_from_the_container_is_not_logged_as_a_failure(
    tmp_path, monkeypatch
):
    """Exit 2 is the scan inside saying it found something, re-derived from the
    results file here; it is not a failed container execution."""
    opts = _opts(tmp_path, mode=RunMode.container, build=False)

    def fake_run_ash_container(**kwargs):
        output_dir = Path(kwargs["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        results_file = output_dir / "ash_aggregated_results.json"
        results_file.write_text(
            AshAggregatedResults().model_dump_json(), encoding="utf-8"
        )
        mark_inner_run_completed(results_file, kwargs["outer_run_id"])
        return create_completed_process(
            args=["docker", "run"], returncode=2, stdout="", stderr="findings"
        )

    monkeypatch.setattr(ras, "run_ash_container", fake_run_ash_container)
    _quiet_container_side_effects(monkeypatch)
    logger = _Logger()

    results = _run_container_mode(opts, logger)

    assert isinstance(results, AshAggregatedResults)
    assert not any(
        "Container execution failed" in message for message in logger.records["error"]
    ), logger.records["error"]


def test_a_crash_that_exits_one_without_results_keeps_its_error_and_stderr(
    tmp_path, monkeypatch
):
    """An incomplete scan and a crash share exit 1; a crash that exits 1 before
    writing the results file has only the failure line and the captured stderr
    to explain itself, and the file-not-found line names the container's code."""
    opts = _opts(tmp_path, mode=RunMode.container, build=False)
    monkeypatch.setattr(
        ras,
        "run_ash_container",
        lambda **kwargs: create_completed_process(
            args=["docker", "run"],
            returncode=1,
            stdout="",
            stderr="Traceback (most recent call last): the scan raised",
        ),
    )
    _quiet_container_side_effects(monkeypatch)
    logger = _Logger()

    with pytest.raises(SystemExit) as exited:
        _run_container_mode(opts, logger)

    assert exited.value.code == 1
    errors = logger.records["error"]
    assert any("Container execution failed with code 1" in m for m in errors), errors
    assert any("the scan raised" in m for m in errors), errors
    assert any(
        "Results file not found" in m and "exited with code 1" in m for m in errors
    ), errors


# ---------------------------------------------------------------------------
# _run_nix_mode: a refusal inside the shell past a kept results file
# ---------------------------------------------------------------------------


def test_a_refusal_inside_the_nix_shell_is_carried_past_a_kept_results_file(
    tmp_path, monkeypatch
):
    """With --use-existing the results file is kept; an inner exit 3 must still
    reach the operator as 3, not be read back as "did not complete" and exit 1."""
    out = tmp_path / "out"
    out.mkdir()
    kept = out / "ash_aggregated_results.json"
    kept.write_text(AshAggregatedResults().model_dump_json(), encoding="utf-8")
    opts = _opts(tmp_path, mode=RunMode.nix, existing_results=str(kept))
    # The venue need not have nix: the two refusals of nix mode are asked through
    # run_ash_scan's own seam, ``nix_preflight`` (bound at import, so a stub of
    # run_ash_nix's lookup does not reach it), which answers nothing here; the
    # runner below starts no shell; and the sweeps of an earlier container run
    # touch nothing of this test's.
    monkeypatch.setattr(ras, "nix_preflight", lambda: None)
    monkeypatch.setattr(ras, "sweep_leftovers_before_run", lambda runner: [])
    monkeypatch.setattr(ras, "sweep_env_dirs", lambda *_args, **_kwargs: [])
    monkeypatch.setattr(
        ras,
        "run_ash_nix",
        lambda **kwargs: create_completed_process(
            args=["nix"], returncode=3, stdout="", stderr=""
        ),
    )

    with pytest.raises(SystemExit) as exited:
        _run_nix_mode(opts, _Logger())

    assert exited.value.code == 3
    assert kept.exists()


# ---------------------------------------------------------------------------
# _run_local_mode: the changed-files redaction reads the loaded config
# ---------------------------------------------------------------------------


class _StubOrchestrator:
    def __init__(self, config):
        self.config = config

    def add_metadata(self, **values):
        pass

    def restrict_to_changed_files(self, changed_files):
        pass

    def execute_scan(self, phases):
        return AshAggregatedResults()


def test_the_changed_files_redaction_reads_the_loaded_configs_values(
    tmp_path, monkeypatch
):
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    loaded = SimpleNamespace(
        _environment_values=["s3cr3t-value"], _override_values=[], fail_on_findings=None
    )
    monkeypatch.setattr(
        ASHScanOrchestrator,
        "create",
        staticmethod(lambda **kwargs: _StubOrchestrator(loaded)),
    )
    seen: Dict[str, object] = {}

    def recording_changed_files(opts, logger, *, values=()):
        seen["values"] = tuple(values)
        return None

    monkeypatch.setattr(ras, "_changed_file_set_for", recording_changed_files)
    opts = _opts(tmp_path)
    # The run writes its results file into the output directory, which the logger
    # would have made; here nothing made it, so it is made for the run.
    opts.output_dir.mkdir()

    _run_local_mode(opts, _Logger())

    assert "s3cr3t-value" in seen["values"], seen


# ---------------------------------------------------------------------------
# _outer_mode_config_load: a discovered loop, and the env config by identity
# ---------------------------------------------------------------------------


def test_a_discovered_link_loop_is_refused_before_the_nix_shell_clears_the_output(
    tmp_path, monkeypatch
):
    """Discovery selected a symbolic link loop as the config. With no --config to
    defer to, the load's own refusal stands, so the previous run's output is kept
    and no shell is entered. The interpreter's resolve() is made to raise as it
    does before Python 3.13, the branch that dropped the refusal."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    loop = source / ".ash.yaml"
    loop.symlink_to(loop)
    out = tmp_path / "out"
    prior = out / "reports" / "ash.sarif"
    prior.parent.mkdir(parents=True)
    prior.write_text('{"runs": []}\n', encoding="utf-8")
    real_resolve = Path.resolve

    def resolve(self, *args, **kwargs):
        if os.fspath(self) == os.fspath(loop):
            raise RuntimeError(f"Symlink loop from {os.fspath(self)!r}")
        return real_resolve(self, *args, **kwargs)

    monkeypatch.setattr(Path, "resolve", resolve)
    launcher = MagicMock()
    monkeypatch.setattr(ras, "run_ash_nix", launcher)

    with pytest.raises(ScanRefusedExit) as refused:
        run_ash_scan(
            source_dir=source,
            output_dir=out,
            mode=RunMode.nix,
            progress=False,
            show_summary=False,
        )

    assert refused.value.code == 3
    assert launcher.call_count == 0
    assert prior.exists(), "the previous run's output was cleared before the refusal"


def _env_config_case(tmp_path, monkeypatch, env_spelling: Path, selected: Path):
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    monkeypatch.setenv("ASH_CONFIG", str(env_spelling))
    monkeypatch.setattr(ras, "_image_schema_may_differ", lambda opts: True)
    monkeypatch.setattr(ras, "_gate_has_a_schema_to_judge", lambda opts, selected: True)
    opts = ScanOptions(
        source_dir=source,
        output_dir=tmp_path / "out",
        mode=RunMode.container,
        config=str(selected),
        build=False,
    )
    return ras._outer_mode_config_load(opts).refusal


def test_the_env_config_is_recognized_as_the_selected_file_by_identity(
    tmp_path, monkeypatch
):
    """When the image's schema may differ, the file ASH_CONFIG names keeps its
    document-only judgment even as the selected file. Named through a linked
    directory it is the same file, whatever the spelling."""
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    config = real_dir / "ash.yaml"
    config.write_text("fail_on_findings: maybe\n", encoding="utf-8")
    link_dir = tmp_path / "link"
    link_dir.symlink_to(real_dir, target_is_directory=True)

    refusal = _env_config_case(tmp_path, monkeypatch, link_dir / "ash.yaml", config)

    assert refusal is None, str(refusal)


def test_control_another_env_config_leaves_the_selected_files_model_refusal(
    tmp_path, monkeypatch
):
    config = tmp_path / "ash.yaml"
    config.write_text("fail_on_findings: maybe\n", encoding="utf-8")
    other = tmp_path / "other.yaml"
    other.write_text("fail_on_findings: true\n", encoding="utf-8")

    refusal = _env_config_case(tmp_path, monkeypatch, other, config)

    assert refusal is not None


# ---------------------------------------------------------------------------
# _print_invalid_config: error_text, not str()
# ---------------------------------------------------------------------------


class _Flag(BaseModel):
    fail_on_findings: bool


def test_an_invalid_config_message_describes_the_error_without_its_input(capsys):
    """A pydantic error in the chain is described without the value the file
    held, as the sibling exit-3 printer describes it."""
    try:
        _Flag(fail_on_findings="s3cr3t-value")
    except ValidationError as pydantic_error:
        try:
            raise ras.ASHConfigValidationError(
                f"Invalid configuration: {pydantic_error}"
            ) from pydantic_error
        except ras.ASHConfigValidationError as error:
            _print_invalid_config(error)

    out = _plain(capsys.readouterr().out)
    assert "ERROR (3) Invalid configuration" in out
    assert "s3cr3t-value" not in out, out


# ---------------------------------------------------------------------------
# print_incompleteness_message: nothing to scan is not a selection mistake
# ---------------------------------------------------------------------------


def _results_ignoring(*patterns: str) -> SimpleNamespace:
    """Results whose recorded config sets global_settings.ignore_paths."""
    return SimpleNamespace(
        ash_config=SimpleNamespace(
            global_settings=SimpleNamespace(ignore_paths=list(patterns))
        )
    )


def test_the_console_names_nothing_to_scan_not_a_selection_mistake(capsys):
    text = ras.nothing_to_scan_message(
        _results_ignoring("vendor/**"), ["bandit"], accept_remedy=False
    )

    print_incompleteness_message(
        [],
        [],
        no_scanner_ran=True,
        observed=[("bandit", ScannerStatus.SKIPPED.value)],
        nothing_to_scan=text,
    )

    out = _plain(capsys.readouterr().out)
    assert "nothing to scan" in out
    assert "usual cause is --scanners" not in out
    # The log line's own text: the pattern the config sets, and the gate's way
    # out, since nothing else fails this run.
    assert "vendor/**" in out
    assert "--no-fail-on-incomplete-scanners" in out


def test_the_console_withholds_the_gates_way_out_when_it_clears_nothing(capsys):
    """A tool that could not be stopped fails the run whatever the gate says, so
    the nothing-to-scan arm does not offer the gate flag beside it."""
    text = ras.nothing_to_scan_message(
        SimpleNamespace(ash_config=None), ["bandit"], accept_remedy=False
    )

    print_incompleteness_message(
        [],
        [],
        no_scanner_ran=True,
        observed=[("bandit", ScannerStatus.SKIPPED.value)],
        nothing_to_scan=text,
        could_not_stop=[("semgrep", "still running")],
    )

    out = _plain(capsys.readouterr().out)
    assert "nothing to scan" in out
    assert "ignore_paths" not in out
    nothing_to_scan_arm = out.split("no scanner ran", 1)[1]
    assert "--no-fail-on-incomplete-scanners" not in nothing_to_scan_arm


def test_the_log_line_and_the_console_text_are_one_helper():
    results = _results_ignoring("vendor/**")

    logged = ras.nothing_to_scan_message(results, ["bandit"])
    shown = ras.nothing_to_scan_message(results, ["bandit"], accept_remedy=False)

    assert logged.startswith(shown)
    assert logged.endswith("--no-fail-on-incomplete-scanners.")
    assert "--no-fail-on-incomplete-scanners" not in shown


def _logged_nothing_to_scan_line(tmp_path, monkeypatch, **causes) -> str:
    """The line `_compute_exit_code` logs for a run whose scanners all had
    nothing to scan, with *causes* (extra fields of ScanIncompleteness) beside it."""
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    logged = []
    monkeypatch.setattr(
        ras.ASH_LOGGER, "error", lambda message, *a, **k: logged.append(str(message))
    )
    monkeypatch.setattr(
        ras, "scanners_with_nothing_to_scan", lambda results: ["bandit"]
    )
    incompleteness = ras.ScanIncompleteness(
        no_scanner_ran=True, observed=(("bandit", "SKIPPED"),), **causes
    )
    monkeypatch.setattr(ras, "scan_incompleteness", lambda *a, **k: incompleteness)
    opts = ras.ScanOptions(source_dir=tmp_path / "src", output_dir=tmp_path / "out")

    assert ras._compute_exit_code(AshAggregatedResults(), opts) == 1

    (line,) = [text for text in logged if "No selected scanner" in text]
    return line


def test_the_logged_line_offers_the_gates_way_out_where_the_console_does(
    tmp_path, monkeypatch
):
    line = _logged_nothing_to_scan_line(tmp_path, monkeypatch)

    assert "--no-fail-on-incomplete-scanners" in line


def test_the_logged_line_withholds_the_gates_way_out_beside_a_cause_it_cannot_clear(
    tmp_path, monkeypatch
):
    """A tool that could not be stopped fails the run whatever the gate says;
    the console withholds the flag beside it, and the log line said the
    opposite."""
    line = _logged_nothing_to_scan_line(
        tmp_path, monkeypatch, could_not_stop=(("semgrep", "still running"),)
    )

    assert "--no-fail-on-incomplete-scanners" not in line


def test_control_every_scanner_skipped_for_another_reason_keeps_the_advice(capsys):
    print_incompleteness_message(
        [],
        [],
        no_scanner_ran=True,
        observed=[("semgrep", ScannerStatus.SKIPPED.value)],
    )

    assert "usual cause is --scanners" in _plain(capsys.readouterr().out)


# ---------------------------------------------------------------------------
# run_ash_scan: MCP-only options outside local mode, the legend's count, and
# the scanned tree of a positional target
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "option, value, mode",
    [
        ("severity_threshold_restriction", "high", RunMode.container),
        ("keep_previous_results", True, RunMode.nix),
    ],
)
def test_an_mcp_only_option_is_refused_outside_local_mode(
    tmp_path, monkeypatch, option, value, mode
):
    """Container and nix mode hand neither option to the ASH they run, so a caller
    that sets one there is told, as for untrusted_config, instead of scanning
    with it silently dropped."""
    (tmp_path / "src").mkdir()
    monkeypatch.setattr(
        ras,
        "run_ash_container",
        lambda **kwargs: pytest.fail("the runtime was reached"),
    )
    monkeypatch.setattr(
        ras, "run_ash_nix", lambda **kwargs: pytest.fail("the shell was reached")
    )

    with pytest.raises(ValueError, match=f"{option} is applied only"):
        run_ash_scan(
            source_dir=str(tmp_path / "src"),
            output_dir=str(tmp_path / "out"),
            mode=mode,
            progress=False,
            show_summary=False,
            **{option: value},
        )


def _local_run_with_one_metric_and_two_sarif_findings(monkeypatch) -> None:
    """A local run whose in-memory metrics say one actionable finding while the
    SARIF report it writes holds two: the two counts differ on purpose."""
    metrics = [
        SimpleNamespace(
            actionable=1,
            scanner_name="fake-scanner",
            status=ScannerStatus.PASSED.value,
        )
    ]
    monkeypatch.setattr(ras, "get_unified_scanner_metrics", lambda *a, **k: metrics)
    monkeypatch.setattr(ras, "_setup_logger", lambda opts: _Logger())

    def fake_local_mode(opts, logger):
        reports = opts.output_dir / "reports"
        reports.mkdir(parents=True, exist_ok=True)
        (reports / "ash.sarif").write_text(
            json.dumps(
                {
                    "version": "2.1.0",
                    "runs": [{"results": [{"level": "error"}, {"level": "error"}]}],
                }
            ),
            encoding="utf-8",
        )
        return sarif_report_written(AshAggregatedResults()), None

    monkeypatch.setattr(ras, "_run_local_mode", fake_local_mode)


def _scan_with_summary(tmp_path) -> int:
    with pytest.raises(SystemExit) as exited:
        run_ash_scan(
            source_dir=tmp_path,
            output_dir=tmp_path / "out",
            mode=RunMode.local,
            show_summary=True,
            min_severity="none",
            progress=False,
        )
    return exited.value.code


def test_the_legend_and_summary_name_the_count_that_gated(
    tmp_path, monkeypatch, capsys
):
    """The in-memory metrics say one actionable finding; the persisted SARIF
    report this run wrote holds two, and the exit code is derived from it. The
    legend names the number that gated."""
    _local_run_with_one_metric_and_two_sarif_findings(monkeypatch)

    assert _scan_with_summary(tmp_path) == 2
    out = _plain(capsys.readouterr().out)
    assert "Exiting due to 2 actionable findings" in out, out


def test_the_gating_count_is_read_once_per_run(tmp_path, monkeypatch):
    """One read of the SARIF report serves the exit code, the summary and the
    legend; a second read could only agree by luck."""
    _local_run_with_one_metric_and_two_sarif_findings(monkeypatch)
    reads: List[int] = []
    real = ras._gating_actionable_count

    def counting(*args, **kwargs):
        reads.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(ras, "_gating_actionable_count", counting)

    assert _scan_with_summary(tmp_path) == 2
    assert len(reads) == 1, reads


def test_a_positional_target_is_registered_as_the_scanned_tree(tmp_path, monkeypatch):
    seen: List[Path] = []

    @contextmanager
    def recording(root):
        seen.append(Path(root))
        yield

    monkeypatch.setattr(
        "automated_security_helper.utils.subprocess_utils.scanning_tree", recording
    )

    @_in_scanned_tree_from_arguments
    def scan(source_dir=None, output_dir=None, workspace_plan=None):
        return "ran"

    assert scan(tmp_path) == "ran"
    assert seen == [tmp_path]
