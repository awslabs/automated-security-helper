# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The container and Nix wrappers never answer from previous results a scan kept.

Container mode and Nix mode run ASH again somewhere else and then read
``ash_aggregated_results.json`` back out of the output directory, so that file's
presence stands in for "this invocation scanned". ``_discard_prior_run_artifacts``
clears what a local scan clears before the inner run so that it does.

An MCP scan keeps the previous scan's results while it runs
(core/previous_results.py): in ``.ash_previous_results`` while it runs, and back at
the top level with a marker file beside them when it ends without results. Both
defeat the read-back. A held set that an inner run puts back after a crash holds
an earlier scan's results, and a directory carrying the marker holds results
that are not the last scan's at all. So the wrappers remove the held set, its
staging directory and the
marker with the rest, and refuse to read back from a directory that carries the
marker after the inner run.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.core.previous_results import (
    HELD_DIR_NAME,
    RESTORED_MARKER_NAME,
    holds_restored_results,
)
from automated_security_helper.interactions import run_ash_scan as module
from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _run_container_mode,
    _run_nix_mode,
)
from automated_security_helper.utils.subprocess_utils import create_completed_process

pytestmark = pytest.mark.unit

STALE = "results an earlier scan left, held while a later one ran"

_ENGINE = (
    "automated_security_helper.core.execution_engine.ScanExecutionEngine.execute_phases"
)


def _results_json(name: str) -> str:
    from automated_security_helper.models.asharp_model import AshAggregatedResults

    model = AshAggregatedResults()
    model.metadata.project_name = name
    return model.model_dump_json(by_alias=True)


def _seed(root: Path, files) -> None:
    for rel, text in files.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")


def _opts(tmp_path: Path) -> ScanOptions:
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    return ScanOptions(source_dir=source, output_dir=tmp_path / "out")


def _plant_a_kept_set(output: Path) -> None:
    _seed(output / HELD_DIR_NAME, {"ash_aggregated_results.json": _results_json(STALE)})
    _seed(output / (HELD_DIR_NAME + ".partial"), {"reports/ash.sarif": "{}"})
    (output / RESTORED_MARKER_NAME).write_text("restored\n", encoding="utf-8")


def _run_mode(mode: str, opts: ScanOptions, inner):
    """Run one wrapper with ``inner`` standing in for the container or the shell."""
    if mode == "container":
        with patch.object(module, "run_ash_container", side_effect=inner):
            return _run_container_mode(opts, MagicMock())
    with (
        patch.object(module, "run_ash_nix", side_effect=inner),
        patch.object(module, "nix_preflight", lambda: None),
    ):
        return _run_nix_mode(opts, MagicMock())


@pytest.mark.parametrize("mode", ["container", "nix"])
def test_a_kept_set_is_removed_before_the_inner_run(tmp_path, mode):
    opts = _opts(tmp_path)
    output = opts.output_dir
    _plant_a_kept_set(output)
    seen = {}

    def inner(*args, **kwargs):
        seen["held"] = (output / HELD_DIR_NAME).exists()
        seen["partial"] = (output / (HELD_DIR_NAME + ".partial")).exists()
        seen["marker"] = holds_restored_results(output)
        return create_completed_process(args=[], returncode=1, stdout="", stderr="")

    with pytest.raises(SystemExit) as exited:
        _run_mode(mode, opts, inner)

    assert seen == {"held": False, "partial": False, "marker": False}
    assert exited.value.code != 0


@pytest.mark.parametrize("mode", ["container", "nix"])
def test_results_a_restore_put_back_are_not_read_back(tmp_path, mode):
    """An inner run that ended without results and put the previous ones back."""
    opts = _opts(tmp_path)
    output = opts.output_dir

    def inner(*args, **kwargs):
        _seed(output, {"ash_aggregated_results.json": _results_json(STALE)})
        (output / RESTORED_MARKER_NAME).write_text("restored\n", encoding="utf-8")
        return create_completed_process(args=[], returncode=0, stdout="", stderr="")

    with pytest.raises(SystemExit) as exited:
        _run_mode(mode, opts, inner)

    assert exited.value.code != 0


@pytest.mark.parametrize("mode", ["container", "nix"])
def test_a_crashed_inner_scan_over_a_held_set_exits_non_zero(tmp_path, mode):
    """An inner CLI that crashes over a held set makes the host exit non-zero,
    never 0 on the held set.

    The inner run here is the real local scan the container's entrypoint runs,
    with its scanners replaced by a crash.
    """
    opts = _opts(tmp_path)
    output = opts.output_dir
    _seed(output / HELD_DIR_NAME, {"ash_aggregated_results.json": _results_json(STALE)})
    inner_exit = {}

    def inner(*args, **kwargs):
        with patch(_ENGINE, side_effect=RuntimeError("scanner orchestration crashed")):
            try:
                module.run_ash_scan(
                    source_dir=str(opts.source_dir),
                    output_dir=str(output),
                    mode=module.RunMode.local,
                    progress=False,
                    show_summary=False,
                    quiet=True,
                )
                inner_exit["code"] = 0
            except SystemExit as e:
                inner_exit["code"] = e.code
        return create_completed_process(
            args=[], returncode=inner_exit["code"], stdout="", stderr=""
        )

    try:
        outcome = ("returned", getattr(_run_mode(mode, opts, inner), "metadata", None))
    except SystemExit as e:
        outcome = ("exited", e.code)

    assert inner_exit["code"] == 1
    assert outcome[0] == "exited" and outcome[1] != 0, outcome
    assert not (output / HELD_DIR_NAME).exists()


def test_the_container_host_exit_code_after_an_inner_crash(tmp_path):
    """Through run_ash_scan(mode=container), as `ash scan --mode container` runs it."""
    opts = _opts(tmp_path)
    output = opts.output_dir
    _seed(
        output / HELD_DIR_NAME,
        {
            "ash_aggregated_results.json": _results_json(STALE),
            "reports/ash.sarif": json.dumps({"version": "2.1.0", "runs": []}),
        },
    )

    def inner(**kwargs):
        with patch(_ENGINE, side_effect=RuntimeError("scanner orchestration crashed")):
            try:
                module.run_ash_scan(
                    source_dir=str(opts.source_dir),
                    output_dir=str(output),
                    mode=module.RunMode.local,
                    progress=False,
                    show_summary=False,
                    quiet=True,
                )
                code = 0
            except SystemExit as e:
                code = e.code
        return create_completed_process(args=[], returncode=code, stdout="", stderr="")

    with patch.object(module, "run_ash_container", side_effect=inner):
        with pytest.raises(SystemExit) as exited:
            module.run_ash_scan(
                source_dir=str(opts.source_dir),
                output_dir=str(output),
                mode=module.RunMode.container,
                progress=False,
                show_summary=False,
                quiet=True,
            )

    assert exited.value.code != 0


def _put_back_results(output: Path) -> None:
    """The output directory a scan that kept its earlier results left behind."""
    _seed(output, {"ash_aggregated_results.json": _results_json(STALE)})
    (output / RESTORED_MARKER_NAME).write_text("restored\n", encoding="utf-8")


def test_a_results_file_elsewhere_does_not_vouch_for_the_put_back_results(tmp_path):
    """The scan inside the container reads the output directory's own results
    file whatever path the caller named, so a caller naming another file did not
    ask for the file the marker describes. The put-back earlier scan was read
    back as this run's."""
    opts = _opts(tmp_path)
    output = opts.output_dir
    _put_back_results(output)
    elsewhere = tmp_path / "elsewhere" / "r.json"
    elsewhere.parent.mkdir()
    elsewhere.write_text(_results_json("the file the caller named"), encoding="utf-8")
    opts.existing_results = str(elsewhere)
    logger = MagicMock()

    def inner(*args, **kwargs):
        return create_completed_process(args=[], returncode=0, stdout="", stderr="")

    with patch.object(module, "run_ash_container", side_effect=inner):
        with pytest.raises(SystemExit) as exited:
            _run_container_mode(opts, logger)

    assert exited.value.code == 1
    assert "put back" in str(logger.error.call_args_list)
    assert (output / RESTORED_MARKER_NAME).exists()


def test_a_marker_that_cannot_be_removed_is_reported_above_debug(tmp_path, monkeypatch):
    """The marker beside this run's fresh results makes a later reader take them
    for an earlier scan's; the failed removal was logged at debug only."""
    opts = _opts(tmp_path)
    _put_back_results(opts.output_dir)
    opts.existing_results = str(opts.output_dir / "ash_aggregated_results.json")

    def refuse(self, *args, **kwargs):
        raise PermissionError(13, "Permission denied", str(self))

    monkeypatch.setattr(Path, "unlink", refuse)
    logger = MagicMock()

    module._drop_restore_marker_after_a_completed_run(opts, logger)

    assert RESTORED_MARKER_NAME in str(logger.warning.call_args_list)
    logger.debug.assert_not_called()


def test_a_marker_that_is_removed_says_nothing(tmp_path):
    """Control."""
    opts = _opts(tmp_path)
    _put_back_results(opts.output_dir)
    opts.existing_results = str(opts.output_dir / "ash_aggregated_results.json")
    logger = MagicMock()

    module._drop_restore_marker_after_a_completed_run(opts, logger)

    assert not (opts.output_dir / RESTORED_MARKER_NAME).exists()
    logger.warning.assert_not_called()


def test_only_the_output_directorys_own_file_is_a_request_for_it(tmp_path):
    """Control: the file the inner run reads, spelled directly or through the
    directory's parent, is the request the marker steps aside for."""
    opts = _opts(tmp_path)
    own = opts.output_dir / "ash_aggregated_results.json"
    opts.output_dir.mkdir()

    opts.existing_results = str(own)
    assert module._names_the_output_directorys_own_results(opts)

    opts.existing_results = str(opts.output_dir / ".." / "out" / own.name)
    assert module._names_the_output_directorys_own_results(opts)

    opts.existing_results = str(tmp_path / "elsewhere" / own.name)
    assert not module._names_the_output_directorys_own_results(opts)

    opts.existing_results = None
    assert not module._names_the_output_directorys_own_results(opts)
