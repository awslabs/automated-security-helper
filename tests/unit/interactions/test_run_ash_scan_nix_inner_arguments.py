# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Nix mode builds the inner scan's command line from the call's own options.

``_run_nix_mode`` handed ``run_ash_nix`` no arguments, so the inner scan was built
from this process's ``sys.argv``. A library caller's
``run_ash_scan(mode=RunMode.nix, source_dir=..., scanners=...)`` then ran the
scan the host program was started with (its directory, its scanner set, its
output directory) and read that run's results back as the call's own. The
inner command line is now built from the ``ScanOptions`` of the call, which is
also why ``--cli-json-input`` never reaches the inner scan: its document was
read into those options already, and the shell's standard input is empty.

The Nix launcher is replaced by a recorder, so no shell is ever started.
"""

from __future__ import annotations

import sys
from typing import Any, Dict
from unittest.mock import MagicMock

import pytest

from automated_security_helper.core.enums import (
    AshLogLevel,
    ExecutionPhase,
    ExecutionStrategy,
    ExportFormat,
    RunMode,
)
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.subprocess_utils import create_completed_process

pytestmark = pytest.mark.unit


@pytest.fixture
def launched(monkeypatch) -> Dict[str, Any]:
    """What _run_nix_mode hands the Nix launcher; nothing is started."""
    seen: Dict[str, Any] = {}

    def fake_run_ash_nix(**kwargs):
        seen.update(kwargs)
        return create_completed_process(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ras, "run_ash_nix", fake_run_ash_nix)
    monkeypatch.setattr(ras, "sweep_leftovers_before_run", lambda runner: [])
    monkeypatch.setattr(ras, "sweep_env_dirs", list)
    return seen


def _after_flag(argv, flag):
    return [argv[i + 1] for i, arg in enumerate(argv[:-1]) if arg == flag]


def _run(tmp_path, **options):
    src = tmp_path / "src"
    src.mkdir(exist_ok=True)
    opts = ras.ScanOptions(
        source_dir=src,
        output_dir=tmp_path / "out",
        mode=RunMode.nix,
        progress=False,
        show_summary=False,
        **options,
    )
    # No results file is written by the recorder, so the read-back exits 1.
    with pytest.raises(SystemExit):
        ras._run_nix_mode(opts, MagicMock())
    return opts


def test_a_library_callers_options_reach_the_inner_scan_not_the_host_programs_argv(
    launched, tmp_path, monkeypatch
):
    monkeypatch.setattr(
        sys,
        "argv",
        ["host-program", "serve", "--source-dir", "/elsewhere", "--scanners", "grype"],
    )

    opts = _run(tmp_path, scanners=["bandit"], config_overrides=["global_settings.x=1"])

    argv = launched.get("argv")
    assert argv is not None, "the inner scan was built from the process's argv"
    assert _after_flag(argv, "--source-dir") == [str(opts.source_dir)]
    assert _after_flag(argv, "--output-dir") == [str(opts.output_dir)]
    assert _after_flag(argv, "--scanners") == ["bandit"]
    assert _after_flag(argv, "--config-overrides") == ["global_settings.x=1"]
    assert "/elsewhere" not in argv
    assert "grype" not in argv
    assert "serve" not in argv
    assert launched["outer_run_id"] is not None


def test_a_json_input_flag_on_the_command_line_does_not_reach_the_inner_scan(
    launched, tmp_path, monkeypatch
):
    """The document was read into the options already; the shell's standard
    input is empty, so a forwarded ``--cli-json-input -`` made the inner scan
    read an empty document and refuse."""
    monkeypatch.setattr(sys, "argv", ["ash", "scan", "--cli-json-input", "-"])

    _run(tmp_path)

    argv = launched.get("argv")
    assert argv is not None
    assert "--cli-json-input" not in argv
    assert "-" not in argv


def test_every_forwarded_option_is_spelled_as_the_scan_cli_reads_it(tmp_path):
    opts = ras.ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        mode=RunMode.nix,
        config=str(tmp_path / "ash.yaml"),
        config_overrides=["a=1", "b=2"],
        scanners=["bandit", "semgrep"],
        excluded_scanners=["grype"],
        ash_plugin_modules=["my.plugins"],
        output_formats=[ExportFormat.SARIF],
        phases=[ExecutionPhase.SCAN],
        strategy=ExecutionStrategy.SEQUENTIAL,
        offline=True,
        progress=False,
        color=False,
        show_summary=False,
        quiet=True,
        verbose=True,
        debug=True,
        simple=True,
        cleanup=True,
        inspect=True,
        python_based_plugins_only=True,
        ignore_suppressions=True,
        log_level=AshLogLevel.DEBUG,
        fail_on_findings=False,
        fail_on_incomplete_scanners=True,
        min_severity="high",
        changed_files_only=True,
        base_ref="origin/trunk",
        existing_results=str(tmp_path / "out" / "ash_aggregated_results.json"),
        shard_index=1,
        shard_count=4,
    )

    argv = ras._nix_inner_argv(opts)

    assert argv[0] == "scan"
    assert _after_flag(argv, "--source-dir") == [str(opts.source_dir)]
    assert _after_flag(argv, "--output-dir") == [str(opts.output_dir)]
    assert _after_flag(argv, "--config") == [str(tmp_path / "ash.yaml")]
    assert _after_flag(argv, "--config-overrides") == ["a=1", "b=2"]
    assert _after_flag(argv, "--scanners") == ["bandit", "semgrep"]
    assert _after_flag(argv, "--exclude-scanners") == ["grype"]
    assert _after_flag(argv, "--ash-plugin-modules") == ["my.plugins"]
    assert _after_flag(argv, "--output-formats") == [ExportFormat.SARIF.value]
    assert _after_flag(argv, "--phases") == [ExecutionPhase.SCAN.value]
    assert _after_flag(argv, "--strategy") == [ExecutionStrategy.SEQUENTIAL.value]
    assert _after_flag(argv, "--log-level") == [AshLogLevel.DEBUG.value]
    assert _after_flag(argv, "--min-severity") == ["high"]
    assert _after_flag(argv, "--base-ref") == ["origin/trunk"]
    assert _after_flag(argv, "--shard-index") == ["1"]
    assert _after_flag(argv, "--shard-count") == ["4"]
    for flag in (
        "--offline",
        "--no-progress",
        "--no-color",
        "--no-show-summary",
        "--quiet",
        "--verbose",
        "--debug",
        "--simple",
        "--cleanup",
        "--inspect",
        "--python-based-plugins-only",
        "--ignore-suppressions",
        "--no-fail-on-findings",
        "--fail-on-incomplete-scanners",
        "--changed-files-only",
        "--use-existing",
    ):
        assert argv.count(flag) == 1, (flag, argv)
    # Left to rewrite_mode_args, which appends the local mode once.
    assert "--mode" not in argv


def test_the_defaults_forward_only_the_two_directories(tmp_path):
    opts = ras.ScanOptions(
        source_dir=tmp_path / "src", output_dir=tmp_path / "out", mode=RunMode.nix
    )

    argv = ras._nix_inner_argv(opts)

    assert argv[:5] == [
        "scan",
        "--source-dir",
        str(opts.source_dir),
        "--output-dir",
        str(opts.output_dir),
    ]
    # The default strategy and the three default phases are spelled out; nothing
    # else is given a flag the CLI would read as a non-default.
    rest = argv[5:]
    assert _after_flag(rest, "--phases") == [
        ExecutionPhase.CONVERT.value,
        ExecutionPhase.SCAN.value,
        ExecutionPhase.REPORT.value,
    ]
    assert _after_flag(rest, "--strategy") == [ExecutionStrategy.PARALLEL.value]
    flags = [arg for arg in rest if arg.startswith("--")]
    assert set(flags) == {"--phases", "--strategy"}, rest


def test_a_host_without_nix_keeps_the_previous_runs_output(tmp_path, monkeypatch):
    """The refusal is asked before the previous run's output is cleared: a
    refused run starts no shell, so it must not delete the reports of one that
    did."""
    from automated_security_helper.interactions import run_ash_nix

    monkeypatch.delenv(run_ash_nix.ASH_IN_NIX_ENV_VAR, raising=False)
    monkeypatch.setattr(run_ash_nix, "find_executable", lambda _name: None)
    monkeypatch.setattr(ras, "sweep_leftovers_before_run", lambda runner: [])
    monkeypatch.setattr(ras, "sweep_env_dirs", list)
    src = tmp_path / "src"
    src.mkdir()
    out = tmp_path / "out"
    prior = out / "reports" / "ash.sarif"
    prior.parent.mkdir(parents=True)
    prior.write_text('{"runs": []}\n', encoding="utf-8")
    (out / "ash_aggregated_results.json").write_text("{}\n", encoding="utf-8")
    opts = ras.ScanOptions(
        source_dir=src,
        output_dir=out,
        mode=RunMode.nix,
        progress=False,
        show_summary=False,
    )

    with pytest.raises(SystemExit) as refused:
        ras._run_nix_mode(opts, MagicMock())

    assert refused.value.code == 1
    assert prior.exists(), "the previous run's report was cleared before the refusal"
    assert (out / "ash_aggregated_results.json").exists()


def test_a_stand_in_runner_is_asked_nothing_about_nix(launched, tmp_path, monkeypatch):
    """The refusals travel with the runner: a recorder in run_ash_nix's place
    starts no shell, so a host without `nix` is no reason to refuse before it.
    Asked beside the runner instead, the check refused every such run on a
    host without nix before the recorder was reached."""
    from automated_security_helper.interactions import run_ash_nix

    monkeypatch.setattr(run_ash_nix, "find_executable", lambda _name: None)

    _run(tmp_path)

    assert launched.get("argv") is not None, "the stand-in runner was never reached"


def test_the_real_runner_carries_the_refusals():
    """Control for the test above: the real runner's preflight is the check
    the entry point asks before clearing the previous run's output."""
    from automated_security_helper.interactions import run_ash_nix

    assert run_ash_nix.run_ash_nix.preflight is run_ash_nix.nix_executable_for_this_run
