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
    """What _run_nix_mode hands the Nix launcher; nothing is started.

    Two seams of ``run_ash_scan`` are replaced together: ``run_ash_nix``, the
    runner, by a recorder, and ``nix_preflight``, the refusals asked before the
    previous run's output is cleared, by a no-op. The preflight is asked whatever
    the runner is, so a recorder alone would be refused on a host without `nix`
    before it was reached; replacing it here says, in one place, that these runs
    stand in for a host that has it.
    """
    seen: Dict[str, Any] = {}

    def fake_run_ash_nix(**kwargs):
        seen.update(kwargs)
        return create_completed_process(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ras, "run_ash_nix", fake_run_ash_nix)
    monkeypatch.setattr(ras, "nix_preflight", lambda: None)
    monkeypatch.setattr(ras, "sweep_leftovers_before_run", lambda runner: [])
    monkeypatch.setattr(ras, "sweep_env_dirs", lambda *_args, **_kwargs: [])
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
        offline_semgrep_rulesets="p/custom",
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
    assert _after_flag(argv, "--offline-semgrep-rulesets") == ["p/custom"]
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


def test_a_config_the_cli_read_from_ash_config_is_not_forwarded_as_named(
    tmp_path, monkeypatch
):
    """The scan CLI fills ``--config`` from ``ASH_CONFIG`` when none is typed, and
    the shell keeps that variable, so the inner CLI reads it the same way. Forwarded
    as well, the command named a config the caller never named (install.md: with no
    ``--config``, the file ``ASH_CONFIG`` names is the config too). A config the
    caller did name is forwarded whatever the variable holds."""
    env_config = tmp_path / "env" / "ash.yaml"
    named_config = tmp_path / "cfg" / "ash.yaml"
    monkeypatch.setenv("ASH_CONFIG", str(env_config))

    def options(config):
        return ras.ScanOptions(
            source_dir=tmp_path / "src",
            output_dir=tmp_path / "out",
            mode=RunMode.nix,
            config=config,
        )

    assert "--config" not in ras._nix_inner_argv(options(str(env_config)))
    assert _after_flag(ras._nix_inner_argv(options(str(named_config))), "--config") == [
        str(named_config)
    ]


def test_a_host_without_nix_keeps_the_previous_runs_output(tmp_path, monkeypatch):
    """The refusal is asked before the previous run's output is cleared: a
    refused run starts no shell, so it must not delete the reports of one that
    did."""
    from automated_security_helper.interactions import run_ash_nix

    monkeypatch.delenv(run_ash_nix.ASH_IN_NIX_ENV_VAR, raising=False)
    monkeypatch.setattr(run_ash_nix, "find_executable", lambda _name: None)
    monkeypatch.setattr(ras, "sweep_leftovers_before_run", lambda runner: [])
    monkeypatch.setattr(ras, "sweep_env_dirs", lambda *_args, **_kwargs: [])
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


@pytest.mark.parametrize(
    "given, present, absent",
    [
        pytest.param(
            {"shard_index": 1}, "--shard-index", "--shard-count", id="index-alone"
        ),
        pytest.param(
            {"shard_count": 4}, "--shard-count", "--shard-index", id="count-alone"
        ),
    ],
)
def test_half_a_shard_pair_reaches_the_inner_scan_to_be_refused_there(
    launched, tmp_path, given, present, absent
):
    """ScanPhase is the one place that refuses an unusable pair, and it can
    refuse only what reaches it. Forwarding the pair only when both were set
    turned a caller's half pair into an unsharded whole scan."""
    _run(tmp_path, **given)

    argv = launched["argv"]
    assert present in argv
    assert absent not in argv


def test_a_whole_shard_pair_is_forwarded_as_before(launched, tmp_path):
    """Control."""
    _run(tmp_path, shard_index=1, shard_count=4)

    argv = launched["argv"]
    assert _after_flag(argv, "--shard-index") == ["1"]
    assert _after_flag(argv, "--shard-count") == ["4"]


def test_a_results_file_that_is_not_the_output_directorys_own_is_refused(
    launched, tmp_path
):
    """The inner command line can only say --use-existing, which reads the
    output directory's own file; a caller naming another file was handed that
    flag and had an earlier run's file read in place of its own. Refused with
    exit 3 before the previous run's output is cleared."""
    src = tmp_path / "src"
    src.mkdir()
    out = tmp_path / "out"
    prior = out / "reports" / "ash.sarif"
    prior.parent.mkdir(parents=True)
    prior.write_text('{"runs": []}\n', encoding="utf-8")
    elsewhere = tmp_path / "elsewhere" / "results.json"
    elsewhere.parent.mkdir()
    elsewhere.write_text("{}\n", encoding="utf-8")
    opts = ras.ScanOptions(
        source_dir=src,
        output_dir=out,
        mode=RunMode.nix,
        existing_results=str(elsewhere),
        progress=False,
        show_summary=False,
    )

    with pytest.raises(SystemExit) as refused:
        ras._run_nix_mode(opts, MagicMock())

    assert refused.value.code == 3
    assert "argv" not in launched, "the shell was entered for a file it cannot read"
    assert prior.exists(), "the previous run's report was cleared before the refusal"


@pytest.mark.parametrize(
    "spelling",
    [
        pytest.param(
            lambda out: str(out / "." / "ash_aggregated_results.json"), id="dot"
        ),
        # Relative to the working directory, as a command line names it.
        pytest.param(lambda out: "out/ash_aggregated_results.json", id="relative"),
        pytest.param(
            lambda out: str(
                out.parent / "elsewhere" / ".." / "out" / "ash_aggregated_results.json"
            ),
            id="dot-dot",
        ),
    ],
)
def test_the_output_directorys_own_results_file_is_forwarded_as_use_existing(
    launched, tmp_path, monkeypatch, spelling
):
    """Control: the file --use-existing resolves to, named by the caller through
    a `.` component, a path relative to the working directory, or a `..`
    component, is not refused (both sides are compared resolved) and reaches the
    inner scan as the flag."""
    monkeypatch.chdir(tmp_path)
    out = tmp_path / "out"
    out.mkdir()
    opts = ras.ScanOptions(
        source_dir=tmp_path / "src",
        output_dir=out,
        mode=RunMode.nix,
        existing_results=spelling(out),
        progress=False,
        show_summary=False,
    )

    ras._refuse_a_results_file_the_shell_cannot_be_handed(opts, MagicMock())

    assert "--use-existing" in ras._nix_inner_argv(opts)


# Every ScanOptions field is placed: forwarded by the builder, refused for the
# mode before the builder runs, or left off on purpose. A field added to
# ScanOptions lands in none of these sets and fails the test below, so it cannot
# silently never reach the scan inside the shell.
_FORWARDED = {
    "source_dir",
    "output_dir",
    "allow_missing_projects",
    "config",
    "config_overrides",
    "scanners",
    "excluded_scanners",
    "ash_plugin_modules",
    "output_formats",
    "phases",
    "strategy",
    "offline",
    "offline_semgrep_rulesets",
    "progress",
    "color",
    "show_summary",
    "quiet",
    "verbose",
    "debug",
    "simple",
    "cleanup",
    "inspect",
    "python_based_plugins_only",
    "ignore_suppressions",
    "log_level",
    "fail_on_findings",
    "fail_on_incomplete_scanners",
    "min_severity",
    "changed_files_only",
    "base_ref",
    "existing_results",
    "shard_index",
    "shard_count",
}
# Each refused field with a non-default value run_ash_scan is given below, so a
# field filed here is also shown to be refused: a name alone would let a field be
# listed as refused while the mode dropped it without a word.
_REFUSED_FOR_THE_MODE = {
    "config_base_gate": lambda _path: True,
    "untrusted_config": True,
    "client_config_policy": object(),
    "remote_client": True,
    "severity_threshold_restriction": "HIGH",
    "keep_previous_results": True,
    "trusted_config_path": "/elsewhere/ash.yaml",
}
_NOT_FORWARDED_ON_PURPOSE = {
    "mode",
    "workspace_plan",
    "workspace_config_as_named",
    "client_overrides",
    "selection_origin",
    "build",
    "run",
    "force",
    "oci_runner",
    "build_target",
    "container_uid",
    "container_gid",
    "container_network",
    "ash_revision_to_install",
    "custom_containerfile",
    "custom_build_arg",
}


def test_every_scan_option_is_forwarded_refused_or_excluded_by_name():
    fields = set(ras.ScanOptions.model_fields)
    refused = set(_REFUSED_FOR_THE_MODE)

    unplaced = fields - _FORWARDED - refused - _NOT_FORWARDED_ON_PURPOSE
    assert not unplaced, (
        f"ScanOptions gained {sorted(unplaced)}; decide whether the Nix inner "
        "scan is given it, refuses it or leaves it out, and list it"
    )
    stale = (_FORWARDED | refused | _NOT_FORWARDED_ON_PURPOSE) - fields
    assert not stale, (
        f"the lists name fields ScanOptions no longer has: {sorted(stale)}"
    )
    assert not (_FORWARDED & refused)
    assert not (_FORWARDED & _NOT_FORWARDED_ON_PURPOSE)
    assert not (refused & _NOT_FORWARDED_ON_PURPOSE)


def test_the_builder_reads_every_forwarded_field(tmp_path):
    """The forwarded set is the builder's own: a field listed as forwarded that
    the builder never reads would pass the placement test above and still be
    lost."""
    import inspect
    import re

    source = inspect.getsource(ras._nix_inner_argv)
    # Whole-word reads: `opts.config` is not read because `opts.config_overrides`
    # is, nor `opts.offline` because `opts.offline_semgrep_rulesets` is.
    unread = sorted(
        name
        for name in _FORWARDED
        if not re.search(rf"\bopts\.{re.escape(name)}\b", source)
    )
    assert not unread, unread


@pytest.mark.parametrize(
    "option",
    [
        pytest.param({name: value}, id=name)
        for name, value in _REFUSED_FOR_THE_MODE.items()
    ],
)
def test_an_option_the_shell_cannot_be_given_is_refused_for_nix_mode(tmp_path, option):
    """The scan CLI has no flag for these, so a run in Nix mode dropped them
    without a word: a restriction dropped loosens the gate, a kept-results
    request dropped deletes what the caller asked to keep, a trusted config path
    dropped leaves its grants unread. Every field the placement test files as
    refused is run here, so none can be filed as refused and dropped."""
    with pytest.raises(ValueError) as refused:
        ras.run_ash_scan(
            source_dir=str(tmp_path / "src"),
            output_dir=str(tmp_path / "out"),
            mode=RunMode.nix,
            progress=False,
            show_summary=False,
            **option,
        )

    (name,) = option
    assert name in str(refused.value)
    assert "nix" in str(refused.value)


@pytest.mark.parametrize(
    "option",
    [
        pytest.param({"severity_threshold_restriction": "HIGH"}, id="restriction"),
        pytest.param({"keep_previous_results": True}, id="keep-previous-results"),
        pytest.param({"trusted_config_path": "/elsewhere/ash.yaml"}, id="trusted"),
    ],
)
def test_an_option_the_container_cannot_be_given_is_refused_for_container_mode(
    tmp_path, option
):
    """Container mode is the other mode that re-executes ASH, and its runner has
    no parameter and builds no flag for these three (``run_ash_container``'s
    signature and the inner command line it assembles), so a container run
    dropped them as silently as a Nix run did. The same refusal, before any
    runtime is looked for: the container arm of the loop, pinned on its own."""
    with pytest.raises(ValueError) as refused:
        ras.run_ash_scan(
            source_dir=str(tmp_path / "src"),
            output_dir=str(tmp_path / "out"),
            mode=RunMode.container,
            progress=False,
            show_summary=False,
            **option,
        )

    (name,) = option
    assert name in str(refused.value)
    assert "container" in str(refused.value)


def test_the_missing_payload_message_names_what_ran():
    assert "Nix shell" in ras._no_workspace_payload_message(RunMode.nix)
    assert "container" in ras._no_workspace_payload_message(RunMode.container)
    assert "container" not in ras._no_workspace_payload_message(RunMode.nix)


def test_a_stand_in_runner_does_not_lift_the_refusal(tmp_path, monkeypatch):
    """The preflight is ``run_ash_scan``'s own seam, asked whatever stands in for
    the runner: a recorder in run_ash_nix's place that carries no check of its
    own is still refused on a host without `nix`, and never reached. Read off
    the runner instead (an attribute the real one carried), the check went with
    the runner, and a stand-in lifted it without saying so."""
    from automated_security_helper.interactions import run_ash_nix

    monkeypatch.delenv(run_ash_nix.ASH_IN_NIX_ENV_VAR, raising=False)
    monkeypatch.setattr(run_ash_nix, "find_executable", lambda _name: None)
    monkeypatch.setattr(ras, "sweep_leftovers_before_run", lambda runner: [])
    monkeypatch.setattr(ras, "sweep_env_dirs", lambda *_args, **_kwargs: [])
    reached: list = []

    def recorder(**kwargs):
        reached.append(kwargs)
        return create_completed_process(args=[], returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ras, "run_ash_nix", recorder)
    assert not hasattr(recorder, "preflight")
    src = tmp_path / "src"
    src.mkdir()
    opts = ras.ScanOptions(
        source_dir=src,
        output_dir=tmp_path / "out",
        mode=RunMode.nix,
        progress=False,
        show_summary=False,
    )

    with pytest.raises(SystemExit) as refused:
        ras._run_nix_mode(opts, MagicMock())

    assert refused.value.code == 1
    assert reached == [], "the stand-in runner was reached on a host without nix"


def test_the_seam_is_the_real_preflight_by_default():
    """Control for the test above: left alone, the seam is the runner module's
    own check, the one the entry point asks before clearing the previous run's
    output."""
    from automated_security_helper.interactions import run_ash_nix

    assert ras.nix_preflight is run_ash_nix.nix_executable_for_this_run
