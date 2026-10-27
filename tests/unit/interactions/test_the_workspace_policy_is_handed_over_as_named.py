# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Container mode hands the workspace policy over by the name it was given.

The plan holds the resolved policy path, which is the file read; the refusal
for a policy named inside the workspace's tree that links out of it judges the
operator's spelling, so the carried value has to be that spelling. Carrying
the resolved target instead made the refusal unreachable on the CLI and
run_ash_scan routes: the gate saw only a path outside the tree and let the run
mount the repository-chosen target.
"""

from __future__ import annotations

import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from automated_security_helper.interactions import run_ash_container, run_ash_scan

pytestmark = pytest.mark.skipif(
    os.name == "nt", reason="the layouts are built from POSIX symlinks"
)


def _opts(root: Path, named, target) -> SimpleNamespace:
    plan = SimpleNamespace(
        workspace_root=str(root), workspace_config_source=str(target)
    )
    return SimpleNamespace(
        workspace_plan=plan,
        workspace_config_as_named=None if named is None else str(named),
    )


def _layout(tmp_path: Path):
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    target = outside / "ash-workspace.yaml"
    target.write_text("projects: []\n")
    root = tmp_path / "ws"
    root.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    return root, out, target


def test_a_policy_named_in_the_root_as_a_link_out_is_refused_before_the_run(
    tmp_path, monkeypatch
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    root, out, target = _layout(tmp_path)
    named = root / "pol.yaml"
    named.symlink_to(target)
    opts = _opts(root, named, target.resolve())
    carried = run_ash_scan._workspace_policy_for_the_container(opts)
    assert Path(carried) == named, carried
    refusal = run_ash_container.container_input_refusal(
        root, out, None, carried, "ws.code-workspace"
    )
    assert refusal is not None and "link" in refusal, refusal


def test_a_policy_of_the_operators_own_still_runs(tmp_path, monkeypatch):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    root, out, target = _layout(tmp_path)
    opts = _opts(root, target, target.resolve())
    carried = run_ash_scan._workspace_policy_for_the_container(opts)
    assert Path(carried) == target
    assert (
        run_ash_container.container_input_refusal(
            root, out, None, carried, "ws.code-workspace"
        )
        is None
    )


def test_a_discovered_policy_is_carried_by_its_found_name(tmp_path, monkeypatch):
    """No --workspace-config given: the candidate discovery finds is the name."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    root, out, target = _layout(tmp_path)
    found = root / "ash-workspace.yaml"
    found.symlink_to(target)
    opts = _opts(root, None, target.resolve())
    carried = run_ash_scan._workspace_policy_for_the_container(opts)
    assert Path(carried) == found, carried
    refusal = run_ash_container.container_input_refusal(
        root, out, None, carried, "ws.code-workspace"
    )
    assert refusal is not None and "link" in refusal, refusal


def test_a_policy_spelling_through_a_tree_link_is_not_collapsed(tmp_path, monkeypatch):
    """The carried name keeps the operator's ``..`` spelling. Collapsed as
    text, ``ws/L/../../pol.yaml`` with ``L`` a link inside the workspace
    becomes a sibling path that never mentions ``L``, so the link gate saw a
    name with no link in it and stepped aside, while the host had read the
    file the link's target leads to -- the same collapse the --config gate
    stopped judging. The uncollapsed name walks through ``L``, which sits in
    the workspace's tree, so a policy the repository steers out of the tree
    is refused before the run."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    root = tmp_path / "ws"
    root.mkdir()
    out = tmp_path / "out"
    out.mkdir()
    nest = tmp_path / "d1" / "d2" / "nest"
    nest.mkdir(parents=True)
    (root / "L").symlink_to(nest)
    read_by_the_host = tmp_path / "d1" / "pol.yaml"
    read_by_the_host.write_text("projects: []\n")
    spelled = f"{root}/L/../../pol.yaml"
    assert os.path.realpath(spelled) == str(read_by_the_host)
    assert os.path.abspath(spelled) == str(tmp_path / "pol.yaml")
    opts = _opts(root, spelled, read_by_the_host)
    carried = run_ash_scan._workspace_policy_for_the_container(opts)
    assert carried == spelled, carried
    refusal = run_ash_container.container_input_refusal(
        root, out, None, carried, "ws.code-workspace"
    )
    assert refusal is not None and "link" in refusal, refusal


def test_an_unnamed_plan_policy_beats_a_root_file_discovery_finds(
    tmp_path, monkeypatch
):
    """A plan built without the as-named spelling (an API caller's) can hold
    an explicit policy outside the root while the root carries an
    ash-workspace.yaml of its own, which the plan's resolution skipped
    because the explicit policy was given. Discovery's find is handed over
    only when it IS the plan's policy; otherwise the repository's root file
    would replace the operator's suppressions and ceilings inside the
    container."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    root, out, target = _layout(tmp_path)
    repository_file = root / "ash-workspace.yaml"
    repository_file.write_text("projects: [theirs]\n")
    opts = _opts(root, None, target.resolve())
    carried = run_ash_scan._workspace_policy_for_the_container(opts)
    assert Path(carried) == target.resolve(), carried


def _stubbed_container_cli(monkeypatch) -> list:
    """The container-mode CLI harness: a runner that only records its argv.

    Returns the list every composed runner command is appended to, so a cell
    can assert both that no command ran (a refusal before the run) and what a
    composed run carried.
    """
    from automated_security_helper.utils.subprocess_utils import (
        create_completed_process,
    )
    from tests.utils.helpers import stand_in_host_ids

    for name in ("CI", "ASH_IMAGE_NAME", "ASH_CONFIG", "OCI_RUNNER_WRAPPER"):
        monkeypatch.delenv(name, raising=False)
    commands: list = []
    stand_in_host_ids(monkeypatch)
    monkeypatch.setattr(
        run_ash_container, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(
        run_ash_container, "_runner_supports_buildx", lambda _runner: False
    )
    monkeypatch.setattr(
        run_ash_container,
        "run_cmd_direct",
        lambda cmd, *a, **k: (
            commands.append([str(c) for c in cmd])
            or create_completed_process(args=cmd, returncode=0, stdout="", stderr="")
        ),
    )
    return commands


def _workspace_tree(tmp_path: Path) -> tuple:
    """A scannable workspace checkout and an output directory holding a
    previous run's report, so a cell can tell a pre-run refusal (report kept,
    no command) from a run."""
    import json

    root = tmp_path / "workspace"
    (root / "app").mkdir(parents=True)
    (root / "app" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (root / "w.code-workspace").write_text(
        json.dumps({"folders": [{"path": "app"}]}), encoding="utf-8"
    )
    output = tmp_path / "out"
    (output / "reports").mkdir(parents=True)
    (output / "reports" / "previous.txt").write_text("kept\n", encoding="utf-8")
    return root, output


def _scan_argv(root: Path, output: Path, *policy_args: str) -> list:
    return [
        "scan",
        "--mode",
        "container",
        "--no-build",
        "--no-progress",
        "--workspace",
        str(root / "w.code-workspace"),
        *policy_args,
        "--output-dir",
        str(output),
    ]


def test_an_explicit_in_tree_policy_linking_out_refuses_the_cli_run(
    tmp_path, monkeypatch
):
    """The scan CLI, not the helper alone: ``--workspace-config`` names a file
    inside the workspace's tree that is a link to a file outside it. The host
    read the link's target, so the run is refused only if the CLI hands the
    container the policy by the name it was given; handing over the resolved
    path shows the gate a path outside the tree with no link in it, and the
    run proceeds with the repository-chosen target mounted."""
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app

    commands = _stubbed_container_cli(monkeypatch)
    root, output = _workspace_tree(tmp_path)
    target = tmp_path / "elsewhere" / "ash-workspace.yaml"
    target.parent.mkdir()
    target.write_text("workspace: {}\n", encoding="utf-8")
    named = root / "pol.yaml"
    named.symlink_to(target)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        app, _scan_argv(root, output, "--workspace-config", str(named))
    )

    assert result.exit_code == 3, result.output
    assert commands == []
    assert (output / "reports" / "previous.txt").read_text(encoding="utf-8") == (
        "kept\n"
    )


def test_a_discovered_root_policy_linking_out_refuses_the_cli_run(
    tmp_path, monkeypatch
):
    """No ``--workspace-config`` given: discovery finds the root's own
    ``ash-workspace.yaml``, which is a link to a file outside the tree. The
    found name is inside the tree, so the hand-over by name refuses the run;
    carrying the resolved path instead let the repository steer the policy
    out of its checkout."""
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app

    commands = _stubbed_container_cli(monkeypatch)
    root, output = _workspace_tree(tmp_path)
    target = tmp_path / "elsewhere" / "ash-workspace.yaml"
    target.parent.mkdir()
    target.write_text("workspace: {}\n", encoding="utf-8")
    (root / "ash-workspace.yaml").symlink_to(target)
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(app, _scan_argv(root, output))

    assert result.exit_code == 3, result.output
    assert commands == []


def test_an_outside_policy_named_through_an_alias_is_still_handed_over(
    tmp_path, monkeypatch
):
    """Control: the operator's ``--workspace-config`` is an alias outside the
    workspace's tree linking to the real policy, also outside it. Nothing in
    the spelling is the repository's, so the run composes a container command
    that carries the policy and mounts the real file."""
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app

    commands = _stubbed_container_cli(monkeypatch)
    root, output = _workspace_tree(tmp_path)
    target = tmp_path / "elsewhere" / "ash-workspace.yaml"
    target.parent.mkdir()
    target.write_text("workspace: {}\n", encoding="utf-8")
    alias = tmp_path / "ops" / "pol.yaml"
    alias.parent.mkdir()
    alias.symlink_to(target)
    monkeypatch.chdir(tmp_path)

    CliRunner().invoke(app, _scan_argv(root, output, "--workspace-config", str(alias)))

    handed = [cmd for cmd in commands if "--workspace-config" in cmd]
    assert handed, commands
    argv = handed[-1]
    inner = argv[argv.index("--workspace-config") + 1]
    assert inner.endswith("/ash-workspace.yaml"), argv
    assert any(str(target.resolve()) in part for part in argv), argv


def test_an_unmountable_policy_keeps_the_previous_output(tmp_path, monkeypatch):
    """A policy container mode cannot mount (a comma in its path, which a
    --mount value cannot carry) is refused by the scan CLI with exit 3 before
    the previous run's output is cleared and before any runner call."""
    import json

    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app
    from automated_security_helper.utils.subprocess_utils import (
        create_completed_process,
    )
    from tests.utils.helpers import stand_in_host_ids

    for name in ("CI", "ASH_IMAGE_NAME", "ASH_CONFIG", "OCI_RUNNER_WRAPPER"):
        monkeypatch.delenv(name, raising=False)
    commands = []
    stand_in_host_ids(monkeypatch)
    monkeypatch.setattr(
        run_ash_container, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(
        run_ash_container, "_runner_supports_buildx", lambda _runner: False
    )
    monkeypatch.setattr(
        run_ash_container,
        "run_cmd_direct",
        lambda cmd, *a, **k: (
            commands.append([str(c) for c in cmd])
            or create_completed_process(args=cmd, returncode=0, stdout="", stderr="")
        ),
    )
    root = tmp_path / "workspace"
    (root / "app").mkdir(parents=True)
    (root / "app" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (root / "w.code-workspace").write_text(
        json.dumps({"folders": [{"path": "app"}]}), encoding="utf-8"
    )
    policy = tmp_path / "other,dir" / "policy.yaml"
    policy.parent.mkdir()
    policy.write_text("{}\n", encoding="utf-8")
    assert "," in str(policy.resolve())
    output = tmp_path / "out"
    (output / "reports").mkdir(parents=True)
    (output / "reports" / "previous.txt").write_text("kept\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--no-progress",
            "--workspace",
            str(root / "w.code-workspace"),
            "--workspace-config",
            str(policy),
            "--output-dir",
            str(output),
        ],
    )

    assert result.exit_code == 3, result.output
    assert commands == []
    assert (output / "reports" / "previous.txt").read_text(encoding="utf-8") == (
        "kept\n"
    )
