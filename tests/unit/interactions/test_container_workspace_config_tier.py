# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A workspace scan in container mode marks or refuses a config the repository
could have written.

A one-directory container scan mounts a config from outside ``--source-dir`` at
``/ash-config`` and, when a local scan would count it as repository-written (it is
in the scanned tree, or reached through a link that sits there), passes
``--config-from-scanned-repository`` so the scan inside limits it. A workspace scan
inside the container refused that flag, so in workspace mode the host passed the
config unmarked, and the scan inside, which sees ``/ash-config`` in no checkout,
gave it the operator's grants (``sandbox.extra_read_paths`` and the rest).

In workspace mode the host now marks each file of a config chain that is in another
git checkout with ``--config-file-from-another-checkout``, and the workspace scan
inside accepts the mark and limits those files for every project, as a local
workspace scan does (``sandbox_grants.marked_files_in_another_checkout``; the
settings that come out are compared with a local workspace scan's in
test_container_workspace_config_parity.py). A file there cannot grant and is not a
member of the workspace's tree, so the chain mark, which keeps nothing, is not
passed for it. The workspace scan inside accepts the chain mark as well
(``sandbox_grants.marked_repository_written``). A config in the checkout around the
workspace root, or reached through a link there, is refused with exit 3 before
anything is built, mounted or cleared, judged by the files it would mount (a file
it extends stays inside the config's own directory;
``config_sources.default_confinement_root``). The scan CLI refuses it before that,
as a local workspace scan refuses an operator config inside the workspace's tree
(``resolve_config.check_operator_config``). A config inside the workspace root is
read through ``/src``, and one outside every checkout is the operator's.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from automated_security_helper.core.enums import ExecutionPhase, ExecutionStrategy
from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions.run_ash_container import (
    _assemble_run_command,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.subprocess_utils import create_completed_process
from tests.utils.config_link_layouts import config_through_links
from tests.utils.helpers import link_walk_cannot_examine, mark_git_checkout

pytestmark = pytest.mark.unit

GRANT = "project_name: tier\nsandbox:\n  extra_read_paths:\n    - /opt/tier-grant\n"
FIX = (
    "Keep --config, and every file it extends, outside the checkout around the "
    "workspace root"
)


@pytest.fixture
def commands(monkeypatch, tmp_path) -> List[List[str]]:
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False, env=None):
        cmd = [str(item) for item in cmd_list if item is not None]
        seen.append(cmd)
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    monkeypatch.setattr(subprocess_utils, "get_host_uid", lambda: 1000)
    monkeypatch.setattr(subprocess_utils, "get_host_gid", lambda: 1000)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", record)
    for name in ("CI", "ASH_IMAGE_NAME", "ASH_CONFIG", "OCI_RUNNER_WRAPPER"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    return seen


@pytest.fixture
def checkout(tmp_path) -> Path:
    """A git checkout whose ``ws`` directory is a workspace with one project."""
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    project = repo / "ws" / "proj"
    project.mkdir(parents=True)
    (project / "a.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "ws" / "ash.code-workspace").write_text(
        json.dumps({"folders": [{"path": "proj"}]}), encoding="utf-8"
    )
    return repo


def _config(path: Path, text: str = GRANT) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _workspace_run(checkout: Path, config: Path, tmp_path: Path, **kwargs):
    return rac.run_ash_container(
        source_dir=str(checkout / "ws"),
        output_dir=str(tmp_path / "out"),
        config=str(config),
        workspace_relative_file="ash.code-workspace",
        build=False,
        run=True,
        **kwargs,
    )


def _run_command(commands: List[List[str]]) -> List[str]:
    (run,) = [cmd for cmd in commands if cmd[1] == "run"]
    return run


@pytest.mark.parametrize(
    "where",
    [
        "the-config-in-the-checkout-outside-the-workspace",
        "a-link-outside-the-checkout-to-a-config-in-it",
        "a-link-in-the-checkout-on-the-way-to-a-config-outside-it",
    ],
)
def test_a_config_in_the_workspaces_own_checkout_is_refused(
    where, checkout, commands, tmp_path
):
    if where == "the-config-in-the-checkout-outside-the-workspace":
        config = _config(checkout / "other" / "ash-config.yaml")
    elif where == "a-link-in-the-checkout-on-the-way-to-a-config-outside-it":
        (checkout / "ci").mkdir()
        config = config_through_links(
            "file-link-in-the-scanned-checkout", checkout, tmp_path
        )
    else:
        # Named outside every checkout, but the file it names is in one, and that
        # file is what is mounted.
        target = _config(checkout / "other" / "ash-config.yaml")
        config = tmp_path / "operator" / "ash-config.yaml"
        config.parent.mkdir()
        config.symlink_to(target)

    result = _workspace_run(checkout, config, tmp_path)

    assert result.returncode == 3, result.stderr
    assert not rac.container_was_started(result)
    assert commands == []
    # The refusal names --config as written, through repr (run_ash_container.py,
    # the "is the scanned repository's" message), so a Windows path shows each
    # backslash doubled.
    assert repr(str(config)) in result.stderr
    assert FIX in result.stderr


@pytest.mark.parametrize(
    "where",
    [
        "the-config-in-another-checkout",
        "a-config-extending-a-base-in-another-checkout",
        "a-link-in-another-checkout-to-a-config-outside-every-checkout",
    ],
)
def test_a_config_in_another_checkout_is_marked_for_the_scan_inside(
    where, checkout, commands, tmp_path
):
    """Not the workspace's own checkout: mounted at /ash-config and marked as in
    another checkout, so the scan inside limits it as a local workspace scan does."""
    elsewhere = tmp_path / "elsewhere"
    mark_git_checkout(elsewhere)
    if where == "the-config-in-another-checkout":
        config = _config(elsewhere / "ash-config.yaml")
    elif where == "a-config-extending-a-base-in-another-checkout":
        _config(elsewhere / "base.yaml")
        config = _config(
            elsewhere / "ash-config.yaml", "project_name: tier\nextends: base.yaml\n"
        )
    else:
        target = _config(tmp_path / "operator" / "ash-config.yaml")
        config = elsewhere / "ash-config.yaml"
        config.symlink_to(target)

    result = _workspace_run(checkout, config, tmp_path)

    assert result.returncode != 3, result.stderr
    run = _run_command(commands)
    assert run[run.index("--config") + 1] == "/ash-config/ash-config.yaml"
    # Not the workspace's tree: the chain mark, which keeps nothing, is not used.
    assert rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG not in run
    other = rac.CONFIG_FILE_FROM_ANOTHER_CHECKOUT_FLAG
    marked = [run[i + 1] for i, arg in enumerate(run[:-1]) if arg == other]
    assert "/ash-config/ash-config.yaml" in marked
    if where == "a-config-extending-a-base-in-another-checkout":
        # The base is mounted at its own container path and needs its own mark: a
        # scan inside that learned only the root's would read the base as the
        # operator's.
        assert "/ash-config/base.yaml" in marked
    assert len(marked) == len(set(marked))


def test_the_inner_workspace_scan_accepts_the_mark(monkeypatch, tmp_path):
    """The scan inside the container treats the marked --config, and every file
    it extends, as repository-written while it runs, and only those files."""
    from automated_security_helper.cli import scan as scan_cli
    from automated_security_helper.config.sandbox_grants import repository_written

    workspace = tmp_path / "src"
    (workspace / "proj").mkdir(parents=True)
    (workspace / "proj" / "a.py").write_text("x = 1\n", encoding="utf-8")
    (workspace / "ash.code-workspace").write_text(
        json.dumps({"folders": [{"path": "proj"}]}), encoding="utf-8"
    )
    mounted = tmp_path / "ash-config"
    base = _config(mounted / "base.yaml")
    config = _config(
        mounted / "ash-config.yaml", "project_name: t\nextends: base.yaml\n"
    )
    beside = _config(mounted / "not-in-the-chain.yaml")
    seen = {}

    def run(**kwargs):
        seen["kwargs"] = kwargs
        seen["written"] = repository_written(
            [base.resolve(), config.resolve()], workspace
        )
        seen["beside"] = repository_written([beside.resolve()], workspace)
        seen["project"] = repository_written(
            [(workspace / "proj" / "a.py").resolve()], tmp_path / "unrelated"
        )

    monkeypatch.setattr(scan_cli, "run_ash_scan", run)
    monkeypatch.chdir(workspace)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--workspace",
            str(workspace / "ash.code-workspace"),
            "--config",
            str(config),
            rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG,
        ],
    )

    assert result.exit_code == 0, result.output
    assert seen["written"] == [base.resolve(), config.resolve()]
    assert seen["beside"] == []
    assert seen["project"] == []
    # Applied by the mark, not by untrusted_config, which is for an MCP client's file.
    assert seen["kwargs"].get("untrusted_config", False) is False
    # Only while the scan runs.
    assert repository_written([config.resolve()], workspace) == []


def test_the_inner_workspace_scan_needs_a_config_for_the_mark(monkeypatch, tmp_path):
    from automated_security_helper.cli import scan as scan_cli

    workspace = tmp_path / "src"
    (workspace / "proj").mkdir(parents=True)
    (workspace / "ash.code-workspace").write_text(
        json.dumps({"folders": [{"path": "proj"}]}), encoding="utf-8"
    )
    monkeypatch.setattr(scan_cli, "run_ash_scan", lambda **kw: None)
    monkeypatch.chdir(workspace)

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--workspace",
            str(workspace / "ash.code-workspace"),
            rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG,
        ],
    )

    assert result.exit_code == 3, result.output
    assert rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG in result.output


def test_a_config_inside_the_workspace_is_read_through_src(
    checkout, commands, tmp_path
):
    """Control: read through /src, in the scan's own tree inside, and not marked."""
    config = _config(checkout / "ws" / "ws-config.yaml")

    result = _workspace_run(checkout, config, tmp_path)

    assert result.returncode != 3, result.stderr
    run = _run_command(commands)
    assert run[run.index("--config") + 1] == "/src/ws-config.yaml"
    assert rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG not in run
    assert rac.CONFIG_FILE_FROM_ANOTHER_CHECKOUT_FLAG not in run
    assert "--config-file-walk-undecided" not in run


def test_a_config_outside_every_checkout_is_the_operators(checkout, commands, tmp_path):
    """Control: mounted at /ash-config, unmarked, as before."""
    config = _config(tmp_path / "operator" / "ash-config.yaml")

    result = _workspace_run(checkout, config, tmp_path)

    assert result.returncode != 3, result.stderr
    run = _run_command(commands)
    assert run[run.index("--config") + 1] == "/ash-config/ash-config.yaml"
    assert rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG not in run
    # The operator's own file carries no mark of any kind: one that over-marked it
    # would take its grants away from every project.
    assert rac.CONFIG_FILE_FROM_ANOTHER_CHECKOUT_FLAG not in run
    assert "--config-file-walk-undecided" not in run


def test_a_one_directory_scan_still_marks_it(checkout, commands, tmp_path):
    """Control: the one-directory rule is unchanged."""
    config = _config(checkout / "other" / "ash-config.yaml")

    result = rac.run_ash_container(
        source_dir=str(checkout / "ws" / "proj"),
        output_dir=str(tmp_path / "out"),
        config=str(config),
        build=False,
        run=True,
    )

    assert result.returncode != 3, result.stderr
    assert rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG in _run_command(commands)


def test_a_one_directory_scan_marks_a_config_whose_name_walk_never_finished_as_the_scanned_trees(
    checkout, commands, tmp_path, monkeypatch
):
    """The real link walk of the config's name stops before it can place the file.
    The scanned tree's judgment fails closed and reads it as the repository's, so
    the host sends that mark and neither of the two marks for another checkout:
    the second judgment never runs for a file the first one marked."""
    config = _config(tmp_path / "ops" / "gate" / "ash-config.yaml")
    link_walk_cannot_examine(monkeypatch, config.parent)

    result = rac.run_ash_container(
        source_dir=str(checkout / "ws" / "proj"),
        output_dir=str(tmp_path / "out"),
        config=str(config),
        build=False,
        run=True,
    )

    assert result.returncode != 3, result.stderr
    run = _run_command(commands)
    assert rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG in run
    assert rac.CONFIG_FILE_FROM_ANOTHER_CHECKOUT_FLAG not in run
    assert "--config-file-walk-undecided" not in run


def _assemble_workspace_run(
    checkout: Path, config: Path | None, tmp_path: Path, **extra: Any
) -> List[str]:
    (tmp_path / "out").mkdir(exist_ok=True)
    kwargs: Dict[str, Any] = {
        "oci_command_prefix": [],
        "resolved_oci_runner": "docker",
        "image_name": "ash:test",
        "source_dir": (checkout / "ws").resolve(),
        "output_dir": (tmp_path / "out").resolve(),
        "offline": False,
        "debug": False,
        "color": False,
        "quiet": True,
        "progress": False,
        "verbose": False,
        "simple": True,
        "python_based_plugins_only": False,
        "cleanup": False,
        "inspect": False,
        "fail_on_findings": None,
        "phases": [ExecutionPhase.SCAN],
        "scanners": [],
        "exclude_scanners": [],
        "output_formats": [],
        "config": None if config is None else str(config),
        "config_overrides": [],
        "existing_results": None,
        "ash_plugin_modules": [],
        "strategy": ExecutionStrategy.PARALLEL,
        "ctx": None,
        "workspace_relative_file": "ash.code-workspace",
    }
    kwargs.update(extra)
    return _assemble_run_command(**kwargs)


def test_a_repository_written_workspace_policy_is_refused(checkout, tmp_path):
    """A mounted config chain carries the repository-written judgment into
    the container as a mark; the workspace policy has no mark the scan inside
    reads, so a policy the scanned repository wrote refuses the run instead
    of mounting at /ash-workspace-config with no signal."""
    policy = checkout / "ci" / "policy.yaml"
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("projects: []\n", encoding="utf-8")
    config = _config(tmp_path / "ops" / "ash-config.yaml")

    with pytest.raises(rac.ContainerInputError, match="workspace policy"):
        _assemble_workspace_run(
            checkout, config, tmp_path, workspace_config=str(policy)
        )


def test_the_pre_run_check_refuses_a_repository_written_workspace_policy(
    checkout, tmp_path
):
    """The refusal is part of the check that runs before anything is cleared
    or built, not only of command assembly."""
    policy = checkout / "ci" / "policy.yaml"
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("projects: []\n", encoding="utf-8")

    refusal = rac.container_input_refusal(
        str(checkout / "ws"),
        str(tmp_path / "out"),
        None,
        str(policy),
        "ash.code-workspace",
    )

    assert isinstance(refusal, str), refusal
    assert "workspace policy" in refusal, refusal
    assert "written by the repository being scanned" in refusal, refusal


def test_the_pre_run_check_lets_an_operators_workspace_policy_through(
    checkout, tmp_path
):
    """The must-not twin of the refusal above."""
    policy = tmp_path / "ops" / "policy.yaml"
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("projects: []\n", encoding="utf-8")

    refusal = rac.container_input_refusal(
        str(checkout / "ws"),
        str(tmp_path / "out"),
        None,
        str(policy),
        "ash.code-workspace",
    )

    assert refusal is None, refusal


def test_the_scan_cli_refuses_a_repository_written_policy_before_clearing_the_output(
    checkout, commands, tmp_path
):
    """The scan CLI: the refusal arrives before the previous run's reports are
    cleared and before any command runs."""
    policy = checkout / "ci" / "policy.yaml"
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("workspace: {}\n", encoding="utf-8")
    output = tmp_path / "out"
    (output / "reports").mkdir(parents=True)
    (output / "reports" / "previous.txt").write_text("kept\n", encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--no-progress",
            "--workspace",
            str(checkout / "ws" / "ash.code-workspace"),
            "--workspace-config",
            str(policy),
            "--output-dir",
            str(output),
        ],
    )

    assert result.exit_code == 3, result.output
    assert commands == []
    assert (output / "reports" / "previous.txt").read_text(encoding="utf-8") == "kept\n"
    assert "workspace policy" in " ".join(result.output.split()), result.output


def test_an_operators_workspace_policy_still_mounts(checkout, tmp_path):
    """The must-not twin: a policy the operator keeps outside the checkout
    mounts at its own root as before."""
    policy = tmp_path / "ops" / "policy.yaml"
    policy.parent.mkdir(parents=True, exist_ok=True)
    policy.write_text("projects: []\n", encoding="utf-8")
    config = _config(tmp_path / "ops" / "ash-config.yaml")

    cmd = _assemble_workspace_run(
        checkout, config, tmp_path, workspace_config=str(policy)
    )

    assert any(rac.CONTAINER_WORKSPACE_CONFIG_ROOT in str(arg) for arg in cmd), cmd


def test_an_ash_config_inside_the_checkout_is_mounted_marked(
    checkout, tmp_path, monkeypatch
):
    """The chain-shape pin for the ASH_CONFIG label: a file of the checkout
    the environment names is mounted WITH the repository-written mark, the
    outcome the policy label's refusal stands in for."""
    env_cfg = checkout / "ci" / "env.yaml"
    env_cfg.parent.mkdir(parents=True, exist_ok=True)
    env_cfg.write_text("project_name: env\n", encoding="utf-8")
    monkeypatch.setenv("ASH_CONFIG", str(env_cfg))
    config = _config(tmp_path / "ops" / "ash-config.yaml")

    cmd = _assemble_workspace_run(checkout, config, tmp_path)

    assert rac.CONFIG_FILE_FROM_SCANNED_REPOSITORY_FLAG in cmd, cmd


def test_the_assembled_command_refuses_it_on_its_own(checkout, tmp_path):
    """The check holds wherever it is called from: command assembly applies it
    too, whatever order a caller's checks run in."""
    config = _config(checkout / "other" / "ash-config.yaml")

    with pytest.raises(rac.ContainerInputError, match=FIX):
        _assemble_workspace_run(checkout, config, tmp_path)


def test_the_refusal_names_each_file_once_and_says_how_to_keep_a_setting(
    checkout, tmp_path
):
    """The files of the chain in the workspace's checkout, the --config itself
    among them, each named once, in chain order, and the remedy every
    confinement message ends with: the cause is the repository's tier."""
    from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING

    base = _config(checkout / "other" / "base.yaml")
    config = _config(
        checkout / "other" / "ash-config.yaml", "project_name: t\nextends: base.yaml\n"
    )

    with pytest.raises(rac.ContainerInputError) as raised:
        _assemble_workspace_run(checkout, config, tmp_path)

    message = str(raised.value)
    named = message.split("is the scanned repository's: ", 1)[1].split(
        " is in the git checkout", 1
    )[0]
    assert named.split(", ") == [config.as_posix(), base.as_posix()], message
    assert message.endswith(f"{FIX}. {KEEP_A_SETTING}"), message


def test_a_config_whose_name_walk_never_finished_is_refused_without_a_location(
    checkout, tmp_path, monkeypatch
):
    """The walk of the name stops before the end, so the config is refused like
    the others, fail closed, but the message says the walk stopped instead of
    claiming the file sits in the checkout around the workspace root."""
    config = _config(tmp_path / "ops" / "gate" / "ash-config.yaml")
    link_walk_cannot_examine(monkeypatch, config.parent)

    with pytest.raises(rac.ContainerInputError) as raised:
        rac._refuse_repository_config_in_a_workspace(
            str(config), [config], checkout / "ws"
        )

    message = str(raised.value)
    assert (
        "could not be decided (resolving its name stopped before the walk finished)"
        in message
    ), message
    assert config.as_posix() in message, message
    assert "is in the git checkout" not in message, message
    # Not in a checkout as far as anyone knows, so moving it out is no remedy: the
    # walk has to be able to finish (confinement_remedy, resolve_config).
    from automated_security_helper.config.confinement_remedy import (
        KEEP_A_SETTING_WHEN_THE_WALK_STOPPED,
    )

    assert message.endswith(f"{FIX}. {KEEP_A_SETTING_WHEN_THE_WALK_STOPPED}"), message


def test_a_chain_of_a_found_file_and_an_undecided_one_says_each_reason(
    checkout, tmp_path, monkeypatch
):
    """A file in the workspace's checkout and a base whose name walk never
    finished: the located one keeps the location sentence, the other gets the
    walk-stopped one."""
    located = _config(checkout / "other" / "ash-config.yaml")
    undecided = _config(tmp_path / "ops" / "gate" / "base.yaml")
    link_walk_cannot_examine(monkeypatch, undecided.parent)

    with pytest.raises(rac.ContainerInputError) as raised:
        rac._refuse_repository_config_in_a_workspace(
            str(located), [located, undecided], checkout / "ws"
        )

    message = str(raised.value)
    assert f"{located.as_posix()} is in the git checkout" in message, message
    assert f"whether {undecided.as_posix()} is in that checkout" in message, message
    assert f"{undecided.as_posix()} is in the git checkout" not in message, message
    # The located file still moves out, the undecided one is made resolvable.
    from automated_security_helper.config.confinement_remedy import (
        KEEP_A_SETTING_BESIDE_A_LOCATED_FILE,
    )

    assert message.endswith(f"{FIX}. {KEEP_A_SETTING_BESIDE_A_LOCATED_FILE}"), message


def test_the_scan_cli_refuses_it_before_clearing_the_output(
    checkout, commands, tmp_path
):
    """The CLI's own workspace check comes first, with its message: the operator's
    config is layered over every project, so none of its files may be the
    workspace's."""
    config = _config(checkout / "other" / "ash-config.yaml")
    output = tmp_path / "out"
    (output / "reports").mkdir(parents=True)
    (output / "reports" / "previous.txt").write_text("kept\n", encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--no-progress",
            "--workspace",
            str(checkout / "ws" / "ash.code-workspace"),
            "--config",
            str(config),
            "--output-dir",
            str(output),
        ],
    )

    assert result.exit_code == 3, result.output
    assert commands == []
    assert (output / "reports" / "previous.txt").read_text(encoding="utf-8") == "kept\n"
    message = " ".join(result.output.split())
    assert "ash-config.yaml" in message, message
    assert "is inside the checkout" in message, message
    # The cause is the repository's tier: the remedy every confinement message ends
    # with follows the place to move the config out of.
    from automated_security_helper.config.confinement_remedy import KEEP_A_SETTING

    assert "Move the config, and every base it extends, outside the checkout" in (
        message
    ), message
    assert KEEP_A_SETTING in message, message


def _ash_config_in(directory: Path) -> Path:
    return _config(directory / "env.yaml", "project_name: env\n")


def test_an_ash_config_in_the_checkout_with_no_config_is_refused_on_assembly(
    checkout, tmp_path, monkeypatch
):
    """With no --config the variable's file becomes the inner scan's --config,
    so a direct caller that passes no config gets the same refusal a named
    --config in the workspace's checkout gets."""
    monkeypatch.setenv("ASH_CONFIG", str(_ash_config_in(checkout / "ci")))

    with pytest.raises(rac.ContainerInputError, match=FIX):
        _assemble_workspace_run(checkout, None, tmp_path)


def test_an_ash_config_in_the_checkout_with_no_config_is_refused_before_the_build(
    checkout, tmp_path, monkeypatch
):
    """The pre-run check applies the same rule as command assembly."""
    monkeypatch.setenv("ASH_CONFIG", str(_ash_config_in(checkout / "ci")))

    refusal = rac.container_input_refusal(
        str(checkout / "ws"),
        str(tmp_path / "out"),
        None,
        None,
        "ash.code-workspace",
    )

    assert isinstance(refusal, str), refusal
    assert FIX in " ".join(refusal.split()), refusal


def test_the_file_gets_one_verdict_named_as_config_or_by_the_environment(
    checkout, tmp_path, monkeypatch
):
    """The same file in the workspace's checkout, given once as --config and
    once through ASH_CONFIG with no --config, is refused with one message."""
    target = _ash_config_in(checkout / "ci")

    with pytest.raises(rac.ContainerInputError, match=FIX) as named:
        _assemble_workspace_run(checkout, target, tmp_path)
    monkeypatch.setenv("ASH_CONFIG", str(target))
    with pytest.raises(rac.ContainerInputError, match=FIX) as by_environment:
        _assemble_workspace_run(checkout, None, tmp_path)

    assert str(by_environment.value) == str(named.value)


def test_an_ash_config_outside_every_checkout_with_no_config_is_still_named(
    checkout, tmp_path, monkeypatch
):
    """The must-not twin: the operator's own file, outside every checkout, is
    handed to the inner scan as its --config."""
    monkeypatch.setenv("ASH_CONFIG", str(_ash_config_in(tmp_path / "ops")))

    cmd = _assemble_workspace_run(checkout, None, tmp_path)

    assert cmd[cmd.index("--config") + 1].startswith(rac.CONTAINER_ENV_CONFIG_ROOT), cmd
