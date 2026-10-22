# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The environment handoff carries the operator's names and nothing else.

A config file that reads an environment variable gets the value passed into
the container, by name (``-e NAME``), so the value never goes on the runner's
command line. Only the names the OPERATOR'S files read are passed: a variable
a repository-written file of the chain reads is not, and a name ASH reads as
its own setting refuses the scan with exit 3, by name and field, never
quoting the value. An in-source config whose ``extends`` names a base by
absolute path is refused too: inside the container that path is not the same
file, and for an in-source config this check is the only one that sees the
chain (no file of its own is mounted). The fallback that names ``ASH_CONFIG``
as ``--config`` fires exactly when a local scan would fall back to it.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.interactions import run_ash_container as rac
from automated_security_helper.interactions import run_ash_scan as ras
from automated_security_helper.utils.subprocess_utils import create_completed_process
from tests.utils.helpers import mark_git_checkout, stand_in_host_ids

#: ASH reads only names beginning with ASH_ (plus AWS_DEFAULT_REGION,
#: AWS_PROFILE and AWS_REGION) into a config; these two are readable and
#: outside run_ash_container.CONTAINER_ENV_NOT_PASSED.
OPERATOR_VAR = "ASH_HANDOFF_CELL_OPERATOR_VALUE"
REPOSITORY_VAR = "ASH_HANDOFF_CELL_REPOSITORY_VALUE"
OPERATOR_VALUE = "handoff-operator-value-9b3e"
REPOSITORY_VALUE = "handoff-repository-value-41d7"


@pytest.fixture
def layout(tmp_path, monkeypatch):
    """W (tmp_path, outside every checkout), W/repo a checkout, W/repo/src the
    source directory, W/out the output directory."""
    from automated_security_helper.config.sandbox_grants import scanned_trees

    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    source = repo / "src"
    source.mkdir()
    (source / "a.py").write_text("x = 1\n", encoding="utf-8")
    (repo / "ci").mkdir()
    out = tmp_path / "out"
    out.mkdir()
    for name in (
        "ASH_CONFIG",
        "ASH_SCANNERS",
        OPERATOR_VAR,
        REPOSITORY_VAR,
        "OCI_RUNNER_WRAPPER",
        "CI",
        "ASH_IMAGE_NAME",
    ):
        monkeypatch.delenv(name, raising=False)
    # The layouts assume no git-shaped ancestor above tmp_path: the scanned
    # tree walk looks at every parent, so one would widen the repository's
    # membership and skew every judgment below. Fails loud here, with the
    # tree it found, instead of a wrong verdict later.
    assert scanned_trees(source) == [repo], scanned_trees(source)
    return {"w": tmp_path, "repo": repo, "source": source, "out": out}


@pytest.fixture
def commands(monkeypatch) -> List[List[str]]:
    seen: List[List[str]] = []

    def record(cmd_list, check=True, debug=False, shell=False, env=None):
        cmd = [str(item) for item in cmd_list if item is not None]
        seen.append(cmd)
        return create_completed_process(args=cmd, returncode=0, stdout="", stderr="")

    stand_in_host_ids(monkeypatch)
    monkeypatch.setattr(
        rac, "_find_runner", lambda _name: "/nonexistent/ash-test/docker"
    )
    monkeypatch.setattr(rac, "_runner_supports_buildx", lambda _runner: False)
    monkeypatch.setattr(rac, "run_cmd_direct", record)
    return seen


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def test_an_operator_files_variable_is_passed_by_name(layout, commands, monkeypatch):
    monkeypatch.setenv(OPERATOR_VAR, OPERATOR_VALUE)
    config = _write(layout["w"] / "ash.yaml", "project_name: ${" + OPERATOR_VAR + "}\n")
    assert not rac._repository_written(config, layout["source"])

    result = rac.run_ash_container(
        source_dir=str(layout["source"]),
        output_dir=str(layout["out"]),
        config=str(config),
        build=False,
        run=True,
    )

    assert result.returncode == 0, result.stderr
    (run,) = [cmd for cmd in commands if cmd[1] == "run"]
    pairs = list(zip(run, run[1:]))
    assert ("-e", OPERATOR_VAR) in pairs, run
    assert not any(OPERATOR_VALUE in arg for arg in run), run


def test_a_repository_written_bases_variable_is_not_passed(layout, monkeypatch):
    """The operator root's own variable is passed; the repository-written
    base's is not: the value would be read by a file the scanned repository
    wrote."""
    monkeypatch.setenv(OPERATOR_VAR, OPERATOR_VALUE)
    monkeypatch.setenv(REPOSITORY_VAR, REPOSITORY_VALUE)
    base = _write(
        layout["repo"] / "ci" / "base.yaml",
        "project_name: ${" + REPOSITORY_VAR + "}\n",
    )
    config = _write(
        layout["w"] / "ash.yaml",
        "extends: repo/ci/base.yaml\nproject_name: ${" + OPERATOR_VAR + "}\n",
    )
    assert rac._repository_written(base, layout["source"])
    assert not rac._repository_written(config, layout["source"])

    names = rac.operator_environment_names(str(config), None, layout["source"])

    assert names == [OPERATOR_VAR], names


def test_an_operator_file_reading_an_ash_setting_is_refused(layout, monkeypatch):
    """A name ASH sets in the container or reads as its own setting is
    refused by name and field, never quoting the value."""
    monkeypatch.setenv("ASH_SCANNERS", "handoff-scanner-value")
    config = _write(layout["w"] / "ash.yaml", "project_name: ${ASH_SCANNERS}\n")

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert "reads the environment variable ASH_SCANNERS" in refusal, refusal
    assert "which a container scan does not pass" in refusal, refusal
    assert "handoff-scanner-value" not in refusal, refusal


@pytest.mark.parametrize("name", ["HOME", "PATH"])
def test_an_operator_file_reading_an_image_owned_name_is_refused(
    layout, monkeypatch, name
):
    """A name the image defines for its own tools is refused by name and
    field, never quoting the host's value. The loader reads only an allowlist
    of names, so the allowlist is widened here to put the name in the file's
    recorded reads. The one name rule lives in ``core.constants``
    (``is_readable_environment_name`` reads its module's own list), so that is
    the binding to widen."""
    from automated_security_helper.core import constants

    monkeypatch.setattr(
        constants,
        "ASH_CONFIG_ENV_VAR_ALLOWLIST",
        [*constants.ASH_CONFIG_ENV_VAR_ALLOWLIST, name],
    )
    monkeypatch.setenv(name, "/host/value-7c1e")
    config = _write(layout["w"] / "ash.yaml", "project_name: ${" + name + "}\n")

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert f"reads the environment variable {name}" in refusal, refusal
    assert "which a container scan does not pass" in refusal, refusal
    assert "/host/value-7c1e" not in refusal, refusal


def test_an_operators_own_tool_variable_is_still_passed_by_name(
    layout, commands, monkeypatch
):
    """A name outside both refusal sets keeps being passed by name."""
    monkeypatch.setenv(OPERATOR_VAR, OPERATOR_VALUE)
    config = _write(layout["w"] / "ash.yaml", "project_name: ${" + OPERATOR_VAR + "}\n")

    names = rac.operator_environment_names(str(config), None, layout["source"])

    assert names == [OPERATOR_VAR], names


def test_an_operators_own_tool_variable_is_in_neither_refusal_set():
    """The name the cell above passes is in neither refusal set."""
    assert OPERATOR_VAR not in rac.CONTAINER_IMAGE_OWNED_ENV
    assert OPERATOR_VAR not in rac.CONTAINER_ENV_NOT_PASSED


def test_an_in_source_config_with_an_absolute_base_is_refused(layout):
    base = _write(layout["source"] / ".ash" / "base.yaml", "project_name: b\n")
    config = _write(
        layout["source"] / ".ash" / "ash.yaml", "extends: " + str(base) + "\n"
    )
    assert config.resolve().is_relative_to(layout["source"].resolve())

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert "names a base by absolute path" in refusal, refusal


def test_an_absolute_extends_refusal_shows_the_entry_as_written(layout, monkeypatch):
    """A refusal quotes an env-reading extends entry as the file wrote it.

    The chain walk reads entries with the stock reader, which resolves
    ``${VAR}`` implicitly, so the refusal for an absolute base printed the
    variable's value. The entry as written is what the operator can act on,
    and the value never belongs in a message (the same rule the env-name
    refusal above follows)."""
    ops = layout["w"] / "ops"
    _write(ops / "base.yaml", "project_name: b\n")
    monkeypatch.setenv("ASH_CHAIN_BASE", str(ops))
    config = _write(
        layout["source"] / ".ash" / "ash.yaml",
        "extends: ${ASH_CHAIN_BASE}/base.yaml\n",
    )

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert "names a base by absolute path" in refusal, refusal
    assert "${ASH_CHAIN_BASE}" in refusal, refusal
    assert str(ops) not in refusal, refusal


def test_an_absolute_refusal_names_an_env_chosen_file_as_value(layout, monkeypatch):
    """A chain file reached through an env-reading entry is named ``<value>``.

    The refusal names the extending file; when that file's own place came from
    the environment, its path holds the variable's value, so it is shown as
    the chain views show one -- the rule resolve_config applies to a base the
    environment chose and every base below it."""
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    sub = "chain-sub-3f1d"
    monkeypatch.setenv("ASH_CHAIN_SUB_DIR", sub)
    abs_base = _write(layout["w"] / "abs" / "base.yaml", "project_name: b\n")
    _write(
        layout["source"] / ".ash" / sub / "mid.yaml",
        "extends: " + str(abs_base) + "\n",
    )
    config = _write(
        layout["source"] / ".ash" / "ash.yaml",
        "extends: ${ASH_CHAIN_SUB_DIR}/mid.yaml\n",
    )

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert "names a base by absolute path" in refusal, refusal
    assert f"in {ENVIRONMENT_VALUE_SHOWN} names a base by absolute path" in refusal, (
        refusal
    )
    assert sub not in refusal, refusal


def _operator_config_extending_an_env_chosen_file(layout, monkeypatch, mid_text):
    """An operator config outside the scanned tree that extends
    ``${ASH_CHAIN_SUB_DIR}/mid.yaml``, with ``mid.yaml`` holding *mid_text* in the
    directory the variable names. Returns that directory's name and the config."""
    sub = "chain-sub-7a2c"
    monkeypatch.setenv("ASH_CHAIN_SUB_DIR", sub)
    _write(layout["w"] / sub / "mid.yaml", mid_text)
    config = _write(
        layout["w"] / "ash.yaml", "extends: ${ASH_CHAIN_SUB_DIR}/mid.yaml\n"
    )
    assert not rac._repository_written(config, layout["source"])
    return sub, config


def test_an_image_owned_name_refusal_names_an_env_chosen_file_as_value(
    layout, monkeypatch
):
    """The file that reads an image-owned name was reached through an entry
    that reads the environment, so its path holds that variable's value and the
    refusal names it as the chain views name one."""
    from automated_security_helper.core import constants
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    monkeypatch.setattr(
        constants,
        "ASH_CONFIG_ENV_VAR_ALLOWLIST",
        [*constants.ASH_CONFIG_ENV_VAR_ALLOWLIST, "HOME"],
    )
    sub, config = _operator_config_extending_an_env_chosen_file(
        layout, monkeypatch, "project_name: ${HOME}\n"
    )

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert "reads the environment variable HOME" in refusal, refusal
    assert (
        f"{ENVIRONMENT_VALUE_SHOWN} reads the environment variable HOME" in refusal
    ), refusal
    assert sub not in refusal, refusal


def test_an_ash_setting_refusal_names_an_env_chosen_file_as_value(layout, monkeypatch):
    """The same naming for a file that reads a name ASH reads as its own
    setting."""
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    monkeypatch.setenv("ASH_SCANNERS", "handoff-scanner-value")
    sub, config = _operator_config_extending_an_env_chosen_file(
        layout, monkeypatch, "project_name: ${ASH_SCANNERS}\n"
    )

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert "reads the environment variable ASH_SCANNERS" in refusal, refusal
    assert (
        f"{ENVIRONMENT_VALUE_SHOWN} reads the environment variable ASH_SCANNERS"
        in refusal
    ), refusal
    assert sub not in refusal, refusal
    assert "handoff-scanner-value" not in refusal, refusal


def test_an_unloadable_env_chosen_file_is_named_as_value_in_the_refusal(
    layout, monkeypatch
):
    """A parse error in a file reached through an entry that reads the
    environment names the file as the chain views name one, not by its path."""
    sub, config = _operator_config_extending_an_env_chosen_file(
        layout, monkeypatch, "project_name: [unclosed\nother: {\n"
    )

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert sub not in refusal, refusal
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    assert ENVIRONMENT_VALUE_SHOWN in refusal, refusal
    assert "parse" in refusal.lower(), refusal


def test_an_env_value_naming_the_source_absolutely_is_not_printed(layout, monkeypatch):
    """An entry whose variable holds the source directory's absolute path is
    refused as any absolute base is, quoting the entry as written: the value
    is the operator's directory layout and never belongs in the message."""
    _write(layout["source"] / "inner.yaml", "project_name: i\n")
    monkeypatch.setenv("ASH_REPO", str(layout["source"]))
    config = _write(layout["w"] / "ash.yaml", "extends: ${ASH_REPO}/inner.yaml\n")

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert "names a base by absolute path" in refusal, refusal
    assert "${ASH_REPO}" in refusal, refusal
    assert str(layout["source"]) not in refusal, refusal


def test_a_base_inside_the_source_refusal_shows_no_env_value(layout, monkeypatch):
    """The base-inside-the-source refusal never prints an env-built path.

    An entry that reads the environment and resolves INSIDE the operator's own
    directory passes the chain resolution's confinement, so the walk reaches
    the base-membership refusals, whose texts print resolved host paths -- and
    a path built from an env-reading entry holds the variable's value as a
    substring. The file the environment chose is named the way the chain views
    name one, and the entry is not quoted resolved."""
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    sub = "repo/src/chain-cisub"
    monkeypatch.setenv("ASH_CHAIN_SUB", sub)
    _write(layout["source"] / "chain-cisub" / "base.yaml", "project_name: b\n")
    config = _write(layout["w"] / "ash.yaml", "extends: ${ASH_CHAIN_SUB}/base.yaml\n")

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert sub not in refusal, refusal
    assert f"includes {ENVIRONMENT_VALUE_SHOWN}, which is inside it" in refusal, refusal


def test_a_repository_reach_out_refusal_shows_no_env_value(layout, monkeypatch):
    """The repository-file-reaching-out refusal never prints an env-built path.

    The mid file the environment chose sits inside the scanned checkout and
    extends outside it; the refusal names that file and its base, and the
    file's path holds the variable's value. Both are shown as the chain views
    show a file the environment chose.

    The sibling shape -- the repository file's OWN entry reading a relative
    value (``extends: ${VAR}/base.yaml`` with ``VAR=../ops``) -- was probed
    and never printed the value even before the masking: the refusal prints
    resolved real paths, and a relative value does not survive resolution as
    a substring. No cell pins that shape; this one covers the site."""
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    sub = "repo/ci"
    monkeypatch.setenv("ASH_CHAIN_SUB", sub)
    _write(layout["w"] / "chain-outside.yaml", "project_name: o\n")
    _write(layout["repo"] / "ci" / "cfg.yaml", "extends: ../../chain-outside.yaml\n")
    config = _write(layout["w"] / "ash.yaml", "extends: ${ASH_CHAIN_SUB}/cfg.yaml\n")

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert sub not in refusal, refusal
    assert (
        f"{ENVIRONMENT_VALUE_SHOWN} is in the repository being scanned and extends "
        f"{ENVIRONMENT_VALUE_SHOWN}, which is outside it"
    ) in refusal, refusal


def test_ash_config_is_named_when_the_source_has_no_config(layout, monkeypatch):
    env_config = _write(layout["w"] / "env" / "ash-env.yaml", "project_name: e\n")
    monkeypatch.setenv("ASH_CONFIG", str(env_config))
    assert ras._discovered_config_path(layout["source"]) is None

    assert ras._ash_config_fallback(layout["source"]) == str(env_config)


def test_ash_config_is_not_named_over_the_sources_own_config(layout, monkeypatch):
    """The scan inside would read the operator's file instead of the
    repository's own discovered config."""
    env_config = _write(layout["w"] / "env" / "ash-env.yaml", "project_name: e\n")
    _write(layout["source"] / ".ash" / ".ash.yaml", "project_name: repo\n")
    monkeypatch.setenv("ASH_CONFIG", str(env_config))
    assert ras._discovered_config_path(layout["source"]) is not None

    assert ras._ash_config_fallback(layout["source"]) is None


def test_a_discoverable_source_config_wins_over_ash_config_in_the_container(
    layout, commands, monkeypatch
):
    """With a config discovered in the source directory, ASH_CONFIG is the
    scan's base, not its config. The container is told the base with
    --ash-config-from-host and the scan inside discovers the source's own
    file, as a local scan of the same directory would."""
    from automated_security_helper.core.enums import RunMode

    env_config = _write(layout["w"] / "env" / "ash-env.yaml", "project_name: e\n")
    _write(layout["source"] / ".ash" / ".ash.yaml", "project_name: discovered\n")
    monkeypatch.setenv("ASH_CONFIG", str(env_config))

    try:
        ras.run_ash_scan(
            source_dir=str(layout["source"]),
            output_dir=str(layout["out"]),
            mode=RunMode.container,
            build=False,
            config=None,
            show_summary=False,
            progress=False,
            quiet=True,
        )
    except SystemExit:
        pass  # the stubbed runner writes no results; only the command matters

    (run,) = [cmd for cmd in commands if len(cmd) > 1 and cmd[1] == "run"]
    inner = run[run.index("ash") + 1 :]
    assert "--ash-config-from-host" in inner, run
    # Nothing is named as the scan's config: the scan inside discovers /src's
    # own file. A fallback that handed back ASH_CONFIG's file would put it here
    # as --config, mounted under /ash-config or /ash-env-config.
    assert not any(arg == "--config" or arg.startswith("--config=") for arg in inner), (
        run
    )


def _run_command(source: Path, out: Path, **kwargs) -> List[str]:
    from automated_security_helper.core.enums import (
        ExecutionPhase,
        ExecutionStrategy,
    )

    return rac._assemble_run_command(
        oci_command_prefix=[],
        resolved_oci_runner="/usr/bin/docker",
        image_name="automated-security-helper:non-root",
        source_dir=source,
        output_dir=out,
        offline=False,
        debug=False,
        color=False,
        quiet=True,
        progress=False,
        verbose=False,
        simple=True,
        python_based_plugins_only=False,
        cleanup=False,
        inspect=False,
        fail_on_findings=None,
        phases=[ExecutionPhase.SCAN],
        scanners=[],
        exclude_scanners=[],
        output_formats=[],
        config=None,
        config_overrides=[],
        existing_results=None,
        ash_plugin_modules=[],
        strategy=ExecutionStrategy.PARALLEL,
        ctx=None,
        **kwargs,
    )


def _inner_arguments(cmd: List[str]) -> List[str]:
    return cmd[cmd.index("ash") + 1 :]


def _value_after(arguments: List[str], flag: str):
    values = [b for a, b in zip(arguments, arguments[1:]) if a == flag]
    assert len(values) <= 1, arguments
    return values[0] if values else None


def test_a_workspace_scan_names_ash_config_whatever_the_workspace_root_holds(
    layout, monkeypatch
):
    """The rule asks about one directory's discovery. A workspace root is not a
    project: each project has its own config, so a config at the root decides
    nothing about them and the mounted ASH_CONFIG file is named as it always
    was. A scan of one directory with the same layout names nothing."""
    env_config = _write(layout["w"] / "env" / "ash-env.yaml", "project_name: e\n")
    _write(layout["source"] / ".ash" / ".ash.yaml", "project_name: root\n")
    monkeypatch.setenv("ASH_CONFIG", str(env_config))
    assert ras._discovered_config_path(layout["source"]) is not None

    workspace = _inner_arguments(
        _run_command(layout["source"], layout["out"], workspace_relative_file="ws.yaml")
    )
    one_directory = _inner_arguments(_run_command(layout["source"], layout["out"]))

    assert _value_after(workspace, "--workspace") == "/src/ws.yaml"
    named = _value_after(workspace, rac.ASH_CONFIG_FROM_HOST_FLAG)
    assert named is not None and named.startswith(rac.CONTAINER_ENV_CONFIG_ROOT)
    assert _value_after(workspace, "--config") == named, workspace
    assert _value_after(one_directory, rac.ASH_CONFIG_FROM_HOST_FLAG) == named
    assert _value_after(one_directory, "--config") is None, one_directory


def _record_the_rules_asks(monkeypatch) -> List[tuple]:
    """Every call of the rule itself, with its answer left as it is."""
    asked: List[tuple] = []
    real = rac._env_config_is_the_scans_config

    def recording(env_config, source_dir):
        asked.append((env_config, Path(source_dir)))
        return real(env_config, source_dir)

    monkeypatch.setattr(rac, "_env_config_is_the_scans_config", recording)
    return asked


def _discoverable_source_with_an_env_config(layout, monkeypatch) -> Path:
    env_config = _write(layout["w"] / "env" / "ash-env.yaml", "project_name: e\n")
    _write(layout["source"] / ".ash" / ".ash.yaml", "project_name: root\n")
    monkeypatch.setenv("ASH_CONFIG", str(env_config))
    assert ras._discovered_config_path(layout["source"]) is not None
    return env_config


def test_the_command_of_a_workspace_scan_never_asks_the_rule(layout, monkeypatch):
    """The workspace gate comes first at the command's call site: a workspace
    scan names the mounted file without the rule being asked at all, and a scan
    of one directory with the same layout asks it once."""
    _discoverable_source_with_an_env_config(layout, monkeypatch)
    asked = _record_the_rules_asks(monkeypatch)

    workspace = _inner_arguments(
        _run_command(
            layout["source"],
            layout["out"],
            workspace_relative_file="ws.yaml",
            reads=rac.OperatorConfigReads(),
        )
    )

    assert asked == []
    named = _value_after(workspace, rac.ASH_CONFIG_FROM_HOST_FLAG)
    assert named is not None and _value_after(workspace, "--config") == named

    _run_command(layout["source"], layout["out"], reads=rac.OperatorConfigReads())
    assert len(asked) == 1, asked


def test_the_pre_flight_of_a_workspace_scan_never_asks_the_rule(layout, monkeypatch):
    """The same gate at the pre-flight, which decides ahead of the build for the
    command to carry: nothing is decided for a workspace scan, and the same
    pre-flight for one directory decides once."""
    _discoverable_source_with_an_env_config(layout, monkeypatch)
    asked = _record_the_rules_asks(monkeypatch)

    rac._require_mountable_inputs(
        layout["source"],
        layout["out"],
        None,
        None,
        "ws.yaml",
        rac.OperatorConfigReads(),
    )
    assert asked == []

    rac._require_mountable_inputs(
        layout["source"],
        layout["out"],
        None,
        None,
        None,
        rac.OperatorConfigReads(),
    )
    assert len(asked) == 1, asked


def test_a_one_directory_answer_in_the_record_does_not_reach_a_workspace_command(
    layout, monkeypatch
):
    """The record keeps the rule's answer per (file, source directory). A
    pre-flight of one directory leaves "discovery found a file" in it for the
    key a workspace command then asks about; the workspace gate still wins, and
    the file is named."""
    _discoverable_source_with_an_env_config(layout, monkeypatch)
    reads = rac.OperatorConfigReads()
    rac._require_mountable_inputs(
        layout["source"], layout["out"], None, None, None, reads
    )
    env_config = reads.host_ash_config()
    assert reads.env_config_is_the_scans_config(env_config, layout["source"]) is False

    workspace = _inner_arguments(
        _run_command(
            layout["source"],
            layout["out"],
            workspace_relative_file="ws.yaml",
            reads=reads,
        )
    )

    named = _value_after(workspace, rac.ASH_CONFIG_FROM_HOST_FLAG)
    assert named is not None and _value_after(workspace, "--config") == named


def test_a_workspace_pre_flight_leaves_no_answer_for_a_one_directory_command(
    layout, monkeypatch
):
    """The other direction: after a workspace pre-flight, a command for one
    directory through the same record asks the rule itself and gets the rule's
    answer (a discoverable config, so nothing is named as the scan's config),
    not an answer the workspace path left behind."""
    _discoverable_source_with_an_env_config(layout, monkeypatch)
    asked = _record_the_rules_asks(monkeypatch)
    reads = rac.OperatorConfigReads()
    rac._require_mountable_inputs(
        layout["source"], layout["out"], None, None, "ws.yaml", reads
    )
    assert asked == []

    one_directory = _inner_arguments(
        _run_command(layout["source"], layout["out"], reads=reads)
    )

    assert len(asked) == 1, asked
    assert _value_after(one_directory, "--config") is None, one_directory
    assert _value_after(one_directory, rac.ASH_CONFIG_FROM_HOST_FLAG) is not None


def test_the_pre_flight_of_a_scan_that_names_its_config_never_asks_the_rule(
    layout, monkeypatch
):
    """A named --config wins over discovery, so the answer would go unused:
    the pre-flight does not decide it. The same pre-flight with no --config
    decides once."""
    _discoverable_source_with_an_env_config(layout, monkeypatch)
    named = _write(layout["w"] / "ops" / "named.yaml", "project_name: n\n")
    asked = _record_the_rules_asks(monkeypatch)

    rac._require_mountable_inputs(
        layout["source"],
        layout["out"],
        str(named),
        None,
        None,
        rac.OperatorConfigReads(),
    )
    assert asked == []

    rac._require_mountable_inputs(
        layout["source"], layout["out"], None, None, None, rac.OperatorConfigReads()
    )
    assert len(asked) == 1, asked


def test_a_scan_that_names_its_config_logs_nothing_about_files_discovery_would_read(
    layout, monkeypatch, caplog
):
    """Discovery reads the source directory's pyproject.toml and says so when it
    cannot use it. A scan that names its config reads no such file, so its
    pre-flight logs nothing about one; without a named config the same layout
    does log it, which shows the log is captured."""
    _discoverable_source_with_an_env_config(layout, monkeypatch)
    _unparsable_source_config(layout["source"])
    named = _write(layout["w"] / "ops" / "named.yaml", "project_name: n\n")

    def pyproject_messages() -> List[str]:
        return [
            record.getMessage()
            for record in caplog.records
            if "pyproject.toml" in record.getMessage()
        ]

    with caplog.at_level(logging.WARNING, logger="ash"):
        rac._require_mountable_inputs(
            layout["source"], layout["out"], None, None, None, rac.OperatorConfigReads()
        )
    assert pyproject_messages(), "the control run should log about pyproject.toml"

    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="ash"):
        rac._require_mountable_inputs(
            layout["source"],
            layout["out"],
            str(named),
            None,
            None,
            rac.OperatorConfigReads(),
        )
    assert pyproject_messages() == []


def _discovery_layouts():
    from automated_security_helper.core.constants import (
        ASH_CONFIG_FILE_NAMES,
        ASH_PYPROJECT_FILE_NAME,
        ASH_RC_FILE_NAMES,
    )

    def files(*entries):
        def build(source: Path) -> None:
            for relative, text in entries:
                _write(source / relative, text)

        return build

    def dangling_link(source: Path) -> None:
        (source / ASH_CONFIG_FILE_NAMES[0]).symlink_to(source / "missing.yaml")

    def directory_named_like_a_config(source: Path) -> None:
        (source / ASH_CONFIG_FILE_NAMES[0]).mkdir()

    return [
        pytest.param(files(), True, id="nothing"),
        pytest.param(
            files((ASH_CONFIG_FILE_NAMES[0], "project_name: r\n")),
            False,
            id="dedicated-name-in-the-root",
        ),
        pytest.param(
            files((f".ash/{ASH_CONFIG_FILE_NAMES[0]}", "project_name: r\n")),
            False,
            id="dedicated-name-in-dot-ash",
        ),
        pytest.param(
            files((ASH_CONFIG_FILE_NAMES[-1], "project_name: r\n")),
            False,
            id="last-dedicated-name",
        ),
        pytest.param(
            files((ASH_RC_FILE_NAMES[0], "")), False, id="rc-file-in-the-root"
        ),
        pytest.param(
            files((ASH_PYPROJECT_FILE_NAME, "[tool.ash]\nproject_name = 'r'\n")),
            False,
            id="pyproject-with-an-ash-table",
        ),
        pytest.param(
            files((ASH_PYPROJECT_FILE_NAME, "[project]\nname = 'r'\n")),
            True,
            id="pyproject-without-an-ash-table",
        ),
        pytest.param(dangling_link, True, id="dangling-link-with-a-config-name"),
        pytest.param(
            directory_named_like_a_config, True, id="directory-with-a-config-name"
        ),
    ]


@pytest.mark.parametrize(("populate", "env_config_is_the_config"), _discovery_layouts())
def test_the_rule_and_the_parse_check_agree_on_what_discovery_finds(
    populate, env_config_is_the_config, layout
):
    """The file the host parse-checks and the file the scan inside discovers are
    one answer: ASH_CONFIG is the scan's config exactly when the parse check
    finds no file to check."""
    from types import SimpleNamespace

    source = layout["source"]
    populate(source)

    rule = rac._env_config_is_the_scans_config("env.yaml", source)
    parsed = ras._container_config_to_parse(
        SimpleNamespace(config=None, source_dir=str(source))
    )

    assert rule is env_config_is_the_config
    assert (parsed is None) is env_config_is_the_config, parsed


def test_the_rule_asks_the_same_discovery_call_as_the_parse_check(layout, monkeypatch):
    """One call decides both: a stand-in for ``find_config_file`` that finds a
    file makes the rule answer False, one that fails leaves the error to the scan
    (False), and neither is a second definition of what is discoverable."""
    from automated_security_helper.config import resolve_config

    asked: List[Path] = []

    def finds_a_file(search_dir=None, permit=None):
        asked.append(Path(search_dir))
        return layout["source"] / "found.yaml"

    def fails(search_dir=None, permit=None):
        raise RuntimeError("discovery failed")

    monkeypatch.setattr(resolve_config, "find_config_file", finds_a_file)
    assert rac._env_config_is_the_scans_config("env.yaml", layout["source"]) is False
    assert asked == [layout["source"]]

    monkeypatch.setattr(resolve_config, "find_config_file", fails)
    assert rac._env_config_is_the_scans_config("env.yaml", layout["source"]) is False


def _unparsable_source_config(source: Path) -> None:
    """A pyproject.toml that declares [tool.ash] and does not parse.

    With nothing of higher precedence beside it, discover_config_source raises
    for it (a real filesystem shape, no patching) rather than reporting a
    config or none."""
    _write(source / "pyproject.toml", "[tool.ash]\nproject_name = = broken\n")


def test_a_discovery_error_never_promotes_ash_config_on_the_host(layout, monkeypatch):
    """A source directory whose config discovery raises is not one that has no
    config: ASH_CONFIG is not named as the scan's config, and the error is left
    to the scan to report. The error comes from a real shape (an unparsable
    pyproject.toml that declares [tool.ash]), not from patching discovery."""
    from automated_security_helper.config.config_sources import (
        discover_config_source,
    )

    env_config = _write(layout["w"] / "env" / "ash-env.yaml", "project_name: e\n")
    _unparsable_source_config(layout["source"])
    monkeypatch.setenv("ASH_CONFIG", str(env_config))
    with pytest.raises(Exception):
        discover_config_source(layout["source"])  # control: discovery does raise

    assert ras._ash_config_fallback(layout["source"]) is None


def test_a_discovery_error_never_names_ash_config_in_the_container(
    layout, commands, monkeypatch
):
    """The same discovery error through the container command: the mounted
    ASH_CONFIG file is not named as the inner --config and is not marked, while
    it is still handed over as the scan's base with --ash-config-from-host."""
    env_config = _write(layout["w"] / "env" / "ash-env.yaml", "project_name: e\n")
    _unparsable_source_config(layout["source"])
    monkeypatch.setenv("ASH_CONFIG", str(env_config))

    rac.run_ash_container(
        source_dir=str(layout["source"]),
        output_dir=str(layout["out"]),
        build=False,
        run=True,
    )

    (run,) = [cmd for cmd in commands if len(cmd) > 1 and cmd[1] == "run"]
    assert "--ash-config-from-host" in run, run
    assert "--config" not in run, run
    assert rac.CONFIG_FROM_SCANNED_REPOSITORY_FLAG not in run, run


def test_ash_config_is_named_in_the_container_when_the_source_has_no_config(
    layout, commands, monkeypatch
):
    """With nothing discoverable in the source directory, a local scan reads
    ASH_CONFIG as its config, so the container command names the mounted file as
    the inner --config as well as handing it over as the base."""
    env_config = _write(layout["w"] / "env" / "ash-env.yaml", "project_name: e\n")
    monkeypatch.setenv("ASH_CONFIG", str(env_config))
    assert ras._discovered_config_path(layout["source"]) is None

    rac.run_ash_container(
        source_dir=str(layout["source"]),
        output_dir=str(layout["out"]),
        build=False,
        run=True,
    )

    (run,) = [cmd for cmd in commands if len(cmd) > 1 and cmd[1] == "run"]
    pairs = list(zip(run, run[1:]))
    assert ("--config", "/ash-env-config/ash-env.yaml") in pairs, run
    assert ("--ash-config-from-host", "/ash-env-config/ash-env.yaml") in pairs, run


def test_a_runtime_name_in_a_data_field_is_not_read_and_not_passed(layout):
    """The loader reads only its own allowlist into a config (names beginning
    with ASH_, plus AWS_DEFAULT_REGION, AWS_PROFILE and AWS_REGION): a field
    spelling ${HOME} keeps the reference as written, so a runtime name like
    HOME or PATH can never reach -e or the env file through a data field."""
    config = _write(layout["w"] / "ash.yaml", "project_name: ${HOME}\n")

    names = rac.operator_environment_names(str(config), None, layout["source"])

    assert names == []


def test_a_runtime_name_in_extends_refuses_the_scan(layout):
    """An extends entry spelling ${PATH} does not resolve, because the loader
    does not read that name: the scan is refused with the entry named, rather
    than run with a chain the scan inside would resolve differently."""
    config = _write(layout["w"] / "ash.yaml", "extends: ${PATH}\n")

    with pytest.raises(rac.ContainerInputError, match="Could not read the variables"):
        rac.operator_environment_names(str(config), None, layout["source"])


def test_the_chain_is_placed_where_the_extending_file_names_each_base(layout):
    """Each base is mounted at the entry as written, relative to the extending
    file's container path, with its content from where the host resolves it."""
    base = _write(layout["w"] / "team" / "base.yaml", "project_name: base\n")
    config = _write(layout["w"] / "ash.yaml", "extends: team/base.yaml\n")
    inner = f"{rac.CONTAINER_CONFIG_ROOT}/ash.yaml"

    placements = rac._chain_placements(
        rac._real_path(str(config)), inner, rac.CONTAINER_CONFIG_ROOT
    )

    assert placements == [
        (rac._real_path(str(config)), inner),
        (
            rac._real_path(str(base)),
            f"{rac.CONTAINER_CONFIG_ROOT}/team/base.yaml",
        ),
    ]


def test_a_chain_entry_leaving_the_mount_root_is_refused(layout):
    """An entry whose container path would sit outside the mount root is
    refused before anything is mounted, naming the entry."""
    config = _write(layout["w"] / "ash.yaml", "extends: ../escape.yaml\n")

    with pytest.raises(rac.ContainerInputError, match="outside"):
        rac._chain_placements(
            rac._real_path(str(config)),
            f"{rac.CONTAINER_CONFIG_ROOT}/ash.yaml",
            rac.CONTAINER_CONFIG_ROOT,
        )


def test_a_repository_file_extending_outside_the_checkout_is_refused(layout):
    """A chain file inside the scanned checkout may extend only files inside
    it; one reaching out is refused with both files named. A base inside the
    checkout stays allowed."""
    _write(layout["w"] / "outside.yaml", "project_name: p\n")
    repo_file = _write(
        layout["repo"] / "ci" / "cfg.yaml", "extends: ../../outside.yaml\n"
    )
    placements = [(rac._real_path(str(repo_file)), "/ash-config/cfg.yaml")]

    with pytest.raises(rac.ContainerInputError, match="outside it"):
        rac._refuse_repository_bases_reaching_out(placements, layout["source"])

    _write(layout["repo"] / "ci" / "base.yaml", "project_name: p\n")
    repo_file.write_text("extends: base.yaml\n", encoding="utf-8")
    rac._refuse_repository_bases_reaching_out(placements, layout["source"])


def _debug_scan_output(layout, monkeypatch, config: Path) -> str:
    """Run ``ash scan --mode container --no-build --debug`` with the runner
    stubbed, and return everything the CLI printed plus ash.log's text."""
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app

    monkeypatch.delenv("OCI_RUNNER_WRAPPER", raising=False)
    commands: List[List[str]] = []
    monkeypatch.setattr(
        rac,
        "run_cmd_direct",
        lambda cmd, *a, **k: (
            commands.append([str(c) for c in cmd])
            or create_completed_process(args=cmd, returncode=0, stdout="", stderr="")
        ),
    )
    monkeypatch.chdir(layout["w"])
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--no-progress",
            "--debug",
            "--config",
            str(config),
            "--source-dir",
            str(layout["source"]),
            "--output-dir",
            str(layout["out"]),
        ],
    )
    text = result.output
    log = layout["out"] / "ash.log"
    if log.is_file():
        text += log.read_text(encoding="utf-8", errors="replace")
    assert commands, text  # the echo under test fires only when a run was built
    return text


def test_the_debug_echo_hides_env_chosen_mount_sources(layout, commands, monkeypatch):
    """The --debug echo of the container command never prints an env value.

    The mount source for a base the environment chose holds the variable's
    value as a path segment; the echoed command rewrote only
    --config-overrides values, so the -v/--mount arguments printed it raw, on
    stdout and into ash.log."""
    value = "chainx-opsdir-9e4a"
    monkeypatch.setenv("ASH_CHAIN_X", value)
    _write(layout["w"] / value / "base.yaml", "project_name: b\n")
    config = _write(layout["w"] / "ash.yaml", "extends: ${ASH_CHAIN_X}/base.yaml\n")

    text = _debug_scan_output(layout, monkeypatch, config)

    assert value not in text, [line for line in text.splitlines() if value in line][:3]


def test_the_debug_echo_prints_a_literal_chain_as_written(
    layout, commands, monkeypatch
):
    """Control: a chain with no env-reading entry prints its mount sources as
    written, so the masking never widens past what the environment chose."""
    _write(layout["w"] / "team" / "base.yaml", "project_name: b\n")
    config = _write(layout["w"] / "ash.yaml", "extends: team/base.yaml\n")

    text = _debug_scan_output(layout, monkeypatch, config)

    assert "team/base.yaml" in text, text[-2000:]


def test_an_unmountable_env_chosen_container_path_shows_no_value(layout, monkeypatch):
    """The container-path refusal names an env-built path as the chain views do.

    The entry as written can hold a character --mount cannot carry through a
    link's name while the file's own path does not; when the environment chose
    that name, the refusal printed the variable's value inside the container
    path."""
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    value = "chainlnk,dir"
    monkeypatch.setenv("ASH_CHAIN_C", value)
    _write(layout["w"] / "clean" / "base.yaml", "project_name: b\n")
    (layout["w"] / value).symlink_to(layout["w"] / "clean")
    config = _write(layout["w"] / "ash.yaml", "extends: ${ASH_CHAIN_C}/base.yaml\n")

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert "cannot be handed to the container runner" in refusal, refusal
    assert value not in refusal, refusal
    assert (
        f"The container path of a config file {ENVIRONMENT_VALUE_SHOWN} cannot be handed"
        in refusal
    ), refusal


def _one_base_at_two_container_paths(layout, monkeypatch, link_name: str) -> Path:
    """A config extending one real file twice: first by an environment entry
    that goes through a link to the directory, then by the literal path. Any
    file reached through an environment-reading entry is shown as the marker,
    a deliberate fail-safe over-mask keyed on how the file is reached, not on
    what its path contains."""
    w = layout["w"]
    _write(w / "real" / "base.yaml", "project_name: b\n")
    (w / link_name).symlink_to(w / "real", target_is_directory=True)
    monkeypatch.setenv("ASH_CHAIN_X", link_name)
    return _write(
        w / "ash.yaml",
        # The environment entry is a plain scalar: YAML's implicit resolvers
        # skip quoted strings, so a quoted entry would stay literal.
        "extends:\n  - ${ASH_CHAIN_X}/base.yaml\n  - real/base.yaml\n",
    )


def test_one_base_reached_by_a_link_and_by_its_path_is_mounted_at_both_places(
    layout, commands, monkeypatch
):
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app

    config = _one_base_at_two_container_paths(layout, monkeypatch, "lnk")
    monkeypatch.delenv("OCI_RUNNER_WRAPPER", raising=False)
    monkeypatch.chdir(layout["w"])

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--no-progress",
            "--config",
            str(config),
            "--source-dir",
            str(layout["source"]),
            "--output-dir",
            str(layout["out"]),
        ],
    )

    assert commands, result.output
    run = commands[-1]
    for destination in (
        f"{rac.CONTAINER_CONFIG_ROOT}/lnk/base.yaml",
        f"{rac.CONTAINER_CONFIG_ROOT}/real/base.yaml",
    ):
        assert any(f"destination={destination},readonly" in arg for arg in run), run


def test_a_container_path_through_an_env_entry_is_refused_without_the_value(
    layout, commands, monkeypatch
):
    """The file is reached by its literal path and through an environment-
    reading entry, so it is shown as the marker (a deliberate fail-safe
    over-mask keyed on how the file is reached); the container path that entry
    gives it holds the variable's value and is shown as the marker too."""
    from typer.testing import CliRunner

    from automated_security_helper.cli.main import app
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    config = _one_base_at_two_container_paths(layout, monkeypatch, "lnk,dir")
    monkeypatch.delenv("OCI_RUNNER_WRAPPER", raising=False)
    monkeypatch.chdir(layout["w"])

    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "container",
            "--no-build",
            "--no-progress",
            "--config",
            str(config),
            "--source-dir",
            str(layout["source"]),
            "--output-dir",
            str(layout["out"]),
        ],
    )

    text = result.output
    log = layout["out"] / "ash.log"
    if log.is_file():
        text += log.read_text(encoding="utf-8", errors="replace")
    assert result.exit_code != 0, text
    assert commands == [], commands
    assert "lnk,dir" not in text, text
    assert ENVIRONMENT_VALUE_SHOWN in text, text


#: One base file reached by an environment entry and by a literal one, in the
#: shapes where the file's own path, the link's name, or both carry the value.
#: ``names`` is the exact shown-name map of the container paths (None: the
#: path as written; the marker otherwise) and ``phrase`` the refusal's opening.
_BASE_TWICE_SHAPES = {
    "value-in-a-link-name": {
        "directory": "real",
        "link": "lnk,dir",
        "env_value": "lnk,dir",
        "literal": "real",
        "names": {"lnk,dir/base.yaml": "marker", "real/base.yaml": None},
        "phrase": "The container path of a config file {marker} cannot be handed",
    },
    "value-in-the-real-directory-name": {
        "directory": "sec,ret",
        "link": "lnk",
        "env_value": "sec,ret",
        "literal": "lnk",
        "names": {"sec,ret/base.yaml": "marker", "lnk/base.yaml": None},
        "phrase": "The config file {marker} cannot be handed",
    },
    "both-entries-name-one-path": {
        "directory": "sec,ret",
        "link": None,
        "env_value": "sec,ret",
        "literal": "sec,ret",
        "names": {"sec,ret/base.yaml": "marker"},
        "phrase": "The config file {marker} cannot be handed",
    },
}


def _base_reached_literally_and_through_the_environment(
    layout, monkeypatch, shape: dict, env_first: bool
) -> Path:
    w = layout["w"]
    _write(w / shape["directory"] / "base.yaml", "project_name: b\n")
    if shape["link"] is not None:
        (w / shape["link"]).symlink_to(w / shape["directory"], target_is_directory=True)
    monkeypatch.setenv("ASH_CHAIN_X", shape["env_value"])
    # The environment entry is a plain scalar: YAML's implicit resolvers skip
    # quoted strings, so a quoted entry would stay literal.
    entries = ["${ASH_CHAIN_X}/base.yaml", f"{shape['literal']}/base.yaml"]
    if not env_first:
        entries.reverse()
    return _write(
        w / "ash.yaml", "extends:\n" + "".join(f"  - {entry}\n" for entry in entries)
    )


@pytest.mark.parametrize("env_first", [True, False])
@pytest.mark.parametrize("shape_name", sorted(_BASE_TWICE_SHAPES))
def test_the_chain_names_a_file_and_its_container_paths_by_every_way_they_are_reached(
    layout, monkeypatch, shape_name, env_first
):
    """A file reached through an entry that reads the environment is shown as
    the marker whichever entry the walk visits first; a container path is shown
    by the placement that gave it. The maps are exact."""
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    shape = _BASE_TWICE_SHAPES[shape_name]
    config = _base_reached_literally_and_through_the_environment(
        layout, monkeypatch, shape, env_first
    )
    root = rac.CONTAINER_CONFIG_ROOT
    resolved = rac._real_path(config)

    _placements, file_names, path_names = rac._chain_placements_shown(
        resolved, f"{root}/ash.yaml", root
    )

    base = rac._real_path(layout["w"] / shape["directory"] / "base.yaml")
    assert {str(file): name for file, name in file_names.items()} == {
        str(resolved): str(resolved),
        str(base): ENVIRONMENT_VALUE_SHOWN,
    }
    expected = {f"{root}/ash.yaml": f"{root}/ash.yaml"}
    for relative, name in shape["names"].items():
        expected[f"{root}/{relative}"] = (
            ENVIRONMENT_VALUE_SHOWN if name == "marker" else f"{root}/{relative}"
        )
    assert path_names == expected


@pytest.mark.parametrize("env_first", [True, False])
@pytest.mark.parametrize("shape_name", sorted(_BASE_TWICE_SHAPES))
def test_an_unmountable_base_reached_both_ways_is_refused_without_the_value(
    layout, monkeypatch, shape_name, env_first
):
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    shape = _BASE_TWICE_SHAPES[shape_name]
    config = _base_reached_literally_and_through_the_environment(
        layout, monkeypatch, shape, env_first
    )

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert shape["env_value"] not in refusal, refusal
    assert shape["phrase"].format(marker=ENVIRONMENT_VALUE_SHOWN) in refusal, refusal


#: A directory name that appears in no test name or temporary path, so any
#: text holding it came from the entry the environment chose.
_ENV_DIRECTORY = "zq7dir"


def _base_with_its_own_entry_reached_both_ways(
    layout,
    monkeypatch,
    env_first: bool,
    base_text: str,
    below_text: str | None = None,
) -> Path:
    """A config extending one base twice, by an environment entry and by the
    literal path (both name the same file at the same container path), where
    the base carries its own ``extends`` entry. ``env_first`` lists the
    environment entry first, so the walk visits the literal entry first."""
    w = layout["w"]
    _write(w / _ENV_DIRECTORY / "base.yaml", base_text)
    if below_text is not None:
        _write(w / _ENV_DIRECTORY / "chi,ld.yaml", below_text)
    monkeypatch.setenv("ASH_CHAIN_X", _ENV_DIRECTORY)
    entries = ["${ASH_CHAIN_X}/base.yaml", f"{_ENV_DIRECTORY}/base.yaml"]
    if not env_first:
        entries.reverse()
    return _write(
        w / "ash.yaml", "extends:\n" + "".join(f"  - {entry}\n" for entry in entries)
    )


@pytest.mark.parametrize("env_first", [True, False])
def test_a_file_below_a_base_reached_both_ways_is_named_by_the_entry_that_reached_the_base(
    layout, monkeypatch, env_first
):
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    config = _base_with_its_own_entry_reached_both_ways(
        layout,
        monkeypatch,
        env_first,
        "extends: chi,ld.yaml\n",
        "project_name: b\n",
    )
    root = rac.CONTAINER_CONFIG_ROOT
    resolved = rac._real_path(config)

    _placements, file_names, path_names = rac._chain_placements_shown(
        resolved, f"{root}/ash.yaml", root
    )

    base = rac._real_path(layout["w"] / _ENV_DIRECTORY / "base.yaml")
    below = rac._real_path(layout["w"] / _ENV_DIRECTORY / "chi,ld.yaml")
    assert {str(file): name for file, name in file_names.items()} == {
        str(resolved): str(resolved),
        str(base): ENVIRONMENT_VALUE_SHOWN,
        str(below): ENVIRONMENT_VALUE_SHOWN,
    }
    assert path_names == {
        f"{root}/ash.yaml": f"{root}/ash.yaml",
        f"{root}/{_ENV_DIRECTORY}/base.yaml": ENVIRONMENT_VALUE_SHOWN,
        f"{root}/{_ENV_DIRECTORY}/chi,ld.yaml": ENVIRONMENT_VALUE_SHOWN,
    }


@pytest.mark.parametrize("env_first", [True, False])
def test_an_unmountable_file_below_a_base_reached_both_ways_is_refused_without_the_value(
    layout, monkeypatch, env_first
):
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    config = _base_with_its_own_entry_reached_both_ways(
        layout,
        monkeypatch,
        env_first,
        "extends: chi,ld.yaml\n",
        "project_name: b\n",
    )

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert _ENV_DIRECTORY not in refusal, refusal
    assert f"The config file {ENVIRONMENT_VALUE_SHOWN} cannot be handed" in refusal, (
        refusal
    )


@pytest.mark.parametrize("env_first", [True, False])
def test_a_base_leaving_the_mount_root_below_a_base_reached_both_ways_is_refused_without_the_value(
    layout, monkeypatch, env_first
):
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    config = _base_with_its_own_entry_reached_both_ways(
        layout, monkeypatch, env_first, "extends: ../../outside.yaml\n"
    )
    root = rac.CONTAINER_CONFIG_ROOT

    with pytest.raises(rac.ContainerInputError) as raised:
        rac._chain_placements_shown(rac._real_path(config), f"{root}/ash.yaml", root)

    text = str(raised.value)
    assert f"outside {root}" in text, text
    assert _ENV_DIRECTORY not in text, text
    assert ENVIRONMENT_VALUE_SHOWN in text, text


@pytest.mark.parametrize("env_first", [True, False])
def test_an_absolute_entry_in_a_base_reached_both_ways_is_refused_without_the_value(
    layout, monkeypatch, env_first
):
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    config = _base_with_its_own_entry_reached_both_ways(
        layout, monkeypatch, env_first, "extends: /absent-base/other.yaml\n"
    )

    with pytest.raises(rac.ContainerInputError) as raised:
        rac._refuse_absolute_extends(str(config))

    text = str(raised.value)
    assert f"in {ENVIRONMENT_VALUE_SHOWN} names a base by absolute path" in text, text
    assert _ENV_DIRECTORY not in text, text


def test_a_chain_of_literal_entries_is_named_as_written(layout):
    """Control: with no entry reading the environment, every file and container
    path is named as written, so the marker never widens past what the
    environment chose."""
    w = layout["w"]
    _write(w / "real" / "base.yaml", "project_name: b\n")
    (w / "lnk").symlink_to(w / "real", target_is_directory=True)
    config = _write(w / "ash.yaml", "extends:\n  - lnk/base.yaml\n  - real/base.yaml\n")
    root = rac.CONTAINER_CONFIG_ROOT
    resolved = rac._real_path(config)

    _placements, file_names, path_names = rac._chain_placements_shown(
        resolved, f"{root}/ash.yaml", root
    )

    base = rac._real_path(w / "real" / "base.yaml")
    assert {str(file): name for file, name in file_names.items()} == {
        str(resolved): str(resolved),
        str(base): str(base),
    }
    assert path_names == {
        f"{root}/ash.yaml": f"{root}/ash.yaml",
        f"{root}/lnk/base.yaml": f"{root}/lnk/base.yaml",
        f"{root}/real/base.yaml": f"{root}/real/base.yaml",
    }


def test_an_unmountable_env_chosen_file_path_shows_no_value(layout, monkeypatch):
    """The config-file refusal names an env-chosen chain file as the views do:
    its host path holds the variable's value as a segment."""
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    value = 'chain"dir'
    monkeypatch.setenv("ASH_CHAIN_Q", value)
    _write(layout["w"] / value / "base.yaml", "project_name: b\n")
    config = _write(layout["w"] / "ash.yaml", "extends: ${ASH_CHAIN_Q}/base.yaml\n")

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert "cannot be handed to the container runner" in refusal, refusal
    assert value not in refusal, refusal
    assert f"The config file {ENVIRONMENT_VALUE_SHOWN} cannot be handed" in refusal, (
        refusal
    )


def test_an_unmountable_literal_path_is_still_named_as_written(layout):
    """Control: a literal chain entry's refusal names the path as written, so
    the masking never widens past what the environment chose."""
    _write(layout["w"] / "te,am" / "base.yaml", "project_name: b\n")
    config = _write(layout["w"] / "ash.yaml", "extends: te,am/base.yaml\n")

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert refusal is not None
    assert "cannot be handed to the container runner" in refusal, refusal
    assert "te,am" in refusal, refusal


def test_an_unresolved_chain_debug_line_shows_no_value(layout, monkeypatch):
    """The mounted-alone debug line renders the failure without env values.

    A chain error raised while the mounts are planned logs why and mounts the
    config alone; the error's text can name a path that holds a variable's
    value. An end-to-end chain failure is refused by the scan's own config
    judgment before the mounts are planned, with that refusal's own masking
    (measured), so this cell drives the fallback branch directly with a
    resolution that raises."""
    import logging

    value = "chainm-missing"
    monkeypatch.setenv("ASH_CHAIN_M", value)
    config = _write(layout["w"] / "ash.yaml", "extends: ${ASH_CHAIN_M}/missing.yaml\n")

    from automated_security_helper.config import config_sources

    def raising(path, **kwargs):
        raise ValueError(f"the chain broke at {value}/missing.yaml")

    monkeypatch.setattr(config_sources, "resolve_config_document", raising)

    lines: list = []

    class _Capture(logging.Handler):
        def emit(self, record):
            lines.append(record.getMessage())

    handler = _Capture(level=logging.DEBUG)
    old_level = rac.ASH_LOGGER.level
    rac.ASH_LOGGER.addHandler(handler)
    rac.ASH_LOGGER.setLevel(logging.DEBUG)
    try:
        _mounts, _inner, files, plan = rac._host_file_in_container(
            str(config),
            layout["source"],
            rac.CONTAINER_CONFIG_ROOT,
            follow_extends=True,
        )
    finally:
        rac.ASH_LOGGER.removeHandler(handler)
        rac.ASH_LOGGER.setLevel(old_level)

    text = "\n".join(lines)
    assert "did not resolve" in text, text
    assert value not in text, [line for line in text.splitlines() if value in line][:3]
    assert len(files) == 1 and plan.document is None  # the file is mounted alone


def test_the_env_file_holds_the_values_and_only_this_user_reads_it(layout, monkeypatch):
    """_write_env_file writes NAME=value lines into a mode-0600 file in a new
    mode-0700 directory outside the source and output directories; a runner
    ASH does not know to take --env-file, and a value an env file cannot
    carry, are refused by name."""
    import os as _os
    import stat
    import tempfile

    env_root = layout["w"] / "envtmp"
    env_root.mkdir()
    monkeypatch.setenv("TMPDIR", str(env_root))
    monkeypatch.setattr(tempfile, "tempdir", None)

    with rac._env_file(
        [OPERATOR_VAR],
        {OPERATOR_VAR: OPERATOR_VALUE},
        "docker",
        layout["source"],
        layout["out"],
    ) as (directory, path):
        assert path.read_text(encoding="utf-8") == f"{OPERATOR_VAR}={OPERATOR_VALUE}\n"
        assert stat.S_IMODE(_os.stat(path).st_mode) == 0o600
        assert stat.S_IMODE(_os.stat(directory).st_mode) == 0o700
        assert directory.is_relative_to(env_root), directory

    with pytest.raises(rac.ContainerInputError, match="--env-file"):
        rac._write_env_file(
            [OPERATOR_VAR],
            {OPERATOR_VAR: "x"},
            "unknown-runner",
            layout["source"],
            layout["out"],
        )
    with pytest.raises(rac.ContainerInputError, match="line break or a NUL"):
        rac._write_env_file(
            [OPERATOR_VAR],
            {OPERATOR_VAR: "a\nb"},
            "docker",
            layout["source"],
            layout["out"],
        )


EMPTY_VAR = "ASH_HANDOFF_CELL_EMPTY_VALUE"


def test_an_entry_that_resolves_to_nothing_is_refused_as_the_scan_inside_refuses_it(
    layout, monkeypatch
):
    """An entry reading a variable set to the empty string resolves to no
    path, which the loader refuses; the host answers the same way instead of
    silently dropping the entry and judging a chain the scan inside will not
    read."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    monkeypatch.setenv(EMPTY_VAR, "")
    _write(layout["w"] / "base.yaml", "project_name: base\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "extends:\n  - ${" + EMPTY_VAR + "}\n  - base.yaml\n",
    )

    with pytest.raises(ASHConfigSourceError, match="path or a list of paths"):
        rac._extends_refs_shown(config)


def test_the_naming_walk_stays_best_effort_over_a_refused_chain(layout, monkeypatch):
    """The files-reached walk only supplies names for refusal messages, so a
    chain whose entries refuse ends that walk quietly and names nothing; the
    refusal itself is the entry read's, asserted here with the walk so this
    cell holds both halves of the contract."""
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    monkeypatch.setenv(EMPTY_VAR, "")
    _write(layout["w"] / "base.yaml", "project_name: base\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "extends:\n  - ${" + EMPTY_VAR + "}\n  - base.yaml\n",
    )

    with pytest.raises(ASHConfigSourceError, match="path or a list of paths"):
        rac._extends_refs_shown(config)
    assert rac._files_reached_through_environment(config) == frozenset()


def test_a_streamed_line_keeps_a_bare_common_word_matching_a_short_value():
    """The streamed output is the operator's scan report: a bare word equal
    to a short carried value prints as the child wrote it, while the line
    that quotes the value back does not show it."""
    line = "Severity: HIGH ('HIGH' came back quoted)\n"

    out = rac._streamed_line(line, ("HIGH",), scan_report=True)

    assert "Severity: HIGH" in out, out
    assert "'HIGH'" not in out, out


def test_a_streamed_line_hides_a_long_carried_value_anywhere():
    """The must-flag twin: a value long enough to be matched anywhere stays
    hidden wherever the child prints it."""
    value = "carried-operator-value-length"

    out = rac._streamed_line(
        "prefix " + value + " suffix\n", (value,), scan_report=True
    )

    assert value not in out, out


def test_recorded_text_keeps_its_bands_for_everything_but_the_stream():
    """The loosened band is the stream's own: error text and recorded
    messages keep hiding a short carried value as a whole word."""
    from automated_security_helper.utils.error_text import text_without_values

    out = text_without_values("Severity: HIGH", ("HIGH",))

    assert "HIGH" not in out, out


def test_a_json_extends_entry_keeps_its_reference_literal(layout, monkeypatch):
    """JSON is never interpolated by the loader, so a reference-shaped entry
    in a JSON config names a literal path, exactly as the scan inside will
    read it: followed as written, quoted as written, reading nothing."""
    monkeypatch.setenv(OPERATOR_VAR, "env_base.yaml")
    reference = "${" + OPERATOR_VAR + "}"
    config = _write(
        layout["w"] / "ash.json",
        '{"project_name": "op", "extends": ["' + reference + '"]}',
    )

    assert rac._extends_refs_shown(config) == [(reference, reference, False)]


def test_a_quoted_yaml_extends_entry_keeps_its_reference_literal(layout, monkeypatch):
    """A quoted scalar is the documented way to keep a reference literal, and
    the loader honors it; the host follows the quoted text as the scan inside
    will, instead of resolving a variable the file never reads."""
    monkeypatch.setenv(OPERATOR_VAR, "env_base.yaml")
    reference = "${" + OPERATOR_VAR + "}/base.yaml"
    config = _write(
        layout["w"] / "ash.yaml",
        'extends:\n  - "' + reference + '"\n',
    )

    assert rac._extends_refs_shown(config) == [(reference, reference, False)]


def test_each_extends_entry_is_classified_by_its_own_text(layout, monkeypatch):
    """Control: an entry that reads a variable is resolved, quoted as written
    and marked as reading the environment; the literal entry beside it is
    none of those."""
    monkeypatch.setenv(OPERATOR_VAR, "env_base.yaml")
    _write(layout["w"] / "env_base.yaml", "project_name: env\n")
    _write(layout["w"] / "plain.yaml", "project_name: plain\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "extends:\n  - ${" + OPERATOR_VAR + "}\n  - plain.yaml\n",
    )

    assert rac._extends_refs_shown(config) == [
        ("env_base.yaml", "${" + OPERATOR_VAR + "}", True),
        ("plain.yaml", "plain.yaml", False),
    ]
    assert rac._files_reached_through_environment(config) == {
        rac._real_path(str(layout["w"] / "env_base.yaml"))
    }


def test_a_chain_file_is_read_once_while_one_check_walks_the_chain(layout):
    """Within one decorated call a file's entries are read once, so a change
    made meanwhile is not seen; outside one, each ask reads the file."""
    _write(layout["w"] / "a.yaml", "project_name: a\n")
    _write(layout["w"] / "b.yaml", "project_name: b\n")
    config = _write(layout["w"] / "ash.yaml", "extends: a.yaml\n")

    @rac._reading_chain_files_once
    def ask_twice():
        first = rac._extends_refs_shown(config)
        config.write_text("extends: b.yaml\n", encoding="utf-8")
        return first, rac._extends_refs_shown(config)

    first, second = ask_twice()
    assert first == second == [("a.yaml", "a.yaml", False)]
    assert rac._extends_refs_shown(config) == [("b.yaml", "b.yaml", False)]


def test_every_name_a_config_may_read_has_its_value_hidden(monkeypatch):
    """The values hidden in a failure's text come from the same name rule the
    loader resolves references by: one ``ASH_`` variable and the three
    standard AWS names are all present, and a name outside the rule is not."""
    names = {
        "ASH_HIDDEN_PROBE": "ash-probe-value-1",
        "AWS_DEFAULT_REGION": "aws-default-region-value",
        "AWS_PROFILE": "aws-profile-value",
        "AWS_REGION": "aws-region-value",
    }
    for name, value in names.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setenv("NOT_READABLE_PROBE", "outside-the-rule-value")
    hidden = rac._readable_environment_values()
    for value in names.values():
        assert value in hidden, hidden
    assert "outside-the-rule-value" not in hidden


def test_the_checks_sharing_one_record_see_one_read_across_calls(layout):
    """Two decorated calls that carry the scan's record judge the same
    entries: a file changed between the pre-run check and the mount assembly
    cannot be read two ways within one phase. A fresh record reads afresh, as
    the run phase of a scan that built an image does."""
    _write(layout["w"] / "a.yaml", "project_name: a\n")
    _write(layout["w"] / "b.yaml", "project_name: b\n")
    config = _write(layout["w"] / "ash.yaml", "extends: a.yaml\n")
    record = rac.OperatorConfigReads()

    @rac._reading_chain_files_once
    def ask(reads=None):
        return rac._extends_refs_shown(config)

    first = ask(reads=record)
    config.write_text("extends: b.yaml\n", encoding="utf-8")
    second = ask(reads=record)

    assert first == second == [("a.yaml", "a.yaml", False)]
    assert ask(reads=rac.OperatorConfigReads()) == [("b.yaml", "b.yaml", False)]


def test_the_checks_sharing_a_positional_record_see_one_read(layout):
    """The decorator finds the record among positional arguments too, so a
    caller that passes it positionally shares the same one read."""
    _write(layout["w"] / "a.yaml", "project_name: a\n")
    _write(layout["w"] / "b.yaml", "project_name: b\n")
    config = _write(layout["w"] / "ash.yaml", "extends: a.yaml\n")
    record = rac.OperatorConfigReads()

    @rac._reading_chain_files_once
    def ask(reads):
        return rac._extends_refs_shown(config)

    first = ask(record)
    config.write_text("extends: b.yaml\n", encoding="utf-8")
    second = ask(record)

    assert first == second == [("a.yaml", "a.yaml", False)]


KEY_VAR = "ASH_HANDOFF_CELL_KEY_SPELLING"


def test_a_single_scalar_entry_resolving_to_nothing_is_no_extends(layout, monkeypatch):
    """A reference-only scalar whose variable is empty resolves to no extends,
    and the stock loader runs with no base; the host follows the stock
    reader's count instead of refusing a run the scan inside performs. The
    file still reads the variable, so the variable is named and handed over."""
    monkeypatch.setenv(EMPTY_VAR, "")
    config = _write(layout["w"] / "ash.yaml", "extends: ${" + EMPTY_VAR + "}\n")

    assert rac._extends_refs_shown(config) == []
    assert rac._extends_reference_names(config) == [EMPTY_VAR]
    assert rac.operator_environment_names(str(config), None, layout["source"]) == [
        EMPTY_VAR
    ]
    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))
    assert refusal is None, refusal


def test_an_empty_valued_extends_reference_to_a_name_the_container_sets_is_refused(
    layout, monkeypatch
):
    """The same scalar naming a variable the run command sets inside the
    container: the scan inside would read that value, not the empty one the
    host holds, so the name is refused like any other read of it."""
    monkeypatch.setenv("ASH_OFFLINE", "")
    config = _write(layout["w"] / "ash.yaml", "extends: ${ASH_OFFLINE}\n")

    assert rac._extends_refs_shown(config) == []
    with pytest.raises(rac.ContainerInputError, match="ASH_OFFLINE") as refused:
        rac.operator_environment_names(str(config), None, layout["source"])
    assert "extends" in str(refused.value)
    # The pre-run check reads the chain's entries once and asks for the names
    # from that read.
    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))
    assert isinstance(refusal, str) and "ASH_OFFLINE" in refusal, refusal


BASE_VAR = "ASH_HANDOFF_CELL_BASE_NAME"


def test_a_key_the_environment_spells_is_followed_as_the_loader_follows_it(
    layout, monkeypatch
):
    """A top-level key written as a reference can resolve to ``extends``; the
    loader follows the base it names, so the host follows it too. No written
    spelling names that entry, so it is shown as one the environment chose."""
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    monkeypatch.setenv(KEY_VAR, "extends")
    _write(layout["w"] / "base.yaml", "project_name: base\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "project_name: op\n${" + KEY_VAR + "}: base.yaml\n",
    )

    assert rac._extends_refs_shown(config) == [
        ("base.yaml", ENVIRONMENT_VALUE_SHOWN, True)
    ]


def test_a_key_spelled_as_another_name_leaves_the_written_extends_entry_alone(
    layout, monkeypatch
):
    """A key the environment spells as an ordinary name does not touch the
    written ``extends``: its entry is still quoted as written, and the
    variable it reads is named beside the one that spelled the key."""
    monkeypatch.setenv(KEY_VAR, "project_name")
    monkeypatch.setenv(BASE_VAR, "base.yaml")
    _write(layout["w"] / "base.yaml", "project_name: base\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "${" + KEY_VAR + "}: op\nextends: ${" + BASE_VAR + "}\n",
    )

    assert rac._extends_refs_shown(config) == [
        ("base.yaml", "${" + BASE_VAR + "}", True)
    ]
    names = rac.operator_environment_names(str(config), None, layout["source"])
    assert names == sorted([KEY_VAR, BASE_VAR]), names


def test_a_written_extends_after_a_key_spelled_as_extends_keeps_its_variable(
    layout, monkeypatch
):
    """The loader keeps the last ``extends`` the file writes, so a written
    entry after the key the environment spells as ``extends`` is the one
    followed, quoted as written, and its variable is named. The variable that
    spelled the key the written entry replaced is still read from the
    environment by the file, so it is named too."""
    monkeypatch.setenv(KEY_VAR, "extends")
    monkeypatch.setenv(BASE_VAR, "base.yaml")
    _write(layout["w"] / "base.yaml", "project_name: base\n")
    _write(layout["w"] / "other.yaml", "project_name: other\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "${" + KEY_VAR + "}: other.yaml\nextends: ${" + BASE_VAR + "}\n",
    )

    assert rac._extends_refs_shown(config) == [
        ("base.yaml", "${" + BASE_VAR + "}", True)
    ]
    names = rac.operator_environment_names(str(config), None, layout["source"])
    assert names == sorted([KEY_VAR, BASE_VAR]), names


def test_a_replaced_key_spelled_as_a_name_the_container_sets_is_refused(
    layout, monkeypatch
):
    """The key the written ``extends`` replaced is still read from the
    environment by the file, so a variable the run command sets inside the
    container is refused for it like any other read of that name."""
    monkeypatch.setenv("ASH_OFFLINE", "extends")
    monkeypatch.setenv(BASE_VAR, "base.yaml")
    _write(layout["w"] / "base.yaml", "project_name: base\n")
    _write(layout["w"] / "other.yaml", "project_name: other\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "${ASH_OFFLINE}: other.yaml\nextends: ${" + BASE_VAR + "}\n",
    )

    with pytest.raises(rac.ContainerInputError, match="ASH_OFFLINE"):
        rac.operator_environment_names(str(config), None, layout["source"])
    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))
    assert isinstance(refusal, str) and "ASH_OFFLINE" in refusal, refusal


def test_a_key_spelled_as_extends_after_the_written_entry_is_the_one_followed(
    layout, monkeypatch
):
    """The control of the cell above: with the spelled key last, its base is
    the one followed and shown as one the environment chose."""
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    monkeypatch.setenv(KEY_VAR, "extends")
    monkeypatch.setenv(BASE_VAR, "base.yaml")
    _write(layout["w"] / "base.yaml", "project_name: base\n")
    _write(layout["w"] / "other.yaml", "project_name: other\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "extends: ${" + BASE_VAR + "}\n${" + KEY_VAR + "}: other.yaml\n",
    )

    assert rac._extends_refs_shown(config) == [
        ("other.yaml", ENVIRONMENT_VALUE_SHOWN, True)
    ]
    names = rac.operator_environment_names(str(config), None, layout["source"])
    assert names == sorted([KEY_VAR, BASE_VAR]), names


def test_a_key_spelled_as_another_name_after_the_written_extends_leaves_it_alone(
    layout, monkeypatch
):
    """Order does not make a key the environment spells as an ordinary name
    take the ``extends`` entry: the written entry is still quoted as written
    and its variable is found."""
    monkeypatch.setenv(KEY_VAR, "project_name")
    monkeypatch.setenv(BASE_VAR, "base.yaml")
    _write(layout["w"] / "base.yaml", "project_name: base\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "extends: ${" + BASE_VAR + "}\n${" + KEY_VAR + "}: op\n",
    )

    assert rac._extends_refs_shown(config) == [
        ("base.yaml", "${" + BASE_VAR + "}", True)
    ]
    names = rac.operator_environment_names(str(config), None, layout["source"])
    assert names == sorted([KEY_VAR, BASE_VAR]), names


def test_an_extends_variable_with_a_default_is_handed_over_beside_a_spelled_key(
    layout, monkeypatch
):
    """With a default written after the colon, an unpassed variable would
    resolve silently to that default inside the container, so the name has to
    be among the names handed over when another key is spelled by the
    environment."""
    monkeypatch.setenv(KEY_VAR, "project_name")
    monkeypatch.setenv(BASE_VAR, "base.yaml")
    _write(layout["w"] / "base.yaml", "project_name: base\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "${" + KEY_VAR + "}: op\nextends: ${" + BASE_VAR + ":none.yaml}\n",
    )

    names = rac.operator_environment_names(str(config), None, layout["source"])

    assert BASE_VAR in names, names


def test_an_extends_variable_the_container_sets_is_refused_beside_a_spelled_key(
    layout, monkeypatch
):
    """A spelled key elsewhere in the file does not hide an ``extends`` read of
    a variable the run command sets inside the container."""
    monkeypatch.setenv(KEY_VAR, "project_name")
    monkeypatch.setenv("ASH_OFFLINE", "base.yaml")
    _write(layout["w"] / "base.yaml", "project_name: base\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "${" + KEY_VAR + "}: op\nextends: ${ASH_OFFLINE:none.yaml}\n",
    )

    with pytest.raises(rac.ContainerInputError, match="ASH_OFFLINE"):
        rac.operator_environment_names(str(config), None, layout["source"])


@pytest.mark.parametrize("empty_value", ["", "  "])
def test_a_key_reference_to_a_set_but_empty_variable_refuses_the_container_scan(
    layout, monkeypatch, empty_value
):
    """A top-level key written as a reference to a variable that is set but
    empty resolves to no key. The chain walk reads the entries of such a file
    (the written ``extends`` survives, quoted as written), but the full
    resolution refuses the document outright, so no container scan runs on a
    file whose key the host and the scan inside would read differently. The
    refusal is built without reading a value from the environment, and it
    names the variable, so the operator knows which name to fix; what the
    variable holds is never shown."""
    monkeypatch.setenv(KEY_VAR, empty_value)
    monkeypatch.setenv(BASE_VAR, "base.yaml")
    _write(layout["w"] / "base.yaml", "project_name: base\n")
    _write(layout["w"] / "other.yaml", "project_name: other\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "${" + KEY_VAR + "}: other.yaml\nextends: ${" + BASE_VAR + "}\n",
    )

    assert rac._extends_refs_shown(config) == [
        ("base.yaml", "${" + BASE_VAR + "}", True)
    ]
    with pytest.raises(rac.ContainerInputError) as refused:
        rac.operator_environment_names(str(config), None, layout["source"])
    message = str(refused.value)
    assert "Could not read the variables" in message, message
    assert "does not resolve with the values its environment references hold" in (
        message
    ), message
    assert KEY_VAR in message, message
    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))
    assert isinstance(refusal, str), refusal
    assert KEY_VAR in refusal, refusal


def test_an_empty_valued_key_spelling_a_name_the_container_sets_is_refused(
    layout, monkeypatch
):
    """The same key reference naming a variable the run command sets inside
    the container: the scan is refused the same way, before anything runs.
    The refusal is the chain's own, built without reading a value from the
    environment, and it names the not-passed variable too."""
    monkeypatch.setenv("ASH_OFFLINE", "")
    monkeypatch.setenv(BASE_VAR, "base.yaml")
    _write(layout["w"] / "base.yaml", "project_name: base\n")
    _write(layout["w"] / "other.yaml", "project_name: other\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "${ASH_OFFLINE}: other.yaml\nextends: ${" + BASE_VAR + "}\n",
    )

    with pytest.raises(rac.ContainerInputError) as refused:
        rac.operator_environment_names(str(config), None, layout["source"])
    message = str(refused.value)
    assert "Could not read the variables" in message, message
    assert "ASH_OFFLINE" in message, message
    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))
    assert isinstance(refusal, str), refusal
    assert "ASH_OFFLINE" in refusal, refusal


def test_an_unset_key_reference_with_a_default_reads_nothing_and_is_not_named(
    layout, monkeypatch
):
    """The control: a key reference whose variable is unset resolves from its
    written default, so the file read nothing from the environment, the chain
    loads, and only the written entry's variable is handed over."""
    monkeypatch.delenv(KEY_VAR, raising=False)
    monkeypatch.setenv(BASE_VAR, "base.yaml")
    _write(layout["w"] / "base.yaml", "project_name: base\n")
    _write(layout["w"] / "other.yaml", "project_name: other\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "${" + KEY_VAR + ":other}: other.yaml\nextends: ${" + BASE_VAR + "}\n",
    )

    names = rac.operator_environment_names(str(config), None, layout["source"])
    assert names == [BASE_VAR], names


def test_the_empty_valued_key_refusal_shows_no_value_the_chain_read(
    layout, monkeypatch, caplog
):
    """The must-not-flag side of the naming: the refusal names variables,
    never what they hold. Distinctive values planted in the two variables the
    chain does read (the base-naming entry and a value entry) appear neither
    in the exception's text nor in the run's records."""
    planted_base = "planted-base-name-7c0e4b91d2.yaml"
    planted_value = "planted-operator-value-3f8a61c7e5"
    monkeypatch.setenv(KEY_VAR, "  ")
    monkeypatch.setenv(BASE_VAR, planted_base)
    monkeypatch.setenv(OPERATOR_VAR, planted_value)
    _write(layout["w"] / planted_base, "project_name: base\n")
    _write(layout["w"] / "other.yaml", "project_name: other\n")
    config = _write(
        layout["w"] / "ash.yaml",
        "${" + KEY_VAR + "}: other.yaml\n"
        "project_name: ${" + OPERATOR_VAR + "}\n"
        "extends: ${" + BASE_VAR + "}\n",
    )

    with caplog.at_level(logging.WARNING, logger="ash"):
        with pytest.raises(rac.ContainerInputError) as refused:
            rac.operator_environment_names(str(config), None, layout["source"])

    message = str(refused.value)
    assert planted_base not in message, message
    assert planted_value not in message, message
    assert planted_base not in caplog.text, caplog.text
    assert planted_value not in caplog.text, caplog.text


def test_a_refused_entry_in_an_env_chosen_file_names_it_as_value(layout, monkeypatch):
    """The stock refusal of a chain entry that is no path, raised for a file
    the environment chose, names that file as the chain views name one: its
    path holds the variable's value, which no refusal prints."""
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )

    sub, config = _operator_config_extending_an_env_chosen_file(
        layout, monkeypatch, "extends: 7\n"
    )

    refusal = rac.container_input_refusal(layout["source"], layout["out"], str(config))

    assert isinstance(refusal, str), refusal
    assert ENVIRONMENT_VALUE_SHOWN in refusal, refusal
    assert sub not in refusal, refusal


def test_a_refused_entry_names_the_file_the_walk_gave(layout, monkeypatch):
    """The unit of the same rule: the stock refusal names the file as the
    caller shows it, so a walk that hands ``ENVIRONMENT_VALUE_SHOWN`` gets a
    refusal that holds it and not the path."""
    from automated_security_helper.config.environment_record import (
        ENVIRONMENT_VALUE_SHOWN,
    )
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    config = _write(layout["w"] / "chosen" / "mid.yaml", "extends: 7\n")

    with pytest.raises(ASHConfigSourceError) as raised:
        rac._extends_refs_shown(config, shown=ENVIRONMENT_VALUE_SHOWN)

    assert ENVIRONMENT_VALUE_SHOWN in str(raised.value), raised.value
    assert str(config) not in str(raised.value), raised.value


def test_a_tagged_entry_resolves_and_quotes_its_written_reference(layout, monkeypatch):
    """An explicit ``!ENV`` tag resolves like a plain reference, and the
    written form a message may quote is the reference without the tag."""
    monkeypatch.setenv(OPERATOR_VAR, "env_base.yaml")
    _write(layout["w"] / "env_base.yaml", "project_name: b\n")
    config = _write(layout["w"] / "ash.yaml", "extends: !ENV ${" + OPERATOR_VAR + "}\n")

    assert rac._extends_refs_shown(config) == [
        ("env_base.yaml", "${" + OPERATOR_VAR + "}", True)
    ]


def test_a_json_entry_spelling_the_tag_bytes_is_literal_text(layout, monkeypatch):
    """JSON has no tags: an entry whose text starts with the tag's bytes is a
    literal path spelling, followed and quoted as written, reading nothing."""
    monkeypatch.setenv(OPERATOR_VAR, "env_base.yaml")
    reference = "!ENV ${" + OPERATOR_VAR + "}"
    config = _write(
        layout["w"] / "ash.json",
        '{"project_name": "op", "extends": ["' + reference + '"]}',
    )

    assert rac._extends_refs_shown(config) == [(reference, reference, False)]


def test_a_quoted_yaml_entry_spelling_the_tag_bytes_is_literal_text(
    layout, monkeypatch
):
    """A quoted scalar keeps its text whole, the tag's bytes included: the
    entry is the file's own spelling, not a tag the loader read."""
    monkeypatch.setenv(OPERATOR_VAR, "env_base.yaml")
    reference = "!ENV ${" + OPERATOR_VAR + "}"
    config = _write(layout["w"] / "ash.yaml", 'extends:\n  - "' + reference + '"\n')

    assert rac._extends_refs_shown(config) == [(reference, reference, False)]


def test_a_streamed_line_hides_a_bare_long_plain_value_by_length():
    """The length floor alone hides a letters-and-digits value of the
    anywhere band's length: no punctuation earns it the band, and the floor
    reaches inside a longer word, where no word boundary could."""
    value = "k9Zq2xW4"

    out = rac._streamed_line(
        "prefix " + value + " suffix\n", (value,), scan_report=True
    )
    glued = rac._streamed_line(
        "prefix" + value + "suffix\n", (value,), scan_report=True
    )

    assert value not in out, out
    assert value not in glued, glued


def test_a_streamed_line_hides_a_short_secret_named_value_everywhere():
    """A value carried on the strict carrier has no bare-word exemption: a
    six-character token is hidden wherever the line holds it."""
    value = "k9Zq2x"

    out = rac._streamed_line(
        "prefix " + value + " suffix\n", (), (value,), scan_report=True
    )

    assert value not in out, out


def test_secret_shaped_names_are_split_to_the_strict_carrier(monkeypatch):
    """The run's carried values split by name shape: a secret-shaped name's
    value rides the strict carrier beside the plain one."""
    monkeypatch.setenv("ASH_HANDOFF_CELL_REPORT_TOKEN", "k9Zq2x")
    monkeypatch.setenv("ASH_HANDOFF_CELL_REPORT_REGION", "eu-west-1")

    all_values, strict = rac._carried_values_by_band(
        ["ASH_HANDOFF_CELL_REPORT_TOKEN", "ASH_HANDOFF_CELL_REPORT_REGION"]
    )

    assert set(all_values) == {"k9Zq2x", "eu-west-1"}, all_values
    assert strict == ("k9Zq2x",), strict


def test_a_stream_that_is_not_the_scan_report_keeps_the_strict_band():
    """The image build's stream has no report words to keep: every carried
    value keeps the strict band there."""
    out = rac._streamed_line("Severity: HIGH\n", ("HIGH",), scan_report=False)

    assert "HIGH" not in out, out


def test_a_streamed_line_without_the_scan_report_flag_keeps_the_strict_band():
    """A caller that forgets the flag gets the band the carrier defaults to,
    not the looser one: a bare short value is hidden."""
    out = rac._streamed_line("Severity: HIGH\n", ("HIGH",))

    assert "HIGH" not in out, out


@pytest.mark.parametrize(
    "name",
    [
        "ASH_REPORT_CREDENTIALS",
        "ASH_REPORT_SECRETS",
        "ASH_REPORT_KEYS",
        "ASH_REPORT_TOKENS",
        "ASH_REPORT_PASSWORDS",
        "ASH_DB_PASS",
        "ASH_DB_PASSWD",
        "ASH_DB_PWD",
        "ASH_REPORT_PAT",
        "ASH_REPORT_AUTH",
        "ASH_REPORT_PASSPHRASE",
        "ash_report_token",
    ],
)
def test_names_that_spell_a_secret_by_plural_or_abbreviation_are_strict(
    monkeypatch, name
):
    """A short value read from any of these names rides the strict carrier,
    so it never takes the bare-word exemption."""
    monkeypatch.setenv(name, "k9Zq2x")

    _, strict = rac._carried_values_by_band([name])

    assert strict == ("k9Zq2x",), strict


@pytest.mark.parametrize(
    "name", ["ASH_REPORT_REGION", "ASH_REPORT_PROFILE", "ASH_REPORT_BUCKET"]
)
def test_names_that_say_where_to_send_a_report_stay_loose(monkeypatch, name):
    """The must-not twin: a destination name is not secret-shaped."""
    monkeypatch.setenv(name, "eu-west-1")

    all_values, strict = rac._carried_values_by_band([name])

    assert all_values == ("eu-west-1",), all_values
    assert strict == (), strict


def test_the_build_stream_hides_a_bare_short_value(capsys):
    """The wiring: a stream run without ``scan_report_stream`` is not the
    scan's report, so a bare short carried value stays hidden in it."""
    import sys as _sys

    from automated_security_helper.utils import subprocess_utils

    with subprocess_utils._spawn_values(("HIGH",)):
        rac.run_cmd_direct(
            [_sys.executable, "-c", "print('Severity: HIGH')"], check=False
        )

    assert "HIGH" not in capsys.readouterr().out


def test_the_scan_report_stream_keeps_a_bare_short_value(capsys):
    """The twin: the scan's own report stream keeps the bare word. The scan
    run's spawn carrier marks it (``_spawn_values(scan_report=True)``)."""
    import sys as _sys

    from automated_security_helper.utils import subprocess_utils

    with subprocess_utils._spawn_values(("HIGH",), scan_report=True):
        rac.run_cmd_direct(
            [_sys.executable, "-c", "print('Severity: HIGH')"],
            check=False,
        )

    assert "Severity: HIGH" in capsys.readouterr().out


_MOUNT_FAILURE = "invalid mount config: source=/ops/HIGH/base.yaml"


def test_the_runtimes_stderr_hides_a_bare_short_value_in_the_scan_report_run(capsys):
    """The scan's run marks its stream as the report, but the runtime's own
    stderr is not the report: a mount failure can quote a carried value as a
    path segment, and the bare-word exemption does not reach it."""
    import sys as _sys

    from automated_security_helper.utils import subprocess_utils

    with subprocess_utils._spawn_values(("HIGH",), scan_report=True):
        rac.run_cmd_direct(
            [
                _sys.executable,
                "-c",
                f"import sys; print({_MOUNT_FAILURE!r}, file=sys.stderr)",
            ],
            check=False,
        )

    assert "HIGH" not in capsys.readouterr().err


def test_the_scan_report_run_keeps_the_same_bare_word_on_stdout(capsys):
    """The must-not twin: the same line on stdout is the report's own words
    and prints as the child wrote it."""
    import sys as _sys

    from automated_security_helper.utils import subprocess_utils

    with subprocess_utils._spawn_values(("HIGH",), scan_report=True):
        rac.run_cmd_direct(
            [_sys.executable, "-c", f"print({_MOUNT_FAILURE!r})"],
            check=False,
        )

    assert "/ops/HIGH/base.yaml" in capsys.readouterr().out


def test_the_stream_bands_follow_the_one_secret_name_rule(monkeypatch):
    """The names that take the strict band are the suffixes
    ``core.constants`` lists, read when the run's values are split: changing
    that list changes the split, so there is no second copy to drift."""
    from automated_security_helper.core import constants

    monkeypatch.setenv("ASH_ONE_RULE_CELL_TOKEN", "k9Zq2x")
    monkeypatch.setenv("ASH_ONE_RULE_CELL_ZZZ", "m4Wp8y")
    names = ["ASH_ONE_RULE_CELL_TOKEN", "ASH_ONE_RULE_CELL_ZZZ"]

    _, before = rac._carried_values_by_band(names)
    monkeypatch.setattr(constants, "SECRET_SHAPED_NAME_SUFFIXES", ("ZZZ",))
    _, after = rac._carried_values_by_band(names)

    assert before == ("k9Zq2x",), before
    assert after == ("m4Wp8y",), after


def test_no_name_a_config_may_read_by_allowlist_is_secret_shaped():
    """The allowlisted names say where to send a report, never what to
    authenticate with."""
    from automated_security_helper.core import constants

    for name in constants.ASH_CONFIG_ENV_VAR_ALLOWLIST:
        assert not constants.is_secret_shaped_environment_name(name), name


@pytest.mark.parametrize(
    "name",
    [
        "ASH_API_KEY",
        "ASH_X_DB_PASS",
        "ASH_API_TOKEN",
        "ASH_X_CREDENTIALS",
        "ash-report-token",
        "PASSWD",
        "ASH_PAT",
        "PWD",
        # A trailing qualifier does not hide the word.
        "ASH_API_KEY_PROD",
        "ASH_DB_PASSWORD_2",
        "ASH_TOKEN_STAGING",
        "ASH_TOKEN-STAGING",
        "ash_api_key_prod",
    ],
)
def test_a_secret_word_in_a_whole_segment_makes_a_name_secret_shaped(name):
    from automated_security_helper.core import constants

    assert constants.is_secret_shaped_environment_name(name), name


@pytest.mark.parametrize(
    "name",
    [
        # The exempt glued forms of PAT, PASS and PWD.
        "ASH_COMPAT",
        "ASH_BYPASS",
        "ASH_COMPASS",
        "OLDPWD",
        # Controls that no entry touches.
        "ASH_REPORT_REGION",
        "PROJECT_NAME",
        "",
        "_",
    ],
)
def test_a_denylisted_last_segment_or_an_unrelated_name_is_not_secret_shaped(
    name,
):
    from automated_security_helper.core import constants

    assert not constants.is_secret_shaped_environment_name(name), name


def test_a_multi_segment_entry_matches_only_as_a_contiguous_run(monkeypatch):
    """An entry spelled with a separator matches its segments in order and
    adjacent, anywhere in the name, and not with another segment between."""
    from automated_security_helper.core import constants

    monkeypatch.setattr(constants, "SECRET_SHAPED_NAME_SUFFIXES", ("SIGNING_KEY",))

    assert constants.is_secret_shaped_environment_name("ASH_SIGNING_KEY")
    assert constants.is_secret_shaped_environment_name("ASH_SIGNING_KEY_PROD")
    assert constants.is_secret_shaped_environment_name("ASH_SIGNING-KEY")
    assert not constants.is_secret_shaped_environment_name("ASH_SIGNING_X_KEY")
    assert not constants.is_secret_shaped_environment_name("ASH_KEY_SIGNING")


def test_a_qualified_secret_name_rides_the_strict_carrier(monkeypatch):
    """The streamed report's strict band follows the name rule end to end: a
    short value read from a name with a trailing qualifier is hidden as a whole
    word, and one read from a look-alike name is not held to the strict band."""
    monkeypatch.setenv("ASH_HANDOFF_CELL_API_KEY_PROD", "k9Zq2x")
    monkeypatch.setenv("ASH_HANDOFF_CELL_COMPAT", "true")

    _, strict = rac._carried_values_by_band(
        ["ASH_HANDOFF_CELL_API_KEY_PROD", "ASH_HANDOFF_CELL_COMPAT"]
    )

    assert strict == ("k9Zq2x",), strict


def _report_line_for(monkeypatch, name, value, line):
    """The streamed report's bytes for *line* with *name* set to *value*: the
    sink the masking rules land in, carried and split as the run carries its
    chain's values."""
    monkeypatch.setenv(name, value)
    all_values, strict = rac._carried_values_by_band([name])
    return rac._streamed_line(line, all_values, strict, scan_report=True)


@pytest.mark.parametrize(
    "name",
    [
        "ASH_API_KEY2",
        "ASH_DB_PASSWORD1",
        "ASH_TOKENPROD",
        "ASH_GITHUB_PATS",
        "ASH_SSH_PASSPHRASES",
    ],
)
def test_a_short_secret_from_a_qualified_or_plural_name_never_prints_in_the_report(
    monkeypatch, name
):
    """A digit-qualified, glued-qualified or plural secret name's short value
    never prints in the streamed report, bare or quoted: each of these names
    carries the same word as its plain spelling."""
    out = _report_line_for(
        monkeypatch, name, "k9Zq2x", "prefix k9Zq2x and 'k9Zq2x' suffix\n"
    )

    assert "k9Zq2x" not in out, (name, out)


@pytest.mark.parametrize(
    "name",
    ["ASH_REPORT_AUTHS", "ASH_GATE_PASSES", "ASH_DB_PASSWDS", "ASH_DB_PWDS"],
)
def test_a_plural_spelling_of_any_listed_suffix_rides_the_strict_band(
    monkeypatch, name
):
    """The remaining plurals: every listed word's plural spelling is strict,
    not only the five whose plural is its own entry of long standing."""
    out = _report_line_for(
        monkeypatch, name, "k9Zq2x", "prefix k9Zq2x and 'k9Zq2x' suffix\n"
    )

    assert "k9Zq2x" not in out, (name, out)


@pytest.mark.parametrize(
    "name, value, line",
    [
        ("ASH_PASS_THRESHOLD", "HIGH", "Severity: HIGH and threshold 'HIGH'\n"),
        ("ASH_AUTH_ENABLED", "true", "auth enabled: true and echoed 'true'\n"),
        (
            "ASH_MAX_TOKENS_PER_CALL",
            "1000",
            "total findings: 1000 and count '1000'\n",
        ),
    ],
)
def test_a_flag_or_limit_value_prints_bare_in_the_report_and_hides_only_quoted(
    monkeypatch, name, value, line
):
    """A name that only contains a secret word -- a flag or a limit named
    after it -- is not strict: its short common value keeps the report's
    bare-word exemption, so severity cells, boolean echoes and counts print
    as the scan wrote them, while the quoted echo stays hidden as for any
    carried value."""
    out = _report_line_for(monkeypatch, name, value, line)

    assert f": {value}" in out, (name, out)
    assert f"'{value}'" not in out, (name, out)


def test_a_qualified_secret_stays_hidden_beside_the_freed_flag_names(monkeypatch):
    """The must-flag pair bounding the exemption above: the qualifier
    protection holds (a qualified key name's short value is hidden) and a
    name that ends with the word is strict as before."""
    monkeypatch.setenv("ASH_PAIR_CELL_API_KEY_PROD", "k9Zq2x")
    monkeypatch.setenv("ASH_PAIR_CELL_AUTH", "m4Wp8y")

    all_values, strict = rac._carried_values_by_band(
        ["ASH_PAIR_CELL_API_KEY_PROD", "ASH_PAIR_CELL_AUTH"]
    )
    out = rac._streamed_line(
        "paired k9Zq2x and m4Wp8y\n", all_values, strict, scan_report=True
    )

    assert "k9Zq2x" not in out, out
    assert "m4Wp8y" not in out, out


@pytest.mark.parametrize(
    "name",
    ["ASH_BYPASSES", "ASH_COMPASSES", "ASH_COMPATS", "ASH_OLDPWDS", "ASH_BYPASS2"],
)
def test_a_denylisted_segments_plural_or_digit_spelling_stays_loose(monkeypatch, name):
    """The denylist interaction: the plural or digit-qualified spelling of a
    denylisted segment is no more secret-shaped than the segment itself, so
    its short common value keeps the report's bare-word exemption."""
    out = _report_line_for(monkeypatch, name, "HIGH", "Severity: HIGH\n")

    assert "Severity: HIGH" in out, (name, out)


#: The suffix list the matcher read before the segment rule, member for member.
_PLAIN_SUFFIXES = (
    "KEY",
    "KEYS",
    "TOKEN",
    "TOKENS",
    "SECRET",
    "SECRETS",
    "PASSWORD",
    "PASSWORDS",
    "CREDENTIAL",
    "CREDENTIALS",
    "PASS",
    "PASSWD",
    "PWD",
    "PAT",
    "AUTH",
    "PASSPHRASE",
)
_DENYLIST = ("COMPAT", "BYPASS", "COMPASS", "OLDPWD")


def test_the_suffix_list_still_holds_every_plain_suffix():
    from automated_security_helper.core import constants

    assert set(_PLAIN_SUFFIXES) <= set(constants.SECRET_SHAPED_NAME_SUFFIXES)
    assert set(constants.SECRET_SHAPED_FALSE_POSITIVE_SEGMENTS) == set(_DENYLIST)


@pytest.mark.parametrize("suffix", _PLAIN_SUFFIXES)
def test_every_plain_suffix_reads_strict_bare_separated_and_qualified(suffix):
    from automated_security_helper.core import constants

    strict = constants.is_secret_shaped_environment_name
    assert strict(suffix), suffix
    assert strict(f"MY_{suffix}"), suffix
    assert strict(f"{suffix}_PROD"), suffix
    assert strict(f"MY_{suffix}_2"), suffix
    assert strict(f"my_{suffix.lower()}_2"), suffix


@pytest.mark.parametrize("suffix", _PLAIN_SUFFIXES)
def test_every_plain_suffix_reads_strict_glued(suffix):
    from automated_security_helper.core import constants

    assert constants.is_secret_shaped_environment_name(f"MY{suffix}"), suffix


@pytest.mark.parametrize(
    "name",
    [
        "GITHUBTOKEN",
        "DBPASS",
        "GITHUBPAT",
        "MYPWD",
        "BYPASS_TOKEN",
        "MYCOMPASS_TOKEN",
        "COMPAT_PAT",
        "OLDPWD_PWD",
        "NPMTOKEN",
        "AWSSECRETACCESSKEY",
        "MYPASSWORD",
        "SLACKWEBHOOKSECRET",
        "MONKEY",
        "MYKEY",
        "GITHUBKEY",
        "OAUTH",
        "AWS_SECRET_ACCESS_KEY",
        "GITHUB_TOKEN",
        "DATABASE_PASSWORD",
        "MYSQL_PWD",
    ],
)
def test_a_glued_or_real_secret_name_is_secret_shaped(name):
    from automated_security_helper.core import constants

    assert constants.is_secret_shaped_environment_name(name), name


def test_the_denylisted_segments_are_the_only_names_the_plain_test_matched_and_this_does_not():
    """Over a corpus, every name a plain ends-with test over the plain suffix
    list matched and the matcher does not is listed here, and each one is a
    denylisted segment."""
    from automated_security_helper.core import constants

    corpus = [
        "GITHUBTOKEN",
        "NPMTOKEN",
        "AWSSECRETACCESSKEY",
        "MYPASSWORD",
        "SLACKWEBHOOKSECRET",
        "API_KEY_PROD",
        "DB_PASSWORD_2",
        "TOKEN_STAGING",
        "COMPAT",
        "BYPASS",
        "OLDPWD",
        "MONKEY",
        "COMPASS",
        "APIKEY",
        "MY_APIKEY",
        "SECRETKEY",
        "ACCESSKEY",
        "SSHKEY",
        "DBPASSWORD",
        "DBPASS",
        "CLIENTSECRET",
        "AUTHTOKEN",
        "APITOKEN",
        "ACCESSTOKEN",
        "PASSWD",
        "PASSPHRASE",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_ACCESS_KEY_ID",
        "GITHUB_TOKEN",
        "NPM_TOKEN",
        "DATABASE_PASSWORD",
        "ASH_API_TOKEN",
        "SLACK_WEBHOOK_SECRET",
        "STRIPE_API_KEY",
        "SSH_PRIVATE_KEY",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "TWINE_PASSWORD",
        "PGPASSWORD",
        "MYSQL_PWD",
        "OAUTH",
        "HOTKEY",
        "MYKEY",
        "GITHUBPAT",
        "PROJECT_NAME",
        "AWS_PROFILE",
        "AWS_REGION",
    ]

    def plain(name):
        return {w for w in _PLAIN_SUFFIXES if name.upper().endswith(w)}

    lost = [
        name
        for name in corpus
        if plain(name) and not constants.is_secret_shaped_environment_name(name)
    ]

    assert lost == ["COMPAT", "BYPASS", "OLDPWD", "COMPASS"], lost
    assert set(lost) == set(_DENYLIST)


def _standing_below_a_checkout_link(layout, monkeypatch):
    """The shell stands in ``repo/lnk/sub``, ``lnk`` a link the checkout holds to a
    directory outside it, with ``cfg.yaml`` beside that directory's ``sub``."""
    target = layout["w"] / "elsewhere" / "dir"
    (target / "sub").mkdir(parents=True)
    _write(target / "cfg.yaml", "project_name: p\n")
    (layout["repo"] / "lnk").symlink_to(target, target_is_directory=True)
    standing = layout["repo"] / "lnk" / "sub"
    monkeypatch.chdir(standing)
    return standing


def test_a_relative_name_is_judged_from_the_directory_the_shell_names(
    layout, monkeypatch
):
    """``../cfg.yaml`` from below a link the checkout holds reaches the file the
    link's target chose, so it is refused in the words for an ASH_CONFIG file
    that links out of the tree."""
    standing = _standing_below_a_checkout_link(layout, monkeypatch)
    monkeypatch.setenv("PWD", str(standing))

    with pytest.raises(rac.ContainerInputError, match="ASH_CONFIG file") as refused:
        rac._refuse_config_linked_out_of_the_tree(
            "../cfg.yaml", layout["source"], "ASH_CONFIG file"
        )

    assert "is inside the scanned tree but is a link" in str(refused.value)


def test_a_relative_name_is_judged_from_the_physical_directory_alone_without_pwd(
    layout, monkeypatch
):
    """The control: with ``$PWD`` unset only the physical walk runs, and that
    walk passes no link in the checkout, so the same name is accepted."""
    _standing_below_a_checkout_link(layout, monkeypatch)
    monkeypatch.delenv("PWD", raising=False)

    rac._refuse_config_linked_out_of_the_tree(
        "../cfg.yaml", layout["source"], "ASH_CONFIG file"
    )
