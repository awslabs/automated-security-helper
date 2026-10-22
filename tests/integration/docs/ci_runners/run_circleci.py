# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Starting the two CircleCI CLIs: v1.5.0 to check the config, v0.1.47860 to run it.

``circleci local execute`` is gone from the current CLI, so the job runs with
v0.1.47860, the last release that has it, while ``config validate`` and ``config
process`` run with v1.5.0. Each CLI checks for updates and sends telemetry unless told
not to, and each reads its own switches. On a hosted runner ``CI=true`` would turn
some of that off, but ``env -i`` drops it, and setting ``CI`` changes other behavior of
v1.5.0, so each CLI gets exactly its own switches and ``CI`` is never set. Every
command line also passes ``--skip-update-check``.

``local execute`` runs the build agent pinned in runners.toml (``--build-agent-version``
with its digest), mounts the wheel under test at /ash-wheel and a report directory at
/ash-reports: it discards the project directory when the job ends, so the rewrite's
last step copies the reports to that mount.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .env import launch, launch_env, run_in_new_session
from .manifest import image_digest, image_ref

LOCAL_EXECUTE_TOOL = "tools.circleci-cli-local-execute"
CONFIG_TOOL = "tools.circleci-cli"
PICARD_IMAGE = "images.circleci-picard"
JOB_IMAGE = "images.cimg-python-3-12-node"
MANIFEST_KEYS = (LOCAL_EXECUTE_TOOL, CONFIG_TOOL, PICARD_IMAGE, JOB_IMAGE)
WHEEL_MOUNT = "/ash-wheel"
REPORT_MOUNT = "/ash-reports"
CONFIG_PATH = ".circleci/config.yml"

#: Each CLI's own update-check and telemetry switches, read from its source at its tag.
SWITCHES = {
    "local-execute": {
        "CIRCLECI_CLI_TELEMETRY_OPTOUT": "1",
        "CIRCLECI_CLI_SKIP_UPDATE_CHECK": "true",
    },
    "config": {
        "CIRCLE_NO_TELEMETRY": "1",
        "DO_NOT_TRACK": "1",
        "CIRCLE_NO_UPDATE_CHECK": "1",
    },
}
CLI_TOOLS = {"local-execute": LOCAL_EXECUTE_TOOL, "config": CONFIG_TOOL}


def circleci_launch_env(
    cli: str,
    *,
    home: Path,
    runner_bin: Path,
    tool_cache: Path,
    outer: Mapping[str, str],
) -> dict[str, str]:
    """The environment ``cli`` (``local-execute`` or ``config``) starts in."""
    if cli not in SWITCHES:
        raise ValueError(f"no CircleCI CLI {cli!r}; the CLIs are {sorted(SWITCHES)}")
    env = launch_env(
        "circleci", home=home, runner_bin=runner_bin, tool_cache=tool_cache, outer=outer
    )
    env.update(SWITCHES[cli])
    return env


def circleci_config_argv(*, program: Path, command: str, config_path: str) -> list[str]:
    """``circleci config validate|process`` with the update check off."""
    if command not in ("validate", "process"):
        raise ValueError(f"{command!r} is not a config command this harness runs")
    return [str(program), "config", command, "--skip-update-check", config_path]


def circleci_local_execute_argv(
    manifest: Mapping[str, Any],
    *,
    program: Path,
    job: str,
    wheel_dir: Path,
    report_dir: Path,
    config_path: str = CONFIG_PATH,
) -> list[str]:
    """``circleci local execute <job>`` on the pinned build agent, with both mounts."""
    return [
        str(program),
        "local",
        "execute",
        job,
        "--skip-update-check",
        "--build-agent-version",
        image_digest(image_ref(manifest, PICARD_IMAGE)),
        "-c",
        config_path,
        "-v",
        f"{wheel_dir}:{WHEEL_MOUNT}",
        "-v",
        f"{report_dir}:{REPORT_MOUNT}",
    ]


def run_circleci(
    cli: str,
    argv: list[str],
    *,
    runner_bin: Path,
    cwd: Path,
    home: Path,
    tool_cache: Path,
    outer: Mapping[str, str],
    log: Path,
    run: Callable[..., subprocess.CompletedProcess] = run_in_new_session,
    timeout: float | None = None,
) -> int:
    """Start one CircleCI CLI command through env -i and return its exit code.

    ``local execute`` starts the build agent with ``docker run --rm`` and no label, and
    the agent starts the job's containers through the Docker socket, so the launch
    removes every container that appeared while it ran.
    """
    env = circleci_launch_env(
        cli, home=home, runner_bin=runner_bin, tool_cache=tool_cache, outer=outer
    )
    return launch(
        env,
        argv,
        cwd=cwd,
        log=log,
        run=run,
        timeout=timeout,
        remove_containers=True,
    )
