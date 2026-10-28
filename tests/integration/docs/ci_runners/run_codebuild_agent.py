# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Starting the AWS CodeBuild local agent with codebuild_build.sh.

The script starts the agent with ``docker run -it``, which needs a terminal, and a
workflow step has none, so it runs under util-linux's ``script``, which gives it one.
It is given the build image and the agent image by their pinned digests (``-i``,
``-l``), the fixture as its source (``-s``), and an artifact and a report directory
under the run's output directory (``-a``, ``-r``). It is never given ``-c``, which
passes the host's ``~/.aws`` and every ``AWS_*`` variable to the agent, nor ``-d``,
which runs the build container privileged; the pages' buildspec calls no AWS API.

codebuild_build.sh builds its ``docker run`` command line as one string and runs it
with ``eval``, so every value it is given is read as shell a second time. The paths
are therefore refused unless they hold only letters, digits and ``._/-``, and the
images unless they are digest references made of the same characters and ``:@``.
"""

from __future__ import annotations

import re
import shlex
import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from .env import launch, launch_env, run_in_new_session
from .manifest import image_ref

SCRIPT_TOOL = "tools.codebuild-build-sh"
AGENT_IMAGE = "images.codebuild-local-agent"
BUILD_IMAGE = "images.codebuild-standard-5"
MANIFEST_KEYS = (SCRIPT_TOOL, AGENT_IMAGE, BUILD_IMAGE)

#: What a path may hold and still mean the same after the script's eval.
EVAL_SAFE_PATH = re.compile(r"[A-Za-z0-9._/-]+")
#: A digest reference made of characters the script's eval reads as themselves.
EVAL_SAFE_DIGEST_REF = re.compile(r"[A-Za-z0-9._/:-]+@sha256:[0-9a-f]{64}")


def _eval_safe_path(name: str, path: Path) -> str:
    text = str(path)
    if not EVAL_SAFE_PATH.fullmatch(text):
        raise ValueError(
            f"{name} {text!r} holds a character codebuild_build.sh's eval would read "
            "as shell; only letters, digits and ._/- are passed to it"
        )
    return text


def _eval_safe_image(manifest: Mapping[str, Any], key: str) -> str:
    ref = image_ref(manifest, key)
    if not EVAL_SAFE_DIGEST_REF.fullmatch(ref):
        raise ValueError(
            f"{key} {ref!r} is not a plain digest reference; codebuild_build.sh's eval "
            "would read it as shell"
        )
    return ref


def codebuild_dirs(out_dir: Path) -> tuple[Path, Path]:
    """The artifact and the report directory the agent writes under ``out_dir``."""
    return Path(out_dir) / "codebuild-artifacts", Path(out_dir) / "codebuild-reports"


def codebuild_argv(
    manifest: Mapping[str, Any], *, script: Path, source: Path, out_dir: Path
) -> list[str]:
    """``script -q -e -c '<codebuild_build.sh ...>' /dev/null``.

    Raises ValueError, naming ``script``, ``source`` or ``out_dir``, for a path the
    script's eval would misread, and for an image that is not a plain digest reference.
    """
    artifacts, reports = codebuild_dirs(out_dir)
    command = shlex.join(
        [
            _eval_safe_path("script", script),
            "-i",
            _eval_safe_image(manifest, BUILD_IMAGE),
            "-a",
            _eval_safe_path("out_dir", artifacts),
            "-r",
            _eval_safe_path("out_dir", reports),
            "-s",
            _eval_safe_path("source", source),
            "-l",
            _eval_safe_image(manifest, AGENT_IMAGE),
        ]
    )
    return ["script", "-q", "-e", "-c", command, "/dev/null"]


def run_codebuild_agent(
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
    """Start the agent through env -i and return the exit code ``script`` passes on.

    codebuild_build.sh runs the agent with a plain ``docker run -it`` (no ``--rm``, no
    label), and the agent starts the build container through the Docker socket, so the
    launch removes every container that appeared while it ran.
    """
    env = launch_env(
        "codebuild-agent",
        home=home,
        runner_bin=runner_bin,
        tool_cache=tool_cache,
        outer=outer,
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
