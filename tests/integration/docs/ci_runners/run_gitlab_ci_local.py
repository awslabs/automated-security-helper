# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Starting gitlab-ci-local, and building the images its jobs use.

gitlab-ci-local runs each job with an ``image:`` in that image, and runs its own steps
in a job container (ownership of the build directory, copies of artifacts) in a helper
image. Its default helper is a ``:latest`` tag on Docker Hub, so the run builds its own,
doctest-gitlab-helper:local, from gitlab-helper/Dockerfile, whose base is a pinned
digest. Images are pulled only when missing (``--pull-policy if-not-present``), so the
image the run built for the own-image example is used as built, and the registry that
example names is never contacted.

The wheel under test is mounted read-only at /ash-wheel. A merge request event is
given the two variables the page's merge request rules and scan read; a push gets
gitlab-ci-local's defaults. GitLab has no pull request event.
"""

from __future__ import annotations

import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path

from .env import launch, launch_env, run_in_new_session

GITLAB_CI_LOCAL_TOOL = "tools.gitlab-ci-local"
JOB_IMAGE = "images.python-3-12"
HELPER_BASE_IMAGE = "images.debian-bookworm-slim"
MANIFEST_KEYS = (GITLAB_CI_LOCAL_TOOL, JOB_IMAGE, HELPER_BASE_IMAGE)
HELPER_IMAGE = "doctest-gitlab-helper:local"
HELPER_DOCKERFILE = Path(__file__).resolve().parent / "gitlab-helper" / "Dockerfile"
WHEEL_MOUNT = "/ash-wheel"
EVENTS = (None, "push", "merge_request")


def gitlab_ci_local_argv(
    *,
    program: Path,
    project: Path,
    wheel_dir: Path,
    event: str | None,
    base_sha: str,
) -> list[str]:
    """``gitlab-ci-local`` for the whole pipeline of ``project``."""
    if event not in EVENTS:
        raise ValueError(f"GitLab has no {event} event; the events are {EVENTS}")
    argv = [
        str(program),
        "--cwd",
        str(project),
        "--volume",
        f"{wheel_dir}:{WHEEL_MOUNT}:ro",
        "--helper-image",
        HELPER_IMAGE,
        "--pull-policy",
        "if-not-present",
    ]
    if event == "merge_request":
        argv += [
            "--variable",
            "CI_PIPELINE_SOURCE=merge_request_event",
            "--variable",
            f"CI_MERGE_REQUEST_DIFF_BASE_SHA={base_sha}",
        ]
    return argv


def helper_image_build_argv(dockerfile: Path = HELPER_DOCKERFILE) -> list[str]:
    """``docker build`` of the helper image."""
    return [
        "docker",
        "build",
        "-t",
        HELPER_IMAGE,
        "-f",
        str(dockerfile),
        str(Path(dockerfile).parent),
    ]


def run_gitlab_ci_local(
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
    """Start gitlab-ci-local through env -i and return its exit code.

    gitlab-ci-local has no option that labels the job and helper containers it starts,
    so the launch removes every container that appeared while it ran.
    """
    env = launch_env(
        "gitlab-ci-local",
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


def build_image(
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
    """Run a ``docker build`` for this leg through env -i and return its exit code.

    A build that is stopped can leave its build containers behind, so the launch
    removes every container that appeared while it ran.
    """
    if argv[:2] != ["docker", "build"]:
        raise ValueError(f"{argv[:2]} is not a docker build")
    env = launch_env(
        "gitlab-ci-local",
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
