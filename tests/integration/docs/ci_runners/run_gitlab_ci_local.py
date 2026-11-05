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

import contextlib
import os
import subprocess
import time
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path

from .env import (
    DOCKER_TIMEOUT,
    SYSTEM_PATH,
    launch,
    launch_argv,
    launch_env,
    run_in_new_session,
)

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
    cwd: Path | None = None,
) -> list[str]:
    """``gitlab-ci-local`` for the whole pipeline of ``project``.

    gitlab-ci-local 4.76.1 refuses an absolute ``--cwd`` ("Please use relative path for
    the --cwd option"; ``assert(!path.isAbsolute(cwd), ...)`` in src/argv.ts) and joins
    a relative one onto its own working directory. ``cwd`` is the directory the launch
    runs it in (``project`` when not given, which makes the option ``.``), so the option
    is ``project`` relative to that directory.
    """
    if event not in EVENTS:
        raise ValueError(f"GitLab has no {event} event; the events are {EVENTS}")
    argv = [
        str(program),
        "--cwd",
        os.path.relpath(project, cwd if cwd is not None else project),
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


#: What the identity recording keeps: the start of every container, and the pull, tag
#: and untag of every image. Separate from the workflow's pull recording, which the
#: image allowlist reads and this does not touch.
IDENTITY_EVENT_FILTERS = (
    "type=container",
    "type=image",
    "event=start",
    "event=pull",
    "event=tag",
    "event=untag",
)


def _docker_argv(home: Path, args: list[str]) -> list[str]:
    return launch_argv({"HOME": str(home), "PATH": SYSTEM_PATH}, ["docker", *args])


@contextlib.contextmanager
def record_identity_events(record: Path, *, home: Path) -> Iterator[int]:
    """Record container starts and image pulls, tags and untags into ``record``.

    ``docker events --since`` replays from the second ``since`` falls in, so a start
    that happens before the stream attaches is still recorded. Yields ``since`` in
    nanoseconds; the detector counts only events at or after it, so an event of the
    image build itself in that second is not read as a change made during the run.
    The stream ends when the block does.
    """
    since_ns = time.time_ns()
    argv = [
        "events",
        "--since",
        str(since_ns // 1_000_000_000),
        "--format",
        "{{json .}}",
    ]
    for name in IDENTITY_EVENT_FILTERS:
        argv += ["--filter", name]
    Path(record).parent.mkdir(parents=True, exist_ok=True)
    with Path(record).open("wb") as out:
        try:
            process = subprocess.Popen(
                _docker_argv(home, argv),
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=subprocess.DEVNULL,
                env={"PATH": SYSTEM_PATH},
                start_new_session=True,
            )
        except OSError:
            process = None
        try:
            yield since_ns
        finally:
            if process is not None:
                process.terminate()
                try:
                    process.wait(timeout=DOCKER_TIMEOUT)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()


def inspect_image_id(tag: str, *, home: Path) -> str | None:
    """The id ``docker image inspect`` gives ``tag`` now, None when it cannot say."""
    try:
        done = subprocess.run(
            _docker_argv(home, ["image", "inspect", tag, "--format", "{{.Id}}"]),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": SYSTEM_PATH},
            timeout=DOCKER_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = done.stdout.decode(errors="replace").strip()
    return text if done.returncode == 0 and text else None


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
