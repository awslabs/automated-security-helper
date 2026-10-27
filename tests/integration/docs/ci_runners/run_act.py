# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Starting nektos/act on a page's GitHub Actions workflow.

act runs every job on the host (``-P ubuntu-latest=-self-hosted``), so no image is
pulled and no container is given the Docker socket (``--container-daemon-socket -``
keeps it that way should a job ask for one). Host-mode jobs share one working
directory, so they run one at a time (``--concurrent-jobs 1``). The log is act's
``--json`` output, never its verbose one: the uploaded logs are public for a week.

The actions that write to GitHub (code scanning uploads, pull request comments, check
runs) are replaced with the composite actions under stubs/, through
``--local-repository <owner>/<repo>@<ref>=<stub>`` for every ref of them the fixture's
workflows use. The stubs record their inputs under the directory act passes them as
DOCTEST_STUB_RECORDS. act is given no token, and the repository name explicitly, since
the fixture's ``origin`` is a local bare repository act cannot read a name from.

A page's call to ASH's reusable workflows is rewritten to the pull request's own
workflow file (``uses: ./.github/workflows/<file>``), which ``copy_local_uses`` copies
into the fixture beside the pipeline.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable, Iterable, Mapping
from pathlib import Path, PurePosixPath
from typing import Any

from .env import launch, launch_env, run_in_new_session

ACT_TOOL = "tools.act"
MANIFEST_KEYS = (ACT_TOOL,)
STUBS_DIR = Path(__file__).resolve().parent / "stubs"
STUB_RECORDS_VARIABLE = "DOCTEST_STUB_RECORDS"

#: The actions that write to GitHub, and the stub directory that stands in for each.
#: A stub directory has the layout of the action's repository.
WRITER_ACTIONS = {
    "github/codeql-action": "codeql-action",
    "mshick/add-pr-comment": "add-pr-comment",
    "mikepenz/action-junit-report": "action-junit-report",
}

_USES = re.compile(
    r"uses:\s*['\"]?(?P<repo>[\w.-]+/[\w.-]+)(?P<path>/[^@\s'\"]*)?@(?P<ref>[^\s'\"#]+)"
)
_LOCAL_USES = re.compile(r"uses:\s*['\"]?(?P<path>\./[^\s'\"#]+)")


def writer_action_refs(texts: Iterable[str]) -> list[str]:
    """``<owner>/<repo>@<ref>`` of every writer action the texts use."""
    refs = {
        f"{match['repo']}@{match['ref']}"
        for text in texts
        for match in _USES.finditer(text)
        if match["repo"] in WRITER_ACTIONS
    }
    return sorted(refs)


def local_uses(text: str) -> list[str]:
    """The ``./`` paths a workflow's ``uses:`` lines name, in order."""
    seen: list[str] = []
    for match in _LOCAL_USES.finditer(text):
        path = match["path"]
        if path not in seen:
            seen.append(path)
    return seen


def copy_local_uses(text: str, *, source_root: Path, project: Path) -> list[Path]:
    """Copy every ``./`` workflow or action ``text`` uses, and theirs, into ``project``.

    The files come from ``source_root``, the checkout under test. A path already in
    the project (the pipeline itself) is left as it is.
    """
    copied: list[Path] = []
    queue = local_uses(text)
    done: set[str] = set()
    while queue:
        uses = queue.pop(0)
        relative = PurePosixPath(uses)
        if ".." in relative.parts:
            raise ValueError(f"uses: {uses} leaves the repository")
        key = relative.as_posix()
        if key in done:
            continue
        done.add(key)
        source = Path(source_root).joinpath(*relative.parts)
        target = Path(project).joinpath(*relative.parts)
        if target.exists():
            continue
        if source.is_dir():
            shutil.copytree(source, target, symlinks=False)
            texts = [
                p.read_text(encoding="utf-8")
                for p in sorted(target.rglob("action.y*ml"))
            ]
        elif source.is_file():
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            texts = [target.read_text(encoding="utf-8")]
        else:
            raise FileNotFoundError(f"uses: {uses} names nothing in {source_root}")
        copied.append(target)
        for more in texts:
            queue.extend(path for path in local_uses(more) if path not in done)
    return copied


def act_event(
    event_name: str, *, head_sha: str, base_sha: str, branch: str, repository: str
) -> dict[str, Any]:
    """The event payload act gives the workflow (``-e``)."""
    owner, _, name = repository.partition("/")
    repo = {
        "full_name": repository,
        "name": name,
        "owner": {"login": owner},
        "default_branch": "main",
    }
    if event_name == "pull_request":
        return {
            "action": "opened",
            "number": 1,
            "pull_request": {
                "number": 1,
                "head": {"sha": head_sha, "ref": branch, "repo": repo},
                "base": {"sha": base_sha, "ref": "main", "repo": repo},
            },
            "repository": repo,
        }
    if event_name == "push":
        return {
            "ref": f"refs/heads/{branch}",
            "before": "0" * 40,
            "after": head_sha,
            "repository": repo,
        }
    raise ValueError(
        f"the pages' workflows run on pull_request or push, not {event_name}"
    )


def act_argv(
    *,
    program: Path,
    event_name: str,
    workflow: Path,
    event_path: Path,
    project: Path,
    artifact_dir: Path,
    cache_dir: Path,
    stub_records: Path,
    writer_refs: Iterable[str],
    repository: str,
) -> list[str]:
    """The act command line for ``workflow``."""
    argv = [
        str(program),
        event_name,
        "-C",
        str(project),
        "-W",
        str(workflow),
        "-e",
        str(event_path),
        "-P",
        "ubuntu-latest=-self-hosted",
        "--concurrent-jobs",
        "1",
        "--json",
        "--container-daemon-socket",
        "-",
        "--artifact-server-path",
        str(artifact_dir),
        "--cache-server-path",
        str(cache_dir),
        "--env",
        f"{STUB_RECORDS_VARIABLE}={stub_records}",
        "--env",
        f"GITHUB_REPOSITORY={repository}",
        "--env",
        f"GITHUB_REPOSITORY_OWNER={repository.partition('/')[0]}",
    ]
    for ref in writer_refs:
        repo = ref.partition("@")[0]
        if repo not in WRITER_ACTIONS:
            raise ValueError(f"{ref} is not an action a stub stands in for")
        argv += ["--local-repository", f"{ref}={STUBS_DIR / WRITER_ACTIONS[repo]}"]
    return argv


def run_act(
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
    """Start act through env -i and return its exit code.

    act's steps may start containers with the docker CLI, which act cannot label, so
    the launch removes whatever containers appeared while it ran.
    """
    env = launch_env(
        "act", home=home, runner_bin=runner_bin, tool_cache=tool_cache, outer=outer
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
