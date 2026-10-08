# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Every step that needs a composite action's hand-off maps it into its own `env:`.

Why this file exists
--------------------
Three hand-offs used to go through GITHUB_ENV, which puts a value into every later
step of the caller's job:

* prepull-base-image's verified base image: ASH_BASE_OCI_LAYOUT on a cache hit,
  ASH_BASE_IMAGE_OVERRIDE when the fallback registry answered.
* tool-download-cache's directory, ASH_TOOL_DOWNLOAD_CACHE, plus the restore's hit
  flag carried to the save.
* The Actions cache credentials (ACTIONS_RUNTIME_TOKEN, ACTIONS_CACHE_URL,
  ACTIONS_RESULTS_URL) that ASH's buildx layer cache needs, exported by an
  actions/github-script step and written back empty by a revoke step afterwards.

zizmor's github-env audit reports a composite action that writes GITHUB_ENV, and
the token in particular was reachable by every step until the revoke ran. All
three are now step or action outputs, and each consumer maps them itself.

The argument prepull-base-image's header once made against outputs is the
failure this file exists to catch: every consumer is "a place to forget". A
forgotten mapping does not fail loudly. A build without ASH_BASE_OCI_LAYOUT asks
the registry for the base image (and on a cache hit the registry is blocked, so
that build fails late and confusingly), a build without the token silently skips
the layer cache, and a step without ASH_TOOL_DOWNLOAD_CACHE downloads everything
again. So the mappings are checked here, from the YAML, for every job and
composite action under .github/.

What it does not cover
----------------------
Which steps count as consumers is a text match on `run:` (see the patterns
below). A step that reaches an ASH build some other way, for example through a
script file, is not seen. The match errs toward including steps: mapping an
output into a step that does not need it costs nothing.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Iterator

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
GITHUB_DIR = REPO_ROOT / ".github"

PREPULL = "prepull-base-image"
TOOL_CACHE = "tool-download-cache"

# A step that builds ASH's image, or may: `ash build-image`, `ash --mode container`
# and `ash scan --mode container` (both rebuild by default), the PowerShell wrapper,
# and the bash wrapper `./ash`, which builds before it runs anything.
BUILD_RE = re.compile(r"build-image|--mode container|Invoke-ASH|(?<![\w/.-])\./ash\b")
# A step that runs ASH on the host, which may download pinned tool release assets.
ASH_RUN_RE = re.compile(r"(?<![\w./$-])ash\s|scripts/verify_\w+\.py")

TOKEN_NAMES = ("ACTIONS_RUNTIME_TOKEN", "ACTIONS_CACHE_URL", "ACTIONS_RESULTS_URL")


def _step_lists() -> Iterator[tuple[str, list[dict[str, Any]]]]:
    files = sorted(GITHUB_DIR.rglob("*.yml")) + sorted(GITHUB_DIR.rglob("*.yaml"))
    for path in files:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            continue
        rel = str(path.relative_to(REPO_ROOT))
        for name, job in (data.get("jobs") or {}).items():
            steps = (job or {}).get("steps") or []
            if steps:
                yield f"{rel} job {name}", steps
        steps = (data.get("runs") or {}).get("steps") or []
        if steps:
            yield rel, steps


def _uses(step: dict[str, Any], action: str) -> bool:
    return str(step.get("uses", "")).split("@", 1)[0].endswith(f"/actions/{action}")


def _label(step: dict[str, Any]) -> str:
    return str(step.get("name") or step.get("id") or step.get("uses") or "<step>")


def _maps(step: dict[str, Any], var: str, ids: list[str], output: str) -> bool:
    value = str((step.get("env") or {}).get(var, ""))
    return any(f"steps.{i}.outputs.{output}" in value for i in ids)


def _is_token_handoff(step: dict[str, Any]) -> bool:
    script = str((step.get("with") or {}).get("script", ""))
    return "ACTIONS_RUNTIME_TOKEN" in script and "setOutput" in script


def handoff_problems(where: str, steps: list[dict[str, Any]]) -> list[str]:
    """Every consumer in one step list that does not map a hand-off it needs."""
    problems: list[str] = []
    prepull_ids: list[str] = []
    tool_ids: list[str] = []
    token_ids: list[str] = []
    for step in steps:
        label = _label(step)
        run = str(step.get("run", ""))
        if _uses(step, PREPULL):
            if not step.get("id"):
                problems.append(f"{where}: {label!r} uses {PREPULL} without an id")
            else:
                prepull_ids.append(step["id"])
            continue
        if _uses(step, TOOL_CACHE):
            mode = str((step.get("with") or {}).get("mode", ""))
            if mode == "restore":
                if not step.get("id"):
                    problems.append(
                        f"{where}: {label!r} restores {TOOL_CACHE} without an id"
                    )
                else:
                    tool_ids.append(step["id"])
            elif mode == "save":
                hit = str((step.get("with") or {}).get("cache-hit", ""))
                if not any(f"steps.{i}.outputs.cache-hit" in hit for i in tool_ids):
                    problems.append(
                        f"{where}: {label!r} saves {TOOL_CACHE} without passing the "
                        "restore's cache-hit output"
                    )
            continue
        if _is_token_handoff(step):
            if not step.get("id"):
                problems.append(
                    f"{where}: {label!r} hands over the token without an id"
                )
            else:
                token_ids.append(step["id"])
            continue
        if not run:
            continue
        if BUILD_RE.search(run):
            if prepull_ids:
                for var, out in (
                    ("ASH_BASE_OCI_LAYOUT", "oci-layout"),
                    ("ASH_BASE_IMAGE_OVERRIDE", "base-image-override"),
                ):
                    if not _maps(step, var, prepull_ids, out):
                        problems.append(
                            f"{where}: {label!r} builds after {PREPULL} but does not "
                            f"map {var} from outputs.{out}"
                        )
            if token_ids:
                for var in TOKEN_NAMES:
                    if not _maps(step, var, token_ids, var):
                        problems.append(
                            f"{where}: {label!r} builds after the cache-credential "
                            f"hand-off but does not map {var}"
                        )
        if tool_ids and ASH_RUN_RE.search(run):
            if not _maps(step, "ASH_TOOL_DOWNLOAD_CACHE", tool_ids, "dir"):
                problems.append(
                    f"{where}: {label!r} runs ASH after the {TOOL_CACHE} restore but "
                    "does not map ASH_TOOL_DOWNLOAD_CACHE from outputs.dir"
                )
    return problems


def test_every_consumer_maps_its_handoff() -> None:
    problems = [
        p for where, steps in _step_lists() for p in handoff_problems(where, steps)
    ]
    assert not problems, "\n".join(problems)


def test_the_check_sees_the_handoffs_it_is_about() -> None:
    """Fails if the tree stops matching, so the test above cannot pass on nothing."""
    seen = {"prepull": 0, "tool": 0, "token": 0}
    for _, steps in _step_lists():
        for step in steps:
            seen["prepull"] += _uses(step, PREPULL)
            seen["tool"] += _uses(step, TOOL_CACHE)
            seen["token"] += _is_token_handoff(step)
    assert seen["prepull"] >= 5 and seen["tool"] >= 6 and seen["token"] >= 2, seen


def test_a_missing_mapping_is_reported() -> None:
    steps = [
        {
            "name": "creds",
            "id": "c",
            "uses": "actions/github-script@x",
            "with": {
                "script": "core.setSecret(v); core.setOutput('ACTIONS_RUNTIME_TOKEN', v)"
            },
        },
        {"name": "pull", "id": "p", "uses": "./.github/actions/prepull-base-image"},
        {
            "name": "tools",
            "id": "t",
            "uses": "./.github/actions/tool-download-cache",
            "with": {"mode": "restore"},
        },
        {"name": "build", "run": "ash build-image --no-run"},
        {"name": "install", "run": "ash dependencies install"},
        {
            "name": "save",
            "uses": "./.github/actions/tool-download-cache",
            "with": {"mode": "save"},
        },
    ]
    problems = "\n".join(handoff_problems("fixture", steps))
    for needle in (
        "ASH_BASE_OCI_LAYOUT",
        "ASH_BASE_IMAGE_OVERRIDE",
        "ACTIONS_RUNTIME_TOKEN",
        "'install' runs ASH",
        "cache-hit",
    ):
        assert needle in problems, (needle, problems)


def test_a_complete_mapping_is_accepted() -> None:
    steps = [
        {"name": "pull", "id": "p", "uses": "./.github/actions/prepull-base-image"},
        {
            "name": "build",
            "run": "./ash --build-target ci",
            "env": {
                "ASH_BASE_OCI_LAYOUT": "${{ steps.p.outputs.oci-layout }}",
                "ASH_BASE_IMAGE_OVERRIDE": "${{ steps.p.outputs.base-image-override }}",
            },
        },
    ]
    assert handoff_problems("fixture", steps) == []


def test_no_handoff_is_written_to_github_env_again() -> None:
    offenders = []
    pattern = re.compile(
        r"(ASH_BASE_OCI_LAYOUT|ASH_BASE_IMAGE_OVERRIDE|ASH_TOOL_DOWNLOAD_CACHE\w*)=[^\n]*GITHUB_ENV"
        r"|exportVariable\(\s*name"
    )
    for path in sorted(GITHUB_DIR.rglob("*")):
        if path.suffix in {".yml", ".yaml", ".sh"} and path.is_file():
            text = path.read_text(encoding="utf-8")
            if pattern.search(text):
                offenders.append(str(path.relative_to(REPO_ROOT)))
    assert not offenders, offenders
