# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every `ash dependencies install --tool <community scanner>` loads that scanner's module.

Why this exists
---------------
A community scanner (trivy-repo, snyk-code, ferret-scan, ...) is a plugin only once
its module is listed, so `ash dependencies install --tool trivy-repo` without the
module refuses the name and exits 2. Two CI steps once did exactly that for scanners
that were community plugins at the time, and nothing ran them before the change
reached CI. This reads every
`ash dependencies install` in the workflows, composite actions and Dockerfile and
fails if one names a community tool without loading its module, either through a
`--config` whose `ash_plugin_modules` lists it or a
`--config-overrides "ash_plugin_modules+=[...]"` that names it.
"""

import re
import shlex
from pathlib import Path

import pytest
import yaml

from automated_security_helper.core.community_scanners import community_module_for

REPO_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE_ARG = re.compile(r'^ARG (\w+)="([^"]*)"$', re.MULTILINE)


def _scripts():
    """(where, script text) for every run: block and the Dockerfile's RUN lines."""
    for path in sorted((REPO_ROOT / ".github").rglob("*.y*ml")):
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        steps = []
        for job in (doc.get("jobs") or {}).values():
            steps.extend((job or {}).get("steps") or [])
        steps.extend(((doc.get("runs") or {}).get("steps")) or [])
        for step in steps:
            run = (step or {}).get("run")
            if run:
                yield f"{path.relative_to(REPO_ROOT)}: {step.get('name')}", run
    dockerfile = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    args = dict(DOCKERFILE_ARG.findall(dockerfile))
    text = re.sub(
        r"\$\{(\w+)\}", lambda m: args.get(m.group(1), m.group(0)), dockerfile
    )
    yield "Dockerfile", text


def _install_commands(script: str):
    """Each `ash dependencies install ...` command, continuation lines joined."""
    joined = re.sub(r"\\\n\s*", " ", script)
    for line in joined.splitlines():
        if "ash dependencies install" in line:
            yield line[line.index("ash dependencies install") :]


def _config_modules(path: str) -> "set[str]":
    doc = yaml.safe_load((REPO_ROOT / path).read_text(encoding="utf-8")) or {}
    return set(doc.get("ash_plugin_modules") or [])


def problems_in(command: str) -> "list[str]":
    try:
        argv = shlex.split(command, comments=True)
    except ValueError:
        argv = command.split()
    tools, loaded = [], set()
    for flag, value in zip(argv, argv[1:]):
        if flag == "--tool":
            tools.append(value)
        elif flag in ("--config", "-c"):
            loaded |= _config_modules(value)
        elif flag == "--config-overrides":
            match = re.match(r"ash_plugin_modules\+?=\[(.*)\]$", value)
            if match:
                loaded |= {m.strip() for m in match.group(1).split(",") if m.strip()}
        elif flag == "--ash-plugin-modules":
            loaded.add(value)
    found = []
    for tool in tools:
        module = community_module_for(tool)
        if module and module not in loaded:
            found.append(f"--tool {tool} without {module}")
    return found


def test_every_community_tool_install_loads_its_module():
    problems = [
        f"{where}: {p}"
        for where, script in _scripts()
        for command in _install_commands(script)
        for p in problems_in(command)
    ]
    assert not problems, "\n".join(problems)


def test_the_scan_finds_the_installs_it_is_meant_to_check():
    """Control: the walk sees the CI install that names a community tool."""
    named = [
        command
        for _, script in _scripts()
        for command in _install_commands(script)
        if "--tool trivy-repo" in command
    ]
    assert named, "no CI install of a community tool found; the check is vacuous"


_TRIVY = "automated_security_helper.plugin_modules.ash_trivy_plugins"
_SNYK = "automated_security_helper.plugin_modules.ash_snyk_plugins"
_COMMUNITY = "--config .ash/.ash_community_plugins.yaml"


@pytest.mark.parametrize(
    "command,bad",
    [
        ("ash dependencies install --tool trivy-repo", True),
        ("ash dependencies install --tool gitleaks", False),
        (f"ash dependencies install {_COMMUNITY} --tool trivy-repo", False),
        (
            f'ash dependencies install --config-overrides "ash_plugin_modules+=[{_TRIVY}]" --tool trivy-repo',
            False,
        ),
        (
            f'ash dependencies install --config-overrides "ash_plugin_modules+=[{_SNYK}]" --tool trivy-repo',
            True,
        ),
    ],
)
def test_the_check_itself(command, bad):
    assert bool(problems_in(command)) is bad
