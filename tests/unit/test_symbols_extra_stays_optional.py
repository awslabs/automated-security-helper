# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The [symbols] extra stays optional in every package that installs ASH's wheel.

[symbols] is tree-sitter and four grammar wheels. They are native, and
tree-sitter publishes no musllinux aarch64 wheel, so pyproject.toml carries them
as an extra rather than a core requirement: a plain install must not need a C
compiler. Without the extra a `symbol:` suppression matches nothing and the scan
says which extra is missing.

The .deb, .rpm, Flatpak, MSIX (and the winget manifest, which installs that MSIX),
Chocolatey, MCPB and the operator's e2e scanner image all install the bare wheel
or source tree, so they resolve the wheel's Requires-Dist with no extra. This file
pins both halves: the extra is not a core requirement, and each channel's install
line asks for no extra. Homebrew is pinned separately by
tests/unit/test_homebrew_formula_lock_sync.py, because its closure is computed from
uv.lock rather than written as an install line.

The ASH container image is the one channel that requests the extra on purpose
(Dockerfile: `[cdk,symbols]`). It is a Debian glibc image, so the wheels exist for
it, and shipping the extra there is what makes symbol suppressions work in
container mode. A separate test below pins that it keeps asking for it.

Each install line is located by a pattern that has to match, so a channel whose
install step moved or was rewritten fails here instead of passing because nothing
was checked.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]


def _requirement_name(requirement: str) -> str:
    match = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", requirement)
    assert match, requirement
    return re.sub(r"[-_.]+", "-", match.group(1)).lower()


def test_symbols_packages_are_not_core_requirements():
    project = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text("utf-8"))[
        "project"
    ]
    symbols = {
        _requirement_name(r) for r in project["optional-dependencies"]["symbols"]
    }
    core = {_requirement_name(r) for r in project["dependencies"]}

    assert "tree-sitter" in symbols, symbols
    assert not symbols & core, sorted(symbols & core)


# (file, pattern that finds the line installing ASH, pattern for the word that
# names ASH's wheel or source tree on that line, packages allowed after it).
# Each line pattern must match exactly one line.
INSTALL_LINES = [
    (
        "packaging/deb/debian/postinst",
        r'bin/pip" install .*"\$WHEEL"',
        r'"\$WHEEL"',
        set(),
    ),
    ("packaging/rpm/ash.spec", r'bin/pip" install .*"\$WHEEL"', r'"\$WHEEL"', set()),
    (
        "packaging/flatpak/ash-launcher.sh",
        r'-m pip install .*"\$WHEEL"',
        r'"\$WHEEL"',
        set(),
    ),
    (
        "packaging/chocolatey/tools/chocolateyinstall.ps1",
        r"-m pip install .*\$wheel$",
        r"\$wheel",
        set(),
    ),
    (
        "packaging/msix/AshLauncher.cs",
        r"-m pip install .*Quote\(wheel\)",
        r"Quote\(wheel\)",
        set(),
    ),
    (
        "ash-agent-plugins/agentic-coding/plugins/mcpb/manifest.json",
        r'"--from=git\+https://github\.com/awslabs/automated-security-helper@',
        r'"--from=[^"]*"',
        set(),
    ),
    # The operator's e2e image installs two scanners by name next to the source
    # tree; see the comment above that RUN line.
    (
        "deploy/kubernetes-operator/tests/e2e/Dockerfile.ash",
        r"pip install .* \. ",
        r" \. ",
        {"bandit", "detect-secrets"},
    ),
]

# What ends the install command after the wheel: a shell separator, or the end of
# a C# or JSON argument.
_COMMAND_END = re.compile(r";|&&|\|\||\||,")


def _logical_line(text: str, line: str) -> str:
    """``line`` with any backslash-continued lines that follow it joined on."""
    lines = text.splitlines()
    index = lines.index(line)
    joined = line
    while joined.endswith("\\") and index + 1 < len(lines):
        index += 1
        joined = joined[:-1] + " " + lines[index]
    return joined


def _packages_after_wheel(logical: str, wheel: str) -> list[str]:
    """The words between ASH's wheel and the end of the install command."""
    match = re.search(wheel, logical)
    assert match, f"{wheel!r} not on the install line {logical}"
    tail = _COMMAND_END.split(logical[match.end() :], maxsplit=1)[0]
    return [word for word in tail.split() if not word.startswith("-")]


@pytest.mark.parametrize(
    "relative,pattern,wheel,allowed",
    INSTALL_LINES,
    ids=[entry[0] for entry in INSTALL_LINES],
)
def test_channel_installs_without_the_symbols_extra(relative, pattern, wheel, allowed):
    text = (REPO_ROOT / relative).read_text("utf-8")
    lines = [line for line in text.splitlines() if re.search(pattern, line)]

    assert len(lines) == 1, (
        f"{relative}: expected one line matching {pattern!r}, found {lines}. "
        "If the install step moved, update INSTALL_LINES to find it."
    )
    line = lines[0]
    assert "symbols" not in line, f"{relative} requests the symbols extra: {line}"
    # An extra on the wheel or the source tree is spelled with brackets.
    assert "[" not in line, f"{relative} requests an extra: {line}"

    logical = _logical_line(text, line)
    # The extra's packages can also be named outright after the wheel.
    extra = [p for p in _packages_after_wheel(logical, wheel) if p not in allowed]
    assert not extra, f"{relative} installs more than ASH: {extra} in {logical}"


def test_mcpb_server_adds_no_packages_to_the_uvx_environment():
    """uvx takes extra packages as ``--with``, which no install line would show."""
    manifest = json.loads(
        (
            REPO_ROOT / "ash-agent-plugins/agentic-coding/plugins/mcpb/manifest.json"
        ).read_text("utf-8")
    )
    args = manifest["server"]["mcp_config"]["args"]

    assert args[0].startswith("--from=git+"), args
    assert not [a for a in args if a.startswith("--with")], args


def test_container_image_installs_the_cdk_and_symbols_extras():
    """The one channel that asks for [symbols]: dropping it would leave every
    ``symbol:`` suppression in container mode matching nothing."""
    text = (REPO_ROOT / "Dockerfile").read_text("utf-8")
    lines = [
        line
        for line in text.splitlines()
        if re.search(r"^RUN uv pip install --system .*\*\.whl", line)
    ]

    assert len(lines) == 1, lines
    match = re.search(r"\*\.whl\)\[([^\]]*)\]", lines[0])
    assert match, f"Dockerfile installs the wheel with no extras: {lines[0]}"
    extras = {extra.strip() for extra in match.group(1).split(",")}
    assert extras == {"cdk", "symbols"}, extras
