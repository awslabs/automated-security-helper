# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The floating-tag tip in the docs must name the project's own major version.

Why this file exists
--------------------
``.github/workflows/ash-tag-on-merge.yml`` moves a floating tag named after the
released major: ``v3`` follows 3.x, ``v4`` follows 4.x. The two tags coexist, so
``@v3`` keeps resolving after 4.0.0 ships and quietly installs the last 3.x release.

The docs tell users to "stay up to date automatically" with that tag. Before this
file existed, every template wrote the major as a literal, so the version bump to
4.0.0 regenerated the pinned ``@v4.0.0`` examples while the same sentence went on
recommending ``@v3`` as the way to get the latest release. Nothing failed: the
round-trip test in ``test_version_template_round_trip.py`` only compares a doc with
its own template, and both said ``v3``.

What this asserts
-----------------
1. Every template, rendered at the current version AND at the next major, names
   that version's major in each floating-tag line. Rendering at the next major is
   what catches a literal major in a template: a literal renders identically at
   any version, so a check at the current version alone passes until the bump.
2. Every committed Markdown doc (generated or not) names the current major in each
   floating-tag line, so a hand-written doc that repeats the tip is held to the
   same rule.

The major comes from ``[tool.commitizen] version`` in pyproject.toml, for the reason
recorded in ``test_version_template_round_trip.py``.

A "floating-tag line" is a line that mentions a floating tag, names a major series
(``v4.x``), or carries an ASH install ref at a bare major
(``automated-security-helper.git@v4`` with no minor). The series form is there
because a sentence can describe the tip without saying "floating tag" ("a `v4` Git
tag that always points to the latest stable v4.x release"). Within such a
line the majors read are `` `vN` ``, ``@vN`` (not followed by a dot or digit) and
``vN.x``. Pinned refs such as ``@v4.0.0`` and unrelated actions such as
``actions/checkout@v3`` are on other lines or do not match.
"""

from __future__ import annotations

import importlib.util
import re
import subprocess
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_template_manager.py"

# Docs that mention a floating tag for a reason other than recommending it.
#   CHANGELOG.md   -- release history; each entry is about the version it records.
#   DEVELOPMENT.md -- describes what ash-tag-on-merge does for any major, and names
#                     two majors on purpose ("`v3` for a 3.x release, `v4` for a 4.x").
_EXEMPT_DOCS = {"CHANGELOG.md", "DEVELOPMENT.md"}

_REPO_NAME = "automated-security-" + "helper"
_BARE_MAJOR_INSTALL_REF = re.compile(
    rf"{_REPO_NAME}(?:\.git)?@v\d+(?![\d.])", re.IGNORECASE
)
_FLOATING_MENTION = re.compile(r"floating[- ]tag", re.IGNORECASE)
_MAJOR_SERIES = re.compile(r"\bv\d+\.x\b")
_MAJOR_TOKENS = (
    re.compile(r"`v(\d+)`"),
    re.compile(r"@v(\d+)(?![\d.])"),
    re.compile(r"\bv(\d+)\.x\b"),
)


def _load_manager():
    spec = importlib.util.spec_from_file_location(
        "version_template_manager_floating", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.VersionTemplateManager(REPO_ROOT)


MANAGER = _load_manager()


def _project_version() -> str:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["tool"]["commitizen"]["version"]


def _major(version: str) -> int:
    return int(version.split(".", 1)[0])


def floating_tag_majors(text: str) -> list[tuple[int, int, str]]:
    """Return (line number, major, line) for every major named on a floating-tag line."""
    found = []
    for number, line in enumerate(text.splitlines(), start=1):
        if not (
            _FLOATING_MENTION.search(line)
            or _MAJOR_SERIES.search(line)
            or _BARE_MAJOR_INSTALL_REF.search(line)
        ):
            continue
        for token in _MAJOR_TOKENS:
            for match in token.finditer(line):
                found.append((number, int(match.group(1)), line.strip()))
    return found


def _wrong_majors(text: str, expected: int) -> list[str]:
    return [
        f"  line {number}: names v{major}, expected v{expected}: {line[:160]}"
        for number, major, line in floating_tag_majors(text)
        if major != expected
    ]


def _templates() -> list[str]:
    return [
        relative
        for relative in MANAGER.target_files
        if (REPO_ROOT / f"{relative}.template").is_file()
    ]


def _templates_with_the_tip() -> list[str]:
    return [
        relative
        for relative in _templates()
        if floating_tag_majors(
            (REPO_ROOT / f"{relative}.template").read_text(encoding="utf-8")
        )
        or "{{MAJOR_VERSION}}"
        in (REPO_ROOT / f"{relative}.template").read_text(encoding="utf-8")
    ]


def _tracked_docs() -> list[str]:
    listing = subprocess.run(
        ["git", "ls-files", "--", "*.md"],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.split()
    return sorted(path for path in listing if path not in _EXEMPT_DOCS)


class TestTemplatesDeriveTheFloatingMajor:
    @pytest.mark.parametrize("relative_path", _templates_with_the_tip())
    @pytest.mark.parametrize("bump", [0, 1], ids=["current-major", "next-major"])
    def test_rendered_tip_names_the_rendered_major(self, relative_path, bump):
        current = _project_version()
        version = current if bump == 0 else f"{_major(current) + 1}.0.0"
        template = (REPO_ROOT / f"{relative_path}.template").read_text(encoding="utf-8")
        rendered = MANAGER.render(template, version)

        assert floating_tag_majors(rendered), (
            f"{relative_path}.template rendered no floating-tag line to check"
        )
        wrong = _wrong_majors(rendered, _major(version))
        assert not wrong, (
            f"{relative_path}.template rendered at {version} recommends a floating tag "
            "for a different major. Write the major as {{MAJOR_VERSION}} in the "
            "template so the bump moves it:\n" + "\n".join(wrong)
        )


class TestCommittedDocsNameTheCurrentMajor:
    @pytest.mark.parametrize("relative_path", _tracked_docs())
    def test_floating_tag_lines_name_the_project_major(self, relative_path):
        text = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
        wrong = _wrong_majors(text, _major(_project_version()))
        assert not wrong, (
            f"{relative_path} recommends a floating tag that is not the project's "
            f"major (pyproject version {_project_version()}):\n" + "\n".join(wrong)
        )


class TestTheCheckCanFail:
    """Positive controls, so an empty census or a dead matcher cannot read as green."""

    def test_the_tip_is_found_in_several_templates(self):
        assert len(_templates_with_the_tip()) >= 8

    def test_the_tip_is_found_in_the_committed_docs(self):
        hits = [
            path
            for path in _tracked_docs()
            if floating_tag_majors((REPO_ROOT / path).read_text(encoding="utf-8"))
        ]
        assert len(hits) >= 9, hits

    def test_a_stale_major_is_reported(self):
        line = (
            "> **Floating tag `v3`**: use `@v3` to get the latest stable v3.x release."
        )
        assert len(_wrong_majors(line, 4)) == 3
        assert _wrong_majors(line, 3) == []

    # The repository name is interpolated in the fixtures below. The tree-wide pin
    # walk in test_agent_plugin_ash_version.py reads every tracked file as text and
    # would report a literal install ref here as a stale documented pin.
    def test_pinned_refs_and_unrelated_actions_are_ignored(self):
        text = (
            f"pip install git+https://github.com/awslabs/{_REPO_NAME}.git@v3.7.0\n"
            "      - uses: actions/checkout@v3\n"
        )
        assert floating_tag_majors(text) == []

    def test_a_major_series_is_a_floating_tag_line(self):
        line = (
            "We maintain a `v3` Git tag that always points to the latest stable "
            "v3.x release. This means you can use `@v3` in your installation commands."
        )
        assert len(_wrong_majors(line, 4)) == 3
        assert _wrong_majors(line, 3) == []

    def test_a_bare_major_install_ref_is_a_floating_tag_line(self):
        text = f'alias ashx="uvx git+https://github.com/awslabs/{_REPO_NAME}.git@v3"'
        assert _wrong_majors(text, 4)
