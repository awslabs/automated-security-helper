# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What the docs say about floating major tags must stay true across a major bump.

Why this file exists
--------------------
Floating major tags are retired (#928). ``v3`` is frozen at v3.8.0 and no
floating tag is created for v4 or later, so a bare ``@vN`` ref never follows a
release. The docs say so: they name ``v3`` as the frozen tag, and the templates
say that a floating major tag "such as `vN`" is no longer updated, where N is the
major being released.

The hazard this file guards is the one that predates the retirement, in its new
form. A template that writes the current major as a literal renders the same at
any version, so the bump to the next major regenerates the pinned examples while
the floating-tag sentence goes on naming the old major. Before the retirement that
sentence recommended a stale tag; now it would state the retirement about the wrong
tag. Nothing fails on its own: the round-trip test in
``test_version_template_round_trip.py`` only compares a doc with its own template.

What this asserts
-----------------
1. Every template, rendered at the current version AND at the next major, names
   only that version's major (or the frozen one) in each floating-tag line.
   Rendering at the next major is what catches a literal major in a template.
2. Every committed Markdown doc (generated or not) names only the current major or
   the frozen one in each floating-tag line, so a hand-written doc that repeats
   the sentence is held to the same rule.

The frozen major is ``FROZEN_MAJOR`` (3). It is allowed because the retirement
text has to name it: "the `v3` tag is frozen at v3.8.0" is true at every later
version. Any other major on such a line fails, which is what keeps a literal
``v4`` from surviving into 5.0.0 and a stray ``v2`` from passing.

The major comes from ``[tool.commitizen] version`` in pyproject.toml, for the reason
recorded in ``test_version_template_round_trip.py``.

A "floating-tag line" is a line that mentions a floating tag (``floating tag``,
``floating major tag``), or names a major series (``v4.x``), or carries an ASH
install ref at a bare major (the repository's git URL followed by ``@v4`` with no
minor), or directly follows such a line: a sentence wraps, and the major often
lands on the line after the words "floating major tags such as". Within such a
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

pytestmark = pytest.mark.unit

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
_FLOATING_MENTION = re.compile(r"floating[- ](?:major[- ])?tags?\b", re.IGNORECASE)

# The major whose floating tag existed and is now frozen (at v3.8.0). The docs name
# it when they explain the retirement, so it is a legitimate major on a
# floating-tag line at every later version.
FROZEN_MAJOR = 3
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
    previous_was_floating = False
    for number, line in enumerate(text.splitlines(), start=1):
        mentions = bool(
            _FLOATING_MENTION.search(line)
            or _MAJOR_SERIES.search(line)
            or _BARE_MAJOR_INSTALL_REF.search(line)
        )
        in_scope = mentions or previous_was_floating
        # A blank line ends the sentence; only a wrapped continuation inherits.
        previous_was_floating = mentions if line.strip() else False
        if not in_scope:
            continue
        for token in _MAJOR_TOKENS:
            for match in token.finditer(line):
                found.append((number, int(match.group(1)), line.strip()))
    return found


def _wrong_majors(text: str, expected: int) -> list[str]:
    """Majors on floating-tag lines that are neither `expected` nor the frozen one."""
    return [
        f"  line {number}: names v{major}, expected v{expected} "
        f"(or the frozen v{FROZEN_MAJOR}): {line[:160]}"
        for number, major, line in floating_tag_majors(text)
        if major not in (expected, FROZEN_MAJOR)
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

    # The floors are the counts measured on the tree after the retirement (#928):
    # 5 templates (README, advanced-usage, platform-teams, install, the Streamlit
    # example README) and 7 committed docs (those five plus the releases page and
    # the FAQ, which carry the sentence with no template of their own to render).
    # Before the retirement the promise to "stay up to date" with the tag was
    # repeated on more pages, which is why the old floors were 8 and 9; the
    # deprecation note replaced those repeats and lives on fewer. A floor is only
    # worth having at the real count: lower, and a matcher that silently drops a
    # page still passes. A page that legitimately loses the note lowers its floor
    # here, in the same change, with its reason.
    def test_the_tip_is_found_in_several_templates(self):
        assert len(_templates_with_the_tip()) >= 5

    def test_the_tip_is_found_in_the_committed_docs(self):
        hits = [
            path
            for path in _tracked_docs()
            if floating_tag_majors((REPO_ROOT / path).read_text(encoding="utf-8"))
        ]
        assert len(hits) >= 7, hits

    def test_a_stale_major_is_reported(self):
        line = (
            "> **Floating tag `v2`**: use `@v2` to get the latest stable v2.x release."
        )
        assert len(_wrong_majors(line, 4)) == 3
        assert _wrong_majors(line, 2) == []

    def test_a_literal_current_major_fails_after_the_bump(self):
        # What the next-major render catches: a literal `v4` in a template renders
        # the same at 5.0.0, where it names a major that is neither current nor frozen.
        line = "Floating major tags such as `v4` are no longer updated."
        assert _wrong_majors(line, 4) == []
        assert len(_wrong_majors(line, 5)) == 1

    def test_the_frozen_major_is_allowed_on_a_floating_tag_line(self):
        line = "The `v3` floating tag is frozen at v3.8.0 and never moves."
        assert floating_tag_majors(line)
        assert _wrong_majors(line, 4) == []
        assert _wrong_majors(line, 7) == []

    def test_a_wrapped_sentence_keeps_its_floating_context(self):
        text = "Floating major tags such as\n`@v2` do not follow releases.\n"
        assert len(_wrong_majors(text, 4)) == 1

    def test_a_blank_line_ends_the_floating_context(self):
        text = (
            "Floating major tags are retired.\n\n`actions/checkout@v2` is unrelated.\n"
        )
        assert floating_tag_majors(text) == []

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
            "We maintain a `v2` Git tag that always points to the latest stable "
            "v2.x release. This means you can use `@v2` in your installation commands."
        )
        assert len(_wrong_majors(line, 4)) == 3
        assert _wrong_majors(line, 2) == []

    def test_a_bare_major_install_ref_is_a_floating_tag_line(self):
        text = f'alias ashx="uvx git+https://github.com/awslabs/{_REPO_NAME}.git@v2"'
        assert _wrong_majors(text, 4)
