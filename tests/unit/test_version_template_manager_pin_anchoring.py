# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``convert`` templatizes the ``--branch v`` and ``rev: v`` pins of ASH and no one else's.

Why this file exists
--------------------
``find_version_references`` matched ``--branch v<version>`` and ``rev: v<version>``
anywhere in a page. A page that shows another project in the same example, such as a
pre-commit configuration that lists a second hook repository, or a clone of a third-party
repository, had that project's tag rewritten to ``{{VERSION}}``, and the next ``generate``
stamped ASH's release number into it. Only the ``git+`` pattern and the ``@v`` patterns
named this repository.

The two patterns now require this repository in the same command (``--branch``) or in the
``repo:`` line of the same pre-commit entry (``rev:``). The ``@v`` form was anchored by an
earlier change and is pinned in ``test_version_template_manager_at_pattern.py``.

The ``--branch`` patterns also end the repository name where the name ends: a sibling
repository whose name starts with this one's (``<name>-plugins.git``) is another project,
as the ``rev:`` pattern already required.

"The same command" ended only at a newline or a shell separator. In prose, a line holds
several inline code spans and links, so a link to this repository followed by a span with
another project's clone (or the reverse) was read as one command. A backtick, ``)`` or
``]`` now ends it as well.

What is asserted
----------------
``convert``, run in memory over example pages, rewrites the pin of this repository and
leaves every other project's pin as written: a ``rev:`` under another ``repo:``, a clone
of another URL before or after the flag, chained commands, prose that mentions this
repository and another project's clone on one line, and a repository name that only
begins with this one's.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_template_manager.py"
REPO = "automated-security-" + "helper"
ASH_URL = f"https://github.com/awslabs/{REPO}"
OTHER_URL = "https://github.com/example/other-project"


def _load_manager_class():
    spec = importlib.util.spec_from_file_location(
        "version_template_manager_pin_anchoring", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.VersionTemplateManager


VersionTemplateManager = _load_manager_class()


def _convert(text: str) -> str:
    """What convert_to_template writes, in memory."""
    manager = VersionTemplateManager(REPO_ROOT)
    for old_pattern, new_pattern in manager.find_version_references(text):
        text = re.sub(old_pattern, new_pattern, text)
    return text


class TestRevPins:
    def test_another_repository_s_pin_is_left_alone(self):
        text = (
            "repos:\n"
            "  - repo: https://github.com/example/pre-commit-hooks\n"
            "    rev: v4.6.0\n"
            "    hooks:\n"
            "      - id: check-yaml\n"
        )
        assert _convert(text) == text

    def test_ash_s_pin_is_templatized(self):
        """The control: the entry whose repo is this repository."""
        text = f"repos:\n  - repo: {ASH_URL}\n    rev: v3.4.0\n"
        assert _convert(text) == (
            f"repos:\n  - repo: {ASH_URL}\n    rev: v{{{{VERSION}}}}\n"
        )

    def test_a_comment_between_the_repo_and_its_pin_is_admitted(self):
        text = f"  - repo: {ASH_URL}.git\n    # pinned release\n\n    rev: v3.4.0\n"
        assert _convert(text) == (
            f"  - repo: {ASH_URL}.git\n    # pinned release\n\n    rev: v{{{{VERSION}}}}\n"
        )

    def test_only_ash_s_entry_changes_in_a_mixed_configuration(self):
        text = (
            "repos:\n"
            "  - repo: https://github.com/example/pre-commit-hooks\n"
            "    rev: v4.6.0\n"
            f"  - repo: {ASH_URL}\n"
            "    rev: v3.4.0\n"
            f"  - repo: {OTHER_URL}\n"
            "    rev: v1.2.3\n"
        )
        assert _convert(text) == (
            "repos:\n"
            "  - repo: https://github.com/example/pre-commit-hooks\n"
            "    rev: v4.6.0\n"
            f"  - repo: {ASH_URL}\n"
            "    rev: v{{VERSION}}\n"
            f"  - repo: {OTHER_URL}\n"
            "    rev: v1.2.3\n"
        )

    def test_the_match_does_not_reach_into_the_next_entry(self):
        """An ASH entry with no pin of its own must not claim the next entry's pin."""
        text = (
            f"  - repo: {ASH_URL}\n"
            "    hooks:\n"
            "      - id: ash-simple-scan\n"
            f"  - repo: {OTHER_URL}\n"
            "    rev: v1.2.3\n"
        )
        assert _convert(text) == text


class TestBranchPins:
    def test_another_repository_s_clone_is_left_alone(self):
        text = f"git clone --branch v1.2.3 {OTHER_URL}.git\n"
        assert _convert(text) == text

    def test_ash_s_clone_is_templatized_with_the_flag_first(self):
        text = f"git clone --depth 1 --branch v3.4.0 {ASH_URL}.git\n"
        assert _convert(text) == (
            f"git clone --depth 1 --branch v{{{{VERSION}}}} {ASH_URL}.git\n"
        )

    def test_ash_s_clone_is_templatized_with_the_url_first(self):
        text = f"git clone {ASH_URL}.git --branch v3.4.0\n"
        assert _convert(text) == (
            f"git clone {ASH_URL}.git --branch v{{{{VERSION}}}}\n"
        )

    def test_a_clone_split_over_escaped_lines_is_templatized(self):
        text = f"git clone \\\n  --branch v3.4.0 \\\n  {ASH_URL}.git\n"
        assert _convert(text) == (
            f"git clone \\\n  --branch v{{{{VERSION}}}} \\\n  {ASH_URL}.git\n"
        )

    def test_a_pin_in_one_command_does_not_borrow_the_next_command(self):
        """Another project's clone, chained to a clone of ASH, keeps its own tag."""
        text = f"git clone --branch v1.2.3 {OTHER_URL}.git && git clone {ASH_URL}.git\n"
        assert _convert(text) == text

    def test_a_pin_on_one_line_does_not_borrow_the_next_line(self):
        text = f"git clone --branch v1.2.3 {OTHER_URL}.git\ngit clone {ASH_URL}.git\n"
        assert _convert(text) == text

    @pytest.mark.parametrize(
        "text",
        [
            # A link to this repository, then a span with another project's clone.
            (
                f"Clone [ASH]({ASH_URL}), then the rules: "
                f"`git clone --branch v2.0.0 {OTHER_URL}.git`\n"
            ),
            # The same two mentions in the other order.
            (
                f"Run `git clone --branch v2.0.0 {OTHER_URL}.git`, then see "
                f"[ASH]({ASH_URL}).\n"
            ),
            # A repository in square brackets, then a span with another clone.
            f"See [{ASH_URL}] and `git clone --branch v2.0.0 {OTHER_URL}.git`\n",
            # Two code spans: this repository's clone, then another project's.
            (
                f"Clone `git clone {ASH_URL}.git` and "
                f"`git clone --branch v2.0.0 {OTHER_URL}.git`\n"
            ),
        ],
    )
    def test_prose_with_several_code_spans_on_a_line_keeps_the_other_tag(self, text):
        """Red before: the rest of the line counted as one command, so a link or a span
        naming this repository reached the next span's --branch."""
        assert _convert(text) == text

    def test_a_clone_in_a_code_span_is_still_templatized(self):
        """The control for the prose cases: this repository's own span converts."""
        text = f"Run `git clone --branch v3.4.0 {ASH_URL}.git` first.\n"
        assert _convert(text) == (
            f"Run `git clone --branch v{{{{VERSION}}}} {ASH_URL}.git` first.\n"
        )

    @pytest.mark.parametrize(
        "text",
        [
            f"git clone --branch v1.0.0 {ASH_URL}-plugins.git\n",
            f"git clone {ASH_URL}-plugins.git --branch v1.0.0\n",
            f"git clone --branch v1.0.0 {ASH_URL}.github.io\n",
        ],
    )
    def test_a_repository_that_only_starts_with_ash_s_name_is_left_alone(self, text):
        """Red before: the patterns had no right boundary after the name, so a sibling
        repository's tag was rewritten to the placeholder."""
        assert _convert(text) == text

    @pytest.mark.parametrize(
        "text, expected",
        [
            (
                f"git clone --branch v3.4.0 {ASH_URL}\n",
                f"git clone --branch v{{{{VERSION}}}} {ASH_URL}\n",
            ),
            (
                f"git clone {ASH_URL}/ --branch v3.4.0\n",
                f"git clone {ASH_URL}/ --branch v{{{{VERSION}}}}\n",
            ),
        ],
    )
    def test_a_url_without_a_git_suffix_is_still_templatized(self, text, expected):
        """The control for the boundary: the name ends the URL or a slash follows."""
        assert _convert(text) == expected
