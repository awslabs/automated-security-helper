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

The anchoring covered only ``find_version_references``. The two readers of a built page's
pins, ``release_pins`` and ``forms_pinning_a_release`` (read by
``scripts/docs_versions.py check``), were built from the bare prefixes of
``INSTALL_REF_FORMS`` and still took another project's ``rev: v4.6.0``,
``--branch v2.0.0`` or ``actions/checkout@v4.1.2`` for a pin of this repository. A page
that keeps such a tag as ``convert`` leaves it then failed the check: on a release build
(``pins != wanted``), on the main build (a pin where none is allowed), and by requiring a
``rev: main`` command the page never had. All three now take their patterns from
``ASH_PIN_PATTERNS``.

What is asserted
----------------
``convert``, run in memory over example pages, rewrites the pin of this repository and
leaves every other project's pin as written: a ``rev:`` under another ``repo:``, a clone
of another URL before or after the flag, chained commands, prose that mentions this
repository and another project's clone on one line, and a repository name that only
begins with this one's. ``release_pins`` and ``forms_pinning_a_release`` read no pin from
the same texts, read this repository's pin in each form of ``INSTALL_REF_FORMS``, and
agree with ``convert`` on whether a text holds one.
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


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "version_template_manager_pin_anchoring", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MODULE = _load_module()
VersionTemplateManager = MODULE.VersionTemplateManager


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


#: Text that pins another project's release, in each form the readers look for.
OTHER_PROJECTS_PINS = {
    "a rev: under another repo": (
        "repos:\n"
        "  - repo: https://github.com/example/pre-commit-hooks\n"
        "    rev: v4.6.0\n"
    ),
    "a clone of another project": f"git clone --branch v2.0.0 {OTHER_URL}.git\n",
    "a third-party action": "      - uses: actions/checkout@v4.1.2\n",
    "an action whose name ends with this repository's": (
        f"      - uses: example/fork-{REPO}@v1.0.0\n"
    ),
    "a package whose name has a dot before this repository's": (
        f"      - uses: example/my.{REPO}@v1.0.0\n"
    ),
    "another project's action, shortened with an ellipsis": (
        "      - uses: actions/...@v4.1.2\n"
    ),
    "another organization's workflow, shortened with an ellipsis": (
        "      uses: some-org/...@v2.0.0\n"
    ),
    "another project's reusable workflow": (
        "      uses: example/other-project/.github/workflows/x.yml@v1.0.0\n"
    ),
    "another project's tag lookup": f"git ls-remote {OTHER_URL} refs/tags/v1.0.0\n",
    "a sibling of this repository": f"git clone --branch v1.0.0 {ASH_URL}-plugins.git\n",
    "prose naming this repository and cloning another": (
        f"Clone [ASH]({ASH_URL}), then the rules: "
        f"`git clone --branch v2.0.0 {OTHER_URL}.git`\n"
    ),
}

#: This repository's pin in each form of INSTALL_REF_FORMS, and the form's name.
ASH_PINS = {
    "@ (git URL, uses:)": f"uv tool install git+{ASH_URL}.git@v3.4.0\n",
    "--branch": f"git clone --branch v3.4.0 {ASH_URL}.git\n",
    "rev:": f"repos:\n  - repo: {ASH_URL}\n    rev: v3.4.0\n",
    "refs/tags/ (git ls-remote)": f"git ls-remote {ASH_URL} refs/tags/v3.4.0\n",
    "flake ref": f"nix run github:awslabs/{REPO}/v3.4.0\n",
    "--ash-revision-to-install": "ash build-image --ash-revision-to-install v3.4.0\n",
    "ash-version:": "with:\n  ash-version: v3.4.0\n",
}


class TestTheReadersOfAPageSeeOnlyAshPins:
    """release_pins and forms_pinning_a_release read what `convert` templatizes.

    scripts/docs_versions.py check requires every release pin on a built page to be the
    release's own and the main version's install commands to pin none. A page that keeps
    another project's tag as written, as `convert` rightly leaves it, failed that check
    when the readers took the bare prefixes (`--branch `, `rev: `, `@`) for ASH's.
    """

    @pytest.mark.parametrize(
        "text", list(OTHER_PROJECTS_PINS.values()), ids=list(OTHER_PROJECTS_PINS)
    )
    def test_another_project_s_pin_is_not_a_release_pin(self, text):
        """Red before: each prefix alone matched, so the tag was read as ASH's."""
        manager = VersionTemplateManager(REPO_ROOT)
        assert manager.release_pins(text) == set()
        assert manager.forms_pinning_a_release(text) == []

    @pytest.mark.parametrize("form, text", list(ASH_PINS.items()), ids=list(ASH_PINS))
    def test_ash_s_pin_is_read_in_every_form(self, form, text):
        """The control: each form's own pin is still read, and only as that form."""
        manager = VersionTemplateManager(REPO_ROOT)
        assert manager.release_pins(text) == {"3.4.0"}
        assert manager.forms_pinning_a_release(text) == [form]

    def test_only_ash_s_entry_of_a_mixed_configuration_is_read(self):
        text = (
            "repos:\n"
            "  - repo: https://github.com/example/pre-commit-hooks\n"
            "    rev: v4.6.0\n"
            f"  - repo: {ASH_URL}\n"
            "    rev: v3.4.0\n"
            f"  - repo: {OTHER_URL}\n"
            "    rev: v1.2.3\n"
        )
        manager = VersionTemplateManager(REPO_ROOT)
        assert manager.release_pins(text) == {"3.4.0"}
        assert manager.forms_pinning_a_release(text) == ["rev:"]

    def test_the_forms_come_back_in_the_order_the_manager_lists_them(self):
        text = ASH_PINS["rev:"] + ASH_PINS["--branch"]
        assert VersionTemplateManager(REPO_ROOT).forms_pinning_a_release(text) == [
            "--branch",
            "rev:",
        ]

    @pytest.mark.parametrize(
        "text",
        [
            *OTHER_PROJECTS_PINS.values(),
            *ASH_PINS.values(),
            f"uses: awslabs/{REPO}/.github/workflows/run.yml@v3.4.0\n",
            "Pin (`@v3.4.0`) for repeatable installs\n",
            "- `uses: ...@v3.4.0` selects the workflow file\n",
            f"Run `git clone --branch v3.4.0 {ASH_URL}.git` first.\n",
        ],
    )
    def test_a_text_is_converted_exactly_when_it_holds_a_release_pin(self, text):
        """The two readers and `convert` share one definition of an ASH pin, in every
        form of INSTALL_REF_FORMS."""
        converted = _convert(text) != text
        assert converted == bool(VersionTemplateManager(REPO_ROOT).release_pins(text))

    @pytest.mark.parametrize("form, text", list(ASH_PINS.items()), ids=list(ASH_PINS))
    def test_convert_templatizes_a_pin_in_every_form(self, form, text):
        """Red before: convert had no pattern for the refs/tags/, build-flag and
        action-input forms, so it wrote the stale literal into the template while
        the reader of a built page counted it as a pin."""
        converted = _convert(text)
        assert "3.4.0" not in converted, converted
        assert "{{VERSION}}" in converted, converted

    @pytest.mark.parametrize(
        "text",
        [
            f"      - uses: awslabs/{REPO}@v3.4.0\n",
            f"      - uses: {REPO}@v3.4.0\n",
            f"      uses: awslabs/{REPO}/.github/workflows/run.yml@v3.4.0\n",
            f"uvx --from=git+{ASH_URL}@v3.4.0 ash\n",
        ],
    )
    def test_the_action_and_workflow_forms_are_still_ash_s_pin(self, text):
        """The control for the left boundary of the repository name in the `@` form."""
        manager = VersionTemplateManager(REPO_ROOT)
        assert manager.release_pins(text) == {"3.4.0"}
        assert manager.unrecognized_pins(text) == []
        assert "3.4.0" not in _convert(text)

    def test_the_ellipsis_form_is_ash_s_pin(self):
        """Red before: the bare form refuses a `@` after a dot, so the page's prose
        `uses: ...@v<version>` was no pin to the anchored readers (the old readers
        counted it, and the check lost it)."""
        text = "- `uses: ...@v3.4.0` selects the workflow file\n"
        manager = VersionTemplateManager(REPO_ROOT)
        assert manager.release_pins(text) == {"3.4.0"}
        assert manager.unrecognized_pins(text) == []
        assert (
            _convert(text) == "- `uses: ...@v{{VERSION}}` selects the workflow file\n"
        )

    @pytest.mark.parametrize(
        "form, text",
        [
            ("rev:", f"- rev: v3.3.0\n  repo: {ASH_URL}\n"),
            ("rev:", f"- {{repo: {ASH_URL}, rev: v3.3.0}}\n"),
            ("--branch", 'git clone --branch v3.3.0 "$ASH_REPO_URL"\n'),
            # Spellings the anchored patterns do not read either: the safety net has to
            # search for the loose forms, or these pass silently.
            ("rev:", f"- {{repo: {ASH_URL}, rev:  v3.3.0}}\n"),
            ("rev:", f"- {{repo: {ASH_URL}, rev:\tv3.3.0}}\n"),
            ("--branch", 'git clone --branch=v3.3.0 "$ASH_REPO_URL"\n'),
            ("--branch", 'git clone -b v3.3.0 "$ASH_REPO_URL"\n'),
            # A run of blanks after the flag, as after `rev:` above: red at the base,
            # where the net took exactly one blank and these were never listed.
            ("--branch", 'git clone --branch  v3.3.0 "$ASH_REPO_URL"\n'),
            ("--branch", 'git clone --branch\tv3.3.0 "$ASH_REPO_URL"\n'),
            ("--branch", 'git clone -b  v3.3.0 "$ASH_REPO_URL"\n'),
        ],
        ids=[
            "rev-before-repo",
            "flow-style",
            "url-in-a-variable",
            "rev-two-spaces",
            "rev-tab",
            "branch-equals",
            "short-flag",
            "branch-two-spaces",
            "branch-tab",
            "short-flag-two-spaces",
        ],
    )
    def test_a_pin_in_a_shape_no_anchor_knows_is_listed_not_dropped(self, form, text):
        """Red before: the readers counted only the anchored shapes, so a pin of this
        repository written one of these ways was invisible to every check."""
        manager = VersionTemplateManager(REPO_ROOT)
        assert manager.release_pins(text) == set()
        found = manager.unrecognized_pins(text)
        assert [(pin.form, pin.version) for pin in found] == [(form, "3.3.0")]
        assert _convert(text) == text  # convert misses it too: the gap is real

    @pytest.mark.parametrize("text", list(ASH_PINS.values()))
    def test_a_recognized_pin_is_not_listed_as_unrecognized(self, text):
        assert VersionTemplateManager(REPO_ROOT).unrecognized_pins(text) == []

    def test_the_loose_search_does_not_list_what_an_anchor_accepts(self):
        """The control for the loose prefixes: a block-style entry with extra blanks
        after `rev:` is an anchored pin, so it is counted and not listed; and a key that
        only ends in `rev:` is no pin."""
        manager = VersionTemplateManager(REPO_ROOT)
        block = f"  - repo: {ASH_URL}\n    rev:  v3.3.0\n"
        assert manager.release_pins(block) == {"3.3.0"}
        assert manager.unrecognized_pins(block) == []
        assert manager.unrecognized_pins("prev: v3.3.0\nweb-b v3.3.0\n") == []
        # The wider gap after a flag does not widen the net past the flag's own name.
        assert manager.unrecognized_pins("web-b  v3.3.0\nxbranch  v3.3.0\n") == []

    @pytest.mark.parametrize(
        "text", list(OTHER_PROJECTS_PINS.values()), ids=list(OTHER_PROJECTS_PINS)
    )
    def test_another_project_s_pin_is_listed_for_an_explicit_allowance(self, text):
        found = VersionTemplateManager(REPO_ROOT).unrecognized_pins(text)
        assert len(found) == 1, found
        assert found[0].line in text
        # The entry is the command around the pin, cut at the separators of a chain, so
        # it need not hold the whole line; it holds the pin.
        assert f"v{found[0].version}" in found[0].entry

    @pytest.mark.parametrize(
        "text, entry",
        [
            # A block-style entry: the pin's line comes with the repo: line above it.
            (
                (
                    f"repos:\n  - repo: {OTHER_URL}\n    rev: v4.6.0\n    hooks:\n"
                    "      - id: x\n  - repo: https://github.com/example/next\n"
                    "    rev: v1.0.0\n"
                ),
                f"  - repo: {OTHER_URL}\n    rev: v4.6.0\n    hooks:\n      - id: x",
            ),
            # A rev: written first: the entry runs down to its repo: line.
            (
                f"- rev: v4.6.0\n  repo: {OTHER_URL}\n- repo: https://github.com/e/n\n",
                f"- rev: v4.6.0\n  repo: {OTHER_URL}",
            ),
            # A clone continued with backslashes is one command.
            (
                f"echo hi\ngit clone \\\n  --branch v2.0.0 \\\n  {OTHER_URL}.git\n",
                f"git clone \\\n  --branch v2.0.0 \\\n  {OTHER_URL}.git",
            ),
            # Prose stays one line, cut at the code span that holds the command.
            (
                f"Intro line.\nRun `git clone --branch v2.0.0 {OTHER_URL}.git`.\nOutro.\n",
                f"git clone --branch v2.0.0 {OTHER_URL}.git",
            ),
            # A chain of commands is cut at its separators: the pin is in the second
            # clone, so the first clone's project is not in its entry. Red at the base,
            # where the entry was both lines.
            (
                f'git clone {OTHER_URL}.git && \\\n  git clone --branch v3.3.0 "$X"\n',
                ' \\\n  git clone --branch v3.3.0 "$X"',
            ),
            # The pin comes first: the entry ends at the separator after it.
            (
                f'git clone --branch v3.3.0 "$X" && \\\n  git clone {OTHER_URL}.git\n',
                'git clone --branch v3.3.0 "$X" ',
            ),
            # The same on one line, and with a semicolon.
            (
                f'git clone {OTHER_URL}.git; git clone --branch v3.3.0 "$X"\n',
                ' git clone --branch v3.3.0 "$X"',
            ),
            # A rev: written after a list nested under a sibling key: the entry still
            # runs up to its repo: line. Red at the base, where the walk stopped at the
            # nested `- id:` line and returned the rev: line alone.
            (
                (
                    f"  - repo: {OTHER_URL}\n    hooks:\n      - id: x\n"
                    "    rev: v4.6.0\n  - repo: https://github.com/e/n\n"
                ),
                f"  - repo: {OTHER_URL}\n    hooks:\n      - id: x\n    rev: v4.6.0",
            ),
        ],
        ids=[
            "block",
            "rev-first",
            "continued",
            "prose",
            "below-a-nested-item",
            "chained-pin-last",
            "chained-pin-first",
            "chained-on-one-line",
        ],
    )
    def test_the_entry_around_a_listed_pin_is_the_whole_entry_or_command(
        self, text, entry
    ):
        """Red before: only the physical line was returned, so an allowance could not
        name the project that sits on the repo: line or in the continued URL."""
        found = VersionTemplateManager(REPO_ROOT).unrecognized_pins(text)
        assert found[0].entry == entry, found

    def test_every_form_has_patterns_with_one_group(self):
        """A form added to INSTALL_REF_FORMS needs its ASH anchor in ASH_PIN_PATTERNS."""
        forms = [name for name, *_ in MODULE.INSTALL_REF_FORMS]
        assert sorted(MODULE.ASH_PIN_PATTERNS) == sorted(forms)
        for patterns in MODULE.ASH_PIN_PATTERNS.values():
            for pattern in patterns:
                assert re.compile(pattern).groups == 1, pattern
