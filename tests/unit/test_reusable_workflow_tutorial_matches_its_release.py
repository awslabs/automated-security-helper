# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The CI tutorial shows the reusable workflow's new inputs only for a release that has them.

Why this file exists
--------------------
docs/content/tutorials/running-ash-in-ci.md shows how to call
``.github/workflows/run-ash-security-scan.yml``, pinned to the release the page
documents (``@v{{VERSION}}`` in its template). The example uses ``config-ref``, and the
text around it describes the separate reporting job and the cache rules. None of that is
in v3.7.1 or earlier, and GitHub refuses a call that passes an input the called workflow
does not declare, so a copy of the example pinned to such a release never starts. The
docs publish on every push to main, before any release carries the inputs.

So the section is a conditional block of the template: ``scripts/version_template_manager.py``
renders it only when the documented version is after v3.7.1, and otherwise renders a
short note that names that release.

What this asserts
-----------------
1. The template manager's ``{{#after X.Y.Z}} ... {{else}} ... {{/after}}`` block: the
   first part for a later version, the second (or nothing) otherwise; prereleases of a
   later version count as later; a block left open, a nested block or a threshold that
   is not ``X.Y.Z`` is an error rather than text.
2. The tutorial rendered for v3.7.0 and v3.7.1 has no ``config-ref`` and says the inputs
   are in releases after v3.7.1; rendered for v3.7.2, v3.8.0 and v4.0.0 it has the
   example, pinned to that version, and every input the example passes is one this
   tree's run-ash-security-scan.yml declares.
3. The committed tutorial, whatever version it documents, follows the same rule.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest
import yaml

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_template_manager.py"
TUTORIAL = REPO_ROOT / "docs" / "content" / "tutorials" / "running-ash-in-ci.md"
TEMPLATE = TUTORIAL.with_name(TUTORIAL.name + ".template")
SCAN_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"
LAST_RELEASE_WITHOUT_THE_INPUTS = (3, 7, 1)


def _manager():
    spec = importlib.util.spec_from_file_location(
        "version_template_manager", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.VersionTemplateManager(REPO_ROOT)


def _render(text: str, version: str) -> str:
    return _manager().render(text, version)


def _packaged_version() -> str:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["tool"]["commitizen"]["version"]


def _release(version: str) -> tuple[int, int, int]:
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    assert match, version
    return tuple(int(part) for part in match.groups())


def _examples(doc: str) -> list[str]:
    """The YAML blocks that call run-ash-security-scan.yml."""
    blocks = re.findall(r"```yaml\n(.*?)```", doc, re.DOTALL)
    return [b for b in blocks if "run-ash-security-scan.yml@" in b]


def _uses_the_inputs(doc: str) -> bool:
    """Whether the doc passes config-ref or config-ref-missing anywhere (as a `with:` key)."""
    return re.search(r"^\s*config-ref(-missing)?:", doc, re.MULTILINE) is not None


def _example(doc: str) -> dict:
    """The YAML block that calls run-ash-security-scan.yml."""
    found = _examples(doc)
    assert len(found) == 1, (
        f"expected one example calling the workflow, found {len(found)}"
    )
    return yaml.safe_load(found[0])


class TestTheConditionalBlock:
    TEXT = "a\n{{#after 3.7.1}}\nnew\n{{else}}\nold\n{{/after}}\nz {{VERSION}}\n"

    @pytest.mark.parametrize(
        "version,expected",
        [
            ("3.7.0", "a\nold\nz 3.7.0\n"),
            ("3.7.1", "a\nold\nz 3.7.1\n"),
            ("3.7.2", "a\nnew\nz 3.7.2\n"),
            ("3.8.0", "a\nnew\nz 3.8.0\n"),
            ("4.0.0rc1", "a\nnew\nz 4.0.0rc1\n"),
        ],
    )
    def test_the_block_follows_the_version(self, version, expected):
        assert _render(self.TEXT, version) == expected

    def test_without_else_an_earlier_version_renders_nothing(self):
        text = "a\n{{#after 3.7.1}}\nnew\n{{/after}}\nz\n"
        assert _render(text, "3.7.0") == "a\nz\n"
        assert _render(text, "3.9.0") == "a\nnew\nz\n"

    @pytest.mark.parametrize(
        "text",
        [
            "a\n{{#after 3.7.1}}\nnew\n",
            "a\n{{/after}}\n",
            "{{#after 3.7.1}}\n{{#after 3.8.0}}\nx\n{{/after}}\n{{/after}}\n",
            "{{#after v3}}\nx\n{{/after}}\n",
            "{{else}}\n",
        ],
    )
    def test_a_malformed_block_is_an_error(self, text):
        with pytest.raises(ValueError):
            _render(text, "3.8.0")

    def test_a_version_that_is_not_x_y_z_is_an_error(self):
        with pytest.raises(ValueError):
            _render(self.TEXT, "main")

    # Each of these looks like a marker but is not exactly one. Read as text, it would
    # publish a marker on the page, or both branches, so each is an error.
    MALFORMED_MARKERS = [
        "{{else }}",
        "{{ else}}",
        "{{Else}}",
        "{{else}} more",
        "text {{else}}",
        "{{/after }}",
        "{{ /after}}",
        "{{/After}}",
        "{{/after}} more",
        "text {{/after}}",
        "{{/after 3.7.1}}",
        "{{/after}}{{/after}}",
    ]

    @pytest.mark.parametrize("marker", MALFORMED_MARKERS)
    def test_a_malformed_else_or_close_marker_is_an_error(self, marker):
        text = f"a\n{{{{#after 3.7.1}}}}\nnew\n{marker}\nold\n{{{{/after}}}}\nz\n"
        with pytest.raises(ValueError, match="malformed"):
            _render(text, "3.8.0")

    @pytest.mark.parametrize(
        "opening",
        [
            "{{#After 3.7.1}}",
            "{{ #after 3.7.1}}",
            "{{#after 3.7.1 }}",
            "{{#after  3.7.1}}",
            "{{#after 3.7.1}} more",
            "text {{#after 3.7.1}}",
            "{{#after 3.7.1junk}}",
            "{{#after 3.7}}",
            "{{#after 3.7.1.2}}",
            "{{#after 3.7.1rc1}}",
            "{{#after v3.7.1}}",
            "{{#after}}",
        ],
    )
    def test_a_malformed_opening_marker_is_an_error(self, opening):
        text = f"a\n{opening}\nnew\n{{{{/after}}}}\nz\n"
        with pytest.raises(ValueError):
            _render(text, "3.8.0")

    def test_a_second_else_in_one_block_is_an_error(self):
        text = "{{#after 3.7.1}}\nx\n{{else}}\ny\n{{else}}\nw\n{{/after}}\n"
        with pytest.raises(ValueError):
            _render(text, "3.8.0")

    @pytest.mark.parametrize(
        "version", ["3.8.0junk", "3.8", "3.8.0.1", "v3.8.0", " 3.8.0", "3.8.0\n"]
    )
    def test_with_a_block_the_whole_version_must_be_a_release(self, version):
        with pytest.raises(ValueError):
            _render(self.TEXT, version)

    @pytest.mark.parametrize(
        "version",
        ["3.8.0", "3.8.0rc1", "3.8.0a1", "3.8.0b2", "3.8.0.dev1", "3.8.0.post1"],
    )
    def test_a_release_or_prerelease_version_renders(self, version):
        assert _render(self.TEXT, version) == f"a\nnew\nz {version}\n"

    def test_without_a_block_any_version_only_fills_the_placeholder(self):
        assert _render("a {{VERSION}}\n", "main") == "a main\n"
        assert _render("plain\n", "not a version") == "plain\n"


class TestTheTutorialMatchesTheReleaseItDocuments:
    @pytest.mark.parametrize("version", ["3.7.0", "3.7.1"])
    def test_a_release_without_the_inputs_shows_no_example_using_them(self, version):
        doc = _render(TEMPLATE.read_text(encoding="utf-8"), version)
        assert not _examples(doc) and not _uses_the_inputs(doc), (
            f"the tutorial rendered for v{version} shows a call using config-ref, which "
            "that release's run-ash-security-scan.yml does not declare"
        )
        assert "after v3.7.1" in doc, "the note does not name the release that has them"

    @pytest.mark.parametrize("version", ["3.7.2", "3.8.0", "4.0.0"])
    def test_a_later_release_shows_the_example_pinned_to_it(self, version):
        doc = _render(TEMPLATE.read_text(encoding="utf-8"), version)
        example = _example(doc)
        (job,) = example["jobs"].values()
        assert job["uses"].endswith(f"run-ash-security-scan.yml@v{version}"), job[
            "uses"
        ]
        assert job["with"]["ash-version"] == f"v{version}"
        declared = set(
            yaml.safe_load(SCAN_WORKFLOW.read_text(encoding="utf-8")).get(
                "on",
                yaml.safe_load(SCAN_WORKFLOW.read_text(encoding="utf-8")).get(True),
            )["workflow_call"]["inputs"]
        )
        unknown = sorted(set(job["with"]) - declared)
        assert not unknown, (
            f"the example passes inputs the workflow does not declare: {unknown}"
        )
        assert "after v3.7.1" in doc, (
            "the section does not name the first release with them"
        )

    def test_the_committed_tutorial_follows_the_rule(self):
        version = _packaged_version()
        doc = TUTORIAL.read_text(encoding="utf-8")
        if _release(version) <= LAST_RELEASE_WITHOUT_THE_INPUTS:
            assert not _examples(doc) and not _uses_the_inputs(doc), (
                f"the published tutorial documents v{version}, which predates "
                "config-ref, and still shows it"
            )
        else:
            assert f"run-ash-security-scan.yml@v{version}" in doc
