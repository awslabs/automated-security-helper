# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every templated doc must equal its own rendered template.

Why this file exists
--------------------
Ten documentation files under this repository are generated. Each has a sibling
``<name>.template`` holding ``{{VERSION}}`` where the release version goes, and
``scripts/version_template_manager.py generate`` renders the template over the
committed file.

``generate`` runs in exactly one place: ``.github/workflows/ash-create-release.yml``,
and only on a release that bumped the version. Nothing in pull-request CI compared a
rendered template against its doc. So the two could disagree for an unbounded number
of releases, and the disagreement would be resolved at the next bump -- silently, in
the template's favour, because ``generate`` overwrites the doc.

That is not a hypothetical failure mode; it is what happened. Measured at this
branch's merge base (804036ba), two of the ten targets had drifted:

* ``README.md`` -- rendering its template would have DELETED 87 committed lines and
  added 3. Among the 87 was the fix for a ``@v3.0,1`` install command, a comma where
  a dot belongs, which had survived six releases.
* ``docs/content/docs/installation-guide.md`` -- rendering would have ADDED 39 lines
  that the committed doc was missing.

The mechanism is ordinary and will recur without a check. ``README.md`` is the file
GitHub renders and the obvious one to edit; ``README.md.template`` is not. A
contributor edits the doc, review passes, it lands, and the next release throws the
edit away.

What this asserts, and what it deliberately does not
----------------------------------------------------
It asserts the round trip: ``template`` with ``{{VERSION}}`` replaced by the packaged
version is byte-identical to the committed doc. That is the whole invariant
``generate`` establishes, so checking it on every pull request means a doc-only edit
fails here instead of at the next release.

It does not run ``generate``. ``generate`` writes to the working tree, and a test that
repairs the drift it is looking for cannot report it -- the second run would pass. The
comparison is done in memory.

Where the version comes from
----------------------------
``[tool.commitizen] version``, not ``version_management.get_version()``.
``get_version()`` prefers installed package metadata, so in any environment where ASH
is installed from outside this checkout it returns a version unrelated to the tree
being tested, and this file would fail for a reason that has nothing to do with
template drift. ``tests/unit/test_agent_plugin_ash_version.py`` records the same
hazard and resolves it the same way, and it separately asserts that
``[project] version`` and ``[tool.commitizen] version`` agree.

The consequence to be aware of: ``generate`` substitutes ``get_version()``, so this
file checks what a release *should* produce rather than replaying the substitution
``generate`` performs. Those coincide whenever the installed distribution is this
checkout, which is the case in CI.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on 3.10
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_template_manager.py"
PLACEHOLDER = "{{VERSION}}"

# Floor for the positive control. The manager names ten targets today; a floor rather
# than an equality so adding an eleventh templated doc does not need an edit here,
# while losing the list entirely fails.
_MINIMUM_TARGETS = 10


def _load_manager_class():
    """Import the script by path; ``scripts/`` is not an importable package.

    Same approach as ``tests/unit/test_multi_project_attribution_gate.py``. The
    target list is read from the script rather than copied here on purpose: a second
    copy would be a second thing to forget, and a doc added to the script but not to
    this file would be tested by neither.
    """
    spec = importlib.util.spec_from_file_location(
        "version_template_manager", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module.VersionTemplateManager


VersionTemplateManager = _load_manager_class()


def _packaged_version() -> str:
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        return tomllib.load(handle)["tool"]["commitizen"]["version"]


def _targets() -> list[str]:
    return list(VersionTemplateManager(REPO_ROOT).target_files)


def _render(template_text: str) -> str:
    return template_text.replace(PLACEHOLDER, _packaged_version())


class TestTemplatesRenderToTheCommittedDocs:
    """The round trip, one test per target so a failure names the file."""

    @pytest.mark.parametrize("relative_path", _targets())
    def test_rendering_the_template_reproduces_the_doc(self, relative_path: str):
        doc = REPO_ROOT / relative_path
        template = REPO_ROOT / f"{relative_path}.template"

        assert template.is_file(), (
            f"{relative_path} is named in VersionTemplateManager.target_files but "
            f"{template.relative_to(REPO_ROOT)} does not exist. `generate` skips a "
            "missing template with a warning and returns success, so the doc would "
            "simply never be regenerated."
        )
        assert doc.is_file(), (
            f"{relative_path} is a generate target but the file does not exist. Run "
            "`python scripts/version_template_manager.py generate`."
        )

        rendered = _render(template.read_text(encoding="utf-8"))
        actual = doc.read_text(encoding="utf-8")

        if rendered == actual:
            return

        # A unified diff, because the useful information is WHICH lines differ. The
        # figures are the ones a reader needs to judge severity: a release would apply
        # this diff to the committed file without asking.
        import difflib

        diff = list(
            difflib.unified_diff(
                actual.splitlines(),
                rendered.splitlines(),
                fromfile=f"{relative_path} (committed)",
                tofile=f"{relative_path}.template (rendered)",
                lineterm="",
                n=1,
            )
        )
        added = sum(
            1 for line in diff if line.startswith("+") and not line.startswith("+++")
        )
        removed = sum(
            1 for line in diff if line.startswith("-") and not line.startswith("---")
        )

        pytest.fail(
            f"{relative_path} and its template disagree. The next release runs "
            "`version_template_manager.py generate`, which would overwrite the "
            f"committed file -- adding {added} line(s) and removing {removed}.\n\n"
            "Fix the TEMPLATE, not the generated file: an edit to the generated file "
            "is what the next release discards. Then run\n"
            "  python scripts/version_template_manager.py generate\n"
            "and commit both.\n\n" + "\n".join(diff[:60])
        )


class TestTheRoundTripCheckCanFail:
    """Positive controls. Every assertion above is satisfiable by an empty target list.

    Without these, emptying ``target_files``, renaming the placeholder, or a template
    set that happens to contain no placeholder at all would each leave this file
    reporting success over nothing.
    """

    def test_the_target_list_is_populated(self):
        targets = _targets()

        assert len(targets) >= _MINIMUM_TARGETS, (
            f"VersionTemplateManager.target_files names {len(targets)} file(s), below "
            f"the floor of {_MINIMUM_TARGETS}. The parametrized test above generates "
            "one case per entry, so an empty or truncated list makes it vacuous rather "
            "than failing."
        )

    def test_the_placeholder_is_actually_substituted_somewhere(self):
        """Otherwise the comparison degenerates into "two identical files are equal".

        If ``{{VERSION}}`` appeared in no template, ``_render`` would be the identity
        function and every case above would pass without exercising substitution at
        all -- so a renamed placeholder would read as success while `generate` quietly
        stopped inserting the version.
        """
        with_placeholder = [
            relative
            for relative in _targets()
            if (REPO_ROOT / f"{relative}.template").is_file()
            and PLACEHOLDER
            in (REPO_ROOT / f"{relative}.template").read_text(encoding="utf-8")
        ]

        assert with_placeholder, (
            f"No template contains {PLACEHOLDER}. Either the placeholder was renamed "
            "-- in which case VersionTemplateManager.version_placeholder and this file "
            "disagree -- or the templates no longer carry a version at all."
        )

    def test_a_mutated_template_is_detected(self):
        """The check must fail on drift, demonstrated rather than asserted.

        The parametrized test above passes only while the tree is clean, so it stops
        being evidence that it *can* fail the moment it goes green. This mutates a
        template in memory and requires the comparison to notice.
        """
        relative = next(
            r for r in _targets() if (REPO_ROOT / f"{r}.template").is_file()
        )
        template_text = (REPO_ROOT / f"{relative}.template").read_text(encoding="utf-8")
        actual = (REPO_ROOT / relative).read_text(encoding="utf-8")

        assert _render(template_text) == actual, (
            f"precondition: {relative} is expected to round-trip cleanly here"
        )

        mutated = _render(template_text + "\na line the committed doc does not have\n")
        assert mutated != actual, (
            "Adding a line to a template must make the rendered result differ from the "
            "committed doc. If it does not, the comparison is not reading what it "
            "believes it is reading."
        )
