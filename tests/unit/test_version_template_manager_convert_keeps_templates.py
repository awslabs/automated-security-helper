# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``convert`` keeps an existing template unless told to overwrite it.

Why this file exists
--------------------
``convert_to_template`` wrote ``<doc>.template`` from the rendered doc whenever the
doc held a version reference, with no check that a template already existed. A
template is hand-maintained once it exists: it carries placeholders the rendered
doc holds only as plain numbers (``{{RELEASE}}`` in a table, which no pattern
recognizes on the way back), so a second ``convert`` replaced the template with
one missing those placeholders, and the next ``generate`` wrote the stale values
over the doc. The existing template is now kept, and ``--overwrite`` is the
explicit way to replace it.

``--overwrite`` replaces a template only with one that renders back to the doc it was
written from. A doc that pins two releases, that names ``{{VERSION}}`` in its text, or
that holds a spelling its release does not read (a command of a newer ASH on a page
pinned to an older one) comes back different when the template is rendered for the
release the doc pins, so the next ``generate`` would write something other than the doc
it was converted from. That refusal is a failure of the run, and the template stays as
it was.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_template_manager.py"
REPO = "automated-security-" + "helper"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "version_template_manager_convert_keeps", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


module = _load_module()
VersionTemplateManager = module.VersionTemplateManager

DOC = f"pip install git+https://github.com/awslabs/{REPO}.git@v3.4.0\n\n| release | 3.4.0 |\n"
HAND_EDITED_TEMPLATE = (
    f"pip install git+https://github.com/awslabs/{REPO}.git@v{{{{VERSION}}}}\n\n"
    "| release | {{RELEASE}} |\n"
)


@pytest.fixture
def doc_and_template(tmp_path):
    doc = tmp_path / "README.md"
    doc.write_text(DOC, encoding="utf-8")
    template = tmp_path / "README.md.template"
    template.write_text(HAND_EDITED_TEMPLATE, encoding="utf-8")
    return doc, template


def test_an_existing_template_is_kept(doc_and_template, tmp_path, capsys):
    doc, template = doc_and_template
    assert VersionTemplateManager(tmp_path).convert_to_template(doc) is False
    assert template.read_text(encoding="utf-8") == HAND_EDITED_TEMPLATE
    assert "keeping it" in capsys.readouterr().out


def test_overwrite_replaces_it(doc_and_template, tmp_path):
    doc, template = doc_and_template
    assert VersionTemplateManager(tmp_path).convert_to_template(doc, overwrite=True)
    text = template.read_text(encoding="utf-8")
    assert "{{VERSION}}" in text
    assert "{{RELEASE}}" not in text


def test_convert_and_the_target_list_follow_one_template_rule(tmp_path, monkeypatch):
    """Where a template sits is written once; convert and generate both ask it."""
    # Red before: there was no one place. convert_file built the template's name
    # itself, so changing the rule in template_path_for left convert writing the old
    # name; the monkeypatch of the shared rule fails there with no such attribute.
    manager = VersionTemplateManager(tmp_path)
    monkeypatch.setattr(
        manager, "template_beside", lambda page: page.with_name(page.name + ".kept")
    )
    page = tmp_path / "docs" / "guide.md"
    page.parent.mkdir()
    page.write_text(DOC, encoding="utf-8")

    assert manager.convert_to_template(page) is True

    kept = tmp_path / "docs" / "guide.md.kept"
    assert manager.template_path_for("docs/guide.md") == kept
    assert kept.is_file()
    assert not (tmp_path / "docs" / "guide.md.template").exists()


def test_a_doc_with_no_template_is_converted(tmp_path):
    """The control: the first convert still writes the template."""
    doc = tmp_path / "README.md"
    doc.write_text(DOC, encoding="utf-8")
    assert VersionTemplateManager(tmp_path).convert_to_template(doc) is True
    assert "{{VERSION}}" in (tmp_path / "README.md.template").read_text(
        encoding="utf-8"
    )


def test_convert_all_passes_overwrite_through(doc_and_template, tmp_path):
    doc, template = doc_and_template
    manager = VersionTemplateManager(tmp_path)
    manager.target_files = ["README.md"]
    assert manager.convert_all_to_templates() == 0
    assert template.read_text(encoding="utf-8") == HAND_EDITED_TEMPLATE
    assert manager.convert_all_to_templates(overwrite=True) == 1
    assert "{{RELEASE}}" not in template.read_text(encoding="utf-8")


def test_the_cli_has_an_overwrite_flag(doc_and_template, tmp_path, monkeypatch):
    doc, template = doc_and_template
    monkeypatch.setattr(
        sys,
        "argv",
        ["version_template_manager.py", "convert", "--project-root", str(tmp_path)],
    )
    original_init = VersionTemplateManager.__init__

    def init(self, project_root):
        original_init(self, project_root)
        self.target_files = ["README.md"]

    monkeypatch.setattr(VersionTemplateManager, "__init__", init)
    module.main()
    assert template.read_text(encoding="utf-8") == HAND_EDITED_TEMPLATE
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "version_template_manager.py",
            "convert",
            "--overwrite",
            "--project-root",
            str(tmp_path),
        ],
    )
    module.main()
    assert "{{RELEASE}}" not in template.read_text(encoding="utf-8")


def _page(release: str, rest: str = "") -> str:
    """A doc with one install command pinned to ``release``, then ``rest``."""
    return f"pip install git+https://github.com/awslabs/{REPO}.git@v{release}\n{rest}"


#: Docs whose template, written by convert and rendered for the release they pin, is not
#: the doc: the placeholder named in text comes back as a number, two pins come back as
#: one, and a command of a newer ASH comes back in the spelling of the pinned release.
NOT_GIVEN_BACK = {
    "a placeholder in its text": _page(
        "3.4.0", "\nThe template writes `{{VERSION}}` for the release.\n"
    ),
    "two pinned releases": _page("3.3.0") + _page("3.4.0"),
    "a newer spelling on an older release": _page(
        "3.8.0", "\n```bash\nash scan fs .\n```\n"
    ),
}


@pytest.mark.parametrize("page_text", NOT_GIVEN_BACK.values(), ids=list(NOT_GIVEN_BACK))
def test_overwrite_refuses_a_template_that_does_not_render_back_to_the_page(
    page_text, tmp_path, capsys
):
    # Red before: convert_file wrote the template over the hand-maintained one and said
    # it had, so the next generate wrote a page that was not the one converted from.
    doc = tmp_path / "README.md"
    doc.write_text(page_text, encoding="utf-8")
    template = tmp_path / "README.md.template"
    template.write_text(HAND_EDITED_TEMPLATE, encoding="utf-8")
    manager = VersionTemplateManager(tmp_path)

    assert manager.convert_file(doc, overwrite=True) is module.FileResult.FAILED

    assert template.read_text(encoding="utf-8") == HAND_EDITED_TEMPLATE
    out = capsys.readouterr().out
    assert f"not replacing {template}" in out
    assert "would not give it back" in out
    assert "Created template" not in out


def test_the_refusal_names_the_line_the_template_would_change(tmp_path, capsys):
    doc = tmp_path / "README.md"
    doc.write_text(NOT_GIVEN_BACK["a newer spelling on an older release"], "utf-8")
    template = tmp_path / "README.md.template"
    template.write_text(HAND_EDITED_TEMPLATE, encoding="utf-8")

    converted = VersionTemplateManager(tmp_path).convert_to_template(
        doc, overwrite=True
    )

    assert converted is False
    assert (
        "Rendered for 3.8.0, line 4 of the page is 'ash scan fs .' and the template "
        "writes 'ash scan --source-dir .'." in capsys.readouterr().out
    )


def test_two_pinned_releases_are_named_by_the_refusal(tmp_path, capsys):
    doc = tmp_path / "README.md"
    doc.write_text(NOT_GIVEN_BACK["two pinned releases"], encoding="utf-8")
    (tmp_path / "README.md.template").write_text(HAND_EDITED_TEMPLATE, "utf-8")

    VersionTemplateManager(tmp_path).convert_file(doc, overwrite=True)

    assert "The page pins 2 releases (3.3.0, 3.4.0)" in capsys.readouterr().out


def test_a_page_that_holds_its_own_releases_spellings_replaces_the_template(tmp_path):
    """The control for the refusal: a page pinned to a release before the subjects, in
    that release's own spellings, renders back from its template, so overwrite goes on."""
    doc = tmp_path / "README.md"
    doc.write_text(
        _page("3.8.0", "\n```bash\nash scan --source-dir .\n```\n"), encoding="utf-8"
    )
    template = tmp_path / "README.md.template"
    template.write_text(HAND_EDITED_TEMPLATE, encoding="utf-8")

    result = VersionTemplateManager(tmp_path).convert_file(doc, overwrite=True)

    assert result is module.FileResult.DONE
    assert "ash scan --source-dir ." in template.read_text(encoding="utf-8")
    assert "@v{{VERSION}}" in template.read_text(encoding="utf-8")


def test_a_template_that_does_not_exist_is_written_whatever_the_page_pins(tmp_path):
    """The check guards a template that would be lost. With none to replace, convert
    writes what it always did, so a doc that pins two releases still gets its first
    template."""
    doc = tmp_path / "README.md"
    doc.write_text(NOT_GIVEN_BACK["two pinned releases"], encoding="utf-8")

    result = VersionTemplateManager(tmp_path).convert_file(doc, overwrite=True)

    assert result is module.FileResult.DONE
    written = (tmp_path / "README.md.template").read_text(encoding="utf-8")
    assert written.count("{{VERSION}}") == 2


def test_a_refused_overwrite_fails_the_convert_run(tmp_path, monkeypatch, capsys):
    doc = tmp_path / "README.md"
    doc.write_text(NOT_GIVEN_BACK["two pinned releases"], encoding="utf-8")
    template = tmp_path / "README.md.template"
    template.write_text(HAND_EDITED_TEMPLATE, encoding="utf-8")
    manager = VersionTemplateManager(tmp_path)
    manager.target_files = ["README.md"]

    assert manager.convert_all_to_templates(overwrite=True) == 0
    assert manager.failures == [doc]

    original_init = VersionTemplateManager.__init__

    def init(self, project_root):
        original_init(self, project_root)
        self.target_files = ["README.md"]

    monkeypatch.setattr(VersionTemplateManager, "__init__", init)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "version_template_manager.py",
            "convert",
            "--overwrite",
            "--project-root",
            str(tmp_path),
        ],
    )
    assert module.main() == 1
    assert template.read_text(encoding="utf-8") == HAND_EDITED_TEMPLATE
    assert "were not converted to templates" in capsys.readouterr().err
