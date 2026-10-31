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
