# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The workspace project section shows every label and renders the detail.

A project's label is ``project_name`` from that project's own config file. The
Markdown table escaped only ``|`` in it and the text table nothing, so a newline
started a line of its own (a heading, a CI command) and markup rendered instead
of reading, unlike every other repository-controlled value those reporters
print. Each table value is now one shown line, and the Markdown values are kept
literal the way the Markdown reporter keeps every other table entry.

``workspace_project_rows`` also built a per-project ``detail`` (the error text,
the scanners that did not complete, a conversion gap, a stale database) that no
renderer emitted. Each renderer now writes the non-empty details under the
table.
"""

import pytest

from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_section import (
    html_workspace_section,
    markdown_workspace_section,
    text_workspace_section,
)

pytestmark = pytest.mark.unit

HOSTILE_LABEL = "web|x\n## injected\x1b[31m *bold* <b>"


def _project(key: str, **overrides) -> WorkspaceProjectResult:
    fields = {
        "project": key,
        "relative_path": key,
        "display_label": key,
        "status": ProjectRunStatus.COMPLETED,
        "severity_threshold": "MEDIUM",
        "output_path": f"projects/{key}",
    }
    fields.update(overrides)
    return WorkspaceProjectResult(**fields)


def _model(*projects: WorkspaceProjectResult) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.workspace = WorkspaceResults(
        workspace_file="/w/.ash-workspace.yaml",
        workspace_root="/w",
        exit_code=0,
        projects=list(projects),
    )
    return model


class TestTheLabelIsShownNotObeyed:
    def test_markdown_keeps_the_label_on_its_row_and_literal(self):
        lines = markdown_workspace_section(
            _model(_project("web", display_label=HOSTILE_LABEL))
        )
        text = "\n".join(lines)
        assert "\x1b" not in text
        # The lines the document is made of, not the list elements: an element
        # that kept a raw newline would hold a heading on a line of its own and
        # pass a check made element by element.
        assert all("\n" not in line.rstrip("\n") for line in lines), lines
        rendered = text.splitlines()
        assert not any(line.startswith("## injected") for line in rendered)
        (row,) = [line for line in rendered if "injected" in line]
        # The label's own pipe is written escaped (a backslash before it) and is
        # not a column edge; every other pipe is one.
        assert (
            row.replace("\\|", "").count("|")
            == len(
                ("Project", "Status", "Findings", "Actionable", "Threshold", "Result")
            )
            + 1
        )
        assert "web\\|x" in row, row
        assert "\\*bold\\*" in row, row
        assert "&lt;b&gt;" in row, row

    def test_text_keeps_the_label_on_its_row(self):
        lines = text_workspace_section(
            _model(_project("web", display_label=HOSTILE_LABEL))
        )
        text = "\n".join(lines)
        assert "\x1b" not in text
        assert all("\n" not in line for line in lines), lines
        rendered = text.splitlines()
        assert not any(line.startswith("## injected") for line in rendered)
        assert any("\\x1b" in line and "injected" in line for line in rendered), lines

    def test_html_shows_the_control_as_an_escape(self):
        fragment = html_workspace_section(
            _model(_project("web", display_label=HOSTILE_LABEL))
        )
        assert "\x1b" not in fragment
        assert "\\x1b" in fragment
        assert "<b>" not in fragment.split("<tbody>", 1)[1]

    def test_an_ordinary_label_is_unchanged(self):
        lines = markdown_workspace_section(_model(_project("api")))
        assert any(line.startswith("| api |") for line in lines), lines


class TestTheDetailIsRendered:
    @staticmethod
    def _incomplete() -> AshAggregatedResults:
        return _model(
            _project(
                "svc",
                scan_incomplete=True,
                incomplete_scanners=["semgrep", "grype"],
            ),
            _project("clean"),
        )

    def test_markdown_lists_the_detail_under_the_table(self):
        text = "\n".join(markdown_workspace_section(self._incomplete()))
        assert "did not complete: semgrep, grype" in text, text
        assert "- **svc**:" in text, text
        assert "- **clean**:" not in text, text

    def test_text_lists_the_detail_under_the_table(self):
        lines = text_workspace_section(self._incomplete())
        assert any(
            line.strip().startswith("svc:")
            and "did not complete: semgrep, grype" in line
            for line in lines
        ), lines
        assert not any(line.strip().startswith("clean:") for line in lines), lines

    def test_html_lists_the_detail_under_the_table(self):
        fragment = html_workspace_section(self._incomplete())
        assert 'class="project-notes"' in fragment
        assert "did not complete: semgrep, grype" in fragment
        assert fragment.count("<li>") == 1

    HOSTILE_ERROR = "boom\n## injected-note <b>x</b>\x1b[31m *bold* | pipe"

    @classmethod
    def _hostile(cls) -> AshAggregatedResults:
        """A failed project whose label and error text both hold a newline, a
        tag, an escape code, emphasis and a pipe: the error text is the field
        most likely to carry arbitrary text from a scanner."""
        return _model(
            _project(
                "web",
                display_label=HOSTILE_LABEL,
                status=ProjectRunStatus.FAILED,
                error=cls.HOSTILE_ERROR,
                severity_threshold=None,
            )
        )

    def test_markdown_shows_the_label_and_the_error_on_one_note_line(self):
        lines = markdown_workspace_section(self._hostile())
        text = "\n".join(lines)
        assert "\x1b" not in text
        rendered = text.splitlines()
        assert not any(line.startswith("## injected") for line in rendered)
        (note,) = [line for line in rendered if line.startswith("- **")]
        assert "&lt;b&gt;" in note and "<b>" not in note, note
        assert "\\*bold\\*" in note, note
        assert "\\x1b" in note, note
        assert "injected-note" in note, note

    def test_text_shows_the_label_and_the_error_on_one_note_line(self):
        lines = text_workspace_section(self._hostile())
        text = "\n".join(lines)
        assert "\x1b" not in text
        rendered = text.splitlines()
        assert not any(line.lstrip().startswith("## injected") for line in rendered)
        (note,) = [line for line in rendered if "injected-note" in line]
        assert note.startswith("  "), note
        assert "\\x1b" in note, note

    def test_html_escapes_the_label_and_the_error_in_the_note(self):
        fragment = html_workspace_section(self._hostile())
        assert "\x1b" not in fragment
        notes = fragment.split('class="project-notes"', 1)[1]
        assert fragment.count("<li>") == 1
        assert "<b>" not in notes
        assert "&lt;b&gt;" in notes
        assert "\\x1b" in notes

    def test_no_notes_when_no_row_has_a_detail(self):
        model = _model(_project("api"), _project("web"))
        assert 'class="project-notes"' not in html_workspace_section(model)
        assert not any(
            line.startswith("- **") for line in markdown_workspace_section(model)
        )
