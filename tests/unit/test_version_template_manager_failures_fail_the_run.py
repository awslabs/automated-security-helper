# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``generate`` and ``convert`` exit non-zero when a file fails, and never write "unknown".

Why this file exists
--------------------
``generate_from_template`` and ``convert_to_template`` catch every exception, print it and
return False. ``generate_all_from_templates`` and ``convert_all_to_templates`` only count
the Trues, and ``main`` printed "Successfully generated N files" and fell off the end, so
the process exited 0 whatever failed: a target with no template, a doc that could not be
written, a template that could not be read. The release workflow runs ``generate`` and
passed with stale docs. ``main`` now exits 1 and names the files, using the new
``failures`` list, which also tells a failed file from one skipped for a reason that is
not an error (a template kept, no version reference).

``generate`` also rendered ``get_version()`` without looking at it. When neither the
checkout's pyproject.toml nor the installed metadata names a version, that function
returns the word "unknown", and every pin in every generated doc became "unknown". The
render now refuses it.

``convert`` skipped a listed target whose page does not exist with a warning and exited 0,
the twin of the generate case above: the list names a file that was renamed or deleted,
and nothing reported it. A missing page now fails the run. A template kept, or a page with
no version reference, is still a skip.

The "unknown" version check sat in the per-template step, so a root with no version
printed the same error once per target (fifteen times for the real list) and the summary
listed every target for one cause. ``generate_all_from_templates`` now reads the version
once, before the first template, reports it once and lists every target as not generated.
``failures`` is the list of the last ``*_all`` run: a ``convert_to_template`` or
``generate_from_template`` called on its own only returns False and leaves it alone, so
entries from earlier calls no longer pile up in it.

That left a caller of a single-file method with a bare False for a kept template and for
an unreadable page alike. ``convert_file`` and ``generate_file`` now return a
``FileResult`` (DONE, SKIPPED or FAILED), the bool methods are true only for DONE, and
a missing target reads "Error: ... does not exist." for convert and generate alike.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = REPO_ROOT / "scripts" / "version_template_manager.py"
VERSION_MODULE = "automated_security_helper.utils.version_management"
REPO = "automated-security-" + "helper"
PIN_TEMPLATE = (
    f"pip install git+https://github.com/awslabs/{REPO}.git@v{{{{VERSION}}}}\n"
)
PIN_RENDERED = f"pip install git+https://github.com/awslabs/{REPO}.git@v1.2.3\n"
PIN_STALE = f"pip install git+https://github.com/awslabs/{REPO}.git@v1.0.0\n"


def _load_module():
    spec = importlib.util.spec_from_file_location(
        "version_template_manager_failures", SCRIPT_PATH
    )
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


module = _load_module()


def _project(root: Path, *, with_version: bool = True) -> Path:
    root.mkdir(exist_ok=True)
    if with_version:
        root.joinpath("pyproject.toml").write_text(
            "[project]\n"
            f'name = "{REPO}"\n'
            'version = "1.2.3"\n'
            "\n"
            "[tool.commitizen]\n"
            'version = "1.2.3"\n',
            encoding="utf-8",
        )
    root.joinpath("README.md.template").write_text(PIN_TEMPLATE, encoding="utf-8")
    root.joinpath("README.md").write_text(PIN_STALE, encoding="utf-8")
    return root


def _run(monkeypatch, root: Path, action: str, targets: list[str]):
    """Run main() for action against root, with the manager's targets replaced."""
    original_init = module.VersionTemplateManager.__init__

    def init(self, project_root):
        original_init(self, project_root)
        self.target_files = list(targets)

    monkeypatch.setattr(module.VersionTemplateManager, "__init__", init)
    monkeypatch.setattr(
        sys,
        "argv",
        ["version_template_manager.py", action, "--project-root", str(root)],
    )
    return module.main()


class TestGenerateExitStatus:
    def test_a_clean_run_exits_zero_and_writes_the_version(
        self, tmp_path, monkeypatch, capsys
    ):
        """The control."""
        root = _project(tmp_path / "project")
        assert (_run(monkeypatch, root, "generate", ["README.md"]) or 0) == 0
        assert root.joinpath("README.md").read_text(encoding="utf-8") == PIN_RENDERED
        assert "Successfully generated 1 files" in capsys.readouterr().out

    def test_a_target_with_no_template_exits_one(self, tmp_path, monkeypatch, capsys):
        root = _project(tmp_path / "project")
        status = _run(monkeypatch, root, "generate", ["README.md", "docs/missing.md"])
        captured = capsys.readouterr()
        assert status == 1
        assert "Successfully generated" not in captured.out
        assert "missing.md.template" in captured.err

    def test_a_doc_that_cannot_be_written_exits_one(
        self, tmp_path, monkeypatch, capsys
    ):
        root = _project(tmp_path / "project")
        root.joinpath("README.md").unlink()
        root.joinpath("README.md").mkdir()  # open(..., "w") on a directory raises
        status = _run(monkeypatch, root, "generate", ["README.md"])
        captured = capsys.readouterr()
        assert status == 1
        assert "Successfully generated" not in captured.out
        assert "README.md.template" in captured.err

    def test_the_failures_list_names_the_files(self, tmp_path):
        root = _project(tmp_path / "project")
        manager = module.VersionTemplateManager(root)
        manager.target_files = ["README.md", "docs/missing.md"]
        assert manager.generate_all_from_templates() == 1
        assert manager.failures == [root / "docs/missing.md.template"]
        manager.target_files = ["README.md"]
        assert manager.generate_all_from_templates() == 1
        assert manager.failures == []


class TestAnUnknownVersionIsNotRendered:
    def test_generate_keeps_the_doc_when_no_version_is_found(
        self, tmp_path, monkeypatch, capsys
    ):
        root = _project(tmp_path / "project", with_version=False)
        # No pyproject.toml in the root and no installed metadata: get_version()
        # falls through to its "unknown" last resort.
        monkeypatch.setattr(f"{VERSION_MODULE}._installed_version", lambda: None)
        manager = module.VersionTemplateManager(root)
        assert manager.generate_from_template(root / "README.md.template") is False
        assert root.joinpath("README.md").read_text(encoding="utf-8") == PIN_STALE
        assert "unknown" not in root.joinpath("README.md").read_text(encoding="utf-8")
        assert "no version could be determined" in capsys.readouterr().out

    def test_the_cli_exits_one_when_no_version_is_found(
        self, tmp_path, monkeypatch, capsys
    ):
        root = _project(tmp_path / "project", with_version=False)
        monkeypatch.setattr(f"{VERSION_MODULE}._installed_version", lambda: None)
        assert _run(monkeypatch, root, "generate", ["README.md"]) == 1
        assert root.joinpath("README.md").read_text(encoding="utf-8") == PIN_STALE


def _with_extra_pages(root: Path, names: list[str]) -> None:
    """Give root more targets, each with a template and a stale page."""
    for name in names:
        root.joinpath(name + ".template").write_text(PIN_TEMPLATE, encoding="utf-8")
        root.joinpath(name).write_text(PIN_STALE, encoding="utf-8")


class TestTheVersionIsReadOncePerRun:
    def test_an_unknown_version_is_one_error_not_one_per_template(
        self, tmp_path, monkeypatch, capsys
    ):
        """Red before: the check sat in the per-template step, so three templates
        printed three identical errors."""
        root = _project(tmp_path / "project", with_version=False)
        _with_extra_pages(root, ["a.md", "b.md"])
        monkeypatch.setattr(f"{VERSION_MODULE}._installed_version", lambda: None)
        manager = module.VersionTemplateManager(root)
        manager.target_files = ["README.md", "a.md", "b.md"]
        assert manager.generate_all_from_templates() == 0
        assert capsys.readouterr().out.count("no version could be determined") == 1
        assert manager.failures == [
            root / "README.md.template",
            root / "a.md.template",
            root / "b.md.template",
        ]
        for name in manager.target_files:
            assert root.joinpath(name).read_text(encoding="utf-8") == PIN_STALE

    def test_a_run_asks_for_the_version_once(self, tmp_path, monkeypatch):
        """Red before: every template asked again, three times for three targets."""
        root = _project(tmp_path / "project")
        _with_extra_pages(root, ["a.md", "b.md"])
        real_get_version = importlib.import_module(VERSION_MODULE).get_version
        calls = []

        def counting(project_root=None):
            calls.append(project_root)
            return real_get_version(project_root)

        monkeypatch.setattr(f"{VERSION_MODULE}.get_version", counting)
        manager = module.VersionTemplateManager(root)
        manager.target_files = ["README.md", "a.md", "b.md"]
        assert manager.generate_all_from_templates() == 3
        assert calls == [root]
        assert manager.failures == []


class TestFailuresDescribeOneRun:
    def test_failed_calls_made_directly_do_not_pile_up(self, tmp_path):
        """Red before: every failed per-file call added to the list that the
        class describes as the last run's, so a caller looping over files saw the
        entries of every earlier call."""
        root = _project(tmp_path / "project")
        manager = module.VersionTemplateManager(root)
        missing = root / "docs/missing.md.template"
        assert manager.generate_from_template(missing) is False
        assert manager.generate_from_template(missing) is False
        unreadable = root / "unreadable.md"
        unreadable.mkdir()  # open(..., "r") on a directory raises
        assert manager.convert_to_template(unreadable) is False
        assert manager.failures == []

    def test_a_run_lists_only_its_own_failures(self, tmp_path):
        """The control: a direct failure before the run does not reach its list."""
        root = _project(tmp_path / "project")
        manager = module.VersionTemplateManager(root)
        manager.target_files = ["README.md", "docs/missing.md"]
        manager.generate_from_template(root / "other.md.template")
        assert manager.generate_all_from_templates() == 1
        assert manager.failures == [root / "docs/missing.md.template"]


class TestTheSingleFileMethodsTellAFailureFromASkip:
    def test_convert_file_returns_done_skipped_or_failed(self, tmp_path):
        """Red before: the three-way answer lived in a private method, so a caller
        looping over its own files got a bare False for a kept template and for an
        unreadable page alike."""
        root = _project(tmp_path / "project")
        manager = module.VersionTemplateManager(root)
        result = module.FileResult
        # The template exists, so convert keeps it: a skip, not an error.
        assert manager.convert_file(root / "README.md") is result.SKIPPED
        root.joinpath("plain.md").write_text("no pin here\n", encoding="utf-8")
        assert manager.convert_file(root / "plain.md") is result.SKIPPED
        assert manager.convert_file(root / "README.md", overwrite=True) is result.DONE
        assert manager.convert_file(root / "missing.md") is result.FAILED
        root.joinpath("unreadable.md").mkdir()  # open(..., "r") on a directory raises
        assert manager.convert_file(root / "unreadable.md") is result.FAILED
        assert manager.failures == []

    def test_the_bool_methods_are_true_only_for_done(self, tmp_path):
        root = _project(tmp_path / "project")
        manager = module.VersionTemplateManager(root)
        assert manager.convert_to_template(root / "README.md") is False
        assert manager.convert_to_template(root / "README.md", overwrite=True) is True
        assert manager.generate_from_template(root / "README.md.template") is True

    def test_generate_file_returns_done_or_failed(self, tmp_path):
        root = _project(tmp_path / "project")
        manager = module.VersionTemplateManager(root)
        result = module.FileResult
        assert manager.generate_file(root / "README.md.template") is result.DONE
        assert manager.generate_file(root / "missing.md.template") is result.FAILED

    def test_a_missing_target_reads_the_same_for_convert_and_generate(
        self, tmp_path, capsys
    ):
        """Red before: generate called a missing template a warning and said it was
        skipping, then the run counted it as a failure and exited 1."""
        root = _project(tmp_path / "project")
        manager = module.VersionTemplateManager(root)
        manager.convert_file(root / "a.md")
        manager.generate_file(root / "b.md.template")
        assert capsys.readouterr().out.splitlines() == [
            f"Error: File {root / 'a.md'} does not exist.",
            f"Error: Template {root / 'b.md.template'} does not exist.",
        ]


class TestConvertExitStatus:
    def test_a_doc_that_cannot_be_read_exits_one(self, tmp_path, monkeypatch, capsys):
        root = tmp_path / "project"
        root.mkdir()
        root.joinpath("README.md").mkdir()  # open(..., "r") on a directory raises
        status = _run(monkeypatch, root, "convert", ["README.md"])
        captured = capsys.readouterr()
        assert status == 1
        assert "Successfully converted" not in captured.out
        assert "README.md" in captured.err

    def test_a_listed_target_with_no_page_exits_one(
        self, tmp_path, monkeypatch, capsys
    ):
        """Red before: convert printed a warning for the missing page, counted it as a
        skip and exited 0, while generate fails on a target with no template."""
        root = _project(tmp_path / "project")
        status = _run(monkeypatch, root, "convert", ["README.md", "docs/missing.md"])
        captured = capsys.readouterr()
        assert status == 1
        assert "Successfully converted" not in captured.out
        assert "missing.md" in captured.err

    def test_the_failures_list_names_a_target_with_no_page(self, tmp_path):
        root = _project(tmp_path / "project")
        manager = module.VersionTemplateManager(root)
        manager.target_files = ["README.md", "docs/missing.md"]
        assert manager.convert_all_to_templates() == 0
        assert manager.failures == [root / "docs/missing.md"]

    def test_a_template_kept_is_not_a_failure(self, tmp_path, monkeypatch, capsys):
        """The control: skipping a file for a reason that is not an error exits 0."""
        root = _project(tmp_path / "project")
        assert (_run(monkeypatch, root, "convert", ["README.md"]) or 0) == 0
        assert "Successfully converted 0 files" in capsys.readouterr().out
        assert root.joinpath("README.md.template").read_text(encoding="utf-8") == (
            PIN_TEMPLATE
        )
