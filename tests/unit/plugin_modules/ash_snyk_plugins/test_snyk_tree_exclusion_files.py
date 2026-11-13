# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""snyk-code does not run when the scanned tree carries exclusions the operator did not accept.

``snyk code test`` collects every ``.snyk`` and ``.dcignore`` file under the path it
tests (and, in its legacy implementation, any file whose name ends in ``.snyk``,
``.dcignore`` or ``.gitignore``) and leaves the files they name out of the
analysis. It has no flag that stops this: there is no ``--policy-path`` for
``code test``, and the rule-file list is fixed in the CLI (code-client-go
``native_workflow.go``, ``@snyk/code-client`` ``collectFilePolicies``). So unless
the operator sets ``honor_tree_exclusions``, ASH refuses the scan and names the
files, rather than report a result the repository narrowed.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_snyk_plugins import snyk_code_scanner
from automated_security_helper.plugin_modules.ash_snyk_plugins.snyk_code_scanner import (
    SnykCodeScanner,
    SnykCodeScannerConfig,
)

pytestmark = pytest.mark.unit

SARIF = json.dumps(
    {
        "version": "2.1.0",
        "runs": [
            {"tool": {"driver": {"name": "SnykCode", "rules": []}}, "results": []}
        ],
    }
)


@pytest.fixture
def context(tmp_path: Path) -> PluginContext:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for path in (context.source_dir, context.output_dir, context.work_dir):
        path.mkdir(parents=True)
    (context.source_dir / "app.js").write_text("const a = 1;\n", encoding="utf-8")
    return context


@pytest.fixture(autouse=True)
def snyk_on_path(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    binary = tmp_path / "bin" / "snyk"
    binary.parent.mkdir(parents=True)
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    monkeypatch.setattr(snyk_code_scanner, "find_executable", lambda name: str(binary))
    monkeypatch.setenv("SNYK_TOKEN", "placeholder-token")


@pytest.fixture
def runs() -> List[List[str]]:
    """The argv of each snyk run, which writes an empty SARIF where it is told."""
    calls: List[List[str]] = []

    def run(self, command, **kwargs):
        calls.append(list(command))
        output = next(
            a.split("=", 1)[1] for a in command if a.startswith("--sarif-file-output=")
        )
        Path(output).write_text(SARIF, encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 0}

    with patch.object(SnykCodeScanner, "_run_subprocess", autospec=True) as double:
        double.side_effect = run
        yield calls


def _scan(context: PluginContext, **options):
    scanner = SnykCodeScanner(
        context=context, config=SnykCodeScannerConfig(options=options)
    )
    return scanner.scan(target=Path(context.source_dir), target_type="source")


def _write(context: PluginContext, name: str, text: str) -> Path:
    path = Path(context.source_dir) / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "name,text",
    [
        (".snyk", "exclude:\n  global:\n    - app.js\n"),
        (".snyk", "exclude:\n  code:\n    - app.js\n"),
        ("sub/dir/.snyk", "exclude:\n  code:\n    - '*.js'\n"),
        (".dcignore", "# generated\napp.js\n"),
        ("lib/.dcignore", "*.js\n"),
        ("policy.snyk", "exclude:\n  global:\n    - app.js\n"),
        ("tests.gitignore", "app.js\n"),
        (".snyk", "exclude: {global: [app.js\n"),
        (".snyk", "exclude: " + "[" * 3000 + "\n"),
    ],
    ids=[
        "global",
        "code",
        "nested",
        "dcignore",
        "nested-dcignore",
        "suffixed-snyk",
        "suffixed-gitignore",
        "unparseable",
        "nested-too-deep-to-parse",
    ],
)
def test_a_tree_exclusion_file_refuses_the_scan(
    context: PluginContext,
    runs: List[List[str]],
    name: str,
    text: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """The source target is judged on its staged copy, so the refusal comes after a
    copy of the source exists under the temporary directory: that copy is removed
    with the refusal, and the message names the file by its place in the tree,
    not by the deleted temporary path the operator cannot act on."""
    copies = tmp_path / "copies"
    copies.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(copies))
    _write(context, name, text)
    with pytest.raises(ScannerError) as raised:
        _scan(context)
    message = str(raised.value)
    assert name in message
    assert "scanners.snyk-code.options.honor_tree_exclusions" in message
    assert str(copies) not in message, message
    assert list(copies.iterdir()) == [], list(copies.iterdir())
    assert runs == [], "snyk must not run on a tree whose exclusions apply"


@pytest.mark.parametrize(
    "name,text",
    [
        (
            ".snyk",
            "version: v1.25.0\nignore:\n  SNYK-JS-LODASH-567746:\n    - '*':\n        reason: none\npatch: {}\n",
        ),
        (".snyk", "exclude:\n  iac-drift:\n    - aws_s3_bucket\n"),
        (".snyk", "exclude:\n  global: []\n"),
        (".snyk", ""),
        (".dcignore", "# only a comment\n\n"),
        (".gitignore", "app.js\n"),
    ],
    ids=[
        "open-source-ignores",
        "other-section",
        "empty-section",
        "empty-file",
        "comment-only-dcignore",
        "gitignore",
    ],
)
def test_a_file_that_excludes_nothing_from_code_test_does_not(
    context: PluginContext, runs: List[List[str]], name: str, text: str
) -> None:
    """A .snyk with only open source ignores is common and leaves code test alone.

    ``.gitignore`` is not refused: ASH's own scan set honors it as well
    (utils/get_scan_set.py).
    """
    _write(context, name, text)
    _scan(context)
    assert len(runs) == 1


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_a_link_at_a_policy_name_refuses_the_scan(
    context: PluginContext, runs: List[List[str]], tmp_path: Path
) -> None:
    """snyk reads a .snyk through a link; ASH does not follow one to check it."""
    outside = tmp_path / "elsewhere.yaml"
    outside.write_text("exclude:\n  global: [app.js]\n", encoding="utf-8")
    os.symlink(outside, Path(context.source_dir) / ".snyk")
    with pytest.raises(ScannerError, match=r"\.snyk"):
        _scan(context)
    assert runs == []


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges")
def test_a_linked_directory_is_neither_followed_nor_counted(
    context: PluginContext, runs: List[List[str]], tmp_path: Path
) -> None:
    """snyk does not walk into a link to a directory, so its files exclude nothing.

    See ``tree_exclusion_files`` for where snyk's file filters were read. The scan
    is still refused, for the link itself: a link to a directory outside the tree
    is not scanned (test_walking_scanners_skip_links_leaving_the_tree.py), and the
    refusal names the link, not the file behind it.
    """
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / ".snyk").write_text("exclude:\n  global: [app.js]\n", encoding="utf-8")
    # The same file counts where it is not behind a link.
    assert snyk_code_scanner.tree_exclusion_files(outside) == [outside / ".snyk"]
    os.symlink(outside, Path(context.source_dir) / "linked", target_is_directory=True)

    assert snyk_code_scanner.tree_exclusion_files(Path(context.source_dir)) == []
    with pytest.raises(ScannerError) as refused:
        _scan(context)
    assert "'linked'" in str(refused.value)
    assert "link leaves the scanned tree" in str(refused.value)
    assert ".snyk" not in str(refused.value)
    assert runs == []


def test_the_operator_can_accept_the_trees_exclusions(
    context: PluginContext, runs: List[List[str]]
) -> None:
    _write(context, ".snyk", "exclude:\n  global:\n    - app.js\n")
    _scan(context, honor_tree_exclusions=True)
    assert len(runs) == 1


def test_a_file_under_git_never_reaches_snyk_so_it_does_not_refuse(
    context: PluginContext,
) -> None:
    """snyk reads a copy of the scan set, and the scan set leaves ``.git`` out, so a
    rule file under it is never in what snyk reads: the source target is judged on
    the copy (``tree_exclusion_files`` on the staged directory), the file counts
    for nothing, and snyk runs. Read at the moment snyk runs, on the directory it
    is given: the file is not in the copy, and the copy carries no exclusion file,
    so a copy that put ``.git`` back would fail here rather than let snyk apply
    the rule quietly."""
    _write(context, ".git/.snyk", "exclude:\n  global:\n    - app.js\n")
    seen: List[dict] = []

    def run(self, command, **kwargs):
        destination = next(
            a.split("=", 1)[1] for a in command if a.startswith("--sarif-file-output=")
        )
        target = Path(
            next(a for a in command[3:] if not a.startswith("-") and a != destination)
        )
        seen.append(
            {
                "git_snyk_in_copy": (target / ".git" / ".snyk").exists(),
                "exclusion_files": snyk_code_scanner.tree_exclusion_files(target),
            }
        )
        Path(destination).write_text(SARIF, encoding="utf-8")
        return {"stdout": "", "stderr": "", "returncode": 0}

    with patch.object(SnykCodeScanner, "_run_subprocess", autospec=True) as double:
        double.side_effect = run
        _scan(context)

    assert seen == [{"git_snyk_in_copy": False, "exclusion_files": []}], seen
