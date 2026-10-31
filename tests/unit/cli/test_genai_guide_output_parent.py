# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash get-genai-guide --output PATH`` makes PATH's directory when it is missing.

The destination is a path the operator names. Before the fix the command opened its
staging file inside a directory that did not exist, and the FileNotFoundError from
that open escaped as a traceback: only a link at the destination itself was caught.
``ash scan --output-dir`` and ``ash config init`` make a missing directory, so this
command does the same, and a file in the directory's place is refused in the
command's own words (``Error: ...``, exit 1) rather than with a traceback.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import main as cli_main

pytestmark = pytest.mark.unit

GUIDE = "# GenAI guide\n\nUse ash_aggregated_results.json.\n"


@pytest.fixture
def installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """ASH 'installed' under tmp_path/install with its guide."""
    root = tmp_path / "install"
    main_py = root / "automated_security_helper" / "cli" / "main.py"
    main_py.parent.mkdir(parents=True)
    guide = root / "docs" / "content" / "docs" / "genai-steering-guide.md"
    guide.parent.mkdir(parents=True)
    guide.write_text(GUIDE, encoding="utf-8")
    monkeypatch.setattr(cli_main, "__file__", str(main_py))
    return root


def _run(destination: Path):
    return CliRunner().invoke(
        cli_main.app, ["get-genai-guide", "--output", str(destination)]
    )


def test_a_missing_parent_directory_is_made(tmp_path, installed):
    destination = tmp_path / "not-yet" / "deeper" / "guide.md"
    assert not destination.parent.exists()

    result = _run(destination)

    assert result.exit_code == 0, result.output
    assert result.exception is None, repr(result.exception)
    assert destination.parent.is_dir()
    assert destination.read_text(encoding="utf-8") == GUIDE
    assert [p.name for p in destination.parent.iterdir()] == ["guide.md"], (
        "no staging file is left behind"
    )


def test_a_file_in_the_directorys_place_is_refused(tmp_path, installed):
    blocker = tmp_path / "blocker"
    blocker.write_text("a file, not a directory\n", encoding="utf-8")
    destination = blocker / "guide.md"

    result = _run(destination)

    assert result.exit_code == 1, result.output
    # A clean exit, not an escaped OSError: CliRunner records the exception a
    # command raised, and a traceback has no "Error:" line.
    assert result.exception is None or isinstance(result.exception, SystemExit), repr(
        result.exception
    )
    assert "Error: cannot create the directory for" in result.output, result.output
    assert blocker.read_text(encoding="utf-8") == "a file, not a directory\n"
    assert not destination.exists()


def test_an_existing_parent_is_written(tmp_path, installed):
    """Control."""
    destination = tmp_path / "guide.md"

    result = _run(destination)

    assert result.exit_code == 0, result.output
    assert destination.read_text(encoding="utf-8") == GUIDE
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "guide.md",
        "install",
    ], "no staging file is left behind"
