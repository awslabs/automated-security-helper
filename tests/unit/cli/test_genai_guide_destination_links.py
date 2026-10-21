"""``ash get-genai-guide --output PATH`` never writes through a link at PATH.

The destination is a path the operator names, outside every output directory, so
nothing below it is a guarded root. The command writes a new file beside it and
renames that over it, and refuses a symlink at the destination: the file the link
names is left as it was, and the command exits non-zero saying why.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli import main as cli_main

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX links")

GUIDE = "# GenAI guide\n\nUse ash_aggregated_results.json.\n"
ORIGINAL = "outside content\n"


@pytest.fixture
def installed(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """ASH 'installed' under tmp_path/install with its guide, and an outside file."""
    root = tmp_path / "install"
    main_py = root / "automated_security_helper" / "cli" / "main.py"
    main_py.parent.mkdir(parents=True)
    guide = root / "docs" / "content" / "docs" / "genai-steering-guide.md"
    guide.parent.mkdir(parents=True)
    guide.write_text(GUIDE, encoding="utf-8")
    monkeypatch.setattr(cli_main, "__file__", str(main_py))
    outside = tmp_path / "outside.txt"
    outside.write_text(ORIGINAL, encoding="utf-8")
    return outside


def _run(destination: Path):
    return CliRunner().invoke(
        cli_main.app, ["get-genai-guide", "--output", str(destination)]
    )


def test_a_link_at_the_destination_is_refused(tmp_path, installed):
    destination = tmp_path / "guide.md"
    destination.symlink_to(installed)

    result = _run(destination)

    assert result.exit_code != 0, result.output
    assert installed.read_text(encoding="utf-8") == ORIGINAL
    assert destination.is_symlink(), "the link is left where it was"
    assert "symlink" in " ".join(result.output.split()), result.output


def test_a_file_another_name_refers_to_is_replaced_not_written_through(
    tmp_path, installed
):
    destination = tmp_path / "guide.md"
    os.link(installed, destination)

    result = _run(destination)

    assert result.exit_code == 0, result.output
    assert installed.read_text(encoding="utf-8") == ORIGINAL
    assert destination.read_text(encoding="utf-8") == GUIDE


def test_a_plain_destination_is_written(tmp_path, installed):
    """Control."""
    destination = tmp_path / "guide.md"
    destination.write_text("previous\n", encoding="utf-8")

    result = _run(destination)

    assert result.exit_code == 0, result.output
    assert destination.read_text(encoding="utf-8") == GUIDE
    assert sorted(p.name for p in tmp_path.iterdir()) == [
        "guide.md",
        "install",
        "outside.txt",
    ], "no staging file is left behind"
