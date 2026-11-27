"""``--no-color`` turns the scan's console color off on Windows too.

Both places in ``run_ash_scan`` that pick the orchestrator's ``color_system``
(the single-directory scan and the workspace settings builder) used to read

    "windows" if platform.system() == "Windows" else "auto" if opts.color else None

which Python groups as ``"windows"`` for every Windows run: ``--no-color`` was
ignored there, and the console was bound to the "windows" color system whatever
file it wrote to, so output into a pipe carried escape codes.

The expectation is the one ``utils.log`` already has: "auto" when color is on
(Rich reads the file the console writes to) and None when it is off, on every
platform.
"""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from automated_security_helper.interactions.run_ash_scan import (
    ScanOptions,
    _run_local_mode,
    build_project_scan_settings,
)

pytestmark = pytest.mark.unit

ESCAPE = "\x1b["


def _color_system_the_single_scan_hands_the_orchestrator(
    tmp_path, *, color: bool, system: str
):
    source_dir = tmp_path / "source"
    source_dir.mkdir(exist_ok=True)
    opts = ScanOptions(source_dir=source_dir, output_dir=tmp_path / "out", color=color)
    orchestrator = MagicMock()
    orchestrator.config = MagicMock()
    orchestrator.config.fail_on_findings = True

    with (
        patch("platform.system", return_value=system),
        patch(
            "automated_security_helper.core.orchestrator.ASHScanOrchestrator.create",
            return_value=orchestrator,
        ) as create,
        patch("builtins.open", MagicMock()),
        patch(
            "automated_security_helper.interactions.run_ash_scan.write_text_atomically"
        ),
        patch("pathlib.Path.exists", return_value=False),
    ):
        _run_local_mode(opts, MagicMock())

    return create.call_args.kwargs["color_system"]


def _color_system_the_workspace_builder_records(tmp_path, *, color: bool, system: str):
    root = tmp_path / "work"
    root.mkdir(exist_ok=True)
    opts = ScanOptions(source_dir=root, output_dir=tmp_path / "out", color=color)
    with patch("platform.system", return_value=system):
        return build_project_scan_settings(opts).color_system


@pytest.mark.parametrize("system", ["Windows", "Linux", "Darwin"])
class TestColorSystemFollowsTheColorFlagOnEveryPlatform:
    def test_single_scan_color_off_is_none(self, tmp_path, system):
        assert (
            _color_system_the_single_scan_hands_the_orchestrator(
                tmp_path, color=False, system=system
            )
            is None
        )

    def test_single_scan_color_on_is_auto(self, tmp_path, system):
        assert (
            _color_system_the_single_scan_hands_the_orchestrator(
                tmp_path, color=True, system=system
            )
            == "auto"
        )

    def test_workspace_color_off_is_none(self, tmp_path, system):
        assert (
            _color_system_the_workspace_builder_records(
                tmp_path, color=False, system=system
            )
            is None
        )

    def test_workspace_color_on_is_auto(self, tmp_path, system):
        assert (
            _color_system_the_workspace_builder_records(
                tmp_path, color=True, system=system
            )
            == "auto"
        )


class _Terminal(io.StringIO):
    """A stream that says it is a terminal."""

    def isatty(self) -> bool:
        return True


def test_auto_color_writes_escape_codes_to_a_stream_that_is_a_terminal(monkeypatch):
    """The positive case: with color on, a terminal gets escapes.

    Without it the tests above would also pass for a console that never colors.
    """
    for name in ("FORCE_COLOR", "NO_COLOR", "TTY_COMPATIBLE", "COLORTERM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    stream = _Terminal()

    Console(file=stream, color_system="auto", width=80).print("[red]refused[/red]")

    written = stream.getvalue()
    assert "refused" in written
    assert ESCAPE in written, written


def test_auto_color_writes_plain_text_to_a_pipe(monkeypatch):
    for name in ("FORCE_COLOR", "NO_COLOR", "TTY_COMPATIBLE", "COLORTERM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    stream = io.StringIO()

    Console(file=stream, color_system="auto", width=80).print("[red]refused[/red]")

    assert "refused" in stream.getvalue()
    assert ESCAPE not in stream.getvalue()
