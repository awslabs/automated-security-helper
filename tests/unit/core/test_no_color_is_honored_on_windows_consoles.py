"""``--no-color`` turns color off in the progress display and the metrics table
on Windows too.

Two more Rich consoles forced the "windows" color system on every Windows run,
whatever the color option said:

* ``ScanExecutionEngine`` built its ``LiveProgressDisplay`` with
  ``"windows" if platform.system() == "Windows" else color_system``, so the
  progress display kept a color system under ``--no-color``.
* ``display_metrics_table`` is told ``use_color`` by the engine, as "the progress
  display's console has a color system", so the same flag made the final table
  color-on, and the table's own console then forced "windows" for it.

The expectation is the one ``utils.log`` already has, and the one the scan
orchestrator's color argument now has: "auto" when color is on (Rich reads the
file the console writes to) and None when it is off, on every platform. Each
test patches ``platform.system`` so a Linux runner exercises the Windows branch.
"""

from __future__ import annotations

import io
from unittest.mock import MagicMock, patch

import pytest
from rich.console import Console

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core import metrics_table
from automated_security_helper.core.execution_engine import ScanExecutionEngine

pytestmark = pytest.mark.unit

ESCAPE = "\x1b["
SYSTEMS = ["Windows", "Linux", "Darwin"]


def _context(tmp_path) -> PluginContext:
    return PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "output",
        work_dir=tmp_path / "work",
        config=AshConfig(),
    )


class _Terminal(io.StringIO):
    """A stream that says it is a terminal."""

    def isatty(self) -> bool:
        return True


@pytest.mark.parametrize("system", SYSTEMS)
class TestEngineHandsTheProgressDisplayTheColorOption:
    def _color_system_given_to_the_display(self, tmp_path, *, color_system, system):
        with (
            patch("platform.system", return_value=system),
            patch(
                "automated_security_helper.core.execution_engine.LiveProgressDisplay"
            ) as display,
        ):
            ScanExecutionEngine(
                context=_context(tmp_path),
                color_system=color_system,
                show_progress=False,
            )
        return display.call_args.kwargs["color_system"]

    def test_color_off_is_none(self, tmp_path, system):
        assert (
            self._color_system_given_to_the_display(
                tmp_path, color_system=None, system=system
            )
            is None
        )

    def test_color_on_is_auto(self, tmp_path, system):
        assert (
            self._color_system_given_to_the_display(
                tmp_path, color_system="auto", system=system
            )
            == "auto"
        )

    def test_color_off_leaves_the_display_console_without_a_color_system(
        self, tmp_path, system
    ):
        """The value ``display_metrics_table`` is told ``use_color`` from."""
        with patch("platform.system", return_value=system):
            engine = ScanExecutionEngine(
                context=_context(tmp_path),
                color_system=None,
                show_progress=False,
            )

        assert engine.progress_display.console.color_system is None


@pytest.mark.parametrize("system", SYSTEMS)
class TestMetricsTableConsoleFollowsUseColor:
    def _console_kwargs(self, *, use_color, system, monkeypatch):
        monkeypatch.delenv("NO_COLOR", raising=False)
        with (
            patch("platform.system", return_value=system),
            patch.object(
                metrics_table, "ash_console", return_value=MagicMock()
            ) as make_console,
            patch.object(
                metrics_table,
                "generate_metrics_table_from_unified_data",
                return_value="table",
            ),
            patch.multiple(
                metrics_table,
                print_coverage_shortfalls=MagicMock(),
                print_inputs_not_scanned=MagicMock(),
                print_requested_scanners_not_run=MagicMock(),
                print_stale_content_databases=MagicMock(),
                print_converter_refusals=MagicMock(),
            ),
        ):
            metrics_table.display_metrics_table(MagicMock(), use_color=use_color)
        return make_console.call_args.kwargs

    def test_no_color_is_none(self, system, monkeypatch):
        kwargs = self._console_kwargs(
            use_color=False, system=system, monkeypatch=monkeypatch
        )

        assert kwargs["color_system"] is None
        assert kwargs["force_terminal"] is False

    def test_color_is_auto(self, system, monkeypatch):
        kwargs = self._console_kwargs(
            use_color=True, system=system, monkeypatch=monkeypatch
        )

        assert kwargs["color_system"] == "auto"
        assert kwargs["force_terminal"] is True


def test_a_console_with_no_color_system_writes_no_escape_codes(monkeypatch):
    """What None means to Rich: plain text even on a stream that is a terminal."""
    for name in ("FORCE_COLOR", "NO_COLOR", "TTY_COMPATIBLE", "COLORTERM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    stream = _Terminal()

    Console(file=stream, color_system=None, width=80).print("[red]refused[/red]")

    assert "refused" in stream.getvalue()
    assert ESCAPE not in stream.getvalue()


def test_an_auto_console_writes_escape_codes_to_a_terminal(monkeypatch):
    """The positive case: without it the test above also passes for a console
    that never colors."""
    for name in ("FORCE_COLOR", "NO_COLOR", "TTY_COMPATIBLE", "COLORTERM"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    stream = _Terminal()

    Console(file=stream, color_system="auto", width=80).print("[red]refused[/red]")

    assert ESCAPE in stream.getvalue(), stream.getvalue()
