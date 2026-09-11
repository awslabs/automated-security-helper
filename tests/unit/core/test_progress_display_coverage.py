"""Behavior tests for :class:`LiveProgressDisplay`.

Every test drives the real class rather than a double. Two shared hazards are
handled by fixtures:

* ``__init__`` attaches a ``LiveDisplayLogHandler`` to the process-wide ``ash``
  logger. Left in place it outlives the test and every later ASH record in the
  same xdist worker renders into a dead panel, so the handler list is snapshotted
  and restored.
* ``__init__`` builds a ``Console`` bound to the real stdout. The tests replace it
  with one writing to an in-memory buffer, so ``Live.__enter__`` does not write
  escape sequences into pytest's captured streams.
"""

import io
import logging
from unittest.mock import create_autospec

import pytest
from rich.console import Console
from rich.live import Live

from automated_security_helper.core.enums import ExecutionPhase
from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.utils.log import ASH_LOGGER


@pytest.fixture
def autospec_live(monkeypatch):
    """Replace rich's Live with an autospec of the real class.

    A real ``Live`` cannot be entered here: it defaults to
    ``redirect_stdout=True`` and ``redirect_stderr=True``, so ``__enter__``
    swaps ``sys.stdout``/``sys.stderr`` for rich proxies. Under pytest's capture
    that produces a run which emits no output and never terminates.

    Autospec rather than ``Mock()`` because the double stands in for a real
    class: the spec validates that ``start()`` calls ``Live`` with kwargs the
    real signature accepts, so a typo'd or removed constructor argument fails
    the test instead of being silently absorbed.
    """
    import automated_security_helper.core.progress as progress_module

    live_class = create_autospec(Live)
    monkeypatch.setattr(progress_module, "Live", live_class)
    return live_class


@pytest.fixture
def display_factory():
    """Build LiveProgressDisplay instances with an in-memory console.

    Restores ``ASH_LOGGER.handlers`` and stops any live display afterwards.
    """
    original_handlers = list(ASH_LOGGER.handlers)
    created = []

    def _make(**kwargs):
        display = LiveProgressDisplay(**kwargs)
        display.console = Console(file=io.StringIO(), width=120)
        created.append(display)
        return display

    yield _make

    for display in created:
        display.stop()
    ASH_LOGGER.handlers = original_handlers


def test_default_handler_level_is_verbose(display_factory):
    """With neither flag set the log handler sits at the VERBOSE level (15)."""
    display = display_factory()

    assert display.log_handler.level == 15
    assert display.verbose is False
    assert display.debug is False


def test_verbose_flag_selects_verbose_handler_level(display_factory):
    """verbose=True records the flag and pins the handler to VERBOSE (15)."""
    display = display_factory(verbose=True)

    assert display.verbose is True
    assert display.log_handler.level == 15


def test_debug_flag_lowers_handler_level_to_debug(display_factory):
    """debug=True wins over the default and drops the handler to DEBUG (10)."""
    display = display_factory(debug=True)

    assert display.debug is True
    assert display.log_handler.level == logging.DEBUG
    assert display.log_handler.level < 15


def test_debug_wins_when_both_verbose_and_debug_are_set(display_factory):
    """The debug branch is evaluated after the verbose branch, so debug wins."""
    display = display_factory(verbose=True, debug=True)

    assert display.log_handler.level == logging.DEBUG


def test_constructor_attaches_handler_to_ash_logger(display_factory):
    display = display_factory()

    assert display.log_handler in ASH_LOGGER.handlers


def test_constructor_registers_the_three_execution_phases(display_factory):
    display = display_factory()

    assert set(display.tasks) == {
        ExecutionPhase.CONVERT,
        ExecutionPhase.SCAN,
        ExecutionPhase.REPORT,
    }
    assert display.live is None


def test_start_creates_live_display_and_stop_tears_it_down(
    display_factory, autospec_live
):
    """start() enters a Live context; stop() exits it and detaches the handler."""
    display = display_factory()

    display.start()

    assert display.live is not None
    assert display.live.__enter__.called
    assert display.log_handler in ASH_LOGGER.handlers

    entered = display.live
    display.stop()

    assert display.live is None
    entered.__exit__.assert_called_once_with(None, None, None)
    assert display.log_handler not in ASH_LOGGER.handlers


def test_start_passes_the_layout_and_console_to_the_live_display(
    display_factory, autospec_live
):
    """The Live is built against the display's own layout and console."""
    display = display_factory()

    display.start()

    kwargs = autospec_live.call_args.kwargs
    assert kwargs["console"] is display.console
    assert kwargs["refresh_per_second"] == 4
    assert kwargs["screen"] is False
    assert autospec_live.call_args.args[0] is display.layout


def test_start_is_idempotent_while_a_live_display_is_running(
    display_factory, autospec_live
):
    display = display_factory()

    display.start()
    first = display.live
    display.start()

    assert display.live is first
    assert autospec_live.call_count == 1


def test_start_does_nothing_when_progress_is_disabled(display_factory):
    display = display_factory(show_progress=False)

    display.start()

    assert display.live is None


def test_start_falls_back_to_no_progress_when_live_cannot_initialize(
    display_factory, monkeypatch
):
    """A Live that raises must degrade to non-progress mode, not propagate."""
    import automated_security_helper.core.progress as progress_module

    def _boom(*args, **kwargs):
        raise RuntimeError("no tty available")

    monkeypatch.setattr(progress_module, "Live", _boom)

    display = display_factory()
    display.start()

    assert display.show_progress is False
    assert display.live is None


def test_stop_is_a_noop_when_never_started(display_factory):
    display = display_factory()

    display.stop()

    assert display.live is None


def test_add_task_returns_none_when_progress_is_disabled(display_factory):
    display = display_factory(show_progress=False)

    assert display.add_task(ExecutionPhase.SCAN, "bandit") is None
    assert display.task_start_times == {}


def test_add_task_prefixes_the_description_with_the_upper_cased_phase(
    display_factory,
):
    display = display_factory()

    task_id = display.add_task(ExecutionPhase.CONVERT, "jupyter", total=42)

    assert task_id is not None
    task = display.progress.tasks[0]
    assert task.description == "[CONVERT] jupyter"
    assert task.total == 42
    assert task_id in display.task_start_times


def test_add_task_defaults_total_to_one_hundred(display_factory):
    display = display_factory()

    display.add_task(ExecutionPhase.REPORT, "sarif")

    assert display.progress.tasks[0].total == 100


def test_update_task_ignores_a_none_task_id(display_factory):
    display = display_factory()
    display.add_task(ExecutionPhase.SCAN, "bandit")

    display.update_task(ExecutionPhase.SCAN, None, completed=100)

    assert display.progress.tasks[0].completed == 0


def test_update_task_ignores_updates_when_progress_is_disabled(display_factory):
    display = display_factory(show_progress=False)
    disabled_task = display.progress.add_task("[SCAN] bandit", total=100)

    display.update_task(ExecutionPhase.SCAN, disabled_task, completed=100)

    assert display.progress.tasks[0].completed == 0


def test_update_task_advances_without_stopping_the_timer(display_factory):
    """A partial advance leaves the task running, so stop_time stays unset."""
    display = display_factory()
    task_id = display.add_task(ExecutionPhase.SCAN, "bandit", total=100)

    display.update_task(ExecutionPhase.SCAN, task_id, advance=25)

    task = display.progress.tasks[0]
    assert task.completed == 25
    assert task.stop_time is None


def test_update_task_at_partial_completion_leaves_the_task_running(display_factory):
    display = display_factory()
    task_id = display.add_task(ExecutionPhase.SCAN, "bandit", total=100)

    display.update_task(ExecutionPhase.SCAN, task_id, completed=50)

    task = display.progress.tasks[0]
    assert task.completed == 50
    assert task.stop_time is None


def test_update_task_at_one_hundred_percent_stops_the_task_timer(display_factory):
    """completed == 100 must also stop the task, otherwise the timer keeps ticking."""
    display = display_factory()
    task_id = display.add_task(ExecutionPhase.SCAN, "bandit", total=100)

    display.update_task(ExecutionPhase.SCAN, task_id, completed=100)

    task = display.progress.tasks[0]
    assert task.completed == 100
    assert task.stop_time is not None


def test_update_task_rewrites_the_description_with_the_phase_prefix(display_factory):
    display = display_factory()
    task_id = display.add_task(ExecutionPhase.CONVERT, "old")

    display.update_task(ExecutionPhase.REPORT, task_id, description="new")

    assert display.progress.tasks[0].description == "[REPORT] new"


def test_update_task_applies_visibility(display_factory):
    display = display_factory()
    task_id = display.add_task(ExecutionPhase.SCAN, "bandit")
    assert display.progress.tasks[0].visible is True

    display.update_task(ExecutionPhase.SCAN, task_id, visible=False)

    assert display.progress.tasks[0].visible is False


def test_add_summary_row_does_nothing_when_progress_is_disabled(display_factory):
    display = display_factory(show_progress=False)

    display.add_summary_row("scan", "Completed", "3 scanners")

    assert display.progress.tasks == []


def test_add_summary_row_marks_a_completed_row_with_the_success_emoji(display_factory):
    display = display_factory()

    display.add_summary_row("scan", "Completed", "3 scanners")

    task = display.progress.tasks[0]
    assert task.description == "[SCAN] 3 scanners - ✅ Completed"
    assert task.completed == 100
    assert task.total == 100


def test_add_summary_row_marks_a_failed_row_with_the_failure_emoji(display_factory):
    display = display_factory()

    display.add_summary_row("scan", "Failed with 2 errors", "3 scanners")

    assert display.progress.tasks[0].description == (
        "[SCAN] 3 scanners - ❌ Failed with 2 errors"
    )


def test_add_summary_row_marks_a_warning_row_with_the_warning_emoji(display_factory):
    display = display_factory()

    display.add_summary_row("report", "Warning: 1 scanner missing", "5 reporters")

    assert display.progress.tasks[0].description == (
        "[REPORT] 5 reporters - ⚠️ Warning: 1 scanner missing"
    )


def test_add_summary_row_prefers_failure_over_warning_when_both_words_appear(
    display_factory,
):
    """The Failed check runs first, so a message with both words reads as failed."""
    display = display_factory()

    display.add_summary_row("scan", "Failed after Warning", "1 scanner")

    assert "❌" in display.progress.tasks[0].description
    assert "⚠️" not in display.progress.tasks[0].description
