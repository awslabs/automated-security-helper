"""Regression tests: rendering the live log panel must terminate.

The bug these cover: ``RichLogPanel.__rich__`` padded the panel out to
``max_lines`` rows with a ``while`` loop whose condition it never advanced. The
loop read ``len(log_list)``, where ``log_list`` is a plain list snapshot of the
deque taken once before the loop, while the body appended to the ``Table``. So
the condition was invariant and the render never returned for any buffer
occupancy in ``[1, max_lines - 1]``.

Two things made that survivable for as long as it did.

* The occupancies that terminate are the two an offhand test would pick. An
  empty buffer returns placeholder text from the ``if not self.logs`` guard
  before reaching the loop, and a saturated buffer -- ``max_lines`` records,
  which is all the deque can hold -- makes the loop condition false on entry.
  Everything between those two hangs.
* ``__rich__`` had no test at all. A non-terminating render cannot be observed
  from a passing test, only from a hanging one, and pytest reports a hang as no
  result rather than as a failure.

The second point is why these tests bound the render instead of merely calling
it. ``bounded_add_row`` caps how many times one render may call
``Table.add_row`` and raises when the cap is passed, which converts
non-termination into an ordinary assertion failure. Without that cap a
regression here would wedge the test session and grow the table until the
machine ran out of memory. ``pytest-timeout`` would be the other way to bound
it; it is not a dependency of this project and these tests do not add one.

The contract being asserted is the one the padding loop was written to
establish: a rendered panel has exactly ``max_lines`` rows at every non-empty
occupancy, so the panel occupies a fixed height in the live display and the
frame below it does not jump as records arrive.
"""

import logging

import pytest
from rich.console import Console
from rich.table import Table
from rich.text import Text

from automated_security_helper.utils.rich_log_handler import (
    LiveDisplayLogHandler,
    RichLogPanel,
)


# A terminating __rich__ calls Table.add_row exactly max_lines times per render:
# once per buffered record and once per pad row, and those two counts sum to
# max_lines because the deque's maxlen is max_lines. This cap is far above that
# for the max_lines values used below, so it cannot fire on a correct
# implementation. The non-terminating one reaches it in about a millisecond.
ADD_ROW_CALL_CAP = 1000


class RenderDidNotTerminate(AssertionError):
    """The padding loop ran past any legitimate row count for one render."""


@pytest.fixture
def bounded_add_row(monkeypatch):
    """Make a non-terminating render fail rather than hang.

    Wraps the real ``Table.add_row`` rather than replacing the ``Table`` so the
    renderable under test is a genuine rich table and the row assertions below
    are measuring the real object. ``monkeypatch`` restores the method at
    teardown.

    The counter spans the whole test, not one render, which is deliberate: it
    keeps the fixture free of any reset the test has to remember to call, and
    the legitimate totals here are two orders of magnitude under the cap.
    """
    real_add_row = Table.add_row
    calls = 0

    def counting_add_row(self, *args, **kwargs):
        nonlocal calls
        calls += 1
        if calls > ADD_ROW_CALL_CAP:
            raise RenderDidNotTerminate(
                f"Table.add_row was called more than {ADD_ROW_CALL_CAP} times; "
                "the padding loop in RichLogPanel.__rich__ is not advancing "
                "its condition."
            )
        return real_add_row(self, *args, **kwargs)

    monkeypatch.setattr(Table, "add_row", counting_add_row)


def _panel_with(occupancy: int, max_lines: int = 15) -> RichLogPanel:
    """Return a panel holding ``occupancy`` records at assorted levels."""
    panel = RichLogPanel(max_lines=max_lines)
    levels = [
        logging.CRITICAL,
        logging.ERROR,
        logging.WARNING,
        logging.INFO,
        15,  # VERBOSE
        logging.DEBUG,
        5,  # TRACE
    ]
    for index in range(occupancy):
        panel.add_log(f"record {index}", levels[index % len(levels)])
    return panel


@pytest.mark.parametrize("occupancy", [1, 2, 7, 14])
def test_render_terminates_at_partial_occupancy(occupancy, bounded_add_row):
    """Every occupancy strictly between empty and saturated must render.

    This is the defect's whole reachable range. It is parameterized rather than
    written once at a single occupancy because the two endpoints of the range
    are the ones that used to terminate by accident.
    """
    panel = _panel_with(occupancy)

    rendered = panel.__rich__()

    assert isinstance(rendered, Table)
    assert rendered.row_count == 15


def test_render_of_an_empty_panel_returns_placeholder_text(bounded_add_row):
    """An empty buffer keeps its early return; it never reaches the table."""
    rendered = RichLogPanel(max_lines=15).__rich__()

    assert isinstance(rendered, Text)
    assert rendered.plain == "No log messages"


def test_render_of_a_saturated_panel_adds_no_padding(bounded_add_row):
    """A full deque needs no pad rows, and must not grow past max_lines."""
    panel = _panel_with(15)

    rendered = panel.__rich__()

    assert isinstance(rendered, Table)
    assert rendered.row_count == 15


def test_padding_does_not_displace_the_buffered_records(bounded_add_row):
    """The pad rows are additional to the records, not a replacement for them.

    Fifteen blank rows would satisfy the row count on its own, so this renders
    the panel through a console and asserts the resolved line-by-line output:
    the records first, in arrival order and carrying their own level labels,
    then the padding. That also pins the contract at the level an operator sees
    -- the panel occupies ``max_lines`` terminal lines regardless of occupancy.
    """
    panel = _panel_with(3)
    console = Console(width=80, force_terminal=False, no_color=True)

    with console.capture() as capture:
        console.print(panel)
    lines = capture.get().splitlines()

    assert len(lines) == 15
    assert [line.split() for line in lines[:3]] == [
        ["CRIT", "record", "0"],
        ["ERR", "record", "1"],
        ["WARN", "record", "2"],
    ]
    assert [line.strip() for line in lines[3:]] == [""] * 12


def test_render_terminates_for_a_record_arriving_through_the_handler(
    bounded_add_row,
):
    """Cover the path the live display actually takes.

    ``LiveProgressDisplay`` attaches a ``LiveDisplayLogHandler`` to the ASH
    logger and then logs, which is how the buffer reaches occupancy 1 -- the
    first occupancy that used to hang -- before rich's next refresh renders the
    panel. Going through the handler rather than calling ``add_log`` directly is
    what makes this the reachability test rather than a second unit test of the
    same loop.
    """
    panel = RichLogPanel(max_lines=15)
    logger = logging.getLogger("test_rich_log_handler_render")
    logger.setLevel(logging.INFO)
    handler = LiveDisplayLogHandler(panel, level=logging.INFO)
    logger.addHandler(handler)
    try:
        logger.info("scan started")
    finally:
        logger.removeHandler(handler)

    rendered = panel.__rich__()

    assert isinstance(rendered, Table)
    assert rendered.row_count == 15


@pytest.mark.parametrize("max_lines", [1, 2, 5, 30])
def test_row_count_tracks_max_lines(max_lines, bounded_add_row):
    """The padded height follows the configured height, at one record in.

    ``max_lines=1`` is the boundary where a single record saturates the deque,
    so it is the one non-empty occupancy that terminated under the old loop for
    every configuration.
    """
    panel = _panel_with(1, max_lines=max_lines)

    rendered = panel.__rich__()

    assert isinstance(rendered, Table)
    assert rendered.row_count == max_lines
