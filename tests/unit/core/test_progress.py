"""Tests for LiveProgressDisplay's log-level selection.

Why this exists. ``LiveProgressDisplay.__init__`` turns the ``verbose`` and
``debug`` flags into the level of the handler it attaches to ``ASH_LOGGER``, and
nothing tested that mapping. Under that gap the constructor carried a dead
branch for years: it set ``log_level = 15``, then ``if verbose: log_level = 15``.
The value was already 15, so the branch could not change anything, and no test
failed when it was deleted -- because no test looked at the level at all.

So these tests do not exist to catch the dead branch. They exist to catch the
change that gap invites next. The natural reading of the old code is that the
default was meant to be ``logging.INFO`` and ``verbose`` was meant to raise it to
VERBOSE; someone acting on that reading would lower the default and change what
every run prints, verbose or not. That is a behavior change requiring the
original author's intent, not a cleanup, so the mapping is pinned here and the
default stays at VERBOSE until someone decides otherwise on purpose.

Note on what is asserted. The tests read ``display.log_handler.level`` rather
than capturing emitted output. That is the value under test -- the level the
handler filters at -- and reading it avoids ``caplog``/``capsys`` entirely.
Worth avoiding: ``pytest.ini`` sets ``log_cli = True``, and pytest's live-logging
handler on the ``ash`` logger suspends and resumes capture around each write,
which can close a captured stream and raise ``ValueError: I/O operation on closed
file``. See ``_keep_live_logging_off_the_ash_logger`` in ``tests/conftest.py``.
"""

import logging

import pytest

from automated_security_helper.core.progress import LiveProgressDisplay
from automated_security_helper.utils.log import ASH_LOGGER

# ``utils.log`` registers VERBOSE at 15 via ``addLoggingLevel("VERBOSE", 15)``.
# Spelled as a literal here for the same reason ``progress.py`` uses one: the
# module-level ``VERBOSE_LEVEL`` reads back whatever is registered under that
# name, so it is only usually 15, and these tests are pinning the number.
VERBOSE = 15


@pytest.fixture
def make_display():
    """Build ``LiveProgressDisplay`` objects, detaching their handlers on teardown.

    ``__init__`` calls ``ASH_LOGGER.addHandler``, and ``ASH_LOGGER`` is a
    process-global logger, so a test that constructs a display and walks away
    leaks a handler into every test that follows it in the same xdist worker.
    Teardown removes only the handlers these tests added; it must not clear
    ``ASH_LOGGER.handlers``, which would also detach the session-scoped
    live-logging handler that ``tests/conftest.py`` manages.
    """
    created = []

    def _make(*, verbose: bool, debug: bool) -> LiveProgressDisplay:
        # show_progress=False keeps the Live display from taking over the
        # terminal; the level is computed regardless of that flag.
        display = LiveProgressDisplay(show_progress=False, verbose=verbose, debug=debug)
        created.append(display)
        return display

    yield _make

    for display in created:
        ASH_LOGGER.removeHandler(display.log_handler)


@pytest.mark.parametrize(
    ("verbose", "debug", "expected_level"),
    [
        (False, False, VERBOSE),
        (True, False, VERBOSE),
        (False, True, logging.DEBUG),
        (True, True, logging.DEBUG),
    ],
)
def test_log_handler_level_for_each_flag_combination(
    make_display, verbose, debug, expected_level
):
    """Every (verbose, debug) pair maps to exactly one handler level.

    VERBOSE is the floor, and ``debug`` wins wherever it is set. Lowering the
    no-flags case to INFO fails here, which is the point.
    """
    display = make_display(verbose=verbose, debug=debug)

    assert display.log_handler.level == expected_level, (
        f"verbose={verbose}, debug={debug} produced "
        f"{logging.getLevelName(display.log_handler.level)} "
        f"({display.log_handler.level}), expected "
        f"{logging.getLevelName(expected_level)} ({expected_level})"
    )


@pytest.mark.parametrize("debug", [False, True])
def test_verbose_does_not_change_the_level(make_display, debug):
    """``verbose`` is deliberately not a lever on this level.

    This is the property that made the old ``if verbose:`` branch dead, stated
    directly: the level is the same whether or not ``verbose`` is set. It is
    separate from the mapping test above because it still holds if the default
    moves -- so re-adding a ``verbose`` branch that actually does something
    fails here, while a change to the default fails the mapping test instead.
    """
    without_verbose = make_display(verbose=False, debug=debug)
    with_verbose = make_display(verbose=True, debug=debug)

    assert with_verbose.log_handler.level == without_verbose.log_handler.level


def test_verbose_is_still_recorded_on_the_instance():
    """``verbose`` survives as public state even though it sets no level.

    Deleting the dead branch left ``self.verbose = verbose`` as the parameter's
    only use. ``LiveProgressDisplay`` is public API in a published package, so
    the attribute stays whether or not this module reads it; this pins that, so
    a later "unused parameter" cleanup has to break a test rather than a caller.
    """
    display = LiveProgressDisplay(show_progress=False, verbose=True, debug=False)
    try:
        assert display.verbose is True
        assert display.debug is False
    finally:
        ASH_LOGGER.removeHandler(display.log_handler)
