"""One lock for every runtime change to ``os.environ``, and a safe copy of it.

Why this exists. On Linux, CPython 3.10+ starts children with ``vfork``. When a
spawn passes ``env=None`` the child calls ``execv`` with the parent's live
``environ`` array, and until ``execve`` returns that memory is shared with the
parent. ASH runs scanners in parallel threads, and some of them change the
environment while they work (``cdk_nag_wrapper`` sets and removes three JSII
variables around every template). A ``setenv``/``unsetenv`` in one thread while
another thread's child sits between ``vfork`` and ``execve`` lets glibc
reallocate and free the array the child is reading, and ``execve`` fails with
``[Errno 14] Bad address`` (EFAULT). In CI that showed up as cfn-nag recording
"returned no stdout" for a template, and a rerun passing.

The fix has two halves and needs both:

* Every spawn ASH makes passes an explicit ``env``. The child then gets an
  ``envp`` that ``_posixsubprocess`` built from a dict, which no other thread can
  free. ``snapshot_environ()`` is how a spawn site gets that dict.
* Every runtime mutation goes through this module, under ``ENVIRON_LOCK``, so a
  snapshot is never taken halfway through someone else's change. Copying
  ``os.environ`` reads the key list and then each value, so a concurrent ``pop``
  between the two raises ``KeyError`` in the copying thread, and a copy taken
  during a multi-variable override gets some of its values and not others.
  So every copy goes through ``snapshot_environ()`` too, not only a spawn's:
  ``tests/unit/utils/test_environ_mutations_are_locked.py`` refuses a write
  outside this module and ``test_environ_copies_are_locked.py`` any read of the
  whole mapping (a copy, ``**`` or ``|``, iteration, ``env=os.environ``, an
  alias, or the mapping handed to a function).

The lock is held only while variables are written or copied, never across the
work done with them. ``cdk_nag_wrapper`` keeps its own lock to serialize whole
evaluations; holding this one that long would stall every other scanner's spawn
behind a cdk-nag run.

Known limitation: third-party code that spawns with ``env=None`` still hands its
child the live array. JSII, the one library ASH drives while variables are being
changed, copies ``os.environ`` and passes ``env=`` itself.
"""

import os
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Dict, Iterator, Mapping, Optional

#: Re-entrant so a helper here can call another helper here without deadlocking.
ENVIRON_LOCK = threading.RLock()


def snapshot_environ() -> Dict[str, str]:
    """A plain-dict copy of the environment, taken under ``ENVIRON_LOCK``.

    Pass this as ``env=`` to a spawn that would otherwise inherit the live
    environment. The child sees the same variables it would have inherited.
    """
    with ENVIRON_LOCK:
        return dict(os.environ)


#: The environment as this module was first imported: the operator's own
#: variables, before any scanner ran (every plugin imports this module through
#: plugin_base before a scanner instance exists).
_STARTUP_ENVIRON: Dict[str, str] = snapshot_environ()


def startup_environ() -> Dict[str, str]:
    """A copy of the environment as it was when ASH started.

    For a reader that must take only the operator's own value of a variable
    and never one a scanner thread set, or set for a moment, while others
    spawn (the sandbox-exec backend grants a read of the operator's
    SSL_CERT_FILE, and must not grant one for a value a scanner put there).
    ``snapshot_environ`` answers what a child would inherit now; this answers
    what the operator started ASH with.
    """
    return dict(_STARTUP_ENVIRON)


#: The variables that set how a child lays text out and colors it for a terminal.
#: uv wraps its messages at the caller's COLUMNS and colors them under FORCE_COLOR
#: or CLICOLOR_FORCE even into a pipe (measured with uv 0.13), so text ASH parses
#: came back split across lines or wrapped in escape codes.
DISPLAY_VARIABLES = (
    "COLUMNS",
    "LINES",
    "FORCE_COLOR",
    "CLICOLOR_FORCE",
    "TTY_COMPATIBLE",
    "TTY_INTERACTIVE",
)


def environ_for_parsed_output(
    env: Optional[Mapping[str, str]] = None,
) -> Dict[str, str]:
    """The environment for a child whose output ASH parses: ``env``, or a snapshot
    of the environment when it is None, without ``DISPLAY_VARIABLES`` and with
    ``NO_COLOR=1``, which stops uv's color even alongside FORCE_COLOR.

    A new dict; ``env`` is left as it was.
    """
    parsed = dict(env) if env is not None else snapshot_environ()
    for name in DISPLAY_VARIABLES:
        parsed.pop(name, None)
    parsed["NO_COLOR"] = "1"
    return parsed


def apply_environ_overrides(
    overrides: Mapping[str, Optional[str]],
) -> Dict[str, Optional[str]]:
    """Set (or, for a ``None`` value, remove) variables; return what they were.

    Hand the return value to :func:`restore_environ` to undo the change. For
    call sites that need the change to span a ``try``/``finally`` they already
    have; everything else should use :func:`environ_overrides`.

    All or nothing: when an assignment raises (a value that is not a str, a
    name the platform refuses), the variables set before it are put back
    before the error is raised, since the caller never receives the previous
    values to put them back itself.
    """
    with ENVIRON_LOCK:
        previous = {key: os.environ.get(key) for key in overrides}
        done: Dict[str, Optional[str]] = {}
        try:
            for key, value in overrides.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
                done[key] = previous[key]
        except BaseException:
            restore_environ(done)
            raise
        return previous


def restore_environ(previous: Mapping[str, Optional[str]]) -> None:
    """Put back the values :func:`apply_environ_overrides` returned.

    A variable that did not exist before is removed again.
    """
    with ENVIRON_LOCK:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@contextmanager
def environ_overrides(
    overrides: Mapping[str, Optional[str]],
) -> Iterator[None]:
    """Apply ``overrides`` for the body of the ``with`` block, then restore them.

    The lock is taken to apply and again to restore, not held across the body.
    """
    previous = apply_environ_overrides(overrides)
    try:
        yield
    finally:
        restore_environ(previous)


@dataclass
class _Hold:
    """One variable hold_environ holds."""

    value: str
    holders: int
    #: The variable's value before the first hold, None when it was unset.
    original: Optional[str]


#: Variables held by hold_environ, by name.
_HELD: Dict[str, _Hold] = {}


def hold_environ(key: str, value: str) -> None:
    """Set ``key`` to ``value`` for as long as at least one caller holds it.

    For a change that several overlapping callers each need, such as
    ``ASH_OFFLINE=YES`` for two offline scans in one process. Snapshot and restore
    (:func:`apply_environ_overrides`) breaks there: the first caller to finish
    restores the value it saw while the other is still running, and the last one
    restores the first one's change. Here the first holder records the original
    value and sets the variable, and the last :func:`release_environ` puts the
    original back.

    Raises ValueError if the variable is already held at a different value, since
    two holders cannot both have their way.
    """
    with ENVIRON_LOCK:
        held = _HELD.get(key)
        if held is not None and held.value != value:
            raise ValueError(
                f"{key} is held at {held.value!r}; it cannot also be held at {value!r}"
            )
        # The variable is set before the hold is recorded: a set that raises (a
        # value that is not a str) leaves no hold behind that no caller would
        # release.
        original = os.environ.get(key)
        os.environ[key] = value
        if held is None:
            _HELD[key] = _Hold(value=value, holders=1, original=original)
        else:
            held.holders += 1


def release_environ(key: str) -> None:
    """Release one :func:`hold_environ` of ``key``; the last restores its original.

    Raises RuntimeError if nobody holds it, which is a hold and release that do not
    pair up.
    """
    with ENVIRON_LOCK:
        held = _HELD.get(key)
        if held is None:
            raise RuntimeError(f"{key} is released but not held")
        held.holders -= 1
        if held.holders:
            return
        del _HELD[key]
        original = held.original
        if original is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = original


def setdefault_environ(key: str, value: str) -> str:
    """``os.environ.setdefault`` under ``ENVIRON_LOCK``."""
    with ENVIRON_LOCK:
        return os.environ.setdefault(key, value)


def set_environ(key: str, value: str) -> None:
    """``os.environ[key] = value`` under ``ENVIRON_LOCK``, left in place.

    For a setting the process keeps for the rest of its life. Use
    :func:`environ_overrides` when the change should be undone.
    """
    with ENVIRON_LOCK:
        os.environ[key] = value
