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
  between the two raises ``KeyError`` in the copying thread.

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


def apply_environ_overrides(
    overrides: Mapping[str, Optional[str]],
) -> Dict[str, Optional[str]]:
    """Set (or, for a ``None`` value, remove) variables; return what they were.

    Hand the return value to :func:`restore_environ` to undo the change. For
    call sites that need the change to span a ``try``/``finally`` they already
    have; everything else should use :func:`environ_overrides`.
    """
    with ENVIRON_LOCK:
        previous = {key: os.environ.get(key) for key in overrides}
        for key, value in overrides.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
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
