# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The forward reference is imported before the resolver's lock is taken.

The last line of ``config/ash_config.py`` calls the model's resolver. With the
import inside the lock, a thread importing that module held its import lock and
then asked for the resolver's lock, while a thread that first used the model held
the resolver's lock and asked for the import lock: a deadlock. The import now runs
first, in the shared ``base.forward_refs.OnceOnlyResolver`` both models call.

Measured by behavior, with a probe that cannot hang: the resolver's lock is
reentrant, so only another thread can tell whether it is held. ``import_target``
starts a thread that tries ``acquire(blocking=False)`` and joins it with a
timeout; a thread that got the lock proves the import ran outside it. A control
runs the same probe inside ``bind``, which does run under the lock, so the probe
is shown to tell the two apart.
"""

from __future__ import annotations

import threading

import pytest

from automated_security_helper.base.forward_refs import OnceOnlyResolver

pytestmark = pytest.mark.unit


def _another_thread_got_the_lock(resolver: OnceOnlyResolver) -> bool:
    """Whether a second thread can take the resolver's lock right now."""
    outcome: list[bool] = []

    def _probe() -> None:
        got = resolver._lock.acquire(blocking=False)
        outcome.append(got)
        if got:
            resolver._lock.release()

    thread = threading.Thread(target=_probe, daemon=True)
    thread.start()
    thread.join(timeout=10)
    assert not thread.is_alive(), "the probe thread did not finish"
    assert len(outcome) == 1, outcome
    return outcome[0]


def test_the_import_runs_outside_the_lock():
    resolver: OnceOnlyResolver[str] = OnceOnlyResolver()
    seen: list[bool] = []

    def _import() -> str:
        seen.append(_another_thread_got_the_lock(resolver))
        return "target"

    resolver.resolve(_import, lambda target: None)

    assert seen == [True], "the import ran while the lock was held"


def test_the_bind_runs_under_the_lock():
    """The control: the same probe inside ``bind`` finds the lock held."""
    resolver: OnceOnlyResolver[str] = OnceOnlyResolver()
    seen: list[bool] = []

    resolver.resolve(
        lambda: "target",
        lambda target: seen.append(_another_thread_got_the_lock(resolver)),
    )

    assert seen == [False], "the bind ran without the lock"


def test_resolved_is_set_only_after_bind_returned():
    resolver: OnceOnlyResolver[str] = OnceOnlyResolver()
    during_bind: list[bool] = []

    resolver.resolve(
        lambda: "target", lambda target: during_bind.append(resolver.resolved)
    )

    assert during_bind == [False]
    assert resolver.resolved is True


def test_an_import_error_binds_nothing_and_a_later_call_resolves():
    resolver: OnceOnlyResolver[str] = OnceOnlyResolver()
    bound: list[str] = []

    def _not_yet() -> str:
        raise ImportError("mid-cycle")

    resolver.resolve(_not_yet, bound.append)

    assert resolver.resolved is False and bound == []

    resolver.resolve(lambda: "target", bound.append)
    resolver.resolve(lambda: "again", bound.append)

    assert resolver.resolved is True
    assert bound == ["target"], "bind must run once"
