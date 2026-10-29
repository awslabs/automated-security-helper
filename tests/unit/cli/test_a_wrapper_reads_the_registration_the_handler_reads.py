# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The shutdown registration the signal handlers read is readable by callers.

The SIGTERM handler cooperates only while a scan is registered through
``shutdown_cancels``; with none it keeps SIGTERM's kill semantics and dies at
once. A wrapper deciding whether to leave the handler in charge has to read
that same condition. The ambient cancel event is not it: ``cancel_scope``
has a different owner (the module docstring's split), so a scope can be
active with nothing registered, and a wrapper gating on the event then keeps
a handler that will take the no-scan die-now on the first signal.

``shutdown_scopes_registered`` answers the handler's own question -- is
anything registered right now -- so both sides gate on one condition.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core import cancellation
from automated_security_helper.core.cancellation import (
    CancelEvent,
    cancel_scope,
    shutdown_cancels,
    shutdown_scopes_registered,
)


@pytest.fixture
def no_registrations(monkeypatch):
    """The registration tuple empty, as a fresh process starts."""
    monkeypatch.setattr(cancellation, "_SHUTDOWN_SCOPES", ())
    monkeypatch.setattr(cancellation, "_SHUTDOWN_REQUESTED", False)


def test_nothing_registered_reads_false(no_registrations):
    assert shutdown_scopes_registered() is False


def test_a_registered_scope_reads_true_until_it_exits(no_registrations):
    event = CancelEvent()
    with shutdown_cancels(event):
        assert shutdown_scopes_registered() is True
    assert shutdown_scopes_registered() is False, (
        "the registration ended with its scope, so a wrapper reading it late "
        "must see what the handler sees"
    )


def test_an_ambient_cancel_scope_alone_is_not_a_registration(no_registrations):
    """The condition is the handler's, not the event's.

    A cancel scope with no registration is the state where the first SIGTERM
    takes the no-scan die-now; a wrapper that read the ambient event here
    would keep the handler in charge of a kill it does not soften.
    """
    event = CancelEvent()
    with cancel_scope(event):
        assert shutdown_scopes_registered() is False


def test_nested_registrations_read_true_until_the_last_exits(no_registrations):
    outer = CancelEvent()
    inner = CancelEvent()
    with shutdown_cancels(outer):
        with shutdown_cancels(inner):
            assert shutdown_scopes_registered() is True
        assert shutdown_scopes_registered() is True, (
            "one registration remains, and the handler still cooperates"
        )
    assert shutdown_scopes_registered() is False
