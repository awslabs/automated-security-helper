# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``OnceOnlyResolver.resolve`` says at debug level which ImportError it swallowed.

The resolver treats every ImportError from its import as "the target is not
importable yet" and returns, so a later call can try again. That is right in the
import cycle it exists for, but it also hid an ImportError of another kind (a
dependency of the target that is missing) without a trace. The control flow is
unchanged; the text of the error is logged.
"""

from __future__ import annotations

import logging

import pytest

from automated_security_helper.base.forward_refs import OnceOnlyResolver

pytestmark = pytest.mark.unit

LOGGER_NAME = "automated_security_helper.base.forward_refs"


def _raising(message: str):
    def import_target():
        raise ImportError(message)

    return import_target


def test_a_swallowed_import_error_is_logged_at_debug(caplog):
    resolver = OnceOnlyResolver()
    bound = []

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        result = resolver.resolve(
            _raising("cannot import name 'Target' (partially initialized)"),
            bound.append,
        )

    assert result is None
    assert resolver.resolved is False
    assert bound == []
    messages = [
        record.getMessage() for record in caplog.records if record.name == LOGGER_NAME
    ]
    assert len(messages) == 1, messages
    assert "cannot import name 'Target' (partially initialized)" in messages[0]
    assert [r.levelno for r in caplog.records if r.name == LOGGER_NAME] == [
        logging.DEBUG
    ]


def test_a_later_call_still_resolves_once_the_import_works(caplog):
    resolver = OnceOnlyResolver()
    bound = []

    with caplog.at_level(logging.DEBUG, logger=LOGGER_NAME):
        resolver.resolve(_raising("not yet"), bound.append)
        resolver.resolve(lambda: "the target", bound.append)
        resolver.resolve(_raising("never asked again"), bound.append)

    assert bound == ["the target"]
    assert resolver.resolved is True
    messages = [
        record.getMessage() for record in caplog.records if record.name == LOGGER_NAME
    ]
    assert len(messages) == 1 and "not yet" in messages[0], messages
