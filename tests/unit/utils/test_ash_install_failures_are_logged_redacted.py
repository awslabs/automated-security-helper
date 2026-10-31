# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The install metadata reads log a failure's traceback redacted.

``ash_install`` reads the installed distributions' metadata and, when one read
fails, logs the cause at debug level and goes on. The cause used to ride on the
record as ``exc_info``, so the handler printed the raw traceback, whose last line
repeats the error's message with any value the error carries. The project's own
rule is that a traceback is formatted by ``traceback_text`` with the values the
error carries, and these cases hold the three sites to it.
"""

from __future__ import annotations

import pytest

from automated_security_helper.utils import ash_install
from automated_security_helper.utils.error_text import carry_environment_values

pytestmark = pytest.mark.unit

SECRET = "tok-9f3a1c77e0b24d58"


class _Recorder:
    """Stands in for ``ASH_LOGGER``: the debug calls, as made."""

    def __init__(self):
        self.calls = []

    def debug(self, message, *args, **kwargs):
        self.calls.append((message, kwargs))


@pytest.fixture
def logged(monkeypatch):
    recorder = _Recorder()
    monkeypatch.setattr(ash_install, "ASH_LOGGER", recorder)
    return recorder.calls


def _failure(kind=ValueError):
    error = kind(f"could not read {SECRET}")
    carry_environment_values(error, [SECRET])
    return error


def _one_record(logged):
    assert len(logged) == 1, logged
    message, kwargs = logged[0]
    # The raw traceback rides on no record: the handler would print it whole.
    assert "exc_info" not in kwargs, kwargs
    assert SECRET not in message, message
    # The traceback itself is kept, with the error's type in it.
    assert "Traceback" in message, message
    return message


def test_a_failed_enumeration_of_distributions_logs_a_redacted_traceback(
    logged, monkeypatch
):
    def _fail():
        raise _failure(KeyError)

    monkeypatch.setattr(ash_install, "packages_distributions", _fail)
    ash_install._distributions_declaring_this_module(ash_install._ROOT_PACKAGE)
    assert "KeyError" in _one_record(logged)


def test_a_distribution_whose_requirements_cannot_be_read_logs_a_redacted_traceback(
    logged, monkeypatch
):
    class _Broken:
        @property
        def requires(self):
            raise _failure(OSError)

    monkeypatch.setattr(ash_install, "_distributions_to_read", lambda name: [_Broken()])
    assert ash_install._requirements_declared("anything") == []
    assert "OSError" in _one_record(logged)


def test_a_distribution_that_cannot_be_read_at_all_logs_a_redacted_traceback(
    logged, monkeypatch
):
    def _fail(dist_name):
        raise _failure(ValueError)

    monkeypatch.setattr(
        ash_install, "_distributions_declaring_this_module", lambda root: ["somedist"]
    )
    monkeypatch.setattr(ash_install, "_requirements_declared", _fail)
    assert ash_install.extra_requirements_from_metadata("cdk") is None
    assert "ValueError" in _one_record(logged)
