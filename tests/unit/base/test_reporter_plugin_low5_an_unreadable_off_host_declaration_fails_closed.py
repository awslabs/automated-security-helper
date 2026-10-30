# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``sends_off_host`` declaration the class cannot answer reads as True.

The declaration is read off the class when the reporter class is created, and
every test of it is ``is True``. A ``property`` comes back from the class as the
property object, which is truthy and not a bool, so it is converted to ``True``:
a reporter whose answer is not known before it is built runs only when its
section enables it, never as a local one. These tests pin that reading.
"""

from __future__ import annotations

import pytest

from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    off_host_reporter_refused,
)

pytestmark = pytest.mark.unit


class _AsksAtRunTime:
    """A plain mixin that declares the answer as a property."""

    @property
    def sends_off_host(self) -> bool:
        return False


class _Reporter(_AsksAtRunTime, ReporterPluginBase[ReporterPluginConfigBase]):
    def report(self, model) -> str:
        return ""


def test_a_property_declaration_reads_as_true_on_the_class():
    assert _Reporter.sends_off_host is True


def test_such_a_reporter_runs_only_when_its_section_enables_it():
    assert off_host_reporter_refused(_Reporter, None) is True
    assert off_host_reporter_refused(_Reporter, {"enabled": True}) is False


def test_a_reporter_that_declares_nothing_stays_local():
    class _Plain(ReporterPluginBase[ReporterPluginConfigBase]):
        def report(self, model) -> str:
            return ""

    assert _Plain.sends_off_host is False
