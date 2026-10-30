# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A ``sends_off_host`` a reporter inherits from a mixin is read as the bool it is truthy as.

Every test of it is ``is True``. The class-creation hook read only the class's own
``__dict__``, so ``class R(OffHost, ReporterPluginBase[C])`` with a plain mixin
declaring ``sends_off_host = 1`` kept the ``1``: ``off_host_reporter_refused``
answered False and the reporter ran without ``enabled: true``.
"""

from __future__ import annotations

from typing import Literal

import pytest

from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    off_host_reporter_refused,
)

pytestmark = pytest.mark.unit


class _MixedInConfig(ReporterPluginConfigBase):
    name: Literal["low4-mixed-in"] = "low4-mixed-in"
    extension: str | None = "low4.json"


class _OffHostNumber:
    sends_off_host = 1


class _OffHostText:
    sends_off_host = "yes"


class _OffHostNothing:
    sends_off_host = 0


class _FromNumber(_OffHostNumber, ReporterPluginBase[_MixedInConfig]):
    def report(self, model) -> str:
        return ""


class _FromText(_OffHostText, ReporterPluginBase[_MixedInConfig]):
    def report(self, model) -> str:
        return ""


class _FromNothing(_OffHostNothing, ReporterPluginBase[_MixedInConfig]):
    def report(self, model) -> str:
        return ""


class _FromNumberThenSubclassed(_FromNumber):
    pass


@pytest.mark.parametrize(
    "reporter_class", [_FromNumber, _FromText, _FromNumberThenSubclassed]
)
def test_an_inherited_truthy_sends_off_host_is_declared_as_true(reporter_class):
    assert reporter_class.sends_off_host is True


def test_an_inherited_falsy_sends_off_host_is_declared_as_false():
    assert _FromNothing.sends_off_host is False


def test_the_mixin_itself_is_left_as_it_was_declared():
    assert _OffHostNumber.sends_off_host == 1
    assert _OffHostNumber.sends_off_host is not True


@pytest.mark.parametrize("reporter_class", [_FromNumber, _FromText])
def test_such_a_reporter_runs_only_when_its_section_enables_it(reporter_class):
    assert off_host_reporter_refused(reporter_class, None) is True
    assert off_host_reporter_refused(reporter_class, {"enabled": False}) is True
    assert off_host_reporter_refused(reporter_class, {"enabled": True}) is False
