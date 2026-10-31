# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What a reporter declares about itself is read the way the code that uses it reads it.

``sends_off_host`` is tested with ``is True`` at every site that acts on it, so a
reporter declaring it with a truthy value that is not a bool (``1``, ``"yes"``) was
run as a local one, without ``enabled: true``. And ``configure`` assigned the config
it was given as it was, where the ``config`` field holds a config given at
construction to the model the reporter declares.
"""

from __future__ import annotations

from typing import Literal

import pytest
from pydantic import ValidationError

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    off_host_reporter_refused,
)
from automated_security_helper.config.ash_config import AshConfig

pytestmark = pytest.mark.unit


class _DeclaredConfig(ReporterPluginConfigBase):
    name: Literal["low-declared"] = "low-declared"
    extension: str | None = "low.json"


class _Declared(ReporterPluginBase[_DeclaredConfig]):
    def report(self, model) -> str:
        return ""


class _TruthyNumber(_Declared):
    sends_off_host = 1  # type: ignore[assignment]


class _TruthyText(_Declared):
    sends_off_host = "yes"  # type: ignore[assignment]


class _Falsy(_Declared):
    sends_off_host = 0  # type: ignore[assignment]


@pytest.mark.parametrize("reporter_class", [_TruthyNumber, _TruthyText])
def test_a_truthy_sends_off_host_is_declared_as_true(reporter_class):
    assert reporter_class.sends_off_host is True


def test_a_falsy_sends_off_host_is_declared_as_false():
    assert _Falsy.sends_off_host is False
    assert _Declared.sends_off_host is False


@pytest.mark.parametrize("reporter_class", [_TruthyNumber, _TruthyText])
def test_such_a_reporter_runs_only_when_its_section_enables_it(reporter_class):
    assert off_host_reporter_refused(reporter_class, None) is True
    assert off_host_reporter_refused(reporter_class, {"enabled": True}) is False


def _reporter(tmp_path) -> _Declared:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "work",
        config=AshConfig(),
    )
    return _Declared(context=context)


def test_configure_reads_a_generic_section_through_the_declared_model(tmp_path):
    reporter = _reporter(tmp_path)

    reporter.configure(
        ReporterPluginConfigBase(name="low-declared", extension="given.json")
    )

    assert isinstance(reporter.config, _DeclaredConfig)
    assert reporter.config.extension == "given.json"


def test_configure_refuses_a_section_the_declared_model_refuses(tmp_path):
    reporter = _reporter(tmp_path)

    with pytest.raises(ValidationError):
        reporter.configure(ReporterPluginConfigBase(name="another-reporter"))

    assert isinstance(reporter.config, _DeclaredConfig)
    assert reporter.config.name == "low-declared"


def test_configure_keeps_a_config_of_the_declared_model(tmp_path):
    reporter = _reporter(tmp_path)
    given = _DeclaredConfig(extension="kept.json")

    reporter.configure(given)

    assert reporter.config is given


def test_configure_with_nothing_changes_nothing(tmp_path):
    reporter = _reporter(tmp_path)
    before = reporter.config

    reporter.configure(None)

    assert reporter.config is before
