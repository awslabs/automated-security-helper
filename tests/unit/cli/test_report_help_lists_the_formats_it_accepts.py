# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash report --help`` lists the formats ``ash report --format`` accepts.

A format listed plainly is accepted with the default configuration.
``aggregated``, ``dict``, ``asff`` and ``custom``, which no reporter writes and
which ``--format`` refuses with exit 5, are not listed. The AWS plugin module's
reporters are listed apart: each is accepted once the configuration's
``ash_plugin_modules`` loads that module, and refused with exit 5 otherwise.
"""

from __future__ import annotations

import importlib
import pkgutil
import re

import pytest
import typer

from automated_security_helper.base.reporter_plugin import ReporterPluginConfigBase
from automated_security_helper.core.constants import ASH_EXIT_USAGE_ERROR
from automated_security_helper.core.enums import ExportFormat
from tests.unit.cli.test_report_format_output import _report, _write_results

pytestmark = pytest.mark.unit

AWS_MODULE = "automated_security_helper.plugin_modules.ash_aws_plugins"
FORMATS = sorted(fmt.value for fmt in ExportFormat)


def _format_help() -> str:
    from automated_security_helper.cli.main import app

    report = typer.main.get_command(app).commands["report"]
    option = next(param for param in report.params if "--format" in param.opts)
    return option.help or ""


def _listed() -> tuple[set, set]:
    """(the formats the help lists as accepted, those it lists for the AWS
    module): format names in the help before and after the module's name."""
    text = _format_help()
    plain, _, module = text.partition("ash_aws_plugins")

    def formats(part: str) -> set:
        return {word for word in re.split(r"[^a-z0-9-]+", part) if word in FORMATS}

    return formats(plain), formats(module)


def _aws_module_reporter_names() -> set:
    package = importlib.import_module(AWS_MODULE)
    for module in pkgutil.iter_modules(package.__path__):
        importlib.import_module(f"{AWS_MODULE}.{module.name}")
    names = set()
    pending = list(ReporterPluginConfigBase.__subclasses__())
    while pending:
        cls = pending.pop()
        pending.extend(cls.__subclasses__())
        field = cls.model_fields.get("name")
        if cls.__module__.startswith(AWS_MODULE) and isinstance(field.default, str):
            names.add(field.default)
    return names


@pytest.mark.parametrize("fmt", FORMATS)
def test_a_format_is_listed_exactly_when_it_is_accepted(tmp_path, fmt):
    plain, _ = _listed()
    _write_results(tmp_path)
    accepted = _report(tmp_path, fmt).exit_code != ASH_EXIT_USAGE_ERROR
    # Booleans, so a failure names the format and the two answers only.
    assert (fmt in plain) == accepted, (fmt, fmt in plain, accepted)


def test_the_aws_module_s_reporters_are_listed_with_it():
    """Not run: they need AWS. Each is a reporter of that module, by name."""
    _, module = _listed()
    names = _aws_module_reporter_names()
    assert names, "the control: the AWS module defines reporters"
    assert module == names, (sorted(module), sorted(names))
