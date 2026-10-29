# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every reporter ASH ships can be named on ``--output-formats``.

Why this exists
---------------
``ash scan -f`` and ``ash merge --output-formats`` validate each name against
``ExportFormat``, and a reporter is then selected by its configured ``name``
(``base/reporter_plugin.py``). Nothing tied the two together. ``ExportFormat`` had
no member for four built-in reporters that run by default -- ``github-ghas``,
``gitlab-sast``, ``gitlab-cyclonedx`` and ``unused-suppressions`` -- nor for the
four AWS reporters. Naming one of them was refused as "not a valid format" (exit
2), so an operator could not ask for ``sarif,github-ghas``; and because any ``-f``
list is a filter, every ``-f`` list silently turned all eight off.

The names here are read from the reporter classes themselves rather than typed
out, so a reporter added without a matching ``ExportFormat`` member fails
:func:`test_every_shipped_reporter_name_is_an_export_format` instead of shipping
unselectable. :func:`test_no_reporter_ships_outside_the_enumerated_packages` keeps
that enumeration honest: a reporter class defined anywhere else under
``plugin_modules`` would escape the check, so its existence fails the test.

Known limitations
-----------------
* Reporters from a third-party plugin module (``ash_plugin_modules``) are not
  covered. Their names are unknown until the module is imported, which happens
  after the command line is parsed, so ``-f`` cannot accept them without moving
  typo detection to after the scan has started.
* The AWS reporter names are accepted on the command line whether or not
  ``ash_plugin_modules`` loads the AWS module. When it does not, the report phase
  logs that no reporter in the run has that name, as it does for ``asff``.
"""

import ast
import typing
from pathlib import Path
from types import SimpleNamespace
from typing import Dict, List
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

import automated_security_helper.plugin_modules as plugin_modules
import automated_security_helper.plugin_modules.ash_aws_plugins as aws_plugins
import automated_security_helper.plugin_modules.ash_builtin.reporters as builtin_reporters
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    reporter_matches_requested_formats,
)
from automated_security_helper.cli.main import app
from automated_security_helper.cli.merge import _parse_output_formats
from automated_security_helper.cli.report import get_report_formats
from automated_security_helper.core.enums import ExportFormat

pytestmark = pytest.mark.unit

RUN_ASH_SCAN = "automated_security_helper.cli.scan.run_ash_scan"

#: The packages whose reporter classes ASH ships. Importing them fires the
#: ``@ash_reporter_plugin`` decorators, which is the registration a scan relies on.
REPORTER_PACKAGES = (builtin_reporters, aws_plugins)

PLUGIN_MODULES_DIR = Path(plugin_modules.__file__).resolve().parent

#: The names this change made selectable. Spelled out once, for the assertion that
#: they are among the derived names, so that a derivation that silently found
#: nothing cannot pass.
PREVIOUSLY_UNSELECTABLE = (
    "aws-security-hub",
    "bedrock-summary-reporter",
    "cloudwatch-logs",
    "github-ghas",
    "gitlab-cyclonedx",
    "gitlab-sast",
    "s3",
    "unused-suppressions",
)


def _shipped_reporter_classes() -> Dict[str, type]:
    """Class name -> class, for every reporter class the shipped packages export."""
    found: Dict[str, type] = {}
    for package in REPORTER_PACKAGES:
        for value in vars(package).values():
            if (
                isinstance(value, type)
                and issubclass(value, ReporterPluginBase)
                and value is not ReporterPluginBase
            ):
                found[value.__name__] = value
    return found


def _default_config(reporter_class: type):
    """The config a reporter has when the operator configures nothing.

    Read from the ``config`` field's declared type, the same way
    ``scripts/generate_reporter_docs.py`` reads it, because building a reporter
    instance needs a plugin context and this does not.
    """
    field = reporter_class.model_fields["config"]
    args = [a for a in typing.get_args(field.annotation) if a is not type(None)]
    config_class = args[0] if args else field.annotation
    return config_class()


def _shipped_reporter_names() -> List[str]:
    return sorted(
        _default_config(cls).name for cls in _shipped_reporter_classes().values()
    )


SHIPPED_REPORTER_NAMES = _shipped_reporter_names()


def _decorated_reporter_class_names() -> Dict[str, Path]:
    """Every class under ``plugin_modules`` decorated ``@ash_reporter_plugin``.

    Found by parsing rather than importing, so the community plugin modules (which
    register scanners process-wide when imported) are not loaded by this test.
    """
    found: Dict[str, Path] = {}
    for path in sorted(PLUGIN_MODULES_DIR.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            for decorator in node.decorator_list:
                target = (
                    decorator.func if isinstance(decorator, ast.Call) else decorator
                )
                name = getattr(target, "id", None) or getattr(target, "attr", None)
                if name == "ash_reporter_plugin":
                    found[node.name] = path
    return found


def test_the_enumeration_found_the_reporters():
    """Guards the derivation itself: an empty or partial walk would pass vacuously."""
    assert len(SHIPPED_REPORTER_NAMES) == len(set(SHIPPED_REPORTER_NAMES))
    for name in PREVIOUSLY_UNSELECTABLE:
        assert name in SHIPPED_REPORTER_NAMES
    for name in ("sarif", "markdown", "flat-json"):
        assert name in SHIPPED_REPORTER_NAMES


def test_no_reporter_ships_outside_the_enumerated_packages():
    """A reporter class outside :data:`REPORTER_PACKAGES` would escape every check here."""
    decorated = _decorated_reporter_class_names()
    exported = _shipped_reporter_classes()

    missing = {
        name: str(path.relative_to(PLUGIN_MODULES_DIR))
        for name, path in decorated.items()
        if name not in exported
    }
    assert not missing, (
        f"reporter classes not exported by any package in REPORTER_PACKAGES: "
        f"{missing}. Export them, or add their package to REPORTER_PACKAGES, so "
        f"their names are checked against ExportFormat."
    )


@pytest.mark.parametrize("name", SHIPPED_REPORTER_NAMES)
def test_every_shipped_reporter_name_is_an_export_format(name):
    """The name a reporter is selected by is a value ``--output-formats`` accepts."""
    valid = sorted(fmt.value for fmt in ExportFormat)
    assert name in valid, (
        f"reporter '{name}' cannot be named on --output-formats: ExportFormat has "
        f"no member with that value. Add one in core/enums.py. Valid now: {valid}"
    )


@pytest.mark.parametrize(
    "reporter_class",
    sorted(_shipped_reporter_classes().values(), key=lambda cls: cls.__name__),
    ids=lambda cls: cls.__name__,
)
def test_the_accepted_name_selects_its_reporter(reporter_class):
    """The ``ExportFormat`` member for a reporter's name is what selects it.

    A stand-in carrying the reporter's default config, because selection reads
    only ``config.name`` and constructing the AWS reporters is not needed to
    show that.
    """
    config = _default_config(reporter_class)
    stand_in = SimpleNamespace(config=config)

    assert reporter_matches_requested_formats(stand_in, [ExportFormat(config.name)])
    assert not reporter_matches_requested_formats(stand_in, [ExportFormat.ASFF])


@pytest.mark.parametrize("name", SHIPPED_REPORTER_NAMES)
def test_ash_scan_accepts_every_reporter_name(name, tmp_path):
    """``ash scan -f <name>`` reaches the scan with that format selected."""
    source = tmp_path / "src"
    source.mkdir()
    with patch(RUN_ASH_SCAN) as mock_run:
        result = CliRunner().invoke(
            app,
            [
                "scan",
                "--source-dir",
                str(source),
                "--output-dir",
                str(tmp_path / "out"),
                "-f",
                f"sarif,{name}",
            ],
        )

    assert result.exit_code == 0, result.output
    mock_run.assert_called_once()
    requested = mock_run.call_args.kwargs["output_formats"]
    assert [getattr(fmt, "value", fmt) for fmt in requested] == ["sarif", name]


@pytest.mark.parametrize("name", SHIPPED_REPORTER_NAMES)
def test_ash_merge_accepts_every_reporter_name(name):
    """``ash merge --output-formats`` validates with the same list as ``ash scan``."""
    assert _parse_output_formats([f"markdown,{name}"]) == ["markdown", name]


@pytest.mark.parametrize("name", SHIPPED_REPORTER_NAMES)
def test_ash_report_offers_every_reporter_name(name):
    """``ash report --format`` completes and documents the same names."""
    assert name in get_report_formats("")


def test_an_unknown_name_is_refused(tmp_path):
    """Widening the list must not turn a typo into a silently empty report set."""
    source = tmp_path / "src"
    source.mkdir()
    with patch(RUN_ASH_SCAN) as mock_run:
        result = CliRunner().invoke(
            app,
            ["scan", "--source-dir", str(source), "-f", "github-gas"],
        )

    assert result.exit_code != 0
    assert "is not a valid format" in result.output
    mock_run.assert_not_called()
