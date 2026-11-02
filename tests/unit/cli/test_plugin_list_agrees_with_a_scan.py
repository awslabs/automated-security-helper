# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ash plugin list`` describes the plugins a scan with the same configuration
runs, as that scan reads them.

Four readings the listing took on its own:

* it listed every class registered in the process, while a scan selects its
  own share of the registry (``plugins.loader.scan_plugin_filter``) and drops
  the off-host classes its trusted modules do not load;
* with ``--show-versions`` it looked each scanner up in the inventory by a name
  derived from the class name, while the inventory keys its entries by the
  scanner's config name, so a scanner whose two names differ read Unknown;
* it read a plugin's section as a plain dict, so a section that leaves
  ``enabled`` out read as enabled whatever the plugin's own default;
* it read an off-host reporter's section as the repository's file wrote it,
  while a scan builds that reporter from the operator's section
  (``config/operator_only_options.reporter_section``) and runs it only on an
  ``enabled: true`` of its own.

Every test runs the command in process with stand-in plugin classes and a
configuration built here; nothing is imported from a plugin package.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Annotated, ClassVar, Literal
from unittest.mock import patch

import pytest
from pydantic import Field
from typer.testing import CliRunner

from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
)
from automated_security_helper.cli.plugin import plugin_app
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.operator_only_options import (
    record_operator_reporters,
)

pytestmark = pytest.mark.unit

WIDE = {"COLUMNS": "400", "NO_COLOR": "1"}
BUILTIN_MODULE = "automated_security_helper.plugin_modules.ash_builtin.scanners.stub"


class _StubConfig:
    def __init__(self, name, enabled=True):
        self.name = name
        self.enabled = enabled

    def model_dump(self):
        return {"name": self.name, "enabled": self.enabled}


class _StubScanner:
    """A scanner stand-in with what the listing and the inventory read."""

    offline_strategy = None
    _name = "stub"
    _satisfied = True
    _version = None

    def __init__(self, context=None, config=None):
        self.config = _StubConfig(self._name)
        self.tool_version = self._version

    def validate_plugin_dependencies(self):
        return self._satisfied


def _stub(class_name: str, module: str, **attrs):
    return type(class_name, (_StubScanner,), {"__module__": module, **attrs})


class _TitleOptions(ReporterOptionsBase):
    title: str = "default title"


class OptInReporterConfig(ReporterPluginConfigBase):
    name: Literal["opt-in"] = "opt-in"
    extension: str = "opt-in.json"
    enabled: bool = False
    options: Annotated[_TitleOptions, Field()] = _TitleOptions()


class OptInReporter(ReporterPluginBase[OptInReporterConfig]):
    """Off by default, stays on the host; a section may turn it on."""

    def model_post_init(self, context):
        if self.config is None:
            self.config = OptInReporterConfig()
        return super().model_post_init(context)

    def report(self, model):
        return json.dumps({"title": self.config.options.title})


class OffHostReporterConfig(ReporterPluginConfigBase):
    name: Literal["quiet-offhost"] = "quiet-offhost"
    extension: str = "quiet.json"
    enabled: bool = False
    options: Annotated[_TitleOptions, Field()] = _TitleOptions()


class OffHostReporter(ReporterPluginBase[OffHostReporterConfig]):
    """Sends findings off the host, so only the operator's section turns it on."""

    sends_off_host: ClassVar[bool] = True

    def model_post_init(self, context):
        if self.config is None:
            self.config = OffHostReporterConfig()
        return super().model_post_init(context)

    def report(self, model):
        return json.dumps({"title": self.config.options.title})


class ShippedOnOffHostReporterConfig(ReporterPluginConfigBase):
    name: Literal["shipped-on-offhost"] = "shipped-on-offhost"
    extension: str = "shipped-on.json"
    enabled: bool = True
    options: Annotated[_TitleOptions, Field()] = _TitleOptions()


class ShippedOnOffHostReporter(ReporterPluginBase[ShippedOnOffHostReporterConfig]):
    """Sends findings off the host and ships enabled, which no scan honors."""

    sends_off_host: ClassVar[bool] = True

    def model_post_init(self, context):
        if self.config is None:
            self.config = ShippedOnOffHostReporterConfig()
        return super().model_post_init(context)

    def report(self, model):
        return json.dumps({"title": self.config.options.title})


# The listing selects as a scan selects: a class whose module is neither ASH's
# built-in package nor one the run's ash_plugin_modules names is left out. The
# stand-in reporters are defined here, so they are given a built-in module name,
# as the scanner stand-ins are; without it the reporters table is empty.
BUILTIN_REPORTERS_MODULE = (
    "automated_security_helper.plugin_modules.ash_builtin.reporters.stub"
)


@pytest.fixture(autouse=True)
def _reporters_are_built_in(monkeypatch):
    """Give the stand-in reporters a built-in module name for one test, and put
    the module they are defined in back after it. Set when this file was
    imported, the name stayed on the classes for the rest of the session."""
    for reporter in (OptInReporter, OffHostReporter, ShippedOnOffHostReporter):
        monkeypatch.setattr(reporter, "__module__", BUILTIN_REPORTERS_MODULE)


def _listing(
    tmp_path: Path,
    args: list,
    *,
    scanners: list = (),
    reporters: list = (),
    config: AshConfig | None = None,
):
    """The command's output with the stand-ins as the registered plugins and
    *config* as the resolved configuration.

    The registry stand-in applies the filter it is given, so a class the
    command's own selection leaves out is left out here too.
    """
    from automated_security_helper.plugins import ash_plugin_manager

    registered = {
        "scanner": list(scanners),
        "converter": [],
        "reporter": list(reporters),
    }

    def plugin_modules(plugin_type, filter_callback=lambda cls: True, *a, **k):
        return [cls for cls in registered[plugin_type] if filter_callback(cls)]

    named = tmp_path / "probe.ash.yaml"
    named.write_text("project_name: probe\n", encoding="utf-8")
    with (
        patch("automated_security_helper.cli.plugin.load_plugins") as mock_load,
        patch(
            "automated_security_helper.cli.plugin.resolve_config",
            return_value=config if config is not None else AshConfig(),
        ),
        patch.object(ash_plugin_manager, "plugin_modules", side_effect=plugin_modules),
    ):
        mock_load.return_value = {
            "scanners": list(scanners),
            "converters": [],
            "reporters": list(reporters),
        }
        result = CliRunner().invoke(
            plugin_app, [*args, "--config", str(named)], env=WIDE
        )
    return result


def _columns(line: str) -> list:
    """The columns of one table line, whichever box characters draw it."""
    return [text.strip() for text in re.split(r"[│┃|]", line)][1:-1]


def _enabled(output: str, name: str) -> str:
    """The Enabled value of the row named *name*, found by the header's column, so
    a ``True`` or ``False`` in another column of the row cannot answer for it."""
    header = next(
        line for line in output.splitlines() if "Name" in line and "Enabled" in line
    )
    return _columns(_row(output, name))[_columns(header).index("Enabled")]


def _row(output: str, name: str) -> str:
    rows = [line for line in output.splitlines() if f" {name} " in line]
    assert len(rows) == 1, (name, output)
    return rows[0]


def test_a_registered_class_no_module_of_the_run_brings_in_is_not_listed(tmp_path):
    kept = _stub("KeptScanner", BUILTIN_MODULE, _name="kept")
    stray = _stub("StrayScanner", "stray_ash_plugins.scanner", _name="stray")

    result = _listing(tmp_path, ["--no-color"], scanners=[kept, stray])

    assert result.exit_code == 0, result.output
    assert "KeptScanner" in result.output
    assert "StrayScanner" not in result.output


def test_a_class_from_a_module_the_run_names_is_listed(tmp_path):
    """The other half of the selection rule: a listing that kept the built-ins
    alone, ignoring ash_plugin_modules, would pass the test above and drop every
    plugin a configured module defines.

    The class is defined in the named module itself. A class a submodule defines
    is selected only when the package's namespace binds or lists it, which needs
    the package imported (plugins.loader.scan_plugin_filter); nothing here is."""
    kept = _stub("KeptScanner", BUILTIN_MODULE, _name="kept")
    stray = _stub("StrayScanner", "stray_ash_plugins", _name="stray")
    config = AshConfig.model_validate(
        {"project_name": "probe", "ash_plugin_modules": ["stray_ash_plugins"]}
    )

    result = _listing(tmp_path, ["--no-color"], scanners=[kept, stray], config=config)

    assert result.exit_code == 0, result.output
    assert "KeptScanner" in result.output
    assert "StrayScanner" in result.output


def test_show_versions_matches_the_inventory_by_class_not_by_a_derived_name(
    tmp_path,
):
    """The config name ``renamed-tool`` is not what ``AlphaScanner`` derives to,
    so a lookup by the derived name read Unknown with the probe's answer in
    hand."""
    alpha = _stub(
        "AlphaScanner", BUILTIN_MODULE, _name="renamed-tool", _version="1.2.3"
    )

    result = _listing(tmp_path, ["--show-versions", "--no-color"], scanners=[alpha])

    assert result.exit_code == 0, result.output
    row = _row(result.output, "renamed-tool")
    assert "1.2.3" in row, row
    assert "Yes" in row, row
    assert "Unknown" not in row, row


def test_show_versions_pairs_each_row_with_its_own_scanners_entry(tmp_path):
    """Two scanners with different answers: each row carries its own. One
    scanner cannot tell a row paired with the wrong entry from a row paired
    with the right one."""
    alpha = _stub(
        "AlphaScanner", BUILTIN_MODULE, _name="renamed-tool", _version="1.2.3"
    )
    beta = _stub(
        "BetaScanner",
        BUILTIN_MODULE,
        _name="other-tool",
        _version="9.8.7",
        _satisfied=False,
    )

    result = _listing(
        tmp_path, ["--show-versions", "--no-color"], scanners=[alpha, beta]
    )

    assert result.exit_code == 0, result.output
    alpha_row = _row(result.output, "renamed-tool")
    beta_row = _row(result.output, "other-tool")
    assert "1.2.3" in alpha_row and "9.8.7" not in alpha_row, alpha_row
    assert " Yes " in alpha_row and " No " not in alpha_row, alpha_row
    assert "9.8.7" in beta_row and "1.2.3" not in beta_row, beta_row
    assert " No " in beta_row and " Yes " not in beta_row, beta_row


def test_show_versions_reads_unknown_when_the_inventory_is_not_the_one_asked_for(
    tmp_path,
):
    """An inventory with another number of entries cannot be paired with the
    scanners by position; every row then reads Unknown rather than another
    scanner's answer."""
    alpha = _stub("AlphaScanner", BUILTIN_MODULE, _name="alpha", _version="1.2.3")
    beta = _stub("BetaScanner", BUILTIN_MODULE, _name="beta", _version="9.8.7")
    one_entry = [
        {
            "name": "alpha",
            "version": "1.2.3",
            "dependencies_satisfied": True,
            "offline_strategy": None,
            "enabled": True,
            "installs_on_first_scan": False,
        }
    ]

    with patch(
        "automated_security_helper.core.scanner_inventory.list_scanner_inventory",
        return_value=one_entry,
    ):
        result = _listing(
            tmp_path, ["--show-versions", "--no-color"], scanners=[alpha, beta]
        )

    assert result.exit_code == 0, result.output
    for name in ("alpha", "beta"):
        row = _row(result.output, name)
        assert "1.2.3" not in row, row
        assert row.count("Unknown") >= 2, row


def test_an_opt_in_plugin_whose_section_omits_enabled_is_listed_off(tmp_path):
    config = AshConfig.model_validate(
        {
            "project_name": "probe",
            "reporters": {"opt-in": {"options": {"title": "set"}}},
        }
    )

    result = _listing(
        tmp_path, ["--no-color"], reporters=[OptInReporter], config=config
    )

    assert result.exit_code == 0, result.output
    assert _enabled(result.output, "opt-in") == "False", result.output


def test_an_opt_in_plugin_whose_section_sets_enabled_true_is_listed_on(tmp_path):
    config = AshConfig.model_validate(
        {"project_name": "probe", "reporters": {"opt-in": {"enabled": True}}}
    )

    result = _listing(
        tmp_path, ["--no-color"], reporters=[OptInReporter], config=config
    )

    assert result.exit_code == 0, result.output
    assert _enabled(result.output, "opt-in") == "True", result.output


def test_an_off_host_reporter_the_repository_turned_on_is_listed_off(tmp_path):
    """The repository's file wrote ``enabled: true`` and a title; the operator's
    configuration has no section for it, so a scan builds it from nothing and
    does not run it. The listing says the same, and shows the section the scan
    builds it from, not the repository's."""
    config = AshConfig.model_validate(
        {
            "project_name": "probe",
            "reporters": {
                "quiet-offhost": {"enabled": True, "options": {"title": "repo title"}}
            },
        }
    )
    record_operator_reporters(
        config, AshConfig(), [tmp_path / "src" / ".ash" / ".ash.yaml"]
    )

    result = _listing(
        tmp_path,
        ["--no-color", "--include-plugin-config"],
        reporters=[OffHostReporter],
        config=config,
    )

    assert result.exit_code == 0, result.output
    assert _enabled(result.output, "quiet-offhost") == "False", result.output
    assert "repo title" not in result.output


def test_an_off_host_reporter_the_operator_turned_on_is_listed_on(tmp_path):
    config = AshConfig.model_validate(
        {"project_name": "probe", "reporters": {"quiet-offhost": {"enabled": True}}}
    )

    result = _listing(
        tmp_path, ["--no-color"], reporters=[OffHostReporter], config=config
    )

    assert result.exit_code == 0, result.output
    assert _enabled(result.output, "quiet-offhost") == "True", result.output


def test_an_off_host_reporter_enabled_by_a_non_boolean_is_listed_off(tmp_path):
    """``enabled: "yes"`` is not the boolean true the scan requires of an
    off-host reporter's section, so the scan does not run it."""
    config = AshConfig.model_validate(
        {"project_name": "probe", "reporters": {"quiet-offhost": {"enabled": "yes"}}}
    )

    result = _listing(
        tmp_path, ["--no-color"], reporters=[OffHostReporter], config=config
    )

    assert result.exit_code == 0, result.output
    assert _enabled(result.output, "quiet-offhost") == "False", result.output


def test_an_off_host_reporter_that_ships_enabled_is_dumped_off_with_no_section(
    tmp_path,
):
    """No section turns it on, so a scan builds it off. It was built from nothing
    and took its own default of enabled, so its config dump read ``true`` beside
    an Enabled column of False."""
    result = _listing(
        tmp_path,
        ["--no-color", "--include-plugin-config"],
        reporters=[ShippedOnOffHostReporter],
    )

    assert result.exit_code == 0, result.output
    assert _enabled(result.output, "shipped-on-offhost") == "False", result.output
    assert '"enabled": false' in result.output, result.output
    assert '"enabled": true' not in result.output, result.output
