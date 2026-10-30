# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""`ash plugin list` lists what a scan of its configuration selects, built as a scan builds.

The registry is process-wide; the listing keeps to ASH's built-ins and the
modules the configuration names, and drops the off-host classes those modules
do not load, as a scan does. Plugins are built inside the check-only and
deferred-probe scopes, so a listing installs and downloads nothing. A section
without a name is still the plugin's declared name; a plugin's own redaction
values mask its config column; --no-color reaches the tables and the refusal
lines; an inventory that fails says so where the operator reads.
"""

from __future__ import annotations

import re
from unittest.mock import patch

import pytest
from typer.testing import CliRunner

from automated_security_helper.base.uv_tool_mixin import _DEFER_VERSION_PROBES
from automated_security_helper.cli.plugin import plugin_app
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.utils.uv_tool_runner import is_checking_only

pytestmark = pytest.mark.unit

ANSI = re.compile(r"\x1b\[[0-9;]*m")
WIDE = {"COLUMNS": "400"}


class _Config:
    def __init__(self, name="stub", enabled=True, options=None):
        self.name = name
        self.enabled = enabled
        self.options = options or {}

    def model_dump(self):
        return {"name": self.name, "enabled": self.enabled, "options": self.options}


class _Stub:
    """A scanner stand-in that records the scopes it was built under."""

    built_under: list = []
    _name = "stub"

    def __init__(self, context=None, config=None):
        type(self).built_under.append((is_checking_only(), _DEFER_VERSION_PROBES.get()))
        self.config = _Config(self._name)

    def validate_plugin_dependencies(self):
        return True


def _stub(name, **attrs):
    return type(f"{name}Scanner", (_Stub,), {"_name": name, "built_under": [], **attrs})


def _list(args, scanners, reporters=()):
    """The listing with *scanners* and *reporters* as the registry's answer."""
    with (
        patch("automated_security_helper.cli.plugin.load_plugins") as load,
        patch.object(
            ash_plugin_manager,
            "plugin_modules",
            side_effect=lambda plugin_type, *a, **k: (
                list(scanners)
                if plugin_type == "scanner"
                else list(reporters)
                if plugin_type == "reporter"
                else []
            ),
        ),
    ):
        load.return_value = {
            "scanners": list(scanners),
            "converters": [],
            "reporters": list(reporters),
        }
        return CliRunner().invoke(plugin_app, args, env=WIDE)


# --- built as a scan builds ---


def test_a_plugin_without_a_section_is_built_in_the_check_only_scopes():
    """The default listing built a plugin whose section is absent outside
    checking_only() and the deferred probes, so a uv-based scanner's
    construction probe could resolve and download its tool."""
    stub = _stub("probing")

    result = _list(["--no-color"], [stub])

    assert result.exit_code == 0, result.output
    assert stub.built_under == [(True, True)], stub.built_under


def test_a_scan_scoped_filter_is_asked_of_the_registry():
    """The listing read the whole registry; a scan asks it with the filter the
    engine builds from the run's plugin modules (scan_plugin_filter)."""
    asked: list = []

    def plugin_modules(plugin_type, *args, **kwargs):
        asked.append(args[0] if args else kwargs.get("filter_callback"))
        return []

    with (
        patch("automated_security_helper.cli.plugin.load_plugins") as load,
        patch.object(ash_plugin_manager, "plugin_modules", side_effect=plugin_modules),
    ):
        load.return_value = {"scanners": [], "converters": [], "reporters": []}
        result = CliRunner().invoke(plugin_app, ["--no-color"], env=WIDE)

    assert result.exit_code == 0, result.output
    assert asked and all(callable(callback) for callback in asked), asked


def test_an_off_host_class_a_trusted_module_does_not_load_is_not_listed(monkeypatch):
    """A scan drops such a class (drop_untrusted_off_host_plugins); the listing
    showed it. The listing imports the filter from its module at each run, so
    it is replaced there."""
    dropped: list = []

    def drop(config, plugins, operator_modules):
        dropped.append(sorted(plugins))
        return {kind: [] for kind in plugins}

    monkeypatch.setattr(
        "automated_security_helper.config.plugin_module_trust."
        "drop_untrusted_off_host_plugins",
        drop,
    )
    stub = _stub("offhost")

    result = _list(["--no-color"], [stub])

    assert result.exit_code == 0, result.output
    assert dropped == [["converter", "reporter", "scanner"]]
    assert "offhost" not in ANSI.sub("", result.output)


# --- the rows ---


def test_a_section_without_a_name_shows_the_plugins_declared_name():
    """A dict section that omits "name" showed the class name; the plugin is
    built from its section, as a scan builds it, and its own model names it."""
    stub = _stub("unnamed")
    section = {"enabled": True}

    with patch(
        "automated_security_helper.config.ash_config.AshConfig.get_plugin_config",
        return_value=section,
    ):
        result = _list(["--no-color"], [stub])

    assert result.exit_code == 0, result.output
    plain = ANSI.sub("", result.output)
    assert "unnamed" in plain, plain
    # The Class column still names the class, which _stub spells "unnamedScanner".
    assert "unnamedScanner" in plain, plain
    assert plain.count("unnamedScanner") == 1, plain


def test_a_plugins_own_redaction_values_mask_its_config_column():
    """An option default a plugin read straight from the environment is in
    its dump and in none of the config's recorded values; the row masked
    with the config's values alone and printed it."""
    secret = "zq7ownvalue-x5y6z7w8"

    class Reads(_Stub):
        _name = "reads"

        def __init__(self, context=None, config=None):
            super().__init__(context, config)
            self.config = _Config("reads", options={"model_id": secret})

        def _values_to_redact(self):
            return (secret,)

    result = _list(["--no-color", "--include-plugin-config"], [Reads])

    assert result.exit_code == 0, result.output
    plain = ANSI.sub("", result.output)
    assert "reads" in plain, plain
    assert secret not in plain, plain


@pytest.mark.parametrize("flag, expected", [("--no-color", True), ("--color", False)])
def test_color_reaches_the_tables_console(monkeypatch, flag, expected):
    """--no-color reached the logger alone; the tables' console colored on."""
    from automated_security_helper.cli import plugin as plugin_cli

    made: list = []
    real = plugin_cli.ash_console

    def recording(*args, **kwargs):
        made.append(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(plugin_cli, "ash_console", recording)

    result = _list([flag], [_stub("plain")])

    assert result.exit_code == 0, result.output
    assert [kwargs.get("no_color") for kwargs in made] == [expected], made


def test_no_color_reaches_the_refusal_lines(monkeypatch):
    from automated_security_helper.cli import plugin as plugin_cli
    from automated_security_helper.core.exceptions import ASHConfigValidationError

    said: list = []
    monkeypatch.setattr(
        plugin_cli, "secho", lambda message, **kwargs: said.append(kwargs.get("fg"))
    )

    def refusing(*args, **kwargs):
        raise ASHConfigValidationError("the file does not parse")

    monkeypatch.setattr(plugin_cli, "resolve_config", refusing)

    result = _list(["--no-color"], [])

    assert result.exit_code == 3, result.output
    assert said and all(fg is None for fg in said), said


def test_a_failed_inventory_is_said_once_at_warning(monkeypatch):
    from unittest.mock import MagicMock

    from automated_security_helper.cli import plugin as plugin_cli

    logger = MagicMock()
    monkeypatch.setattr(plugin_cli, "get_logger", lambda **kwargs: logger)

    def failing(*args, **kwargs):
        raise RuntimeError("the probe host is gone")

    monkeypatch.setattr(
        "automated_security_helper.core.scanner_inventory.list_scanner_inventory",
        failing,
    )

    result = _list(["--show-versions", "--no-color"], [_stub("alpha")])

    assert result.exit_code == 0, result.output
    plain = ANSI.sub("", result.output)
    assert "Unknown" in plain, plain
    logger.warning.assert_called_once()
    message = logger.warning.call_args.args[0]
    assert "Could not build the scanner inventory" in message, message
    assert "the probe host is gone" in message, message
    assert not logger.debug.called or all(
        "Could not build scanner inventory" not in str(call.args[0])
        for call in logger.debug.call_args_list
    )
