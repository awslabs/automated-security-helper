# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An untouched opt-in scanner's config entry stays out of what ASH writes.

Why this exists
---------------
The scan phase drops an opt-in scanner nobody enabled, but a builtin opt-in
scanner also declares a field on ``ScannerConfigSegment``, and every serialized
config carried that field: the config embedded in ``ash_aggregated_results.json``,
the YAML report, the S3 and CloudWatch payloads (one embeds the repr), the
"Loaded N scanners" log line, and the workspace plan's pins. Five scanner
builders measured that independently once a real opt-in scanner existed. The
foundation's own tests missed it because their dummy scanner was never part of
the config model.

How the dummy is registered
---------------------------
The way a shipped builtin is: a config field on a ``ScannerConfigSegment`` and an
``AshConfig`` whose ``scanners`` field is that segment, with the scanner class and
its config class defined in one module (this one), which is how
``is_opt_in_scanner_config`` finds the scanner. Subclasses are used so nothing
global changes; a subclass instance in a field annotated with the parent would be
serialized with the parent's fields, so ``ash_config`` is re-annotated too.

Negative control
----------------
``NotOptInScanner`` shares a config class shape but is not opt-in, and its entry
must be dumped. ``test_negative_control_the_dump_shows_a_non_opt_in_twin`` is the
check that the omission tests can see an entry when it is there.
"""

from __future__ import annotations

import json
import logging
from typing import Annotated, ClassVar, Literal, Optional

import pytest
import yaml
from pydantic import Field

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig, ScannerConfigSegment
from automated_security_helper.models.asharp_model import AshAggregatedResults

KEY = "dummy-optin"
TWIN_KEY = "dummy-twin"


class DummyOptInOptions(ScannerOptionsBase):
    level: Annotated[str, Field(description="An option with a default")] = "low"
    tool_version: Annotated[str, Field(description="A default version pin")] = "9.9"


class DummyOptInConfig(ScannerPluginConfigBase):
    name: Literal["dummy-optin"] = KEY
    enabled: bool = False
    options: DummyOptInOptions = DummyOptInOptions()


class DummyOptInScanner(ScannerPluginBase[DummyOptInConfig]):
    OPT_IN: ClassVar[bool] = True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError


class TwinConfig(ScannerPluginConfigBase):
    name: Literal["dummy-twin"] = TWIN_KEY
    enabled: bool = False
    options: DummyOptInOptions = DummyOptInOptions()


class NotOptInScanner(ScannerPluginBase[TwinConfig]):
    """Disabled by default, like opengrep on Windows, and not opt-in."""

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError


class SegmentWithDummies(ScannerConfigSegment):
    dummy_optin: Annotated[
        DummyOptInConfig, Field(description="A dummy opt-in scanner", alias=KEY)
    ] = DummyOptInConfig()
    dummy_twin: Annotated[
        TwinConfig, Field(description="A dummy non-opt-in scanner", alias=TWIN_KEY)
    ] = TwinConfig()


class ConfigWithDummies(AshConfig):
    scanners: Annotated[
        SegmentWithDummies, Field(description="Scanner configurations by name.")
    ] = SegmentWithDummies()


class ResultsWithDummies(AshAggregatedResults):
    ash_config: Optional[ConfigWithDummies] = None


def _config(scanners: dict | None = None) -> ConfigWithDummies:
    return ConfigWithDummies.model_validate(
        {"project_name": "x", "scanners": scanners or {}}
    )


def test_the_dummy_is_found_the_way_a_builtin_is():
    from automated_security_helper.core.scanner_opt_in import is_opt_in_scanner_config

    assert is_opt_in_scanner_config(DummyOptInConfig)
    assert not is_opt_in_scanner_config(TwinConfig)
    assert not is_opt_in_scanner_config(ScannerPluginConfigBase)
    assert not is_opt_in_scanner_config(None)


@pytest.mark.parametrize("by_alias", [True, False])
def test_a_default_dump_omits_the_untouched_opt_in_scanner(by_alias):
    dumped = _config().model_dump(by_alias=by_alias)["scanners"]
    assert KEY not in dumped and "dummy_optin" not in dumped
    assert {"bandit", TWIN_KEY if by_alias else "dummy_twin"} <= set(dumped)


def test_json_and_repr_omit_it():
    config = _config()
    assert KEY not in json.loads(config.model_dump_json(by_alias=True))["scanners"]
    assert "dummy_optin=" not in repr(config.scanners)
    assert "dummy_optin=" not in repr(config)
    assert "dummy_twin=" in repr(config.scanners)


def test_the_aggregated_results_and_yaml_report_omit_it():
    results = ResultsWithDummies(ash_config=_config())
    assert KEY not in results.model_dump_json(by_alias=True)
    assert KEY not in json.dumps(results.to_simple_dict(), default=str)
    assert KEY not in yaml.dump(results.model_dump(by_alias=True, mode="json"))
    # The twin, which is not opt-in, is in all three.
    assert TWIN_KEY in results.model_dump_json(by_alias=True)


def test_negative_control_the_dump_shows_a_non_opt_in_twin():
    """Same shape, same disabled default, not opt-in: it is dumped."""
    dumped = _config().model_dump(by_alias=True)["scanners"]
    assert dumped[TWIN_KEY]["enabled"] is False


def test_enabled_it_is_dumped():
    dumped = _config({KEY: {"enabled": True}}).model_dump(by_alias=True)["scanners"]
    assert dumped[KEY]["enabled"] is True


def test_disabled_with_an_option_set_it_is_dumped():
    """Options must survive a round trip: --scanners can run it with them."""
    config = _config({KEY: {"enabled": False, "options": {"level": "high"}}})
    dumped = config.model_dump(by_alias=True)["scanners"][KEY]
    assert dumped["enabled"] is False
    assert dumped["options"]["level"] == "high"


def test_the_omission_is_lossless():
    for config in (_config(), _config({KEY: {"enabled": True}})):
        reloaded = ConfigWithDummies.model_validate(config.model_dump(by_alias=True))
        assert reloaded.scanners == config.scanners


def test_get_plugin_config_still_finds_the_entry():
    """Lookups read every entry; only output dumps leave it out."""
    found = _config().get_plugin_config(plugin_type="scanner", plugin_name=KEY)
    assert isinstance(found, dict)
    assert found["name"] == KEY and found["enabled"] is False


def test_a_config_class_that_defaults_on_is_not_hidden():
    """Only a disabled entry is omitted: one whose class default is on would run."""

    class OnConfig(ScannerPluginConfigBase):
        name: Literal["dummy-on"] = "dummy-on"
        enabled: bool = True

    class OnScanner(ScannerPluginBase[OnConfig]):
        OPT_IN: ClassVar[bool] = True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            raise NotImplementedError

    # Defined in a function, so its module scan sees the module-level names only;
    # put them where the lookup looks, as a builtin module would have them.
    globals()["OnConfig"], globals()["OnScanner"] = OnConfig, OnScanner
    try:

        class Segment(ScannerConfigSegment):
            dummy_on: Annotated[OnConfig, Field(alias="dummy-on")] = OnConfig()

        from automated_security_helper.core.scanner_opt_in import (
            is_opt_in_scanner_config,
        )

        assert is_opt_in_scanner_config(OnConfig)
        assert "dummy-on" in Segment().model_dump(by_alias=True)
    finally:
        del globals()["OnConfig"], globals()["OnScanner"]


def test_the_schema_still_documents_it():
    """Hidden from dumps, not from the schema: validation and completion keep it.

    The only schema difference an opt-in scanner makes is the ``default`` value of
    the ``scanners`` property, which is a dump.
    """
    for mode in ("validation", "serialization"):
        schema = ConfigWithDummies.model_json_schema(mode=mode)
        segment = schema["$defs"]["SegmentWithDummies"]
        assert KEY in segment["properties"], (mode, sorted(segment["properties"]))
        ref = segment["properties"][KEY]
        target = ref.get("$ref") or ref["allOf"][0]["$ref"]
        definition = schema["$defs"][target.rsplit("/", 1)[-1]]
        assert {"enabled", "options", "name"} <= set(definition["properties"])
    # And validation still applies to it.
    with pytest.raises(Exception):
        _config({KEY: {"enabled": "not-a-bool"}})


def test_the_loaded_count_leaves_out_opt_in_scanners(caplog, monkeypatch):
    from automated_security_helper.plugins import loader

    monkeypatch.setattr(
        loader,
        "load_internal_plugins",
        lambda: {
            "converters": [],
            "scanners": [NotOptInScanner, DummyOptInScanner],
            "reporters": [],
        },
    )
    with caplog.at_level(logging.INFO):
        loader.load_plugins()
    lines = [
        r.getMessage() for r in caplog.records if r.getMessage().startswith("Loaded ")
    ]
    assert lines and "1 scanners" in lines[-1], lines


def test_workspace_pins_leave_out_an_untouched_opt_in_scanner():
    from automated_security_helper.workspace.resolver import _scanner_state

    _, pins = _scanner_state(_config())
    # Both carry a default pin; only the untouched opt-in scanner is left out.
    assert KEY not in pins
    assert pins.get(TWIN_KEY) == "9.9"
    enabled, _ = _scanner_state(_config({KEY: {"enabled": True}}))
    assert KEY in enabled


def test_a_runtime_patch_can_enable_an_untouched_opt_in_scanner():
    """MCP inherit-and-patch must be able to point into the hidden entry."""
    from automated_security_helper.config.ash_config import RuntimeOverridesConfig
    from automated_security_helper.config.runtime_patch import apply_runtime_patch

    patched = apply_runtime_patch(
        _config(),
        [{"op": "replace", "path": "/scanners/dummy_optin/enabled", "value": True}],
        allowlist=RuntimeOverridesConfig(enabled=True, allowed_paths=["/scanners/**"]),
    )
    entry = patched.scanners.model_extra["dummy_optin"]
    enabled = entry["enabled"] if isinstance(entry, dict) else entry.enabled
    assert enabled is True


class EnvOptions(ScannerOptionsBase):
    mode: Annotated[
        str,
        Field(
            description="A default read from the environment when built",
            default_factory=lambda: __import__("os").environ.get(
                "ASH_TEST_OPTIN_MODE", "a"
            ),
        ),
    ]


class EnvOptInConfig(ScannerPluginConfigBase):
    name: Literal["dummy-env"] = "dummy-env"
    enabled: bool = False
    options: Annotated[EnvOptions, Field(default_factory=EnvOptions)]


class EnvOptInScanner(ScannerPluginBase[EnvOptInConfig]):
    OPT_IN: ClassVar[bool] = True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError


class SegmentWithEnvDummy(ScannerConfigSegment):
    dummy_env: Annotated[EnvOptInConfig, Field(alias="dummy-env")] = EnvOptInConfig()


def test_a_default_that_reads_the_environment_is_still_recognized(monkeypatch):
    """The field default was built at import; the entry was built later.

    With the environment changed in between (as offline mode does once the CLI
    has parsed --offline), the entry equals a freshly built default but not the
    import-time one, and it must still be left out.
    """
    monkeypatch.setenv("ASH_TEST_OPTIN_MODE", "b")
    segment = SegmentWithEnvDummy.model_validate({"dummy-env": {"enabled": False}})
    assert segment.dummy_env.options.mode == "b"
    assert segment.dummy_env != SegmentWithEnvDummy.model_fields["dummy_env"].default
    assert "dummy-env" not in segment.model_dump(by_alias=True)


def test_every_shipped_opt_in_scanner_is_found_from_its_config_class():
    """The config dump finds an opt-in scanner through its config class's module.

    A shipped opt-in scanner whose config class moved to another module would
    reappear in every default config dump, so the pairing is pinned here.
    """
    from automated_security_helper.core.scanner_inventory import (
        _loaded_scanner_classes,
    )
    from automated_security_helper.core.scanner_opt_in import (
        _declared_config_class,
        is_opt_in,
        is_opt_in_scanner_config,
    )

    for cls in _loaded_scanner_classes():
        if is_opt_in(cls):
            assert is_opt_in_scanner_config(_declared_config_class(cls)), cls
    # What it would catch: the dummy here is found, the twin is not.
    assert is_opt_in_scanner_config(_declared_config_class(DummyOptInScanner))
    assert not is_opt_in_scanner_config(_declared_config_class(NotOptInScanner))
