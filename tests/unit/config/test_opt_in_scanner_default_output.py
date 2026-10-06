# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An opt-in scanner nobody enabled leaves no trace in what a default scan writes.

The scan phase already drops such a scanner before it is built. Two other places
named it anyway, measured with the snapshot suite and on a real default scan once
gitleaks shipped: the config dump ASH writes into ``ash_aggregated_results.json``
(and the YAML report and the AWS reporter payloads) gained a
``gitleaks: {enabled: false, ...}`` block, and the "Loaded N scanners" line every
scan logs counted it.
"""

from __future__ import annotations

import json
import logging

import pytest

from automated_security_helper.config.ash_config import AshConfig, ScannerConfigSegment
from automated_security_helper.core.scanner_opt_in import is_opt_in
from automated_security_helper.plugins import ash_plugin_manager
from automated_security_helper.plugins.loader import load_plugins


def _opt_in_keys() -> list[str]:
    """Segment keys of the shipped opt-in scanners, found from the registry."""
    import automated_security_helper.plugin_modules.ash_builtin  # noqa: F401

    names = {
        cls.model_fields["config"].annotation.__args__[0]().name
        for cls in ash_plugin_manager.plugin_modules("scanner")
        if is_opt_in(cls)
    }
    keys = [
        info.alias or field
        for field, info in ScannerConfigSegment.model_fields.items()
        if getattr(info.default, "name", None) in names
    ]
    assert keys, "no shipped opt-in scanner declares a config field; nothing to test"
    return keys


OPT_IN_KEYS = _opt_in_keys()


@pytest.mark.parametrize("by_alias", [True, False])
def test_a_default_config_dump_omits_opt_in_scanners(by_alias):
    dumped = AshConfig().model_dump(by_alias=by_alias)["scanners"]
    for key in OPT_IN_KEYS:
        assert key not in dumped and key.replace("-", "_") not in dumped
    # The scanners that run by default are all still there.
    assert {"bandit", "detect-secrets" if by_alias else "detect_secrets"} <= set(dumped)


def test_the_json_dump_omits_them_too():
    text = AshConfig().model_dump_json(by_alias=True)
    scanners = json.loads(text)["scanners"]
    assert not set(OPT_IN_KEYS) & set(scanners)


def test_omission_is_lossless():
    config = AshConfig()
    reloaded = AshConfig.model_validate(config.model_dump(by_alias=True))
    assert reloaded.scanners == config.scanners


@pytest.mark.parametrize("key", OPT_IN_KEYS)
def test_an_enabled_opt_in_scanner_is_dumped(key):
    config = AshConfig.model_validate(
        {"project_name": "x", "scanners": {key: {"enabled": True}}}
    )
    assert config.model_dump(by_alias=True)["scanners"][key]["enabled"] is True


@pytest.mark.parametrize("key", OPT_IN_KEYS)
def test_a_disabled_opt_in_scanner_with_options_is_dumped(key):
    """Options must survive a round trip: --scanners can run it with them."""
    config = AshConfig.model_validate(
        {
            "project_name": "x",
            "scanners": {key: {"enabled": False, "options": {"scan_timeout": 7}}},
        }
    )
    dumped = config.model_dump(by_alias=True)["scanners"][key]
    assert dumped["enabled"] is False
    assert dumped["options"]["scan_timeout"] == 7


def test_every_other_scanner_is_still_dumped_and_repr_d():
    """Only opt-in scanners are left out, whatever their default says.

    opengrep defaults to enabled: false on Windows and is not opt-in, so an
    omission keyed on the enabled default alone would drop it there.
    """
    config = AshConfig()
    dumped = config.model_dump(by_alias=True)["scanners"]
    text = repr(config.scanners)
    for field, info in ScannerConfigSegment.model_fields.items():
        key = info.alias or field
        if key in OPT_IN_KEYS:
            assert key not in dumped and f"{field}=" not in text
        else:
            assert key in dumped and f"{field}=" in text


def test_opengrep_disabled_by_default_is_still_dumped(monkeypatch):
    config = AshConfig.model_validate(
        {"project_name": "x", "scanners": {"opengrep": {"enabled": False}}}
    )
    assert config.model_dump(by_alias=True)["scanners"]["opengrep"]["enabled"] is False


def test_the_loaded_count_leaves_out_opt_in_scanners(caplog):
    with caplog.at_level(logging.DEBUG):
        plugins = load_plugins()
    total = len(plugins["scanners"])
    opt_in = sum(1 for s in plugins["scanners"] if is_opt_in(s))
    assert opt_in >= 1
    info = [
        r.getMessage() for r in caplog.records if r.getMessage().startswith("Loaded ")
    ]
    assert info and f"{total - opt_in} scanners" in info[-1], info
    assert any(
        r.getMessage().startswith(f"Also loaded {opt_in} opt-in scanners")
        for r in caplog.records
    )
