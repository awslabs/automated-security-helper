# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The plugin module refusals carry their refused entries.

``ConfigValidator.with_environment_remedy`` reads ``error.entries`` to decide
whether the closing offers "unset it in ASH_PLUGIN_MODULES", so a raiser that
leaves ``entries`` empty makes the environment remedy silently never show.
Every module name here is a planted fake (``zz_`` prefix): the namespace
refusal runs before any import, so nothing real is imported.
"""

from __future__ import annotations

import pytest


def test_an_environment_only_refused_entry_renders_the_unset_remedy():
    """Drives the real judge, ``refuse_plugin_modules_a_scan_refuses``, with a
    planted module name only the environment list contributes (the resolved
    config names none). The judge records the subtraction in
    ``environment_only_entries``; ``with_environment_remedy`` matches it
    against ``error.entries``, which the raiser sets, so the rendered
    refusal closes with the one remedy such an entry has."""
    from automated_security_helper.config.ash_config import AshConfig
    from automated_security_helper.config.plugin_module_trust import (
        plugin_module_refusal_message,
        refuse_plugin_modules_a_scan_refuses,
    )
    from automated_security_helper.plugins.loader import PluginModuleError

    resolved = AshConfig()
    resolved.ash_plugin_modules = []

    with pytest.raises(PluginModuleError) as raised:
        refuse_plugin_modules_a_scan_refuses(resolved, ["zz_env_only_fake_mod"])

    message = plugin_module_refusal_message(raised.value)
    assert message.endswith("or unset it in ASH_PLUGIN_MODULES."), message
