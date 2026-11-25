# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Reading a manifest loads no plugin.

Importing a plugin package fires its ``@ash_scanner_plugin`` registrations, so
a manifest that was read by importing its plugin could not tell the scan phase
"this scanner exists but is not loaded". Each check runs in a FRESH interpreter
(``-I``: no ``PYTHON*`` variables, no cwd on the path), because this process has
already imported the plugins and its ``sys.modules`` proves nothing.

The planted control imports one plugin package in the same kind of child and
requires the check to see it, so a probe that could not see a plugin load fails
here instead of passing every other row.
"""

from __future__ import annotations

import json
import subprocess
import sys

import pytest

pytestmark = pytest.mark.unit

_PROBE = """
import json, sys
{imports}
loaded = sorted(
    name for name in sys.modules
    if name.startswith("automated_security_helper.plugin_modules.")
)
print(json.dumps({{"plugin_modules": loaded}}))
"""


def _run(imports: str) -> list[str]:
    result = subprocess.run(
        [sys.executable, "-I", "-B", "-c", _PROBE.format(imports=imports)],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stderr[-2000:]
    return json.loads(result.stdout.strip().splitlines()[-1])["plugin_modules"]


def test_the_probe_sees_a_plugin_load() -> None:
    """Planted control: importing a plugin package is visible to the probe."""
    loaded = _run("import automated_security_helper.plugin_modules.ash_snyk_plugins")
    assert any("ash_snyk_plugins" in name for name in loaded), loaded


def test_importing_every_manifest_loads_no_plugin_module() -> None:
    loaded = _run(
        "from automated_security_helper.plugin_manifests import ("
        "scanner_manifests, alpha_scanner_modules, dispatch_target)\n"
        "assert len(scanner_manifests()) == 22\n"
        "assert alpha_scanner_modules()\n"
        "assert dispatch_target('semgrep') == 'opengrep'\n"
    )
    assert loaded == [], f"reading manifests imported plugin modules: {loaded}"


def test_the_model_module_loads_no_plugin_module() -> None:
    loaded = _run("import automated_security_helper.base.plugin_manifest")
    assert loaded == [], loaded
