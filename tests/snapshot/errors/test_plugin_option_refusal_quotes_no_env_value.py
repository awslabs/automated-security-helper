# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A loaded plugin's option refusal names no value read from the environment.

The options of a plugin from ``ash_plugin_modules`` are checked once the
plugins load (``config/plugin_option_check.py``), and the refusal names each
option by its location. A key the file reads from the environment, here the
plain ``${ASH_PROBE_VALUE}: true`` under ``scanners.trivy-repo.options`` or
beside its ``enabled``, is the environment's value by then, so the exit-3
refusal names it by its location and leaves the value out. A built-in plugin's
section redacts the same key, as every config refusal does.
"""

from __future__ import annotations

from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

CANARY = "ash-canary-7f3e-0123456789"
TRIVY_PLUGINS = "automated_security_helper.plugin_modules.ash_trivy_plugins"

_HEAD = (
    "project_name: demo\n"
    "ash_plugin_modules:\n"
    f"  - {TRIVY_PLUGINS}\n"
    "scanners:\n"
    "  trivy-repo:\n"
    "    enabled: true\n"
)
# The env-read key, and the location the refusal names for it.
_SHAPES = {
    "option key": (
        _HEAD + "    options:\n      ${ASH_PROBE_VALUE}: true\n",
        "scanners.trivy-repo.options",
    ),
    "section key": (_HEAD + "    ${ASH_PROBE_VALUE}: true\n", "scanners.trivy-repo"),
}


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize("shape", sorted(_SHAPES))
@pytest.mark.parametrize("source", ["repository file", "--config", "ASH_CONFIG"])
def test_an_env_read_key_of_a_loaded_plugin(
    run_cli, in_tmp, monkeypatch, shape, source
):
    """``ASH_CONFIG`` is the configuration a scan starts from when the scanned
    tree has none and none is named (config/default_config.py)."""
    monkeypatch.setenv("ASH_PROBE_VALUE", CANARY)
    text, location = _SHAPES[shape]
    _write(in_tmp / "src" / "app.py", "print('hello')\n")
    args = ["scan", "--no-progress", "--source-dir", "src", "--output-dir", "out"]
    if source == "--config":
        args += ["--config", str(_write(in_tmp / "op.yaml", text))]
    elif source == "ASH_CONFIG":
        monkeypatch.setenv("ASH_CONFIG", str(_write(in_tmp / "env.yaml", text)))
    else:
        _write(in_tmp / "src" / ".ash" / ".ash.yaml", text)
    seen = run_cli(args)

    printed = (
        f"{seen['stdout']}\n{seen['stderr']}\n{seen.get('uncaught_exception', '')}"
    )
    # The control: the key was refused, as an invalid configuration, and it
    # was read from the environment: the refusal shows the marker where the
    # value would be, not the reference as written.
    assert seen["exit_code"] == 3, seen
    assert location in " ".join(printed.split()), printed
    assert "'<value>'" in printed, printed
    assert CANARY not in printed, printed
    for path in (in_tmp / "out").rglob("*"):
        if path.is_file():
            text = path.read_text(encoding="utf-8", errors="replace")
            assert CANARY not in text, path
