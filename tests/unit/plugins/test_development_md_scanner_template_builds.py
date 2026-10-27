# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""DEVELOPMENT.md's scanner template builds as written.

The template is what a plugin author copies first, and the defect class is
docs that compile in the reader's head but not in Python: the previous
template referenced a config class it never defined, overrode ``scan`` with a
body of ``pass`` where the base's template calls ``_execute_scan``, and said
nothing about where the uv helpers live or what ``use_uv_tool`` False means.
This test executes the template straight from the file, builds the scanner it
defines against a real context, and drives its ``_execute_scan``.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugins import ash_plugin_manager

REPO_ROOT = Path(__file__).resolve().parents[3]


def _template() -> str:
    """The first fenced python block after the Base Scanner Plugin heading."""
    text = (REPO_ROOT / "DEVELOPMENT.md").read_text(encoding="utf-8")
    section = text.split("### Base Scanner Plugin", 1)[1]
    match = re.search(r"```python\n(.*?)```", section, flags=re.DOTALL)
    assert match is not None, "no python block under '### Base Scanner Plugin'"
    return match.group(1)


@pytest.fixture
def registry_restored():
    """The decorator in the template auto-registers; put the registry back.

    Through the manager's own API (remove_plugin_module_registration, the
    documented inverse of what the decorator did), never by rewriting the
    manager's state: the isolation sweep
    (test_project_isolation.py::TestPluginManagerSingletonState) fails any
    other file that touches plugin_library or _resolved_plugins directly, and
    the removal's docstring records that the resolved memo follows the
    registrations, so no cache needs touching.
    """
    yield
    removed = ash_plugin_manager.remove_plugin_module_registration(
        "scanner", "MyCustomScanner"
    )
    # The control: the template registered under the class's name, so this
    # removal is what puts the registry back; False would mean the template's
    # registration leaked under another name.
    assert removed, "the template's scanner was not registered as MyCustomScanner"


def test_the_scanner_template_builds_and_drives_the_scan_hook(
    tmp_path, monkeypatch, registry_restored
):
    # The template's model_post_init asks uv for the tool's version; this test
    # builds the class and drives _execute_scan, and starts no tool, so the
    # runner answers "unavailable" and _get_uv_tool_version returns None.
    class _NoUv:
        def is_uv_available(self) -> bool:
            return False

        def unavailable_reason(self) -> str:
            return "uv is not consulted while building the documented template"

    monkeypatch.setattr(
        "automated_security_helper.utils.uv_tool_runner.get_uv_tool_runner",
        lambda: _NoUv(),
    )

    namespace: dict = {}
    exec(compile(_template(), "DEVELOPMENT.md", "exec"), namespace)  # nosec B102 - the repo's own documented template

    scanner_class = namespace["MyCustomScanner"]
    config_class = namespace["MyCustomScannerConfig"]
    source = tmp_path / "src"
    output = tmp_path / "out"
    (output / "work").mkdir(parents=True)
    source.mkdir()
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "work",
        config=AshConfig(project_name="template"),
    )

    scanner = scanner_class(context=context, config=config_class())

    final_args, results_file, env = scanner._execute_scan(source, "source", [])
    # The controls: the invocation names the tool, the target and the results
    # file the base template will read back, and inherits the environment.
    assert final_args[0] == "my-tool", final_args
    assert str(source) in final_args, final_args
    assert str(results_file) in final_args, final_args
    assert results_file.parent.is_dir()
    assert env is None
