# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The import refusal names an env-read plugin module masked, error text included.

The refusal labels an ``ash_plugin_modules`` entry the config read from the
environment as ``<value>``, but a module's import error routinely quotes the
module's own name -- ``cannot import name ... from 'the_module'``, ``No module
named 'the_module.sub'`` -- so quoting the recorded error beside the masked
label puts the variable's value in the refusal anyway: on the console, in the
scan's exit-3 message, and in every surface that prints the refusal (report,
dependencies install, merge, plugin list, the MCP progress record and ash.log).
For a masked name only the error's kind may be said, the way the import log's
:func:`~automated_security_helper.plugins.discovery.shown_import_failure`
already says it.

The canary package exists and is inside the plugin namespace, so the run
reaches the import, which fails with the package's own name in the error text.
"""

from __future__ import annotations

import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app
from tests.utils.helpers import builtin_scanner_config_names

pytestmark = pytest.mark.unit

#: The variable's value: a plantable namespace package whose name nothing else
#: in these runs would print, so finding it in the refusal is the leak.
CANARY = "refusalcanary_ash_plugins"


@pytest.fixture
def env_read_broken_config(tmp_path, monkeypatch):
    """A config whose one entry reads the canary from the environment.

    The canary package imports a name it does not define, so the import fails
    with ``ImportError: cannot import name ... from 'refusalcanary_ash_plugins'``
    -- error text that quotes the env-read value.
    """
    modules = tmp_path / "modules"
    (modules / CANARY).mkdir(parents=True)
    (modules / CANARY / "__init__.py").write_text(
        f"from {CANARY} import does_not_exist  # noqa: F401\n", encoding="utf-8"
    )
    monkeypatch.syspath_prepend(str(modules))
    monkeypatch.delitem(sys.modules, CANARY, raising=False)
    monkeypatch.setenv("ASH_REFUSALCANARY", CANARY)
    source = tmp_path / "src"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    monkeypatch.chdir(source)
    # Every built-in scanner disabled, derived from the registry so a newly
    # shipped one stays covered: the scan cell measures only the plugin, and
    # even the fail-open state would select nothing.
    disabled = "".join(
        f"  {name}:\n    enabled: false\n" for name in builtin_scanner_config_names()
    )
    config_file = tmp_path / "cfg" / ".ash.yaml"
    config_file.parent.mkdir()
    config_file.write_text(
        "project_name: probe\n"
        "ash_plugin_modules:\n  - !ENV ${ASH_REFUSALCANARY}\n"
        f"scanners:\n{disabled}",
        encoding="utf-8",
    )
    yield config_file
    sys.modules.pop(CANARY, None)


def test_the_refusal_text_says_the_errors_kind_and_never_the_value(
    tmp_path, env_read_broken_config
):
    """The exception the loader raises: the masked label and the error's kind,
    with the error's own text left out because it quotes the name."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugins.loader import (
        PluginModuleImportError,
        load_plugins,
    )

    config = resolve_config(config_path=str(env_read_broken_config))
    with pytest.raises(PluginModuleImportError) as caught:
        load_plugins(
            plugin_context=PluginContext(
                source_dir=tmp_path / "src",
                output_dir=tmp_path / "out",
                work_dir=tmp_path / "out" / "work",
                config=config,
            )
        )

    text = str(caught.value)
    assert CANARY not in text, text
    assert "'<value>'" in text, text
    assert "ImportError" in text, text


def test_a_scans_refusal_output_never_quotes_the_env_value(
    tmp_path, env_read_broken_config
):
    """The whole scan output on the refusal path: the value appears nowhere --
    not in the refusal, not in the loader's warning line beside it."""
    result = CliRunner().invoke(
        app,
        [
            "scan",
            "--mode",
            "local",
            "--no-progress",
            "--source-dir",
            str(tmp_path / "src"),
            "--output-dir",
            str(tmp_path / "out"),
            "--config",
            str(env_read_broken_config),
        ],
        env={"NO_COLOR": "1", "COLUMNS": "250"},
    )

    assert result.exit_code == 3, result.output[-4000:]
    assert CANARY not in result.output, result.output[-4000:]
    assert "<value>" in result.output, result.output[-4000:]
