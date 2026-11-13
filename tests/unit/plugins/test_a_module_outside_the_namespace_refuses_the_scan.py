# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An ``ash_plugin_modules`` entry outside the plugin namespace refuses the scan.

The scan refuses such an entry before any import, so a config that misspells
its plugin package does not run without the plugins it asked for. The documented
behavior is a refusal: the scan exits 3 (invalid configuration) before any
named module is imported, naming each refused entry and the namespace rule
(``refuse_plugin_modules_outside_namespace``).

Each cell plants its modules under its own tmp_path and reads back whether an
import ran, from ``sys.modules`` and from a marker file the module writes when
it is imported. The refusal must come before any import, so an accepted name
beside a refused one is not imported either.
"""

from __future__ import annotations

import sys

import pytest
from typer.testing import CliRunner

from automated_security_helper.cli.main import app

pytestmark = pytest.mark.unit

#: The refusal's own words, which the scan shows with exit 3.
WORDS = "is not a plugin module ASH imports"
NOTHING = "Nothing was imported and nothing was scanned"

#: A name outside the namespace, and one inside it, both importable when planted.
OUTSIDE = "outside_module"
BESIDE = "beside_ash_plugins"


@pytest.fixture
def planted_modules(tmp_path, monkeypatch):
    """Two importable modules on sys.path, each writing a marker when imported."""
    monkeypatch.setenv("COLUMNS", "400")
    monkeypatch.setenv("NO_COLOR", "1")
    monkeypatch.chdir(tmp_path)
    modules = tmp_path / "modules"
    modules.mkdir()
    for name in (OUTSIDE, BESIDE):
        (modules / f"{name}.py").write_text(
            "from pathlib import Path\n"
            "Path(__file__).with_suffix('.imported').write_text('ran')\n"
        )
        monkeypatch.delitem(sys.modules, name, raising=False)
    monkeypatch.syspath_prepend(str(modules))
    yield modules
    for name in (OUTSIDE, BESIDE):
        sys.modules.pop(name, None)


def _scan(tmp_path, entries: str):
    source = tmp_path / "src"
    source.mkdir(exist_ok=True)
    (source / "README.md").write_text("sample\n")
    return CliRunner().invoke(
        app,
        [
            "scan",
            "--source-dir",
            str(source),
            "--output-dir",
            str(tmp_path / "out"),
            "--no-progress",
            "--python-based-plugins-only",
            "--scanners",
            "detect-secrets",
            "--ash-plugin-modules",
            entries,
        ],
    )


def test_a_scan_naming_a_module_outside_the_namespace_exits_3(
    tmp_path, planted_modules, no_tool_probes
):
    """The scan refuses with exit 3 in the refusal's words, and imports nothing.

    The entry names the refused module beside an accepted one: the refusal comes
    before any import, so the accepted module is not imported either.
    """
    result = _scan(tmp_path, f"{OUTSIDE},{BESIDE}")

    assert result.exit_code == 3, result.output
    assert WORDS in result.output, result.output
    assert NOTHING in result.output, result.output
    assert OUTSIDE in result.output, result.output
    assert OUTSIDE not in sys.modules
    assert BESIDE not in sys.modules
    assert not (planted_modules / f"{OUTSIDE}.imported").exists()
    assert not (planted_modules / f"{BESIDE}.imported").exists()


def test_a_scan_naming_only_namespace_modules_is_not_refused(
    tmp_path, planted_modules, no_tool_probes
):
    """The control: a name inside the namespace imports and draws no refusal."""
    result = _scan(tmp_path, BESIDE)

    assert WORDS not in result.output, result.output
    # Exactly 0: a crash with exit 1 or 2 would also not be the refusal's 3.
    assert result.exit_code == 0, (result.exit_code, result.output)
    assert (planted_modules / f"{BESIDE}.imported").exists()


def test_the_refusal_names_each_refused_entry_and_the_rule(planted_modules):
    from automated_security_helper.core.exceptions import ASHConfigValidationError
    from automated_security_helper.plugins.loader import (
        PluginModuleNamespaceError,
        refuse_plugin_modules_outside_namespace,
    )

    with pytest.raises(PluginModuleNamespaceError) as refused:
        refuse_plugin_modules_outside_namespace([OUTSIDE, "my plugins", BESIDE])

    message = str(refused.value)
    assert WORDS in message
    assert NOTHING in message
    assert repr(OUTSIDE) in message
    assert repr("my plugins") in message
    assert BESIDE not in message
    # A scan maps every ASHConfigValidationError to exit 3.
    assert isinstance(refused.value, ASHConfigValidationError)


def test_a_namespace_package_is_refused(tmp_path, planted_modules):
    """A directory with no __init__.py declares no plugins, so naming it refuses."""
    from automated_security_helper.plugins.loader import (
        PluginModuleNamespaceError,
        refuse_plugin_modules_outside_namespace,
    )

    (planted_modules / "nspkg_ash_plugins").mkdir()

    with pytest.raises(PluginModuleNamespaceError) as refused:
        refuse_plugin_modules_outside_namespace(["nspkg_ash_plugins"])

    assert "namespace package" in str(refused.value)


def test_the_suffix_needs_its_separator(planted_modules):
    """The top-level package is 'ash_plugins' or ends in '_ash_plugins', so a
    name that only ends in the letters, such as 'myash_plugins', is refused."""
    from automated_security_helper.plugins.loader import (
        PluginModuleNamespaceError,
        refuse_plugin_modules_outside_namespace,
    )

    with pytest.raises(PluginModuleNamespaceError):
        refuse_plugin_modules_outside_namespace(["myash_plugins"])


def test_names_inside_the_namespace_are_accepted(planted_modules):
    from automated_security_helper.plugins.loader import (
        refuse_plugin_modules_outside_namespace,
    )

    refuse_plugin_modules_outside_namespace(
        [
            BESIDE,
            "ash_plugins.extra",
            "automated_security_helper.plugin_modules.ash_builtin",
            "",
        ]
    )
