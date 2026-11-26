# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""What ``docs/plugins/alpha/binskim-plugin.md`` says about the BinSkim plugin is true.

The page tells an operator how to turn the plugin on, how to install the pinned tool,
which builds exist, what ASH passes to BinSkim, how its levels are rated, and which
variable every run sets. Each test below pins one of those passages with
``assert_on_page`` and reads what makes it true from the code: the module the page
lists, the scanner's defaults, ``binskim_install.py``'s pin and build table, the argv
and environment one run gets, ``BINSKIM_LEVEL_MAP`` and the license table. A pin bump,
a renamed option or a changed flag then fails here until the page says the same.

Not pinned: the description of what BinSkim checks (the tool's own scope), the
suppression example (ASH's shared suppression rules hold it), and the offline
paragraph, which restates the network facet the scanner's own tests pin.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path
from typing import Any, List

import pytest
import yaml

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_binskim_plugins import (
    binskim_install,
)
from automated_security_helper.plugin_modules.ash_binskim_plugins import (
    binskim_scanner as bs,
)
from automated_security_helper.utils.tool_downloads import THIRD_PARTY_LICENSES
from tests.unit.docs.test_page_claims import _page_text, assert_on_page

pytestmark = pytest.mark.unit

BINSKIM_PAGE = "docs/plugins/alpha/binskim-plugin.md"
BINSKIM_MODULE = "automated_security_helper.plugin_modules.ash_binskim_plugins"
INSTALL_COMMAND = (
    "ash dependencies install --config-overrides "
    f"'ash_plugin_modules+=[\"{BINSKIM_MODULE}\"]' --tool binskim"
)


def _yaml_block(start: str) -> Any:
    """The YAML of the page's fenced block that opens with ``start``."""
    blocks = re.findall(r"```yaml\n(.*?)```", _page_text(BINSKIM_PAGE), flags=re.DOTALL)
    (block,) = [text for text in blocks if text.lstrip().startswith(start)]
    return yaml.safe_load(block)


def _scanner(tmp_path: Path) -> bs.BinskimScanner:
    """A BinSkim scanner over an empty tree, built as a scan builds it."""
    source = tmp_path / "src"
    source.mkdir()
    output = tmp_path / "out"
    return bs.BinskimScanner(
        context=PluginContext(
            source_dir=source,
            output_dir=output,
            work_dir=output / "converted",
            config=get_default_config(),
        ),
        config=bs.BinskimScannerConfig(),
    )


def test_the_page_lists_the_module_that_ships_the_scanner() -> None:
    """Enabling: the module the page lists is importable and offers ``binskim``, which
    runs once listed."""
    assert_on_page(BINSKIM_PAGE, "With the module listed, `binskim` runs by default.")
    assert _yaml_block("ash_plugin_modules:") == {
        "ash_plugin_modules": [BINSKIM_MODULE]
    }
    module = importlib.import_module(BINSKIM_MODULE)
    assert module.ASH_SCANNERS == [bs.BinskimScanner]
    assert bs.BinskimScannerConfig().name == "binskim"
    assert bs.BinskimScannerConfig().enabled is True


def test_the_configuration_block_is_the_scanners_defaults() -> None:
    """Configuration: every option the block shows is the scanner's default value."""
    shown = _yaml_block("scanners:")["scanners"]["binskim"]
    defaults = bs.BinskimScannerConfig()
    assert shown["enabled"] is defaults.enabled
    assert set(shown["options"]) == {"scan_timeout", "severity_threshold"}
    for key, value in shown["options"].items():
        assert getattr(defaults.options, key) == value, key
    assert_on_page(
        BINSKIM_PAGE,
        "# Seconds for the whole BinSkim scan "
        f"(default {defaults.options.scan_timeout}; null for no limit).",
    )


def test_the_install_section_names_the_pin_and_the_builds_the_installer_holds() -> None:
    """Installing BinSkim: the version, the published builds, the tree name and the
    platforms with no build are binskim_install.py's."""
    version = binskim_install.BINSKIM_VERSION
    assert_on_page(
        BINSKIM_PAGE, f"ASH pins BinSkim {version} in the plugin's own install module"
    )
    rids = list(binskim_install.RIDS.values())
    named = ", ".join(f"`{rid}`" for rid in rids[:-1]) + f" and `{rids[-1]}`"
    assert_on_page(
        BINSKIM_PAGE,
        f"The package holds a self-contained build for {named}, so no .NET install "
        "is needed.",
    )
    assert_on_page(
        BINSKIM_PAGE,
        f"The host's build is extracted into `{binskim_install.tree_name('<rid>')}/` "
        "in ASH's bin directory",
    )
    assert_on_page(
        BINSKIM_PAGE,
        "BinSkim publishes no build for Apple silicon (`osx-arm64`), 32-bit Linux or "
        "Windows on Arm, so ASH installs nothing on those platforms.",
    )
    for pair in (("darwin", "arm64"), ("windows", "arm64")):
        assert pair not in binskim_install.RIDS, pair


def test_the_install_command_is_the_one_the_scanner_tells_an_operator_to_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The command on the page is the command the missing-tool warning names."""
    assert_on_page(BINSKIM_PAGE, INSTALL_COMMAND)
    monkeypatch.setattr(bs, "find_executable", lambda command: None)
    monkeypatch.setattr(bs, "installed_executable", lambda: None)
    seen: List[str] = []
    monkeypatch.setattr(
        bs.ASH_LOGGER, "warning", lambda message, *a, **k: seen.append(message)
    )
    assert _scanner(tmp_path).validate_plugin_dependencies() is False
    assert len(seen) == 1
    assert f"`{INSTALL_COMMAND}`" in seen[0]


def test_the_flags_the_page_names_are_the_ones_a_run_is_given(tmp_path: Path) -> None:
    """What is scanned: the level and kind filters are passed, and no policy file or
    symbol path is."""
    assert_on_page(
        BINSKIM_PAGE,
        "ASH passes `--level=Error;Warning;Note` and `--kind=Fail`, so passing and "
        "not-applicable results are not written.",
    )
    assert_on_page(
        BINSKIM_PAGE,
        "It passes no `--config`, so a policy file in the scanned tree is not read, "
        "and no `--sympath`, so no symbol server is contacted.",
    )
    assert_on_page(
        BINSKIM_PAGE, "BinSkim is handed the whole target with `--recurse=true`"
    )
    scanner = _scanner(tmp_path)
    argv = scanner._build_arguments(tmp_path / "src", tmp_path / "out" / "b.sarif")
    for flag in ("--level=Error;Warning;Note", "--kind=Fail", "--recurse=true"):
        assert flag in argv, flag
    assert not [a for a in argv if a.startswith(("--config", "--sympath"))]


def test_the_severity_table_is_the_adapters_map() -> None:
    """Severity: one row per level the adapter rates, the level-less row included, and
    none of them CRITICAL."""
    assert_on_page(BINSKIM_PAGE, "| BinSkim SARIF level | ASH severity |")
    rows = dict(
        re.findall(
            r"^\| (`[a-z]+`|none) \| ([A-Z]+) \|$",
            _page_text(BINSKIM_PAGE),
            flags=re.MULTILINE,
        )
    )
    expected = {
        f"`{level}`": severity for level, (severity, _) in bs.BINSKIM_LEVEL_MAP.items()
    }
    expected["none"] = bs.DEFAULT_SEVERITY[0]
    assert rows == expected
    assert_on_page(
        BINSKIM_PAGE,
        "A missing mitigation is a hardening gap and not a vulnerability by itself, "
        "so no result is CRITICAL.",
    )
    assert "CRITICAL" not in rows.values()


def test_the_globalization_variable_is_set_on_every_run(tmp_path: Path) -> None:
    """Globalization: the variable the page names is set to 1 in the environment one
    run is given."""
    assert_on_page(
        BINSKIM_PAGE,
        f"so every run sets `{bs.GLOBALIZATION_INVARIANT_ENV}=1`, on every host",
    )
    scanner = _scanner(tmp_path)
    scanner.results_dir = tmp_path / "results"
    _argv, _results_file, env = scanner._execute_scan(tmp_path / "src", "source", [])
    assert env[bs.GLOBALIZATION_INVARIANT_ENV] == "1"


def test_the_license_section_names_the_entry_the_image_carries() -> None:
    """License: the license and the pinned release of the ``binskim`` entry."""
    assert_on_page(BINSKIM_PAGE, "BinSkim is MIT-licensed.")
    assert_on_page(BINSKIM_PAGE, "the `binskim` entry in `THIRD_PARTY_LICENSES`")
    entry = THIRD_PARTY_LICENSES["binskim"]
    assert entry.license == "MIT"
    assert entry.version == f"v{binskim_install.BINSKIM_VERSION}"
