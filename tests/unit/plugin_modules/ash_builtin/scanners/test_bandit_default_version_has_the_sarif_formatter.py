# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The default bandit version range admits only releases that can write SARIF.

ASH runs bandit with ``--format sarif``. Bandit added its SARIF output formatter
in release 1.7.8 (https://github.com/PyCQA/bandit/releases/tag/1.7.8, "Add a
SARIF output formatter", pull request 1113); the release notes of 1.7.7
(https://github.com/PyCQA/bandit/releases/tag/1.7.7) do not mention it. The
default ``tool_version`` used to start at 1.7.0, so seven bandit releases passed
the version check and then failed when the scan asked for a format they do not
have. The extras check does not catch that: it looks at the extras and the
constraint, never at which formatters a release ships.

The range is checked as a range, with the same parser ``pre_installed_tool``
uses, so a rewording of the default cannot keep the text and lose the meaning.
"""

import pytest
from packaging.specifiers import SpecifierSet

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
    BanditScanner,
    BanditScannerConfig,
    BanditScannerConfigOptions,
)

pytestmark = pytest.mark.unit

DEFAULT_RANGE = BanditScannerConfigOptions().tool_version


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True)
    return context


def _scanner(plugin_context, **options) -> BanditScanner:
    return BanditScanner(
        context=plugin_context,
        config=BanditScannerConfig(options=BanditScannerConfigOptions(**options)),
    )


def test_the_default_range_starts_at_the_first_release_with_the_sarif_formatter():
    assert DEFAULT_RANGE == ">=1.7.8,<2.0.0"


@pytest.mark.parametrize(
    "release", ["1.7.0", "1.7.1", "1.7.4", "1.7.5", "1.7.6", "1.7.7"]
)
def test_a_release_without_the_sarif_formatter_is_outside_the_default_range(release):
    assert release not in SpecifierSet(DEFAULT_RANGE)


@pytest.mark.parametrize("release", ["1.7.8", "1.7.10", "1.8.0", "1.9.4"])
def test_a_release_with_the_sarif_formatter_is_inside_the_default_range(release):
    assert release in SpecifierSet(DEFAULT_RANGE)


def test_the_next_major_version_stays_outside_the_default_range():
    assert "2.0.0" not in SpecifierSet(DEFAULT_RANGE)


def test_an_unset_scanner_installs_bandit_under_the_default_range(plugin_context):
    scanner = _scanner(plugin_context)

    assert scanner._get_tool_version_constraint() == DEFAULT_RANGE
    assert scanner._uv_from_spec() == f"bandit[sarif,toml]{DEFAULT_RANGE}"


def test_a_null_tool_version_falls_back_to_the_default_range(plugin_context):
    scanner = _scanner(plugin_context, tool_version=None)

    assert scanner._get_tool_version_constraint() == DEFAULT_RANGE


def test_a_configured_tool_version_is_used_as_written(plugin_context):
    scanner = _scanner(plugin_context, tool_version=">=1.8.0,<2.0.0")

    assert scanner._get_tool_version_constraint() == ">=1.8.0,<2.0.0"
    assert scanner._uv_from_spec() == "bandit[sarif,toml]>=1.8.0,<2.0.0"
