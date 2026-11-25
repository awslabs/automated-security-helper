# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pre-rename "community" spellings of the alpha tier are aliases for one release.

The opt-in scanners ASH ships but does not promote as supported were called
"community"; the tier is now "alpha". Every old user-facing spelling still works,
maps to the new one, and warns once, naming the release that drops it. Each test
here reads one old spelling through the real code path and fails when the alias
is gone, does not map, or stays silent.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import yaml

from automated_security_helper.base import plugin_manifest
from automated_security_helper.base.plugin_manifest import PluginTier

REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.unit


@pytest.fixture
def warnings_logged(monkeypatch):
    """Capture ASH_LOGGER warnings and forget which aliases already warned."""
    import automated_security_helper.utils.log as log_module

    logger = MagicMock()
    monkeypatch.setattr(log_module, "ASH_LOGGER", logger)
    monkeypatch.setattr(plugin_manifest, "_WARNED_COMMUNITY_ALIASES", set())
    return logger


def _messages(logger: MagicMock) -> list[str]:
    return [call.args[0] for call in logger.warning.call_args_list]


@pytest.mark.parametrize("old", ["community", "community_optin"])
def test_the_old_tier_value_maps_to_the_alpha_tier_and_warns(warnings_logged, old):
    assert PluginTier(old) is PluginTier.ALPHA
    messages = _messages(warnings_logged)
    assert len(messages) == 1
    assert f"'{old}' is deprecated" in messages[0]
    assert "'alpha'" in messages[0]
    assert plugin_manifest.COMMUNITY_ALIASES_DROPPED_IN in messages[0]


def test_the_old_tier_value_warns_once_per_process(warnings_logged):
    PluginTier("community")
    PluginTier("community")
    assert len(_messages(warnings_logged)) == 1


def test_the_new_tier_value_does_not_warn(warnings_logged):
    assert PluginTier("alpha") is PluginTier.ALPHA
    assert PluginTier("supported") is PluginTier.SUPPORTED
    assert PluginTier("deprecated") is PluginTier.DEPRECATED
    assert _messages(warnings_logged) == []


def test_an_unrelated_tier_value_is_still_refused(warnings_logged):
    with pytest.raises(ValueError):
        PluginTier("beta")
    assert _messages(warnings_logged) == []


def test_the_manifest_model_accepts_the_old_tier_value(warnings_logged):
    from automated_security_helper.plugin_manifests import scanner_manifests

    data = scanner_manifests()[0].model_dump(mode="json")
    data["tier"] = "community"
    data["superseded_by"] = None
    manifest = plugin_manifest.parse_scanner_manifest(data)
    assert manifest.tier is PluginTier.ALPHA
    assert len(_messages(warnings_logged)) == 1


def _docs_checks():
    """scripts/docs_checks.py, loaded by path as the docs-check tests load it."""
    import importlib.util
    import sys

    name = "_ash_docs_checks"
    if name in sys.modules:
        return sys.modules[name]
    if str(REPO_ROOT) not in sys.path:
        sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location(
        name, REPO_ROOT / "scripts" / "docs_checks.py"
    )
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    "old_heading,new_heading",
    [
        ("Community plugins", "alpha plugins"),
        ("Community scanners", "alpha scanners"),
    ],
)
def test_an_old_scanner_column_heading_is_checked_as_alpha_and_warns(
    tmp_path, warnings_logged, old_heading, new_heading
):
    dc = _docs_checks()
    page = tmp_path / "docs" / "page.md"
    page.parent.mkdir(parents=True)
    # bandit is built in: under the old heading it must be refused as built in,
    # which proves the heading still names the (renamed) alpha kind.
    page.write_text(
        f"| What | {old_heading} |\n|---|---|\n| Python | bandit |\n",
        encoding="utf-8",
    )
    findings = dc.check_scanner_names([page], tmp_path)
    assert any("is a built-in scanner" in str(f) for f in findings), findings
    messages = _messages(warnings_logged)
    assert len(messages) == 1
    assert f"'{old_heading.lower()}' is deprecated" in messages[0]
    assert f"'{new_heading}'" in messages[0]


def test_the_new_scanner_column_heading_does_not_warn(tmp_path, warnings_logged):
    dc = _docs_checks()
    page = tmp_path / "docs" / "page.md"
    page.parent.mkdir(parents=True)
    page.write_text(
        "| What | Alpha plugins |\n|---|---|\n| Python | snyk-code |\n",
        encoding="utf-8",
    )
    assert dc.check_scanner_names([page], tmp_path) == []
    assert _messages(warnings_logged) == []


def test_the_alias_window_names_the_next_release():
    assert plugin_manifest.COMMUNITY_ALIASES_DROPPED_IN == "3.9.0"


def test_every_old_docs_page_redirects_to_its_alpha_page():
    redirects = yaml.safe_load((REPO_ROOT / "docs" / "redirects.yml").read_text())[
        "redirects"
    ]
    content = REPO_ROOT / "docs" / "content"
    alpha_pages = sorted((content / "docs" / "plugins" / "alpha").glob("*.md"))
    assert alpha_pages, "the alpha plugin pages moved or the glob is wrong"
    for page in alpha_pages:
        old = f"docs/plugins/community/{page.name}"
        new = f"docs/plugins/alpha/{page.name}"
        assert redirects.get(old) == new, f"{old} must redirect to {new}"
        assert not (content / old).exists(), f"{old} is still a page"
