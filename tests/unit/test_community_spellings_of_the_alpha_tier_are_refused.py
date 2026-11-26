# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pre-rename "community" spellings of the alpha tier are refused from 4.0.

The opt-in scanners ASH ships but does not promote as supported were called
"community"; the tier is "alpha". Through 3.x the old spellings were aliases: the
tier values mapped to alpha and warned, and the Dockerfile build argument
ASH_COMMUNITY_PLUGIN_MODULES won over ASH_ALPHA_PLUGIN_MODULES. 4.0 removes the
aliases, as the release that announced the rename said it would: an old tier value
is refused like any other value that is not a tier, the image build reads only the
new build argument, and the docs keep no anchor ids for the old headings.

Two things were never aliases and stay: the docs lint refuses the old column
headings and names the heading to use, and each old docs page redirects to its
alpha page. Each test here reads one spelling through the real code path.
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
    """Capture ASH_LOGGER warnings."""
    import automated_security_helper.utils.log as log_module

    logger = MagicMock()
    monkeypatch.setattr(log_module, "ASH_LOGGER", logger)
    return logger


def _messages(logger: MagicMock) -> list[str]:
    return [call.args[0] for call in logger.warning.call_args_list]


@pytest.mark.parametrize("old", ["community", "community_optin"])
def test_an_old_tier_value_is_refused(warnings_logged, old):
    with pytest.raises(ValueError):
        PluginTier(old)
    assert _messages(warnings_logged) == []


def test_the_tier_values_are_the_three_tiers(warnings_logged):
    assert PluginTier("alpha") is PluginTier.ALPHA
    assert PluginTier("supported") is PluginTier.SUPPORTED
    assert PluginTier("deprecated") is PluginTier.DEPRECATED
    assert [tier.value for tier in PluginTier] == ["supported", "alpha", "deprecated"]
    assert _messages(warnings_logged) == []


def test_an_unrelated_tier_value_is_still_refused(warnings_logged):
    with pytest.raises(ValueError):
        PluginTier("beta")
    assert _messages(warnings_logged) == []


def test_the_alias_machinery_is_gone():
    for name in (
        "COMMUNITY_ALIASES_DROPPED_IN",
        "warn_community_alias",
        "_WARNED_COMMUNITY_ALIASES",
    ):
        assert not hasattr(plugin_manifest, name), name


@pytest.mark.parametrize("old", ["community", "community_optin"])
def test_the_manifest_model_refuses_the_old_tier_value(warnings_logged, old):
    from automated_security_helper.plugin_manifests import scanner_manifests

    data = scanner_manifests()[0].model_dump(mode="json")
    data["tier"] = old
    data["superseded_by"] = None
    with pytest.raises(ValueError, match="tier"):
        plugin_manifest.parse_scanner_manifest(data)
    assert _messages(warnings_logged) == []


def test_the_manifest_model_reads_the_alpha_tier_value(warnings_logged):
    from automated_security_helper.plugin_manifests import scanner_manifests

    data = scanner_manifests()[0].model_dump(mode="json")
    data["tier"] = "alpha"
    data["superseded_by"] = None
    assert plugin_manifest.parse_scanner_manifest(data).tier is PluginTier.ALPHA
    assert _messages(warnings_logged) == []


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
def test_an_old_scanner_column_heading_is_refused_naming_the_new_one(
    tmp_path, warnings_logged, old_heading, new_heading
):
    """The docs lint is internal: the old heading is a finding, not an alias."""
    dc = _docs_checks()
    page = tmp_path / "docs" / "page.md"
    page.parent.mkdir(parents=True)
    page.write_text(
        f"| What | {old_heading} |\n|---|---|\n| Python | snyk-code |\n",
        encoding="utf-8",
    )
    findings = dc.check_scanner_names([page], tmp_path)
    old = [f for f in findings if "is the old heading" in str(f)]
    assert len(old) == 1, findings
    assert str(page.relative_to(tmp_path)) in str(old[0]).replace("\\", "/")
    assert f"use '{new_heading.capitalize()}'" in str(old[0])
    assert _messages(warnings_logged) == []


def test_a_second_page_with_the_old_heading_is_reported_too(tmp_path):
    dc = _docs_checks()
    docs = tmp_path / "docs"
    docs.mkdir()
    for name in ("a.md", "b.md"):
        (docs / name).write_text(
            "| What | Community plugins |\n|---|---|\n| Python | snyk-code |\n",
            encoding="utf-8",
        )
    findings = dc.check_scanner_names([docs / "a.md", docs / "b.md"], tmp_path)
    assert len([f for f in findings if "is the old heading" in str(f)]) == 2


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


def test_the_image_build_reads_only_the_alpha_build_argument():
    """Both stages take the module list from ASH_ALPHA_PLUGIN_MODULES alone.

    `--build-arg ASH_COMMUNITY_PLUGIN_MODULES=...` is a build argument no ARG
    declares, so the build ignores it (docker names it as unconsumed) and installs
    the alpha modules' tools as it does without it.
    """
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    instructions = "\n".join(
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    )
    assert "ASH_COMMUNITY_PLUGIN_MODULES" not in instructions
    assert "__UNSET__" not in instructions
    assert text.count('    modules="${ASH_ALPHA_PLUGIN_MODULES}" && \\\n') == 2
    assert text.count('--config-overrides "ash_plugin_modules+=[${modules}]"') == 2


def test_the_old_anchor_ids_are_gone_and_the_alpha_ones_stay():
    choose = (REPO_ROOT / "docs/content/how-to/choose-scanners.md").read_text(
        encoding="utf-8"
    )
    assert '<a id="community"></a>' not in choose
    assert '<a id="alpha"></a>' in choose
    trivy = (REPO_ROOT / "docs/content/docs/plugins/builtin/trivy.md").read_text(
        encoding="utf-8"
    )
    assert "trivy-repo-community-plugin" not in trivy
    assert '<a id="running-it-alongside-the-trivy-repo-alpha-plugin"></a>' in trivy


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
