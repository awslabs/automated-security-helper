# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The pre-rename "community" spellings of the alpha tier are aliases through 4.0.

The opt-in scanners ASH ships but does not promote as supported were called
"community"; the tier is now "alpha". The old spellings that still work map to
the new one until ``COMMUNITY_ALIASES_DROPPED_IN`` (4.1.0): the tier values warn
once per process, and the Dockerfile build argument wins over the new one and
warns at build time. The docs-lint column headings are the exception: that lint
is internal, so the old headings are refused with the heading to use rather than
kept as aliases. Each
test here reads one old spelling through the real code path and fails when its
alias is gone, does not map, or stays silent where a warning is promised.
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


def test_the_alias_window_names_the_next_release():
    """4.0 keeps the aliases, so the release after it is the one that drops them."""
    assert plugin_manifest.COMMUNITY_ALIASES_DROPPED_IN == "4.1.0"


def test_the_aliases_are_gone_by_the_release_that_says_it_drops_them():
    """Fails at the version bump that reaches the release, forcing the removal."""
    from packaging.version import Version

    from automated_security_helper import __version__

    assert Version(__version__) < Version(
        plugin_manifest.COMMUNITY_ALIASES_DROPPED_IN
    ), (
        f"ASH {__version__} reached {plugin_manifest.COMMUNITY_ALIASES_DROPPED_IN}: "
        "remove the community aliases (plugin_manifest.warn_community_alias, "
        "PluginTier._missing_, the ASH_COMMUNITY_PLUGIN_MODULES build argument in "
        "the Dockerfile) and the alias-window tests in this module "
        "(test_the_old_dockerfile_build_argument_still_wins_over_the_new_one, "
        "test_the_renamed_anchors_keep_their_old_ids_for_the_alias_window) "
        "along with this test"
    )


def test_the_old_dockerfile_build_argument_still_wins_over_the_new_one():
    """`--build-arg ASH_COMMUNITY_PLUGIN_MODULES=...` is read until the alias window ends.

    An EXPLICITLY EMPTY value wins too (the CHANGELOG says a value given for the
    old name wins), so the default is a sentinel rather than "": a `:-` fallback
    cannot tell `--build-arg ASH_COMMUNITY_PLUGIN_MODULES=""` from the argument
    not being given. A build that gives the old name warns.
    """
    text = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert text.count('ARG ASH_COMMUNITY_PLUGIN_MODULES="__UNSET__"\n') == 2
    assert text.count('[ "${ASH_COMMUNITY_PLUGIN_MODULES}" = "__UNSET__" ]') == 2
    assert text.count('--config-overrides "ash_plugin_modules+=[${modules}]"') == 2
    assert (
        text.count("the ASH_COMMUNITY_PLUGIN_MODULES build argument is deprecated") == 2
    )
    assert "${ASH_COMMUNITY_PLUGIN_MODULES:-" not in text


def test_the_renamed_anchors_keep_their_old_ids_for_the_alias_window():
    """A page redirect cannot carry a #fragment, so the old ids stay as anchors."""
    choose = (REPO_ROOT / "docs/content/how-to/choose-scanners.md").read_text(
        encoding="utf-8"
    )
    assert '<a id="community"></a>' in choose
    trivy = (REPO_ROOT / "docs/content/docs/plugins/builtin/trivy.md").read_text(
        encoding="utf-8"
    )
    assert '<a id="running-it-alongside-the-trivy-repo-community-plugin"></a>' in trivy


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
