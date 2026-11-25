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

from automated_security_helper.base import scanner_operational_facets as opsf
from automated_security_helper.core import alpha_scanners

REPO_ROOT = Path(__file__).resolve().parents[2]

pytestmark = pytest.mark.unit


@pytest.fixture
def warnings_logged(monkeypatch):
    """Capture ASH_LOGGER warnings and forget which aliases already warned."""
    import automated_security_helper.utils.log as log_module

    logger = MagicMock()
    monkeypatch.setattr(log_module, "ASH_LOGGER", logger)
    monkeypatch.setattr(alpha_scanners, "_WARNED_COMMUNITY_ALIASES", set())
    return logger


def _messages(logger: MagicMock) -> list[str]:
    return [call.args[0] for call in logger.warning.call_args_list]


def test_the_old_tier_value_maps_to_the_alpha_tier_and_warns(warnings_logged):
    assert opsf.Tier("community_optin") is opsf.Tier.ALPHA_OPTIN
    messages = _messages(warnings_logged)
    assert len(messages) == 1
    assert "'community_optin' is deprecated" in messages[0]
    assert "'alpha_optin'" in messages[0]
    assert alpha_scanners.COMMUNITY_ALIASES_DROPPED_IN in messages[0]


def test_the_old_tier_value_warns_once_per_process(warnings_logged):
    opsf.Tier("community_optin")
    opsf.Tier("community_optin")
    assert len(_messages(warnings_logged)) == 1


def test_the_new_tier_value_does_not_warn(warnings_logged):
    assert opsf.Tier("alpha_optin") is opsf.Tier.ALPHA_OPTIN
    assert opsf.Tier("builtin_default") is opsf.Tier.BUILTIN_DEFAULT
    assert _messages(warnings_logged) == []


def test_an_unrelated_tier_value_is_still_refused(warnings_logged):
    with pytest.raises(ValueError):
        opsf.Tier("community")
    assert _messages(warnings_logged) == []


def test_the_register_model_accepts_the_old_tier_value(warnings_logged):
    facet = opsf.ProvenanceFacet(
        tier="community_optin",
        source=opsf.ProvenanceSource.USER_INSTALLED,
        selection_surfaces=(),
        upstream_license=opsf.LICENSE_NOT_READ,
    )
    assert facet.tier is opsf.Tier.ALPHA_OPTIN
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
    assert alpha_scanners.COMMUNITY_ALIASES_DROPPED_IN == "3.9.0"


def test_the_old_scanner_index_import_keeps_working_and_warns_once(
    warnings_logged, monkeypatch
):
    """The M1 module-move shim: ``core.alpha_scanners`` still answers, from the
    registry-backed index, and says once where the index moved to."""
    from automated_security_helper.plugins import enablement

    monkeypatch.setattr(enablement, "_WARNED_RENAMED_SPELLINGS", set())
    assert alpha_scanners.alpha_module_for("snyk-code") == (
        enablement.shipped_module_for("snyk-code")
    )
    assert alpha_scanners.alpha_scanner_modules() == (
        enablement.shipped_scanner_modules()
    )
    alpha_scanners.alpha_module_for("snyk-code")
    messages = _messages(warnings_logged)
    assert len(messages) == 2, messages  # one per moved name, once per process
    assert any(
        "'core.alpha_scanners.alpha_module_for' is deprecated" in m for m in messages
    )
    assert all(alpha_scanners.COMMUNITY_ALIASES_DROPPED_IN in m for m in messages)


def test_a_deprecated_tier_declaration_still_validates_and_is_ignored():
    """A third-party declaration written against an earlier release may still
    pass ``tier=``; the register ignores it (membership is the fact), and an
    in-tree declaration is refused by the facets consistency test instead."""
    facet = opsf.ProvenanceFacet(
        source=opsf.ProvenanceSource.USER_INSTALLED,
        selection_surfaces=(),
        upstream_license=opsf.LICENSE_NOT_READ,
    )
    assert facet.tier is None


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
