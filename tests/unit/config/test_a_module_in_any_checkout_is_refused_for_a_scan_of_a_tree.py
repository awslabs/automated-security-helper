# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A plugin module installed inside any git checkout is the scanned party's too.

``plugin_module_trust.refusal_reason`` decides whether a repository's config may
import a module. A config file in any checkout, and a tool config path in any
checkout, are judged by ``sandbox_grants.untrusted_reason`` (inside any checkout
or the scan root, by any name); a module installed in one is judged the same way
for a scan of a tree. A load that judges against a given root (``root_judged``)
keeps the plain tree judgment, and a load with no scanned tree keeps its
any-checkout arm.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Iterator

import pytest

from automated_security_helper.config import resolve_config as rc
from automated_security_helper.config.plugin_module_trust import refusal_reason
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit


def _package(root: Path, name: str) -> Path:
    package = root / name
    package.mkdir(parents=True)
    (package / "__init__.py").write_text("", encoding="utf-8")
    return package


@pytest.fixture(autouse=True)
def _tmp_path_is_outside_every_checkout(tmp_path: Path) -> None:
    # A basetemp inside a repository would make every refusal here pass for the
    # wrong reason, and every keep fail.
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )


@pytest.fixture
def scanned(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    return target


@pytest.fixture
def clean_modules() -> Iterator[None]:
    before = set(sys.modules)
    yield
    for name in set(sys.modules) - before:
        if name.startswith("acme_scan_of_a_tree"):
            sys.modules.pop(name, None)


def test_a_module_in_another_checkout_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanned: Path, clean_modules: None
) -> None:
    other = tmp_path / "plugins-repo"
    mark_git_checkout(other)
    package = _package(other, "acme_scan_of_a_tree_other")
    monkeypatch.syspath_prepend(str(other))

    reason = refusal_reason("acme_scan_of_a_tree_other", scanned)

    assert reason == (
        f"it is at {package.as_posix()}, and it is inside the git checkout at "
        f"{other.absolute().as_posix()}"
    )


def test_positive_control_a_module_outside_every_checkout_is_kept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanned: Path, clean_modules: None
) -> None:
    site = tmp_path / "site"
    _package(site, "acme_scan_of_a_tree_site")
    monkeypatch.syspath_prepend(str(site))

    assert refusal_reason("acme_scan_of_a_tree_site", scanned) is None


def test_control_a_module_inside_the_scanned_tree_is_refused_as_before(
    monkeypatch: pytest.MonkeyPatch, scanned: Path, clean_modules: None
) -> None:
    _package(scanned, "acme_scan_of_a_tree_inside")
    monkeypatch.syspath_prepend(str(scanned))

    assert refusal_reason("acme_scan_of_a_tree_inside", scanned) == (
        "it resolves inside the scanned tree"
    )


def test_a_load_judged_against_a_given_root_keeps_the_plain_tree_judgment(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, scanned: Path, clean_modules: None
) -> None:
    other = tmp_path / "plugins-repo"
    mark_git_checkout(other)
    _package(other, "acme_scan_of_a_tree_given")
    monkeypatch.syspath_prepend(str(other))

    assert (
        refusal_reason("acme_scan_of_a_tree_given", scanned, root_judged=True) is None
    )


def test_a_load_with_no_root_and_no_arm_judges_by_the_client_arm_alone(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, clean_modules: None
) -> None:
    other = tmp_path / "plugins-repo"
    mark_git_checkout(other)
    _package(other, "acme_scan_of_a_tree_rootless")
    monkeypatch.syspath_prepend(str(other))

    assert refusal_reason("acme_scan_of_a_tree_rootless", None) is None
    assert refusal_reason("acme_scan_of_a_tree_rootless", None, any_checkout=True)


def test_a_repository_config_cannot_import_a_module_installed_in_another_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    clean_modules: None,
) -> None:
    """Through the whole resolution: the module is dropped, the kept one stays."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    other = tmp_path / "plugins-repo"
    mark_git_checkout(other)
    _package(other, "acme_scan_of_a_tree_in_a_checkout_ash_plugins")
    site = tmp_path / "site"
    _package(site, "acme_scan_of_a_tree_in_a_site_ash_plugins")
    monkeypatch.syspath_prepend(str(other))
    monkeypatch.syspath_prepend(str(site))
    config_file = repo / ".ash" / ".ash.yaml"
    config_file.parent.mkdir(parents=True)
    config_file.write_text(
        "project_name: x\nash_plugin_modules:\n"
        "  - acme_scan_of_a_tree_in_a_checkout_ash_plugins\n"
        "  - acme_scan_of_a_tree_in_a_site_ash_plugins\n",
        encoding="utf-8",
    )

    with caplog.at_level(logging.WARNING):
        config = rc.resolve_config(source_dir=repo)

    assert "acme_scan_of_a_tree_in_a_checkout_ash_plugins" not in (
        config.ash_plugin_modules or []
    )
    assert "acme_scan_of_a_tree_in_a_site_ash_plugins" in (
        config.ash_plugin_modules or []
    )
    assert "Ignoring ash_plugin_modules entries" in caplog.text
    assert "the git checkout at" in caplog.text
