# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Four judgments of ``config/path_trust.py``.

* A path refusal is logged once per scan run, not once per process: a
  long-lived process (the MCP server) that refuses the same option and path in
  a later run logs the refusal again.
* ``scanned_checkout_reason`` counts a checkout the way ``sandbox_grants`` does
  (``_git_shaped``): a bare empty ``.git`` directory is no checkout, a ``.git``
  directory holding ``HEAD`` is one.
* A baseline reached through a link that sits inside the checkout holding the
  scan root is the repository's, as the other reason tiers read a link in the
  tree.
* A value holding a NUL names no file: ``honored_path`` drops it instead of
  raising out of the scanner's construction.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.config.path_trust import (
    OperatorPaths,
    honored_path,
    reset_path_refusal_warnings,
    scanned_checkout_reason,
)
from automated_security_helper.utils.log import ASH_LOGGER, run_log_scope
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit


@pytest.fixture(autouse=True)
def _fresh_warnings(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("ASH_MCP_WORKSPACE_ROOT", raising=False)
    reset_path_refusal_warnings()
    yield
    reset_path_refusal_warnings()


@pytest.fixture(autouse=True)
def _tmp_path_is_outside_every_checkout(tmp_path):
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )


@pytest.fixture
def ash_warnings():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target, target_is_directory=target.is_dir())
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks are not available here: {error}")


def test_a_refusal_is_logged_again_in_a_later_run(tmp_path, ash_warnings):
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    inside = repo / "bandit.yaml"
    inside.write_text("skips: []\n", encoding="utf-8")
    key = "scanners.bandit.options.config_file"

    with run_log_scope():
        assert honored_path(str(inside), source_dir=repo, key=key) is None
        assert honored_path(str(inside), source_dir=repo, key=key) is None
    with run_log_scope():
        assert honored_path(str(inside), source_dir=repo, key=key) is None

    logged = [r for r in ash_warnings if key in r.getMessage()]
    assert len(logged) == 2, [r.getMessage() for r in ash_warnings]


def test_an_empty_git_directory_does_not_make_the_scanned_tree_a_checkout(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    app = repo / "app"
    app.mkdir()
    baseline = repo / "ops" / ".secrets.baseline"
    baseline.parent.mkdir()
    baseline.write_text("{}\n", encoding="utf-8")

    assert scanned_checkout_reason(baseline, app) is None


def test_a_git_shaped_marker_makes_the_scanned_tree_a_checkout(tmp_path):
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    app = repo / "app"
    app.mkdir()
    baseline = repo / "ops" / ".secrets.baseline"
    baseline.parent.mkdir()
    baseline.write_text("{}\n", encoding="utf-8")

    reason = scanned_checkout_reason(baseline, app)

    assert reason is not None and "git checkout at" in reason


def test_a_baseline_reached_through_a_link_inside_the_checkout_is_the_repositorys(
    tmp_path,
):
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    app = repo / "app"
    app.mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / ".secrets.baseline").write_text("{}\n", encoding="utf-8")
    # A link the repository placed, and a name outside every tree that reaches
    # the baseline only through that link.
    _symlink(repo / "inner", elsewhere)
    other = tmp_path / "other"
    other.mkdir()
    _symlink(other / "x", repo / "inner")
    named = other / "x" / ".secrets.baseline"

    reason = scanned_checkout_reason(named, app)

    assert reason is not None and "a link inside" in reason, reason


def test_an_operator_document_under_a_respelled_scanner_section_is_credited():
    """The operator's file spells the section ``Syft``; the configuration reads
    it as the syft scanner's (case and separators dropped), so the path it names
    is the operator's under the key the scanner asks about."""
    paths = OperatorPaths(
        documents=[
            {"scanners": {"Syft": {"options": {"config_file": "/ops/syft.yaml"}}}}
        ]
    )

    assert paths.named("scanners.syft.options.config_file", "/ops/syft.yaml")
    assert not paths.named("scanners.syft.options.config_file", "/ops/other.yaml")


def test_an_override_under_a_respelled_scanner_section_is_credited():
    paths = OperatorPaths(
        overrides=[("scanners.DetectSecrets.options.baseline_file", "/ops/base.json")]
    )

    assert paths.named(
        "scanners.detect_secrets.options.baseline_file", "/ops/base.json"
    )
    assert not paths.named("scanners.bandit.options.config_file", "/ops/base.json")


def test_a_value_holding_a_nul_is_dropped_not_raised(tmp_path, ash_warnings):
    key = "scanners.detect-secrets.options.baseline_file"

    assert honored_path("base\x00line.json", source_dir=tmp_path, key=key) is None

    logged = [r.getMessage() for r in ash_warnings if key in r.getMessage()]
    assert logged and "base\x00line" not in logged[0], logged
