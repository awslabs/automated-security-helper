# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file reached through a link the scanned repository holds is the repository's.

A config file is judged by where it resolves to and by the name that reached it
(config/sandbox_grants.py, ``files_inside``), so a ``.ash/.ash.yaml`` that links
out of the tree is still the tree's. Two more names are judged:

- an ``extends`` base's own name. An operator's config outside the tree that
  extends ``repo/.ash/link.yaml`` reads whichever file that link, which the
  repository wrote, points to; judging only the resolved target would miss that,
  since the target can be any file under the operator's directory;
- the links a name passes through. ``repo/lnk/../x.yaml`` resolves ``repo/lnk``
  first, so the repository's link picks the directory ``..`` steps up from, and
  the name with ``..`` applied sits outside the tree.

Each is judged by the links resolving it follows: a link inside the tree
makes the file the tree's. The file chosen here turns the S3 upload on to a
bucket; the reporter must not get that section.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

pytestmark = pytest.mark.unit

#: Turns the S3 upload on, to a bucket the repository picked the file for.
_UPLOAD = (
    "reporters:\n  s3:\n    enabled: true\n    options:\n      bucket_name: picked\n"
)


@pytest.fixture(autouse=True)
def _no_ash_config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"symlinks unavailable: {error}")


def _s3_section(config_path: Path, repo: Path, trusted: Path | None = None) -> Any:
    """The s3 section the S3 reporter would run with, scanning *repo*, with
    *trusted* as the operator's config the confinement takes its base from."""
    from automated_security_helper.config.operator_only_options import (
        reporter_section,
    )
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.plugin_modules.ash_aws_plugins.s3_reporter import (
        S3Reporter,
    )

    config = resolve_config(
        config_path=config_path, source_dir=repo, trusted_config_path=trusted
    )
    return reporter_section(config, S3Reporter)


def _uploads_to_the_picked_bucket(section: Any) -> bool:
    if not isinstance(section, dict):
        return False
    options = section.get("options") or {}
    return bool(section.get("enabled")) and options.get("bucket_name") == "picked"


def _operator_dir_holding_the_checkout(tmp_path: Path) -> tuple[Path, Path]:
    """``ops/`` with the operator's files, and the checkout ``ops/repo``."""
    ops = tmp_path / "ops"
    repo = ops / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / ".ash").mkdir()
    (ops / "other.yaml").write_text(_UPLOAD, encoding="utf-8")
    return ops, repo


def test_an_extends_base_the_repositorys_link_picks_is_the_repositorys(tmp_path):
    ops, repo = _operator_dir_holding_the_checkout(tmp_path)
    _symlink_or_skip(repo / ".ash" / "link.yaml", ops / "other.yaml")
    top = ops / "ash.yaml"
    top.write_text("extends: repo/.ash/link.yaml\n", encoding="utf-8")

    section = _s3_section(top, repo)

    assert not _uploads_to_the_picked_bucket(section), section


def test_an_operator_base_the_repositorys_link_picks_is_no_trusted_base(tmp_path):
    """The repository's own config is confined, from the operator's config as the
    trusted base; that config's base is the file the repository's link picks, so
    it is the tree's, and the base is the defaults."""
    ops, repo = _operator_dir_holding_the_checkout(tmp_path)
    _symlink_or_skip(repo / ".ash" / "link.yaml", ops / "other.yaml")
    operator = ops / "ash.yaml"
    operator.write_text("extends: repo/.ash/link.yaml\n", encoding="utf-8")
    own = repo / ".ash" / ".ash.yaml"
    own.write_text("project_name: repo\n", encoding="utf-8")

    section = _s3_section(own, repo, trusted=operator)

    assert not _uploads_to_the_picked_bucket(section), section


def test_a_config_named_through_the_repositorys_link_is_the_repositorys(tmp_path):
    """``repo/lnk/../other.yaml``: the kernel follows ``repo/lnk`` before ``..``."""
    ops, repo = _operator_dir_holding_the_checkout(tmp_path)
    (ops / "sub").mkdir()
    _symlink_or_skip(repo / "lnk", ops / "sub")
    named = repo / "lnk" / ".." / "other.yaml"
    assert named.resolve() == (ops / "other.yaml").resolve()

    section = _s3_section(named, repo)

    assert not _uploads_to_the_picked_bucket(section), section


def test_control_the_operators_own_base_chooses_the_upload(tmp_path):
    """The same base, extended by its own name outside the checkout: it is the
    operator's, and its upload goes ahead. Without this, a reporter that never
    got an s3 section would pass the tests above."""
    ops, repo = _operator_dir_holding_the_checkout(tmp_path)
    top = ops / "ash.yaml"
    top.write_text("extends: other.yaml\n", encoding="utf-8")

    section = _s3_section(top, repo)

    assert _uploads_to_the_picked_bucket(section), section


def test_control_the_operators_config_outside_the_checkout_is_the_trusted_base(
    tmp_path,
):
    """The repository's own config, confined from the operator's config outside
    the checkout, whose base it extends by its own name: the trusted base is the
    operator's, and its upload goes ahead. Without this, a trusted base that was
    always the defaults would pass the no-trusted-base test above."""
    ops, repo = _operator_dir_holding_the_checkout(tmp_path)
    operator = ops / "ash.yaml"
    operator.write_text("extends: other.yaml\n", encoding="utf-8")
    own = repo / ".ash" / ".ash.yaml"
    own.write_text("project_name: repo\n", encoding="utf-8")

    section = _s3_section(own, repo, trusted=operator)

    assert _uploads_to_the_picked_bucket(section), section
