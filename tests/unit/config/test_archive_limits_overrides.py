# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""How ``config/archive_limits.py`` finds the trusted value of each extraction limit.

``test_archive_limits_are_operator_settings.py`` covers who may raise the limits.
This covers the pieces it rests on: which ``--config-overrides`` entries are
replayed onto the trusted base, that an override can raise a limit above the
defaults for a repository with its own config, that an ``ASH_CONFIG`` file inside
the scanned tree is no trusted base, and that lowering a limit in the tree is
kept without a warning.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.config.archive_limits import _sets_a_limit
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.log import ASH_LOGGER

pytestmark = pytest.mark.unit


@pytest.fixture
def ash_warnings():
    records: List[logging.LogRecord] = []

    class _Collect(logging.Handler):
        def emit(self, record):
            records.append(record)

    handler = _Collect(level=logging.WARNING)
    ASH_LOGGER.addHandler(handler)
    try:
        yield records
    finally:
        ASH_LOGGER.removeHandler(handler)


@pytest.fixture
def tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    root = tmp_path / "repo"
    (root / ".ash").mkdir(parents=True)
    monkeypatch.chdir(root)
    return root


def write_options(path: Path, **options) -> None:
    lines = "".join(f"      {name}: {value}\n" for name, value in options.items())
    path.write_text(
        f"project_name: scanned\nconverters:\n  archive:\n    options:\n{lines}"
    )


@pytest.mark.parametrize(
    "override, sets",
    [
        ("converters.archive.options.max_members=5", True),
        ("converters.archive.options.max-total-bytes=5", True),
        ("converters.archive.options={}", True),
        ("converters.archive={}", True),
        ("converters={}", True),
        # Spellings the apply folds onto the declared archive section: an
        # override written this way raises the limit in the resolved config, so
        # it is replayed onto the trusted base too, or the raise is capped back
        # and the warning blames the in-tree file.
        ("converters.Archive.options.max_members=5", True),
        ("converters.ARCHIVE.options.max-member-bytes=5", True),
        ("converters.arc_hive.options.max_total_bytes=5", True),
        ("converters.Arc-Hive={}", True),
        ("converters.archive.options.something_else=5", False),
        ("converters.archive.enabled=false", False),
        ("converters.jupyter.options.install_timeout=5", False),
        ("sandbox.mode=auto", False),
    ],
)
def test_which_overrides_are_replayed_onto_the_trusted_base(override, sets):
    assert _sets_a_limit(override) is sets


def test_an_override_raises_a_limit_for_a_repository_with_its_own_config(tree):
    write_options(tree / ".ash" / ".ash.yaml", max_member_bytes=1000)

    config = resolve_config(
        source_dir=tree,
        config_overrides=["converters.archive.options.max_member_bytes=4294967296"],
    )

    assert config.converters.archive.options.max_member_bytes == 4294967296


def test_an_ash_config_inside_the_tree_is_not_a_trusted_base(
    tree, monkeypatch, ash_warnings
):
    inside = tree / "operator.yaml"
    write_options(inside, max_total_bytes=4 * 1024**4)
    monkeypatch.setenv("ASH_CONFIG", str(inside))

    config = resolve_config(source_dir=tree)

    assert config.converters.archive.options.max_total_bytes == 1024**3
    assert any(
        "converters.archive.options.max_total_bytes" in r.getMessage()
        for r in ash_warnings
    )


def test_a_repository_config_may_lower_a_limit_without_a_warning(tree, ash_warnings):
    write_options(tree / ".ash" / ".ash.yaml", max_members=10, max_total_bytes=4096)

    config = resolve_config(source_dir=tree)

    options = config.converters.archive.options
    assert (options.max_members, options.max_total_bytes) == (10, 4096)
    assert not [
        r for r in ash_warnings if "converters.archive.options" in r.getMessage()
    ]
