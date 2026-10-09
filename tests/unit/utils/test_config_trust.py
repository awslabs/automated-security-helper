# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which config values the operator set, as the new scanners see it.

``utils/config_trust.py`` tells a value the operator chose (a config file outside the
scanned tree, or --config-overrides) from one the scanned repository chose. The
provenance is recorded by ``resolve_config``, with the tree and the trusted base that
``config/sandbox_grants.py`` uses, so these tests resolve real config files. The
orchestrator test goes through ``initialize()`` and reads the provenance off the
PluginContext the scan engine receives, which is what the scanners consult.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import yaml

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.orchestrator import ASHScanOrchestrator
from automated_security_helper.utils.config_trust import (
    scan_root,
    set_by_operator,
)

KEY = "scanners.actionlint.options.shellcheck"


def _config_text(shellcheck: str = "sh", **extra) -> str:
    return yaml.safe_dump(
        {
            "project_name": "scanned",
            "scanners": {"actionlint": {"options": {"shellcheck": shellcheck}}},
            **extra,
        }
    )


@pytest.fixture
def repo(tmp_path) -> Path:
    """A checkout: the scanned tree is the directory holding ``.git``."""
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    return root


def test_a_config_without_provenance_is_not_the_operators():
    assert set_by_operator(AshConfig(), KEY, "sh") is False
    assert set_by_operator(None, KEY, "sh") is False


def test_a_discovered_config_is_the_scanned_trees(repo):
    (repo / ".ash").mkdir()
    (repo / ".ash" / ".ash.yaml").write_text(_config_text())

    config = resolve_config(source_dir=repo)

    assert set_by_operator(config, KEY, "sh") is False


def test_a_config_file_outside_the_tree_is_the_operators(repo, tmp_path):
    operator = tmp_path / "operator.yaml"
    operator.write_text(_config_text())

    config = resolve_config(config_path=operator, source_dir=repo)

    assert set_by_operator(config, KEY, "sh") is True


def test_a_config_above_the_scan_root_but_inside_the_checkout_is_the_trees(repo):
    """Scanning a subdirectory: the repository still wrote its root config."""
    scan_root = repo / "services" / "api"
    scan_root.mkdir(parents=True)
    repo_config = repo / "ash.yaml"
    repo_config.write_text(_config_text())

    config = resolve_config(config_path=repo_config, source_dir=scan_root)

    assert set_by_operator(config, KEY, "sh") is False


def test_an_extends_base_inside_the_tree_makes_the_config_the_trees(repo, tmp_path):
    """An operator file that pulls its value from an in-tree base is not vouched for."""
    base = repo / ".ash" / "base.yaml"
    base.parent.mkdir()
    base.write_text(_config_text())
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        yaml.safe_dump({"extends": base.as_posix(), "project_name": "operator"})
    )

    try:
        config = resolve_config(
            config_path=operator, source_dir=repo, permit_base=lambda path: True
        )
    except Exception as exc:  # the base may be refused outright, which is safe too
        pytest.skip(f"extends across the tree boundary is refused: {exc}")

    assert set_by_operator(config, KEY, "sh") is False


@pytest.mark.skipif(not hasattr(Path, "symlink_to"), reason="no symlinks")
def test_a_symlink_into_the_tree_is_the_trees(repo, tmp_path):
    real = repo / ".ash" / ".ash.yaml"
    real.parent.mkdir()
    real.write_text(_config_text())
    link = tmp_path / "looks-outside.yaml"
    try:
        link.symlink_to(real)
    except OSError:
        pytest.skip("symlinks need privileges here")

    config = resolve_config(config_path=link, source_dir=repo)

    assert set_by_operator(config, KEY, "sh") is False


@pytest.mark.parametrize(
    "override",
    [
        f"{KEY}=sh",
        'scanners.actionlint.options={"shellcheck": "sh"}',
        'scanners.actionlint={"options": {"shellcheck": "sh"}}',
    ],
)
def test_an_override_that_resolves_to_the_value_vouches_for_it(repo, override):
    (repo / ".ash").mkdir()
    (repo / ".ash" / ".ash.yaml").write_text(_config_text())

    config = resolve_config(source_dir=repo, config_overrides=[override])

    assert set_by_operator(config, KEY, "sh") is True


@pytest.mark.parametrize(
    "override",
    [
        "scanners.actionlint.options.pyflakes=pyflakes",
        f"{KEY}=shellcheck",
        "scanners.actionlintx.options.shellcheck=sh",
    ],
)
def test_an_override_that_resolves_elsewhere_does_not(repo, override):
    (repo / ".ash").mkdir()
    (repo / ".ash" / ".ash.yaml").write_text(_config_text())

    config = resolve_config(source_dir=repo, config_overrides=[override])

    # With KEY=shellcheck the resolved config holds "shellcheck"; a scanner that
    # was given "sh" anyway is not vouched for by it.
    assert set_by_operator(config, KEY, "sh") is False


@pytest.mark.parametrize("spelling", ["cfn-lint", "cfn_lint"])
def test_scanner_names_match_with_either_separator(repo, spelling):
    (repo / ".ash").mkdir()
    (repo / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump(
            {
                "project_name": "scanned",
                "scanners": {"cfn-lint": {"options": {"config_file": "/x/rc"}}},
            }
        )
    )

    config = resolve_config(
        source_dir=repo,
        config_overrides=[f"scanners.{spelling}.options.config_file=/x/rc"],
    )

    for key in (
        "scanners.cfn-lint.options.config_file",
        "scanners.cfn_lint.options.config_file",
    ):
        assert set_by_operator(config, key, "/x/rc") is True
        assert set_by_operator(config, key, Path("/x/rc")) is True


def test_scan_root_is_the_recorded_workspace_root_else_the_source_dir(repo, tmp_path):
    """The root path_trust.in_scanned_tree is given, as honored_path chooses it."""
    config = AshConfig()
    assert scan_root(config, repo) == repo
    workspace = tmp_path / "workspace"
    config._scanned_root = workspace
    assert scan_root(config, repo) == workspace
    assert scan_root(None, repo) == repo


def _context_after_initialize(source: Path, config_path=None, overrides=None):
    engine = MagicMock()
    orchestrator = ASHScanOrchestrator(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        config_path=config_path,
        config_overrides=overrides,
        no_cleanup=True,
        metadata=None,
        ash_plugin_modules=[],
    )
    with patch(
        "automated_security_helper.core.orchestrator.ScanExecutionEngine",
        return_value=engine,
    ) as engine_class:
        orchestrator.initialize()
    return engine_class.call_args.kwargs["context"]


def test_the_scanners_context_carries_the_trees_provenance(repo):
    (repo / ".ash").mkdir()
    (repo / ".ash" / ".ash.yaml").write_text(_config_text())

    context = _context_after_initialize(repo)

    assert set_by_operator(context.config, KEY, "sh") is False


def test_the_scanners_context_carries_the_operators_provenance(repo, tmp_path):
    operator = tmp_path / "operator.yaml"
    operator.write_text(_config_text())

    context = _context_after_initialize(repo, config_path=operator)

    assert set_by_operator(context.config, KEY, "sh") is True


def test_the_scanners_context_carries_the_overrides(repo):
    (repo / ".ash").mkdir()
    (repo / ".ash" / ".ash.yaml").write_text(_config_text())

    context = _context_after_initialize(repo, overrides=[f"{KEY}=sh"])

    assert set_by_operator(context.config, KEY, "sh") is True
    assert (
        set_by_operator(context.config, "scanners.actionlint.options.pyflakes", "x")
        is False
    )


# --------------------------------------------------------------------------- #
# operator_path: the one rule for an option that names a tool's config file
# --------------------------------------------------------------------------- #


def _operator_path_case(tmp_path, *, operator: bool):
    from automated_security_helper.utils.config_trust import record_provenance

    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    config = AshConfig()
    record_provenance(
        config,
        in_tree=[] if operator else [repo / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
    )
    return repo, config


def test_operator_path_refuses_a_value_the_operator_did_not_set(tmp_path):
    from automated_security_helper.utils.config_trust import (
        NOT_THE_OPERATORS,
        operator_path,
    )

    repo, config = _operator_path_case(tmp_path, operator=False)
    outside = tmp_path / "elsewhere.yaml"
    outside.write_text("", encoding="utf-8")
    chosen = operator_path(config, "scanners.x.options.config_file", str(outside), repo)
    assert chosen.path is None and chosen.refusal == NOT_THE_OPERATORS


def test_operator_path_refuses_the_tree_unless_told_not_to(tmp_path):
    from automated_security_helper.utils.config_trust import (
        INSIDE_THE_TREE,
        operator_path,
    )

    repo, config = _operator_path_case(tmp_path, operator=True)
    inside = repo / "tool.yaml"
    inside.write_text("", encoding="utf-8")
    refused = operator_path(config, "scanners.x.options.config_file", "tool.yaml", repo)
    assert refused.path is None and refused.refusal == INSIDE_THE_TREE
    allowed = operator_path(
        config, "scanners.x.options.config_file", "tool.yaml", repo, outside_tree=False
    )
    assert allowed.path == inside.resolve()


def test_operator_path_returns_the_path_it_checked(tmp_path, monkeypatch):
    from automated_security_helper.utils.config_trust import operator_path

    repo, config = _operator_path_case(tmp_path, operator=True)
    home = tmp_path / "home"
    home.mkdir()
    (home / "tool.yaml").write_text("", encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    chosen = operator_path(
        config, "scanners.x.options.config_file", "~/tool.yaml", repo
    )
    assert chosen.path == (home / "tool.yaml").resolve()
