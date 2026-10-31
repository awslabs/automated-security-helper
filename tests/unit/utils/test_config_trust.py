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

import sys
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
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

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
    mark_git_checkout(root)
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


def test_a_config_file_in_another_git_checkout_is_not_the_operators(repo, tmp_path):
    """Repository-written, as for the sandbox grants: inside any git checkout.

    A trusted config kept in an ops or dotfiles checkout outside the scanned tree
    counts too; the operator passes such a value with --config-overrides.
    """
    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    operator = ops / "ash.yaml"
    operator.write_text(_config_text())

    config = resolve_config(config_path=operator, source_dir=repo)
    overridden = resolve_config(
        config_path=operator, source_dir=repo, config_overrides=[f"{KEY}=sh"]
    )

    assert config.scanners.actionlint.options.shellcheck == "sh"
    assert set_by_operator(config, KEY, "sh") is False
    assert set_by_operator(overridden, KEY, "sh") is True


def test_an_operator_file_that_extends_a_repository_written_base_vouches_for_nothing(
    repo, tmp_path
):
    """Judged as a whole: even the value the operator's own file writes."""
    base = repo / ".ash" / "base.yaml"
    base.parent.mkdir()
    base.write_text(yaml.safe_dump({"project_name": "base"}))
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        yaml.safe_dump(
            {
                "extends": base.as_posix(),
                "project_name": "operator",
                "scanners": {"actionlint": {"options": {"shellcheck": "sh"}}},
            }
        )
    )

    config = resolve_config(
        config_path=operator, source_dir=repo, permit_base=lambda path: True
    )

    assert config.scanners.actionlint.options.shellcheck == "sh"
    assert set_by_operator(config, KEY, "sh") is False


def test_a_config_inside_a_scanned_directory_outside_every_checkout_is_not_the_operators(
    tmp_path,
):
    """With no checkout around the scan, the scanned directory is the tree."""
    scanned = tmp_path / "scanned"
    (scanned / ".ash").mkdir(parents=True)
    (scanned / ".ash" / ".ash.yaml").write_text(_config_text())
    outside = tmp_path / "operator.yaml"
    outside.write_text(_config_text())

    assert set_by_operator(resolve_config(source_dir=scanned), KEY, "sh") is False
    assert (
        set_by_operator(
            resolve_config(config_path=outside, source_dir=scanned), KEY, "sh"
        )
        is True
    )


def test_a_config_above_the_scan_root_but_inside_the_checkout_is_the_trees(repo):
    """Scanning a subdirectory: the repository still wrote its root config."""
    scan_root = repo / "services" / "api"
    scan_root.mkdir(parents=True)
    repo_config = repo / "ash.yaml"
    repo_config.write_text(_config_text())

    config = resolve_config(config_path=repo_config, source_dir=scan_root)

    assert set_by_operator(config, KEY, "sh") is False


def test_an_extends_base_inside_the_tree_makes_the_config_the_trees(repo, tmp_path):
    """An operator file that pulls its value from an in-tree base is not vouched for.

    With ``permit_base`` allowing it, resolve_config applies the in-tree base, so the
    value is there and must still count as the tree's. This used to catch any
    exception and skip, which turned a resolve_config regression into a skip.
    """
    base = repo / ".ash" / "base.yaml"
    base.parent.mkdir()
    base.write_text(_config_text())
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        yaml.safe_dump({"extends": base.as_posix(), "project_name": "operator"})
    )

    config = resolve_config(
        config_path=operator, source_dir=repo, permit_base=lambda path: True
    )

    assert config.project_name == "operator"
    assert config.scanners.actionlint.options.shellcheck == "sh", (
        "the in-tree base was not applied, so nothing below tests its provenance"
    )
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


def _context_after_initialize(
    source: Path, config_path=None, overrides=None, client_overrides=False
):
    engine = MagicMock()
    orchestrator = ASHScanOrchestrator(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        config_path=config_path,
        config_overrides=overrides,
        client_overrides=client_overrides,
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
# Overrides an MCP client supplied (resolve_config(client_overrides=True))
# --------------------------------------------------------------------------- #

#: An option only the operator may set: cfn-lint imports the Python rules a
#: ``.cfnlintrc`` names.
CFN_LINT_CONFIG = "scanners.cfn-lint.options.config_file"


def _where(where: str, repo: Path, tmp_path: Path, monkeypatch) -> dict:
    """resolve_config's arguments for a config in the tree, outside it, or none."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    if where == "in-tree":
        (repo / ".ash").mkdir()
        (repo / ".ash" / ".ash.yaml").write_text(_config_text())
        return {"source_dir": repo}
    if where == "operator-file":
        operator = tmp_path / "operator.yaml"
        operator.write_text(_config_text())
        return {"config_path": operator, "source_dir": repo}
    return {"source_dir": repo}


@pytest.mark.parametrize("where", ["in-tree", "operator-file", "no-file"])
def test_a_client_override_is_not_the_operators(repo, tmp_path, monkeypatch, where):
    """The MCP server passes a client's overrides with ``client_overrides=True``.

    They are applied to the config, but a value only they set is the client's: the
    same override from the operator (``--config-overrides``) is the operator's.
    """
    args = _where(where, repo, tmp_path, monkeypatch)
    override = f"{CFN_LINT_CONFIG}=/x/rc"

    client = resolve_config(**args, config_overrides=[override], client_overrides=True)
    operator = resolve_config(**args, config_overrides=[override])

    assert str(client.scanners.cfn_lint.options.config_file) == "/x/rc", (
        "the client's override was not applied, so nothing below tests its provenance"
    )
    assert set_by_operator(client, CFN_LINT_CONFIG, "/x/rc") is False
    assert set_by_operator(client, CFN_LINT_CONFIG, Path("/x/rc")) is False
    assert set_by_operator(operator, CFN_LINT_CONFIG, "/x/rc") is True


def test_a_client_override_leaves_the_operators_own_values_the_operators(
    repo, tmp_path, monkeypatch
):
    """The operator's file, named as the trusted base, vouches for what it sets
    beside a client's override.

    ``trusted_config_path`` is the operator's own file; ``config_path`` is the
    config the scan selected, which a client's upload or a project's own file
    can replace. With a client's overrides present, a load with ``config_path``
    alone resolves on the defaults (or ASH_CONFIG's file) as the trusted base, as
    the MCP flow's callers pass both (``cli/mcp/workspace.py``'s session binding).
    """
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    operator = tmp_path / "operator.yaml"
    operator.write_text(
        yaml.safe_dump(
            {
                "project_name": "operator",
                "scanners": {"cfn-lint": {"options": {"config_file": "/x/rc"}}},
            }
        )
    )

    config = resolve_config(
        config_path=operator,
        trusted_config_path=operator,
        source_dir=repo,
        config_overrides=[f"{KEY}=sh"],
        client_overrides=True,
    )

    assert set_by_operator(config, CFN_LINT_CONFIG, "/x/rc") is True
    assert set_by_operator(config, KEY, "sh") is False


def test_a_client_override_that_changes_the_operators_value_is_not_the_operators(
    repo, tmp_path, monkeypatch
):
    """A client's override of a value the operator's trusted base sets is the
    client's; the operator's own value stays the operator's."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    operator = tmp_path / "operator.yaml"
    operator.write_text(_config_text())

    config = resolve_config(
        config_path=operator,
        trusted_config_path=operator,
        source_dir=repo,
        config_overrides=[f"{KEY}=client-sh"],
        client_overrides=True,
    )

    assert config.scanners.actionlint.options.shellcheck == "client-sh"
    assert set_by_operator(config, KEY, "client-sh") is False
    assert set_by_operator(config, KEY, "sh") is True


def test_the_scanners_context_carries_a_clients_overrides_as_the_clients(
    repo, monkeypatch
):
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    context = _context_after_initialize(
        repo, overrides=[f"{CFN_LINT_CONFIG}=/x/rc"], client_overrides=True
    )

    assert set_by_operator(context.config, CFN_LINT_CONFIG, "/x/rc") is False


# --------------------------------------------------------------------------- #
# operator_path: the one rule for an option that names a tool's config file
# --------------------------------------------------------------------------- #


def _operator_path_case(tmp_path, *, operator: bool):
    from automated_security_helper.utils.config_trust import record_provenance

    repo = tmp_path / "repo"
    mark_git_checkout(repo)
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


def test_operator_paths_decides_provenance_for_the_list_and_checks_each_entry(
    tmp_path,
):
    from automated_security_helper.utils.config_trust import (
        INSIDE_THE_TREE,
        NOT_THE_OPERATORS,
        operator_paths,
    )

    key = "scanners.x.options.rules_paths"
    outside = tmp_path / "rules"
    outside.mkdir()
    values = [str(outside), "policy"]

    repo, config = _operator_path_case(tmp_path, operator=False)
    refused = operator_paths(config, key, values, repo)
    assert [(c.path, c.refusal) for c in refused] == [(None, NOT_THE_OPERATORS)] * 2

    repo, config = _operator_path_case(tmp_path / "op", operator=True)
    (repo / "policy").mkdir()
    strict = operator_paths(config, key, values, repo)
    assert [(c.path, c.refusal) for c in strict] == [
        (outside.resolve(), None),
        (None, INSIDE_THE_TREE),
    ]
    relaxed = operator_paths(config, key, values, repo, outside_tree=False)
    assert [c.path for c in relaxed] == [outside.resolve(), (repo / "policy").resolve()]


# --------------------------------------------------------------------------- #
# leaves_the_tree_through_a_link: a path in the tree whose links lead out of it
# --------------------------------------------------------------------------- #


def _tree_and_outside(tmp_path):
    """A checkout, and a file outside it."""
    repo = tmp_path / "repo"
    mark_git_checkout(repo)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "creds").write_text("x\n", encoding="utf-8")
    return repo, outside


def _link(link: Path, target) -> None:
    try:
        link.symlink_to(target, target_is_directory=Path(target).is_dir())
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


@pytest.mark.parametrize(
    "shape", ["file", "chain", "dangling", "directory", "nested directory"]
)
def test_a_link_in_the_tree_that_leads_out_of_it_is_found(tmp_path, shape):
    from automated_security_helper.utils.config_trust import (
        leaves_the_tree_through_a_link,
    )

    repo, outside = _tree_and_outside(tmp_path)
    if shape == "file":
        _link(repo / "named.yml", outside / "creds")
        value = "named.yml"
    elif shape == "chain":
        # Both links are in the tree; only the last one leaves it.
        _link(repo / "second.yml", outside / "creds")
        _link(repo / "named.yml", repo / "second.yml")
        value = "named.yml"
    elif shape == "dangling":
        _link(repo / "named.yml", outside / "missing")
        value = "named.yml"
    elif shape == "directory":
        _link(repo / "linked", outside)
        value = "linked/creds"
    else:
        (repo / "deep").mkdir()
        _link(repo / "deep" / "up", outside)
        value = "deep/up/creds"
    assert leaves_the_tree_through_a_link(value, repo, repo) is True
    assert leaves_the_tree_through_a_link(str(repo / value), repo, repo) is True


@pytest.mark.parametrize(
    "shape", ["plain file", "link inside", "dangling inside", "out and back"]
)
def test_a_path_that_ends_inside_the_tree_does_not_leave_it(tmp_path, shape):
    from automated_security_helper.utils.config_trust import (
        leaves_the_tree_through_a_link,
    )

    repo, outside = _tree_and_outside(tmp_path)
    (repo / "real").mkdir()
    (repo / "real" / "file.yml").write_text("", encoding="utf-8")
    value = "named.yml"
    if shape == "plain file":
        value = "real/file.yml"
    elif shape == "link inside":
        _link(repo / "named.yml", Path("real") / "file.yml")
    elif shape == "dangling inside":
        _link(repo / "named.yml", repo / "missing.yml")
    else:
        # Through a directory outside the tree and back into it: the file the
        # tool would open is in the tree.
        _link(repo / "away", outside)
        value = "away/../repo/real/file.yml"
    assert leaves_the_tree_through_a_link(value, repo, repo) is False


def test_a_path_that_leaves_by_dot_dot_with_no_link_is_the_operators(tmp_path):
    """``../shared.toml`` names a file next to the tree; the tree chose nothing."""
    from automated_security_helper.utils.config_trust import (
        leaves_the_tree_through_a_link,
    )

    repo, outside = _tree_and_outside(tmp_path)
    (repo / "sub").mkdir()
    for value in (
        "../outside/creds",
        "sub/../../outside/creds",
        str(outside / "creds"),
    ):
        assert leaves_the_tree_through_a_link(value, repo, repo) is False, value


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="Windows resolves '..' in a path's text before it follows any link, so "
    "'sub/..' is never a step out of the directory 'sub' links to",
)
def test_a_dot_dot_that_a_link_in_the_tree_moved_out_of_it_is_found(tmp_path):
    """As written, ``a/b/sub/../creds`` is ``a/b/creds``, in the tree. With ``sub``
    a link to the tree's root, the ``..`` lands next to the tree instead."""
    from automated_security_helper.utils.config_trust import (
        leaves_the_tree_through_a_link,
    )

    repo, _ = _tree_and_outside(tmp_path)
    (tmp_path / "creds").write_text("x\n", encoding="utf-8")
    nested = repo / "a" / "b"
    nested.mkdir(parents=True)
    _link(nested / "sub", repo)
    assert leaves_the_tree_through_a_link("a/b/sub/../creds", repo, repo) is True


def test_a_link_outside_the_tree_is_the_operators(tmp_path):
    """Outside the tree the operator controls the path and the links on it."""
    from automated_security_helper.utils.config_trust import (
        leaves_the_tree_through_a_link,
    )

    repo, outside = _tree_and_outside(tmp_path)
    _link(tmp_path / "shared.yml", outside / "creds")
    assert leaves_the_tree_through_a_link("../shared.yml", repo, repo) is False


def test_operator_path_refuses_a_path_in_the_tree_that_links_out_of_it(tmp_path):
    """With the tree allowed, the operator may name a file in it, but a link there
    to a file outside it is the tree's choice of file."""
    from automated_security_helper.utils.config_trust import operator_path

    repo, config = _operator_path_case(tmp_path, operator=True)
    outside = tmp_path / "outside.yaml"
    outside.write_text("", encoding="utf-8")
    _link(repo / "tool.yaml", outside)
    chosen = operator_path(
        config, "scanners.x.options.config_file", "tool.yaml", repo, outside_tree=False
    )
    assert chosen.path is None
    from automated_security_helper.utils.config_trust import LEADS_OUT_OF_THE_TREE

    assert chosen.refusal == LEADS_OUT_OF_THE_TREE
    # A link the operator keeps next to the tree is theirs.
    _link(tmp_path / "shared.yaml", outside)
    kept = operator_path(
        config,
        "scanners.x.options.config_file",
        "../shared.yaml",
        repo,
        outside_tree=False,
    )
    assert kept.path == outside.resolve()


def test_operator_path_kept_outside_the_tree_refuses_a_link_out_of_it(tmp_path):
    """A path written in the tree that resolves outside it passes the "inside the
    tree" test on where it lands, but the tree's link chose where that is."""
    from automated_security_helper.utils.config_trust import operator_path

    repo, config = _operator_path_case(tmp_path, operator=True)
    outside = tmp_path / "outside" / "tool"
    outside.parent.mkdir()
    outside.write_text("", encoding="utf-8")
    (repo / "bin").mkdir()
    _link(repo / "bin" / "tool", outside)
    _link(repo / "linked", outside.parent)
    for value in ("bin/tool", "linked/tool", str(repo / "bin" / "tool")):
        chosen = operator_path(config, "scanners.x.options.y", value, repo)
        assert chosen.path is None, value
        from automated_security_helper.utils.config_trust import (
            LEADS_OUT_OF_THE_TREE,
        )

        assert chosen.refusal == LEADS_OUT_OF_THE_TREE
    # The same file, named directly or through the operator's own link, is used.
    _link(tmp_path / "mine", outside)
    for value in (str(outside), "../mine"):
        assert operator_path(config, "scanners.x.options.y", value, repo).path == (
            outside.resolve()
        )
