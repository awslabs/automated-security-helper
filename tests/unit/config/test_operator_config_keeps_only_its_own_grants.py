# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file keeps the sandbox grants it writes itself only when it is the operator's.

The operator's own config sits outside every git checkout and may extend a base
inside one. ``resolve_config`` then keeps the ``sandbox`` settings the operator's
file writes itself and drops the base's (``_with_own_sandbox``). The file has to be
the operator's for that. One an MCP client delivered under the workspace root, as
the file or as a link there to a file elsewhere, is the client's wherever it
resolves, and so is one that a link inside the scanned tree reaches. Each file is
judged by every name it was reached by (``ResolvedConfigDocument.names``), and
such a file keeps nothing.

The file is named three ways, and each is a call site of the rule: ``ASH_CONFIG``,
the trusted config (``trusted_config_path``) and the selected config
(``config_path``). The first two are driven through ``resolve_config``, with the
grant under ``extra_read_paths``. A delivered ``config_path`` that widens a grant
is refused before this rule runs (``client_config_policy``), so the rule is called
directly for that site and for the names it reads.

The controls are the operator's own file, which keeps its grant. One layout is the
one the rule exists for: the config in ``W`` extending a base inside the checkout
``W/repo``. The base's grant (``network_scanners``) is dropped, the operator's own
(``extra_read_paths``) survives, and the warning names the file that was dropped and
says where to set the grant instead.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List, Tuple

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import (
    _with_own_sandbox,
    resolve_config,
)
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.delivered_trees import symlink, write

OWN_GRANT = "/opt/operator-own-grant"
REPOSITORY_GRANT = "/opt/repository-grant"
BASE_SCANNER = "grype"
#: How the warning that drops a grant says where to set it instead.
REMEDY = "--config-overrides or a config file outside the tree"
OPERATOR = f"sandbox:\n  extra_read_paths:\n    - {OWN_GRANT}\n"
REPOSITORY = f"sandbox:\n  extra_read_paths:\n    - {REPOSITORY_GRANT}\n"
BASE = f"project_name: base\nsandbox:\n  network_scanners:\n    - {BASE_SCANNER}\n"


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(" ".join(record.getMessage().split()))


@pytest.fixture
def sandbox_warnings():
    """The warnings ASH logs while a test resolves a config; it does not propagate."""
    handler = _Collect()
    ASH_LOGGER.addHandler(handler)
    try:
        yield handler.messages
    finally:
        ASH_LOGGER.removeHandler(handler)


@pytest.fixture(autouse=True)
def _isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    # ASH_CONFIG would add a file of its own to a resolution, and a basetemp inside
    # a checkout would put every layout inside that checkout too.
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    for directory in (tmp_path, *tmp_path.parents):
        assert not os.path.lexists(directory / ".git"), (
            f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
        )


def _checkout(root: Path, repository_config: str = "") -> Path:
    """A git checkout to scan, with a config of its own when one is given."""
    (root / ".git").mkdir(parents=True)
    write(root / "a.py", "x = 1\n")
    if repository_config:
        write(root / ".ash" / ".ash.yaml", repository_config)
    return root


def _delivered(tmp_path: Path, how: str, text: str) -> Path:
    """A config an MCP client delivered: the file, or a link there to a host file."""
    delivered = tmp_path / "mcp-workspaces" / "session-1" / "source" / "ash.yaml"
    if how == "file":
        return write(delivered, text)
    symlink(delivered, write(tmp_path / "host" / "ash.yaml", text))
    return delivered


def _granted(result: Tuple[AshConfig, bool]) -> List[str]:
    return list(result[0].sandbox.extra_read_paths)


def _dropped(messages: List[str]) -> List[str]:
    return [message for message in messages if message.startswith("Ignoring sandbox.")]


# ---------------------------------------------------------------------------
# A config the client delivered grants nothing, named by ASH_CONFIG or as the
# trusted config
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("how", ["file", "link"])
def test_an_ash_config_the_client_delivered_grants_nothing(
    how: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The repository's own config puts the resolution under the confinement, and
    ASH_CONFIG then supplies the trusted base unless the client delivered it."""
    repo = _checkout(tmp_path / "repo", REPOSITORY)
    monkeypatch.setenv("ASH_CONFIG", str(_delivered(tmp_path, how, OPERATOR)))

    config = resolve_config(source_dir=repo)

    assert list(config.sandbox.extra_read_paths) == []


@pytest.mark.parametrize("how", ["file", "link"])
def test_a_trusted_config_the_client_delivered_grants_nothing(
    how: str, tmp_path: Path
) -> None:
    repo = _checkout(tmp_path / "repo", REPOSITORY)
    trusted = _delivered(tmp_path, how, OPERATOR)

    config = resolve_config(source_dir=repo, trusted_config_path=trusted)

    assert list(config.sandbox.extra_read_paths) == []


@pytest.mark.parametrize("site", ["ASH_CONFIG", "trusted_config_path"])
def test_control_the_operators_config_outside_everything_still_grants(
    site: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same file, placed outside the workspace root, so the tests above can fail."""
    repo = _checkout(tmp_path / "repo", REPOSITORY)
    operator = write(tmp_path / "host" / "ash.yaml", OPERATOR)
    if site == "ASH_CONFIG":
        monkeypatch.setenv("ASH_CONFIG", str(operator))
        config = resolve_config(source_dir=repo)
    else:
        config = resolve_config(source_dir=repo, trusted_config_path=operator)

    assert list(config.sandbox.extra_read_paths) == [OWN_GRANT]


# ---------------------------------------------------------------------------
# The operator's own file extending a base in the checkout: its grant is kept
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("site", "dropped_file"),
    [
        ("ASH_CONFIG", "base.yaml"),
        ("trusted_config_path", ".ash.yaml"),
        ("config_path", "base.yaml"),
    ],
)
def test_the_operators_own_grant_is_kept_and_the_bases_is_dropped(
    site: str,
    dropped_file: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    sandbox_warnings: List[str],
) -> None:
    """Judging the file by its own names must not count its base's name against it.

    The base is named inside the checkout, and the file that extends it sits
    outside every checkout. Under ``trusted_config_path`` the selected config is
    the checkout's own, so that is the file the warning names.
    """
    w = tmp_path / "W"
    repo = _checkout(w / "repo")
    write(repo / ".ash" / "base.yaml", BASE)
    config = write(w / "ash-config.yaml", "extends: repo/.ash/base.yaml\n" + OPERATOR)
    if site == "ASH_CONFIG":
        monkeypatch.setenv("ASH_CONFIG", str(config))
        resolved = resolve_config(source_dir=repo)
    elif site == "trusted_config_path":
        write(repo / ".ash" / ".ash.yaml", REPOSITORY)
        resolved = resolve_config(source_dir=repo, trusted_config_path=config)
    else:
        resolved = resolve_config(config_path=config, source_dir=repo)

    sandbox = resolved.sandbox

    assert list(sandbox.extra_read_paths) == [OWN_GRANT]
    assert BASE_SCANNER not in (sandbox.network_scanners or [])
    dropped = _dropped(sandbox_warnings)
    assert dropped, "no warning names the file whose grant was dropped"
    for message in dropped:
        assert dropped_file in message, message
        assert REMEDY in message, message
        assert config.name not in message, message


# ---------------------------------------------------------------------------
# _with_own_sandbox itself: the selected config's site, and the names it reads
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("how", ["file", "link"])
def test_a_file_the_client_delivered_keeps_no_grant_of_its_own(
    how: str, tmp_path: Path
) -> None:
    """The chain holds resolved paths; a link's own name is in ``names``."""
    repo = _checkout(tmp_path / "repo")
    delivered = _delivered(tmp_path, how, OPERATOR)
    path = delivered.resolve()
    names = {path: (delivered,)} if path != delivered else {}

    result = _with_own_sandbox(AshConfig(), path, repo, [], [repo], names)

    assert _granted(result) == []
    assert result[1] is False


@pytest.mark.parametrize(
    ("names_the_link", "granted"),
    [(True, []), (False, [OWN_GRANT])],
    ids=["link-is-named", "control-link-is-not-named"],
)
def test_a_file_a_link_in_the_scanned_tree_reaches_is_the_repositorys(
    names_the_link: bool, granted: List[str], tmp_path: Path
) -> None:
    """Whoever wrote the link chose the file, so its name decides, not the target's."""
    repo = _checkout(tmp_path / "repo")
    target = write(tmp_path / "host" / "ash.yaml", OPERATOR)
    link = repo / ".ash" / "ops.yaml"
    symlink(link, target)
    names = {target: (link,)} if names_the_link else {}

    result = _with_own_sandbox(AshConfig(), target, repo, [], [repo], names)

    assert _granted(result) == granted


@pytest.mark.parametrize(
    ("where", "mode", "wrote_mode"),
    [("delivered", "off", False), ("host", "bwrap", True)],
)
def test_a_mode_only_the_operators_file_writes_is_its_own_choice(
    where: str, mode: str, wrote_mode: bool, tmp_path: Path
) -> None:
    """A mode a file that may grant writes stands over the floor, so it must be the
    operator's. A delivered file's does not."""
    repo = _checkout(tmp_path / "repo")
    text = "sandbox:\n  mode: bwrap\n"
    if where == "delivered":
        path = _delivered(tmp_path, "file", text).resolve()
    else:
        path = write(tmp_path / "host" / "ash.yaml", text)

    updated, wrote = _with_own_sandbox(AshConfig(), path, repo, [], [repo], {})

    assert (updated.sandbox.mode, wrote) == (mode, wrote_mode)
