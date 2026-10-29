# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""An operator file keeps the sandbox grants it writes itself, whatever its base is.

``resolve_config`` lets a file that is the operator's keep the ``sandbox``
settings it writes itself when only a base it extends is repository-written
(``_with_own_sandbox``). The file is judged by the names it was reached by: its
resolved path and the name it was given. The spelling of a base it extends
(``repo/.ash/base.yaml``, or a link in the file's directory that leads there) is
that base's name, so it must not count against the file that extends it.

The selected ``--config`` is driven in
``test_operator_config_keeps_only_its_own_grants.py``. The other two files this
rule is called for are driven here:

- the file ``ASH_CONFIG`` names;
- the operator's trusted config (``trusted_config_path``).

Each sits outside every checkout and extends a base inside the scanned checkout
``W/repo``, which also holds a config of its own that grants
``/opt/repository-grant``, so the confinement runs. The operator file writes
``extra_read_paths`` and its base writes ``network_scanners``: the operator's
grant survives, and neither the base's nor the repository's does. A file with no
``extends`` is the control.

The overlay (``overlay_config_path``) is the operator's file layered over the
selected config, and it is the last file of the chain. It is judged by the names
it was reached by, not by the name of the config it is layered over: outside
every checkout it keeps its own grant beside a base in the scanned checkout, and
named through a link in another checkout it keeps none.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.log import ASH_LOGGER
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

OWN_GRANT = "/opt/operator-own-grant"
REPOSITORY_GRANT = "/opt/repository-grant"
BASE_SCANNER = "grype"
OPERATOR_FILE = "operator.yaml"
OPERATOR = f"sandbox:\n  extra_read_paths:\n    - {OWN_GRANT}\n"
REPOSITORY = f"sandbox:\n  extra_read_paths:\n    - {REPOSITORY_GRANT}\n"
BASE = f"project_name: base\nsandbox:\n  network_scanners:\n    - {BASE_SCANNER}\n"

SITES = ["the-file-ASH_CONFIG-names", "the-trusted-config"]
LAYOUTS = [
    "extends-spelled-in-the-checkout",
    "extends-through-a-link-into-the-checkout",
    "no-extends",
]


class _Collect(logging.Handler):
    def __init__(self) -> None:
        super().__init__(logging.WARNING)
        self.messages: List[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.messages.append(" ".join(record.getMessage().split()))


@pytest.fixture
def warnings_logged():
    """The warnings ASH logs while a test resolves a config; filled as it runs."""
    handler = _Collect()
    ASH_LOGGER.addHandler(handler)
    try:
        yield handler.messages
    finally:
        ASH_LOGGER.removeHandler(handler)


def _dropped(messages: List[str]) -> List[str]:
    return [message for message in messages if message.startswith("Ignoring sandbox.")]


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    # ASH_CONFIG would add a file of its own to the resolution, and a basetemp
    # inside a checkout would put every layout inside that checkout too. A
    # workspace root of the MCP server that holds the basetemp would make every
    # file here a client's, so it is pointed at a directory nothing is in.
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp-workspaces"))
    for directory in (tmp_path, *tmp_path.parents):
        assert not os.path.lexists(directory / ".git"), (
            f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
        )


def _write(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _symlink(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")


def _scanned_checkout(w: Path) -> Path:
    """W/repo, a checkout with a config of its own that grants something."""
    repo = w / "repo"
    mark_git_checkout(repo)
    _write(repo / "a.py", "x = 1\n")
    _write(repo / ".ash" / ".ash.yaml", REPOSITORY)
    return repo


def _operator_file(layout: str, w: Path) -> Path:
    """W/operator.yaml, outside every checkout, extending a base in W/repo."""
    if layout == "no-extends":
        return _write(w / OPERATOR_FILE, OPERATOR)
    base = _write(w / "repo" / ".ash" / "base.yaml", BASE)
    if layout == "extends-spelled-in-the-checkout":
        return _write(w / OPERATOR_FILE, "extends: repo/.ash/base.yaml\n" + OPERATOR)
    if layout == "extends-through-a-link-into-the-checkout":
        _symlink(w / "base.yaml", base)
        return _write(w / OPERATOR_FILE, "extends: base.yaml\n" + OPERATOR)
    raise AssertionError(layout)


def _resolved_sandbox(site: str, operator: Path, repo: Path, monkeypatch):
    if site == "the-file-ASH_CONFIG-names":
        monkeypatch.setenv("ASH_CONFIG", str(operator))
        return resolve_config(source_dir=repo).sandbox
    return resolve_config(source_dir=repo, trusted_config_path=operator).sandbox


@pytest.mark.parametrize("layout", LAYOUTS)
@pytest.mark.parametrize("site", SITES)
def test_the_operators_own_grant_is_kept_and_nothing_else_is(
    site, layout, tmp_path, monkeypatch, warnings_logged
):
    w = tmp_path / "W"
    repo = _scanned_checkout(w)
    operator = _operator_file(layout, w)

    sandbox = _resolved_sandbox(site, operator, repo, monkeypatch)

    assert list(sandbox.extra_read_paths) == [OWN_GRANT]
    assert BASE_SCANNER not in (sandbox.network_scanners or [])
    # The repository's own grant is dropped with a warning that names the
    # repository's file, never the operator's.
    dropped = _dropped(warnings_logged)
    assert dropped, "no warning names the repository config whose grant was dropped"
    for message in dropped:
        assert OPERATOR_FILE not in message, message


def _selected_config_with_a_base_in_the_checkout(w: Path) -> tuple[Path, Path]:
    """(W/selected.yaml, W/repo): a config outside every checkout whose only
    content is an extends of a base inside the scanned checkout."""
    repo = w / "repo"
    mark_git_checkout(repo)
    _write(repo / "a.py", "x = 1\n")
    _write(repo / ".ash" / "base.yaml", BASE)
    return _write(w / "selected.yaml", "extends: repo/.ash/base.yaml\n"), repo


def _overlay_file(layout: str, w: Path) -> Path:
    """The operator's file, outside every checkout: named directly, or through a
    link in W/other, a checkout that is not scanned."""
    real = _write(w / "operator" / OPERATOR_FILE, OPERATOR)
    if layout == "outside-every-checkout":
        return real
    mark_git_checkout(w / "other")
    link = w / "other" / "overlay.yaml"
    _symlink(link, real)
    return link


@pytest.mark.parametrize(
    ("layout", "kept"),
    [
        ("outside-every-checkout", [OWN_GRANT]),
        ("named-through-a-link-in-another-checkout", []),
    ],
)
def test_an_overlay_is_judged_by_its_own_names(layout, kept, tmp_path):
    w = tmp_path / "W"
    selected, repo = _selected_config_with_a_base_in_the_checkout(w)
    overlay = _overlay_file(layout, w)

    sandbox = resolve_config(
        config_path=selected, source_dir=repo, overlay_config_path=overlay
    ).sandbox

    assert list(sandbox.extra_read_paths) == kept
    assert BASE_SCANNER not in (sandbox.network_scanners or [])
