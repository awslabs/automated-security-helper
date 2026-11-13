# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file an MCP client delivered grants no sandbox access, however it is reached.

A file under the MCP workspace root is a client's (``_not_the_operators``),
whoever names it and by whichever name. ``resolve_config`` builds the trusted
base the scan's sandbox grants are held to in three places that each judge a
file that way: ``ASH_CONFIG``'s file (``default_config_chain``), the
operator's ``trusted_config_path``, and the ``--config`` file the scan selected
(``_with_own_sandbox``). Every shape below reaches one of them with a client's
file that writes all five sandbox grants and ``network_scanners``, and none of
them may reach the resolved config.

The client-policy step (``apply_client_config_rules``) is replaced by one that
changes nothing, so what is measured is the confinement alone: the policy step
refuses some of these files before confinement runs, and that refusal is tested
on its own (``test_files_under_the_mcp_root_are_the_clients.py``).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Callable, Dict, Iterator

import pytest
import yaml

from automated_security_helper.config import client_config_policy
from automated_security_helper.config import resolve_config as rc
from automated_security_helper.config.ash_config import SandboxConfig
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

#: The sandbox settings every client file writes: the five grants, the environment
#: list among them (a marker label, never a real library). Each differs from the
#: default.
GRANTS: Dict[str, Any] = {
    "sandbox": {
        "network_scanners": ["checkov"],
        "extra_read_paths": ["/data"],
        "read_path_scanners": ["semgrep"],
        "env_scanners": ["semgrep"],
        "environment": ["LD_PRELOAD=MARKER-not-a-real-library"],
    }
}

GRANT_KEYS = (
    "network_scanners",
    "extra_read_paths",
    "read_path_scanners",
    "env_scanners",
    "environment",
)


class Layout:
    """The directories one shape is built in."""

    def __init__(self, tmp_path: Path) -> None:
        self.mcp_root = tmp_path / "mcp-workspaces"
        #: Where a client's files are delivered.
        self.delivered = self.mcp_root / "session-1" / "source"
        self.delivered.mkdir(parents=True)
        #: Outside every checkout and outside the MCP root.
        self.outside = tmp_path / "operator"
        self.outside.mkdir()
        #: The scanned repository.
        self.repo = tmp_path / "repo"
        mark_git_checkout(self.repo)

    def write(self, path: Path, document: Dict[str, Any]) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
        return path

    def repo_config(self) -> None:
        """A repository config that writes the same grants, so a trusted base
        built from a client's file would let them through."""
        self.write(self.repo / ".ash" / ".ash.yaml", GRANTS)

    def link(self, link: Path, target: Path) -> Path:
        link.symlink_to(target)
        return link


Shape = Callable[[Layout, pytest.MonkeyPatch], Dict[str, Any]]


def _ash_config(layout: Layout, monkeypatch: pytest.MonkeyPatch, path: Path) -> None:
    monkeypatch.setenv("ASH_CONFIG", str(path))


def ash_config_delivered(layout, monkeypatch):
    _ash_config(
        layout, monkeypatch, layout.write(layout.delivered / "ash.yaml", GRANTS)
    )
    return {"source_dir": layout.repo}


def ash_config_delivered_with_a_repository_config(layout, monkeypatch):
    layout.repo_config()
    return ash_config_delivered(layout, monkeypatch)


def ash_config_a_link_outside_to_a_delivered_file(layout, monkeypatch):
    target = layout.write(layout.delivered / "ash.yaml", GRANTS)
    _ash_config(layout, monkeypatch, layout.link(layout.outside / "ash.yaml", target))
    layout.repo_config()
    return {"source_dir": layout.repo}


def ash_config_a_delivered_link_to_a_file_outside(layout, monkeypatch):
    target = layout.write(layout.outside / "ash.yaml", GRANTS)
    _ash_config(layout, monkeypatch, layout.link(layout.delivered / "ash.yaml", target))
    layout.repo_config()
    return {"source_dir": layout.repo}


def ash_config_a_delivered_root_extending_a_sibling(layout, monkeypatch):
    layout.write(layout.delivered / "base.yaml", {"project_name": "base"})
    root = layout.write(
        layout.delivered / "ash.yaml", {"extends": "base.yaml", **GRANTS}
    )
    _ash_config(layout, monkeypatch, root)
    layout.repo_config()
    return {"source_dir": layout.repo}


def config_delivered(layout, monkeypatch):
    path = layout.write(layout.delivered / "ash.yaml", GRANTS)
    return {"config_path": path, "source_dir": layout.repo}


def config_a_link_outside_to_a_delivered_file(layout, monkeypatch):
    target = layout.write(layout.delivered / "ash.yaml", GRANTS)
    link = layout.link(layout.outside / "ash.yaml", target)
    return {"config_path": link, "source_dir": layout.repo}


def config_a_delivered_link_to_a_file_outside(layout, monkeypatch):
    target = layout.write(layout.outside / "ash.yaml", GRANTS)
    link = layout.link(layout.delivered / "ash.yaml", target)
    return {"config_path": link, "source_dir": layout.repo}


def config_a_delivered_root_extending_a_sibling(layout, monkeypatch):
    layout.write(layout.delivered / "base.yaml", {"project_name": "base"})
    root = layout.write(
        layout.delivered / "ash.yaml", {"extends": "base.yaml", **GRANTS}
    )
    return {"config_path": root, "source_dir": layout.repo}


def discovered_in_a_delivered_tree(layout, monkeypatch):
    """The scan of a client's delivered tree discovers the config it holds."""
    layout.write(layout.delivered / ".ash" / ".ash.yaml", GRANTS)
    return {"source_dir": layout.delivered}


def trusted_config_path_delivered(layout, monkeypatch):
    """The operator's config named as a delivered file; the repository's config
    is held to it."""
    layout.repo_config()
    path = layout.write(layout.delivered / "ash.yaml", GRANTS)
    return {"source_dir": layout.repo, "trusted_config_path": path}


SHAPES = [
    ash_config_delivered,
    ash_config_delivered_with_a_repository_config,
    ash_config_a_link_outside_to_a_delivered_file,
    ash_config_a_delivered_link_to_a_file_outside,
    ash_config_a_delivered_root_extending_a_sibling,
    config_delivered,
    config_a_link_outside_to_a_delivered_file,
    config_a_delivered_link_to_a_file_outside,
    config_a_delivered_root_extending_a_sibling,
    discovered_in_a_delivered_tree,
    trusted_config_path_delivered,
]


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Layout]:
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    # A basetemp inside a repository would make the controls below read as
    # confined files, and every refusal pass for the wrong reason.
    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )
    layout = Layout(tmp_path)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(layout.mcp_root))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    # resolve_config looks the step up in client_config_policy each time it runs,
    # so that is the name to replace; the resolve_config module holds no such name.
    monkeypatch.setattr(
        client_config_policy,
        "apply_client_config_rules",
        lambda config, *args, **kwargs: config,
    )
    rc.reset_dropped_own_sandbox_warnings()
    yield layout
    rc.reset_dropped_own_sandbox_warnings()


def _grants(config) -> Dict[str, Any]:
    return {key: getattr(config.sandbox, key) for key in GRANT_KEYS}


@pytest.mark.parametrize("shape", SHAPES, ids=lambda shape: shape.__name__)
def test_a_client_file_grants_nothing(
    layout: Layout, monkeypatch: pytest.MonkeyPatch, shape: Shape
) -> None:
    config = rc.resolve_config(**shape(layout, monkeypatch))

    defaults = SandboxConfig()
    assert _grants(config) == {key: getattr(defaults, key) for key in GRANT_KEYS}


@pytest.mark.parametrize(
    "shape",
    [
        ash_config_delivered,
        ash_config_a_delivered_link_to_a_file_outside,
        config_a_delivered_root_extending_a_sibling,
        trusted_config_path_delivered,
    ],
    ids=lambda shape: shape.__name__,
)
def test_the_dropped_settings_are_named_once(
    layout: Layout,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    shape: Shape,
) -> None:
    """A file whose own sandbox settings are dropped because a client delivered
    it is named in one warning, however often the config is resolved."""
    call = shape(layout, monkeypatch)

    with caplog.at_level(logging.WARNING):
        rc.resolve_config(**call)
        rc.resolve_config(**call)

    named = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring the sandbox settings")
    ]
    assert len(named) == 1, named
    assert "was delivered by an MCP client" in named[0]
    assert "ash.yaml" in named[0]
    # The values are the client's; the warning names the file and the section.
    assert "/data" not in named[0]


@pytest.mark.parametrize(
    "where", ["outside", "outside-extending-a-sibling", "trusted_config_path"]
)
def test_control_an_operator_file_outside_every_checkout_still_grants(
    layout: Layout,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    where: str,
) -> None:
    """The same settings in the operator's own file grant, with no warning."""
    if where == "outside":
        _ash_config(
            layout, monkeypatch, layout.write(layout.outside / "ash.yaml", GRANTS)
        )
        call: Dict[str, Any] = {"source_dir": layout.repo}
    elif where == "outside-extending-a-sibling":
        layout.write(layout.outside / "base.yaml", {"project_name": "base"})
        root = layout.write(
            layout.outside / "ash.yaml", {"extends": "base.yaml", **GRANTS}
        )
        call = {"config_path": root, "source_dir": layout.repo}
    else:
        layout.repo_config()
        path = layout.write(layout.outside / "ash.yaml", GRANTS)
        call = {"source_dir": layout.repo, "trusted_config_path": path}

    with caplog.at_level(logging.WARNING):
        config = rc.resolve_config(**call)

    assert _grants(config) == GRANTS["sandbox"]
    assert "Ignoring the sandbox settings" not in caplog.text
