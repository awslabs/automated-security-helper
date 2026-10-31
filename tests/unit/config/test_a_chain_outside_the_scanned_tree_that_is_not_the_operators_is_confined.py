# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A config file the operator did not write grants nothing, wherever the scanned tree is.

The sandbox grants are honored only from ``--config-overrides`` or a config file
outside every git checkout and the scanned directory, and a file an MCP client
delivered is never the operator's (``sandbox_grants``). ``resolve_config``
confines the files it judges are not the operator's to the trusted base. It used
to judge only the files inside the scanned trees, so a chain wholly outside them
was returned unconfined (the early return), and an operator ``trusted_config_path``
or ``ASH_CONFIG`` file outside them became the trusted base the grants are held
to, even when it sat in another git checkout or was delivered.

Every test here runs the real client-policy step (``apply_client_config_rules``
is not replaced). The delivered-file tests that name the two lists of scanners
(``read_path_scanners`` and ``env_scanners``) are refused by that step, which
compares both with the trusted base and names the fields a file asks for beyond
it. The trusted-base tests use all five grants, since that step never sees the
trusted file. Each refusal has a positive control: the same file outside every
checkout and the MCP root grants.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, Iterator

import pytest
import yaml

from automated_security_helper.config import resolve_config as rc
from automated_security_helper.config.ash_config import SandboxConfig
from automated_security_helper.config.sandbox_grants import (
    confinement_membership,
    membership_clause,
    scanned_trees,
)
from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

#: The two lists the client-policy step does not compare with the trusted base.
SCANNER_GRANTS: Dict[str, Any] = {
    "sandbox": {
        "read_path_scanners": ["semgrep"],
        "env_scanners": ["semgrep"],
    }
}

#: All five grants, each different from the default. The environment entry sets a
#: variable in every sandboxed scanner (a marker label, never a real library).
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

#: The sentence a warning explains the drop of a file outside the trees with.
OUTSIDE_SENTENCE = (
    "the file is inside the scanned tree or a git checkout, or an MCP client "
    "delivered it, so someone other than the operator may have written it"
)


class Layout:
    """The directories one test is built in."""

    def __init__(self, tmp_path: Path) -> None:
        self.mcp_root = tmp_path / "mcp-workspaces"
        #: Where a client's files are delivered.
        self.delivered = self.mcp_root / "session-1" / "source"
        self.delivered.mkdir(parents=True)
        #: Outside every checkout and outside the MCP root.
        self.outside = tmp_path / "operator"
        self.outside.mkdir()
        #: Another git checkout: an operator's own ops or dotfiles repository.
        self.ops = tmp_path / "ops"
        mark_git_checkout(self.ops)
        #: The scanned repository, a checkout of its own.
        self.repo = tmp_path / "repo"
        mark_git_checkout(self.repo)

    def write(self, path: Path, document: Dict[str, Any]) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(yaml.safe_dump(document), encoding="utf-8")
        return path

    def repo_config(self, document: Dict[str, Any] = GRANTS) -> Path:
        """A repository config that writes the same grants, so a trusted base
        built from the file under test would let them through."""
        return self.write(self.repo / ".ash" / ".ash.yaml", document)


@pytest.fixture
def layout(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Layout]:
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    # A basetemp inside a repository would make every control here read as a
    # refusal, and every refusal pass for the wrong reason.
    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )
    layout = Layout(tmp_path)
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(layout.mcp_root))
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    rc.reset_dropped_own_sandbox_warnings()
    yield layout
    rc.reset_dropped_own_sandbox_warnings()


def _grants(config) -> Dict[str, Any]:
    return {key: getattr(config.sandbox, key) for key in GRANT_KEYS}


def _defaults() -> Dict[str, Any]:
    return {key: getattr(SandboxConfig(), key) for key in GRANT_KEYS}


# --- The early return: a chain wholly outside the scanned tree ---------------


def test_a_delivered_config_outside_the_tree_applies_no_scanner_grants(
    layout: Layout,
) -> None:
    """A delivered chain wholly outside the scanned tree is not returned unconfined.

    The client-policy step compares both lists with the trusted base (the server's
    own settings, here the defaults, which name no scanner), so a file that asks
    for more is refused with the fields named; no config comes back to apply a
    grant from."""
    delivered = layout.write(layout.delivered / "ash.yaml", SCANNER_GRANTS)

    with pytest.raises(ASHConfigFieldDeniedError) as refusal:
        rc.resolve_config(config_path=delivered, source_dir=layout.repo)

    refused = str(refusal.value)
    assert "sandbox.read_path_scanners" in refused, refused
    assert "sandbox.env_scanners" in refused, refused


def test_a_delivered_ash_config_with_no_config_file_applies_no_scanner_grants(
    layout: Layout, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With no config file the configuration is ASH_CONFIG's chain, refused the
    same way as a config path the client names."""
    delivered = layout.write(layout.delivered / "ash.yaml", SCANNER_GRANTS)
    monkeypatch.setenv("ASH_CONFIG", str(delivered))

    with pytest.raises(ASHConfigFieldDeniedError) as refusal:
        rc.resolve_config(source_dir=layout.repo)

    refused = str(refusal.value)
    assert "sandbox.read_path_scanners" in refused, refused
    assert "sandbox.env_scanners" in refused, refused


def test_positive_control_the_same_file_outside_the_mcp_root_keeps_scanner_grants(
    layout: Layout, caplog: pytest.LogCaptureFixture
) -> None:
    operator = layout.write(layout.outside / "ash.yaml", SCANNER_GRANTS)

    with caplog.at_level(logging.WARNING):
        config = rc.resolve_config(config_path=operator, source_dir=layout.repo)

    assert config.sandbox.read_path_scanners == ["semgrep"]
    assert config.sandbox.env_scanners == ["semgrep"]
    assert "Ignoring sandbox" not in caplog.text


def test_a_config_in_another_checkout_grants_nothing(
    layout: Layout, caplog: pytest.LogCaptureFixture
) -> None:
    """The operator's own ops checkout is a checkout: ASH cannot tell who wrote the file."""
    ops_config = layout.write(layout.ops / "ash.yaml", GRANTS)

    with caplog.at_level(logging.WARNING):
        config = rc.resolve_config(config_path=ops_config, source_dir=layout.repo)

    assert _grants(config) == _defaults()
    ignored = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring sandbox.")
    ]
    assert len(ignored) == 1, caplog.text
    for key in GRANT_KEYS:
        assert f"sandbox.{key}" in ignored[0]
    # The sentence names the checkout the file sits in, not a load with no
    # working directory, and not the scanned tree.
    assert OUTSIDE_SENTENCE in ignored[0]
    assert "no working directory" not in ignored[0]


def test_positive_control_the_same_file_outside_every_checkout_grants(
    layout: Layout, caplog: pytest.LogCaptureFixture
) -> None:
    operator = layout.write(layout.outside / "ash.yaml", GRANTS)

    with caplog.at_level(logging.WARNING):
        config = rc.resolve_config(config_path=operator, source_dir=layout.repo)

    assert _grants(config) == GRANTS["sandbox"]
    assert "Ignoring sandbox" not in caplog.text


def test_a_delivered_config_that_is_the_operators_session_profile_is_not_confined(
    layout: Layout,
) -> None:
    """The profile files the server writes in a session's config/ directory are
    the operator's, even though they sit under the MCP root."""
    profile = layout.write(
        layout.mcp_root / "session-1" / "config" / "ash.yaml", SCANNER_GRANTS
    )

    config = rc.resolve_config(config_path=profile, source_dir=layout.repo)

    assert config.sandbox.read_path_scanners == ["semgrep"]
    assert config.sandbox.env_scanners == ["semgrep"]


# --- The trusted base: a file that is not the operator's cannot be it --------


def test_a_delivered_trusted_config_path_is_not_the_trusted_base(
    layout: Layout,
) -> None:
    """The client-policy step never sees the trusted file, so the repository's
    config would otherwise be held to grants the client wrote."""
    layout.repo_config()
    trusted = layout.write(layout.delivered / "ash.yaml", GRANTS)

    config = rc.resolve_config(source_dir=layout.repo, trusted_config_path=trusted)

    assert _grants(config) == _defaults()


def test_a_delivered_ash_config_is_not_the_trusted_base(
    layout: Layout, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout.repo_config()
    delivered = layout.write(layout.delivered / "ash.yaml", GRANTS)
    monkeypatch.setenv("ASH_CONFIG", str(delivered))

    config = rc.resolve_config(source_dir=layout.repo)

    assert _grants(config) == _defaults()


def test_a_trusted_config_path_in_another_checkout_is_not_the_trusted_base(
    layout: Layout,
) -> None:
    layout.repo_config()
    trusted = layout.write(layout.ops / "ash.yaml", GRANTS)

    config = rc.resolve_config(source_dir=layout.repo, trusted_config_path=trusted)

    assert _grants(config) == _defaults()


def test_an_ash_config_in_another_checkout_is_not_the_trusted_base(
    layout: Layout, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout.repo_config()
    ops_config = layout.write(layout.ops / "ash.yaml", GRANTS)
    monkeypatch.setenv("ASH_CONFIG", str(ops_config))

    config = rc.resolve_config(source_dir=layout.repo)

    assert _grants(config) == _defaults()


def test_an_ash_config_linked_from_another_checkout_grants_nothing(
    layout: Layout, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The link is kept in the ops checkout, so the file it leads to is held to
    the same rule though it sits outside every checkout."""
    real = layout.write(layout.outside / "real.yaml", GRANTS)
    link = layout.ops / "link.yaml"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")
    monkeypatch.setenv("ASH_CONFIG", str(link))

    config = rc.resolve_config(source_dir=layout.repo)

    assert _grants(config) == _defaults()


def test_an_operators_root_keeps_its_own_grant_and_a_base_in_another_checkout_loses_its(
    layout: Layout,
) -> None:
    """Each file grants under its own key, so the result shows whose grant survived."""
    root = layout.repo.parent
    layout.write(layout.ops / "base.yaml", {"sandbox": {"network_scanners": ["grype"]}})
    operator = layout.write(
        root / "operator-root.yaml",
        {"extends": "ops/base.yaml", "sandbox": {"extra_read_paths": ["/own"]}},
    )

    config = rc.resolve_config(config_path=operator, source_dir=layout.repo)

    assert config.sandbox.extra_read_paths == ["/own"]
    assert config.sandbox.network_scanners is None


@pytest.mark.parametrize("route", ["trusted_config_path", "ASH_CONFIG"])
def test_positive_control_the_operators_file_outside_every_checkout_is_the_trusted_base(
    layout: Layout, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    """The repository's config asks for what the operator's own file grants."""
    layout.repo_config()
    operator = layout.write(layout.outside / "ash.yaml", GRANTS)
    if route == "ASH_CONFIG":
        monkeypatch.setenv("ASH_CONFIG", str(operator))
        call: Dict[str, Any] = {"source_dir": layout.repo}
    else:
        call = {"source_dir": layout.repo, "trusted_config_path": operator}

    config = rc.resolve_config(**call)

    assert _grants(config) == GRANTS["sandbox"]


def test_the_trusted_base_judges_the_operators_file_by_outside_files_only_when_asked(
    layout: Layout,
) -> None:
    """The container floor reads the base for its mode alone and does not ask."""
    operator = rc._load_operator_config(
        layout.write(layout.ops / "ash.yaml", GRANTS), layout.repo, None
    )
    trees = scanned_trees(layout.repo)

    plain = rc.trusted_base_config(operator, trees, False, merged_fallback=True)
    asked = rc.trusted_base_config(
        operator, trees, False, merged_fallback=True, outside_files=True
    )

    assert plain.sandbox.extra_read_paths == ["/data"]
    assert asked.sandbox.extra_read_paths == []


# --- What the change must leave as it was -------------------------------------


def test_the_mode_an_operator_file_in_another_checkout_sets_is_still_the_floor(
    layout: Layout,
) -> None:
    """A mode other than off grants nothing, so it counts wherever the file lives:
    the repository's config cannot turn off the sandbox the operator's file in
    another checkout turned on."""
    layout.repo_config({"sandbox": {"mode": "off"}})
    trusted = layout.write(layout.ops / "ash.yaml", {"sandbox": {"mode": "bwrap"}})

    config = rc.resolve_config(source_dir=layout.repo, trusted_config_path=trusted)

    assert config.sandbox.mode == "bwrap"


def test_the_mode_an_ash_config_in_another_checkout_sets_is_still_the_floor(
    layout: Layout, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The operator's config extends a base in the scanned tree, so ASH_CONFIG's file
    is the base the grants and the mode are held to; ASH_CONFIG sits in another
    checkout, so it grants nothing, but the mode it turned on still holds."""
    root = layout.repo.parent
    layout.write(layout.repo / ".ash" / "base.yaml", {"project_name": "base"})
    operator = layout.write(
        root / "operator-root.yaml", {"extends": "repo/.ash/base.yaml"}
    )
    layout.repo_config({"sandbox": {"mode": "off"}})
    ops_config = layout.write(layout.ops / "ash.yaml", {"sandbox": {"mode": "bwrap"}})
    monkeypatch.setenv("ASH_CONFIG", str(ops_config))

    config = rc.resolve_config(source_dir=layout.repo, trusted_config_path=operator)

    assert config.sandbox.mode == "bwrap"


def test_the_mode_an_operator_file_in_another_checkout_sets_beats_ash_config_s(
    layout: Layout, monkeypatch: pytest.MonkeyPatch
) -> None:
    layout.repo_config({"sandbox": {"mode": "off"}})
    trusted = layout.write(layout.ops / "ash.yaml", {"sandbox": {"mode": "firejail"}})
    elsewhere = layout.write(
        layout.outside / "ash.yaml", {"sandbox": {"mode": "bwrap"}}
    )
    monkeypatch.setenv("ASH_CONFIG", str(elsewhere))

    config = rc.resolve_config(source_dir=layout.repo, trusted_config_path=trusted)

    assert config.sandbox.mode == "firejail"


def test_a_link_in_the_tree_to_a_file_elsewhere_is_still_worded_as_the_trees(
    layout: Layout, caplog: pytest.LogCaptureFixture
) -> None:
    """The link is the repository's, so the sentence names the tree, not the
    outside memberships, though the file it reaches sits outside the tree."""
    host = layout.write(layout.outside / "real.yaml", GRANTS)
    link = layout.repo / ".ash" / ".ash.yaml"
    link.parent.mkdir(parents=True)
    try:
        link.symlink_to(host)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not available on this platform")

    with caplog.at_level(logging.WARNING):
        config = rc.resolve_config(source_dir=layout.repo)

    assert _grants(config) == _defaults()
    ignored = [
        record.getMessage()
        for record in caplog.records
        if record.getMessage().startswith("Ignoring sandbox.")
    ]
    assert len(ignored) == 1, caplog.text
    assert "the file is inside the scanned tree" in ignored[0]
    assert "or an MCP client delivered it" not in ignored[0]


# --- The warning's sentence ----------------------------------------------------


def test_the_outside_sentence_names_every_membership_a_file_can_have() -> None:
    assert membership_clause(checkout_membership=False, outside=True) == (
        "the file is inside the scanned tree or a git checkout, or an MCP client "
        "delivered it"
    )
    assert confinement_membership(checkout_membership=False, outside=True) == (
        OUTSIDE_SENTENCE
    )


def test_the_outside_sentence_yields_to_the_client_and_the_undecided_ones() -> None:
    client = membership_clause(
        checkout_membership=False, client_supplied=True, outside=True
    )
    assert client == membership_clause(checkout_membership=False, client_supplied=True)
    stopped = membership_clause(checkout_membership=False, undecided=True, outside=True)
    assert stopped == membership_clause(checkout_membership=False, undecided=True)
    assert confinement_membership(
        checkout_membership=False, undecided=True, outside=True
    ) == confinement_membership(checkout_membership=False, undecided=True)


def test_control_the_other_sentences_are_what_they_were() -> None:
    assert membership_clause(checkout_membership=False) == (
        "the file is inside the scanned tree"
    )
    assert membership_clause(checkout_membership=True) == (
        "the file is in a checkout, which with no working directory is read as "
        "the scanned tree"
    )
    assert membership_clause(checkout_membership=False, given_root=True) == (
        "the file is inside the given root's trees"
    )
