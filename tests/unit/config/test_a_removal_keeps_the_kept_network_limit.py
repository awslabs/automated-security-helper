"""A ``-=`` removal keeps the network limit a file in another checkout kept.

An operator config file that sits in a git checkout other than the scanned one
may not grant, so the trusted base falls to the defaults, but a
``network_scanners`` list in that file still holds as a limit
(``restrictions_kept``): a scanner outside it gets no network.
``_sets_network_scanners`` decides whether one of the operator's overrides
replaces that limit. An override that writes the list (``=`` or ``+=``, at the
key or at the whole ``sandbox`` section) is the operator's own grant, so it
replaces the limit. A removal writes no list: it takes scanners out of the list
in force, and ``confine_sandbox_grants`` intersects that list with the kept limit,
so the limit narrows with it. Read as a write of the list,
``sandbox.network_scanners-=[grype]`` would drop the limit and give every scanner
the limit left out its network back, the opposite of what a removal asks for.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, List, Optional

import pytest

from automated_security_helper.config import resolve_config as resolve_config_module
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.utils.sandbox.policy import (
    SandboxRequirements,
    build_scanner_policy,
)
from tests.utils.helpers import mark_git_checkout

pytestmark = pytest.mark.unit

#: The operator's file. In another checkout its network list is kept as a limit.
OPERATOR = """\
project_name: operator
sandbox:
  network_scanners: [semgrep]
"""

#: The scanned repository's own config, which writes no network list.
REPOSITORY = """\
project_name: repository
"""

#: The scanned repository's own config with a network list of its own, which names
#: grype, a scanner the kept limit leaves out.
WIDE_REPOSITORY = """\
project_name: repository
sandbox:
  network_scanners: [semgrep, grype]
"""

ROUTES = ["ASH_CONFIG", "trusted_config_path"]


@pytest.fixture(autouse=True)
def _tmp_path_is_outside_every_checkout(tmp_path: Path) -> None:
    from automated_security_helper.config.sandbox_grants import in_any_checkout

    assert not in_any_checkout(tmp_path), (
        f"{tmp_path} is inside a git checkout; run with --basetemp outside one"
    )


@pytest.fixture(autouse=True)
def _own_notice_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """A notice set of this test's own: a removal that finds no list says so once
    per run, and the notices given here must not reach another test."""
    monkeypatch.setattr(
        resolve_config_module, "_OVERRIDE_NOTICES_GIVEN", set(), raising=False
    )


def _resolve(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    route: str,
    repository_text: str = REPOSITORY,
    overrides: Optional[List[str]] = None,
) -> AshConfig:
    """Resolve the repository's config as a scan does, with the operator's file in
    a git checkout other than the scanned one, named by *route*, and *overrides*
    as the operator's ``--config-overrides``."""
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    ops = tmp_path / "ops"
    mark_git_checkout(ops)
    path = ops / "ash.yaml"
    path.write_text(OPERATOR, encoding="utf-8")
    repository = tmp_path / "repo"
    mark_git_checkout(repository)
    (repository / ".ash.yaml").write_text(repository_text, encoding="utf-8")
    if route == "ASH_CONFIG":
        monkeypatch.setenv("ASH_CONFIG", str(path))
        return resolve_config(source_dir=repository, config_overrides=overrides)
    return resolve_config(
        source_dir=repository, trusted_config_path=path, config_overrides=overrides
    )


def _network(sandbox: Any, name: str, declared: bool, tmp_path: Path) -> bool:
    """Whether *name* gets a network under *sandbox*, given what it declares."""
    results = tmp_path / "results"
    results.mkdir(exist_ok=True)
    return build_scanner_policy(
        name,
        SandboxRequirements(network=declared),
        argv0="/bin/true",
        source_dir=tmp_path,
        output_dir=tmp_path,
        results_dir=results,
        scan_target=None,
        cwd=None,
        offline=False,
        network_scanners=sandbox.network_scanners,
        extra_read_paths=sandbox.extra_read_paths,
        network_limit=sandbox.network_limit,
    ).network


@pytest.mark.parametrize(
    ("override", "writes_a_list"),
    [
        ("sandbox.network_scanners=[grype]", True),
        ("sandbox.network_scanners+=[grype]", True),
        ("sandbox.network-scanners+=[grype]", True),
        ('sandbox={"mode": "bwrap"}', True),
        ('sandbox+={"mode": "bwrap"}', True),
        ("sandbox.mode=bwrap", False),
        ("sandbox.network_scanners-=[grype]", False),
        ("sandbox.network-scanners-=[grype]", False),
        ('sandbox-={"mode": "bwrap"}', False),
    ],
    ids=[
        "set",
        "append",
        "append-kebab",
        "section-set",
        "section-append",
        "other-key",
        "remove",
        "remove-kebab",
        "section-remove",
    ],
)
def test_only_a_replacement_or_an_append_writes_the_network_list(
    override: str, writes_a_list: bool
) -> None:
    """A control on how the override's operator is read. A replacement or an
    append, at the key in either separator spelling or at the whole ``sandbox``
    section, writes the list and so replaces the kept limit; another sandbox key
    does not; a removal, at the key or at the section, writes no list and keeps
    the limit. It must hold both while a key ending in ``-`` names no setting and
    once ``-=`` is read as a removal; a read that cuts the operator off the key
    without checking which one it was answers True for the three removal rows."""
    from automated_security_helper.config.resolve_config import _sets_network_scanners

    assert _sets_network_scanners(override) is writes_a_list


@pytest.mark.parametrize(
    ("repository_text", "removal"),
    [
        (WIDE_REPOSITORY, "sandbox.network_scanners-=[zap]"),
        (REPOSITORY, "sandbox.network_scanners-=[grype]"),
    ],
    ids=["unheld-name", "unset-list"],
)
def test_a_removal_keeps_the_network_limit_a_file_in_another_checkout_kept(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    repository_text: str,
    removal: str,
) -> None:
    """The kept limit survives a removal, so grype, which the limit leaves out,
    gets no network whatever the removal names.

    ``unheld-name``: the repository's own list names grype, and the removal names
    a scanner no list holds, so nothing is removed; were the kept limit dropped,
    the repository's list would be the limit on its own and grype would get a
    network. ``unset-list``: no list is in force (each scanner's declared need
    applies) and the removal removes nothing; were the kept limit dropped, every
    scanner that declares a need would get a network, grype among them.

    Run on the ``trusted_config_path`` route. There the operator's file is only
    the trusted base and never part of the run's own configuration, so the run's
    own list is the repository's alone, and both rows tell a kept limit from a
    dropped one.
    """
    config = _resolve(
        tmp_path,
        monkeypatch,
        "trusted_config_path",
        repository_text=repository_text,
        overrides=[removal],
    )

    assert config.sandbox.network_limit == ["semgrep"]
    assert config.sandbox.network_scanners is None
    assert _network(config.sandbox, "grype", True, tmp_path) is False
    assert _network(config.sandbox, "semgrep", True, tmp_path) is True


@pytest.mark.parametrize("route", ROUTES, ids=["ash-config", "trusted-path"])
@pytest.mark.parametrize(
    "grant",
    ["sandbox.network_scanners=[grype]", "sandbox.network_scanners+=[grype]"],
    ids=["set", "append"],
)
def test_a_replacement_or_an_append_is_the_operators_own_grant(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, route: str, grant: str
) -> None:
    """A control: the operator's own list replaces the kept limit, so grype, which
    the kept limit leaves out, gets a network, and semgrep, which the list leaves
    out, gets none. It must hold whatever a removal does: kept beside the
    operator's list, the limit would cut that list to nothing and grype would get
    no network."""
    config = _resolve(tmp_path, monkeypatch, route, overrides=[grant])

    assert config.sandbox.network_scanners == ["grype"]
    assert config.sandbox.network_limit == ["grype"]
    assert _network(config.sandbox, "grype", True, tmp_path) is True
    assert _network(config.sandbox, "semgrep", True, tmp_path) is False
