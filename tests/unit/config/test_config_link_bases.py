# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The bases a client's linked config extends are the client's too.

A config named with ``--config`` or ``ASH_CONFIG`` may be a link an MCP client
delivered, to a file elsewhere that extends a base. The file that names a base
chose it, so the base is judged by the paths of the files above it as well as
its own, and the directory the bases must stay inside is worked out from where
the client's link sits, not from where it leads.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
)
from tests.utils.delivered_trees import clone, reads, symlink, write

SESSION = "client-1"

SUPPRESSIONS = (
    "global_settings:\n"
    "  suppressions:\n"
    "    - rule_id: B101\n"
    "      path: 'tests/**'\n"
    "      reason: asserts in tests\n"
)


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    workspace = tmp_path / "workspaces"
    host = tmp_path / "host"
    host.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    yield {"workspace": workspace, "host": host, "tmp": tmp_path}
    clear_profile_registry()
    clear_all_session_state()


def _linked(server, base_text: str) -> Path:
    """A delivered ``conf/ash.yaml`` linking to a host file that extends ``base_text``."""
    host_config = write(
        server["host"] / "conf" / "ash.yaml",
        "project_name: linked\nextends: base.yaml\n",
    )
    write(server["host"] / "conf" / "base.yaml", "project_name: base\n" + base_text)
    source = clone(
        server["tmp"], {"main.py": "x = 1\n"}, {"conf/ash.yaml": host_config}, SESSION
    )
    return source / "conf" / "ash.yaml"


def _base(server) -> Path:
    return (server["host"] / "conf" / "base.yaml").resolve()


# ---------------------------------------------------------------------------
# The bases must stay where the client's link sits
# ---------------------------------------------------------------------------


def test_a_named_delivered_link_cannot_extend_a_host_file(_server) -> None:
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    link = _linked(_server, "fail_on_findings: false\n")
    source = link.parent.parent

    def run() -> None:
        with pytest.raises(ASHConfigSourceError):
            resolve_config(config_path=link, source_dir=source)

    assert _base(_server) not in reads(run)


def test_ash_config_naming_a_delivered_link_cannot_extend_a_host_file(
    _server, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.config.default_config import (
        default_config_document,
    )
    from automated_security_helper.core.exceptions import ASHConfigSourceError

    link = _linked(_server, "fail_on_findings: false\n")
    monkeypatch.setenv("ASH_CONFIG", str(link))

    def run() -> None:
        with pytest.raises(ASHConfigSourceError):
            default_config_document()

    assert _base(_server) not in reads(run)


def test_an_operators_own_link_still_extends_beside_its_target(_server) -> None:
    """A link nobody delivered is followed as before, bases and all."""
    from automated_security_helper.config.resolve_config import resolve_config

    host_config = write(
        _server["host"] / "conf" / "ash.yaml",
        "project_name: linked\nextends: base.yaml\n",
    )
    write(_server["host"] / "conf" / "base.yaml", "fail_on_findings: false\n")
    link = _server["tmp"] / "operator" / "ash.yaml"
    symlink(link, host_config)

    config = resolve_config(config_path=link)

    assert config.project_name == "linked"
    assert config.fail_on_findings is False


# ---------------------------------------------------------------------------
# A base is judged by the files above it as well
# ---------------------------------------------------------------------------
# A source directory that holds both the delivered tree and the host file puts
# the base inside the confinement root, so it is read and has to be judged.


def test_a_base_of_a_delivered_link_may_not_set_a_denied_field(_server) -> None:
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    link = _linked(_server, "fail_on_findings: false\n")

    with pytest.raises(ASHConfigFieldDeniedError):
        resolve_config(config_path=link, source_dir=_server["tmp"])


def test_a_base_of_a_delivered_links_suppressions_are_marked(_server) -> None:
    from automated_security_helper.config.resolve_config import resolve_config

    link = _linked(_server, SUPPRESSIONS)

    config = resolve_config(config_path=link, source_dir=_server["tmp"])

    assert [s.client_supplied for s in config.global_settings.suppressions] == [True]


def test_a_base_records_its_own_spelling_first(_server) -> None:
    """A message about a base names the base, not the file above it."""
    from automated_security_helper.config.config_sources import (
        resolve_config_document,
    )

    link = _linked(_server, SUPPRESSIONS)

    document = resolve_config_document(link, confine_to=_server["tmp"])

    names = document.names[_base(_server)]
    assert names[0] == (_server["host"] / "conf" / "base.yaml").resolve()
    assert link in names


# ---------------------------------------------------------------------------
# A base is judged by the path its extends entry spells
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("spelled", ["through a delivered link", "directly"])
def test_a_base_spelled_through_a_delivered_link_is_the_clients(
    _server, spelled: str
) -> None:
    """An operator's file that names its base through a client's link gets the client's file."""
    from automated_security_helper.config.resolve_config import resolve_config

    base = write(_server["host"] / "conf" / "shared.yaml", SUPPRESSIONS)
    if spelled == "directly":
        entry = base
    else:
        entry = _server["workspace"] / SESSION / "source" / "shared.yaml"
        symlink(entry, base)
    root = write(
        _server["host"] / "conf" / "ash.yaml", f"project_name: op\nextends: {entry}\n"
    )

    config = resolve_config(config_path=root, source_dir=_server["tmp"])

    marks = [s.client_supplied for s in config.global_settings.suppressions]
    assert marks == [spelled != "directly"]
