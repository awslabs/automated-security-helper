# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ASH_CONFIG`` and the trusted config are judged by every path they were reached by.

Each of these is the operator's unless an MCP client delivered it. A link under
the MCP workspace root is a file the client chose wherever it points, so a link
there to a file elsewhere is the client's: as ``ASH_CONFIG`` it is checked as a
client's file and confined, and as the trusted config it supplies neither the
runtime-override policy nor anything else a client may not set.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.cli.mcp.profile_registry import (
    clear_profile_registry,
    clear_all_session_state,
)
from tests.utils.delivered_trees import symlink, write

pytestmark = pytest.mark.unit

SESSION = "client-1"

DENIED = "project_name: linked\nfail_on_findings: false\n"

#: A profile that denies a client only its own policy section.
LOOSENED = (
    "project_name: loosened\n"
    "global_settings:\n"
    "  mcp:\n"
    "    runtime_overrides:\n"
    "      replace_default_denied_paths: true\n"
    "      denied_paths: ['/global_settings/mcp', '/global_settings/mcp/**']\n"
)


@pytest.fixture(autouse=True)
def _server(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    workspace = tmp_path / "workspaces"
    host = tmp_path / "host"
    host.mkdir()
    plain = tmp_path / "plain"
    plain.mkdir()
    monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(workspace))
    monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
    monkeypatch.delenv("ASH_MCP_ALLOWED_CONFIG_ROOTS", raising=False)
    monkeypatch.delenv("ASH_CONFIG", raising=False)
    clear_profile_registry()
    clear_all_session_state()
    yield {"workspace": workspace, "host": host, "plain": plain, "tmp": tmp_path}
    clear_profile_registry()
    clear_all_session_state()


def _delivered_link(server, text: str) -> Path:
    """A link in a session's delivered source, to a host file holding ``text``."""
    target = write(server["host"] / "ash.yaml", text)
    link = server["workspace"] / SESSION / "source" / "ash.yaml"
    symlink(link, target)
    return link


def _delivered_file(server, text: str) -> Path:
    return write(server["workspace"] / SESSION / "source" / "app" / "ash.yaml", text)


# ---------------------------------------------------------------------------
# ASH_CONFIG naming a delivered link
# ---------------------------------------------------------------------------


def test_ash_config_naming_a_delivered_link_is_checked_as_the_clients(
    _server, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    monkeypatch.setenv("ASH_CONFIG", str(_delivered_link(_server, DENIED)))

    with pytest.raises(ASHConfigFieldDeniedError):
        resolve_config(source_dir=_server["plain"])


def test_positive_control_ash_config_naming_the_host_file_is_the_operators(
    _server, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.config.resolve_config import resolve_config

    monkeypatch.setenv("ASH_CONFIG", str(write(_server["host"] / "ash.yaml", DENIED)))

    config = resolve_config(source_dir=_server["plain"])

    assert config.fail_on_findings is False


def test_a_delivered_link_named_with_config_is_confined_as_the_clients(
    _server,
) -> None:
    """The files confinement applies to include the file a delivered link reaches.

    Called directly: through ``resolve_config`` a client's widening is refused
    before confinement runs, so confinement's own judgment is not observable
    there.
    """
    from automated_security_helper.config.config_sources import (
        resolve_config_document,
    )
    from automated_security_helper.config.resolve_config import _not_the_operators

    document = resolve_config_document(_delivered_link(_server, "project_name: g\n"))

    confined = _not_the_operators(document.chain, [], document.names)

    assert confined == [(_server["host"] / "ash.yaml").resolve()]


# ---------------------------------------------------------------------------
# The trusted config, and the policy it supplies
# ---------------------------------------------------------------------------


def test_a_delivered_link_as_the_trusted_config_supplies_no_policy(_server) -> None:
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    trusted = _delivered_link(_server, LOOSENED)

    with pytest.raises(ASHConfigFieldDeniedError):
        resolve_config(
            config_path=_delivered_file(_server, DENIED),
            source_dir=_server["plain"],
            trusted_config_path=trusted,
        )


def test_ash_config_naming_a_delivered_link_supplies_no_policy(
    _server, monkeypatch: pytest.MonkeyPatch
) -> None:
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.core.exceptions import ASHConfigFieldDeniedError

    monkeypatch.setenv("ASH_CONFIG", str(_delivered_link(_server, LOOSENED)))

    with pytest.raises(ASHConfigFieldDeniedError):
        resolve_config(
            config_path=_delivered_file(_server, DENIED), source_dir=_server["plain"]
        )


@pytest.mark.parametrize("route", ["trusted_config_path", "ASH_CONFIG"])
def test_positive_control_the_host_profile_itself_supplies_the_policy(
    _server, monkeypatch: pytest.MonkeyPatch, route: str
) -> None:
    """The same profile, named where it is, loosens the policy; so the tests above can fail."""
    from automated_security_helper.config.resolve_config import resolve_config

    profile = write(_server["host"] / "ash.yaml", LOOSENED)
    kwargs = {}
    if route == "ASH_CONFIG":
        monkeypatch.setenv("ASH_CONFIG", str(profile))
    else:
        kwargs["trusted_config_path"] = profile

    config = resolve_config(
        config_path=_delivered_file(_server, DENIED),
        source_dir=_server["plain"],
        **kwargs,
    )

    assert config.fail_on_findings is False
