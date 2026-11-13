# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A pinned-tool install downloads nothing while ASH is offline.

``ash scan --offline`` and ``ASH_OFFLINE`` mean ASH reaches no network. A pinned
binary (grype, syft, opengrep, ...) that is not installed and has no verified copy
present is refused then, with the reason, instead of fetched from its release URL;
an installed or present verified copy is used as at any other time.

Every outbound connection in the process is recorded and refused, so nothing leaves
in either case. The online cell is the control: without offline mode the same call
does try to connect, so the recorder sees a connection when one is made.
"""

from __future__ import annotations

import socket

import pytest

from automated_security_helper.core.exceptions import ToolNotProvisionableError


@pytest.fixture
def connections(monkeypatch) -> list:
    """Every connection this process tries, each refused."""
    tried: list = []

    def refuse(self, address, *args, **kwargs):
        tried.append(address)
        raise ConnectionRefusedError("refused by the test")

    monkeypatch.setattr(socket.socket, "connect", refuse)
    monkeypatch.setattr(socket.socket, "connect_ex", refuse)
    monkeypatch.setenv("ASH_DOWNLOAD_MAX_ATTEMPTS", "1")
    monkeypatch.setenv("ASH_DOWNLOAD_RETRY_DELAY", "0")
    # No release-asset cache, so a verified cached copy cannot stand in for the download.
    monkeypatch.delenv("ASH_TOOL_DOWNLOAD_CACHE", raising=False)
    return tried


@pytest.mark.unit
@pytest.mark.parametrize("value", ["YES", "true", "1"])
def test_offline_a_missing_pinned_tool_is_refused_without_a_connection(
    connections, monkeypatch, tmp_path, value
):
    from automated_security_helper.utils import download_utils

    monkeypatch.setenv("ASH_OFFLINE", value)

    with pytest.raises(ToolNotProvisionableError, match="offline"):
        download_utils.install_pinned_tool("grype", "linux", "amd64", tmp_path / "bin")

    assert connections == []
    assert not any((tmp_path / "bin").glob("grype*"))


@pytest.mark.unit
def test_offline_a_url_install_is_refused_without_a_connection(
    connections, monkeypatch, tmp_path
):
    """The configured-version opengrep download (install_binary_from_url), offline."""
    from automated_security_helper.utils import download_utils

    monkeypatch.setenv("ASH_OFFLINE", "YES")

    with pytest.raises(ToolNotProvisionableError, match="offline"):
        download_utils.install_binary_from_url(
            "https://example.invalid/tool", tmp_path / "bin", expected_sha256="0" * 64
        )

    assert connections == []
    assert not (tmp_path / "bin" / "tool").exists()


@pytest.mark.integration
def test_online_the_same_install_tries_to_connect(connections, monkeypatch, tmp_path):
    """The control: the recorder sees the download a non-offline install starts."""
    from automated_security_helper.utils import download_utils

    monkeypatch.delenv("ASH_OFFLINE", raising=False)

    with pytest.raises(Exception):
        download_utils.install_pinned_tool("grype", "linux", "amd64", tmp_path / "bin")

    assert connections != []
