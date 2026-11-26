# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``detect_engine_socket``: the engine a scan delegates to, and how to reach it.

Both halves of the answer drive what a scan does. The engine picks the
scanners' image source (``docker:``, ``podman:``, ``registry:``), and the
socket says whether the daemon is LOCAL or only declared: a declared remote
daemon (``tcp://``, ``ssh://``, ``npipe://``, ``fd://`` -- nothing to stat)
makes grype and syft name their sources (``--from``) instead of a scheme, makes
the digest resolver stop rather than ask a registry in the daemon's place, and
makes trivy skip a layer join it could not trust. ``detect_container_engine``
is the engine half alone and has its own rows; these pin the pair.

Every row passes its own environment mapping and points the platform default
sockets into its own tmp tree, so no answer depends on the suite's host. The
classes that bind a real AF_UNIX socket are integration (a test that opens a
socket is, tests/NAMING_CONVENTIONS.md) and are skipped where CPython has none
(Windows); every bind uses a relative name from inside the socket's directory,
because an AF_UNIX path holds about 100 bytes and a deep basetemp makes a full
path too long for the bind. The rows that bind nothing are unit.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path

import pytest

import automated_security_helper.core.container_engine as engine_module
from automated_security_helper.core.container_engine import (
    ContainerEngine,
    detect_container_engine,
    detect_engine_socket,
)

needs_af_unix = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="binding a unix socket needs AF_UNIX, which this platform lacks",
)


@pytest.fixture
def defaults(monkeypatch, tmp_path):
    """The two platform default sockets, moved into this test's own tree."""
    root = tmp_path / "defaults"
    root.mkdir()
    docker = root / "docker.sock"
    podman = root / "podman.sock"
    monkeypatch.setattr(engine_module, "DOCKER_DEFAULT_SOCKET", str(docker))
    monkeypatch.setattr(engine_module, "PODMAN_SYSTEM_SOCKET", str(podman))
    return {"docker": docker, "podman": podman}


@pytest.fixture
def bound():
    """Bind a unix socket at a path, by a relative name; closed at teardown."""
    servers = []
    here = os.getcwd()

    def bind(path: Path) -> str:
        path.parent.mkdir(parents=True, exist_ok=True)
        server = socket.socket(socket.AF_UNIX)
        servers.append(server)
        os.chdir(path.parent)
        try:
            server.bind(path.name)
        finally:
            os.chdir(here)
        return str(path)

    yield bind
    for server in servers:
        server.close()


def _both(environment):
    """The pair, checked against the engine-only reading of the same mapping."""
    answer = detect_engine_socket(environment)
    assert detect_container_engine(environment) == answer[0]
    return answer


@pytest.mark.unit
class TestNothingDeclaredNothingFound:
    def test_no_variable_and_no_socket_is_none(self, defaults):
        assert _both({}) == (ContainerEngine.NONE, None)

    def test_an_empty_declaration_is_no_declaration(self, defaults):
        assert _both({"DOCKER_HOST": "", "CONTAINER_HOST": "  "}) == (
            ContainerEngine.NONE,
            None,
        )

    def test_a_regular_file_is_not_a_socket(self, defaults, tmp_path):
        plain = tmp_path / "not-a-socket"
        plain.write_text("", encoding="utf-8")
        assert _both({"DOCKER_HOST": f"unix://{plain}"}) == (ContainerEngine.NONE, None)
        assert _both({"CONTAINER_HOST": f"unix://{plain}"}) == (
            ContainerEngine.NONE,
            None,
        )

    @pytest.mark.skipif(
        os.name == "nt",
        reason="a bare path is read as a socket path only when it starts with '/', "
        "which a Windows drive path does not",
    )
    def test_a_bare_path_to_a_regular_file_is_not_a_socket(self, defaults, tmp_path):
        plain = tmp_path / "not-a-socket"
        plain.write_text("", encoding="utf-8")
        assert _both({"DOCKER_HOST": str(plain)}) == (ContainerEngine.NONE, None)
        assert _both({"CONTAINER_HOST": str(plain)}) == (ContainerEngine.NONE, None)


@pytest.mark.unit
class TestADeclaredRemoteDaemonHasNoSocket:
    @pytest.mark.parametrize(
        "value",
        [
            "tcp://docker:2375",
            "tcp://127.0.0.1:2376",
            "ssh://build@ci-daemon",
            "npipe:////./pipe/docker_engine",
            "fd://",
        ],
    )
    def test_a_remote_docker_host_is_docker_and_no_socket(self, defaults, value):
        # Declared, not stat'able: the engine counts, and there is no local
        # socket to hand the digest resolver or to read as "local".
        assert _both({"DOCKER_HOST": value}) == (ContainerEngine.DOCKER, None)

    def test_a_remote_container_host_is_podman_and_no_socket(self, defaults):
        assert _both(
            {"CONTAINER_HOST": "ssh://core@localhost:2222/run/user/1000/podman.sock"}
        ) == (ContainerEngine.PODMAN, None)

    def test_a_remote_docker_host_comes_before_a_container_host(self, defaults):
        assert _both(
            {
                "DOCKER_HOST": "tcp://docker:2375",
                "CONTAINER_HOST": "ssh://core@localhost:2222/run/podman.sock",
            }
        ) == (ContainerEngine.DOCKER, None)


@pytest.mark.unit
class TestTheEnvironmentItReads:
    def test_a_given_mapping_is_read_instead_of_the_process_environment(
        self, defaults, monkeypatch
    ):
        monkeypatch.setenv("DOCKER_HOST", "tcp://docker:2375")
        assert _both({}) == (ContainerEngine.NONE, None)

    def test_no_mapping_reads_the_process_environment(self, defaults, monkeypatch):
        monkeypatch.delenv("CONTAINER_HOST", raising=False)
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        monkeypatch.setenv("DOCKER_HOST", "tcp://docker:2375")
        assert _both(None) == (ContainerEngine.DOCKER, None)


@pytest.mark.integration
@needs_af_unix
class TestALocalDockerDaemon:
    def test_the_default_socket_is_docker_with_its_path(self, defaults, bound):
        path = bound(defaults["docker"])
        assert _both({}) == (ContainerEngine.DOCKER, path)

    def test_a_unix_docker_host_is_docker_with_its_path(
        self, defaults, bound, tmp_path
    ):
        path = bound(tmp_path / "run" / "d.sock")
        assert _both({"DOCKER_HOST": f"unix://{path}"}) == (
            ContainerEngine.DOCKER,
            path,
        )

    def test_a_bare_path_docker_host_is_docker_with_its_path(
        self, defaults, bound, tmp_path
    ):
        path = bound(tmp_path / "run" / "d.sock")
        assert _both({"DOCKER_HOST": path}) == (ContainerEngine.DOCKER, path)

    def test_the_declaration_is_read_without_its_padding(
        self, defaults, bound, tmp_path
    ):
        path = bound(tmp_path / "run" / "d.sock")
        assert _both({"DOCKER_HOST": f"  unix://{path}  "}) == (
            ContainerEngine.DOCKER,
            path,
        )

    def test_docker_is_found_before_podman(self, defaults, bound, tmp_path):
        docker = bound(defaults["docker"])
        bound(tmp_path / "xdg" / "podman" / "podman.sock")
        assert _both({"XDG_RUNTIME_DIR": str(tmp_path / "xdg")}) == (
            ContainerEngine.DOCKER,
            docker,
        )

    def test_a_remote_docker_host_wins_over_a_live_default_socket(
        self, defaults, bound
    ):
        # The declaration names the daemon the tools will use; a socket that
        # happens to exist at the default path is not that daemon.
        bound(defaults["docker"])
        assert _both({"DOCKER_HOST": "tcp://docker:2375"}) == (
            ContainerEngine.DOCKER,
            None,
        )


@pytest.mark.integration
@needs_af_unix
class TestADeadDeclarationIsNotAnEngine:
    def test_a_dead_docker_host_does_not_fall_back_to_the_default_socket(
        self, defaults, bound, tmp_path
    ):
        # A leftover variable naming a removed socket stops the docker probe:
        # the default socket is another daemon than the one declared.
        bound(defaults["docker"])
        gone = tmp_path / "gone.sock"
        assert _both({"DOCKER_HOST": f"unix://{gone}"}) == (ContainerEngine.NONE, None)

    def test_a_dead_docker_host_still_lets_podman_be_found(
        self, defaults, bound, tmp_path
    ):
        user = bound(tmp_path / "xdg" / "podman" / "podman.sock")
        gone = tmp_path / "gone.sock"
        assert _both(
            {"DOCKER_HOST": f"unix://{gone}", "XDG_RUNTIME_DIR": str(tmp_path / "xdg")}
        ) == (ContainerEngine.PODMAN, user)

    def test_a_dead_container_host_stops_the_podman_probe(
        self, defaults, bound, tmp_path
    ):
        # Falling through to podman's default sockets would inspect a store
        # (possibly root's) other than the one CONTAINER_HOST names.
        bound(tmp_path / "xdg" / "podman" / "podman.sock")
        bound(defaults["podman"])
        gone = tmp_path / "gone.sock"
        assert _both(
            {
                "CONTAINER_HOST": f"unix://{gone}",
                "XDG_RUNTIME_DIR": str(tmp_path / "xdg"),
            }
        ) == (ContainerEngine.NONE, None)


@pytest.mark.integration
@needs_af_unix
class TestALocalPodman:
    def test_a_unix_container_host_is_podman_with_its_path(
        self, defaults, bound, tmp_path
    ):
        path = bound(tmp_path / "run" / "p.sock")
        assert _both({"CONTAINER_HOST": f"unix://{path}"}) == (
            ContainerEngine.PODMAN,
            path,
        )

    def test_the_runtime_socket_is_podman_with_its_path(
        self, defaults, bound, tmp_path
    ):
        user = bound(tmp_path / "xdg" / "podman" / "podman.sock")
        assert _both({"XDG_RUNTIME_DIR": str(tmp_path / "xdg")}) == (
            ContainerEngine.PODMAN,
            user,
        )

    def test_the_system_socket_is_podman_with_its_path(self, defaults, bound):
        system = bound(defaults["podman"])
        assert _both({}) == (ContainerEngine.PODMAN, system)

    def test_the_runtime_socket_comes_before_the_system_one(
        self, defaults, bound, tmp_path
    ):
        user = bound(tmp_path / "xdg" / "podman" / "podman.sock")
        bound(defaults["podman"])
        assert _both({"XDG_RUNTIME_DIR": str(tmp_path / "xdg")}) == (
            ContainerEngine.PODMAN,
            user,
        )
