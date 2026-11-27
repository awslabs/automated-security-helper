# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which container engine can prepare an image for the scanners.

ASH builds no resource-fetcher layer. Fetching, caching and preparing image
bytes belong to a container engine (the docker daemon, podman) or to the
scanner tools' own registry clients; ASH passes locators and detects
availability, and never stores, pulls, exports or unpacks an image itself. One
engine present means one pull serves every scanner -- the engine's content
store is the fanout dedup -- which is why detection exists at all.

The probe order: the docker daemon (``DOCKER_HOST`` if set, of any transport,
else the platform's default socket), then podman (``CONTAINER_HOST`` if set,
then ``podman.sock`` under ``XDG_RUNTIME_DIR``, then the system path), then
none. One cheap stat per local candidate, no connection and no request: a
declared remote daemon (``tcp://``, ``ssh://``, ``npipe://``) counts as
declared, a local socket counts when it exists and is a socket, and a dead
daemon behind either is the tool's own error to report, exactly as a registry
that refuses a pull is. containerd is reached only through a tool's own
``--image-src containerd`` and is never probed by ASH.
"""

from __future__ import annotations

import os
import stat
from enum import Enum
from typing import Mapping, Optional, Tuple

from automated_security_helper.utils.process_env import snapshot_environ


class ContainerEngine(str, Enum):
    """The engines ASH can delegate image preparation to."""

    DOCKER = "docker"
    PODMAN = "podman"
    NONE = "none"


#: The platform default sockets, module-level so a test can point them into
#: its own tmp tree: the suite must never read the host's real daemon state.
DOCKER_DEFAULT_SOCKET = "/var/run/docker.sock"
PODMAN_SYSTEM_SOCKET = "/run/podman/podman.sock"


def _is_unix_socket(path: str) -> bool:
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except (OSError, ValueError):
        return False


def _docker_host_socket(value: str) -> Optional[str]:
    """The socket path a ``DOCKER_HOST`` names, or None for another transport."""
    if value.startswith("unix://"):
        return value[len("unix://") :]
    if value.startswith("/"):
        return value
    return None


def detect_engine_socket(
    environment: Optional[Mapping[str, str]] = None,
) -> Tuple[ContainerEngine, Optional[str]]:
    """The engine available to this scan and the unix socket that reaches it.

    A declared host wins before any stat. ``DOCKER_HOST`` (and podman's
    ``CONTAINER_HOST``) of any transport counts as its engine: a GitLab
    docker-in-docker ``tcp://docker:2375``, an ``ssh://`` or Windows
    ``npipe://`` daemon cannot be stat'ed, and probing one with a connection is
    a network action detection never takes -- the operator declared the daemon,
    and a dead one behind the declaration is the tool's own error to report,
    exactly as a registry that refuses a pull is. Such a daemon has no LOCAL
    socket, so the answer is ``(<engine>, None)`` and a caller that needs the
    socket (the digest resolver's engine rung) goes without it. A declared
    ``unix://`` or bare path is still stat'ed, so a leftover variable naming a
    removed socket does not read as an engine. Docker CONTEXTS (Colima,
    OrbStack, Docker Desktop without the default socket) are not read: a
    context lives in ``~/.docker``'s config, which detection does not open;
    set ``DOCKER_HOST`` to make such a daemon count.

    ``(ContainerEngine.NONE, None)`` when nothing is declared and no candidate
    is a socket. *environment* defaults to ``os.environ``; tests pass their own
    mapping so no probe ever depends on the suite's host.
    """
    env = snapshot_environ() if environment is None else environment

    docker_host = env.get("DOCKER_HOST", "").strip()
    if docker_host:
        socket_path = _docker_host_socket(docker_host)
        if socket_path is None:
            # tcp://, ssh://, npipe://, fd://: a declared non-local daemon.
            return ContainerEngine.DOCKER, None
        if _is_unix_socket(socket_path):
            return ContainerEngine.DOCKER, socket_path
    elif _is_unix_socket(DOCKER_DEFAULT_SOCKET):
        return ContainerEngine.DOCKER, DOCKER_DEFAULT_SOCKET

    container_host = env.get("CONTAINER_HOST", "").strip()
    if container_host:
        socket_path = _docker_host_socket(container_host)
        if socket_path is None:
            return ContainerEngine.PODMAN, None
        if _is_unix_socket(socket_path):
            return ContainerEngine.PODMAN, socket_path
        # Declared but dead: stop, exactly as a dead DOCKER_HOST never probes
        # the default docker socket. Falling through to podman's default
        # sockets would have ASH inspect a store (possibly root's) other than
        # the one tools that honor CONTAINER_HOST will use.
        return ContainerEngine.NONE, None

    runtime_dir = env.get("XDG_RUNTIME_DIR", "").strip()
    if runtime_dir:
        user_socket = os.path.join(runtime_dir, "podman", "podman.sock")
        if _is_unix_socket(user_socket):
            return ContainerEngine.PODMAN, user_socket
    if _is_unix_socket(PODMAN_SYSTEM_SOCKET):
        return ContainerEngine.PODMAN, PODMAN_SYSTEM_SOCKET

    return ContainerEngine.NONE, None


def detect_container_engine(
    environment: Optional[Mapping[str, str]] = None,
) -> ContainerEngine:
    """The engine available to this scan: docker, podman, or none.

    *environment* defaults to ``os.environ``; tests pass their own mapping so
    no probe ever depends on the suite's host.
    """
    return detect_engine_socket(environment)[0]
