# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which container engine can prepare an image for the scanners.

ASH builds no resource-fetcher layer. Fetching, caching and preparing image
bytes belong to a container engine (the docker daemon, podman) or to the
scanner tools' own registry clients; ASH passes locators and detects
availability, and never stores, pulls, exports or unpacks an image itself. One
engine present means one pull serves every scanner -- the engine's content
store is the fanout dedup -- which is why detection exists at all.

The probe order: the docker daemon (``DOCKER_HOST`` if set, else the
platform's default socket), then podman (``podman.sock`` under
``XDG_RUNTIME_DIR``, then the system path), then none. One cheap stat per
candidate, no connection and no request: a socket that exists and is a socket
is an engine the tools can be pointed at, and a dead daemon behind it is the
tool's own error to report, exactly as a registry that refuses a pull is.
containerd is reached only through a tool's own ``--image-src containerd``
and is never probed by ASH.
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
    """The socket path a ``DOCKER_HOST`` names, or None for another transport.

    Only ``unix://`` values are probed: a tcp daemon's reachability cannot be
    read from a stat, and probing it with a connection is a network action
    detection deliberately never takes. A tcp ``DOCKER_HOST`` still reaches
    the tools through their own environment; it is only ASH's engine ANSWER
    that stays conservative about it.
    """
    if value.startswith("unix://"):
        return value[len("unix://") :]
    if value.startswith("/"):
        return value
    return None


def detect_engine_socket(
    environment: Optional[Mapping[str, str]] = None,
) -> Tuple[ContainerEngine, Optional[str]]:
    """The engine available to this scan and the unix socket that reaches it.

    ``(ContainerEngine.NONE, None)`` when no candidate is a socket. The probe is
    the one stat per candidate described in the module docstring.
    """
    env = snapshot_environ() if environment is None else environment

    docker_host = env.get("DOCKER_HOST", "").strip()
    if docker_host:
        socket_path = _docker_host_socket(docker_host)
        if socket_path is not None and _is_unix_socket(socket_path):
            return ContainerEngine.DOCKER, socket_path
    elif _is_unix_socket(DOCKER_DEFAULT_SOCKET):
        return ContainerEngine.DOCKER, DOCKER_DEFAULT_SOCKET

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
