# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Which container engine can prepare an image for the scanners: none, today.

ASH builds no resource-fetcher layer. Fetching, caching and preparing image
bytes belong to a container engine (the docker daemon, podman) or to the
scanner tools' own registry clients; ASH passes locators and detects
availability, and never stores, pulls, exports or unpacks an image itself. One
engine present means one pull serves every scanner -- the engine's content
store is the fanout dedup -- which is why detection exists at all.

This module is the unit-A stub of that detection: it answers
:data:`ContainerEngine.NONE` without probing anything, so every consumer is
written against the real vocabulary while no socket is touched. The probe
order, when wiring lands with the first image-capable scanner, is: the docker
daemon (``DOCKER_HOST`` if set, else the platform's default socket), then
podman (``podman.sock`` under ``XDG_RUNTIME_DIR`` or the system path), then
none -- one cheap socket probe at scan start, recorded in the scan metadata.
containerd is reached only through a tool's own ``--image-src containerd`` and
is never probed by ASH.
"""

from __future__ import annotations

from enum import Enum


class ContainerEngine(str, Enum):
    """The engines ASH can delegate image preparation to."""

    DOCKER = "docker"
    PODMAN = "podman"
    NONE = "none"


def detect_container_engine() -> ContainerEngine:
    """The engine available to this scan: always ``NONE`` in this phase.

    No probe is made. With no image-capable scanner wired yet, an answer other
    than NONE could change nothing a scan does, so the stub keeps the one
    truthful answer until the probe has a consumer.
    """
    return ContainerEngine.NONE
