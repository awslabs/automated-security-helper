# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Resolving a tag-only image reference to its digest: a ladder of two rungs.

A scan keys an image finding's id on the image's sha256 digest when it has one
and on the submitted reference text otherwise (``utils/image_attribution``). A
tag-only reference (``registry.example.com/app:1.2``) carries no digest, and
grype and syft report none, so its ids changed whenever the reference did and
moved with the tag. This module finds the digest the tag points at and records
it on the locator as ``resolved_digest`` so the ids key on it. The rungs, in
order, and the first that answers wins:

1. **The local engine.** With a docker or podman daemon present (the engine
   detection of ``core/container_engine``), ask it about the image over its
   socket (``GET /images/<ref>/json``, the API both speak): the registry digest
   in ``RepoDigests`` that belongs to the reference's repository, else the
   image's own ``Id``. It needs no network, so it works offline, and no layer
   is read. An image the daemon does not hold answers 404 and the ladder goes on.
2. **The registry.** ``crane digest`` (the pinned ``crane`` of
   ``utils/tool_downloads``) reads the manifest's digest from the registry. It
   is a registry read, so it is network use: offline mode never makes it, and
   the three scanners that read images declare the fetch in their
   operational-facets rows (``Fetched.IMAGE_DIGEST``).

Which rung answered is logged once, at INFO. When EVERY rung fails the locator
is returned unchanged, the ids key on the reference text exactly as they did
before the ladder existed, and ONE warning names the fallback and why each rung
failed. A resolution failure never fails or skips the scan.

Nothing here pulls an image: the engine is asked about what it holds, and
``crane digest`` reads one manifest digest and no layer.

The two rungs can name different digests for one image (the engine's ``Id`` is
the image config's digest, a registry digest names the manifest), so a tag
resolved offline by rung 1 may key its ids differently from the same tag
resolved by rung 2 online. A pinned reference (``repo@sha256:...``) needs no
ladder and keys the same everywhere.
"""

from __future__ import annotations

import http.client
import json
import re
import socket
from typing import Callable, Optional, Tuple
from urllib.parse import quote

from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.utils.log import ASH_LOGGER

#: The seconds ``crane digest`` may take: a registry round trip, not a transfer.
RESOLVE_TIMEOUT_SECONDS = 60

#: The seconds the engine may take to answer an inspect: a local socket read.
ENGINE_TIMEOUT_SECONDS = 10

#: The most an engine's inspect answer may hold before it is refused.
_MAX_INSPECT_BYTES = 8 * 1024 * 1024

#: What ``crane digest`` prints: ``sha256:`` and 64 hex digits, one line.
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")

#: ``Runner(argv, timeout)`` returns ``(exit_code, stdout)``; tests pass a fake
#: so no suite run reads a registry.
Runner = Callable[[list[str], float], "tuple[int, str]"]

#: ``Inspector(ref)`` returns ``(digest or None, why it answered nothing)``;
#: tests pass a fake so no suite run asks an engine.
Inspector = Callable[[str], "Tuple[Optional[str], str]"]

#: Registry hosts a Docker Hub image is also named by, dropped before two
#: repository names are compared.
_HUB_PREFIXES = ("docker.io/", "index.docker.io/", "registry-1.docker.io/")


def _pinned_by_digest(ref: str) -> bool:
    """Whether *ref* already states its digest (``repo@sha256:...``)."""
    return _DIGEST.fullmatch(ref.rsplit("@", 1)[-1]) is not None


def _spawn(argv: list[str], timeout: float) -> "tuple[int, str]":
    from automated_security_helper.utils.subprocess_utils import spawn_run

    completed = spawn_run(
        argv, capture_output=True, text=True, timeout=timeout, check=False
    )
    return completed.returncode, completed.stdout or ""


def _repository(ref: str) -> str:
    """*ref*'s repository name: no tag, no digest, Docker Hub's defaults dropped."""
    name = ref.split("@", 1)[0]
    last = name.rsplit("/", 1)[-1]
    if ":" in last:
        name = name[: len(name) - len(last)] + last.split(":", 1)[0]
    for prefix in _HUB_PREFIXES:
        if name.startswith(prefix):
            name = name[len(prefix) :]
            break
    return name.removeprefix("library/")


class _UnixHTTPConnection(http.client.HTTPConnection):
    """An HTTP connection over a unix socket, as an engine's API is reached."""

    def __init__(self, path: str, timeout: float) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        try:
            sock.connect(self._socket_path)
        except BaseException:
            sock.close()
            raise
        self.sock = sock


def inspect_digest(ref: str, socket_path: str) -> "Tuple[Optional[str], str]":
    """The digest the engine at *socket_path* holds for *ref*, and why not if none.

    The ``RepoDigests`` entry of the reference's own repository (the registry
    manifest digest, what ``crane digest`` would print), else the image's
    ``Id``. A request the engine answers with anything but a 200 and a body that
    names no digest are both "answered nothing" with the reason.
    """
    connection = _UnixHTTPConnection(socket_path, ENGINE_TIMEOUT_SECONDS)
    try:
        # Unversioned: both docker and podman route it to their current API.
        connection.request("GET", f"/images/{quote(ref, safe='/:@')}/json")
        response = connection.getresponse()
        if response.status == 404:
            return None, "the engine does not hold this image"
        if response.status != 200:
            return None, f"the engine answered HTTP {response.status}"
        body = response.read(_MAX_INSPECT_BYTES + 1)
        if len(body) > _MAX_INSPECT_BYTES:
            return None, "the engine's answer was too large"
        document = json.loads(body)
    except (OSError, ValueError, http.client.HTTPException) as error:
        return None, f"the engine could not be asked ({type(error).__name__})"
    finally:
        connection.close()
    if not isinstance(document, dict):
        return None, "the engine's answer was not an image record"
    wanted = _repository(ref)
    for entry in document.get("RepoDigests") or []:
        if not isinstance(entry, str) or "@" not in entry:
            continue
        repo, _, digest = entry.rpartition("@")
        if _repository(repo) == wanted and _DIGEST.fullmatch(digest):
            return digest, ""
    image_id = document.get("Id")
    if isinstance(image_id, str) and _DIGEST.fullmatch(image_id):
        return image_id, ""
    return None, "the engine's record names no digest"


def _engine_inspector() -> "Optional[tuple[str, Inspector]]":
    """The detected engine's name and an inspector bound to its socket, or None."""
    from automated_security_helper.core.container_engine import (
        ContainerEngine,
        detect_engine_socket,
    )

    engine, socket_path = detect_engine_socket()
    if engine == ContainerEngine.NONE or socket_path is None:
        return None
    return engine.value, lambda ref: inspect_digest(ref, socket_path)


def resolve_image_locator(
    image: ImageLocator,
    *,
    offline: bool,
    runner: Optional[Runner] = None,
    crane: Optional[str] = None,
    inspector: "Optional[tuple[str, Inspector]]" = None,
    detect_engine: bool = True,
) -> ImageLocator:
    """*image* with ``resolved_digest`` filled where a rung can say it.

    Returned unchanged (the same object) for a direct payload, a reference
    that is already digest-pinned, and every fallback. The one notice is
    logged here, so a caller never has to count: this is called once per scan.

    *runner*, *crane* and *inspector* (an ``(engine name, inspect function)``
    pair) are injectable for tests; in a scan they default to the
    sandbox-routed spawn, the ``crane`` the pinned-tool install put on the
    search path, and the engine the detection found. ``detect_engine=False``
    leaves the engine rung out when no *inspector* is given.
    """
    if image.ref is None or _pinned_by_digest(image.ref):
        return image
    if image.resolved_digest is not None:
        return image

    ref = image.ref
    reasons: list[str] = []

    def fall_back() -> ImageLocator:
        ASH_LOGGER.warning(
            f"Could not resolve {ref} to a digest ({'; '.join(reasons)}); its "
            "finding ids key on the reference text and change when the reference "
            "does. Pin the reference by digest (repo@sha256:...) for stable ids."
        )
        return image

    def resolved(digest: str, rung: str) -> ImageLocator:
        ASH_LOGGER.info(f"Resolved {ref} to {digest} through {rung}.")
        return image.model_copy(update={"resolved_digest": digest})

    if ref.startswith("-"):
        # Never handed to an engine or to crane as a word that could read as one
        # of their options.
        reasons.append("the reference starts with '-'")
        return fall_back()

    # Rung 1: the local engine, which needs no network.
    if inspector is None and detect_engine:
        inspector = _engine_inspector()
    if inspector is not None:
        name, inspect = inspector
        try:
            digest, why = inspect(ref)
        except Exception as error:  # noqa: BLE001 - a rung failing falls to the next
            digest, why = (
                None,
                f"the engine could not be asked ({type(error).__name__})",
            )
        if digest is not None:
            return resolved(digest, f"the local {name} engine")
        reasons.append(f"the local {name} engine: {why}")

    # Rung 2: the registry.
    if offline:
        reasons.append("offline mode makes no registry request")
        return fall_back()

    if crane is None:
        from automated_security_helper.utils.subprocess_utils import find_executable

        crane = find_executable("crane")
    if crane is None:
        reasons.append(
            "crane is not installed; `ash dependencies install --tool crane` "
            "installs the pinned release"
        )
        return fall_back()

    try:
        # "--" ends the options, so the reference is an operand whatever it holds.
        code, stdout = (runner or _spawn)(
            [crane, "digest", "--", ref], RESOLVE_TIMEOUT_SECONDS
        )
    except Exception as error:  # noqa: BLE001 - every failure ends in the fallback
        reasons.append(f"crane did not run: {type(error).__name__}")
        return fall_back()
    if code != 0:
        reasons.append(f"crane digest exited {code}")
        return fall_back()
    digest = stdout.strip()
    if _DIGEST.fullmatch(digest) is None:
        reasons.append("crane digest printed no sha256 digest")
        return fall_back()
    return resolved(digest, "the registry (crane digest)")
