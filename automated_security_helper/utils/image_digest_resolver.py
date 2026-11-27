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
   A Python with no unix sockets (Windows' CPython has no ``socket.AF_UNIX``)
   cannot open an engine's socket, so there the rung answers nothing, with that
   reason, and the ladder goes on.
2. **The registry.** ``crane digest`` (the pinned ``crane`` of
   ``utils/tool_downloads``) reads the manifest's digest from the registry. It
   is a registry read, so it is network use: offline mode never makes it,
   grype and trivy -- the image scanners whose FINDING ids the digest keys --
   declare the fetch in their operational-facets rows
   (``Fetched.IMAGE_DIGEST``; syft reports no findings, so it declares none),
   and the scan phase runs the ladder only when a selected scanner declaring
   it will run (``utils/scanner_tool_types.an_image_digest_consumer_is_selected``).

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
from typing import Any, Callable, Optional, Tuple
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
    names no digest are both "answered nothing" with the reason, and so is a
    Python that has no unix sockets at all.
    """
    if not hasattr(socket, "AF_UNIX"):
        # Windows' CPython has no socket.AF_UNIX: no engine socket can be opened,
        # and the rung answers nothing rather than raising AttributeError.
        return None, "the engine could not be asked (this Python has no unix sockets)"
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


#: The most of a payload's index or manifest record that is read: both are a
#: few hundred bytes of JSON naming blobs; a bigger one is refused unread.
_MAX_PAYLOAD_RECORD_BYTES = 1024 * 1024


def _single_index_digest(document: object) -> Tuple[Optional[str], str]:
    """The one manifest digest an OCI index names, or why there is not one."""
    manifests = document.get("manifests") if isinstance(document, dict) else None
    if not isinstance(manifests, list):
        return None, "its index names no manifests"
    digests = []
    for entry in manifests:
        digest = entry.get("digest") if isinstance(entry, dict) else None
        if isinstance(digest, str) and _DIGEST.fullmatch(digest):
            digests.append(digest)
    if len(digests) == 1:
        return digests[0], ""
    if not digests:
        return None, "its index names no sha256 manifest digest"
    return (
        None,
        (
            f"its index names {len(digests)} manifests, and which one the "
            "scan is about is not said"
        ),
    )


def _single_config_digest(document: object) -> Tuple[Optional[str], str]:
    """The one config digest a docker-archive manifest names, or why not."""
    if not isinstance(document, list):
        return None, "its manifest.json is not a list of image records"
    if len(document) != 1:
        return (
            None,
            (
                f"its manifest.json records {len(document)} images, and "
                "which one the scan is about is not said"
            ),
        )
    entry = document[0]
    config = entry.get("Config") if isinstance(entry, dict) else None
    if not isinstance(config, str):
        return None, "its manifest.json names no config blob"
    # "blobs/sha256/<hex>" (recent docker) or "<hex>.json" (older saves).
    stem = config.rsplit("/", 1)[-1].removesuffix(".json")
    if re.fullmatch(r"[0-9a-f]{64}", stem):
        return f"sha256:{stem}", ""
    return None, "its manifest.json's config entry names no sha256 digest"


def payload_digest(image: ImageLocator) -> Tuple[Optional[str], str]:
    """The content digest a direct payload names, read from the payload itself.

    A payload scan used to key its finding ids and its scan scope on the
    payload's PATH, so the same bytes uploaded twice (the MCP channel writes
    each upload under a new id) were two subjects, and only the runs that
    record a digest themselves (trivy's ``imageID``) keyed on content --
    splitting one image's ids between trivy rows and everyone else's. The
    payload names its own digest:

    - an OCI image layout's ``index.json`` (and an ``oci-archive`` tar's)
      names its one manifest's digest -- the MANIFEST digest, the value a
      pinned reference states;
    - a ``docker save`` tarball's ``manifest.json`` names the config blob,
      whose name is the CONFIG digest -- the same value as the tools'
      ``imageID``, the honest key for a never-pushed local build, which has
      no manifest digest anywhere.

    Only the record file is read (one bounded member read; no layer), and an
    index that names several manifests answers nothing with the reason: which
    of them the scan is about is not this module's guess to make.

    The payload is a client's file, so what its record holds is not this
    module's to choose. A member that is not a regular file is skipped, never
    read: the archive reader would follow a link to another member, and raises
    on one the archive lacks. A record that cannot be read or parsed (JSON
    nested past the parser's recursion limit included) answers nothing, with a
    reason that names it. Nothing the payload holds raises out of this
    function: a payload that names no digest is keyed on its path, and a
    resolution failure never fails or skips the scan.
    """
    import tarfile
    from pathlib import Path

    if image.oci_layout is not None:
        index = Path(image.oci_layout) / "index.json"
        try:
            # Sized: an index is a few hundred bytes; read(cap + 1) so a
            # bigger file is seen as over the cap rather than truncated.
            with open(index, "rb") as index_handle:
                body = index_handle.read(_MAX_PAYLOAD_RECORD_BYTES + 1)
            if len(body) > _MAX_PAYLOAD_RECORD_BYTES:
                return None, "its index.json is too large to be an image index"
            return _single_index_digest(json.loads(body))
        except Exception as error:  # noqa: BLE001 - a bad index is no digest
            return None, f"its index.json could not be read ({type(error).__name__})"
    if image.oci_archive is None:
        return None, "not a direct payload"
    not_regular: list[str] = []
    try:
        with tarfile.open(image.oci_archive, "r:") as saved:
            records: dict[str, Any] = {}
            for member in saved:
                name = member.name.lstrip("./")
                if name not in ("manifest.json", "index.json"):
                    continue
                if not member.isreg():
                    # A record is a plain file: extractfile would follow a link
                    # to another member, and raises on one the archive lacks.
                    not_regular.append(name)
                    continue
                if member.size > _MAX_PAYLOAD_RECORD_BYTES:
                    return None, f"its {name} is too large to be an image record"
                try:
                    handle = saved.extractfile(member)
                    if handle is None:
                        continue
                    with handle:
                        records[name] = json.loads(
                            handle.read(_MAX_PAYLOAD_RECORD_BYTES + 1)
                        )
                except Exception as error:  # noqa: BLE001 - a bad record is no digest
                    kind = type(error).__name__
                    return None, f"its {name} could not be read ({kind})"
                # manifest.json decides (a recent docker save writes BOTH, and
                # is read as a docker archive, exactly as archive_scheme
                # routes it); nothing later in the tar changes that.
                if name == "manifest.json":
                    break
    except Exception as error:  # noqa: BLE001 - a bad archive is no digest
        return None, f"the archive could not be read ({type(error).__name__})"
    if "manifest.json" in records:
        return _single_config_digest(records["manifest.json"])
    if "index.json" in records:
        return _single_index_digest(records["index.json"])
    if not_regular:
        return None, f"its {not_regular[0]} is not a regular file"
    return None, "the archive holds no manifest.json or index.json"


def _engine_inspector() -> "Optional[tuple[str, Optional[Inspector]]]":
    """The detected engine's name and an inspector bound to its socket.

    None when no engine is declared or found. ``(name, None)`` for an engine
    that is DECLARED with no local socket to ask (a ``tcp://`` or ``ssh://``
    ``DOCKER_HOST``, a remote ``CONTAINER_HOST``): the caller must know the
    difference, because the scanners read the image through that daemon, and
    a digest resolved from anywhere else could name other bytes than the ones
    scanned.
    """
    from automated_security_helper.core.container_engine import (
        ContainerEngine,
        detect_engine_socket,
    )

    engine, socket_path = detect_engine_socket()
    if engine == ContainerEngine.NONE:
        return None
    if socket_path is None:
        return engine.value, None
    return engine.value, lambda ref: inspect_digest(ref, socket_path)


def resolve_image_locator(
    image: ImageLocator,
    *,
    offline: bool,
    runner: Optional[Runner] = None,
    crane: Optional[str] = None,
    inspector: "Optional[tuple[str, Optional[Inspector]]]" = None,
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

    A direct payload takes its own one rung, :func:`payload_digest` (the
    digest the payload itself names; no engine, no network), and never falls
    through to the reference rungs.
    """
    if image.resolved_digest is not None:
        return image
    if image.ref is None:
        if image.oci_archive is None and image.oci_layout is None:
            return image
        digest, why = payload_digest(image)
        if digest is not None:
            ASH_LOGGER.info(
                f"Read the digest of {image.shown()} from the payload itself: {digest}."
            )
            return image.model_copy(
                update={"resolved_digest": digest, "resolved_from": "payload"}
            )
        ASH_LOGGER.info(
            f"{image.shown()} names no single digest ({why}); its finding ids "
            "key on the payload path."
        )
        return image
    if _pinned_by_digest(image.ref):
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

    def resolved(digest: str, rung: str, source: str) -> ImageLocator:
        ASH_LOGGER.info(f"Resolved {ref} to {digest} through {rung}.")
        return image.model_copy(
            update={"resolved_digest": digest, "resolved_from": source}
        )

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
        if inspect is None:
            # The engine is declared (tcp:// or ssh:// DOCKER_HOST, a remote
            # CONTAINER_HOST) with no local socket to ask. The SCANNERS read
            # the image through that daemon, so a digest from the registry
            # could pin bytes the daemon never built -- the docker-in-docker
            # CI job that scans a fresh local build under a tag the registry
            # still holds an older image for would key, and pull, the OLD
            # image. No rung can answer for the daemon's copy, so the ladder
            # stops here and the ids key on the reference text.
            reasons.append(
                f"the declared {name} daemon has no local socket to ask, and "
                "the registry is not asked in its place: the scanners read "
                "that daemon's copy of the image, which a registry digest "
                "could misname"
            )
            return fall_back()
        try:
            digest, why = inspect(ref)
        except Exception as error:  # noqa: BLE001 - a rung failing falls to the next
            digest, why = (
                None,
                f"the engine could not be asked ({type(error).__name__})",
            )
        if digest is not None:
            return resolved(digest, f"the local {name} engine", "engine")
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
    return resolved(digest, "the registry (crane digest)", "registry")
