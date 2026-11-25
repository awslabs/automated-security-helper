# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tag-only reference resolves through a ladder: the local engine, then the registry.

Rung 1 asks a docker or podman daemon over its socket and needs no network, so
it works offline; rung 2 is ``crane digest`` (tests/unit/utils/
test_image_digest_resolver.py holds its rows). The ids key on whichever digest
the first rung to answer gave, the notice names the rung, and the reference
text is the key only when every rung fails. The engine is a fake here: a real
unix-socket HTTP server for the inspect call, a table for the ladder's order.
"""

from __future__ import annotations

import json
import logging
import socket
import tempfile
import threading
from pathlib import Path

import pytest

from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.utils.image_digest_resolver import (
    inspect_digest,
    resolve_image_locator,
)

pytestmark = pytest.mark.unit

MANIFEST = "sha256:" + "ab" * 32
IMAGE_ID = "sha256:" + "cd" * 32
OTHER = "sha256:" + "ef" * 32
REF = "registry.example.com/team/app:1.2.3"
CRANE = "/opt/bin/crane"


class _Logged(logging.Handler):
    def __init__(self) -> None:
        super().__init__(level=1)
        self.records = []

    def emit(self, record) -> None:
        self.records.append(record)

    def text(self, level=None) -> str:
        return "\n".join(
            r.getMessage() for r in self.records if level is None or r.levelno == level
        )


@pytest.fixture
def logged():
    from automated_security_helper.utils.log import ASH_LOGGER

    handler = _Logged()
    before = ASH_LOGGER.level
    ASH_LOGGER.setLevel(1)
    ASH_LOGGER.addHandler(handler)
    try:
        yield handler
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(before)


def _registry(table=None, code=0):
    calls = []

    def run(argv, timeout):
        calls.append(list(argv))
        return code, (table or {}).get(argv[-1], "") + "\n"

    run.calls = calls
    return run


def _engine(answer, name="docker"):
    """An inspector pair answering ``(digest or None, why)`` and recording asks."""
    asked = []

    def inspect(ref):
        asked.append(ref)
        return answer

    inspect.asked = asked
    return name, inspect


class TestTheLadderOrder:
    def test_the_engine_answers_first_and_the_registry_is_not_asked(self, logged):
        registry = _registry({REF: OTHER})
        engine = _engine((MANIFEST, ""))
        resolved = resolve_image_locator(
            ImageLocator(ref=REF),
            offline=False,
            runner=registry,
            crane=CRANE,
            inspector=engine,
        )
        assert resolved.resolved_digest == MANIFEST
        assert engine[1].asked == [REF]
        assert registry.calls == []
        assert "local docker engine" in logged.text(logging.INFO)
        assert "Could not resolve" not in logged.text()

    def test_it_works_offline_where_the_registry_rung_cannot(self, logged):
        registry = _registry({REF: OTHER})
        resolved = resolve_image_locator(
            ImageLocator(ref=REF),
            offline=True,
            runner=registry,
            crane=CRANE,
            inspector=_engine((IMAGE_ID, ""), name="podman"),
        )
        assert resolved.resolved_digest == IMAGE_ID
        assert registry.calls == []
        assert "local podman engine" in logged.text(logging.INFO)

    def test_an_engine_that_does_not_hold_the_image_falls_to_the_registry(self, logged):
        registry = _registry({REF: OTHER})
        resolved = resolve_image_locator(
            ImageLocator(ref=REF),
            offline=False,
            runner=registry,
            crane=CRANE,
            inspector=_engine((None, "the engine does not hold this image")),
        )
        assert resolved.resolved_digest == OTHER
        assert registry.calls == [[CRANE, "digest", "--", REF]]
        assert "registry (crane digest)" in logged.text(logging.INFO)
        assert "Could not resolve" not in logged.text()

    def test_an_engine_that_raises_falls_to_the_registry(self, logged):
        def explode(ref):
            raise RuntimeError("boom")

        resolved = resolve_image_locator(
            ImageLocator(ref=REF),
            offline=False,
            runner=_registry({REF: OTHER}),
            crane=CRANE,
            inspector=("docker", explode),
        )
        assert resolved.resolved_digest == OTHER

    def test_every_rung_failing_keeps_the_reference_text_with_one_notice(self, logged):
        locator = ImageLocator(ref=REF)
        result = resolve_image_locator(
            locator,
            offline=False,
            runner=_registry(code=1),
            crane=CRANE,
            inspector=_engine((None, "the engine does not hold this image")),
        )
        assert result is locator
        warnings = [r for r in logged.records if "Could not resolve" in r.getMessage()]
        assert len(warnings) == 1
        text = warnings[0].getMessage()
        assert "local docker engine: the engine does not hold this image" in text
        assert "crane digest exited 1" in text
        assert "reference text" in text

    def test_offline_with_no_answering_engine_names_both_reasons_once(self, logged):
        locator = ImageLocator(ref=REF)
        result = resolve_image_locator(
            locator,
            offline=True,
            crane=CRANE,
            inspector=_engine((None, "the engine does not hold this image")),
        )
        assert result is locator
        text = logged.text(logging.WARNING)
        assert text.count("Could not resolve") == 1
        assert "offline mode makes no registry request" in text

    def test_no_engine_leaves_the_registry_rungs_notice_as_it_was(self, logged):
        locator = ImageLocator(ref=REF)
        resolve_image_locator(locator, offline=True, crane=CRANE, detect_engine=False)
        assert logged.text(logging.WARNING).startswith(
            f"Could not resolve {REF} to a digest (offline mode makes no registry "
            "request); its finding ids key on the reference text"
        )

    def test_a_pinned_reference_asks_no_rung(self):
        engine = _engine((MANIFEST, ""))
        locator = ImageLocator(ref=f"registry.example.com/team/app@{OTHER}")
        assert (
            resolve_image_locator(
                locator,
                offline=False,
                runner=_registry(),
                crane=CRANE,
                inspector=engine,
            )
            is locator
        )
        assert engine[1].asked == []

    def test_a_payload_asks_no_rung(self, tmp_path):
        engine = _engine((MANIFEST, ""))
        archive = tmp_path / "image.tar"
        archive.write_bytes(b"")
        locator = ImageLocator(oci_archive=archive)
        assert (
            resolve_image_locator(
                locator,
                offline=False,
                runner=_registry(),
                crane=CRANE,
                inspector=engine,
            )
            is locator
        )
        assert engine[1].asked == []

    def test_an_option_shaped_ref_is_never_handed_to_a_rung(self):
        engine = _engine((MANIFEST, ""))
        registry = _registry()
        locator = ImageLocator(ref="--insecure")
        resolve_image_locator(
            locator,
            offline=False,
            runner=registry,
            crane=CRANE,
            inspector=engine,
        )
        assert engine[1].asked == [] and registry.calls == []


class _FakeDaemon:
    """A docker-API-shaped HTTP server on a unix socket, answering one table."""

    def __init__(self, responses):
        self.responses = responses
        self.requests = []
        self._dir = tempfile.mkdtemp(prefix="eng")
        self.path = str(Path(self._dir) / "e.sock")
        self._server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._server.bind(self.path)
        self._server.listen(4)
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while True:
            try:
                conn, _ = self._server.accept()
            except OSError:
                return
            with conn:
                data = b""
                while b"\r\n\r\n" not in data:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                line = data.split(b"\r\n", 1)[0].decode()
                self.requests.append(line)
                status, body = self.responses.get(
                    line.split(" ")[1], (404, b'{"message":"no such image"}')
                )
                conn.sendall(
                    f"HTTP/1.1 {status} X\r\nContent-Type: application/json\r\n"
                    f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                    + body
                )

    def close(self):
        self._server.close()


@pytest.fixture
def daemon():
    made = []

    def make(responses):
        fake = _FakeDaemon(responses)
        made.append(fake)
        return fake

    yield make
    for fake in made:
        fake.close()


def _record(**fields) -> bytes:
    return json.dumps(fields).encode()


class TestInspectOverTheSocket:
    def test_the_repository_digest_of_the_reference_is_the_answer(self, daemon):
        fake = daemon(
            {
                f"/images/{REF}/json": (
                    200,
                    _record(
                        Id=IMAGE_ID,
                        RepoDigests=[
                            f"registry.example.com/other/app@{OTHER}",
                            f"registry.example.com/team/app@{MANIFEST}",
                        ],
                    ),
                )
            }
        )
        assert inspect_digest(REF, fake.path) == (MANIFEST, "")
        assert fake.requests == [f"GET /images/{REF}/json HTTP/1.1"]

    def test_a_local_build_with_no_repo_digest_answers_its_id(self, daemon):
        fake = daemon(
            {f"/images/{REF}/json": (200, _record(Id=IMAGE_ID, RepoDigests=[]))}
        )
        assert inspect_digest(REF, fake.path) == (IMAGE_ID, "")

    def test_docker_hub_spellings_name_one_repository(self, daemon):
        fake = daemon(
            {
                "/images/docker.io/library/alpine:3.19/json": (
                    200,
                    _record(Id=IMAGE_ID, RepoDigests=[f"alpine@{MANIFEST}"]),
                )
            }
        )
        assert inspect_digest("docker.io/library/alpine:3.19", fake.path) == (
            MANIFEST,
            "",
        )

    def test_an_image_the_engine_does_not_hold_is_a_404_with_a_reason(self, daemon):
        fake = daemon({})
        digest, why = inspect_digest(REF, fake.path)
        assert digest is None
        assert "does not hold" in why

    @pytest.mark.parametrize(
        "status,body,reason",
        [
            (500, b"{}", "HTTP 500"),
            (200, b"not json", "could not be asked"),
            (200, b"[]", "not an image record"),
            (200, _record(Id="latest", RepoDigests=["x@y"]), "names no digest"),
        ],
    )
    def test_anything_else_answers_nothing_with_a_reason(
        self, daemon, status, body, reason
    ):
        fake = daemon({f"/images/{REF}/json": (status, body)})
        digest, why = inspect_digest(REF, fake.path)
        assert digest is None
        assert reason in why

    def test_a_dead_socket_answers_nothing_with_a_reason(self, tmp_path):
        digest, why = inspect_digest(REF, str(tmp_path / "gone.sock"))
        assert digest is None
        assert "could not be asked" in why


class TestTheDefaultEngineRung:
    def test_a_detected_socket_is_asked_and_a_missing_one_is_not(
        self, daemon, monkeypatch, tmp_path
    ):
        import automated_security_helper.core.container_engine as engine_module

        fake = daemon(
            {f"/images/{REF}/json": (200, _record(Id=IMAGE_ID, RepoDigests=[]))}
        )
        monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
        monkeypatch.setattr(
            engine_module, "PODMAN_SYSTEM_SOCKET", str(tmp_path / "no-podman.sock")
        )
        monkeypatch.setenv("DOCKER_HOST", f"unix://{fake.path}")
        resolved = resolve_image_locator(ImageLocator(ref=REF), offline=True)
        assert resolved.resolved_digest == IMAGE_ID

        monkeypatch.setenv("DOCKER_HOST", f"unix://{tmp_path / 'absent.sock'}")
        locator = ImageLocator(ref=REF)
        assert resolve_image_locator(locator, offline=True) is locator
