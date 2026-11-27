# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tag-only reference resolves through a ladder: the local engine, then the registry.

Rung 1 asks a docker or podman daemon over its socket and needs no network, so
it works offline; rung 2 is ``crane digest`` (tests/unit/utils/
test_image_digest_resolver.py holds its rows). The ids key on whichever digest
the first rung to answer gave, the notice names the rung, and the reference
text is the key only when every rung fails. The engine is a fake here: a real
unix-socket HTTP server for the inspect call, a table for the ladder's order.

Windows' CPython has no ``socket.AF_UNIX``, so the fake server cannot be built
there and the rows that ask it do not apply (``needs_unix_sockets``). What the
inspect answers on such a Python is pinned on every platform by a row that
deletes the attribute.
"""

from __future__ import annotations

import json
import logging
import re
import socket
import tempfile
import threading
from pathlib import Path

import pytest
import yaml

from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.utils.image_digest_resolver import (
    inspect_digest,
    resolve_image_locator,
)
from automated_security_helper.utils.scanner_tool_types import (
    an_image_digest_consumer_is_selected,
)

pytestmark = pytest.mark.unit

MANIFEST = "sha256:" + "ab" * 32
IMAGE_ID = "sha256:" + "cd" * 32
OTHER = "sha256:" + "ef" * 32
REF = "registry.example.com/team/app:1.2.3"
CRANE = "/opt/bin/crane"

#: A row that needs the fake daemon below: it serves on a unix socket, which a
#: Python without socket.AF_UNIX (Windows' CPython) cannot open.
needs_unix_sockets = pytest.mark.skipif(
    not hasattr(socket, "AF_UNIX"),
    reason="no socket.AF_UNIX (Windows), so no unix-socket engine can be faked",
)


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
        # No surface builds this locator any more (the reference grammar
        # refuses a leading '-'); model_construct skips that check so the
        # resolver's own guard is what this row measures.
        locator = ImageLocator.model_construct(ref="--insecure")
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
    @needs_unix_sockets
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

    @needs_unix_sockets
    def test_a_local_build_with_no_repo_digest_answers_its_id(self, daemon):
        fake = daemon(
            {f"/images/{REF}/json": (200, _record(Id=IMAGE_ID, RepoDigests=[]))}
        )
        assert inspect_digest(REF, fake.path) == (IMAGE_ID, "")

    @needs_unix_sockets
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

    @needs_unix_sockets
    def test_an_image_the_engine_does_not_hold_is_a_404_with_a_reason(self, daemon):
        fake = daemon({})
        digest, why = inspect_digest(REF, fake.path)
        assert digest is None
        assert "does not hold" in why

    @needs_unix_sockets
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

    def test_a_python_without_unix_sockets_answers_nothing_with_a_reason(
        self, monkeypatch, tmp_path
    ):
        # Windows' CPython has no socket.AF_UNIX. Deleting it here measures that
        # case on every platform: the inspect answers nothing with the reason
        # instead of raising AttributeError out of the rung.
        monkeypatch.delattr(socket, "AF_UNIX", raising=False)
        digest, why = inspect_digest(REF, str(tmp_path / "engine.sock"))
        assert digest is None
        assert "could not be asked" in why
        assert "no unix sockets" in why


class TestTheDefaultEngineRung:
    @needs_unix_sockets
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


REPO_ROOT = Path(__file__).resolve().parents[3]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ash-image-scan-live-engine.yml"

IMAGE_TAG = "localhost:5000/ash-live-engine:ci"
DIGEST = "sha256:" + "ab" * 32


def _scan_steps() -> list[str]:
    """The run text of each workflow step that runs ``ash scan --image``.

    A backslash continuation is joined, so a command is one line.
    """
    document = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    steps = []
    for job in document["jobs"].values():
        for step in job.get("steps", []):
            run = step.get("run")
            if isinstance(run, str) and "ash scan --image" in run:
                steps.append(run.replace("\\\n", " "))
    return steps


def _command(step: str) -> str:
    """The ``ash scan --image`` line of a step."""
    (command,) = [line for line in step.splitlines() if "ash scan --image" in line]
    return command


def _selection(command: str) -> list[str]:
    """The scanner names the command's ``--only-scanners`` values name."""
    values = re.findall(r"--only-scanners[= ]+(\S+)", command)
    return [name for value in values for name in value.split(",") if name]


def _greps(step: str) -> list[str]:
    """The phrases a step ``grep -F``s the scan's log for."""
    return re.findall(r'grep -F "([^"]+)"', step)


class _Lines(logging.Handler):
    """Every message ASH_LOGGER writes: that logger does not propagate to caplog."""

    def __init__(self) -> None:
        super().__init__(level=1)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


def _what_the_ladder_logs(engine_holds_the_image: bool) -> str:
    """The ladder's log for a tag, against a fake engine and a fake registry."""
    from automated_security_helper.utils.log import ASH_LOGGER

    def inspect(ref):
        if engine_holds_the_image:
            return DIGEST, ""
        return None, "the engine does not hold this image"

    def registry(argv, timeout):
        return 0, DIGEST + "\n"

    handler = _Lines()
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(1)
    ASH_LOGGER.addHandler(handler)
    try:
        resolved = resolve_image_locator(
            ImageLocator(ref=IMAGE_TAG),
            offline=False,
            runner=registry,
            crane="/opt/bin/crane",
            inspector=("docker", inspect),
        )
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)
    assert resolved.resolved_digest == DIGEST
    return "\n".join(handler.lines)


class TestTheLiveEngineWorkflowSelectsADigestConsumer:
    """The live-engine image scan selects a scanner that consumes the digest ladder.

    Why this class exists
    ---------------------
    .github/workflows/ash-image-scan-live-engine.yml scans an image by tag against a real
    container engine and a real registry. It requires two things of each scan: a log line
    from the digest ladder (``through the local docker engine`` while the engine holds the
    image, ``through the registry (crane digest)`` once it does not) and a
    ``metadata.scan_source`` that names the digest the registry holds.

    The scan phase resolves a tag-only reference only when a selected scanner declares the
    registry read (``Fetched.IMAGE_DIGEST`` in its operational facets; see
    ``an_image_digest_consumer_is_selected``). syft reports no findings, so it does not
    declare it. The job selected syft alone, so once that gate landed neither line was ever
    written, the job failed at its first ``grep`` on every pull request, and nothing in the
    unit tier read the workflow to say why.

    What it pins
    ------------
    - Each ``ash scan --image`` command in the workflow names a ``--only-scanners``
      selection that the function the scan phase asks reads as holding a digest consumer.
    - Each phrase the job greps for is a line the ladder writes: the engine rung's for the
      first scan, the registry rung's for the second. The ladder runs here against an
      injected engine and registry, so nothing is pulled or asked.

    Known limits
    ------------
    The selection is read as text. A scan whose scanners come from ``--scanners``, a config
    file or the environment reads as no selection and fails the first test, so the author
    changes the selection here instead of getting past it. Which scanner classes count is
    the gate's own walk of the classes already imported, so the test imports the two it
    needs.
    """

    @pytest.fixture(autouse=True)
    def _the_scanners_the_gate_reads_are_loaded(self):
        """The gate walks the scanner classes already imported; import the two it needs."""
        from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
            GrypeScanner,
        )
        from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
            SyftScanner,
        )

        return GrypeScanner, SyftScanner

    def test_the_workflow_scans_by_tag_twice(self):
        steps = _scan_steps()
        assert len(steps) == 2, (
            "one scan for the engine rung and one for the registry rung"
        )

    def test_each_scan_selects_a_scanner_that_consumes_the_digest(self):
        for step in _scan_steps():
            command = _command(step)
            names = _selection(command)
            assert names, f"no --only-scanners selection in: {command}"
            assert an_image_digest_consumer_is_selected(enabled_scanners=names), (
                f"{names} declares no image-digest registry read, so the scan phase "
                f"resolves no digest for: {command}"
            )

    def test_the_gate_reads_syft_alone_as_no_consumer(self):
        # The control. The job once selected syft alone: if that read as a consumer, the
        # test above could never have gone red.
        assert an_image_digest_consumer_is_selected(enabled_scanners=["syft"]) is False
        assert an_image_digest_consumer_is_selected(enabled_scanners=["grype"]) is True

    def test_the_phrases_each_scan_greps_for_are_lines_the_ladder_writes(self):
        engine_scan, registry_scan = _scan_steps()
        engine_phrases, registry_phrases = _greps(engine_scan), _greps(registry_scan)
        assert engine_phrases, "the engine rung's scan greps for nothing"
        assert registry_phrases, "the registry rung's scan greps for nothing"
        engine_log = _what_the_ladder_logs(engine_holds_the_image=True)
        registry_log = _what_the_ladder_logs(engine_holds_the_image=False)
        for phrase in engine_phrases:
            assert phrase in engine_log, f"{phrase!r} is not in: {engine_log}"
        for phrase in registry_phrases:
            assert phrase in registry_log, f"{phrase!r} is not in: {registry_log}"
