# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The MCP image delivery channel: one session, one scan subject.

The C2 rows of the container-targets design on the MCP surface:

- ``set_source_image`` stores an ImageLocator on the session and fetches
  nothing; refs that can never be references are refused at delivery.
- ``set_source_image_archive_chunk`` + ``..._finalize`` are the zip channel's
  shape byte for byte: the same chunk machinery, a sha256 verified at
  finalize, and -- the image difference -- no extraction, one tar shape
  sniff, the archive moved whole under ``<session>/image/``.
- one session has one subject: a source delivery drops the image binding and
  an image delivery is the newest word, so ``get_session_image_locator`` not
  None always means "delivered after any tree the session still holds".
"""

from __future__ import annotations

import base64
import hashlib
import io
import tarfile

import pytest

from automated_security_helper.cli.mcp import source_delivery as sd
from automated_security_helper.cli.mcp.source_delivery import UploadNotFoundError

pytestmark = pytest.mark.unit

_SESSION = "session-image-delivery"
IMAGE_REF = "registry.example.com/team/app@sha256:" + "a" * 64


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    # The default workspace root too, so a call that is given no root cannot touch
    # the developer's own MCP workspace, and a "nothing was created" check looks
    # where the call would have created it.
    monkeypatch.setattr(sd, "resolve_workspace_root", lambda: tmp_path)
    # The reference rows are about the delivery, not the registry gate, which
    # admits nothing by default; TestTheRegistryAllowlist clears this again.
    monkeypatch.setenv("ASH_MCP_IMAGE_ALLOWED_REGISTRIES", "registry.example.com")
    yield tmp_path
    sd.clear_source(_SESSION, workspace_root=tmp_path)


def _tar_bytes(member: str = "manifest.json", content: bytes = b"[]") -> bytes:
    """A tar with one member: the ustar magic sits in a member's header, so an
    EMPTY archive (zero blocks only) carries none and the shape gate refuses
    it -- which is right, since a saved image always has members."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as archive:
        info = tarfile.TarInfo(name=member)
        info.size = len(content)
        archive.addfile(info, io.BytesIO(content))
    return buf.getvalue()


def _upload(payload: bytes, upload_id: str, workspace_root) -> str:
    sd.set_source_image_archive_chunk(
        upload_id=upload_id,
        sequence=0,
        data_b64=base64.b64encode(payload).decode("ascii"),
        last=True,
        workspace_root=workspace_root,
        session_id=_SESSION,
    )
    return hashlib.sha256(payload).hexdigest()


class TestSetSourceImage:
    def test_a_ref_is_stored_and_nothing_is_fetched(self, workspace):
        locator = sd.set_source_image(f"  {IMAGE_REF} ", session_id=_SESSION)
        assert locator.ref == IMAGE_REF
        stored = sd.get_session_image_locator(_SESSION)
        assert stored is not None
        assert stored.ref == IMAGE_REF
        # Nothing was fetched: the session directory exists -- the TTL sweep
        # finds sessions through their workspace directories, so a ref-only
        # session must have one to be collectable -- but holds no image bytes.
        session_dir = workspace / _SESSION
        assert session_dir.is_dir()
        assert not any(session_dir.rglob("*.tar"))

    def test_a_ref_only_session_is_visible_to_the_ttl_sweep(self, workspace):
        # Before this, set_source_image wrote nothing to disk while the
        # registry counted the locator as a binding: the session could never
        # be collected, and past the registry's cap every new session ran an
        # eviction pass that freed nothing.
        sd.set_source_image(IMAGE_REF, session_id=_SESSION)
        assert (workspace / _SESSION).is_dir()
        assert sd.remove_session_workspace(_SESSION, workspace_root=workspace)
        assert not (workspace / _SESSION).exists()
        assert sd.get_session_image_locator(_SESSION) is None

    def test_an_empty_ref_names_nothing(self, workspace):
        with pytest.raises(ValueError, match="names no reference"):
            sd.set_source_image("   ", session_id=_SESSION)

    def test_a_leading_dash_reads_as_an_option(self, workspace):
        with pytest.raises(ValueError, match="cannot start with '-'"):
            sd.set_source_image("--rm", session_id=_SESSION)

    def test_a_control_character_is_no_reference(self, workspace):
        with pytest.raises(ValueError, match="control character"):
            sd.set_source_image("repo\x1b[31m:tag", session_id=_SESSION)

    def test_an_inner_space_is_no_reference(self, workspace):
        with pytest.raises(ValueError, match="whitespace"):
            sd.set_source_image("repo tag", session_id=_SESSION)

    def test_non_ascii_is_no_reference(self, workspace):
        # C1 controls and bidi overrides reach log lines and tool argv; no OCI
        # reference grammar allows any non-ASCII text. U+202E is the
        # right-to-left override, spelled as an escape so no literal control
        # character sits in this file.
        with pytest.raises(ValueError, match="non-ASCII"):
            sd.set_source_image("repo:tag" + chr(0x202E), session_id=_SESSION)

    def test_a_scheme_and_path_is_no_reference(self, workspace):
        # dir:/etc, oci-archive:/root/x.tar: handed schemeless to a tool, the
        # text reads as a LOCAL PATH, so a remote client could name server
        # files with it. No port and no tag starts with "/".
        with pytest.raises(ValueError, match="scheme-and-path"):
            sd.set_source_image("dir:/etc", session_id=_SESSION)

    def test_a_tool_source_scheme_is_no_reference(self, workspace):
        # docker-archive:x.tar parses as repo "docker-archive" tag "x.tar",
        # which stereoscope reads as an archive at a server-relative path.
        with pytest.raises(ValueError, match="source scheme"):
            sd.set_source_image("docker-archive:x.tar", session_id=_SESSION)

    def test_a_port_and_a_tag_still_read_as_references(self, workspace):
        # The refusals above must not eat real references: a registry with a
        # port, and a plain tag whose repository is no scheme word.
        locator = sd.set_source_image(
            "registry.example.com:5000/team/app:1.2.3", session_id=_SESSION
        )
        assert locator.ref == "registry.example.com:5000/team/app:1.2.3"


class TestTheRegistryAllowlist:
    """set_source_image reaches only registries the operator listed.

    A scan of a delivered ref makes the SERVER's own tools reach that
    registry -- any host the ref can spell, internal addresses included --
    with the server's network, daemon store and registry credentials: the
    reach ``ASH_MCP_GIT_ALLOWED_HOSTS`` closes for the git channel, closed
    here the same way. Empty (the default) admits nothing; the archive
    upload needs no registry and is not gated.
    """

    def test_an_empty_list_admits_no_reference(self, workspace, monkeypatch):
        monkeypatch.delenv("ASH_MCP_IMAGE_ALLOWED_REGISTRIES", raising=False)
        with pytest.raises(sd.ImageRegistryRefused, match="not in"):
            sd.set_source_image(IMAGE_REF, session_id=_SESSION)
        assert sd.get_session_image_locator(_SESSION) is None

    def test_a_listed_registry_is_admitted_with_ports_normalized(
        self, workspace, monkeypatch
    ):
        monkeypatch.setenv(
            "ASH_MCP_IMAGE_ALLOWED_REGISTRIES",
            "other.example.com, registry.example.com:443",
        )
        locator = sd.set_source_image(IMAGE_REF, session_id=_SESSION)
        assert locator.ref == IMAGE_REF

    def test_a_bare_hub_reference_needs_docker_io_listed(self, workspace, monkeypatch):
        monkeypatch.setenv("ASH_MCP_IMAGE_ALLOWED_REGISTRIES", "registry.example.com")
        with pytest.raises(sd.ImageRegistryRefused, match="docker.io"):
            sd.set_source_image("alpine:3.20", session_id=_SESSION)
        monkeypatch.setenv("ASH_MCP_IMAGE_ALLOWED_REGISTRIES", "docker.io")
        assert sd.set_source_image("alpine:3.20", session_id=_SESSION).ref == (
            "alpine:3.20"
        )

    def test_the_refusals_error_type_is_its_own(self, workspace, monkeypatch):
        # A client branches on error_type, so the gate's refusal is not the
        # generic ValueError answer.
        from automated_security_helper.cli.mcp_tools import mcp_set_source_image

        monkeypatch.delenv("ASH_MCP_IMAGE_ALLOWED_REGISTRIES", raising=False)
        answer = mcp_set_source_image(IMAGE_REF, session_id=_SESSION)
        assert answer["success"] is False
        assert answer["error_type"] == "image_registry_not_permitted"

    def test_the_registry_of_a_ref_is_the_distribution_reading(self, workspace):
        assert sd.image_ref_registry("alpine:3.20") == "docker.io"
        assert sd.image_ref_registry("team/app:1") == "docker.io"
        assert sd.image_ref_registry("localhost/app:1") == "localhost"
        assert sd.image_ref_registry("reg.example.com:5000/app") == (
            "reg.example.com:5000"
        )
        assert sd.image_ref_registry("Reg.Example.com:443/app") == "reg.example.com"


class TestOneSubjectPerSession:
    def test_a_source_delivery_drops_the_image_binding(self, workspace):
        sd.set_source_image(IMAGE_REF, session_id=_SESSION)
        assert sd.get_session_image_locator(_SESSION) is not None
        sd._set_session_source_dir(_SESSION, workspace / _SESSION / "source")
        assert sd.get_session_image_locator(_SESSION) is None

    def test_an_image_after_a_source_is_the_newest_word(self, workspace):
        sd._set_session_source_dir(_SESSION, workspace / _SESSION / "source")
        sd.set_source_image(IMAGE_REF, session_id=_SESSION)
        assert sd.get_session_image_locator(_SESSION) is not None

    def test_removing_the_workspace_forgets_the_binding(self, workspace):
        sd.set_source_image(IMAGE_REF, session_id=_SESSION)
        sd.remove_session_workspace(_SESSION, workspace_root=workspace)
        assert sd.get_session_image_locator(_SESSION) is None


class TestImageArchiveFinalize:
    def test_a_verified_tar_lands_under_image_and_binds(self, workspace):
        payload = _tar_bytes()
        sha = _upload(payload, "up-tar", workspace)
        incoming = workspace / _SESSION / "incoming"
        assert any(incoming.iterdir()), "the assembled upload exists before finalize"

        archive = sd.set_source_image_archive_finalize(
            upload_id="up-tar",
            expected_sha256=sha,
            workspace_root=workspace,
            session_id=_SESSION,
        )

        assert archive == workspace / _SESSION / "image" / "up-tar.tar"
        assert archive.read_bytes() == payload
        locator = sd.get_session_image_locator(_SESSION)
        assert locator is not None
        assert locator.oci_archive == archive
        assert locator.ref is None
        # The assembled upload was consumed by the move.
        assert not list(incoming.iterdir())

    def test_a_sha_mismatch_is_refused_and_binds_nothing(self, workspace):
        _upload(_tar_bytes(), "up-bad-sha", workspace)
        incoming = workspace / _SESSION / "incoming"
        assert any(incoming.iterdir()), "the assembled upload exists before finalize"
        with pytest.raises(ValueError, match="sha256 mismatch"):
            sd.set_source_image_archive_finalize(
                upload_id="up-bad-sha",
                expected_sha256="0" * 64,
                workspace_root=workspace,
                session_id=_SESSION,
            )
        assert sd.get_session_image_locator(_SESSION) is None
        # The refused upload was removed, as the zip channel removes one.
        assert not list(incoming.iterdir())

    def test_bytes_that_are_not_a_tar_are_refused_with_the_gate_text(self, workspace):
        payload = b"not a tar at all" + b"\x00" * 600
        sha = _upload(payload, "up-not-tar", workspace)
        with pytest.raises(ValueError, match="is not a tar archive"):
            sd.set_source_image_archive_finalize(
                upload_id="up-not-tar",
                expected_sha256=sha,
                workspace_root=workspace,
                session_id=_SESSION,
            )
        assert sd.get_session_image_locator(_SESSION) is None
        # Nothing half-delivered stays under image/.
        image_dir = workspace / _SESSION / "image"
        assert not image_dir.exists() or not list(image_dir.iterdir())

    def test_an_upload_without_its_last_chunk_is_not_found(self, workspace):
        with pytest.raises(UploadNotFoundError):
            sd.set_source_image_archive_finalize(
                upload_id="never-finished",
                expected_sha256="0" * 64,
                workspace_root=workspace,
                session_id=_SESSION,
            )

    def test_a_second_archive_replaces_the_first(self, workspace):
        first = _tar_bytes()
        sha_first = _upload(first, "up-one", workspace)
        sd.set_source_image_archive_finalize(
            upload_id="up-one",
            expected_sha256=sha_first,
            workspace_root=workspace,
            session_id=_SESSION,
        )
        second = _tar_bytes(member="layer.tar", content=b"data")
        sha_second = _upload(second, "up-two", workspace)

        delivered = sd.set_source_image_archive_finalize(
            upload_id="up-two",
            expected_sha256=sha_second,
            workspace_root=workspace,
            session_id=_SESSION,
        )

        locator = sd.get_session_image_locator(_SESSION)
        assert locator is not None
        assert locator.oci_archive == delivered
        # The replaced archive is scratch and was removed.
        assert not (workspace / _SESSION / "image" / "up-one.tar").exists()


class TestTheArchiveCleanupStaysInItsDirectory:
    def test_a_binding_outside_the_session_image_dir_deletes_nothing(
        self, workspace, tmp_path
    ):
        # The locator registry is a module global: a binding whose archive
        # path an operator owns must never have that directory emptied by the
        # next delivery. The cleanup rebuilds the expected <session>/image
        # path and acts only there; anything else is dropped, not deleted.
        from automated_security_helper.core.asset import ImageLocator

        operator_dir = tmp_path / "operator-owned"
        operator_dir.mkdir()
        archive = operator_dir / "their-image.tar"
        archive.write_bytes(b"x")
        bystander = operator_dir / "unrelated-notes.txt"
        bystander.write_text("not ASH's to delete")
        sd._set_session_image_locator(_SESSION, ImageLocator(oci_archive=archive))

        sd._set_session_source_dir(_SESSION, workspace / _SESSION / "source")

        assert archive.exists()
        assert bystander.exists()
        assert sd.get_session_image_locator(_SESSION) is None

    def test_a_staged_archive_is_still_cleaned(self, workspace):
        payload = _tar_bytes()
        sha = _upload(payload, "up-contained", workspace)
        sd.set_source_image_archive_finalize(
            upload_id="up-contained",
            expected_sha256=sha,
            workspace_root=workspace,
            session_id=_SESSION,
        )
        staged = workspace / _SESSION / "image" / "up-contained.tar"
        assert staged.exists()
        sd._set_session_source_dir(_SESSION, workspace / _SESSION / "source")
        assert not staged.exists()


class TestTheCapNamesWhatTheClientSent:
    def test_an_oversize_image_archive_upload_names_an_image_archive(
        self, workspace, monkeypatch
    ):
        monkeypatch.setattr(sd, "_MAX_ZIP_BYTES", 8)
        with pytest.raises(ValueError, match="max image archive size"):
            _upload(_tar_bytes(), "up-oversize", workspace)

    def test_the_zip_channels_own_cap_still_names_a_zip(self, workspace, monkeypatch):
        monkeypatch.setattr(sd, "_MAX_ZIP_BYTES", 8)
        with pytest.raises(ValueError, match="max zip size"):
            sd.set_source_zip_chunk(
                upload_id="up-zip-oversize",
                sequence=0,
                data_b64=base64.b64encode(b"0123456789abcdef").decode("ascii"),
                last=True,
                workspace_root=workspace,
                session_id=_SESSION,
            )
