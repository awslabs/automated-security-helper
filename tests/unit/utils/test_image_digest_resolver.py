# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A tag-only image reference resolved to its digest through crane.

No registry is read and no crane runs: the resolver takes an injected runner, so
each row hands it the output a registry would give and reads what the scan does
with it. The rows pin the three outcomes the design names: a digest recorded on
the locator (and the ids keyed on it, stable when the tag re-points), a
digest-pinned or payload locator left alone, and the single-notice fallback to
the reference text when the lookup cannot or may not run.
"""

from __future__ import annotations

import hashlib
import io
import json
import logging
import os
import tarfile
import threading

import pytest

from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import Run
from automated_security_helper.utils.image_attribution import mark_image_results
from automated_security_helper.utils.image_digest_resolver import (
    resolve_image_locator,
)
from automated_security_helper.utils.image_tool_targets import archive_scheme

pytestmark = pytest.mark.unit

DIGEST = "sha256:" + "ab" * 32
OTHER = "sha256:" + "cd" * 32

#: A saved image's config blob, and the digest those bytes really have: a
#: payload names a digest only when the blob it points at hashes to it.
CONFIG_BLOB = b'{"architecture": "amd64", "os": "linux"}'
HEX = hashlib.sha256(CONFIG_BLOB).hexdigest()
PAYLOAD_DIGEST = "sha256:" + HEX
BLOB_PATH = f"blobs/sha256/{HEX}"

#: The config blob of a different image, and the path a docker save manifest.json
#: names it by: a manifest.json that is not the image an index.json names.
OTHER_CONFIG_BLOB = b'{"architecture": "arm64", "os": "linux"}'
OTHER_HEX = hashlib.sha256(OTHER_CONFIG_BLOB).hexdigest()
OTHER_BLOB_PATH = f"blobs/sha256/{OTHER_HEX}"
REF = "registry.example.com/team/app:1.2.3"
CRANE = "/opt/bin/crane"


class FakeRegistry:
    """A runner answering ``crane digest <ref>`` from a table, recording calls."""

    def __init__(self, table=None, code=0, text=None, raises=None):
        self.table = table or {}
        self.code = code
        self.text = text
        self.raises = raises
        self.calls = []

    def __call__(self, argv, timeout):
        self.calls.append((list(argv), timeout))
        if self.raises is not None:
            raise self.raises
        if self.text is not None:
            return self.code, self.text
        assert argv[:3] == [argv[0], "digest", "--"]
        return self.code, self.table.get(argv[-1], "") + "\n"


class _Notices(logging.Handler):
    """Every record ASH_LOGGER logs during a cell: the logger does not propagate."""

    def __init__(self) -> None:
        super().__init__(level=1)
        self.records = []

    def emit(self, record) -> None:
        self.records.append(record)

    @property
    def text(self) -> str:
        return "\n".join(r.getMessage() for r in self.records)


@pytest.fixture
def notices():
    from automated_security_helper.utils.log import ASH_LOGGER

    handler = _Notices()
    level = ASH_LOGGER.level
    ASH_LOGGER.setLevel(1)
    ASH_LOGGER.addHandler(handler)
    try:
        yield handler
    finally:
        ASH_LOGGER.removeHandler(handler)
        ASH_LOGGER.setLevel(level)


@pytest.fixture(autouse=True)
def no_engine_on_this_host(monkeypatch, tmp_path):
    """The engine rung of the ladder sees no daemon: these rows are the registry's.

    The suite must never ask the host's real engine (tests/unit/utils/
    test_image_digest_ladder.py covers the engine rung with its own socket).
    """
    import automated_security_helper.core.container_engine as engine_module

    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.delenv("CONTAINER_HOST", raising=False)
    monkeypatch.delenv("XDG_RUNTIME_DIR", raising=False)
    monkeypatch.setattr(
        engine_module, "DOCKER_DEFAULT_SOCKET", str(tmp_path / "absent-docker.sock")
    )
    monkeypatch.setattr(
        engine_module, "PODMAN_SYSTEM_SOCKET", str(tmp_path / "absent-podman.sock")
    )


def _notice_count(handler) -> int:
    return sum(1 for r in handler.records if "Could not resolve" in r.getMessage())


class TestResolution:
    def test_a_tag_resolves_to_the_registrys_digest(self, notices):
        registry = FakeRegistry({REF: DIGEST})
        resolved = resolve_image_locator(
            ImageLocator(ref=REF), offline=False, runner=registry, crane=CRANE
        )
        assert resolved.resolved_digest == DIGEST
        assert resolved.ref == REF
        assert registry.calls[0][0] == [CRANE, "digest", "--", REF]
        assert _notice_count(notices) == 0

    def test_a_reference_that_reads_as_an_option_is_never_handed_to_crane(
        self, notices
    ):
        registry = FakeRegistry({"--insecure": DIGEST})
        # No surface builds this locator any more (the reference grammar
        # refuses a leading '-'); model_construct skips that check so the
        # resolver's own guard is what this row measures.
        locator = ImageLocator.model_construct(ref="--insecure")
        assert (
            resolve_image_locator(locator, offline=False, runner=registry, crane=CRANE)
            is locator
        )
        assert registry.calls == []
        assert _notice_count(notices) == 1

    def test_a_digest_pinned_ref_is_not_looked_up(self):
        registry = FakeRegistry()
        locator = ImageLocator(ref=f"registry.example.com/team/app@{DIGEST}")
        assert (
            resolve_image_locator(locator, offline=False, runner=registry, crane=CRANE)
            is locator
        )
        assert registry.calls == []

    def test_a_payload_locator_is_not_looked_up(self, tmp_path):
        registry = FakeRegistry()
        archive = tmp_path / "image.tar"
        archive.write_bytes(b"")
        locator = ImageLocator(oci_archive=archive)
        assert (
            resolve_image_locator(locator, offline=False, runner=registry, crane=CRANE)
            is locator
        )
        assert registry.calls == []


class TestIdsKeyOnTheResolvedDigest:
    @staticmethod
    def _id(locator: ImageLocator) -> str:
        run = Run.model_validate(
            {
                "tool": {"driver": {"name": "grype", "version": "0.0.0"}},
                "results": [
                    {
                        "ruleId": "CVE-2024-0001",
                        "message": {"text": "libssl is vulnerable"},
                        "level": "error",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "/usr/lib/libssl.so.3"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        )

        class _Report:
            runs = [run]

        mark_image_results(_Report(), locator)
        return FlatVulnerability.from_sarif_result(
            run.results[0], tool_name="grype", tool_type="SCA", run=run
        ).id

    def test_the_id_is_stable_when_the_tag_re_points_to_the_same_image(self):
        first = resolve_image_locator(
            ImageLocator(ref="registry.example.com/app:latest"),
            offline=False,
            runner=FakeRegistry({"registry.example.com/app:latest": DIGEST}),
            crane=CRANE,
        )
        # The tag now has another name, the registry still says the same digest.
        second = resolve_image_locator(
            ImageLocator(ref="registry.example.com/app:1.2.3"),
            offline=False,
            runner=FakeRegistry({"registry.example.com/app:1.2.3": DIGEST}),
            crane=CRANE,
        )
        assert self._id(first) == self._id(second)

    def test_the_id_changes_when_the_tag_moves_to_another_image(self):
        before = resolve_image_locator(
            ImageLocator(ref=REF),
            offline=False,
            runner=FakeRegistry({REF: DIGEST}),
            crane=CRANE,
        )
        after = resolve_image_locator(
            ImageLocator(ref=REF),
            offline=False,
            runner=FakeRegistry({REF: OTHER}),
            crane=CRANE,
        )
        assert self._id(before) != self._id(after)

    def test_without_resolution_the_id_keys_on_the_reference_text(self):
        unresolved = ImageLocator(ref=REF)
        resolved = resolve_image_locator(
            unresolved,
            offline=False,
            runner=FakeRegistry({REF: DIGEST}),
            crane=CRANE,
        )
        assert self._id(unresolved) != self._id(resolved)


class TestTheFallback:
    def test_offline_makes_no_request_and_names_the_fallback_once(self, notices):
        registry = FakeRegistry({REF: DIGEST})
        locator = ImageLocator(ref=REF)
        result = resolve_image_locator(
            locator, offline=True, runner=registry, crane=CRANE
        )
        assert result is locator
        assert registry.calls == []
        assert _notice_count(notices) == 1
        assert "offline" in notices.text
        assert "reference text" in notices.text

    @pytest.mark.parametrize(
        "registry",
        [
            FakeRegistry(code=1),
            FakeRegistry(text="not a digest"),
            FakeRegistry(raises=TimeoutError("slow registry")),
        ],
        ids=["nonzero exit", "garbage output", "raised"],
    )
    def test_a_failed_lookup_falls_back_with_one_notice(self, registry, notices):
        locator = ImageLocator(ref=REF)
        assert (
            resolve_image_locator(locator, offline=False, runner=registry, crane=CRANE)
            is locator
        )
        assert _notice_count(notices) == 1

    def test_a_missing_crane_falls_back_with_one_notice(self, notices, monkeypatch):
        from automated_security_helper.utils import subprocess_utils

        monkeypatch.setattr(subprocess_utils, "find_executable", lambda name: None)
        locator = ImageLocator(ref=REF)
        registry = FakeRegistry({REF: DIGEST})
        assert resolve_image_locator(locator, offline=False, runner=registry) is locator
        assert registry.calls == []
        assert _notice_count(notices) == 1
        assert "crane is not installed" in notices.text


class TestThePayloadRung:
    """A direct payload names its own digest; nothing is asked or fetched.

    A payload scan used to key its ids and its scan scope on the payload's
    PATH, so the same bytes uploaded twice (the MCP channel writes each upload
    under a new id) were two subjects, and only trivy's run-recorded imageID
    keyed on content -- splitting one image's ids between trivy rows and
    everyone else's.
    """

    def _layout(self, tmp_path, manifests, blobs=None):
        """A layout whose index names *manifests*; *blobs* maps a digest to its bytes."""
        layout = tmp_path / "layout"
        layout.mkdir(exist_ok=True)
        (layout / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
        (layout / "index.json").write_text(
            json.dumps({"schemaVersion": 2, "manifests": manifests})
        )
        for digest, body in (blobs or {}).items():
            blob = layout / "blobs" / "sha256" / digest.removeprefix("sha256:")
            blob.parent.mkdir(parents=True, exist_ok=True)
            blob.write_bytes(body)
        return layout

    def _tar(self, tmp_path, members: dict, name="image.tar"):
        import io
        import tarfile

        path = tmp_path / name
        with tarfile.open(path, "w") as archive:
            for member, body in members.items():
                info = tarfile.TarInfo(name=member)
                info.size = len(body)
                archive.addfile(info, io.BytesIO(body))
        return path

    def _docker_archive(self, tmp_path):
        config = f"{HEX}.json"
        return self._tar(
            tmp_path,
            {
                "manifest.json": json.dumps([{"Config": config}]).encode(),
                config: CONFIG_BLOB,
            },
        )

    def test_a_layouts_one_manifest_digest_is_read(self, tmp_path):
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        layout = self._layout(
            tmp_path,
            [{"digest": PAYLOAD_DIGEST, "mediaType": "x"}],
            {PAYLOAD_DIGEST: CONFIG_BLOB},
        )
        assert payload_digest(ImageLocator(oci_layout=layout)) == (PAYLOAD_DIGEST, "")

    def test_a_multi_manifest_index_names_nothing_with_the_reason(self, tmp_path):
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        layout = self._layout(tmp_path, [{"digest": DIGEST}, {"digest": OTHER}])
        digest, why = payload_digest(ImageLocator(oci_layout=layout))
        assert digest is None
        assert "2 manifests" in why

    @pytest.mark.parametrize(
        "config_entry",
        [BLOB_PATH, HEX + ".json"],
        ids=["recent docker save", "older save"],
    )
    def test_a_docker_archives_config_digest_is_read(self, tmp_path, config_entry):
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        archive = self._tar(
            tmp_path,
            {
                "manifest.json": json.dumps([{"Config": config_entry}]).encode(),
                config_entry: CONFIG_BLOB,
            },
        )
        assert payload_digest(ImageLocator(oci_archive=archive)) == (
            PAYLOAD_DIGEST,
            "",
        )

    def test_an_oci_archives_index_is_read(self, tmp_path):
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        archive = self._tar(
            tmp_path,
            {
                "oci-layout": b'{"imageLayoutVersion": "1.0.0"}',
                "index.json": json.dumps(
                    {"schemaVersion": 2, "manifests": [{"digest": PAYLOAD_DIGEST}]}
                ).encode(),
                BLOB_PATH: CONFIG_BLOB,
            },
        )
        assert payload_digest(ImageLocator(oci_archive=archive)) == (
            PAYLOAD_DIGEST,
            "",
        )

    def test_an_oversized_record_is_refused_unread(self, tmp_path):
        from automated_security_helper.utils import image_digest_resolver as idr

        archive = self._tar(
            tmp_path,
            {"manifest.json": b" " * (idr._MAX_PAYLOAD_RECORD_BYTES + 1)},
        )
        digest, why = idr.payload_digest(ImageLocator(oci_archive=archive))
        assert digest is None
        assert "too large" in why

    def test_the_resolver_fills_the_locator_from_the_payload(self, tmp_path, notices):
        resolved = resolve_image_locator(
            ImageLocator(oci_archive=self._docker_archive(tmp_path)), offline=True
        )
        assert resolved.resolved_digest == PAYLOAD_DIGEST
        assert resolved.resolved_from == "payload"
        # No warning: the payload answered, and nothing was asked or fetched
        # (offline=True would have refused a registry rung).
        assert _notice_count(notices) == 0

    def test_a_payload_digest_never_pins_a_pull(self, tmp_path):
        resolved = resolve_image_locator(
            ImageLocator(oci_archive=self._docker_archive(tmp_path)), offline=True
        )
        assert resolved.pulled_ref() is None

    def test_the_stamp_and_the_scope_key_on_the_payloads_digest(self, tmp_path):
        from automated_security_helper.utils.image_attribution import (
            image_scan_source,
        )

        resolved = resolve_image_locator(
            ImageLocator(oci_archive=self._docker_archive(tmp_path)), offline=True
        )
        # The scope a reporter compares within is the digest, not the upload
        # path, so the same bytes delivered twice are one subject...
        assert image_scan_source(resolved) == f"image:{PAYLOAD_DIGEST}"
        # ...and a grype-shaped run (no run digest of its own) gets the same
        # digest trivy's rows get, so an image: suppression by digest covers
        # both and their ids share one basis.
        run = Run.model_validate(
            {
                "tool": {"driver": {"name": "grype", "version": "0.0.0"}},
                "results": [
                    {
                        "ruleId": "CVE-2024-0001",
                        "message": {"text": "libssl is vulnerable"},
                        "level": "error",
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "/usr/lib/libssl.so.3"},
                                    "region": {"startLine": 1},
                                }
                            }
                        ],
                    }
                ],
            }
        )

        class _Report:
            runs = [run]

        mark_image_results(_Report(), resolved)
        flat = FlatVulnerability.from_sarif_result(
            run.results[0], tool_name="grype", tool_type="SCA", run=run
        )
        assert flat.image_digest == PAYLOAD_DIGEST


def _tar_of(tmp_path, *members):
    """A tar of ``(info, body)`` pairs in order; a link has no body."""
    path = tmp_path / "payload.tar"
    with tarfile.open(path, "w") as archive:
        for info, body in members:
            archive.addfile(info, None if body is None else io.BytesIO(body))
    return path


def _record(name, body):
    """A regular member called *name* that holds *body*."""
    info = tarfile.TarInfo(name=name)
    info.size = len(body)
    return info, body


def _link(name, kind, target):
    """A member called *name* that is a link (*kind*) to the member *target*."""
    info = tarfile.TarInfo(name=name)
    info.type = kind
    info.linkname = target
    return info, None


def _manifest_naming_the_digest() -> bytes:
    """A ``docker save`` manifest.json whose one config blob is PAYLOAD_DIGEST's."""
    return json.dumps([{"Config": BLOB_PATH}]).encode()


def _manifest_naming_the_other_image() -> bytes:
    """A ``docker save`` manifest.json whose one config blob is OTHER_BLOB_PATH's."""
    return json.dumps([{"Config": OTHER_BLOB_PATH}]).encode()


def _saved_image(record="manifest.json", blob=CONFIG_BLOB, blob_name=BLOB_PATH):
    """The members of a ``docker save`` tar: its record, then the config blob it names.

    *blob* None leaves the blob out; *blob* other bytes than CONFIG_BLOB makes the
    digest the record names the digest of other bytes.
    """
    members = [_record(record, _manifest_naming_the_digest())]
    if blob is not None:
        members.append(_record(blob_name, blob))
    return members


def _oci_index() -> bytes:
    """An OCI index.json whose one manifest is PAYLOAD_DIGEST."""
    return json.dumps(
        {"schemaVersion": 2, "manifests": [{"digest": PAYLOAD_DIGEST}]}
    ).encode()


def _oci_archive_members(record="index.json", blob=CONFIG_BLOB):
    """The members of an OCI archive: its index, then the manifest blob it names."""
    members = [_record(record, _oci_index())]
    if blob is not None:
        members.append(_record(BLOB_PATH, blob))
    return members


def _nested_json() -> bytes:
    """JSON as long as a record may be, nested as deep as that length allows.

    Exactly the record size cap, so the member is read in full and handed to the
    parser instead of being refused as too large; the parser gives up on the
    nesting long before the end.
    """
    from automated_security_helper.utils import image_digest_resolver as idr

    depth = idr._MAX_PAYLOAD_RECORD_BYTES // 2
    return b"[" * depth + b"]" * depth


def _archive_holding(tmp_path, *members):
    return ImageLocator(oci_archive=_tar_of(tmp_path, *members))


def _layout_holding(tmp_path, index: bytes, blob=None):
    """A layout holding *index*, and *blob* as the blob PAYLOAD_DIGEST names."""
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
    (layout / "index.json").write_bytes(index)
    if blob is not None:
        (layout / "blobs" / "sha256").mkdir(parents=True)
        (layout / BLOB_PATH).write_bytes(blob)
    return ImageLocator(oci_layout=layout)


#: Payloads whose record cannot be read, each with the member a reason must name.
UNREADABLE_PAYLOADS = [
    pytest.param(
        lambda tmp_path: _archive_holding(
            tmp_path, _link("manifest.json", tarfile.SYMTYPE, "no-such-member.json")
        ),
        "manifest.json",
        id="manifest-symlink-to-a-missing-member",
    ),
    pytest.param(
        lambda tmp_path: _archive_holding(
            tmp_path, _link("manifest.json", tarfile.SYMTYPE, "manifest.json")
        ),
        "manifest.json",
        id="manifest-symlink-to-itself",
    ),
    pytest.param(
        lambda tmp_path: _archive_holding(
            tmp_path, _link("manifest.json", tarfile.LNKTYPE, "manifest.json")
        ),
        "manifest.json",
        id="manifest-hard-link-to-itself",
    ),
    pytest.param(
        lambda tmp_path: _archive_holding(
            tmp_path, _record("manifest.json", _nested_json())
        ),
        "manifest.json",
        id="manifest-nested-past-the-parsers-limit",
    ),
    pytest.param(
        lambda tmp_path: _archive_holding(
            tmp_path, _record("index.json", _nested_json())
        ),
        "index.json",
        id="archive-index-nested-past-the-parsers-limit",
    ),
    pytest.param(
        lambda tmp_path: _layout_holding(tmp_path, _nested_json()),
        "index.json",
        id="layout-index-nested-past-the-parsers-limit",
    ),
]


@pytest.mark.parametrize(("build", "member"), UNREADABLE_PAYLOADS)
class TestAPayloadWhoseRecordCannotBeRead:
    """A payload's record is a client's file, and it can be anything.

    ``payload_digest`` reads one JSON record from a saved image or an OCI layout
    the client supplied. A record it cannot read as one answers no digest, with a
    reason that names the member, and the scan keys its ids on the payload path
    as it does for a payload that names none: a resolution failure never fails
    or skips the scan.
    """

    def test_a_record_that_cannot_be_read_names_no_digest(
        self, tmp_path, build, member
    ):
        """A link in place of the record, or JSON nested past the parser's limit.

        The standard library's lookup of a link's target raises KeyError for a
        missing target and RecursionError for a link to itself, and the JSON
        parser raises RecursionError past its depth limit. None of them may leave
        ``payload_digest``.
        """
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        digest, why = payload_digest(build(tmp_path))
        assert digest is None
        assert member in why

    def test_the_resolver_returns_the_locator_unchanged(
        self, tmp_path, notices, build, member
    ):
        """Resolving such a payload keeps the locator and says why it has no digest."""
        locator = build(tmp_path)
        resolved = resolve_image_locator(locator, offline=True)
        assert resolved is locator
        assert resolved.resolved_digest is None
        assert member in notices.text


class TestOnlyARegularMemberIsARecord:
    """The record is read from a regular member; a link is passed over, not followed."""

    def test_a_link_named_like_a_record_is_skipped_and_the_next_record_is_read(
        self, tmp_path
    ):
        """A link called index.json is passed over, and manifest.json still decides.

        Reading the link would follow it to a member the archive lacks; the
        regular manifest.json after it names the config digest.
        """
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        archive = _archive_holding(
            tmp_path,
            _link("index.json", tarfile.SYMTYPE, "no-such-member.json"),
            *_saved_image(),
        )
        assert payload_digest(archive) == (PAYLOAD_DIGEST, "")

    def test_a_well_formed_payload_still_names_its_digest(self, tmp_path):
        """Control: the builders above, given a readable record, name the digest.

        A saved image's manifest.json and an OCI layout's index.json, built the
        way the rows that fail are built, each resolve to the digest they name,
        so those rows fail on what their record holds and not on how it was made.
        """
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        archive = _archive_holding(tmp_path, *_saved_image())
        layout = _layout_holding(tmp_path, _oci_index(), CONFIG_BLOB)
        assert payload_digest(archive) == (PAYLOAD_DIGEST, "")
        assert payload_digest(layout) == (PAYLOAD_DIGEST, "")


#: Payloads whose record names a digest the blob it points at does not have, each
#: with the record a reason must name and the words it must use.
UNVERIFIED_PAYLOADS = [
    pytest.param(
        lambda tmp_path: _archive_holding(
            tmp_path, *_saved_image(blob=b"bytes of another image")
        ),
        "manifest.json",
        "do not match",
        id="saved-image-config-blob-hashes-to-another-digest",
    ),
    pytest.param(
        lambda tmp_path: _archive_holding(tmp_path, *_saved_image(blob=None)),
        "manifest.json",
        "not in the payload",
        id="saved-image-config-blob-missing",
    ),
    pytest.param(
        lambda tmp_path: _archive_holding(
            tmp_path, *_oci_archive_members(blob=b"bytes of another image")
        ),
        "index.json",
        "do not match",
        id="oci-archive-manifest-blob-hashes-to-another-digest",
    ),
    pytest.param(
        lambda tmp_path: _archive_holding(tmp_path, *_oci_archive_members(blob=None)),
        "index.json",
        "not in the payload",
        id="oci-archive-manifest-blob-missing",
    ),
    pytest.param(
        lambda tmp_path: _layout_holding(
            tmp_path, _oci_index(), b"bytes of another image"
        ),
        "index.json",
        "do not match",
        id="layout-manifest-blob-hashes-to-another-digest",
    ),
    pytest.param(
        lambda tmp_path: _layout_holding(tmp_path, _oci_index()),
        "index.json",
        "not in the payload",
        id="layout-manifest-blob-missing",
    ),
]


@pytest.mark.parametrize(("build", "record", "phrase"), UNVERIFIED_PAYLOADS)
class TestADigestIsAcceptedOnlyForBytesThatHashToIt:
    """A payload's record names a digest; the blob it points at has to have it."""

    def test_a_record_whose_blob_does_not_hash_to_its_digest_names_none(
        self, tmp_path, build, record, phrase
    ):
        """The record is the client's word: it names a digest, and no blob is hashed.

        The digest keys the image's finding ids and its ``image:`` suppressions,
        so a record that names a blob its bytes do not have, or one the payload
        lacks, names no digest, with a reason that names the record.
        """
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        digest, why = payload_digest(build(tmp_path))
        assert digest is None
        assert record in why
        assert phrase in why

    def test_the_resolver_keys_the_payload_on_its_path(
        self, tmp_path, notices, build, record, phrase
    ):
        """Resolving such a payload keeps the locator, and the notice says why."""
        locator = build(tmp_path)
        resolved = resolve_image_locator(locator, offline=True)
        assert resolved is locator
        assert resolved.resolved_digest is None
        assert phrase in notices.text


class TestTheBlobIsChecked:
    def test_a_blob_over_the_size_bound_names_no_digest(self, tmp_path, monkeypatch):
        """A blob too large to check against its digest is not taken on trust."""
        from automated_security_helper.utils import image_digest_resolver as idr

        monkeypatch.setattr(
            idr, "_MAX_PAYLOAD_BLOB_BYTES", len(CONFIG_BLOB) - 1, raising=False
        )
        digest, why = idr.payload_digest(_archive_holding(tmp_path, *_saved_image()))
        assert digest is None
        assert "too large" in why

    @pytest.mark.parametrize(
        "config",
        [f"x/../{HEX}.json", f"blobs/./sha256/{HEX}", f"blobs//sha256/{HEX}"],
        ids=["dot-dot", "dot", "empty-part"],
    )
    def test_a_blob_named_by_a_path_a_tool_would_resolve_elsewhere_is_not_taken(
        self, tmp_path, config
    ):
        """A tool reads ``x/../<hex>.json`` as ``<hex>.json``, so the member that
        has the first name, and hashes right, proves nothing about the second."""
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        archive = _archive_holding(
            tmp_path,
            _record("manifest.json", json.dumps([{"Config": config}]).encode()),
            _record(config, CONFIG_BLOB),
        )
        digest, why = payload_digest(archive)
        assert digest is None
        assert "manifest.json" in why

    def test_two_members_named_like_the_record_name_no_digest(self, tmp_path):
        """A tool may read the later of two same-named members, so neither is trusted."""
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        archive = _archive_holding(
            tmp_path, *_saved_image(), _record("manifest.json", b"[]")
        )
        digest, why = payload_digest(archive)
        assert digest is None
        assert "manifest.json" in why


class TestOnlyAnExactRecordNameIsARecord:
    """``./manifest.json`` is the record; a name that needs more stripped is not."""

    @pytest.mark.parametrize(
        "name",
        [".manifest.json", "../manifest.json", ".//manifest.json", "/manifest.json"],
    )
    def test_a_saved_image_record_under_another_name_is_not_read(self, tmp_path, name):
        """The name test used to strip any run of dots and slashes from the front.

        A saved image's record under such a name is not read as the record. The
        archive routing still reads the member as manifest.json, so the archive
        names no digest, and the reason says why.
        """
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        archive = _archive_holding(tmp_path, *_saved_image(record=name))
        digest, why = payload_digest(archive)
        assert digest is None
        assert "not a regular file named exactly manifest.json" in why

    @pytest.mark.parametrize("name", ["..index.json", "../index.json", "/index.json"])
    def test_an_index_under_another_name_is_not_read(self, tmp_path, name):
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        archive = _archive_holding(tmp_path, *_oci_archive_members(record=name))
        assert payload_digest(archive) == (
            None,
            "the archive holds no manifest.json or index.json",
        )

    def test_one_leading_dot_slash_is_still_stripped(self, tmp_path):
        """Control: ``./manifest.json`` and ``./index.json`` are the records."""
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        saved = _archive_holding(tmp_path, *_saved_image(record="./manifest.json"))
        assert payload_digest(saved) == (PAYLOAD_DIGEST, "")
        other = tmp_path / "other"
        other.mkdir()
        oci = _archive_holding(other, *_oci_archive_members(record="./index.json"))
        assert payload_digest(oci) == (PAYLOAD_DIGEST, "")


#: Spellings of manifest.json that the archive routing reads as manifest.json and
#: the digest reader's exact name test does not: the routing drops any leading run
#: of dots and slashes from a member's name, the reader one leading "./".
ROUTED_AS_MANIFEST_NAMES = {
    "dot-prefixed": ".manifest.json",
    "parent-directory": "../manifest.json",
    "root-directory": "/manifest.json",
    "double-slash": ".//manifest.json",
    "repeated-dot-slash": "././manifest.json",
}


def _regular_member_called(name):
    """A payload whose manifest.json is a regular member under another spelling.

    The member names another image than the regular index.json beside it does, as
    a member the routing reads as manifest.json can.
    """

    def build(tmp_path):
        return _archive_holding(
            tmp_path,
            _record(name, _manifest_naming_the_other_image()),
            *_oci_archive_members(),
        )

    return build


#: Payloads in which a member the archive routing reads as manifest.json is not the
#: regular member named exactly that, each beside a regular index.json that names
#: PAYLOAD_DIGEST and the regular blob whose bytes have it.
MISREAD_MANIFEST_PAYLOADS = [
    pytest.param(
        lambda tmp_path: _archive_holding(
            tmp_path,
            _record("other.json", _manifest_naming_the_other_image()),
            _link("manifest.json", tarfile.SYMTYPE, "other.json"),
            *_oci_archive_members(),
        ),
        id="manifest-symlink-to-another-member",
    ),
    pytest.param(
        lambda tmp_path: _archive_holding(
            tmp_path,
            _record("other.json", _manifest_naming_the_other_image()),
            _link("manifest.json", tarfile.LNKTYPE, "other.json"),
            *_oci_archive_members(),
        ),
        id="manifest-hard-link-to-another-member",
    ),
    *(
        pytest.param(_regular_member_called(name), id=f"regular-{label}-name")
        for label, name in ROUTED_AS_MANIFEST_NAMES.items()
    ),
]


@pytest.mark.parametrize("build", MISREAD_MANIFEST_PAYLOADS)
class TestAMemberReadAsManifestJsonIsTheRecordOrTheArchiveNamesNoDigest:
    """The member the routing reads as manifest.json decides the archive's route.

    ``archive_scheme`` hands a tar that holds a member called manifest.json (once
    any leading run of dots and slashes is dropped, and whatever the member's type)
    to grype and syft as a docker archive, not as an OCI archive. A regular
    index.json beside such a member can name the image of another record than the
    member that routed the archive, so the digest it names is not taken: when a
    member the routing reads as manifest.json is not the regular, exact-named
    record ``payload_digest`` reads, the archive names no digest, with a reason
    that names manifest.json.
    """

    def test_the_archive_names_no_digest(self, tmp_path, build):
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        locator = build(tmp_path)
        # The premise: the tools are told to read this tar as a docker archive.
        assert archive_scheme(locator.oci_archive) == "docker-archive"
        digest, why = payload_digest(locator)
        assert digest is None
        assert "manifest.json" in why
        assert "not a regular file named exactly manifest.json" in why

    def test_the_resolver_keys_the_payload_on_its_path(self, tmp_path, notices, build):
        """Resolving such a payload keeps the locator, and the notice names the record."""
        locator = build(tmp_path)
        resolved = resolve_image_locator(locator, offline=True)
        assert resolved is locator
        assert resolved.resolved_digest is None
        assert "manifest.json" in notices.text


class TestTheManifestRecordStillDecidesWhenNothingElseIsRoutedAsOne:
    """Controls: the refusal is for a misread member, not for manifest.json itself."""

    def test_a_regular_exact_manifest_json_beside_an_index_names_its_own_digest(
        self, tmp_path
    ):
        """The same tar with the record in place: manifest.json decides.

        It names the config blob of the other image, not the manifest blob the
        index names, as the tools that read the archive through manifest.json do.
        """
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        archive = _archive_holding(
            tmp_path,
            _record("manifest.json", _manifest_naming_the_other_image()),
            _record(OTHER_BLOB_PATH, OTHER_CONFIG_BLOB),
            *_oci_archive_members(),
        )
        assert archive_scheme(archive.oci_archive) == "docker-archive"
        assert payload_digest(archive) == (f"sha256:{OTHER_HEX}", "")

    def test_names_that_only_look_like_manifest_json_keep_the_index_route(
        self, tmp_path
    ):
        """A nested manifest.json and a longer name are not read as manifest.json.

        Nothing in the tar is routed as manifest.json, so the index decides.
        """
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        archive = _archive_holding(
            tmp_path,
            _record("layer/manifest.json", b"[]"),
            _record("manifest.json.orig", b"[]"),
            *_oci_archive_members(),
        )
        assert archive_scheme(archive.oci_archive) == "oci-archive"
        assert payload_digest(archive) == (PAYLOAD_DIGEST, "")


def _bare_layout(tmp_path):
    """A layout directory with its marker and nothing else."""
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
    return layout


def _symlink_or_skip(link, target):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError) as error:
        pytest.skip(f"cannot make a symlink here: {error}")


def _answered_within(seconds, call):
    """Whether *call* was still running after *seconds*, and what it answered."""
    answers: list = []
    thread = threading.Thread(target=lambda: answers.append(call()), daemon=True)
    thread.start()
    thread.join(seconds)
    return thread.is_alive(), answers


def _release(fifo):
    """Open the write end of *fifo* without waiting, so a reader stuck on it ends."""
    try:
        os.close(os.open(fifo, os.O_WRONLY | getattr(os, "O_NONBLOCK", 0)))
    except OSError:
        pass


needs_fifos = pytest.mark.skipif(
    not hasattr(os, "mkfifo"), reason="a FIFO needs os.mkfifo, which Windows lacks"
)


class TestALayoutIsReadOnlyThroughRegularFiles:
    """The layout's index and blobs are the client's files: no link, no pipe."""

    def test_a_symlinked_index_names_no_digest(self, tmp_path):
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        layout = _bare_layout(tmp_path)
        real = tmp_path / "real-index.json"
        real.write_bytes(_oci_index())
        (layout / "blobs" / "sha256").mkdir(parents=True)
        (layout / BLOB_PATH).write_bytes(CONFIG_BLOB)
        _symlink_or_skip(layout / "index.json", real)
        digest, why = payload_digest(ImageLocator(oci_layout=layout))
        assert digest is None
        assert "index.json" in why
        assert "regular file" in why

    @needs_fifos
    def test_a_fifo_index_names_no_digest_without_blocking(self, tmp_path):
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        layout = _bare_layout(tmp_path)
        fifo = layout / "index.json"
        os.mkfifo(fifo)
        try:
            still_running, answers = _answered_within(
                5, lambda: payload_digest(ImageLocator(oci_layout=layout))
            )
        finally:
            _release(fifo)
        assert not still_running
        digest, why = answers[0]
        assert digest is None
        assert "index.json" in why
        assert "regular file" in why

    def test_a_symlinked_blob_names_no_digest(self, tmp_path):
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        locator = _layout_holding(tmp_path, _oci_index())
        layout = locator.oci_layout
        real = tmp_path / "real-blob"
        real.write_bytes(CONFIG_BLOB)
        (layout / "blobs" / "sha256").mkdir(parents=True)
        _symlink_or_skip(layout / BLOB_PATH, real)
        digest, why = payload_digest(locator)
        assert digest is None
        assert "index.json" in why
        assert "regular file" in why

    @needs_fifos
    def test_a_fifo_blob_names_no_digest_without_blocking(self, tmp_path):
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        locator = _layout_holding(tmp_path, _oci_index())
        layout = locator.oci_layout
        (layout / "blobs" / "sha256").mkdir(parents=True)
        fifo = layout / BLOB_PATH
        os.mkfifo(fifo)
        try:
            still_running, answers = _answered_within(
                5, lambda: payload_digest(locator)
            )
        finally:
            _release(fifo)
        assert not still_running
        digest, why = answers[0]
        assert digest is None
        assert "regular file" in why


class TestADeclaredEngineWithNoLocalSocket:
    """A declared daemon with no local socket ends the ladder before any registry read."""

    def test_an_inspector_with_no_function_returns_the_locator_and_runs_no_crane(
        self, notices
    ):
        """The ``(name, None)`` answer of the engine detection."""
        registry = FakeRegistry({REF: DIGEST})
        locator = ImageLocator(ref=REF)
        resolved = resolve_image_locator(
            locator,
            offline=False,
            runner=registry,
            crane=CRANE,
            inspector=("docker", None),
        )
        assert resolved is locator
        assert resolved.resolved_digest is None
        assert registry.calls == []
        assert _notice_count(notices) == 1
        assert "the declared docker daemon has no local socket to ask" in notices.text

    @pytest.mark.parametrize(
        ("variable", "value", "engine"),
        [
            ("DOCKER_HOST", "tcp://docker:2375", "docker"),
            ("DOCKER_HOST", "ssh://builder@host", "docker"),
            ("CONTAINER_HOST", "ssh://builder@host", "podman"),
        ],
    )
    def test_a_declared_remote_daemon_stops_the_ladder_the_same_way(
        self, notices, monkeypatch, variable, value, engine
    ):
        monkeypatch.setenv(variable, value)
        registry = FakeRegistry({REF: DIGEST})
        locator = ImageLocator(ref=REF)
        resolved = resolve_image_locator(
            locator, offline=False, runner=registry, crane=CRANE
        )
        assert resolved is locator
        assert registry.calls == []
        assert f"the declared {engine} daemon has no local socket" in notices.text
