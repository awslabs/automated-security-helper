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

import io
import logging
import tarfile

import pytest

from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import Run
from automated_security_helper.utils.image_attribution import mark_image_results
from automated_security_helper.utils.image_digest_resolver import (
    resolve_image_locator,
)

pytestmark = pytest.mark.unit

DIGEST = "sha256:" + "ab" * 32
OTHER = "sha256:" + "cd" * 32
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

    def _layout(self, tmp_path, manifests):
        import json

        layout = tmp_path / "layout"
        layout.mkdir(exist_ok=True)
        (layout / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
        (layout / "index.json").write_text(
            json.dumps({"schemaVersion": 2, "manifests": manifests})
        )
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
        import json

        return self._tar(
            tmp_path,
            {"manifest.json": json.dumps([{"Config": "ab" * 32 + ".json"}]).encode()},
        )

    def test_a_layouts_one_manifest_digest_is_read(self, tmp_path):
        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        layout = self._layout(tmp_path, [{"digest": DIGEST, "mediaType": "x"}])
        assert payload_digest(ImageLocator(oci_layout=layout)) == (DIGEST, "")

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
        ["blobs/sha256/" + "ab" * 32, "ab" * 32 + ".json"],
        ids=["recent docker save", "older save"],
    )
    def test_a_docker_archives_config_digest_is_read(self, tmp_path, config_entry):
        import json

        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        archive = self._tar(
            tmp_path,
            {"manifest.json": json.dumps([{"Config": config_entry}]).encode()},
        )
        assert payload_digest(ImageLocator(oci_archive=archive)) == (DIGEST, "")

    def test_an_oci_archives_index_is_read(self, tmp_path):
        import json

        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        archive = self._tar(
            tmp_path,
            {
                "oci-layout": b'{"imageLayoutVersion": "1.0.0"}',
                "index.json": json.dumps(
                    {"schemaVersion": 2, "manifests": [{"digest": DIGEST}]}
                ).encode(),
            },
        )
        assert payload_digest(ImageLocator(oci_archive=archive)) == (DIGEST, "")

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
        assert resolved.resolved_digest == DIGEST
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
        assert image_scan_source(resolved) == f"image:{DIGEST}"
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
        assert flat.image_digest == DIGEST


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
    """A ``docker save`` manifest.json whose one config blob is DIGEST."""
    import json

    config = DIGEST.removeprefix("sha256:") + ".json"
    return json.dumps([{"Config": config}]).encode()


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


def _layout_holding(tmp_path, index: bytes):
    layout = tmp_path / "layout"
    layout.mkdir()
    (layout / "oci-layout").write_text('{"imageLayoutVersion": "1.0.0"}')
    (layout / "index.json").write_bytes(index)
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
            _record("manifest.json", _manifest_naming_the_digest()),
        )
        assert payload_digest(archive) == (DIGEST, "")

    def test_a_well_formed_payload_still_names_its_digest(self, tmp_path):
        """Control: the builders above, given a readable record, name the digest.

        A saved image's manifest.json and an OCI layout's index.json, built the
        way the rows that fail are built, each resolve to the digest they name,
        so those rows fail on what their record holds and not on how it was made.
        """
        import json

        from automated_security_helper.utils.image_digest_resolver import (
            payload_digest,
        )

        archive = _archive_holding(
            tmp_path, _record("manifest.json", _manifest_naming_the_digest())
        )
        index = json.dumps({"schemaVersion": 2, "manifests": [{"digest": DIGEST}]})
        layout = _layout_holding(tmp_path, index.encode())
        assert payload_digest(archive) == (DIGEST, "")
        assert payload_digest(layout) == (DIGEST, "")
