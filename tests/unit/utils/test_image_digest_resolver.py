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

import logging

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
        locator = ImageLocator(ref="--insecure")
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
