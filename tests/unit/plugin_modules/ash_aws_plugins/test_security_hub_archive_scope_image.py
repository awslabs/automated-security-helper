# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Security Hub archives within one scope: an image's, never a repository's, and by digest.

``archive_resolved_findings`` reads "the scan no longer reports it" as "fixed",
which holds only for what the scan looked at. A finding stores the scope of the
scan that made it (``ash/scope``, ``source=<scan_source>;converted=...``), and a
scan archives only findings of its own scope. An image scan records
``scan_source`` as ``image:<digest>`` (``utils/image_attribution.image_scan_source``),
so:

- an image scan archives no repository finding, and a repository scan no image
  finding, even when both are reported by one scanner under one findings scope;
- a re-tagged image (one digest, two tags) is one scope, so a finding of it the
  second tag's scan no longer reports is archived, which is correct (the image
  is the same bytes, so the finding really is gone: it was rescanned);
- a tag that moves to another image is a NEW scope, so scanning the new image
  archives nothing the old one reported: the old image still exists by its digest
  and its findings are not "fixed" by a different image.

The doubles are the aws reporter tests' (security_hub_reporter_doubles.py): no
AWS call is made, GetFindings is a stub returning the stored findings.
"""

from __future__ import annotations

import pytest

from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.utils.image_attribution import image_scan_source
from tests.unit.plugin_modules.ash_aws_plugins.security_hub_reporter_doubles import (
    ACCOUNT,
    REGION,
    archive_run,
    isolated_aws_environment,  # noqa: F401  (autouse fixture)
    make_model,
    make_reporter,
    make_result,
    no_retry_sleep,  # noqa: F401  (autouse fixture)
    stored_finding,
)

pytestmark = pytest.mark.unit

DIGEST_A = "sha256:" + "aa" * 32
DIGEST_B = "sha256:" + "bb" * 32
REF = "registry.example.com/team/app"
IN_IMAGE_PATH = "/usr/lib/libssl.so.3"


def _image_source(tag: str, digest: str | None) -> str:
    locator = ImageLocator(ref=f"{REF}:{tag}", resolved_digest=digest)
    return image_scan_source(locator)


def _image_result(rule: str, tag: str, digest: str):
    return make_result(
        rule_id=rule,
        uri=IN_IMAGE_PATH,
        line=1,
        scanner="trivy",
        extra_properties={"imageRef": f"{REF}:{tag}", "imageDigest": digest},
    )


def _image_model(results, *, tag: str, digest: str):
    return make_model(
        results, completed=("trivy",), scan_source=_image_source(tag, digest)
    )


def _repo_model(results):
    return make_model(results, completed=("trivy",), scan_source=".")


def _stored_from(tmp_path, model):
    reporter = make_reporter(tmp_path, archive=True)
    [finding] = reporter.build_asff_findings(model, account_id=ACCOUNT, region=REGION)
    return reporter, stored_finding(finding)


def _ids(imports) -> set:
    return {finding["Id"] for finding in imports.findings}


class TestTheRecordedScope:
    def test_a_tag_resolved_to_a_digest_is_that_digest(self):
        assert _image_source("1.2", DIGEST_A) == f"image:{DIGEST_A}"

    def test_a_pinned_reference_is_its_own_digest(self):
        locator = ImageLocator(ref=f"{REF}@{DIGEST_A}")
        assert image_scan_source(locator) == f"image:{DIGEST_A}"

    def test_two_tags_of_one_image_are_one_scope(self):
        assert _image_source("1.2", DIGEST_A) == _image_source("latest", DIGEST_A)

    def test_a_tag_that_moves_to_another_image_is_another_scope(self):
        assert _image_source("latest", DIGEST_A) != _image_source("latest", DIGEST_B)

    def test_with_no_digest_the_reference_is_the_scope_as_before(self):
        assert _image_source("1.2", None) == f"image:{REF}:1.2"

    def test_an_image_scope_is_never_a_directory_scope(self):
        assert not _image_source("1.2", DIGEST_A).startswith((".", "/"))


class TestArchivingNeverCrossesRepositoryAndImage:
    def test_an_image_scan_archives_no_repository_finding(self, tmp_path):
        reporter, stored = _stored_from(
            tmp_path, _repo_model([_image_result("CVE-2024-0001", "1.2", DIGEST_A)])
        )
        assert stored["ProductFields"]["ash/scope"].startswith("source=.;")

        document, imports, _ = archive_run(
            tmp_path,
            _image_model(
                [_image_result("CVE-2024-0002", "1.2", DIGEST_A)],
                tag="1.2",
                digest=DIGEST_A,
            ),
            [stored],
            expected_sent=1,
            reporter=reporter,
        )
        assert document["archived"] == 0
        assert stored["Id"] not in _ids(imports)

    def test_a_repository_scan_archives_no_image_finding(self, tmp_path):
        reporter, stored = _stored_from(
            tmp_path,
            _image_model(
                [_image_result("CVE-2024-0001", "1.2", DIGEST_A)],
                tag="1.2",
                digest=DIGEST_A,
            ),
        )
        assert f"image:{DIGEST_A}" in stored["ProductFields"]["ash/scope"]

        document, imports, _ = archive_run(
            tmp_path,
            _repo_model([_image_result("CVE-2024-0002", "1.2", DIGEST_A)]),
            [stored],
            expected_sent=1,
            reporter=reporter,
        )
        assert document["archived"] == 0
        assert stored["Id"] not in _ids(imports)


class TestArchivingFollowsTheImagesDigest:
    def test_the_control_a_rescan_of_the_same_image_archives_what_it_fixed(
        self, tmp_path
    ):
        reporter, stored = _stored_from(
            tmp_path,
            _image_model(
                [_image_result("CVE-2024-0001", "1.2", DIGEST_A)],
                tag="1.2",
                digest=DIGEST_A,
            ),
        )
        document, imports, _ = archive_run(
            tmp_path,
            _image_model(
                [_image_result("CVE-2024-0002", "1.2", DIGEST_A)],
                tag="1.2",
                digest=DIGEST_A,
            ),
            [stored],
            expected_sent=2,
            reporter=reporter,
        )
        assert document["archived"] == 1
        archived = {f["Id"]: f for f in imports.findings}[stored["Id"]]
        assert archived["RecordState"] == "ARCHIVED"

    def test_another_tag_of_the_same_image_shares_the_scope(self, tmp_path):
        reporter, stored = _stored_from(
            tmp_path,
            _image_model(
                [_image_result("CVE-2024-0001", "1.2", DIGEST_A)],
                tag="1.2",
                digest=DIGEST_A,
            ),
        )
        document, _imports, _ = archive_run(
            tmp_path,
            _image_model(
                [_image_result("CVE-2024-0002", "latest", DIGEST_A)],
                tag="latest",
                digest=DIGEST_A,
            ),
            [stored],
            expected_sent=2,
            reporter=reporter,
        )
        assert document["archived"] == 1

    def test_a_tag_moved_to_another_image_archives_nothing_of_the_old_one(
        self, tmp_path
    ):
        reporter, stored = _stored_from(
            tmp_path,
            _image_model(
                [_image_result("CVE-2024-0001", "latest", DIGEST_A)],
                tag="latest",
                digest=DIGEST_A,
            ),
        )
        document, imports, _ = archive_run(
            tmp_path,
            _image_model(
                [_image_result("CVE-2024-0002", "latest", DIGEST_B)],
                tag="latest",
                digest=DIGEST_B,
            ),
            [stored],
            expected_sent=1,
            reporter=reporter,
        )
        assert document["archived"] == 0
        assert stored["Id"] not in _ids(imports)


def test_an_image_scan_that_resolved_its_tag_is_archivable_at_all(tmp_path):
    """The preconditions the receipt would otherwise name as why nothing archived."""
    reporter = make_reporter(tmp_path, archive=True)
    model = _image_model(
        [_image_result("CVE-2024-0001", "1.2", DIGEST_A)], tag="1.2", digest=DIGEST_A
    )
    completed, skipped = reporter._archive_scope(model)
    assert skipped is None
    assert completed == frozenset({"trivy"})
