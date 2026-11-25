# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A real image scan over a committed saved-image archive, in CI.

What this covers: ``TrivyScanner.scan_image`` through the real pinned trivy, over
``tests/test_data/images/secret-image.tar`` (a ``docker save`` archive built from
nothing; its digest is in the README beside it) and over the OCI image-layout
directory that same archive is re-packed into. The archive path needs no
container engine and no registry, so the scan runs wherever trivy does, and it
finds the one fake token the image holds. The image-layout leg goes through the
production re-pack (``utils/oci_layout_archive``) that hands trivy an archive.

What it does not cover, by design: a live container engine and a live registry.
No CI leg has either, no test pulls an image, and the digest resolver and the
engine-delegated argv are covered with fakes in the unit tier. Secret scanning is
used because it reads the layers and needs no vulnerability database, which a
network-free run does not have.
"""

import os
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
)
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.image_attribution import mark_image_results
from tests.utils.image_archive_fixture import archive_to_layout

PluginContext.model_rebuild()

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name == "nt", reason="POSIX paths"),
]

ARCHIVE = (
    Path(__file__).resolve().parents[2] / "test_data" / "images" / ("secret-image.tar")
)


def _scan(tmp_path: Path, image: ImageLocator, ignore_paths=None):
    source = tmp_path / "anchor"
    source.mkdir()
    output = tmp_path / "out"
    output.mkdir()
    # Built from no config file in the tree: the options here are the operator's.
    config = AshConfig()
    record_provenance(config, in_tree=[])
    scanner = TrivyScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=config),
        config=TrivyScannerConfig(options={"scanners": ["secret"], "offline": True}),
    )
    report = scanner.scan_image(image, global_ignore_paths=ignore_paths)
    return report


def _rule_ids(report) -> set:
    return {r.ruleId for run in report.runs or [] for r in run.results or []}


def test_the_committed_archive_is_scanned_and_yields_a_finding(tmp_path, trivy_on_path):
    assert ARCHIVE.is_file()
    report = _scan(tmp_path, ImageLocator(oci_archive=ARCHIVE))
    assert "github-pat" in _rule_ids(report)


def test_the_findings_carry_the_image_attribution(tmp_path, trivy_on_path):
    locator = ImageLocator(oci_archive=ARCHIVE)
    report = _scan(tmp_path, locator)
    assert mark_image_results(report, locator) > 0
    results = [r for run in report.runs for r in run.results or []]
    assert all(r.properties.imageRef == locator.shown() for r in results)


def test_the_findings_name_the_layer_that_holds_them(tmp_path, trivy_on_path):
    """trivy's SARIF has no layer; the JSON pass fills ``layerDigest``.

    The digest is the fixture's one layer, the blob digest in the archive's own
    manifest (tests/test_data/images/README.md describes the fixture).
    """
    report = _scan(tmp_path, ImageLocator(oci_archive=ARCHIVE))
    results = [r for run in report.runs for r in run.results or []]
    assert results
    assert {getattr(r.properties, "layerDigest", None) for r in results} == {
        "sha256:9fd2968b2b1e3dfa271598db3b56fb431faf5827450d945c04c335b51ae4c077"
    }


@pytest.mark.parametrize("path", ["/app/", "/app", "/app/creds.txt", "/*/creds.txt"])
def test_an_ignore_path_keeps_the_tool_from_reading_the_file(
    tmp_path, trivy_on_path, path
):
    """The ignore path reaches trivy as --skip-files, so the finding never exists.

    ``scan_image`` runs no report filter (the executor does), so the finding's
    absence is trivy leaving the file unread.
    """
    from automated_security_helper.models.core import IgnorePathWithReason

    report = _scan(
        tmp_path,
        ImageLocator(oci_archive=ARCHIVE),
        ignore_paths=[IgnorePathWithReason(path=path, reason="test")],
    )
    assert "github-pat" not in _rule_ids(report)


def test_an_ignore_path_that_matches_nothing_changes_nothing(tmp_path, trivy_on_path):
    from automated_security_helper.models.core import IgnorePathWithReason

    report = _scan(
        tmp_path,
        ImageLocator(oci_archive=ARCHIVE),
        ignore_paths=[IgnorePathWithReason(path="/elsewhere/", reason="test")],
    )
    assert "github-pat" in _rule_ids(report)


def test_the_archive_repacked_as_a_layout_gives_the_same_finding(
    tmp_path, trivy_on_path
):
    layout = archive_to_layout(ARCHIVE, tmp_path / "layout")
    report = _scan(tmp_path, ImageLocator(oci_layout=layout))
    assert "github-pat" in _rule_ids(report)
