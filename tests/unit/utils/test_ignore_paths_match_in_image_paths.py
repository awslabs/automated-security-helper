# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``ignore_paths`` on an image scan names the IN-IMAGE path, as written.

The suppression step the scanner executor runs over every result applies the
global ignore paths, through the same matcher as for a directory scan, to the
path a tool reported inside the image (``/usr/share/doc/x/README``). Two things
make that the in-image semantics and not the source-directory ones:

- the path is matched as written, so an ignore path spells the leading slash
  the tool reports (``/usr/share/doc/``), exactly as an ``AshSuppression.path``
  does (docs: scan-container-images.md);
- the directory the scan was started from only anchors it, so a finding that
  happens to sit under a host path of that name is not rebased onto it.

The control is the same report under a filesystem asset, which reads the
source-directory-relative path as it always did.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.asset import Asset, ImageLocator
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PhysicalLocation2,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
PluginContext.model_rebuild()

IMAGE = Asset.for_image(ImageLocator(ref="registry.example.com/team/app:1.2.3"))
DOC = "/usr/share/doc/libfoo/README"
LIB = "/usr/lib/libssl.so.3"


def _result(uri: str) -> Result:
    return Result(
        ruleId="CVE-2024-0001",
        level="error",
        message=Message(text=f"finding in {uri}"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(artifactLocation=ArtifactLocation(uri=uri))
                )
            )
        ],
    )


def _kept(tmp_path: Path, uris, ignores, asset=None, source: Path | None = None):
    source = source or tmp_path / "anchor"
    source.mkdir(parents=True, exist_ok=True)
    output = tmp_path / "out"
    output.mkdir(exist_ok=True)
    config = AshConfig()
    config.global_settings.ignore_paths = [
        IgnorePathWithReason(path=path, reason="not ours") for path in ignores
    ]
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=config,
        asset=asset,
    )
    report = SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="grype")),
                results=[_result(uri) for uri in uris],
            )
        ]
    )
    report = apply_suppressions_to_sarif(sarif_report=report, plugin_context=context)
    return sorted(
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.runs[0].results
    )


class TestAnInImagePathMatchesAnIgnorePath:
    @pytest.mark.parametrize(
        "ignore",
        ["/usr/share/doc/", "/usr/share/doc/**", "/usr/share/doc/libfoo/README"],
    )
    def test_the_finding_under_it_is_filtered_and_the_other_is_kept(
        self, tmp_path, ignore
    ):
        kept = _kept(tmp_path, [DOC, LIB], [ignore], asset=IMAGE)
        assert kept == [LIB]

    def test_an_ignore_path_naming_nothing_in_the_image_filters_nothing(self, tmp_path):
        kept = _kept(tmp_path, [DOC, LIB], ["/opt/"], asset=IMAGE)
        assert kept == sorted([DOC, LIB])

    def test_a_host_path_that_looks_like_the_anchor_is_not_rebased(self, tmp_path):
        """An in-image path under the anchor directory's own host path stays an
        in-image path: ``app/`` (relative to the anchor) must not match it."""
        anchor = tmp_path / "anchor"
        inside = f"{anchor.resolve().as_posix()}/app/main.py"
        kept = _kept(tmp_path, [inside], ["app/"], asset=IMAGE, source=anchor)
        assert kept == [inside]

    def test_the_same_report_under_a_filesystem_asset_still_reads_relative_paths(
        self, tmp_path
    ):
        anchor = tmp_path / "anchor"
        inside = f"{anchor.resolve().as_posix()}/app/main.py"
        kept = _kept(
            tmp_path,
            [inside],
            ["app/"],
            asset=Asset.for_filesystem(anchor),
            source=anchor,
        )
        assert kept == []
