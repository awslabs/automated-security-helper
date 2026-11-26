# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The executor records which image a scan's results are about, and only then.

``ScannerExecutor`` stamps ``imageRef`` (and ``imageDigest`` where the tool's run
names one) on every result of a task whose type is ``image``, before suppressions
run and before the flat extractor keys the result. A filesystem task's results
carry no such property, so a filesystem scan's findings keep their ids.
"""

from __future__ import annotations

from pathlib import Path
from typing import ClassVar, Literal
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.asset import Asset, ImageLocator
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.phases.scanner_executor import ScannerExecutor
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.finding_identity import (
    IMAGE_DIGEST_PROPERTY,
    IMAGE_REF_PROPERTY,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

REF = "registry.example.com/team/app:1.2.3"
DIGEST = "sha256:" + "ab" * 32


class _Config(ScannerPluginConfigBase):
    name: Literal["image-shape-tool"] = "image-shape-tool"


def _report() -> SarifReport:
    return SarifReport.model_validate(
        {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {"driver": {"name": "image-shape-tool", "version": "1"}},
                    "properties": {"imageID": DIGEST},
                    "results": [
                        {
                            "ruleId": "CVE-2024-0001",
                            "level": "error",
                            "message": {"text": "libssl is vulnerable"},
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": "usr/lib/libssl.so.3"
                                        },
                                        "region": {"startLine": 1},
                                    }
                                }
                            ],
                        }
                    ],
                }
            ],
        }
    )


class ImageShapeScanner(ScannerPluginBase):
    """Returns a prepared SARIF report from both dispatches."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        self.command = "image-shape-tool"
        self.tool_type = ScannerToolType.SCA
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        self._pre_scan(target=target, target_type=target_type, config=config)
        self._post_scan(target=target, target_type=target_type)
        return _report()

    def scan_image(self, image, config=None, *args, **kwargs):
        self._pre_scan(target=Path("."), target_type="image", config=config)
        self._post_scan(target=Path("."), target_type="image")
        return _report()


def _context(tmp_path, *, image: bool) -> PluginContext:
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    extra = {}
    if image:
        extra["asset"] = Asset(kind="container_image", image=ImageLocator(ref=REF))
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="image-stamp"),
        **extra,
    )


def _row(context: PluginContext, task_type: str):
    scanner = ImageShapeScanner(config=_Config(), context=context)
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    (row,) = executor._execute_scanner(
        "image-shape-tool",
        scanner,
        [{"path": Path(context.source_dir), "type": task_type}],
    )
    return row


def _properties(row):
    return row.raw_results.runs[0].results[0].properties


def test_an_image_task_stamps_the_ref_and_the_digest_the_run_named(tmp_path):
    row = _row(_context(tmp_path, image=True), "image")
    properties = _properties(row)
    assert getattr(properties, IMAGE_REF_PROPERTY) == REF
    assert getattr(properties, IMAGE_DIGEST_PROPERTY) == DIGEST


def test_a_source_task_stamps_nothing(tmp_path):
    row = _row(_context(tmp_path, image=False), "source")
    properties = _properties(row)
    assert properties is None or getattr(properties, IMAGE_REF_PROPERTY, None) is None


def test_an_image_task_hands_the_scanner_the_global_ignore_paths(tmp_path):
    """The ignore paths reach scan_image, which turns them into tool excludes."""
    from automated_security_helper.models.core import IgnorePathWithReason

    seen = {}

    class Recording(ImageShapeScanner):
        def scan_image(
            self, image, config=None, *args, global_ignore_paths=None, **kwargs
        ):
            seen["paths"] = global_ignore_paths
            return super().scan_image(image, config)

    context = _context(tmp_path, image=True)
    scanner = Recording(config=_Config(), context=context)
    executor = ScannerExecutor(
        plugin_context=context, progress_display=MagicMock(), scanner_tasks=[]
    )
    ignored = [IgnorePathWithReason(path="/usr/share/doc/", reason="docs")]
    executor._global_ignore_paths = ignored
    executor._execute_scanner(
        "image-shape-tool",
        scanner,
        [{"path": Path(context.source_dir), "type": "image"}],
    )
    assert seen["paths"] == ignored
