# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The Dockle plugin page's suppression example suppresses the finding it names.

The example is read from the page itself, so a page change that makes it match
nothing turns these rows red. Dockle 0.4.15's captured SARIF
(``tests/test_data/scanners/dockle/captured/positive.sarif``) goes through the SARIF
pass the scanner executor runs, stamped first the way an image scan stamps its
results (``mark_image_results``) or left unstamped, as a directory scan leaves them.
No tool runs and no image is read.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Set

import pytest
import yaml

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.image_attribution import mark_image_results
from automated_security_helper.utils.sarif_utils import apply_suppressions_to_sarif

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[4]
_PAGE = _ROOT / "docs/content/docs/plugins/alpha/dockle-plugin.md"
_CAPTURED = _ROOT / "tests/test_data/scanners/dockle/captured/positive.sarif"
#: An image the page's example scopes its entry to.
_IMAGE = ImageLocator(ref="registry.example.com/team/app:1.2.3")


def _documented_entries() -> List[AshSuppression]:
    """The entries of the first YAML block in the page's Suppressions section."""
    page = _PAGE.read_text(encoding="utf-8")
    section = page.split("\n## Suppressions\n", 1)[1].split("\n## ", 1)[0]
    block = section.split("```yaml\n", 1)[1].split("```", 1)[0]
    entries = yaml.safe_load(block)["global_settings"]["suppressions"]
    return [AshSuppression(**entry) for entry in entries]


def _captured() -> SarifReport:
    return SarifReport.model_validate(json.loads(_CAPTURED.read_text(encoding="utf-8")))


def _rules(report: SarifReport) -> Set[str]:
    return {r.ruleId for run in report.runs for r in run.results or []}


def _suppressed(tmp_path: Path, report: SarifReport) -> Set[str]:
    config = AshConfig(
        project_name="p", global_settings={"suppressions": _documented_entries()}
    )
    context = PluginContext(
        source_dir=tmp_path, output_dir=tmp_path / "out", config=config
    )
    applied = apply_suppressions_to_sarif(report, context, scanner_name="dockle")
    return {
        result.ruleId
        for run in applied.runs
        for result in run.results or []
        if result.suppressions
    }


def test_the_page_documents_one_entry_for_a_checkpoint_the_capture_reports():
    (entry,) = _documented_entries()

    assert entry.rule_id in _rules(_captured())
    assert entry.image is not None


def test_the_documented_entry_suppresses_its_checkpoint_in_an_image_scan(tmp_path):
    report = _captured()
    assert mark_image_results(report, _IMAGE) == 6

    assert _suppressed(tmp_path, report) == {"CIS-DI-0001"}


def test_the_documented_entry_never_matches_a_directory_scan_finding(tmp_path):
    # A directory scan that names its image in scanners.dockle.options records no
    # image on its findings, so the page's image-scoped entry never applies.
    report = _captured()

    assert "CIS-DI-0001" in _rules(report)
    assert _suppressed(tmp_path, report) == set()
