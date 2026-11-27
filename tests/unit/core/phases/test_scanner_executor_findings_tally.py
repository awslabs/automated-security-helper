# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The executor's findings-list tally counts what the one-finding-at-a-time loop did.

``_oracle_tally`` below is that loop as it was written before the tally moved onto
``utils.count_frame``, kept verbatim as an oracle: a fresh ``ScannerSeverityCount``
incremented once per finding at the level ``_finding_severity_level`` names, and
``finding_count`` the length of the list. The executor is driven end to end through
``_execute_scanner`` over a returned ``{"findings": [...]}`` dict, and its row must
agree with the oracle on:

* ``severity_counts.model_dump(exclude_unset=True)``, the fields a dump carries,
* ``severity_counts.model_fields_set``, the fields the counts marked set,
* ``finding_count``.

The finding values are the awkward ones: entries that are not mappings, ``None``, a
missing or empty severity, aliases and mixed case, names ASH cannot place, whole
numbers, scores, ``nan``, numbers written as text, and booleans.
"""

from __future__ import annotations

import math
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
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.phases.scanner_executor import (
    ScannerExecutor,
    _finding_severity_level,
)
from automated_security_helper.models.asharp_model import (
    AshAggregatedResults,
    ScannerSeverityCount,
)

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


# ---------------------------------------------------------------------------
# the oracle: the tally as it was, one finding at a time
# ---------------------------------------------------------------------------


def _oracle_tally(findings):
    counted = ScannerSeverityCount()
    for finding in findings:
        counted.increment(
            _finding_severity_level(
                finding.get("severity") if isinstance(finding, dict) else None
            )
        )
    return counted, len(findings)


# ---------------------------------------------------------------------------
# the executor, driven end to end
# ---------------------------------------------------------------------------


class _Config(ScannerPluginConfigBase):
    name: Literal["tally-tool"] = "tally-tool"


class _FindingsScanner(ScannerPluginBase):
    """Overrides ``scan()`` and returns the findings dict it was given."""

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED

    def model_post_init(self, context):
        self.command = "tally-tool"
        self.tool_type = ScannerToolType.SAST
        super().model_post_init(context)

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(self, target, target_type, global_ignore_paths):
        raise NotImplementedError("scan() is overridden directly")

    def scan(self, target, target_type, global_ignore_paths=None, config=None):
        self._pre_scan(target=target, target_type=target_type, config=config)
        self._post_scan(target=target, target_type=target_type)
        return self.returned


@pytest.fixture
def plugin_context(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="tally"),
    )


def _row(plugin_context, findings):
    config = _Config()
    config.options.severity_threshold = "MEDIUM"
    scanner = _FindingsScanner(config=config, context=plugin_context)
    scanner.returned = {"findings": findings}
    executor = ScannerExecutor(
        plugin_context=plugin_context, progress_display=MagicMock(), scanner_tasks=[]
    )
    targets = [{"path": Path(plugin_context.source_dir), "type": "source"}]
    (row,) = executor._execute_scanner("tally-tool", scanner, targets)
    return row


def _observed(counts):
    return counts.model_dump(exclude_unset=True), set(counts.model_fields_set)


# The findings lists, each a case. Single-entry lists pin one value's level; the
# longer ones pin the order-independent sums and the mixed kinds.
CASES = {
    "empty list": [],
    "non-dict entry": [7],
    "string entry": ["high"],
    "none entry": [None],
    "list entry": [["high"]],
    "missing severity": [{"rule": "x"}],
    "severity none": [{"severity": None}],
    "empty severity": [{"severity": ""}],
    "blank severity": [{"severity": "   "}],
    "critical": [{"severity": "critical"}],
    "high": [{"severity": "high"}],
    "medium": [{"severity": "medium"}],
    "low": [{"severity": "low"}],
    "info": [{"severity": "info"}],
    "upper case": [{"severity": "HIGH"}],
    "mixed case": [{"severity": "CrItIcAl"}],
    "padded": [{"severity": "  Low  "}],
    "alias moderate": [{"severity": "Moderate"}],
    "alias important": [{"severity": "IMPORTANT"}],
    "alias blocker": [{"severity": " blocker "}],
    "alias informational": [{"severity": "Informational"}],
    "unknown error": [{"severity": "error"}],
    "unknown severe": [{"severity": "severe"}],
    "unknown name": [{"severity": "catastrophic"}],
    "unknown unicode": [{"severity": "ßevere"}],
    "int 1": [{"severity": 1}],
    "int 3": [{"severity": 3}],
    "int 9": [{"severity": 9}],
    "float 0.0": [{"severity": 0.0}],
    "float 3.9": [{"severity": 3.9}],
    "float 9.8": [{"severity": 9.8}],
    "float 11.0": [{"severity": 11.0}],
    "float nan": [{"severity": math.nan}],
    "text 9.8": [{"severity": "9.8"}],
    "text 3": [{"severity": "3"}],
    "text 1_0": [{"severity": "1_0"}],
    "bool true": [{"severity": True}],
    "bool false": [{"severity": False}],
    "mixed": [
        {"severity": "high"},
        7,
        {"severity": "HIGH"},
        {"severity": "Important"},
        {"rule": "x"},
        {"severity": 9.8},
        {"severity": "catastrophic"},
        None,
        {"severity": "low"},
        {"severity": "info"},
    ],
    "many of one": [{"severity": "medium"}] * 40,
}


@pytest.mark.parametrize("name", sorted(CASES), ids=sorted(CASES))
def test_the_row_agrees_with_the_oracle(plugin_context, name):
    findings = CASES[name]
    expected, expected_count = _oracle_tally(findings)

    row = _row(plugin_context, findings)

    assert _observed(row.severity_counts) == _observed(expected)
    assert row.finding_count == expected_count
    assert "severity_counts" in row.model_fields_set


def test_an_alias_is_counted_under_the_level_it_names(plugin_context):
    """Pinned apart from the oracle: ``blocker`` is critical, ``Moderate`` medium."""
    row = _row(plugin_context, [{"severity": "blocker"}, {"severity": "Moderate"}])

    assert row.severity_counts.critical == 1
    assert row.severity_counts.medium == 1
    assert row.severity_counts.info == 0
    assert row.finding_count == 2


def test_an_empty_list_sets_no_count(plugin_context):
    row = _row(plugin_context, [])

    assert row.severity_counts.model_fields_set == set()
    assert row.finding_count == 0
