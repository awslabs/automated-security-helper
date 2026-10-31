# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanner plugin carries the could-not-end records its executor reads.

The scan executor attributes a failed end to a run through
``scan_could_not_stop_runs``, and a reader that has to name every process reads
``scan_could_not_stop_history``. Both are declared on ``PluginBase`` and reach a
scanner by inheritance; ``scanner_plugin`` declares neither. A reader that
guarded its read because "the scanner base class lacks the attribute" would be
guarding a name that is there, so this pins where the names live: a scanner
built over the real init path answers both, empty before any run.
"""

from __future__ import annotations

import inspect

import pytest

from automated_security_helper.base.plugin_base import PluginBase
from automated_security_helper.base.scanner_plugin import ScannerPluginBase
from tests.unit.base.test_scanner_plugin_coverage import _scanner

pytestmark = pytest.mark.unit

RECORDS = (
    "scan_could_not_stop",
    "scan_could_not_stop_runs",
    "scan_could_not_stop_history",
)


@pytest.mark.parametrize("name", RECORDS)
def test_the_plugin_base_declares_each_record_and_the_scanner_inherits_it(name):
    declared = inspect.getattr_static(PluginBase, name)
    assert isinstance(declared, property)
    # Inherited as is: the scanner base does not declare a second copy.
    assert inspect.getattr_static(ScannerPluginBase, name) is declared


def test_a_scanner_answers_each_record_empty_before_any_run(plugin_context):
    scanner = _scanner(plugin_context)

    assert scanner.scan_could_not_stop is None
    assert scanner.scan_could_not_stop_runs == {}
    assert scanner.scan_could_not_stop_history == []
