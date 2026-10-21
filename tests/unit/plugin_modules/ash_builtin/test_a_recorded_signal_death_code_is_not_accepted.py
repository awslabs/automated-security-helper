# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A recorded signal death's negative code is not accepted by any scanner.

A child killed by a signal records the negative code the runner saw (-9 for
a SIGKILL), and that sign is the record's meaning: the tool never returned.
These cells pin the grading seam against the two normalizations that would
erase it. Taking the magnitude would turn -9 into 9, which cfn_nag's band
reads as a violation count and npm audit's 0-31 band accepts outright.
Defaulting a falsy code to 0 would turn an absent code into the accepted 0.
Either way a killed run whose targets were all counted evaluated would
render as a successful execution, so the cells grade a -9 directly: with
every attempted target counted evaluated, the verdict must still be
refusal, for a wide band (cfn_nag) and a narrow one (npm audit) alike.
"""

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
    CfnNagScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.npm_audit_scanner import (
    NpmAuditScanner,
    NpmAuditScannerConfig,
)


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    context.work_dir.mkdir(parents=True)
    return context


@pytest.fixture
def cfn_scanner(plugin_context):
    return CfnNagScanner(context=plugin_context, config=CfnNagScannerConfig())


@pytest.fixture
def npm_scanner(plugin_context):
    return NpmAuditScanner(context=plugin_context, config=NpmAuditScannerConfig())


@pytest.mark.parametrize("scanner_fixture", ["cfn_scanner", "npm_scanner"])
def test_a_recorded_signal_death_code_is_not_an_accepted_execution(
    request, scanner_fixture
):
    scanner = request.getfixturevalue(scanner_fixture)
    scanner.exit_code = -9
    scanner.targets_attempted = 3
    scanner.targets_failed = 0

    assert scanner._sarif_execution_successful() is False
