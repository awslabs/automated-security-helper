# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for plugin discovery.

Covers bug H-NEW: the ASH_REPORTERS discovery list in ash_builtin omitted
GitLabSASTReporter and UnusedSuppressionsReporter even though both are
exported from the reporters package. Plugins outside this list are not
discovered at runtime.
"""

from automated_security_helper.plugin_modules.ash_builtin import ASH_REPORTERS
from automated_security_helper.plugin_modules.ash_builtin.reporters import (
    GitLabSASTReporter,
    UnusedSuppressionsReporter,
)


def test_gitlab_sast_reporter_is_discoverable():
    assert GitLabSASTReporter in ASH_REPORTERS


def test_unused_suppressions_reporter_is_discoverable():
    assert UnusedSuppressionsReporter in ASH_REPORTERS
