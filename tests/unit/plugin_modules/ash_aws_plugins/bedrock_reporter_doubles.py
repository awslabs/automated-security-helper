# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""One way to build a Bedrock summary reporter for every test in this directory.

Three test modules each built the reporter their own way: from an options object
carrying a placeholder model, from a PluginContext made out of an output
directory, and from the default config with its options set after construction.
A change to how the reporter is constructed then had three places to miss. This
module is the one place. ``make_reporter`` builds the reporter from a
PluginContext and option overrides; ``plugin_context_in`` builds a PluginContext
whose source, output and work directories all sit under one directory, for tests
that work from a ``tmp_path``.

This is not a test file (pytest collects ``test_*.py`` only), so it defines no
test and carries no tier marker.

No account ids and no real model ARNs appear below; model ids are opaque
placeholders, which is all the code under test treats them as.
"""

from __future__ import annotations

from pathlib import Path

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter import (
    BedrockSummaryReporter,
    BedrockSummaryReporterConfig,
    BedrockSummaryReporterConfigOptions,
)

#: The reporter's module path, for monkeypatching its boto3 boundary.
MODULE = (
    "automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_summary_reporter"
)

#: The region every test reporter is configured with.
REGION = "us-east-1"

# Opaque placeholders. The reporter only ever compares or forwards these.
PRIMARY_MODEL = "test-vendor.test-model-primary-v1:0"
FALLBACK_ONE = "test-vendor.test-model-fallback-1-v1:0"
FALLBACK_TWO = "test-vendor.test-model-fallback-2-v1:0"

AshAggregatedResults.model_rebuild()
BedrockSummaryReporterConfig.model_rebuild()
BedrockSummaryReporter.model_rebuild()


def make_reporter(context: PluginContext, **option_overrides) -> BedrockSummaryReporter:
    """A reporter on *context* configured with ``REGION`` and ``PRIMARY_MODEL``,
    with *option_overrides* applied on top of them: an override of
    ``aws_region`` or ``model_id`` replaces the default rather than raising
    the "multiple values for keyword argument" TypeError two keyword sets
    would, so a test that needs its own model id builds its reporter here too.

    The boto3 boundary is not patched here. A test patches
    ``<MODULE>.boto3.Session`` before it calls this (the ``runtime`` fixtures
    do), so nothing reaches AWS.
    """
    options = BedrockSummaryReporterConfigOptions(
        **{"aws_region": REGION, "model_id": PRIMARY_MODEL, **option_overrides}
    )
    return BedrockSummaryReporter(
        context=context, config=BedrockSummaryReporterConfig(options=options)
    )


def plugin_context_in(directory: Path) -> PluginContext:
    """A PluginContext whose source and output directories are *directory* and
    whose work directory is ``directory / "work"``, with a default AshConfig."""
    return PluginContext(
        source_dir=directory,
        output_dir=directory,
        work_dir=directory / "work",
        config=AshConfig(),
    )
