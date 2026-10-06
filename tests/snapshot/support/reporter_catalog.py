# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every reporter ASH ships, and how each one's snapshot is stored.

The names are written out rather than read from the registry on purpose. The reporter
snapshot tests parametrize over these names, and
``test_snapshot_reporters.py::test_every_registered_reporter_is_snapshotted`` asserts
the registry holds exactly this set. A reporter added to ASH therefore fails that
test until it is listed here, and once listed, fails its own snapshot test until a
snapshot of its output is committed. Neither step can be skipped by accident.
"""

from __future__ import annotations

from typing import Any

#: Reporters in ``plugin_modules/ash_builtin/reporters`` (``ASH_REPORTERS``).
BUILTIN_REPORTER_NAMES = (
    "csv",
    "cyclonedx",
    "flat-json",
    "github-ghas",
    "gitlab-cyclonedx",
    "gitlab-sast",
    "html",
    "junitxml",
    "markdown",
    "ocsf",
    "sarif",
    "spdx",
    "text",
    "unused-suppressions",
    "yaml",
)

#: Reporters in ``plugin_modules/ash_aws_plugins`` (``ASH_REPORTERS``).
AWS_REPORTER_NAMES = (
    "aws-security-hub",
    "bedrock-summary-reporter",
    "cloudwatch-logs",
    "s3",
)

#: The three model shapes every reporter is rendered against.
MODEL_VARIANTS = ("single", "workspace", "skipped-workspace")

#: Extensions a text snapshot may carry; see tests/snapshot/conftest.py.
SNAPSHOT_EXTENSIONS = frozenset(
    {"md", "html", "sarif", "csv", "xml", "json", "yaml", "txt"}
)


def reporter_classes() -> dict[str, type]:
    """Configured name -> class for every reporter both plugin packages export."""
    from automated_security_helper.plugin_modules.ash_aws_plugins import (
        ASH_REPORTERS as AWS_REPORTERS,
    )
    from automated_security_helper.plugin_modules.ash_builtin import (
        ASH_REPORTERS as BUILTIN_REPORTERS,
    )

    return {
        _default_config(cls).name: cls for cls in (*BUILTIN_REPORTERS, *AWS_REPORTERS)
    }


def _default_config(reporter_class: type) -> Any:
    """The config a reporter gives itself when constructed without one."""
    from automated_security_helper.base.plugin_context import PluginContext

    # Imported before PluginContext is constructed: its `config` field refers to
    # AshConfig by name and stays undefined until the config module is loaded.
    from automated_security_helper.config.ash_config import AshConfig

    from tests.snapshot.support.normalize import REPO_ROOT

    context = PluginContext(
        source_dir=REPO_ROOT, output_dir=REPO_ROOT, config=AshConfig()
    )
    return reporter_class(context=context).config


def snapshot_extension(reporter: Any) -> str:
    """The extension of the file ASH writes for ``reporter``: ``ash.<extension>``.

    The last suffix of the configured extension, so ``summary.md`` -> ``md`` and
    ``flat.json`` -> ``json``. The snapshot file then opens in the same viewer as
    the report, and a reviewer diffs the document a user would open.
    """
    extension = str(reporter.config.extension).rsplit(".", 1)[-1]
    if extension not in SNAPSHOT_EXTENSIONS:
        raise ValueError(
            f"reporter {reporter.config.name!r} writes .{extension}, which has no "
            f"snapshot extension; add it to SNAPSHOT_EXTENSIONS deliberately"
        )
    return extension


def build_reporter(reporter_class: type, context: Any) -> Any:
    """Instantiate a reporter the way ``ReportPhase._execute_phase`` does."""
    from automated_security_helper.base.plugin_config import plugin_config_key

    plugin_config = context.config.get_plugin_config(
        plugin_type="reporter", plugin_name=plugin_config_key(reporter_class)
    )
    return reporter_class(context=context, config=plugin_config)
