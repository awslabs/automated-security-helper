# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Real checkov, real ``--skip-path``: ASH's output directory is not scanned.

The unit tests check the pattern against checkov's matching rule as read from
its source. This runs checkov itself, so a change in how checkov applies
``--skip-path`` shows up here rather than as ASH scanning its own reports again.
"""

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
    CheckovScannerConfigOptions,
)

PluginContext.model_rebuild()

pytestmark = pytest.mark.integration

# Fails CKV_AWS_20 (public-read ACL), so a scan that reads it reports a finding.
_INSECURE_BUCKET = """
resource "aws_s3_bucket" "b" {
  bucket = "example"
  acl    = "public-read"
}
"""


def _uris(report):
    return [
        location.physicalLocation.root.artifactLocation.uri or ""
        for run in report.runs or []
        for result in run.results or []
        for location in result.locations or []
    ]


@pytest.mark.parametrize("skip", [True, False])
def test_findings_in_the_output_dir_follow_the_option(tmp_path, skip):
    source = tmp_path / "src"
    output = source / "ash-out"
    (output / "reports").mkdir(parents=True)
    (output / "reports" / "copied.tf").write_text(_INSECURE_BUCKET)
    (source / "main.tf").write_text(_INSECURE_BUCKET)

    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    scanner = CheckovScanner(
        context=context,
        config=CheckovScannerConfig(
            options=CheckovScannerConfigOptions(
                frameworks=["terraform"], skip_ash_output_dir=skip
            )
        ),
    )
    report = scanner.scan(target=source, target_type="source")

    uris = _uris(report)
    # The control: the copy outside the output dir is found either way, so an
    # empty report cannot pass for a skipped directory.
    assert any(u.endswith("main.tf") and "ash-out" not in u for u in uris), uris
    under_output = [u for u in uris if "ash-out/" in u]
    if skip:
        assert under_output == [], under_output
    else:
        assert under_output, f"with the option off the copy is scanned: {uris}"
