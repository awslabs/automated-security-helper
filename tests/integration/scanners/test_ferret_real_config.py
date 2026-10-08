# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Real ferret-scan: a ferret.yaml in the scanned tree is not loaded.

ferret-scan loads a ferret.yaml from its working directory when no --config is
given (2.5.3 says "using project config ferret.yaml found in the working
directory"). ASH always passes --config and runs it from the filesystem root
(FerretScanScanner._subprocess_cwd). Skipped when ferret-scan is not installed.
"""

import json
import os
import shutil
import subprocess

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScanScanner,
    FerretScannerConfig,
)

PluginContext.model_rebuild()

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.name == "nt", reason="POSIX paths"),
]

# An AWS example key from AWS's own documentation; ferret-scan reports it.
_SECRET = 'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
# Limits ferret-scan to SSN detection, which hides the finding above.
_ONLY_SSN = "defaults:\n  checks: SSN\n"


def _ferret() -> str:
    found = shutil.which("ferret-scan")
    if found is None:
        pytest.skip("ferret-scan is not installed")
    return found


def test_a_ferret_yaml_in_the_scanned_tree_is_not_loaded(tmp_path):
    ferret = _ferret()
    source = tmp_path / "src"
    source.mkdir()
    (source / "keys.txt").write_text(_SECRET)
    (source / "ferret.yaml").write_text(_ONLY_SSN)

    # The control: from the source directory with no --config, the file applies.
    control = subprocess.run(  # nosec B603 - fixed argv, ferret-scan from PATH
        [ferret, "--file", (source / "keys.txt").as_posix(), "--format", "json"],
        cwd=source,
        capture_output=True,
        text=True,
        check=False,
    )
    assert '"type"' not in control.stdout

    output = tmp_path / "out"
    output.mkdir()
    scanner = FerretScanScanner(
        context=PluginContext(source_dir=source, output_dir=output, config=AshConfig()),
        # Without the bundled config ASH used to pass no --config at all.
        config=FerretScannerConfig(options={"use_default_config": False}),
    )
    report = scanner.scan(target=source, target_type="source")
    results = [r for run in report.runs or [] for r in run.results or []]
    assert results, json.dumps(report.model_dump(mode="json", exclude_none=True))[:2000]
