# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The detect-secrets worker scans under bwrap and Landlock from its own start directory.

The worker used to start in the scanner's results directory. It now starts in an
empty directory created under its work directory for each scan
(``utils/python_child.py``), which a sandboxed process can only use if the policy
lets it see that directory. This runs the real scanner under each backend over a
tree with a planted credential and a planted ``automated_security_helper/`` package:
the credential must be found, and the package must not be imported.

Skipped when a backend cannot start a sandbox, unless ASH_REQUIRE_SANDBOX_BACKENDS
names it, which the sandbox CI job does.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
)
from automated_security_helper.utils.sandbox.backends import (
    BwrapBackend,
    LandlockBackend,
)
from automated_security_helper.utils.sandbox.scope import SandboxScope, sandbox_scope

pytestmark = pytest.mark.integration

#: AWS's documentation placeholder, assembled so this file holds no key-shaped text.
PLANTED_KEY = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002


def _require(backend):
    reason = backend.probe()
    if reason:
        required = os.environ.get("ASH_REQUIRE_SANDBOX_BACKENDS", "").split(",")
        if backend.name in [name.strip() for name in required]:
            pytest.fail(
                f"{backend.name} is required (ASH_REQUIRE_SANDBOX_BACKENDS) but: {reason}"
            )
        pytest.skip(f"{backend.name} unavailable: {reason}")
    return backend


@pytest.mark.parametrize(
    "backend_class", [BwrapBackend, LandlockBackend], ids=["bwrap", "landlock"]
)
def test_the_worker_scans_from_its_own_start_directory_under_the_sandbox(
    tmp_path, monkeypatch, backend_class
):
    backend = _require(backend_class())
    source = tmp_path / "src"
    output = source / ".ash" / "ash_output"
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )
    for directory in (context.source_dir, context.output_dir, context.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    results_dir = Path(scanner.results_dir)

    (source / "settings.py").write_text(
        f"AWS_ACCESS_KEY_ID = '{PLANTED_KEY}'\n", encoding="utf-8"
    )
    marker = tmp_path / "IMPORTED"
    for directory in (source, results_dir):
        package = directory / "automated_security_helper"
        package.mkdir(parents=True, exist_ok=True)
        (package / "__init__.py").write_text(
            f"open({str(marker)!r}, 'a').write('imported')\n", encoding="utf-8"
        )

    scope = SandboxScope(
        backend=backend,
        scanner_name="detect-secrets",
        requirements=scanner.sandbox_requirements,
        source_dir=source,
        output_dir=output,
        results_dir=results_dir,
        scan_target=source,
        offline=True,
    )
    monkeypatch.delenv("PYTHONSAFEPATH", raising=False)
    monkeypatch.chdir(source)
    with sandbox_scope(scope):
        report = scanner.scan(target=source, target_type="source")

    # The planted package's marker path can also read as a high-entropy string.
    rules = [result.ruleId for result in report.runs[0].results]
    assert "SECRET-AWS-ACCESS-KEY" in rules, rules
    assert not marker.exists(), "the worker imported the planted package"
    leftovers = [p.name for p in (results_dir / "source").glob("ash-child-*")]
    assert leftovers == [], f"start directories left behind: {leftovers}"
