# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""detect-secrets runs in a worker subprocess so the scanner sandbox can wrap it.

Pins the two things the move has to preserve: the worker reports the same
collection the in-process scan built (same keys, same secrets), and the scanner
asks the sandbox for a network only when its settings verify secrets online.
"""

import json
import subprocess
import sys

from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScanSettingsFiltersUsed,
)

AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # pragma: allowlist secret


def _in_process(root, paths, settings):
    from detect_secrets.core.secrets_collection import SecretsCollection
    from detect_secrets.settings import transient_settings

    collection = SecretsCollection()
    collection.root = str(root)
    with transient_settings(settings):
        collection.scan_files(*paths)
    return {
        key: sorted(json.dumps(s.json(), sort_keys=True) for s in secrets)
        for key, secrets in collection.data.items()
    }


def test_worker_reports_the_collection_the_in_process_scan_builds(tmp_path):
    src = tmp_path / "src"
    (src / "a").mkdir(parents=True)
    (src / "a" / "one.py").write_text(f'key = "{AWS_KEY}"\n', encoding="utf-8")
    (src / "two.py").write_text(f'\n\nother = "{AWS_KEY}"\n', encoding="utf-8")
    paths = [str(p) for p in sorted(src.rglob("*.py"))]
    settings = {"plugins_used": [{"name": "AWSKeyDetector"}]}

    request = tmp_path / "request.json"
    output = tmp_path / "output.json"
    request.write_text(
        json.dumps(
            {"root": str(src), "baseline": None, "settings": settings, "paths": paths}
        ),
        encoding="utf-8",
    )
    subprocess.run(  # nosec B603 - fixed argv
        [
            sys.executable,
            "-m",
            "automated_security_helper.utils.detect_secrets_worker",
            str(request),
            str(output),
        ],
        check=True,
        cwd=tmp_path,
    )
    from_worker = {
        key: sorted(json.dumps(s, sort_keys=True) for s in secrets)
        for key, secrets in json.loads(output.read_text(encoding="utf-8"))
    }

    expected = _in_process(src, paths, settings)
    assert expected, "the fixture should contain findings"
    assert from_worker == expected


def _scanner(tmp_path):
    ctx = PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    return DetectSecretsScanner(context=ctx, config=DetectSecretsScannerConfig())


def test_no_network_unless_secrets_are_verified_online(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    scanner = _scanner(tmp_path)
    assert scanner.sandbox_requirements.network is False
    assert isinstance(scanner.sandbox_requirements, SandboxRequirements)

    scanner.config.options.scan_settings.filters_used = [
        DetectSecretsScanSettingsFiltersUsed(
            path="detect_secrets.filters.common.is_ignored_due_to_verification_policies",
            min_level=2,
        )
    ]
    assert scanner.sandbox_requirements.network is True
