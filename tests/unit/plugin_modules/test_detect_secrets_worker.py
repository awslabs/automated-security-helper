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

import pytest

from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScanSettingsFiltersUsed,
)
from tests.utils.refusing_proxy import (
    RecordingProxy,
    route_through,
    scrub_cloud_credentials,
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


#: AWS's documentation placeholder secret key, in parts so that this file holds no
#: key-shaped literal for ASH's own detect-secrets self-scan to report.
_SECRET_KEY_PARTS = ("wJalrXUtnFEMI/K7MDENG/", "bPxRfiCY", "EXAMPLEKEY")


def _verifying_worker_run(tmp_path, verify):
    """Run the worker on a key pair with the verification filter in its settings."""
    secret = "".join(_SECRET_KEY_PARTS)
    src = tmp_path / "src"
    src.mkdir()
    target = src / "creds.py"
    target.write_text(
        f'aws_access_key_id = "{AWS_KEY}"\naws_secret_access_key = "{secret}"\n',
        encoding="utf-8",
    )
    request = {
        "root": str(src),
        "baseline": None,
        "settings": {
            "plugins_used": [{"name": "AWSKeyDetector"}],
            "filters_used": [
                {
                    "path": "detect_secrets.filters.common.is_ignored_due_to_verification_policies",
                    "min_level": 2,
                }
            ],
        },
        "paths": [str(target)],
    }
    if verify is not None:
        request["verify"] = verify
    request_file = tmp_path / "request.json"
    output = tmp_path / "output.json"
    request_file.write_text(json.dumps(request), encoding="utf-8")
    subprocess.run(  # nosec B603 - fixed argv
        [
            sys.executable,
            "-m",
            "automated_security_helper.utils.detect_secrets_worker",
            str(request_file),
            str(output),
        ],
        check=True,
        cwd=tmp_path,
    )
    return json.loads(output.read_text(encoding="utf-8"))


@pytest.mark.parametrize("verify", [False, None], ids=["verify-false", "no-verify-key"])
def test_the_worker_sends_no_request_unless_the_scan_may_verify(
    tmp_path, monkeypatch, verify
):
    """The scanner removes the filter when verification may not run; the worker
    also refuses the requests, so a filter that reaches it anyway sends nothing.
    The secret is still reported, as unverified."""
    scrub_cloud_credentials(monkeypatch)
    proxy = RecordingProxy()
    route_through(monkeypatch, proxy)
    try:
        scanned = _verifying_worker_run(tmp_path, verify)
    finally:
        proxy.close()

    assert proxy.external_requests() == [], proxy.requests
    assert scanned and scanned[0][1], "the key was not reported"


def test_control_the_worker_verifies_when_the_scan_may(tmp_path, monkeypatch):
    """Control: with verify true the same run asks the issuer (the refusing local
    proxy answers), which shows the run above would have sent a request."""
    scrub_cloud_credentials(monkeypatch)
    proxy = RecordingProxy()
    route_through(monkeypatch, proxy)
    try:
        _verifying_worker_run(tmp_path, True)
    finally:
        proxy.close()

    assert any("sts.amazonaws.com" in line for line in proxy.external_requests()), (
        proxy.requests
    )
