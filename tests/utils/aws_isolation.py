# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Keep a test's AWS reporters from finding credentials or a reachable endpoint.

``isolate_from_aws`` is what the cloud reporter tests
(``tests/unit/plugin_modules/ash_aws_plugins/test_cloud_reporters_*.py``) use to
run a scan, ``ash report`` or ``ash merge`` with the AWS plugins loaded and
nothing able to reach AWS.
"""

from __future__ import annotations

from pathlib import Path

import pytest


def isolate_from_aws(monkeypatch: pytest.MonkeyPatch, root: Path) -> None:
    """Leave botocore no credentials and no reachable endpoint for the scan.

    Once a test in the process has imported ``ash_aws_plugins``, its reporters are
    registered, and the report phase builds each one. They default to disabled,
    so none calls ``validate_plugin_dependencies`` (Security Hub's ``DescribeHub``,
    the others' STS) unless a test enables it or a regression turns one back on;
    this covers both. Without credentials botocore stops before sending anything;
    the loopback endpoint is a second stop in case some provider still finds one.
    """
    import os

    for name in list(os.environ):
        if name.startswith("AWS_"):
            monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", str(root / "no-aws-config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(root / "no-aws-credentials"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.setenv("AWS_ENDPOINT_URL", "http://127.0.0.1:9")
