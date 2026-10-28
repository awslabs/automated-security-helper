# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The detect-secrets dependency check starts no uv.

The scanner scans with the in-process detect-secrets library (its worker is
``python -m automated_security_helper.utils.detect_secrets_worker``) and never
its CLI, so the check has nothing to ask uv. It used to run ``uv tool run
detect-secrets --version`` through ``get_uv_tool_command`` for one debug line:
under the unit tool guard that is a recorded tool start (tests/unit/conftest.py),
and online it resolved detect-secrets against the index for a tool never run.
"""

from __future__ import annotations

import subprocess


def test_the_dependency_check_asks_uv_for_nothing(monkeypatch, test_plugin_context):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
    )
    from automated_security_helper.utils import uv_tool_runner

    spawned = []

    def recording(args, **kwargs):
        spawned.append(list(args))
        return subprocess.CompletedProcess(list(args), 1, "", "")

    # A uv is present, so get_uv_tool_command would probe if it were asked;
    # the spawn is recorded instead of started.
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: "/stand-in/uv")
    monkeypatch.setattr(uv_tool_runner, "spawn_run", recording)

    scanner = DetectSecretsScanner(context=test_plugin_context)

    assert scanner.validate_plugin_dependencies() is True
    assert spawned == []
