# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline, syft and grype do not hand a Go module to a Go toolchain that can download.

Measured with a fake ``go`` first on PATH that logs its argv: on a Go module, syft
(``golang.use-packages-lib``, on by default) and grype both ran
``go list -e -f {{context.ReleaseTags}} -- unsafe`` in an offline scan. A real toolchain
then resolves missing modules from GOPROXY (proxy.golang.org by default), and a
``go``/``toolchain`` line newer than the local Go downloads a toolchain
(GOTOOLCHAIN=auto). ``SYFT_GOLANG_USE_PACKAGES_LIB=false`` stops syft running ``go``;
grype has no such setting, so ``GOPROXY=off`` and ``GOTOOLCHAIN=local`` keep the
toolchain it runs from downloading.

The first tests read the environment the scanners hand their tool. The last one runs
a real syft, when one is installed, against a module with a fake ``go`` on PATH.
"""

import os
import shutil
import sys
from typing import Dict, List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.grype_scanner import (
    GrypeScanner,
    GrypeScannerConfig,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.syft_scanner import (
    SyftScanner,
    SyftScannerConfig,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.offline_tool_env import offline_tool_environment
from tests.utils.refusing_proxy import (
    RecordingProxy,
    route_through,
    scrub_cloud_credentials,
)

GO_IS_LOCAL = {
    "GOPROXY": "off",
    "GOTOOLCHAIN": "local",
}


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    for name in ("GOPROXY", "GOTOOLCHAIN", "SYFT_GOLANG_USE_PACKAGES_LIB"):
        monkeypatch.delenv(name, raising=False)
    return monkeypatch


@pytest.fixture
def context(tmp_path) -> PluginContext:
    ctx = PluginContext(
        source_dir=tmp_path / "repo",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    for directory in (ctx.source_dir, ctx.output_dir, ctx.work_dir):
        directory.mkdir(parents=True, exist_ok=True)
    (ctx.source_dir / "go.mod").write_text(
        "module example.com/m\n\ngo 1.21\n\nrequire github.com/google/uuid v1.6.0\n"
    )
    (ctx.source_dir / "main.go").write_text(
        'package main\n\nimport _ "github.com/google/uuid"\n\nfunc main() {}\n'
    )
    return ctx


def _scan_envs(scanner, ctx, monkeypatch) -> List[Dict[str, str]]:
    envs: List[Dict[str, str]] = []

    def record(command, *args, **kwargs):
        if any(ctx.source_dir.as_posix() in str(part) for part in command):
            env = kwargs.get("env")
            envs.append(dict(env) if env is not None else dict(os.environ))
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", record)
    monkeypatch.setattr(
        type(scanner), "validate_plugin_dependencies", lambda self: True
    )
    try:
        scanner.scan(target=ctx.source_dir, target_type="source")
    except Exception:
        pass  # no tool ran, so there is no result file to read
    assert envs, "the scanner started no scan of the source directory"
    return envs


def test_offline_environment_keeps_go_tooling_local(offline):
    env = offline_tool_environment()

    assert env.get("SYFT_GOLANG_USE_PACKAGES_LIB") == "false"
    for name, value in GO_IS_LOCAL.items():
        assert env.get(name) == value, name


def test_offline_syft_does_not_use_the_go_toolchain(offline, context):
    envs = _scan_envs(
        SyftScanner(context=context, config=SyftScannerConfig()), context, offline
    )

    for env in envs:
        assert env.get("SYFT_GOLANG_USE_PACKAGES_LIB") == "false"
        for name, value in GO_IS_LOCAL.items():
            assert env.get(name) == value, name


def test_offline_grype_keeps_the_go_toolchain_local(offline, context):
    """grype runs ``go list`` with no setting to stop it; the toolchain stays local."""
    envs = _scan_envs(
        GrypeScanner(context=context, config=GrypeScannerConfig()), context, offline
    )

    for env in envs:
        for name, value in GO_IS_LOCAL.items():
            assert env.get(name) == value, name


@pytest.mark.skipif(
    sys.platform == "win32", reason="the fake go is a POSIX shell script"
)
@pytest.mark.skipif(shutil.which("syft") is None, reason="needs a syft binary on PATH")
def test_a_real_offline_syft_runs_no_go_command(offline, context, tmp_path):
    """syft itself, with a ``go`` first on PATH that records every invocation."""
    scrub_cloud_credentials(offline)
    proxy = RecordingProxy()
    route_through(offline, proxy)
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    calls = tmp_path / "go-calls.log"
    go = fake_bin / "go"
    go.write_text(f'#!/bin/sh\necho "$@" >> "{calls.as_posix()}"\nexit 1\n')
    go.chmod(0o755)
    offline.setenv("PATH", f"{fake_bin}{os.pathsep}{os.environ['PATH']}")
    offline.setenv("SYFT_CACHE_DIR", str(tmp_path / "syft-cache"))
    subprocess_utils.clear_find_executable_cache()
    try:
        scanner = SyftScanner(context=context, config=SyftScannerConfig())
        assert scanner.validate_plugin_dependencies() is True
        scanner.scan(target=context.source_dir, target_type="source")
    finally:
        proxy.close()
        subprocess_utils.clear_find_executable_cache()

    assert not calls.exists(), (
        f"offline syft ran the Go toolchain: {calls.read_text().splitlines()}"
    )
    assert proxy.external_requests() == [], proxy.requests
