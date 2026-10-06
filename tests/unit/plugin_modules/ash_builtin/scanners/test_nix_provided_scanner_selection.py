# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Under ``--mode nix`` a flake-supplied Python scanner runs as itself, or not at all.

The failure this guards: the flake's checkov is a nixpkgs wrapper (a bash
script exec'ing a bare-interpreter script that adds its closure to sys.path),
so the pre-installed check could not find its environment and called it
unverifiable. The scanner then kept ``uv tool run --offline --from
'checkov>=3.2.0,<4.0.0'``, which ran PyPI's checkov 3.3.25 instead of the
pinned 3.3.9, and only worked when an earlier online version probe had filled
uv's cache. On an arm runner that probe hit its timeout before numpy's wheel
arrived and the scan failed with "Failed to download `numpy==2.5.3`".

Only ``uv tool ...`` is faked, and every call to it is recorded. The wrapper,
its ``--version`` run, and the ``uv pip install --dry-run`` verdict are real.
"""

import os
import shutil
import subprocess
import sys
import venv
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
    CheckovScanner,
    CheckovScannerConfig,
)
from automated_security_helper.utils import subprocess_utils, uv_tool_runner
from automated_security_helper.utils.pre_installed_tool import (
    reset_pre_installed_tool_cache,
)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="nixpkgs wrappers are POSIX shell scripts"
)

BASH = shutil.which("bash") or "/bin/bash"

# What uv printed on the failing runner when the scan fell back to it.
UV_OFFLINE_NUMPY_FAILURE = (
    "error: Failed to download `numpy==2.5.3`\n"
    "  Caused by: Network connectivity is disabled, but the requested data "
    "wasn't found in the cache\n"
)


def _nix_checkov(root: Path, version: str, with_metadata: bool = True) -> Path:
    """The shape nixpkgs builds for checkov, at ``version``."""
    interpreter_root = root / "nix-python"
    venv.EnvBuilder(with_pip=False, symlinks=True).create(interpreter_root)
    interpreter = interpreter_root / "bin" / "python"

    package = root / "store" / f"checkov-{version}"
    site_packages = package / "lib" / "python3" / "site-packages"
    site_packages.mkdir(parents=True)
    if with_metadata:
        dist = site_packages / f"checkov-{version}.dist-info"
        dist.mkdir()
        (dist / "METADATA").write_text(
            f"Metadata-Version: 2.1\nName: checkov\nVersion: {version}\n"
        )

    bin_dir = package / "bin"
    bin_dir.mkdir()
    wrapped = bin_dir / ".checkov-wrapped"
    wrapped.write_text(
        f"#!{interpreter}\n"
        f"import sys;import site;import functools;sys.argv[0] = '{bin_dir / 'checkov'}';"
        "functools.reduce(lambda k, p: site.addsitedir(p, k), "
        f"['{site_packages}'], site._init_pathinfo());\n"
        f"print('{version}')\n"
    )
    wrapped.chmod(0o755)
    wrapper = bin_dir / "checkov"
    wrapper.write_text(
        f"#! {BASH} -e\n"
        "export PYTHONNOUSERSITE='true'\n"
        f'exec -a "$0" "{wrapped}"  "$@" \n'
    )
    wrapper.chmod(0o755)
    return wrapper


class UvToolRecorder:
    """Real subprocesses, except ``uv tool``: no tools installed, nothing cached."""

    def __init__(self, real_run):
        self.real_run = real_run
        self.uv_tool_calls: list[list[str]] = []

    def __call__(self, argv, *args, **kwargs):
        argv_s = [str(a) for a in argv]
        if Path(argv_s[0]).name in ("uv", "uv.exe") and argv_s[1:2] == ["tool"]:
            self.uv_tool_calls.append(argv_s)
            if argv_s[2:3] == ["list"]:
                return subprocess.CompletedProcess(
                    argv_s, 0, "No tools installed\n", ""
                )
            return subprocess.CompletedProcess(argv_s, 2, "", UV_OFFLINE_NUMPY_FAILURE)
        return self.real_run(argv, *args, **kwargs)

    @property
    def network_capable(self):
        """``uv tool run``/``install`` calls that could have fetched over the network."""
        return [
            c
            for c in self.uv_tool_calls
            if c[2:3] in (["run"], ["install"]) and "--offline" not in c
        ]

    @property
    def scan_resolves(self):
        """``uv tool run`` calls other than a version probe: the scan going through uv."""
        return [
            c for c in self.uv_tool_calls if c[2:3] == ["run"] and c[-1] != "--version"
        ]


@pytest.fixture(autouse=True)
def _fresh_caches():
    def reset():
        uv_tool_runner._reset_uv_tool_runner_caches()
        uv_tool_runner.reset_uv_tool_runner()
        subprocess_utils.clear_find_executable_cache()
        reset_pre_installed_tool_cache()

    reset()
    yield
    reset()


@pytest.fixture
def nix_mode(tmp_path, monkeypatch):
    """What the flake's dev shell hands ASH: ASH_OFFLINE and the store on PATH."""

    def make(version, with_metadata=True):
        if shutil.which("uv") is None:
            pytest.fail("uv is a runtime dependency of ASH and must be on PATH")
        wrapper = _nix_checkov(tmp_path / "nix", version, with_metadata)
        monkeypatch.setenv("PATH", f"{wrapper.parent}{os.pathsep}{os.environ['PATH']}")
        monkeypatch.setenv("ASH_OFFLINE", "YES")
        recorder = UvToolRecorder(subprocess.run)
        monkeypatch.setattr(subprocess, "run", recorder)
        return wrapper, recorder

    return make


@pytest.fixture
def plugin_context(tmp_path):
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "work",
        config=get_default_config(),
    )
    for d in (context.source_dir, context.output_dir, context.work_dir):
        d.mkdir(parents=True)
    return context


def test_the_pinned_checkov_runs_directly(nix_mode, plugin_context):
    wrapper, recorder = nix_mode("3.3.9")
    scanner = CheckovScanner(context=plugin_context, config=CheckovScannerConfig())

    assert scanner.validate_plugin_dependencies() is True
    assert scanner.use_uv_tool is False, (
        "the flake's checkov satisfies '>=3.2.0,<4.0.0' and must run as itself"
    )
    assert recorder.network_capable == []
    assert recorder.scan_resolves == []


def test_a_too_old_pinned_checkov_is_missing_with_the_version_named(
    nix_mode, plugin_context
):
    wrapper, recorder = nix_mode("3.1.0")
    scanner = CheckovScanner(context=plugin_context, config=CheckovScannerConfig())

    assert scanner.validate_plugin_dependencies() is False
    reason = scanner.dependency_unavailable_reason or ""
    assert f"checkov at {wrapper} cannot be used" in reason
    assert "installed checkov does not satisfy '>=3.2.0,<4.0.0'" in reason
    assert "Nix flake" in reason and "flake.nix" in reason
    assert "numpy" not in reason
    assert recorder.network_capable == [], (
        "nix mode must never reach for the network to replace a pinned tool"
    )
    assert recorder.scan_resolves == [], (
        "a uv substitute for the pinned checkov is the reported failure"
    )


def test_an_unverifiable_nix_checkov_is_missing_rather_than_substituted(
    nix_mode, plugin_context
):
    """A wrapper whose closure carries no metadata cannot be judged; fail closed."""
    wrapper, recorder = nix_mode("3.3.9", with_metadata=False)
    scanner = CheckovScanner(context=plugin_context, config=CheckovScannerConfig())

    assert scanner.validate_plugin_dependencies() is False
    reason = scanner.dependency_unavailable_reason or ""
    assert f"checkov at {wrapper} could not be verified" in reason
    assert "no distribution metadata" in reason
    assert recorder.network_capable == []
    assert recorder.scan_resolves == []
