# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline, trivy-repo does not run trivy's Terraform checks, which download modules.

trivy's Terraform scanner fetches the source of every ``module`` block it evaluates,
whatever offline flags it is given (measured with trivy 0.75.0, every offline flag
ASH passes plus ``--tf-exclude-downloaded-modules``): a registry source contacted
registry.terraform.io, a ``git::https://`` source ran the host's ``git`` against
github.com, and an ``https://`` archive source fetched it. The scanned repository
chooses those URLs. trivy has no setting that stops it, so offline ASH passes
``--misconfig-scanners`` with trivy's own default list minus ``terraform``, read
from ``trivy <subcommand> --help`` so the list matches the installed trivy. When the
list cannot be read, the misconfiguration scanner is not run offline at all.
"""

import os
from pathlib import Path
from typing import List

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    _trivy_scanner_base as trivy_base,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
    TrivyScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins import (
    trivy_repo_scanner,
)
from automated_security_helper.plugin_modules.ash_trivy_plugins.trivy_repo_scanner import (
    TrivyRepoScanner,
    TrivyRepoScannerConfig,
    TrivyRepoScannerConfigOptions,
)
from automated_security_helper.utils import subprocess_utils
from automated_security_helper.utils.config_trust import record_provenance
from tests.utils.helpers import require_scanner_binary
from tests.utils.refusing_proxy import (
    RecordingProxy,
    route_through,
    scrub_cloud_credentials,
)

#: The --misconfig-scanners line of `trivy repository --help`, trivy 0.75.0.
TRIVY_HELP = (
    "      --misconfig-scanners strings        comma-separated list of misconfig "
    "scanners to use for misconfiguration scanning (default [azure-arm,cloudformation,"
    "dockerfile,helm,kubernetes,terraform,terraformplan-json,terraformplan-snapshot,"
    "ansible])\n"
)
FULL_DEFAULTS = [
    "azure-arm",
    "cloudformation",
    "dockerfile",
    "helm",
    "kubernetes",
    "terraform",
    "terraformplan-json",
    "terraformplan-snapshot",
    "ansible",
]
WITHOUT_TERRAFORM = [
    "azure-arm",
    "cloudformation",
    "dockerfile",
    "helm",
    "kubernetes",
    "terraformplan-json",
    "terraformplan-snapshot",
    "ansible",
]

MODULE_SOURCES = (
    'module "registry" {\n  source = "terraform-aws-modules/vpc/aws"\n}\n'
    'module "git" {\n'
    '  source = "git::https://github.com/terraform-aws-modules/terraform-aws-vpc.git"\n'
    "}\n"
    'resource "aws_s3_bucket" "b" {\n  bucket = "example"\n}\n'
)


@pytest.fixture
def offline(monkeypatch):
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    monkeypatch.delenv("TRIVY_CONFIG", raising=False)
    return monkeypatch


@pytest.fixture
def online(monkeypatch):
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    monkeypatch.delenv("TRIVY_CONFIG", raising=False)
    # Online, trivy and trivy-repo update trivy's database before the scan, which
    # needs trivy itself and the network; these tests read the scan's argv.
    monkeypatch.setattr(trivy_base, "prepare_content_db", lambda *a, **k: None)
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
    (ctx.source_dir / "tf").mkdir()
    (ctx.source_dir / "tf" / "main.tf").write_text(MODULE_SOURCES)
    return ctx


def _values(command: List[str], flag: str) -> List[str]:
    found = []
    for index, arg in enumerate(command):
        if arg.startswith(f"{flag}="):
            found.append(arg.split("=", 1)[1])
        elif arg == flag and index + 1 < len(command):
            found.append(command[index + 1])
    return found


def _scan_command(scanner, ctx, monkeypatch, target_type="source") -> List[str]:
    target = ctx.source_dir if target_type == "source" else ctx.work_dir
    (ctx.work_dir / "converted.tf").write_text(MODULE_SOURCES)
    commands: List[List[str]] = []

    def record(command, *args, **kwargs):
        commands.append([str(part) for part in command])
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", record)
    monkeypatch.setattr(
        type(scanner), "validate_plugin_dependencies", lambda self: True
    )
    try:
        scanner.scan(target=target, target_type=target_type)
    except Exception:
        pass  # no tool ran, so there is no result file to read
    scans = [c for c in commands if any(target.as_posix() in part for part in c)]
    assert scans, commands
    return scans[-1]


def _trivy(ctx) -> TrivyRepoScanner:
    return TrivyRepoScanner(
        context=ctx,
        config=TrivyRepoScannerConfig(options=TrivyRepoScannerConfigOptions()),
    )


@pytest.mark.parametrize("target_type", ["source", "converted"])
def test_offline_trivy_leaves_out_its_terraform_checks(offline, context, target_type):
    offline.setattr(
        trivy_repo_scanner,
        "trivy_default_misconfig_scanners",
        lambda *args, **kwargs: list(FULL_DEFAULTS),
        raising=False,
    )

    command = _scan_command(_trivy(context), context, offline, target_type)

    chosen = _values(command, "--misconfig-scanners")
    assert chosen, f"offline trivy runs its Terraform checks: {command}"
    assert chosen[-1].split(",") == WITHOUT_TERRAFORM


def test_offline_trivy_runs_no_misconfig_checks_when_their_list_is_unknown(
    offline, context
):
    """Fail closed: without trivy's own list, ASH cannot name one that leaves out
    Terraform, and an unknown value makes trivy fall back to all of them."""
    offline.setattr(
        trivy_repo_scanner,
        "trivy_default_misconfig_scanners",
        lambda *args, **kwargs: None,
        raising=False,
    )

    command = _scan_command(_trivy(context), context, offline)

    scanners = ",".join(_values(command, "--scanners")).split(",")
    assert "misconfig" not in scanners, command
    assert "vuln" in scanners, command


def _refusal(scanner, ctx, monkeypatch):
    """The error ``scan`` raised, and the trivy scans it started (expected none)."""
    from automated_security_helper.core.exceptions import ScannerError

    commands: List[List[str]] = []

    def record(command, *args, **kwargs):
        commands.append([str(part) for part in command])
        return {"returncode": 0, "stdout": "", "stderr": ""}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", record)
    monkeypatch.setattr(
        type(scanner), "validate_plugin_dependencies", lambda self: True
    )
    with pytest.raises(ScannerError) as raised:
        scanner.scan(target=ctx.source_dir, target_type="source")
    scans = [c for c in commands if any(ctx.source_dir.as_posix() in p for p in c)]
    return raised.value, scans


def test_offline_misconfig_only_trivy_refuses_without_the_list(offline, context):
    """With misconfig the only scanner and its list unknown, nothing is left to run.

    Dropping misconfig would hand trivy an empty --scanners; running it would let
    the Terraform checks download module sources. So the scan is refused.
    """
    offline.setattr(
        trivy_repo_scanner,
        "trivy_default_misconfig_scanners",
        lambda *args, **kwargs: None,
        raising=False,
    )
    scanner = TrivyRepoScanner(
        context=context,
        config=TrivyRepoScannerConfig(
            options=TrivyRepoScannerConfigOptions(scanners=["misconfig"])
        ),
    )

    error, scans = _refusal(scanner, context, offline)

    assert scans == [], scans
    assert "misconfiguration checks" in str(error)


@pytest.mark.parametrize(
    "variable", ["TRIVY_CONFIG", "TRIVY_IGNOREFILE", "TRIVY_SECRET_CONFIG"]
)
def test_an_operator_input_that_is_not_a_file_refuses_the_scan(
    online, context, tmp_path, variable
):
    """A directory where the operator named a file: trivy is not run without it."""
    directory = tmp_path / "operator-directory"
    directory.mkdir()
    online.setenv(variable, str(directory))

    error, scans = _refusal(_trivy(context), context, online)

    assert scans == [], scans
    assert variable in str(error) and "not a file" in str(error), error


def test_control_online_trivy_keeps_its_terraform_checks(online, context):
    command = _scan_command(_trivy(context), context, online)

    assert _values(command, "--misconfig-scanners") == []
    assert "misconfig" in ",".join(_values(command, "--scanners")).split(",")


# ---------------------------------------------------------------------------
# The builtin trivy, which runs misconfig only when the operator asks for it
# ---------------------------------------------------------------------------


def _builtin_trivy(ctx, scanners) -> TrivyScanner:
    # Built from no config file in the tree, so the scanner set is the operator's
    # (TrivyScanner._honor_scanner_set keeps it).
    record_provenance(ctx.config, in_tree=[])
    return TrivyScanner(
        context=ctx,
        config=TrivyScannerConfig(
            enabled=True, options=TrivyScannerConfigOptions(scanners=scanners)
        ),
    )


@pytest.mark.parametrize("target_type", ["source", "converted"])
def test_offline_builtin_trivy_leaves_out_its_terraform_checks(
    offline, context, target_type
):
    offline.setattr(
        trivy_base,
        "trivy_default_misconfig_scanners",
        lambda *args, **kwargs: list(FULL_DEFAULTS),
        raising=False,
    )
    scanner = _builtin_trivy(context, ["vuln", "misconfig"])

    command = _scan_command(scanner, context, offline, target_type)

    chosen = _values(command, "--misconfig-scanners")
    assert chosen, f"offline trivy runs its Terraform checks: {command}"
    assert chosen[-1].split(",") == WITHOUT_TERRAFORM


def test_offline_builtin_trivy_runs_no_misconfig_checks_when_their_list_is_unknown(
    offline, context
):
    offline.setattr(
        trivy_base,
        "trivy_default_misconfig_scanners",
        lambda *args, **kwargs: None,
        raising=False,
    )
    scanner = _builtin_trivy(context, ["vuln", "misconfig"])

    command = _scan_command(scanner, context, offline)

    scanners = ",".join(_values(command, "--scanners")).split(",")
    assert "misconfig" not in scanners, command
    assert "vuln" in scanners, command


def test_control_online_builtin_trivy_keeps_its_terraform_checks(online, context):
    scanner = _builtin_trivy(context, ["vuln", "misconfig"])

    command = _scan_command(scanner, context, online)

    assert _values(command, "--misconfig-scanners") == []
    assert "misconfig" in ",".join(_values(command, "--scanners")).split(",")


def test_the_default_list_is_read_from_trivys_help(monkeypatch):
    seen = []

    class _Result:
        returncode = 0
        stdout = "Flags:\n" + TRIVY_HELP
        stderr = ""

    def fake_run(args, **kwargs):
        seen.append(list(args))
        return _Result()

    monkeypatch.setattr(subprocess_utils, "run_command", fake_run)
    trivy_repo_scanner.reset_trivy_default_misconfig_scanners()
    try:
        listed = trivy_repo_scanner.trivy_default_misconfig_scanners(
            "trivy", ["repository"]
        )
    finally:
        trivy_repo_scanner.reset_trivy_default_misconfig_scanners()

    assert listed == FULL_DEFAULTS
    assert seen and seen[0][1:] == ["repository", "--help"]


def _reset_list_cache() -> None:
    reset = getattr(trivy_repo_scanner, "reset_trivy_default_misconfig_scanners", None)
    if reset is not None:
        reset()


def test_a_real_offline_trivy_fetches_no_terraform_module(offline, context, tmp_path):
    """trivy itself, offline, over a .tf file that names remote module sources.

    Runs in the CI job that installs every scanner, where a missing trivy fails it
    (tests/utils/helpers.require_scanner_binary); elsewhere it skips without trivy.
    """
    require_scanner_binary("trivy")
    scrub_cloud_credentials(offline)
    proxy = RecordingProxy()
    route_through(offline, proxy)
    offline.setenv("TRIVY_CACHE_DIR", str(tmp_path / "trivy-cache"))
    subprocess_utils.clear_find_executable_cache()
    _reset_list_cache()
    try:
        scanner = TrivyRepoScanner(
            context=context,
            config=TrivyRepoScannerConfig(
                options=TrivyRepoScannerConfigOptions(scanners=["misconfig"])
            ),
        )
        assert scanner.validate_plugin_dependencies() is True
        scanner.scan(target=context.source_dir, target_type="source")
    finally:
        proxy.close()
        _reset_list_cache()
        subprocess_utils.clear_find_executable_cache()

    assert proxy.external_requests() == [], (
        f"offline trivy fetched a Terraform module source: {proxy.requests}"
    )
    assert os.path.isdir(Path(scanner.results_dir) / "source")
