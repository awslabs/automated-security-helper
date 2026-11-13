# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scan-set and committed-output tests start no scanner tool.

Those modules build real scanner plugins, and building one probes its tool: bandit,
checkov and semgrep run ``uv tool run <tool> --version`` when constructed,
detect-secrets' dependency check runs ``uv tool run detect-secrets --version``, and
opengrep's argument builder runs ``opengrep --version``. On a host where uv and the
tools are installed each probe starts the tool itself, and the tools write to the
user's directories: a pytest run of these modules left
``$XDG_CACHE_HOME/checkov/update_checker_cache.json`` and ``~/.semgrep/settings.yml``
behind. Measured with each module run on its own, in a jail whose ``uv`` answers
``--version`` and whose ``uv`` and tools record every call and run nothing: 17 calls
from five modules, ``uv tool run`` for bandit, checkov, semgrep and detect-secrets
among them, and none with the fixture.

Each module that builds a scanner takes the ``no_tool_probes`` fixture
(tests/unit/conftest.py). The first test here pins that it does; the second that
under the fixture the probes these modules reach start no process.
"""

from __future__ import annotations

import ast
import errno
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from tests.utils.process_guard import refuse_process_starts

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
PluginContext.model_rebuild()

UNIT = Path(__file__).resolve().parent

#: The scan-set and committed-output modules, by name.
MODULE_PATTERNS = (
    "test_committed_*.py",
    "test_output_dir_patterns_are_escaped.py",
    "test_ash_output_dirs_are_not_scanned.py",
    "test_scan_set_*.py",
    "utils/test_scan_set_*.py",
    "utils/test_get_scan_set*.py",
    "utils/test_sarif_output_path_exclusion_anchor.py",
)

#: The modules among them that build a scanner plugin today. A control on the
#: detection below, which would otherwise pass by finding nothing.
KNOWN_BUILDERS = {
    "test_ash_output_dirs_are_not_scanned.py",
    "test_committed_files_in_ash_output_are_scanned.py",
    "test_committed_output_entries_are_regular_files.py",
    "test_output_dir_patterns_are_escaped.py",
    "utils/test_scan_set_lists_are_read_only_from_their_run.py",
}

FIXTURE = "no_tool_probes"


def _modules() -> list[Path]:
    found = {path for pattern in MODULE_PATTERNS for path in UNIT.glob(pattern)}
    return sorted(path for path in found if path != Path(__file__).resolve())


def _builds_a_scanner(tree: ast.AST) -> bool:
    """Whether the module calls a class whose name ends in ``Scanner``."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name and name.endswith("Scanner") and name[:1].isupper():
                return True
    return False


def _module_uses_fixture(tree: ast.Module, fixture: str) -> bool:
    """Whether a module-level ``pytestmark`` holds ``usefixtures(<fixture>)``."""
    for node in tree.body:
        targets = getattr(node, "targets", None) or [getattr(node, "target", None)]
        if not any(getattr(t, "id", None) == "pytestmark" for t in targets):
            continue
        for call in ast.walk(node.value):
            if (
                isinstance(call, ast.Call)
                and getattr(call.func, "attr", None) == "usefixtures"
                and any(
                    isinstance(arg, ast.Constant) and arg.value == fixture
                    for arg in call.args
                )
            ):
                return True
    return False


def test_every_module_that_builds_a_scanner_takes_the_fixture():
    builders, missing = set(), []
    for path in _modules():
        tree = ast.parse(path.read_text(encoding="utf-8"))
        if not _builds_a_scanner(tree):
            continue
        relative = path.relative_to(UNIT).as_posix()
        builders.add(relative)
        if not _module_uses_fixture(tree, FIXTURE):
            missing.append(relative)
    assert KNOWN_BUILDERS <= builders, sorted(KNOWN_BUILDERS - builders)
    assert not missing, missing


@pytest.mark.usefixtures(FIXTURE)
def test_under_the_fixture_the_probes_start_no_process(tmp_path, monkeypatch):
    """Every process start is refused and recorded; the uv runner and its memos are
    this test's own, so an answer an earlier test left cannot stand in for a probe."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
        BanditScannerConfig,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.checkov_scanner import (
        CheckovScanner,
        CheckovScannerConfig,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
        OpengrepScanner,
        OpengrepScannerConfig,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.semgrep_scanner import (
        SemgrepScanner,
        SemgrepScannerConfig,
    )
    from automated_security_helper.utils import uv_tool_runner

    monkeypatch.setattr(
        uv_tool_runner, "_uv_tool_runner", uv_tool_runner.UVToolRunner()
    )
    for memo in (
        "_uv_command_cache",
        "_uv_command_binary",
        "_uv_executable_cache",
        "_executable_cache",
        "_uv_tool_version_cache",
    ):
        monkeypatch.setattr(uv_tool_runner, memo, {})
    # Refused as a missing program, so the code goes on as it does without the tool;
    # every route is covered (tests/utils/process_guard.py), and each start is kept.
    started = refuse_process_starts(
        monkeypatch,
        refusal=lambda route, start: FileNotFoundError(
            errno.ENOENT, "process start refused by the test"
        ),
    )
    source = tmp_path / "repo"
    source.mkdir()
    output = source / ".ash" / "ash_output"
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )

    for scanner_class, config_class in (
        (BanditScanner, BanditScannerConfig),
        (CheckovScanner, CheckovScannerConfig),
        (SemgrepScanner, SemgrepScannerConfig),
    ):
        scanner_class(context=context, config=config_class())
    DetectSecretsScanner(
        context=context, config=DetectSecretsScannerConfig()
    ).validate_plugin_dependencies()
    OpengrepScanner(context=context, config=OpengrepScannerConfig()).emit_metrics_flag()

    assert started == []
