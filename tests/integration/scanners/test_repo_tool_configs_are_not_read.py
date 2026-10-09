# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scanned repository's own actionlint, gitleaks and zizmor configs change nothing.

Each of the three tools reads a config the repository commits, and each such config
can drop findings before ASH sees them, so they would be neither reported nor
counted as suppressed:

* actionlint: ``.github/actionlint.yaml`` with ``paths.<glob>.ignore``;
* gitleaks: ``.gitleaks.toml`` (an allowlist, or rules of its own) and a root
  ``.gitleaksignore`` of fingerprints;
* zizmor: ``zizmor.yml`` or ``.github/zizmor.yml`` disabling audits.

ASH runs each with its own config unless the operator set one, so findings are
tuned with ASH suppressions. These tests plant configs that drop every finding
and assert the counts do not move (measured: actionlint 9, gitleaks 5, zizmor 11),
then hand the same configs over as the operator's and assert they do apply, which
is also the proof that the planted configs would have hidden everything.

The binaries are required, not assumed: actionlint and gitleaks must be on PATH
or in ASH's bin directory (the integration job installs them, and
``ASH_REQUIRE_ACTIONLINT`` turns a missing actionlint into a failure), and zizmor
is resolved by its scanner the way ``ash dependencies install`` would.
"""

from __future__ import annotations

import json
import os
import shutil
from pathlib import Path
from typing import Callable, Dict

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.actionlint_scanner import (
    ActionlintScanner,
    ActionlintScannerConfig,
    ActionlintScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
    GitleaksScanner,
    GitleaksScannerConfig,
    GitleaksScannerConfigOptions,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.zizmor_scanner import (
    ZizmorScanner,
    ZizmorScannerConfig,
    ZizmorScannerConfigOptions,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.subprocess_utils import find_executable
from tests.utils.gitleaks_fixture import materialize

PluginContext.model_rebuild()

pytestmark = pytest.mark.integration

DATA = Path(__file__).parents[2] / "test_data" / "scanners"

#: Every audit zizmor reports on the fixture, disabled by the planted zizmor.yml.
_ZIZMOR_AUDITS = (
    "artipacked",
    "dangerous-triggers",
    "excessive-permissions",
    "hardcoded-container-credentials",
    "template-injection",
    "unpinned-uses",
    "unsound-condition",
)

_ACTIONLINT_IGNORE_ALL = (
    "paths:\n  .github/workflows/**/*.yml:\n    ignore:\n      - '.*'\n"
)
_GITLEAKS_ALLOW_ALL = (
    'title = "planted"\n[extend]\nuseDefault = true\n[allowlist]\n'
    "paths = ['''.*''']\n"
)
_ZIZMOR_DISABLE_ALL = "rules:\n" + "".join(
    f"  {audit}:\n    disable: true\n" for audit in _ZIZMOR_AUDITS
)


def _require(tool: str) -> None:
    if find_executable(tool):
        return
    if tool == "actionlint" and os.environ.get(
        "ASH_REQUIRE_ACTIONLINT", ""
    ).strip().upper() in ("1", "YES", "TRUE"):
        pytest.fail(
            "ASH_REQUIRE_ACTIONLINT is set but actionlint is not installed. This "
            "test must run in CI, not skip."
        )
    pytest.skip(f"{tool} is not installed")


@pytest.fixture
def source(tmp_path) -> Path:
    """Two vulnerable workflows and the gitleaks fixture's secrets, no tool config."""
    root = tmp_path / "src"
    workflows = root / ".github" / "workflows"
    workflows.mkdir(parents=True)
    shutil.copy(
        DATA / "actionlint" / "repo" / ".github" / "workflows" / "vulnerable.yml",
        workflows / "actionlint-vuln.yml",
    )
    shutil.copy(
        DATA / "zizmor" / "repo" / ".github" / "workflows" / "vulnerable.yml",
        workflows / "zizmor-vuln.yml",
    )
    # The gitleaks fixture under secrets/, where its own config files are not at
    # the scan root; the root configs are planted by the tests.
    materialize(root / "secrets")
    return root


def _context(root: Path, output: Path, *, operator: bool) -> PluginContext:
    config = AshConfig()
    record_provenance(
        config,
        in_tree=[] if operator else [root / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
    )
    return PluginContext(
        source_dir=root, output_dir=output, work_dir=output / "converted", config=config
    )


def _actionlint(context: PluginContext, **options) -> ActionlintScanner:
    return ActionlintScanner(
        context=context,
        config=ActionlintScannerConfig(
            enabled=True, options=ActionlintScannerConfigOptions(**options)
        ),
    )


def _gitleaks(context: PluginContext, **options) -> GitleaksScanner:
    return GitleaksScanner(
        context=context,
        config=GitleaksScannerConfig(
            enabled=True, options=GitleaksScannerConfigOptions(**options)
        ),
    )


def _zizmor(context: PluginContext, **options) -> ZizmorScanner:
    scanner = ZizmorScanner(
        context=context,
        config=ZizmorScannerConfig(
            enabled=True, options=ZizmorScannerConfigOptions(**options)
        ),
    )
    assert scanner.validate_plugin_dependencies() is True, (
        f"zizmor could not be resolved: {scanner.dependency_unavailable_reason}"
    )
    return scanner


_BUILDERS: Dict[str, Callable[..., object]] = {
    "actionlint": _actionlint,
    "gitleaks": _gitleaks,
    "zizmor": _zizmor,
}


def _count(name: str, root: Path, output: Path, *, operator: bool, **options) -> int:
    scanner = _BUILDERS[name](_context(root, output, operator=operator), **options)
    report = scanner.scan(target=root, target_type="source")
    assert isinstance(report, SarifReport), report
    return len(report.get_all_results())


def _plant(root: Path, gitleaks_fingerprints: list) -> None:
    (root / ".github" / "actionlint.yaml").write_text(
        _ACTIONLINT_IGNORE_ALL, encoding="utf-8"
    )
    (root / ".gitleaks.toml").write_text(_GITLEAKS_ALLOW_ALL, encoding="utf-8")
    (root / ".gitleaksignore").write_text(
        "".join(f"{fingerprint}\n" for fingerprint in gitleaks_fingerprints),
        encoding="utf-8",
    )
    (root / "zizmor.yml").write_text(_ZIZMOR_DISABLE_ALL, encoding="utf-8")
    (root / ".github" / "zizmor.yml").write_text(_ZIZMOR_DISABLE_ALL, encoding="utf-8")


def _fingerprints(sarif_path: Path) -> list:
    """``<file>:<rule>:<line>`` for each result, the form a .gitleaksignore holds."""
    data = json.loads(sarif_path.read_text(encoding="utf-8"))
    out = []
    for result in data["runs"][0]["results"]:
        physical = result["locations"][0]["physicalLocation"]
        out.append(
            f"{physical['artifactLocation']['uri']}:{result['ruleId']}:"
            f"{physical['region']['startLine']}"
        )
    return out


def test_the_scanned_repos_own_configs_change_no_count(source, tmp_path):
    for tool in ("actionlint", "gitleaks"):
        _require(tool)
    control = {
        name: _count(name, source, tmp_path / f"control-{name}", operator=False)
        for name in _BUILDERS
    }
    assert all(control.values()), control
    gitleaks_report = (
        tmp_path / "control-gitleaks" / "scanners" / "gitleaks" / "source"
    ) / "gitleaks.sarif"
    fingerprints = _fingerprints(gitleaks_report)
    assert len(fingerprints) == control["gitleaks"]

    _plant(source, fingerprints)
    planted = {
        name: _count(name, source, tmp_path / f"planted-{name}", operator=False)
        for name in _BUILDERS
    }

    assert planted == control


def test_the_same_configs_apply_when_the_operator_sets_them(source, tmp_path):
    for tool in ("actionlint", "gitleaks"):
        _require(tool)
    operator = tmp_path / "operator"
    operator.mkdir()
    (operator / "actionlint.yaml").write_text(_ACTIONLINT_IGNORE_ALL, encoding="utf-8")
    (operator / "gitleaks.toml").write_text(_GITLEAKS_ALLOW_ALL, encoding="utf-8")
    (operator / "zizmor.yml").write_text(_ZIZMOR_DISABLE_ALL, encoding="utf-8")

    counts = {
        "actionlint": _count(
            "actionlint",
            source,
            tmp_path / "op-actionlint",
            operator=True,
            config_file=str(operator / "actionlint.yaml"),
        ),
        "gitleaks": _count(
            "gitleaks",
            source,
            tmp_path / "op-gitleaks",
            operator=True,
            config_file=str(operator / "gitleaks.toml"),
        ),
        "zizmor": _count(
            "zizmor",
            source,
            tmp_path / "op-zizmor",
            operator=True,
            config_file=str(operator / "zizmor.yml"),
        ),
    }

    assert counts == {"actionlint": 0, "gitleaks": 0, "zizmor": 0}
