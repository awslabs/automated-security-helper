# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The global ignore paths reach the builtin trivy, cfn-lint and cfn-guard too.

ASH drops the findings in ``global_settings.ignore_paths`` from its reports after
the scan, and gives the ignored paths to every scanner that reads the tree, so
the tools do not read them either (test_global_ignore_paths_reach_walking_scanners.py):
trivy-repo gets ``--skip-files`` and ``--skip-dirs``, cfn-nag reads its scan set
without them (``link_exclusions.drop_ignored``).

The builtin trivy walks its target as trivy-repo does, through the same base, and
cfn-lint and cfn-guard take their templates from
``utils/cfn_template_discovery.py``, which restates cfn-nag's selection and must
give cfn-nag's answer. actionlint and zizmor already filter their scan set by the
ignore paths; gitleaks has no option that leaves out a path, so it reads them and
ASH drops its findings.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason

PluginContext.model_rebuild()

pytestmark = [
    pytest.mark.unit,
    pytest.mark.skipif(
        sys.platform == "win32", reason="trivy's skip values are POSIX paths"
    ),
]

TEMPLATE = "Resources:\n  Q:\n    Type: AWS::SQS::Queue\n"
IGNORES = [
    IgnorePathWithReason(path="thirdparty/**", reason="vendored"),
    IgnorePathWithReason(path="gen_stack.yaml", reason="generated"),
]


def _tree(tmp_path: Path) -> Path:
    source = tmp_path / "src"
    for name in ("keep.yaml", "thirdparty/vendored.yaml", "gen_stack.yaml"):
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(TEMPLATE, encoding="utf-8")
    (source / "requirements.txt").write_text("six==1.0.0\n", encoding="utf-8")
    return source


def _context(source: Path) -> PluginContext:
    output = source.parent / "ash-output"
    output.mkdir(exist_ok=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=get_default_config(),
    )


def _values(argv: List[str], flag: str) -> List[str]:
    return [arg[len(flag) + 1 :] for arg in argv if arg.startswith(f"{flag}=")]


def test_the_builtin_trivy_is_given_the_ignored_files_and_directories(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
        TrivyScanner,
        TrivyScannerConfig,
    )

    source = _tree(tmp_path)
    scanner = TrivyScanner(context=_context(source), config=TrivyScannerConfig())

    argv, _, _ = scanner._execute_scan(source, "source", IGNORES)

    assert _values(argv, "--skip-dirs") == ["thirdparty"]
    assert _values(argv, "--skip-files") == ["gen_stack.yaml"]


def test_control_the_builtin_trivy_without_ignore_paths_skips_nothing(tmp_path):
    from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
        TrivyScanner,
        TrivyScannerConfig,
    )

    source = _tree(tmp_path)
    scanner = TrivyScanner(context=_context(source), config=TrivyScannerConfig())

    argv, _, _ = scanner._execute_scan(source, "source", [])

    assert _values(argv, "--skip-files") == []
    assert all("thirdparty" not in arg for arg in _values(argv, "--skip-dirs"))


def test_template_discovery_leaves_out_the_ignored_templates(tmp_path):
    from automated_security_helper.utils.cfn_template_discovery import (
        discover_templates,
        display_path,
    )

    source = _tree(tmp_path)
    context = _context(source)

    found = discover_templates(context, "source", IGNORES)

    assert [display_path(p, source) for p in found.templates] == ["keep.yaml"]


def test_template_discovery_still_gives_cfn_nags_answer(tmp_path):
    """The agreement tests/unit/utils/test_cfn_template_discovery.py holds, with
    the ignore paths cfn-nag is given."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners import (
        cfn_nag_scanner,
    )
    from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
        CfnNagScanner,
    )
    from automated_security_helper.utils.cfn_template_discovery import (
        discover_templates,
    )

    source = _tree(tmp_path)
    context = _context(source)
    handed_to_cfn_nag: List[Path] = []
    stage = cfn_nag_scanner._stage_cfn_nag_input

    def record_stage(results_file_dir, cfn_file, text):
        handed_to_cfn_nag.append(Path(cfn_file))
        return stage(results_file_dir, cfn_file, text)

    def fake_run(self, command, **kwargs):
        return {
            "stdout": '{"version": "2.1.0", "runs": [{"tool": {"driver": '
            '{"name": "cfn_nag"}}, "results": []}]}',
            "stderr": "",
            "returncode": 0,
        }

    scanner = CfnNagScanner(context=context)
    with (
        patch.object(CfnNagScanner, "validate_plugin_dependencies", return_value=True),
        patch.object(CfnNagScanner, "_run_subprocess", fake_run),
        patch.object(cfn_nag_scanner, "_stage_cfn_nag_input", record_stage),
    ):
        scanner.scan(target=source, target_type="source", global_ignore_paths=IGNORES)

    discovered = discover_templates(context, "source", IGNORES)
    assert sorted(p.resolve() for p in handed_to_cfn_nag) == sorted(
        p.resolve() for p in discovered.templates
    )


@pytest.mark.parametrize("name", ["cfn-lint", "cfn-guard"])
def test_the_template_scanners_hand_no_ignored_template_to_their_tool(tmp_path, name):
    if name == "cfn-lint":
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_lint_scanner import (
            CfnLintScanner as scanner_class,
            CfnLintScannerConfig as config_class,
        )
    else:
        from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_guard_scanner import (
            CfnGuardScanner as scanner_class,
            CfnGuardScannerConfig as config_class,
        )

    source = _tree(tmp_path)
    scanner = scanner_class(context=_context(source), config=config_class())
    commands: List[List[str]] = []

    def _record(command, *args, **kwargs):
        commands.append([str(arg) for arg in command])
        return {"returncode": 0, "stdout": "", "stderr": ""}

    scanner.dependencies_satisfied = True
    patches = [
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=_record),
    ]
    if name == "cfn-guard":
        # Its rules come from an installed bundle; none is needed to reach the
        # templates.
        patches.append(patch.object(scanner, "_selected_rules", return_value=[]))
    for active in patches:
        active.start()
    try:
        scanner.scan(target=source, target_type="source", global_ignore_paths=IGNORES)
    except ScannerError:
        pass
    finally:
        for active in patches:
            active.stop()

    handed = " ".join(" ".join(command) for command in commands)
    assert "keep.yaml" in handed, commands
    assert "vendored.yaml" not in handed, commands
    assert "gen_stack.yaml" not in handed, commands
