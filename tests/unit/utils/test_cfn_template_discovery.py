# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-lint and cfn-guard read exactly the files cfn-nag reads.

``utils/cfn_template_discovery.py`` restates cfn-nag's template selection rather than
sharing it, because cfn-nag was not to be changed. This holds the two to one answer:
the same fixture tree goes through ``discover_templates`` and through
``CfnNagScanner.scan`` with only its subprocess faked, and the files cfn-nag hands
to ``cfn_nag_scan`` must be exactly the discovered templates.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    cfn_nag_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.cfn_nag_scanner import (
    CfnNagScanner,
)
from automated_security_helper.utils.cfn_template_discovery import (
    discover_templates,
    display_path,
)

TREE = {
    "stack.yaml": "Resources:\n  Q:\n    Type: AWS::SQS::Queue\n",
    "nested/stack.json": '{"Resources": {"T": {"Type": "AWS::SNS::Topic"}}}',
    "short.yml": "AWSTemplateFormatVersion: '2010-09-09'\nResources: {}\n",
    "intrinsics.yaml": (
        "Resources:\n  B:\n    Type: AWS::S3::Bucket\n"
        "    Properties:\n      BucketName: !Sub '${AWS::StackName}-b'\n"
    ),
    "config.yaml": "service:\n  name: x\n",
    "broken.json": '{"Resources": ',
    "custom.yaml": "Resources:\n  X:\n    Type: 'Not A Valid Type!'\n",
    "notes.txt": "Resources: {}\n",
}


@pytest.fixture
def context(ash_temp_path) -> PluginContext:
    source = ash_temp_path / "src"
    for name, text in TREE.items():
        path = source / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return PluginContext(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        work_dir=source / ".ash" / "ash_output" / "converted",
        config=get_default_config(),
    )


def test_discovery_classifies_the_tree(context):
    found = discover_templates(context, "source")
    source = Path(context.source_dir)
    assert [display_path(p, source) for p in found.templates] == [
        "intrinsics.yaml",
        "nested/stack.json",
        "short.yml",
        "stack.yaml",
    ]
    assert [display_path(p, source) for p, _ in found.unmodelable] == ["custom.yaml"]


def test_cfn_nag_selects_the_same_templates(context):
    """The agreement test the discovery module's docstring promises."""
    handed_to_cfn_nag = []
    stage = cfn_nag_scanner._stage_cfn_nag_input

    # cfn_nag_scan reads a staged copy of each template's checked text, so the
    # template it was given is the one staged, not the --input-path it opens.
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
        scanner.scan(target=Path(context.source_dir), target_type="source")

    discovered = discover_templates(context, "source")
    assert sorted(p.resolve() for p in handed_to_cfn_nag) == sorted(
        p.resolve() for p in discovered.templates
    )
    # And they count the unmodelable template the same way.
    assert scanner.targets_failed == len(discovered.unmodelable) == 1


def test_a_symlinked_template_is_refused_by_both(context, ash_temp_path):
    """A template reached through a symlink is read by neither, and named by both."""
    outside = ash_temp_path / "elsewhere" / "outside.yaml"
    outside.parent.mkdir()
    outside.write_text(TREE["stack.yaml"], encoding="utf-8")
    link = Path(context.source_dir) / "linked.yaml"
    try:
        link.symlink_to(outside)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")

    discovered = discover_templates(context, "source")

    assert link not in discovered.templates
    assert [shown for shown, _ in discovered.refused] == ["linked.yaml"]
    test_cfn_nag_selects_the_same_templates(context)


def test_display_path_is_relative_inside_and_absolute_outside(tmp_path):
    source = tmp_path / "src"
    assert display_path(source / "a" / "b.yaml", source) == "a/b.yaml"
    outside = tmp_path / "out" / "c.yaml"
    assert display_path(outside, source) == outside.absolute().as_posix()
