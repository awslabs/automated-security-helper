"""Discovery names a damaged template, follows --ignore-suppressions, and reads the
run's scan set.

Three gaps in ``utils/cfn_template_discovery.py`` pinned here:

* a template with a YAML syntax error was dropped at TRACE, so cfn-lint and
  cfn-guard graded the tree SKIPPED with "no CloudFormation template" where
  cfn-nag's tool-absent check counts the same file as a template (MISSING); it is
  returned in ``unparseable``, named by the callers, and counts as something to scan;
* ``nothing_to_scan_reason`` read the config's global ignore paths even under
  ``--ignore-suppressions``, where ``scan()`` is given none, so the two selections
  disagreed; both read the same list from the context now;
* ``scan_set`` was called without the workspace output directory, so in a workspace
  scan the tree was walked again instead of the run's recorded set being read.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.utils import cfn_template_discovery
from automated_security_helper.utils.cfn_template_discovery import (
    NO_CLOUDFORMATION_TEMPLATE,
    candidate_files,
    cloudformation_templates_nothing_to_scan_reason,
    discover_templates,
)

pytestmark = pytest.mark.unit

TEMPLATE = "Resources:\n  Q:\n    Type: AWS::SQS::Queue\n"
DAMAGED_TEMPLATE = "AWSTemplateFormatVersion: '2010-09-09'\nResources:\n  Q: [\n"


def _context(source: Path, config=None, **extra) -> PluginContext:
    return PluginContext(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        work_dir=source / ".ash" / "ash_output" / "converted",
        config=config or get_default_config(),
        **extra,
    )


def test_a_damaged_template_is_named_as_unparseable(ash_temp_path):
    source = ash_temp_path / "src"
    source.mkdir()
    (source / "broken.yaml").write_text(DAMAGED_TEMPLATE, encoding="utf-8")
    found = discover_templates(_context(source), "source")
    assert found.templates == [] and found.unmodelable == []
    assert [shown for shown, _ in found.unparseable] == ["broken.yaml"]
    assert "could not be parsed" in found.unparseable[0][1]


def test_a_damaged_template_counts_as_something_to_scan(ash_temp_path):
    """cfn-nag's tool-absent check counts it, so the tool-absent grade agrees."""
    source = ash_temp_path / "src"
    source.mkdir()
    (source / "broken.yaml").write_text(DAMAGED_TEMPLATE, encoding="utf-8")
    assert cloudformation_templates_nothing_to_scan_reason(_context(source)) is None


def test_a_file_that_is_not_yaml_at_all_is_still_dropped_silently(ash_temp_path):
    source = ash_temp_path / "src"
    source.mkdir()
    (source / "config.json").write_text('{"service": ', encoding="utf-8")
    found = discover_templates(_context(source), "source")
    assert found.unparseable == []
    assert (
        cloudformation_templates_nothing_to_scan_reason(_context(source))
        == NO_CLOUDFORMATION_TEMPLATE
    )


def test_ignore_suppressions_keeps_the_ignored_templates(ash_temp_path):
    config = get_default_config()
    config.global_settings.ignore_paths = [
        IgnorePathWithReason(path="ignored/", reason="generated")
    ]
    source = ash_temp_path / "src"
    (source / "ignored").mkdir(parents=True)
    (source / "ignored" / "stack.yaml").write_text(TEMPLATE, encoding="utf-8")

    honored = candidate_files(_context(source, config), "source")
    assert honored == []
    assert (
        cloudformation_templates_nothing_to_scan_reason(_context(source, config))
        == NO_CLOUDFORMATION_TEMPLATE
    )

    ignoring = _context(source, config, ignore_suppressions=True)
    assert [p.name for p in candidate_files(ignoring, "source")] == ["stack.yaml"]
    assert cloudformation_templates_nothing_to_scan_reason(ignoring) is None


def test_the_workspace_output_directory_reaches_the_scan_set(
    ash_temp_path, monkeypatch
):
    source = ash_temp_path / "src"
    source.mkdir()
    (source / "stack.yaml").write_text(TEMPLATE, encoding="utf-8")
    seen = {}

    def fake_scan_set(**kwargs):
        seen.update(kwargs)
        return [str(source / "stack.yaml")]

    monkeypatch.setattr(cfn_template_discovery, "scan_set", fake_scan_set)
    context = _context(source)
    context.workspace_output_dir = ash_temp_path / "ws-out"
    found = candidate_files(context, "source")
    assert [p.name for p in found] == ["stack.yaml"]
    assert seen["workspace_output_dir"] == ash_temp_path / "ws-out"
