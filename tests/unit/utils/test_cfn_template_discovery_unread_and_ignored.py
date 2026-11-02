"""Discovery names what it cannot read, counts what the parser cannot build, and
drops what the global ignore paths ignore.

Three gaps in ``utils/cfn_template_discovery.py`` pinned here:

* a candidate ASH cannot open or decode (bytes that are not UTF-8) vanished at
  TRACE from cfn-lint's and cfn-guard's coverage and from ``nothing_to_scan_reason``;
  it is now returned in ``unreadable`` and counts as something to scan;
* a file whose structure is a template but whose values the parser cannot build
  was dropped at TRACE where cfn-nag counts the same file as a failed target; it
  is now returned in ``unmodelable``;
* ``cloudformation_templates_nothing_to_scan_reason`` selected templates without
  the config's global ignore paths, so a tree whose only templates are ignored read
  MISSING when the tool was absent instead of SKIPPED.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.utils.cfn_template_discovery import (
    NO_CLOUDFORMATION_TEMPLATE,
    cloudformation_templates_nothing_to_scan_reason,
    discover_templates,
    display_path,
)

pytestmark = pytest.mark.unit

TEMPLATE = "Resources:\n  Q:\n    Type: AWS::SQS::Queue\n"

UNBUILDABLE_TEMPLATE = (
    "Resources:\n"
    "  X:\n"
    "    Type: Custom::Thing\n"
    "    Properties:\n"
    "      Count: !!int forty-two\n"
)


def _context(source: Path, config=None) -> PluginContext:
    return PluginContext(
        source_dir=source,
        output_dir=source / ".ash" / "ash_output",
        work_dir=source / ".ash" / "ash_output" / "converted",
        config=config or get_default_config(),
    )


def test_a_candidate_that_is_not_utf8_is_named_as_unreadable(ash_temp_path):
    source = ash_temp_path / "src"
    source.mkdir()
    (source / "latin.yaml").write_bytes(b"Resources:\n  caf\xe9: {}\n")
    found = discover_templates(_context(source), "source")
    assert found.templates == []
    assert [shown for shown, _ in found.unreadable] == ["latin.yaml"]
    assert "UnicodeDecodeError" in found.unreadable[0][1]


def test_an_unreadable_candidate_counts_as_something_to_scan(ash_temp_path):
    """Only MISSING cannot hide a template, so the doubt counts."""
    source = ash_temp_path / "src"
    source.mkdir()
    (source / "latin.yaml").write_bytes(b"Resources:\n  caf\xe9: {}\n")
    assert cloudformation_templates_nothing_to_scan_reason(_context(source)) is None


def test_a_template_whose_values_cannot_be_built_is_a_failed_target(ash_temp_path):
    source = ash_temp_path / "src"
    source.mkdir()
    (source / "custom.yaml").write_text(UNBUILDABLE_TEMPLATE, encoding="utf-8")
    found = discover_templates(_context(source), "source")
    assert found.templates == []
    assert [display_path(p, source) for p, _ in found.unmodelable] == ["custom.yaml"]
    assert "could not be built" in found.unmodelable[0][1]


def test_a_file_that_is_not_yaml_or_json_is_still_dropped(ash_temp_path):
    source = ash_temp_path / "src"
    source.mkdir()
    (source / "broken.json").write_text('{"Resources": ', encoding="utf-8")
    found = discover_templates(_context(source), "source")
    assert found.templates == [] and found.unmodelable == []
    assert found.unreadable == []


def test_nothing_to_scan_reason_drops_the_globally_ignored_templates(ash_temp_path):
    """The only template is ignored, so the answer is SKIPPED, not MISSING."""
    source = ash_temp_path / "src"
    (source / "templates").mkdir(parents=True)
    (source / "templates" / "stack.yaml").write_text(TEMPLATE, encoding="utf-8")
    config = get_default_config()
    config.global_settings.ignore_paths = [
        IgnorePathWithReason(path="templates/stack.yaml", reason="generated")
    ]
    context = _context(source, config)
    ignored = list(config.global_settings.ignore_paths)
    assert discover_templates(context, "source", ignored).templates == []
    assert (
        cloudformation_templates_nothing_to_scan_reason(context)
        == NO_CLOUDFORMATION_TEMPLATE
    )


def test_nothing_to_scan_reason_still_sees_an_unignored_template(ash_temp_path):
    source = ash_temp_path / "src"
    (source / "templates").mkdir(parents=True)
    (source / "templates" / "stack.yaml").write_text(TEMPLATE, encoding="utf-8")
    (source / "other.yaml").write_text(TEMPLATE, encoding="utf-8")
    config = get_default_config()
    config.global_settings.ignore_paths = [
        IgnorePathWithReason(path="templates/stack.yaml", reason="generated")
    ]
    assert (
        cloudformation_templates_nothing_to_scan_reason(_context(source, config))
        is None
    )
