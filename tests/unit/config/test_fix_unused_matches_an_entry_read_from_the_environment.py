# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""``--fix-unused`` comments out an entry whose fields were read from the environment.

The unused-suppressions report lists a suppression's fields as the config file
wrote them: one read from the environment (``${VAR}``, ``!ENV ${VAR}``) is its
reference, never the value. The fixer builds an id from each report entry and
compares it with ids built from its own load of the config file, and that load
resolves environment references, so the two ids hashed different texts and the
entry was silently left in place: the fixer reported nothing fixed where the
scan's report named an unused entry.

The fixer now builds each file entry's id twice, from the resolved fields and
from the fields as the file wrote them, and matches a report entry on either.
That also keeps reports written before the reference form, which hold resolved
values, matching.

Each cell builds the report entry as the reporter writes it
(``recorded_suppressions`` on the resolved config), so the producer and the
consumer are the real pair.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

FORMS = {
    "plain": ("${ASH_GATE_RULE}", "${ASH_GATE_FILE}"),
    "tagged": ("!ENV ${ASH_GATE_RULE}", "!ENV ${ASH_GATE_FILE}"),
    "text": ("B101", "vendor/kept.py"),
}


@pytest.fixture
def environment(monkeypatch):
    monkeypatch.setenv("ASH_GATE_RULE", "GATE-RULE-1")
    monkeypatch.setenv("ASH_GATE_FILE", "gate/resolved.py")
    monkeypatch.delenv("ASH_CONFIG", raising=False)


def _write_config(work: Path, rule: str, path: str) -> Path:
    config_path = work / ".ash.yaml"
    config_path.write_text(
        "project_name: demo\n"
        "global_settings:\n"
        "  suppressions:\n"
        f"    - rule_id: {rule}\n"
        f"      path: {path}\n"
        "      reason: kept\n",
        encoding="utf-8",
    )
    return config_path


def _report_entry_as_the_reporter_writes_it(work: Path, config_path: Path) -> dict:
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.utils.suppression_matcher import (
        SHOWN_SUPPRESSION_FIELDS,
        recorded_suppressions,
    )

    source = work / "src"
    source.mkdir(exist_ok=True)
    resolved = resolve_config(config_path=config_path, source_dir=source)
    suppression = resolved.global_settings.suppressions[0]
    shown = recorded_suppressions(resolved).get(id(suppression), {})
    return {
        name: shown.get(name, getattr(suppression, name, None))
        for name in SHOWN_SUPPRESSION_FIELDS
    }


@pytest.mark.parametrize("form", list(FORMS))
def test_the_entry_is_commented_out(tmp_path, environment, form):
    from automated_security_helper.config.config_linter import ConfigLinter

    rule, path = FORMS[form]
    config_path = _write_config(tmp_path, rule, path)
    entry = _report_entry_as_the_reporter_writes_it(tmp_path, config_path)
    output = tmp_path / "out"
    (output / "reports").mkdir(parents=True)
    (output / "reports" / "ash.unused-suppressions.json").write_text(
        json.dumps({"unused_suppressions": [entry]}, default=str), encoding="utf-8"
    )

    fixed, issues, _stamp = ConfigLinter.fix_unused_suppressions(
        config_path, output_dir=output
    )

    assert len(issues) == 1, [issue.message for issue in issues]
    assert fixed != config_path.read_text(encoding="utf-8")
    # The whole entry is commented out, so every line of it starts a comment.
    assert "# - rule_id:" in fixed, fixed


def test_a_report_written_before_the_reference_form_still_matches(
    tmp_path, environment
):
    """A report holding the resolved values (the form written before the
    reference form) comments the entry out too."""
    from automated_security_helper.config.config_linter import ConfigLinter
    from automated_security_helper.config.resolve_config import resolve_config
    from automated_security_helper.utils.suppression_matcher import (
        SHOWN_SUPPRESSION_FIELDS,
    )

    rule, path = FORMS["plain"]
    config_path = _write_config(tmp_path, rule, path)
    source = tmp_path / "src"
    source.mkdir()
    resolved = resolve_config(config_path=config_path, source_dir=source)
    suppression = resolved.global_settings.suppressions[0]
    entry = {
        name: getattr(suppression, name, None) for name in SHOWN_SUPPRESSION_FIELDS
    }
    output = tmp_path / "out"
    (output / "reports").mkdir(parents=True)
    (output / "reports" / "ash.unused-suppressions.json").write_text(
        json.dumps({"unused_suppressions": [entry]}, default=str), encoding="utf-8"
    )

    fixed, issues, _stamp = ConfigLinter.fix_unused_suppressions(
        config_path, output_dir=output
    )

    assert len(issues) == 1, [issue.message for issue in issues]
    assert fixed != config_path.read_text(encoding="utf-8")


def test_an_entry_with_no_shown_copy_is_quoted_without_its_values(
    tmp_path, environment, monkeypatch
):
    """An entry the shown copy has no place for is quoted with each value as
    read from the environment, never as resolved: the message must not depend
    on _shown_entries keeping its length to keep a value out of it."""
    from automated_security_helper.config.config_linter import ConfigLinter

    rule, path = FORMS["plain"]
    config_path = _write_config(tmp_path, rule, path)
    entry = _report_entry_as_the_reporter_writes_it(tmp_path, config_path)
    output = tmp_path / "out"
    (output / "reports").mkdir(parents=True)
    (output / "reports" / "ash.unused-suppressions.json").write_text(
        json.dumps({"unused_suppressions": [entry]}, default=str), encoding="utf-8"
    )
    monkeypatch.setattr(
        ConfigLinter, "_shown_entries", staticmethod(lambda *args, **kwargs: [])
    )

    _fixed, issues, _stamp = ConfigLinter.fix_unused_suppressions(
        config_path, output_dir=output
    )

    assert len(issues) == 1, [issue.message for issue in issues]
    assert "GATE-RULE-1" not in issues[0].message, issues[0].message
    assert "gate/resolved.py" not in issues[0].message, issues[0].message
