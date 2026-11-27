"""``ash config lint`` reports an old spelling wherever the renamed field's model sits.

The ``expires`` field is declared once, on the ignore-path model, and inherited
by suppressions and exclusions; the old ``expiration`` spelling loads in every
one of those lists. Lint reports it in each, and only where the key is the old
spelling of that model's field: a content database staleness override's
``expiration`` is that model's own canonical key.

Red at the base: an exclusion written with ``expiration`` drew no report.
"""

from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.config.config_linter import (
    ConfigLinter,
    LintCategory,
    LintIssue,
)

pytestmark = pytest.mark.unit


def _lint(tmp_path: Path, document: Dict[str, Any]) -> List[LintIssue]:
    config = tmp_path / ".ash.yaml"
    config.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return ConfigLinter.lint(config, source_dir=tmp_path).issues


def _deprecated_spelling_paths(issues: List[LintIssue]) -> List[str]:
    return [i.path for i in issues if i.category == LintCategory.DEPRECATED_SPELLING]


def test_an_exclusion_written_with_the_old_spelling_is_reported(tmp_path: Path) -> None:
    issues = _lint(
        tmp_path,
        {
            "global_settings": {
                "exclusions": [
                    {
                        "rule_id": "B101",
                        "path": "tests/",
                        "reason": "asserts in tests",
                        "expiration": "2099-01-01",
                    }
                ]
            }
        },
    )

    assert _deprecated_spelling_paths(issues) == ["global_settings.exclusions[0]"]


def test_a_suppression_written_with_the_old_spelling_is_still_reported(
    tmp_path: Path,
) -> None:
    """The control: the list lint already walked keeps its report."""
    issues = _lint(
        tmp_path,
        {
            "global_settings": {
                "suppressions": [
                    {
                        "rule_id": "B101",
                        "path": "src/app.py",
                        "reason": "reviewed",
                        "expiration": "2099-01-01",
                    }
                ]
            }
        },
    )

    assert _deprecated_spelling_paths(issues) == ["global_settings.suppressions[0]"]


def test_a_staleness_overrides_expiration_is_not_reported(tmp_path: Path) -> None:
    issues = _lint(
        tmp_path,
        {
            "content_db_staleness_overrides": [
                {
                    "database": "grype-db",
                    "policy": "warn",
                    "expiration": "2099-01-01",
                    "reason": "upstream paused",
                }
            ]
        },
    )

    assert _deprecated_spelling_paths(issues) == []
