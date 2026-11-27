"""``ash config lint`` reports an old spelling wherever the renamed field's model sits.

The ``expires`` field is declared once, on the ignore-path model, and inherited
by suppressions and exclusions; the old ``expiration`` spelling loads in every
one of those lists. Lint reports it in each, and only where the key is the old
spelling of that model's field: a content database staleness override's
``expiration`` is that model's own canonical key.

So an exclusion written with ``expiration`` is reported, as a suppression is,
under its section's key or that key's ``-``/``_`` twin.

An excluded path in guarddog's section, which the scanners segment does not
declare, is reported too: lint reads the section as the scanner's own config
class, since its manifest gives no typed section, under the key the file writes.
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


def test_an_exclusion_under_the_twin_of_its_sections_key_is_reported(
    tmp_path: Path,
) -> None:
    """``global-settings`` is the ``-``/``_`` twin of the section's key. Lint
    follows it to the exclusion, as it follows another spelling of a plugin's
    section, and names the entry by the keys the file writes."""
    issues = _lint(
        tmp_path,
        {
            "global-settings": {
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

    assert _deprecated_spelling_paths(issues) == ["global-settings.exclusions[0]"]


@pytest.mark.parametrize(
    "section", ["guarddog", "GuardDog"], ids=["manifest-name", "case-variant"]
)
def test_an_excluded_path_in_guarddogs_section_is_reported_where_the_file_writes_it(
    tmp_path: Path, section: str
) -> None:
    """guarddog's manifest gives no typed section, so the scanners segment
    declares no field for it. Lint reads the section as the scanner's own config
    class, under the manifest's name or a case variant of it, and names the entry
    by the keys the file writes."""
    excluded = {"path": "tests/", "reason": "vendored", "expiration": "2099-01-01"}
    issues = _lint(
        tmp_path, {"scanners": {section: {"options": {"excluded_paths": [excluded]}}}}
    )

    assert _deprecated_spelling_paths(issues) == [
        f"scanners.{section}.options.excluded_paths[0]"
    ]


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
