# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The AWS reporters page says the Security Hub reporter imports findings.

The page once said that the Security Hub reporter sends nothing yet, that its import is not
implemented, and that it writes a placeholder file. The reporter has since been built: it
imports every finding with ``BatchImportFindings``. The page is the one that tells an
operator what leaves the machine, so a claim that nothing is sent misleads on exactly the
point the page exists for.

Each test pins one half. The page tests read ``docs/content/plugins/aws.md`` and check the
stale claims are gone and the claims that replaced them are there. The code test reads the
reporter module's source, without importing it, and checks that the import call the page
describes is still made, so a reporter that stops importing makes the page wrong again and
this file says so.
"""

import ast
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
AWS_PAGE = REPO_ROOT / "docs" / "content" / "plugins" / "aws.md"
REPORTER_MODULE = (
    REPO_ROOT
    / "automated_security_helper"
    / "plugin_modules"
    / "ash_aws_plugins"
    / "security_hub_reporter.py"
)

SECTION_HEADING = "### `aws-security-hub` {#aws-security-hub}"
TABLE_ROW_START = "| `aws-security-hub` |"

#: Phrases the page used while the reporter sent nothing. Matched on text with its
#: whitespace collapsed, so a rewrapped paragraph does not hide one.
STALE_CLAIMS = [
    "Nothing yet",
    "does not import findings yet",
    "import is not implemented",
    "sends nothing to Security Hub",
    "placeholder file",
]


def _collapse(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _page() -> str:
    return AWS_PAGE.read_text(encoding="utf-8")


def _section() -> str:
    """The Security Hub section of the page, up to the next second-level heading."""
    text = _page()
    assert SECTION_HEADING in text, (
        f"{AWS_PAGE.name} lost the {SECTION_HEADING!r} heading"
    )
    start = text.index(SECTION_HEADING)
    following = re.search(r"^## ", text[start:], flags=re.MULTILINE)
    end = start + following.start() if following else len(text)
    return _collapse(text[start:end])


def _table_row() -> str:
    for line in _page().splitlines():
        if line.startswith(TABLE_ROW_START):
            return _collapse(line)
    pytest.fail(f"{AWS_PAGE.name} has no table row starting {TABLE_ROW_START!r}")


@pytest.mark.parametrize("claim", STALE_CLAIMS)
def test_the_page_no_longer_says_the_reporter_sends_nothing(claim: str) -> None:
    text = _collapse(_page())
    assert claim not in text, (
        f"{AWS_PAGE.name} still says {claim!r}, but the Security Hub reporter imports "
        "every finding with BatchImportFindings"
    )


def test_the_table_row_names_the_findings_that_leave_the_machine() -> None:
    row = _table_row()
    assert "Every finding in the scan results" in row, (
        "the 'What leaves the machine' column of the aws-security-hub row has to say "
        f"that findings are sent, and it reads: {row!r}"
    )


def test_the_section_says_the_reporter_imports_with_batch_import_findings() -> None:
    section = _section()
    assert "imports every finding in the scan results into Security Hub" in section
    assert "`BatchImportFindings`" in section


def test_the_section_says_a_suppressed_finding_is_sent_archived() -> None:
    section = _section()
    assert (
        "A suppressed finding is sent too, with the record state `ARCHIVED`" in section
    )


def test_the_section_says_findings_scope_is_required() -> None:
    section = _section()
    assert "`findings_scope` names the findings this scan owns" in section
    assert "It is required: without it the reporter refuses to import" in section


def test_the_section_lists_the_permissions_the_import_needs() -> None:
    section = _section()
    iam = section[section.index("IAM:") :]
    assert "`securityhub:BatchImportFindings`" in iam
    assert "`securityhub:GetFindings`" in iam


def test_the_example_config_sets_the_required_scope() -> None:
    section = _section()
    assert "findings_scope: my-repository" in section


def test_the_reporter_module_calls_batch_import_findings() -> None:
    """The code half: the call the page describes is still made."""
    tree = ast.parse(REPORTER_MODULE.read_text(encoding="utf-8"))
    attributes = {
        node.attr for node in ast.walk(tree) if isinstance(node, ast.Attribute)
    }
    assert "batch_import_findings" in attributes, (
        f"{REPORTER_MODULE.name} no longer calls batch_import_findings, so the page's "
        "claim that the reporter imports every finding is wrong again"
    )
