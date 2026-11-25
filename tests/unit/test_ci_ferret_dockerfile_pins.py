# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The two ferret Dockerfile suppressions are line ranges that still hold the flagged
text.

Why this exists
---------------
ferret-scan's netrc_password detector reads the ``--disabled-password`` flag of the
``adduser`` command in the Dockerfile as a password token. The self-scan config
(``.ash/.ash_alpha_plugins.yaml``) suppresses that false positive for the
Dockerfile and for its build-context copy. A whole-file entry would also hide a real
finding anywhere else in those files, so each entry is pinned to a few lines around the
command. A pin goes stale when the file changes above it: the entry then suppresses
nothing and still reads as fine in the config.

What this checks
----------------
* Each of the two entries carries a line range, not the whole file.
* The range holds the ``adduser --disabled-password`` text.
* A finding on that line is suppressed, and a finding on a line outside the range, a
  different rule, or a different file is not.

``automated_security_helper/assets/Dockerfile`` is a build-time copy of ``Dockerfile``
that is not tracked, so a checkout without a build has no such file. The copy is
byte-identical, so the root ``Dockerfile`` stands in for it when it is absent.
"""

from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.suppression_matcher import should_suppress_finding

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SELF_SCAN = REPO_ROOT / ".ash" / ".ash_alpha_plugins.yaml"
RULE_ID = "API_KEY_OR_SECRET"
FLAGGED_TEXT = "adduser --disabled-password"
PINNED_FILES = ("Dockerfile", "automated_security_helper/assets/Dockerfile")


def _entries(path_name: str) -> List[Dict[str, Any]]:
    config = yaml.safe_load(SELF_SCAN.read_text(encoding="utf-8")) or {}
    entries = (config.get("global_settings") or {}).get("suppressions") or []
    return [
        e for e in entries if e.get("rule_id") == RULE_ID and e.get("path") == path_name
    ]


def _lines(path_name: str) -> List[str]:
    target = REPO_ROOT / path_name
    if not target.is_file():
        target = REPO_ROOT / "Dockerfile"
    return target.read_text(encoding="utf-8").splitlines()


def _finding(path_name: str, line: int, rule_id: str = RULE_ID) -> FlatVulnerability:
    return FlatVulnerability(
        id=f"ferret-{path_name}-{line}",
        title="netrc_password",
        description="Credential-like token",
        severity="HIGH",
        scanner="ferret-scan",
        scanner_type="SECRET",
        rule_id=rule_id,
        file_path=path_name,
        line_start=line,
        line_end=line,
    )


@pytest.mark.parametrize("path_name", PINNED_FILES)
def test_the_ferret_entry_is_pinned_to_a_range_that_holds_the_flagged_text(
    path_name: str,
) -> None:
    entries = _entries(path_name)
    assert len(entries) == 1, f"{path_name}: expected one {RULE_ID} entry"
    entry = entries[0]
    start, end = entry.get("line_start"), entry.get("line_end")
    assert isinstance(start, int) and isinstance(end, int), (
        f"{path_name}: the entry has no line range"
    )
    lines = _lines(path_name)
    assert 1 <= start <= end <= len(lines), f"{path_name}: range past the end of file"
    assert end - start <= 5, f"{path_name}: range {start}-{end} is not tight"
    window = "\n".join(lines[start - 1 : end])
    assert FLAGGED_TEXT in window, (
        f"{path_name}: lines {start}-{end} no longer hold {FLAGGED_TEXT!r}. "
        "Re-measure the pin: the file moved under it."
    )


@pytest.mark.parametrize("path_name", PINNED_FILES)
def test_the_pinned_entry_suppresses_the_flagged_line_and_nothing_else(
    path_name: str,
) -> None:
    entry = _entries(path_name)[0]
    suppression = AshSuppression(**entry)
    flagged = next(
        n for n, text in enumerate(_lines(path_name), 1) if FLAGGED_TEXT in text
    )
    hit, _ = should_suppress_finding(_finding(path_name, flagged), [suppression])
    assert hit, f"{path_name}:{flagged} is not suppressed"

    far = max(flagged - 100, 1)
    assert far < entry["line_start"]
    for control in (
        _finding(path_name, far),
        _finding(path_name, flagged, rule_id="SSN"),
        _finding("README.md", flagged),
    ):
        hit, _ = should_suppress_finding(control, [suppression])
        assert not hit, f"control not expected to be suppressed: {control.file_path}"
