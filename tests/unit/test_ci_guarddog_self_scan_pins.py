# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every line-pinned GuardDog suppression points at a line that holds the flagged text.

Why this exists
---------------
A GuardDog suppression in either ``.ash`` config names one rule, one file and one
line, so a new hit anywhere else, even in the same file, is still reported. The cost
is that the pin goes stale when the file changes above it: the entry then suppresses
nothing, the real hit is reported again, and the stale entry still reads as fine to
anyone looking at the config. Measured when this check was added: 8 of the 13 pins in
each config pointed at a blank line, a comment or an unrelated statement.

What this checks
----------------
Every GuardDog suppression (``threat-*`` and ``capability-*`` rule ids) in either
``.ash`` config pins a line that holds at least one of the markers for its rule id.
A rule id with no row in ``_RULE_LINE_MARKERS`` fails, so the first pin for a new rule
adds its row.
"""

from pathlib import Path
from typing import Any, Dict, List

import pytest
import yaml

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[2]
SELF_SCAN = REPO_ROOT / ".ash" / ".ash_community_plugins.yaml"
DEFAULT = REPO_ROOT / ".ash" / ".ash.yaml"


def _guarddog_pins(path: Path) -> List[Dict[str, Any]]:
    config = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    entries = (config.get("global_settings") or {}).get("suppressions") or []
    return [
        entry
        for entry in entries
        if str(entry.get("rule_id") or "").startswith(("threat-", "capability-"))
    ]


#: Text the pinned line must contain, by rule id: the shape of what each GuardDog
#: rule flags. A pin whose line holds none of its rule's markers is pointing at the
#: wrong line (a fold or an edit moved the file under it), so it suppresses nothing
#: and the real hit goes unsuppressed in the self-scan. A rule id with no row here
#: fails below, so a new rule gets markers when its first pin is added. The same
#: idea already guards the ferret-scan line ranges.
_RULE_LINE_MARKERS = {
    "threat-filesystem-read": (
        "/etc/",
        ".git/",
        "file://",
        "traversal",
        "/root/",
        "/var/",
        "creds.env",  # a test writing a fake credentials file
    ),
    "threat-filesystem-destruction": ("rm -rf", "/home/"),
    "threat-process-download-exec": ("subprocess.run", "urlopen", "curl", "pip"),
    "threat-runtime-obfuscation-base64exec": (
        "b64decode",
        "atob(",
        "exec(",
        "Buffer.from",
    ),
    "threat-runtime-environment-read": ("os.environ",),
}


@pytest.mark.parametrize("config", [SELF_SCAN, DEFAULT], ids=lambda p: p.name)
def test_every_guarddog_pin_names_a_line_that_holds_the_flagged_text(
    config: Path,
) -> None:
    pins = _guarddog_pins(config)
    assert pins, f"{config.name} has no GuardDog suppressions to check"
    for entry in pins:
        where = (
            f"{config.name}: {entry['rule_id']} {entry['path']}:{entry['line_start']}"
        )
        markers = _RULE_LINE_MARKERS.get(entry["rule_id"])
        assert markers, f"{where}: no line markers for this rule id; add a row above"
        lines = (REPO_ROOT / entry["path"]).read_text(encoding="utf-8").splitlines()
        number = entry["line_start"]
        assert 1 <= number <= len(lines), f"{where}: past the end of the file"
        line = lines[number - 1]
        assert any(marker in line for marker in markers), (
            f"{where}: the pinned line holds none of {markers}; it reads {line!r}. "
            "Re-measure the pin: the file moved under it."
        )
