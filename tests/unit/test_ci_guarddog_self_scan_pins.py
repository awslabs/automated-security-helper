# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The self-scan runs GuardDog with no hit limit, and every GuardDog pin is one line
that holds the flagged text.

Why this exists
---------------
GuardDog stops a rule after 1, 3 or 5 hits per package root unless
``scanners.guarddog.options.max_hits`` says otherwise. With the default, the
repository's own self-scan (``.ash/.ash_community_plugins.yaml``) stopped
threat-filesystem-read at its 5th hit, so matches past it were never reported or
reviewed. The self-scan sets ``max_hits: 0`` so every hit is visible, and each hit
it reports that is a test or fixture doing what the rule describes is suppressed
on its own line.

A GuardDog suppression in either ``.ash`` config names one rule, one file and one
line, so a new hit anywhere else, even in the same file, is still reported. The cost
is that the pin goes stale when the file changes above it: the entry then suppresses
nothing, the real hit is reported again, and the stale entry still reads as fine to
anyone looking at the config. Measured when that check was added: 8 of the 13 pins in
each config pointed at a blank line, a comment or an unrelated statement.

What this checks
----------------
* The self-scan config sets ``max_hits: 0`` for GuardDog.
* Every GuardDog suppression (``threat-*`` and ``capability-*`` rule ids) in either
  ``.ash`` config names one rule, one file and one line, so a new hit anywhere
  else, even in the same file, is still reported.
* Every such pin names a line that holds at least one of the markers for its rule
  id. A rule id with no row in ``_RULE_LINE_MARKERS`` fails, so the first pin for a
  new rule adds its row.
* Both configs carry the same GuardDog suppressions, as their comments say: the
  self-scan reads only the community config, and ``.ash/.ash.yaml`` keeps the
  same entries for a scan that lists the GuardDog module there.
"""

from pathlib import Path
from typing import Any, Dict, List, Tuple

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SELF_SCAN = REPO_ROOT / ".ash" / ".ash_community_plugins.yaml"
DEFAULT = REPO_ROOT / ".ash" / ".ash.yaml"
GLOB_CHARACTERS = set("*?[")


def _load(path: Path) -> Dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _guarddog_pins(path: Path) -> List[Dict[str, Any]]:
    entries = (_load(path).get("global_settings") or {}).get("suppressions") or []
    return [
        entry
        for entry in entries
        if str(entry.get("rule_id") or "").startswith(("threat-", "capability-"))
    ]


def _key(entry: Dict[str, Any]) -> Tuple[Any, ...]:
    return (
        entry["rule_id"],
        entry["path"],
        entry.get("line_start"),
        entry.get("line_end"),
    )


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
        ".npmrc",  # a package manager's rc file, named in a docstring
        "container.env",  # the env file ASH writes for its own container run
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


def test_the_self_scan_reports_every_guarddog_hit() -> None:
    guarddog = (_load(SELF_SCAN).get("scanners") or {}).get("guarddog") or {}
    assert (guarddog.get("options") or {}).get("max_hits") == 0


@pytest.mark.parametrize("config", [SELF_SCAN, DEFAULT], ids=lambda p: p.name)
def test_every_guarddog_suppression_is_one_rule_one_file_one_line(
    config: Path,
) -> None:
    pins = _guarddog_pins(config)
    assert pins, f"{config.name} has no GuardDog suppressions to check"
    for entry in pins:
        where = f"{config.name}: {entry}"
        assert not GLOB_CHARACTERS & set(entry["rule_id"]), where
        assert not GLOB_CHARACTERS & set(entry.get("path") or "*"), where
        assert isinstance(entry.get("line_start"), int), where
        assert entry.get("line_end") == entry["line_start"], where
        assert str(entry.get("reason") or "").strip(), where


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


def test_both_configs_carry_the_same_guarddog_suppressions() -> None:
    self_scan = sorted(_key(e) for e in _guarddog_pins(SELF_SCAN))
    default = sorted(_key(e) for e in _guarddog_pins(DEFAULT))
    assert self_scan == default
    assert len(set(self_scan)) == len(self_scan), "a GuardDog pin is listed twice"
