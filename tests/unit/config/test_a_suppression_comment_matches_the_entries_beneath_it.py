# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression block's comment, and the tests its entries cite, say what the entries do.

Why this exists
---------------
Each suppression block in ``.ash.yaml`` and ``.ash/.ash_alpha_plugins.yaml`` opens with
a comment that states a decision, and its entries carry the numbers that carry the
decision out. Nothing held the two together, and they drifted three ways:

* a block headed "(expires 2026-12-27)" held one entry that expires on 2027-02-06,
  so three of the four spellings of one advisory lapse six weeks before the fourth;
* a block whose comment says its entries "carry no expiration" held five entries
  that expire on 2027-05-06;
* an entry's reason named a guard test that is not in the tree, so a reader who
  went looking for what fails when the pinned line moves found nothing.

What this checks
----------------
* A block header that states ``(expires DATE)`` has no entry in the block with another
  expiry.
* A block whose comment says its entries carry no expiration has no entry with one.
* Every ``tests/...py`` path a config names, in a comment or in a reason, is a file in
  the repository.
"""

import re
from pathlib import Path
from typing import Dict, List, Set

import pytest

pytestmark = pytest.mark.unit

REPO_ROOT = Path(__file__).resolve().parents[3]
CONFIGS = (".ash.yaml", ".ash/.ash_alpha_plugins.yaml")

_HEADER = re.compile(r"^\s*# === (?P<title>.*?) ===\s*$")
_TOP_LEVEL_KEY = re.compile(r"^ {2}[A-Za-z_]")
_EXPIRY = re.compile(r"^\s+expir(?:es|ation):\s*[\"']?(?P<date>\d{4}-\d{2}-\d{2})")
_HEADER_DATE = re.compile(r"\(expires (?P<date>\d{4}-\d{2}-\d{2})\)")
_NO_EXPIRATION = re.compile(r"carry no expiration")
_TEST_PATH = re.compile(r"tests/[A-Za-z0-9_./-]+\.py")
_PATH_KEY = re.compile(r"^\s*(?:-\s+)?path:")


def _named_test_paths(text: str) -> List[str]:
    """Test files named in comments and reasons; an entry's own ``path:`` is not one."""
    prose = [line for line in text.splitlines() if not _PATH_KEY.match(line)]
    return sorted(set(_TEST_PATH.findall("\n".join(prose))))


class Block:
    def __init__(self, title: str) -> None:
        self.title = title
        self.comment: List[str] = []
        self.expiries: Set[str] = set()


def _blocks(text: str) -> List[Block]:
    blocks: List[Block] = []
    current = None
    for line in text.splitlines():
        header = _HEADER.match(line)
        if header:
            current = Block(header.group("title"))
            blocks.append(current)
            continue
        if _TOP_LEVEL_KEY.match(line):
            current = None
            continue
        if current is None:
            continue
        stripped = line.strip()
        if stripped.startswith("#"):
            current.comment.append(stripped.lstrip("#").strip())
            continue
        expiry = _EXPIRY.match(line)
        if expiry:
            current.expiries.add(expiry.group("date"))
    return blocks


def _read(config: str) -> str:
    return (REPO_ROOT / config).read_text(encoding="utf-8")


def _problems_with_a_stated_expiry(blocks: List[Block]) -> Dict[str, str]:
    found = {}
    for block in blocks:
        stated = _HEADER_DATE.search(block.title)
        if stated and block.expiries != {stated.group("date")}:
            found[block.title] = (
                f"the header says {stated.group('date')}, the entries expire "
                f"{sorted(block.expiries) or 'never'}"
            )
    return found


def _problems_with_no_expiration(blocks: List[Block]) -> Dict[str, str]:
    found = {}
    for block in blocks:
        said = _NO_EXPIRATION.search(" ".join(block.comment))
        if said and block.expiries:
            found[block.title] = (
                f"the comment says the entries carry no expiration, "
                f"but they expire {sorted(block.expiries)}"
            )
    return found


@pytest.mark.parametrize("config", CONFIGS)
def test_a_header_that_states_an_expiry_matches_every_entry_beneath_it(
    config: str,
) -> None:
    assert _problems_with_a_stated_expiry(_blocks(_read(config))) == {}, config


@pytest.mark.parametrize("config", CONFIGS)
def test_a_comment_that_says_no_expiration_has_no_entry_with_one(config: str) -> None:
    assert _problems_with_no_expiration(_blocks(_read(config))) == {}, config


@pytest.mark.parametrize("config", CONFIGS)
def test_every_test_file_a_config_names_exists(config: str) -> None:
    named = _named_test_paths(_read(config))
    assert named, "the config names no test file, so this checks nothing"
    missing = [path for path in named if not (REPO_ROOT / path).is_file()]
    assert missing == [], f"{config} names test files that are not in the tree"


# Controls: the readers above, fed text whose answer is known.

_STATED = (
    "  suppressions:\n"
    "    # === Time-boxed: thing (expires 2026-12-27) ===\n"
    "    - rule_id: A\n"
    '      expires: "2026-12-27"\n'
    "    - rule_id: B\n"
    '      expires: "2027-02-06"\n'
    "    # === Time-boxed: other (expires 2026-12-27) ===\n"
    "    - rule_id: C\n"
    '      expires: "2026-12-27"\n'
)


def test_the_reader_finds_a_block_whose_entries_expire_on_another_date() -> None:
    assert list(_problems_with_a_stated_expiry(_blocks(_STATED))) == [
        "Time-boxed: thing (expires 2026-12-27)"
    ]


def test_the_reader_finds_an_entry_with_an_expiry_under_a_no_expiration_comment() -> (
    None
):
    text = (
        "  suppressions:\n"
        "    # === fixtures ===\n"
        "    # these are permanent, so the entries carry no\n"
        "    # expiration, as the others do.\n"
        "    - rule_id: A\n"
        '      expires: "2027-05-06"\n'
        "    # === other ===\n"
        "    - rule_id: B\n"
        '      expires: "2027-05-06"\n'
    )
    assert list(_problems_with_no_expiration(_blocks(text))) == ["fixtures"]


def test_the_reader_passes_blocks_that_say_what_their_entries_do() -> None:
    text = (
        "  suppressions:\n"
        "    # === fixtures ===\n"
        "    # the entries carry no expiration.\n"
        "    - rule_id: A\n"
        "    # === Time-boxed: thing (expires 2026-12-27) ===\n"
        "    - rule_id: B\n"
        '      expires: "2026-12-27"\n'
        "  ignore_paths:\n"
        "    - path: x\n"
        '      expires: "2030-01-01"\n'
    )
    blocks = _blocks(text)
    assert _problems_with_a_stated_expiry(blocks) == {}
    assert _problems_with_no_expiration(blocks) == {}


def test_the_path_reader_finds_a_test_named_in_prose_and_not_an_entrys_own_path() -> (
    None
):
    text = (
        "    - rule_id: A\n"
        "      path: tests/own/entry_path.py\n"
        "      reason: tests/unit/config/test_x.py fails if the row moves; tests/y/z.py.\n"
        "    - path: tests/own/second_entry.py\n"
    )
    assert _named_test_paths(text) == ["tests/unit/config/test_x.py", "tests/y/z.py"]
