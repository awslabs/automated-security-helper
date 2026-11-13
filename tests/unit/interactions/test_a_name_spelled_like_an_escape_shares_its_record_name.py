# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A file named with an escape's characters shares its record name with the file the escape stands for.

On POSIX a file name may hold a backslash. ``a\\udce9.py`` spelled with the six ASCII
characters ``\\``, ``u``, ``d``, ``c``, ``e``, ``9`` is one file; ``a\\xe9.py``, whose
0xE9 byte is not UTF-8, is another. A result records the second in the record form,
its surrogate written as those same six characters, and the record form is plain text
that holds as it is when it is recorded again (a results file read back is validated
again). So both files have one record name, ``a\\udce9.py``.

That shared name is a known limit, on POSIX only: Windows cannot hold either name. What
holds for the two files:

- both are scanned and both files' findings are in the results, under a plain scan, in
  a report ``ash report`` renders from the saved results, and under
  ``--changed-files-only``;
- the results name both with the one record name;
- an ignore path or a suppression naming either file applies to both. Config names the
  file with the byte by the YAML escape, which reads as the surrogate it holds, and the
  file with the characters by its own name, which is also how the report shows both.

Each file's finding is on its own line (2 and 4), which says which file a finding is
in. Only some filesystems can hold the names; elsewhere the tests skip, with the reason.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Dict, List

import pytest

from tests.utils import undecodable_names as names
from tests.utils.undecodable_names import ABSENT, KEEP, REPORTED, SUPPRESSED

pytestmark = pytest.mark.integration

# Every test here plants a file whose name is not UTF-8.
if os.name == "nt":
    pytest.skip(
        "a file name that is not UTF-8 cannot exist on NTFS (names are UTF-16)",
        allow_module_level=True,
    )

#: The file named with the byte, and the line its finding is on.
BYTE_NAME = b"a\xe9.py"
BYTE_LINE = names.secret_line_number(0)
#: The file named with the six characters, and the line its finding is on.
TEXT_NAME = b"a\\udce9.py"
TEXT_LINE = names.secret_line_number(2)
#: The one record name both files have.
RECORD_NAME = "a\\udce9.py"

#: A changed file named with a byte alone, and its record name. No sibling
#: spells its record name in characters, so a changed-files decision made on
#: raw names has nothing to pair it with; it must still be scanned.
LONE_BYTE_NAME = b"c\xe9.py"
LONE_LINE = names.secret_line_number(3)
LONE_RECORD_NAME = "c\\udce9.py"

#: How config names each file: the byte one by the YAML escape of its surrogate, the
#: other by its own six characters.
SPELLINGS: Dict[str, str] = {
    "names-the-file-with-the-byte": '"a\\udce9.py"',
    "names-the-file-with-the-characters": "'a\\udce9.py'",
}


def _files() -> Dict[object, bytes]:
    return {
        BYTE_NAME: names.secret_source(0),
        TEXT_NAME: names.secret_source(2),
        KEEP: names.secret_source(5),
    }


def _by_line(found: List[names.Finding], line: int) -> List[names.Finding]:
    return [f for f in found if f.line == line and f.uri != KEEP]


def _state(found: List[names.Finding]) -> str:
    states = {f.suppressed for f in found}
    if not states:
        return ABSENT
    return (
        SUPPRESSED if states == {True} else REPORTED if states == {False} else "mixed"
    )


def _states(found: List[names.Finding]) -> Dict[str, str]:
    return {
        "byte": _state(_by_line(found, BYTE_LINE)),
        "text": _state(_by_line(found, TEXT_LINE)),
        "keep": _state([f for f in found if f.uri == KEEP]),
    }


def _odd_uris(found: List[names.Finding]) -> set:
    return {f.uri for f in found if f.uri != KEEP}


def test_both_files_are_reported_under_one_record_name(tmp_path):
    source = names.make_tree(tmp_path / "src", _files())
    output = tmp_path / "out"

    ran = names.scan(tmp_path, source, output)

    assert names.results_file(output).is_file(), ran
    found = names.findings(output)
    expected = {"byte": REPORTED, "text": REPORTED, "keep": REPORTED}
    assert _states(found) == expected, (found, ran)
    assert _odd_uris(found) == {RECORD_NAME}, (found, ran)

    # A report rendered again from the saved results keeps both files' findings too.
    report = names.report_of(tmp_path, output, "flat-json")
    assert report.code == 0, report
    flat = names.flat_findings(report.stdout_bytes.decode("utf-8"))
    assert _states(flat) == expected, (flat, report)
    assert _odd_uris(flat) == {RECORD_NAME}, (flat, report)


def test_both_files_findings_are_kept_under_changed_files_only(tmp_path):
    source = names.make_tree(tmp_path / "src", {KEEP: names.secret_source(5)})
    names.git(source, "init", "-q", "-b", "main")
    names.git(source, "add", "-A")
    names.git(source, "commit", "-q", "-m", "base")
    names.git(source, "branch", "base")
    files = _files()
    files.pop(KEEP)
    files[LONE_BYTE_NAME] = names.secret_source(3)
    names.make_tree(source, files)
    names.git(source, "add", "-A")
    names.git(source, "commit", "-q", "-m", "change")
    output = tmp_path / "out"

    ran = names.scan(
        tmp_path, source, output, "--changed-files-only", "--base-ref", "base"
    )

    assert names.results_file(output).is_file(), ran
    found = names.findings(output)
    expected = {"byte": REPORTED, "text": REPORTED, "keep": ABSENT}
    assert _states(found) == expected, (found, ran)
    # The lone byte-named file changed too. Nothing pairs with its record name,
    # so only the changed-files decision itself can keep it.
    assert _state(_by_line(found, LONE_LINE)) == REPORTED, (found, ran)
    assert _odd_uris(found) == {RECORD_NAME, LONE_RECORD_NAME}, (found, ran)


def _config(tmp_path: Path, key: str, spelling: str) -> Path:
    config = tmp_path / "operator.yaml"
    rule = "      rule_id: 'SECRET-*'\n" if key == "suppressions" else ""
    config.write_text(
        "global_settings:\n"
        f"  {key}:\n"
        f"    - path: {spelling}\n"
        f"{rule}"
        "      reason: decided by name\n",
        encoding="utf-8",
    )
    return config


@pytest.mark.parametrize("spelling", sorted(SPELLINGS))
def test_a_suppression_naming_either_file_applies_to_both(tmp_path, spelling):
    source = names.make_tree(tmp_path / "src", _files())
    output = tmp_path / "out"
    config = _config(tmp_path, "suppressions", SPELLINGS[spelling])

    ran = names.scan(tmp_path, source, output, "--config", str(config))

    assert names.results_file(output).is_file(), ran
    found = names.findings(output)
    expected = {"byte": SUPPRESSED, "text": SUPPRESSED, "keep": REPORTED}
    assert _states(found) == expected, (found, ran)


def test_both_files_findings_are_kept_when_one_of_them_changed(tmp_path):
    files = _files()
    files[LONE_BYTE_NAME] = names.secret_source(3)
    source = names.make_tree(tmp_path / "src", files)
    names.git(source, "init", "-q", "-b", "work")
    names.git(source, "add", "-A")
    names.git(source, "commit", "-q", "-m", "base")
    names.git(source, "branch", "base")
    names.make_tree(
        source,
        {
            TEXT_NAME: names.secret_source(2) + b"# changed\n",
            LONE_BYTE_NAME: names.secret_source(3) + b"# changed\n",
        },
    )
    names.git(source, "add", "-A")
    names.git(source, "commit", "-q", "-m", "change")
    output = tmp_path / "out"

    ran = names.scan(
        tmp_path, source, output, "--changed-files-only", "--base-ref", "base"
    )

    assert names.results_file(output).is_file(), ran
    found = names.findings(output)
    expected = {"byte": REPORTED, "text": REPORTED, "keep": ABSENT}
    assert _states(found) == expected, (found, ran)
    # The lone byte-named file changed too. Nothing pairs with its record name,
    # so only the changed-files decision itself can keep it.
    assert _state(_by_line(found, LONE_LINE)) == REPORTED, (found, ran)
    assert _odd_uris(found) == {RECORD_NAME, LONE_RECORD_NAME}, (found, ran)


@pytest.mark.parametrize("spelling", sorted(SPELLINGS))
def test_an_ignore_path_naming_either_file_applies_to_both(tmp_path, spelling):
    source = names.make_tree(tmp_path / "src", _files())
    output = tmp_path / "out"
    config = _config(tmp_path, "ignore_paths", SPELLINGS[spelling])

    ran = names.scan(tmp_path, source, output, "--config", str(config))

    assert names.results_file(output).is_file(), ran
    found = names.findings(output)
    expected = {"byte": ABSENT, "text": ABSENT, "keep": REPORTED}
    assert _states(found) == expected, (found, ran)


#: Mixed decisions: an ignore naming one spelling with a suppression naming the
#: other, and a suppression naming one spelling alone. One record name means
#: each decision lands on both files, so no case leaves the two files in
#: different states; an ignore removes both from the scan entirely.
MIXED_DECISIONS: Dict[str, tuple] = {
    "ignore-the-characters-suppress-the-byte": (
        SPELLINGS["names-the-file-with-the-characters"],
        SPELLINGS["names-the-file-with-the-byte"],
        ABSENT,
    ),
    "ignore-the-byte-suppress-the-characters": (
        SPELLINGS["names-the-file-with-the-byte"],
        SPELLINGS["names-the-file-with-the-characters"],
        ABSENT,
    ),
    "suppress-the-byte-only": (
        None,
        SPELLINGS["names-the-file-with-the-byte"],
        SUPPRESSED,
    ),
    "suppress-the-characters-only": (
        None,
        SPELLINGS["names-the-file-with-the-characters"],
        SUPPRESSED,
    ),
}


def _decisions_config(tmp_path: Path, ignore: str | None, suppress: str) -> Path:
    """An operator config suppressing one spelling, under an ignore of the other."""
    config = tmp_path / "operator.yaml"
    lines = ["global_settings:"]
    if ignore is not None:
        lines += [
            "  ignore_paths:",
            f"    - path: {ignore}",
            "      reason: decided by name",
        ]
    lines += [
        "  suppressions:",
        f"    - path: {suppress}",
        "      rule_id: 'SECRET-*'",
        "      reason: decided by name",
    ]
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return config


@pytest.mark.parametrize("case", sorted(MIXED_DECISIONS))
def test_a_mixed_decision_applies_to_both_files_in_the_rendered_report_too(
    tmp_path, case
):
    """An ignored pair is absent and a suppressed pair stays suppressed, in the
    scan's results and in a report ``ash report`` renders again from the saved
    results."""
    ignore, suppress, state = MIXED_DECISIONS[case]
    source = names.make_tree(tmp_path / "src", _files())
    output = tmp_path / "out"
    config = _decisions_config(tmp_path, ignore, suppress)

    ran = names.scan(tmp_path, source, output, "--config", str(config))

    assert names.results_file(output).is_file(), ran
    expected = {"byte": state, "text": state, "keep": REPORTED}
    assert _states(names.findings(output)) == expected, ran

    report = names.report_of(tmp_path, output, "flat-json")
    assert report.code == 0, report
    flat = names.flat_findings(report.stdout_bytes.decode("utf-8"))
    assert _states(flat) == expected, (flat, report)
