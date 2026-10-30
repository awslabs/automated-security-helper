# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A client exclusion is read, kept and matched as its scanner reads it.

Each test pins one place the post-scan matching, the trivy ignore file reader,
or the move out of the options read more or less than the scanner did:

* A trivy ignore-file ID was compared case-folded, while trivy compares the
  two exactly; an entry still applied on its expiry date, which trivy and
  ASH's own ``expiration`` rule both drop it on; a plain-format line was cut
  at its first ``#``, so an ``exp:`` field after one was lost and the entry
  applied though trivy drops it.
* A finding whose path stayed absolute (the SARIF step could not make it
  relative to the source directory) was matched as a run of directories, so
  an unanchored glob, a checkov substring or a trivy ``paths`` glob took the
  directories above the scan root.
* A ferret-scan ``exclude_patterns`` entry holding a comma was matched whole,
  while ferret-scan is given the list comma-joined and read it as several.
* Every backslash in a finding's path became a separator, so on POSIX the
  file ``a\\b.py`` was matched as ``a/b.py``.
* A trivy ``ignore_file`` held as a Path was neither the operator's nor the
  trusted value to restore, so the operator's file was replaced with None; a
  delivered override reset the option to the trusted config's value, dropping
  an ignore file an operator file of the chain had set; and an entry an
  operator file added through a ``patch`` operation was nobody's, so a client
  copy of it was moved out and marked.
"""

from __future__ import annotations

import os
import threading
import time
from datetime import date
from pathlib import Path
from types import MappingProxyType

import pytest
import yaml

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.client_scanner_exclusions import (
    SCANNER_EXCLUSION_OPTIONS,
    ClientScannerExclusion,
    _entry_fields,
    _pattern_of,
    _same_trivy_id,
    _trusted_ignore_file,
    glob_excludes,
    parse_trivy_ignore_file,
    strip_client_scanner_exclusions,
    trivy_path_matches,
)
from automated_security_helper.models.core import IgnorePathWithReason

pytestmark = pytest.mark.unit


def _spec(scanner: str):
    return next(spec for spec in SCANNER_EXCLUSION_OPTIONS if spec.scanner == scanner)


def _operator_document(tmp_path: Path) -> Path:
    """Where the operator's document sits for these tests: under the test's own
    path, so a relative value in it anchors the same way on every platform (a
    fixed ``/operator`` resolved to ``C:/operator`` on Windows and matched
    nothing)."""
    return tmp_path / "operator" / "ash.yaml"


def _strip(config, delivered: dict, operator: dict | None, tmp_path: Path, base=None):
    documents = {
        _operator_document(tmp_path): operator or {},
        tmp_path / "c.yaml": delivered,
    }
    return strip_client_scanner_exclusions(
        config,
        documents,
        AshConfig() if base is None else base,
        source_dir=tmp_path,
        scanned_root=tmp_path,
        is_delivered=lambda path: Path(path) == tmp_path / "c.yaml",
    )


# ---------------------------------------------------------------------------
# The trivy ignore file is read as trivy reads it
# ---------------------------------------------------------------------------


def test_a_trivy_ignore_id_is_compared_exactly():
    assert _same_trivy_id("CVE-2020-0001", "CVE-2020-0001")
    assert _same_trivy_id("AVD-AWS-0001", "AWS-0001")
    assert _same_trivy_id("AWS-0001", "AVD-AWS-0001")
    assert not _same_trivy_id("cve-2020-0001", "CVE-2020-0001")
    assert not _same_trivy_id("CVE-2020-0001", "cve-2020-0001")


def test_a_trivy_ignore_entry_no_longer_applies_on_its_expiry_date():
    today = date(2026, 1, 1)
    plain = "CVE-1 exp:2026-01-01\nCVE-2 exp:2026-01-02\n"
    assert parse_trivy_ignore_file(plain, yaml_format=False, today=today) == [
        ("CVE-2", ())
    ]
    document = yaml.safe_dump(
        {
            "vulnerabilities": [
                {"id": "CVE-1", "expired_at": "2026-01-01"},
                {"id": "CVE-2", "expired_at": "2026-01-02"},
            ]
        }
    )
    assert parse_trivy_ignore_file(document, yaml_format=True, today=today) == [
        ("CVE-2", ())
    ]


def test_a_yaml_expiry_written_as_a_bare_date_is_read():
    """A real ``.trivyignore.yaml`` writes ``expired_at: 2026-01-01`` with no
    quotes, which ``yaml.safe_load`` gives the parser as a ``datetime.date``,
    not a string; ``safe_dump`` quotes the value, so the dumped documents above
    never exercised that type."""
    document = (
        "vulnerabilities:\n"
        "  - id: CVE-1\n"
        "    expired_at: 2026-01-01\n"
        "  - id: CVE-2\n"
        "    expired_at: 2026-01-02\n"
    )
    assert yaml.safe_load(document)["vulnerabilities"][0]["expired_at"] == date(
        2026, 1, 1
    )
    assert parse_trivy_ignore_file(
        document, yaml_format=True, today=date(2026, 1, 1)
    ) == [("CVE-2", ())]


@pytest.mark.parametrize(
    ("text", "yaml_format"),
    [
        ("CVE-1 exp:soon\nCVE-2\n", False),
        (
            yaml.safe_dump(
                {
                    "vulnerabilities": [
                        {"id": "CVE-1", "expired_at": "soon"},
                        {"id": "CVE-2"},
                    ]
                }
            ),
            True,
        ),
    ],
    ids=["plain", "yaml"],
)
def test_an_expiry_that_is_not_a_date_makes_the_file_unreadable(text, yaml_format):
    """Read as unexpired before, so the entry applied and suppressed findings
    whatever trivy made of a date it could not read. The file is unreadable, as
    one with a scalar section is, so none of its entries is applied and every
    finding they name is reported; the client entry's own rule reads an
    unreadable expiration as expired, the same side."""
    with pytest.raises(ValueError, match="not a YYYY-MM-DD date"):
        parse_trivy_ignore_file(text, yaml_format=yaml_format, today=date(2026, 1, 1))


def test_a_hash_later_in_a_plain_ignore_line_is_text_not_a_comment():
    text = "CVE-1 # exp:2020-01-01\n# CVE-2\n  # CVE-3\nCVE-4 # a note\nCVE-5\n"
    assert parse_trivy_ignore_file(text, yaml_format=False, today=date(2026, 1, 1)) == [
        ("CVE-4", ()),
        ("CVE-5", ()),
    ]


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("exclusion", "inside", "rule_id"),
    [
        (
            ClientScannerExclusion(
                scanner="semgrep",
                option="exclude",
                kind="glob",
                pattern="vendor",
                reason="r",
            ),
            "elsewhere/vendor/a.py",
            None,
        ),
        (
            ClientScannerExclusion(
                scanner="checkov",
                option="skip_path",
                kind="checkov",
                pattern="vendor",
                reason="r",
            ),
            "elsewhere/vendor/a.tf",
            None,
        ),
        (
            ClientScannerExclusion(
                scanner="trivy-repo",
                option="ignore_file",
                kind="trivy-ignore-file",
                pattern="CVE-1",
                reason="r",
                paths=("vendor/**",),
            ),
            "vendor/a.py",
            "CVE-1",
        ),
    ],
)
def test_a_finding_outside_the_scan_root_is_not_hidden_by_a_path_pattern(
    exclusion, inside, rule_id
):
    """A finding the SARIF step could not make relative keeps an absolute path,
    spelled from the platform's own anchor (``/`` on POSIX, a drive on
    Windows); a POSIX-rooted literal is not absolute on Windows and read as a
    path inside the tree there."""
    outside = str(Path(Path.cwd().anchor, inside))
    assert Path(outside).is_absolute()
    assert not exclusion.hides(relative=outside, absolute=outside, rule_id=rule_id)
    kept = inside.removeprefix("elsewhere/")
    assert exclusion.hides(relative=kept, absolute=f"/s/{kept}", rule_id=rule_id)


@pytest.mark.parametrize(
    "outside",
    [
        "/elsewhere/vendor/a.py",
        "C:/elsewhere/vendor/a.py",
        "../vendor/a.py",
        "./../vendor/a.py",
    ],
    ids=["posix-root", "drive", "parent", "dot-parent"],
)
@pytest.mark.parametrize(
    ("scanner", "option", "kind"),
    [
        ("semgrep", "exclude", "glob"),
        ("checkov", "skip_path", "checkov"),
        ("bandit", "excluded_paths", "bandit"),
    ],
    ids=["glob", "checkov", "bandit"],
)
def test_every_spelling_of_a_path_outside_the_tree_hides_nothing(
    scanner, option, kind, outside
):
    """A POSIX root is absolute to ``Path`` on POSIX alone, a drive on Windows
    alone, and a leading ``..`` nowhere, so the glob, checkov and trivy kinds
    read the other platform's spelling, and a path climbing out of the tree, as
    directories above the scan root and matched an unanchored entry against
    them. One reading (``_names_no_root``) now serves every kind, bandit's
    included, whatever the host."""
    exclusion = ClientScannerExclusion(
        scanner=scanner, option=option, kind=kind, pattern="vendor", reason="r"
    )
    assert not exclusion.hides(relative=outside, absolute=f"/s/{outside}", rule_id=None)
    assert exclusion.hides(
        relative="vendor/a.py", absolute="/s/vendor/a.py", rule_id=None
    )


def test_an_id_only_trivy_entry_still_hides_a_finding_outside_the_scan_root():
    entry = ClientScannerExclusion(
        scanner="trivy-repo",
        option="ignore_file",
        kind="trivy-ignore-file",
        pattern="CVE-1",
        reason="r",
    )
    assert entry.hides(
        relative="/elsewhere/a.py", absolute="/elsewhere/a.py", rule_id="CVE-1"
    )


def test_a_ferret_scan_entry_holding_a_comma_is_each_of_its_patterns():
    ferret = ClientScannerExclusion(
        scanner="ferret-scan",
        option="exclude_patterns",
        kind="glob",
        pattern="vendor,build",
        reason="r",
    )
    assert ferret.hides(relative="build/x.py", absolute="/s/build/x.py", rule_id=None)
    assert ferret.hides(relative="vendor/x.py", absolute="/s/vendor/x.py", rule_id=None)
    assert not ferret.hides(relative="src/x.py", absolute="/s/src/x.py", rule_id=None)
    semgrep = ClientScannerExclusion(
        scanner="semgrep",
        option="exclude",
        kind="glob",
        pattern="vendor,build",
        reason="r",
    )
    assert not semgrep.hides(
        relative="build/x.py", absolute="/s/build/x.py", rule_id=None
    )


@pytest.mark.skipif(os.sep != "/", reason="a backslash separates segments on Windows")
def test_a_posix_backslash_is_a_character_of_the_name():
    assert not glob_excludes("b.py", "a\\b.py")
    assert glob_excludes("a\\b.py", "a\\b.py")
    assert glob_excludes("b.py", "a/b.py")


@pytest.mark.parametrize(
    ("pattern", "relative", "excluded"),
    [
        ("build/", "build/x.py", True),
        ("build/", "src/build/x.py", True),
        ("build/", "tools/build", False),
        ("build/", "build", False),
        ("build", "tools/build", True),
        ("./build/", "build/x.py", True),
        ("./build/", "build", False),
        ("**/", "x.py", False),
    ],
)
def test_a_trailing_slash_names_a_directory_not_a_file(pattern, relative, excluded):
    """The tools read ``build/`` as the directory build; the slash was stripped
    before matching, so the entry also hid findings in a file named build."""
    assert glob_excludes(pattern, relative) is excluded


def test_a_pattern_of_repeated_doublestars_answers_at_once():
    """A delivered ``*/**/**/.../zz`` against a deep path. Matched by trying
    every split at every ``**``, it took billions of calls (about C(35, 16) for
    sixteen of them against twenty components) for each finding and entry; the
    position-set match answers in linear time. Five seconds is a loose bound on
    a linear match and far below what the recursive one needed."""
    pattern = "*/" + "**/" * 16 + "zz"
    path = "/".join(f"d{depth}" for depth in range(20))
    answers: dict[str, bool] = {}

    def match() -> None:
        answers["miss"] = glob_excludes(pattern, path)
        answers["hit"] = glob_excludes(pattern, path + "/zz")
        answers["trivy"] = trivy_path_matches(pattern, path + "/zz")

    # Run under a real deadline: checked only after the matcher returned, a
    # matcher that went back to the recursive split would hold this test for
    # hours, until the runner killed the job, instead of failing it at once.
    started = time.monotonic()
    matcher = threading.Thread(target=match, name="doublestar-match", daemon=True)
    matcher.start()
    matcher.join(5.0)
    assert not matcher.is_alive(), "the doublestar match did not answer in 5 s"
    assert time.monotonic() - started < 5.0
    assert answers == {"miss": False, "hit": True, "trivy": True}


@pytest.mark.parametrize(
    ("pattern", "relative", "excluded"),
    [
        ("**/**/a.py", "x/y/a.py", True),
        ("**/**/a.py", "a.py", True),
        # A trailing ``/**`` is everything inside the directory, as gitignore
        # reads it, so a file named ``src`` is left to its tool; the match
        # alone would reach it, since ``**`` takes no component too.
        ("src/**", "src", False),
        ("src/**/**", "src", False),
        ("src/**", "src/a.py", True),
        ("**/build/**", "x/build", False),
        ("**/build/**", "x/build/a.py", True),
        ("src/**/*.py", "src/a.py", True),
        ("src/**/*.py", "src/x/y/a.py", True),
        ("src/**/*.py", "src/x/y/a.js", False),
        ("a/**/b/**/c", "a/b/c", True),
        ("a/**/b/**/c", "a/x/b/y/z/c", True),
        ("a/**/b/**/c", "a/x/c", False),
    ],
)
def test_doublestar_runs_match_as_before(pattern, relative, excluded):
    """The position-set match agrees with the recursive one on every ``**`` shape."""
    assert glob_excludes(pattern, relative) is excluded


# ---------------------------------------------------------------------------
# The move out of the options
# ---------------------------------------------------------------------------


def test_a_path_typed_trusted_ignore_file_is_the_operators(tmp_path):
    base = AshConfig()
    base.scanners.trivy.options.ignore_file = Path("/operator/.trivyignore")
    spec = _spec("trivy")
    assert _trusted_ignore_file(base, spec) == str(Path("/operator/.trivyignore"))

    config = AshConfig()
    options = config.scanners.trivy.options
    options.ignore_file = "/client/.trivyignore"

    _strip(config, {}, None, tmp_path, base=base)

    assert options.ignore_file == str(Path("/operator/.trivyignore"))
    assert config._client_scanner_exclusions == []


def test_an_operator_chain_files_ignore_file_survives_a_delivered_override(tmp_path):
    """The option takes the operator file's value anchored at THAT file's
    directory: a value anchored at the source directory or at the working
    directory would name a file the operator never wrote. The delivered
    document carries the client's override, as a real delivery does."""
    config = AshConfig()
    options = config.scanners.trivy.options
    options.ignore_file = "/client/.trivyignore"
    operator = {"scanners": {"trivy": {"options": {"ignore_file": "op.trivyignore"}}}}
    delivered = {
        "scanners": {"trivy": {"options": {"ignore_file": "/client/.trivyignore"}}}
    }

    _strip(config, delivered, operator, tmp_path)

    assert options.ignore_file == str(
        _operator_document(tmp_path).parent / "op.trivyignore"
    )
    assert config._client_scanner_exclusions == []


def test_an_entry_an_operator_file_adds_by_a_patch_operation_is_the_operators(
    tmp_path,
):
    """The option keeps the operator's own entry (its reason and expiration),
    not the client's copy. The operator's entry is unexpired here: an expired
    operator entry now drops the client's copy altogether, which
    ``test_a_client_copy_of_an_expired_operator_entry_is_dropped`` pins."""
    config = AshConfig()
    config.scanners.bandit.options.excluded_paths = [
        IgnorePathWithReason(path="shared", reason="client says"),
    ]
    operator = {
        "patch": [
            {
                "op": "add",
                "path": "/scanners/bandit/options/excluded_paths/-",
                "value": {"path": "shared", "reason": "op", "expiration": "2099-01-01"},
            }
        ]
    }

    _strip(config, {}, operator, tmp_path)

    kept = config.scanners.bandit.options.excluded_paths
    assert [entry.path for entry in kept] == ["shared"]
    assert kept[0].expiration == "2099-01-01"
    assert kept[0].reason == "op"
    assert config._client_scanner_exclusions == []


def test_an_entry_held_in_a_mapping_that_is_not_a_dict_reads_whole():
    """The pattern, reason and expiration of one entry come from the same
    reading: an entry in a mapping type that is not a ``dict`` read as a
    pattern-less entry (kept untouched) while its expiration was read, so the
    two readings of one entry disagreed."""
    entry = MappingProxyType(
        {"path": "vendor", "reason": "r", "expiration": "2000-01-01"}
    )
    assert _pattern_of(entry) == ("vendor", "r")
    assert _entry_fields(entry) == ("vendor", "r", "2000-01-01")
    assert _entry_fields({"path": "vendor"}) == ("vendor", None, None)
    assert _entry_fields("vendor") == ("vendor", None, None)
