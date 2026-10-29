# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A client exclusion is applied after the scan only as its scanner would have applied it.

Each test pins one way the post-scan matching, or the move out of the options,
said more than the scanner did:

* ``glob_excludes`` matched with ``fnmatch``, whose ``*`` crosses ``/``, and a
  ``/`` inside the pattern anchored nothing, so ``src/*.py`` suppressed
  ``src/a/b.py`` and ``src/vendor`` suppressed ``x/src/vendor/a.py``.
* A ``.trivyignore.yaml`` entry's ``paths`` were matched at any depth, while
  trivy matches them whole from the scan root; an entry limited by ``purls``
  was applied to every package.
* A ``.trivyignore.yaml`` whose section or ``paths`` was a scalar raised an
  uncaught TypeError; a NUL character in a delivered ``ignore_file`` value
  raised an uncaught ValueError; both ended config resolution.
* An expired client entry was moved and suppressed findings the scanner would
  have reported; a client entry repeating an operator's path stayed in the
  option as the client's own object, so an exclusion the operator let expire
  kept excluding; an entry under a section spelling the scanner never reads was
  recorded as an exclusion; a relative operator ``ignore_file`` was taken for
  the client's because the merged config holds it anchored.
* ``applies_to`` reduced two plugin names with regular expressions on every
  call, once per finding per exclusion, and checkov's skip path was compiled
  per candidate path.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.client_scanner_exclusions import (
    SCANNER_EXCLUSION_OPTIONS,
    ClientScannerExclusion,
    _checkov_pattern,
    _reduced,
    _trivy_ignore_exclusions,
    checkov_skips,
    glob_excludes,
    parse_trivy_ignore_file,
    strip_client_scanner_exclusions,
    trivy_path_matches,
)
from automated_security_helper.models.core import IgnorePathWithReason

pytestmark = pytest.mark.unit


# ---------------------------------------------------------------------------
# Globs match as the tools match them
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("pattern", "relative", "excluded"),
    [
        ("src/*.py", "src/b.py", True),
        ("src/*.py", "src/a/b.py", False),
        ("src/vendor", "src/vendor/a.py", True),
        ("src/vendor", "x/src/vendor/a.py", False),
        ("**/vendor/lib", "a/vendor/lib/x.py", True),
        ("*.py", "a/b/c.py", True),
        ("vendor", "a/vendor/b.py", True),
        ("vendor/", "a/vendor/b.py", True),
        ("./out/**", "out/a/b.json", True),
        ("./out/**", "x/out/a.json", False),
        ("/vendor", "vendor/a.py", True),
        ("/vendor", "x/vendor/a.py", False),
        ("a?c", "x/abc/y.py", True),
        ("a?c", "x/a/c/y.py", False),
        ("", "a.py", False),
    ],
)
def test_glob_excludes_reads_the_pattern_as_the_tool_does(pattern, relative, excluded):
    assert glob_excludes(pattern, relative) is excluded


@pytest.mark.parametrize(
    ("pattern", "relative", "matched"),
    [
        ("requirements.txt", "requirements.txt", True),
        ("requirements.txt", "vendor/requirements.txt", False),
        ("vendor/**", "vendor/a/requirements.txt", True),
        ("vendor/**", "x/vendor/a/requirements.txt", False),
        ("**/requirements.txt", "vendor/requirements.txt", True),
        ("vendor/*/requirements.txt", "vendor/a/requirements.txt", True),
        ("vendor/*/requirements.txt", "vendor/a/b/requirements.txt", False),
    ],
)
def test_trivy_paths_match_whole_from_the_scan_root(pattern, relative, matched):
    assert trivy_path_matches(pattern, relative) is matched


def test_a_trivy_entry_limited_to_a_path_hides_that_path_alone():
    entry = ClientScannerExclusion(
        scanner="trivy-repo",
        option="ignore_file",
        kind="trivy-ignore-file",
        pattern="CVE-2020-0001",
        reason="r",
        paths=("requirements.txt",),
    )
    assert entry.hides(
        relative="requirements.txt",
        absolute="/s/requirements.txt",
        rule_id="CVE-2020-0001",
    )
    assert not entry.hides(
        relative="vendor/requirements.txt",
        absolute="/s/vendor/requirements.txt",
        rule_id="CVE-2020-0001",
    )


# ---------------------------------------------------------------------------
# The trivy ignore file reader
# ---------------------------------------------------------------------------


def test_a_scalar_section_is_a_parse_error():
    with pytest.raises(ValueError):
        parse_trivy_ignore_file(
            yaml.safe_dump({"vulnerabilities": 5}), yaml_format=True
        )


def test_a_scalar_paths_value_is_a_parse_error():
    with pytest.raises(ValueError):
        parse_trivy_ignore_file(
            yaml.safe_dump(
                {"vulnerabilities": [{"id": "CVE-1", "paths": "requirements.txt"}]}
            ),
            yaml_format=True,
        )


def test_an_entry_limited_by_purls_is_not_applied():
    text = yaml.safe_dump(
        {
            "vulnerabilities": [
                {"id": "CVE-1", "purls": ["pkg:pypi/requests@2.0"]},
                {"id": "CVE-2"},
            ]
        }
    )
    assert parse_trivy_ignore_file(text, yaml_format=True) == [("CVE-2", ())]


def test_a_nul_in_the_ignore_file_value_is_read_as_unreadable(tmp_path):
    spec = next(s for s in SCANNER_EXCLUSION_OPTIONS if s.scanner == "trivy-repo")
    found, note = _trivy_ignore_exclusions(
        "a\x00b", spec, source_dir=tmp_path, root=tmp_path
    )
    assert found == []
    assert "could not be read" in note


# ---------------------------------------------------------------------------
# The move out of the options
# ---------------------------------------------------------------------------


def _strip(config, delivered: dict, operator: dict | None, tmp_path: Path):
    documents = {
        Path("/operator/ash.yaml"): operator or {},
        tmp_path / "c.yaml": delivered,
    }
    return strip_client_scanner_exclusions(
        config,
        documents,
        AshConfig(),
        source_dir=tmp_path,
        scanned_root=tmp_path,
        is_delivered=lambda path: Path(path) == tmp_path / "c.yaml",
    )


def _bandit_paths(config) -> list[str]:
    return [entry.path for entry in config.scanners.bandit.options.excluded_paths]


def test_an_expired_client_entry_is_neither_kept_nor_recorded(tmp_path):
    config = AshConfig()
    config.scanners.bandit.options.excluded_paths = [
        IgnorePathWithReason(path="old", reason="r", expiration="2000-01-01"),
        IgnorePathWithReason(path="new", reason="r"),
    ]

    _strip(config, {}, None, tmp_path)

    assert _bandit_paths(config) == []
    assert [item.pattern for item in config._client_scanner_exclusions] == ["new"]
    assert any(
        "'old'" in warning and "expired" in warning
        for warning in config._resolution_warnings
    ), config._resolution_warnings


def test_a_client_copy_of_an_operator_entry_takes_the_operators_expiration(tmp_path):
    config = AshConfig()
    config.scanners.bandit.options.excluded_paths = [
        IgnorePathWithReason(path="shared", reason="client says"),
    ]
    operator = {
        "scanners": {
            "bandit": {
                "options": {
                    "excluded_paths": [
                        {"path": "shared", "reason": "op", "expiration": "2000-01-01"}
                    ]
                }
            }
        }
    }

    _strip(config, {}, operator, tmp_path)

    kept = config.scanners.bandit.options.excluded_paths
    assert [entry.path for entry in kept] == ["shared"]
    assert isinstance(kept[0], IgnorePathWithReason)
    assert kept[0].expiration == "2000-01-01"
    assert kept[0].reason == "op"
    assert config._client_scanner_exclusions == []


def test_an_entry_under_a_spelling_the_scanner_never_reads_is_not_recorded(tmp_path):
    config = AshConfig()
    extra = config.scanners.__pydantic_extra__
    assert extra is not None
    extra["bandit-scanner"] = {
        "options": {"excluded_paths": [{"path": "extra", "reason": "r"}]}
    }
    config.scanners.bandit.options.excluded_paths = [
        IgnorePathWithReason(path="read", reason="r")
    ]

    _strip(config, {}, None, tmp_path)

    assert [item.pattern for item in config._client_scanner_exclusions] == ["read"]
    assert extra["bandit-scanner"]["options"]["excluded_paths"] == []
    assert any(
        "'extra'" in warning and "does not read" in warning
        for warning in config._resolution_warnings
    ), config._resolution_warnings


def test_an_operators_relative_ignore_file_is_not_taken_for_the_clients(tmp_path):
    """The merged config holds the operator's value anchored at the config file's
    directory; the operator document holds the text as written. Compared as text
    alone, the anchored value looked like the client's and was replaced."""
    config = AshConfig()
    options = config.scanners.trivy.options
    options.ignore_file = "/operator/.trivyignore"
    operator = {"scanners": {"trivy": {"options": {"ignore_file": ".trivyignore"}}}}

    _strip(config, {}, operator, tmp_path)

    assert options.ignore_file == "/operator/.trivyignore"
    assert config._client_scanner_exclusions == []


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need a privilege")
def test_a_client_link_to_the_operators_ignore_file_is_replaced_by_its_path(
    tmp_path,
):
    """A client value admitted because it RESOLVES to the operator's file is not
    left in the option: trivy opens the option's value by name later, so a link
    the client controls would be a check here and a different file there. The
    option carries the operator's own resolved path instead."""
    operator_file = tmp_path / "operator" / ".trivyignore"
    operator_file.parent.mkdir()
    operator_file.write_text("CVE-1\n", encoding="utf-8")
    link = tmp_path / "client-link"
    link.symlink_to(operator_file)
    config = AshConfig()
    options = config.scanners.trivy.options
    options.ignore_file = str(link)
    operator = {"scanners": {"trivy": {"options": {"ignore_file": str(operator_file)}}}}

    _strip(config, {}, operator, tmp_path)

    assert options.ignore_file == operator_file.resolve().as_posix()
    assert options.ignore_file != str(link)
    assert any(
        "resolves to the operator's ignore file" in warning
        for warning in config._resolution_warnings
    )


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need a privilege")
def test_a_client_link_resolving_elsewhere_is_still_stripped(tmp_path):
    operator_file = tmp_path / "operator" / ".trivyignore"
    operator_file.parent.mkdir()
    operator_file.write_text("CVE-1\n", encoding="utf-8")
    elsewhere = tmp_path / "elsewhere.yaml"
    elsewhere.write_text("vulnerabilities:\n  - id: CVE-2\n", encoding="utf-8")
    link = tmp_path / "client-link"
    link.symlink_to(elsewhere)
    config = AshConfig()
    options = config.scanners.trivy.options
    options.ignore_file = str(link)
    operator = {"scanners": {"trivy": {"options": {"ignore_file": str(operator_file)}}}}

    _strip(config, {}, operator, tmp_path)

    assert options.ignore_file != str(link)
    assert options.ignore_file != elsewhere.resolve().as_posix()


# ---------------------------------------------------------------------------
# Work done once
# ---------------------------------------------------------------------------


def test_plugin_name_reduction_is_remembered():
    _reduced.cache_clear()
    entry = ClientScannerExclusion(
        scanner="bandit",
        option="excluded_paths",
        kind="bandit",
        pattern="x",
        reason="r",
    )
    assert entry.applies_to("bandit")
    assert entry.applies_to("bandit")
    assert _reduced.cache_info().hits >= 1


def test_the_checkov_pattern_is_compiled_once():
    _checkov_pattern.cache_clear()
    assert checkov_skips("vendor", "/scan/vendor/x.tf", "vendor/x.tf") is True
    assert checkov_skips("vendor", "/scan/vendor/y.tf", "vendor/y.tf") is True
    assert _checkov_pattern.cache_info().misses == 1
    assert _checkov_pattern.cache_info().hits >= 1
    assert checkov_skips("[", "/scan/a[b/x.tf", "a[b/x.tf") is True
