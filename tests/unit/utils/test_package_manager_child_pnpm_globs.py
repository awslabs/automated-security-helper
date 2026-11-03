"""The pnpm-workspace.yaml member-glob filter, read directly on both platforms.

``_pnpm_workspace_copy`` and ``_member_glob_stays_inside`` take bytes and
strings and touch no filesystem, so these tests carry no POSIX dependency and
run on Windows too, where the drive-letter and backslash-led patterns are the
cases that matter. The tests that read the workspace file through the tool's
private copy (what crosses with ``auditConfig``, the registry staying out,
``--ignore-suppressions``) live in ``test_package_manager_child_reads_and_settings.py``,
a module that skips on Windows for its symlink fixtures.
"""

from __future__ import annotations

import logging

import pytest
import yaml

from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.package_manager_child import (
    _member_glob_stays_inside,
    _pnpm_workspace_copy,
)

pytestmark = pytest.mark.unit

AUDIT_CONFIG = {"ignoreCves": ["CVE-2026-0001"], "ignoreGhsas": ["GHSA-aaaa-bbbb-cccc"]}


@pytest.mark.parametrize(
    "glob",
    [
        "packages/*",
        "apps/**",
        "!**/fixtures/**",
        "libs\\core",
        "a/b/c",
        ".",
        # Two dots inside a component are not a parent step: a filter that
        # looked for ".." anywhere in the pattern would drop these members.
        "packages/..cache/*",
        "v1..2/*",
    ],
)
def test_a_relative_glob_without_a_parent_step_stays_inside(glob):
    assert _member_glob_stays_inside(glob) is True


@pytest.mark.parametrize(
    "glob",
    [
        "",
        "!",
        "/srv/shared/*",
        "/**",
        "../**",
        "\\shared\\*",
        "!\\shared\\*",
        "C:\\shared\\*",
        "C:/shared/*",
        "c:shared",
        "../sibling/*",
        "apps/../../escape",
        "apps\\..\\..\\escape",
        "!../x",
        # A brace group expands into separate patterns, so each of these
        # reaches a path outside the package though no component as written
        # is a parent step or absolute.
        "{..,x}/*",
        "{/srv/shared,x}/*",
        # A doubled negation is a positive pattern, so the second "!" is not
        # part of the first component.
        "!!../x",
    ],
)
def test_an_absolute_root_relative_or_climbing_glob_leaves_the_package(glob):
    """A root-relative pattern (a leading slash or backslash with no drive)
    names the current drive's root, which ``PureWindowsPath.is_absolute``
    alone does not refuse; the drive, the parent step, a brace group and a
    doubled negation are refused too."""
    assert _member_glob_stays_inside(glob) is False


def _copy_of(document: dict) -> dict:
    out = _pnpm_workspace_copy(
        yaml.safe_dump(document).encode("utf-8"), ignore_suppressions=False
    )
    return yaml.safe_load(out)


def test_the_copy_keeps_only_the_globs_that_stay_inside():
    copied = _copy_of(
        {
            "packages": [
                "packages/*",
                "../sibling/*",
                "/srv/shared/*",
                "\\shared\\*",
                "C:\\shared\\*",
                "apps/../../escape",
                "!**/fixtures/**",
                "",
            ],
            "auditConfig": AUDIT_CONFIG,
            "registry": "https://registry.example/",
        }
    )

    assert copied == {
        "packages": ["packages/*", "!**/fixtures/**"],
        "auditConfig": AUDIT_CONFIG,
    }


@pytest.fixture
def debug_messages():
    """ASH's logger at DEBUG with a handler of our own: the logger does not
    propagate, so caplog does not see it."""
    messages: list[str] = []

    class Collect(logging.Handler):
        def emit(self, record):
            messages.append(record.getMessage())

    handler = Collect(level=logging.DEBUG)
    saved = ASH_LOGGER.level
    ASH_LOGGER.addHandler(handler)
    ASH_LOGGER.setLevel(logging.DEBUG)
    yield messages
    ASH_LOGGER.removeHandler(handler)
    ASH_LOGGER.setLevel(saved)


def test_each_glob_the_copy_leaves_out_is_logged_with_its_reason(debug_messages):
    """A glob left out was dropped without a word, and a dropped negation
    widens the member set the copy audits. One debug line each names the glob
    and the rule it broke; a glob that stays has none."""
    _copy_of(
        {
            "packages": [
                "packages/*",
                "../sibling/*",
                "{..,x}/*",
                "/srv/shared/*",
                "!../x",
                "!**/fixtures/**",
            ],
            "auditConfig": AUDIT_CONFIG,
        }
    )

    lines = [m for m in debug_messages if "member glob" in m]
    assert len(lines) == 4, debug_messages
    by_glob = {
        line.split("member glob ", 1)[1].split(" ", 1)[0]: line for line in lines
    }
    assert sorted(by_glob) == [
        "'!../x'",
        "'../sibling/*'",
        "'/srv/shared/*'",
        "'{..,x}/*'",
    ]
    assert "parent step" in by_glob["'../sibling/*'"]
    assert "brace group" in by_glob["'{..,x}/*'"]
    assert "absolute" in by_glob["'/srv/shared/*'"]
    assert "negation" in by_glob["'!../x'"]
    assert all("negation" not in by_glob[g] for g in by_glob if not g.startswith("'!"))


def test_globs_that_all_leave_the_package_give_the_package_itself():
    """Control: with no glob left the copy is the package alone, as for a value
    that is not the list-of-strings shape."""
    copied = _copy_of(
        {"packages": ["../*", "/elsewhere/*"], "auditConfig": AUDIT_CONFIG}
    )

    assert copied == {"auditConfig": AUDIT_CONFIG, "packages": ["."]}


def test_a_packages_value_that_is_not_a_list_of_globs_stays_out_of_the_copy():
    """The direct read of the shape the copy-level module also tests on POSIX:
    only the list-of-strings shape pnpm defines is read as member globs."""
    copied = _copy_of({"packages": {"glob": "packages/*"}, "auditConfig": AUDIT_CONFIG})

    assert copied == {"auditConfig": AUDIT_CONFIG, "packages": ["."]}


def test_audit_config_without_member_globs_gets_the_package_itself():
    """A workspace file with no ``packages`` key is one some pnpm releases refuse
    (the module docstring), so the copy names the package."""
    assert _copy_of({"auditConfig": AUDIT_CONFIG}) == {
        "auditConfig": AUDIT_CONFIG,
        "packages": ["."],
    }


def test_a_repository_without_a_workspace_file_gets_the_default_one():
    """pnpm 10 walks up from the copy to the nearest workspace root and reads
    that directory's ``.npmrc``. A copy with no file of its own took the
    repository's root, and the audit went to the registry the repository names.
    So the copy always has one: the package alone."""
    out = _pnpm_workspace_copy(None, ignore_suppressions=False)

    assert yaml.safe_load(out) == {"packages": ["."]}


def test_a_file_without_audit_config_gets_the_default_one_not_its_settings():
    """The registry in a repository's file stays out, and so do its globs: they
    cross only with ``auditConfig``."""
    copied = _copy_of({"packages": ["apps/*"], "registry": "https://registry.example/"})

    assert copied == {"packages": ["."]}


@pytest.mark.parametrize(
    "text",
    ["a: [unclosed", "- one\n- two\n", "just a string\n", ""],
)
def test_a_file_that_is_not_a_mapping_gets_the_default_one(text):
    out = _pnpm_workspace_copy(text.encode("utf-8"), ignore_suppressions=False)

    assert yaml.safe_load(out) == {"packages": ["."]}


def test_nothing_of_the_repository_s_file_crosses_under_ignore_suppressions():
    """The flag lifts every suppression, so ``auditConfig`` goes; the copy is
    still its own workspace root."""
    out = _pnpm_workspace_copy(
        yaml.safe_dump({"auditConfig": AUDIT_CONFIG, "packages": ["apps/*"]}).encode(
            "utf-8"
        ),
        ignore_suppressions=True,
    )

    assert yaml.safe_load(out) == {"packages": ["."]}
