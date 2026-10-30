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

import pytest
import yaml

from automated_security_helper.utils.package_manager_child import (
    _member_glob_stays_inside,
    _pnpm_workspace_copy,
)

pytestmark = pytest.mark.unit

AUDIT_CONFIG = {"ignoreCves": ["CVE-2026-0001"], "ignoreGhsas": ["GHSA-aaaa-bbbb-cccc"]}


@pytest.mark.parametrize(
    "glob",
    ["packages/*", "apps/**", "!**/fixtures/**", "libs\\core", "a/b/c", "."],
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
    ],
)
def test_an_absolute_root_relative_or_climbing_glob_leaves_the_package(glob):
    """A root-relative pattern (a leading slash or backslash with no drive)
    names the current drive's root, which ``PureWindowsPath.is_absolute``
    alone does not refuse; the drive and the parent step are refused too."""
    assert _member_glob_stays_inside(glob) is False


def _copy_of(document: dict) -> dict | None:
    out = _pnpm_workspace_copy(
        yaml.safe_dump(document).encode("utf-8"), ignore_suppressions=False
    )
    return None if out is None else yaml.safe_load(out)


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


def test_globs_that_all_leave_the_package_drop_the_key():
    """Control: with no glob left the key goes too, as for a value that is not
    the list-of-strings shape."""
    copied = _copy_of(
        {"packages": ["../*", "/elsewhere/*"], "auditConfig": AUDIT_CONFIG}
    )

    assert copied == {"auditConfig": AUDIT_CONFIG}


def test_a_packages_value_that_is_not_a_list_of_globs_stays_out_of_the_copy():
    """The direct read of the shape the copy-level module also tests on POSIX:
    only the list-of-strings shape pnpm defines is read as member globs."""
    copied = _copy_of({"packages": {"glob": "packages/*"}, "auditConfig": AUDIT_CONFIG})

    assert copied == {"auditConfig": AUDIT_CONFIG}
