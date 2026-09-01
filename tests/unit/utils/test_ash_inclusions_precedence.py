# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests that an ``ASH_INCLUSIONS`` negation survives an excluded directory.

``ASH_INCLUSIONS`` carries ``!**/*.template.json`` to force CloudFormation
templates into the scan set. It is not a preference that may lose to a user's
ignore file: ``cdk_nag_scanner`` and ``cfn_nag_scanner`` read this scan set, so a
template that leaves it stops being analyzed, and nothing is logged to say so.

Expressing that as a negation inside the same parser as the ignore rules cannot
work. git will not let a negation re-include a path underneath an excluded
*directory* -- it never descends into one -- and igittigitt implements that
faithfully. So a ``src/cdk/.gitignore`` containing ``out/`` removed
``src/cdk/out/Stack.template.json`` and the negation had no say. The rule only
became reachable once nested ignore files started matching at all, which is why
these tests arrive with that change rather than before it.

The negations are therefore applied as a pass of their own, after the spec has
decided. The exclusion tests here are the ones that failed before that pass
existed; the rest are controls against the over-broad fix of just ignoring nested
directory exclusions.
"""

import ntpath
import posixpath
from pathlib import Path

import pytest

from automated_security_helper.utils.get_scan_set import (
    _is_bundled_cdk_path,
    scan_set,
)

WINDOWS_SEPARATORS = "\\/"
POSIX_SEPARATORS = "/"

WINDOWS_ROOT = "C:" + ntpath.sep + ntpath.join("proj", "src")
POSIX_ROOT = posixpath.join(posixpath.sep, "proj", "src")


def _relative_posix_names(scan_root: Path, files: list[str]) -> set[str]:
    """Scan-set paths as ``/``-separated paths relative to *scan_root*."""
    return {Path(f).relative_to(scan_root).as_posix() for f in files}


@pytest.fixture
def cdk_project_with_nested_ignore(tmp_path):
    """A CDK-shaped tree whose nested ignore file excludes the output directory.

    Structure::

        src/
        |-- app.py
        `-- cdk/
            |-- .gitignore   (out/)
            `-- out/
                |-- Stack.template.json   force-included by ASH_INCLUSIONS
                |-- manifest.json         genuinely excluded with the directory
                `-- tree.json             genuinely excluded with the directory
    """
    root = tmp_path / "src"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n")

    cdk = root / "cdk"
    cdk.mkdir()
    (cdk / ".gitignore").write_text("out/\n")

    out = cdk / "out"
    out.mkdir()
    (out / "Stack.template.json").write_text("{}\n")
    (out / "manifest.json").write_text("{}\n")
    (out / "tree.json").write_text("{}\n")

    return root


class TestTemplateSurvivesADirectoryExclusion:
    def test_nested_directory_exclusion_does_not_drop_a_cfn_template(
        self, cdk_project_with_nested_ignore
    ):
        """The defect: the template left the scan set and the scanners stopped
        seeing it."""
        found = _relative_posix_names(
            cdk_project_with_nested_ignore,
            scan_set(source=str(cdk_project_with_nested_ignore)),
        )

        assert "cdk/out/Stack.template.json" in found, (
            "'out/' in cdk/.gitignore defeated the '!**/*.template.json' entry in "
            f"ASH_INCLUSIONS; scan set: {sorted(found)}"
        )

    def test_the_rest_of_the_excluded_directory_stays_excluded(
        self, cdk_project_with_nested_ignore
    ):
        """Re-including everything under the excluded directory would also make the
        test above pass, and would be the wrong fix.

        ``out/`` is a real exclusion for everything ASH did not name. Only the
        ``ASH_INCLUSIONS`` negations override it.
        """
        found = _relative_posix_names(
            cdk_project_with_nested_ignore,
            scan_set(source=str(cdk_project_with_nested_ignore)),
        )

        assert {"cdk/out/manifest.json", "cdk/out/tree.json"}.isdisjoint(found), (
            "forcing templates back in also dragged along files 'out/' excluded; "
            f"scan set: {sorted(found)}"
        )

    def test_a_file_rule_on_a_template_still_loses_to_the_inclusion(self, tmp_path):
        """Control for the case that already worked: an excluding rule that names
        files rather than a directory.

        igittigitt resolves this one inside the spec, because there is no excluded
        ancestor directory to prune the path. It has to keep working, so that the
        new pass is an addition rather than a replacement.
        """
        root = tmp_path / "src"
        root.mkdir()
        (root / ".gitignore").write_text("*.json\n")
        (root / "app.py").write_text("x = 1\n")
        (root / "Stack.template.json").write_text("{}\n")
        (root / "package.json").write_text("{}\n")

        found = _relative_posix_names(root, scan_set(source=str(root)))

        assert "Stack.template.json" in found, (
            f"'*.json' excluded a template ASH_INCLUSIONS re-includes; scan set: {sorted(found)}"
        )
        assert "package.json" not in found, (
            f"'*.json' stopped excluding an ordinary json file; scan set: {sorted(found)}"
        )

    def test_forced_inclusion_does_not_reach_bundled_cdk_fixtures(self, tmp_path):
        """Control for the ``node_modules/aws-cdk`` carve-out.

        That carve-out is checked before the forced-inclusion pass, so the
        templates CDK ships as its own test fixtures do not get pulled into a
        user's scan.
        """
        root = tmp_path / "src"
        root.mkdir()
        (root / "app.py").write_text("x = 1\n")
        bundled = root / "node_modules" / "aws-cdk" / "fixtures"
        bundled.mkdir(parents=True)
        (bundled / "Bundled.template.json").write_text("{}\n")

        found = _relative_posix_names(root, scan_set(source=str(root)))

        assert not any("aws-cdk" in name for name in found), (
            f"a bundled CDK template was forced into the scan set; scan set: {sorted(found)}"
        )


class TestTheCarveOutSeesBothSeparators:
    r"""The carve-out is the only thing keeping CDK's own fixture templates out.

    It reads as though the ignore spec shared the job, and it does not: nothing
    excludes a bundled template in the first place, so ``spec.match`` is False for
    it and the forced-inclusion pass on ``!**/*.template.json`` is never consulted.
    A carve-out that cannot match is therefore not a degraded filter, it is no
    filter.

    It could not match on Windows. The test was ``"/node_modules/aws-cdk" in
    file_path`` against a path ``os.walk`` had joined with ``\``, so CDK's fixtures
    were scanned as though they were the user's infrastructure. The sibling test
    above cannot catch that, because it builds its tree the way the host does; these
    pass the separator set explicitly, which is what makes the Windows answer
    measurable from a POSIX host.
    """

    def test_a_windows_bundled_path_is_recognized(self):
        walked = ntpath.join(
            WINDOWS_ROOT, "node_modules", "aws-cdk", "fixtures", "Bundled.template.json"
        )

        assert _is_bundled_cdk_path(walked, separators=WINDOWS_SEPARATORS), (
            f"the bundled-CDK carve-out did not recognize a Windows-shaped path, "
            f"so CDK's fixture templates enter the scan set; path: {walked!r}"
        )

    def test_a_posix_bundled_path_is_recognized(self):
        """Control: the platform that already worked has to keep its answer."""
        walked = posixpath.join(
            POSIX_ROOT, "node_modules", "aws-cdk", "fixtures", "Bundled.template.json"
        )

        assert _is_bundled_cdk_path(walked, separators=POSIX_SEPARATORS), (
            f"the POSIX answer moved; path: {walked!r}"
        )

    def test_a_path_outside_the_bundled_tree_is_not_recognized(self):
        """Without this the carve-out could be satisfied by anything, and the two
        tests above would pass for the wrong reason."""
        walked = posixpath.join(POSIX_ROOT, "cdk", "out", "Stack.template.json")

        assert not _is_bundled_cdk_path(walked, separators=POSIX_SEPARATORS), (
            f"a user's own template was treated as bundled CDK; path: {walked!r}"
        )

    def test_a_posix_filename_containing_a_backslash_is_not_split(self):
        r"""``\`` is a legal character in a POSIX filename.

        A directory genuinely named ``node_modules\aws-cdk`` is one directory, not
        two, and dropping its contents from a scan on a Windows-shaped reading of
        its name would lose real source. This is why the separator set is read off
        ``os`` rather than hardcoded to both.
        """
        walked = posixpath.join(POSIX_ROOT, "node_modules\\aws-cdk", "app.py")

        assert not _is_bundled_cdk_path(walked, separators=POSIX_SEPARATORS), (
            f"a POSIX filename containing a backslash was read as a nested path; "
            f"path: {walked!r}"
        )


class TestTheCarveOutAndTheInclusionBothHold:
    """One tree, both directions, so neither can be traded for the other.

    The carve-out and the forced-inclusion pass pull opposite ways on the same
    filename: ``*.template.json`` is forced in, except under the bundled CDK tree.
    Asserting the two in separate trees lets a fix satisfy one by weakening the
    other and still show two green tests -- which is the shape of the wrong fix
    here, since making the forced-inclusion pass "respect" the carve-out would give
    up the guarantee the pass exists for.
    """

    @pytest.fixture
    def project_with_both(self, tmp_path):
        """A tree carrying a user template and a bundled one at once.

        Structure::

            src/
            |-- app.py
            |-- cdk/
            |   |-- .gitignore                 (out/)
            |   `-- out/
            |       |-- Stack.template.json    the user's, forced back in
            |       `-- manifest.json          genuinely excluded with the directory
            `-- node_modules/aws-cdk/fixtures/
                `-- Bundled.template.json      CDK's own, stays out
        """
        root = tmp_path / "src"
        root.mkdir()
        (root / "app.py").write_text("x = 1\n")

        cdk = root / "cdk"
        cdk.mkdir()
        (cdk / ".gitignore").write_text("out/\n")
        out = cdk / "out"
        out.mkdir()
        (out / "Stack.template.json").write_text("{}\n")
        (out / "manifest.json").write_text("{}\n")

        bundled = root / "node_modules" / "aws-cdk" / "fixtures"
        bundled.mkdir(parents=True)
        (bundled / "Bundled.template.json").write_text("{}\n")

        return root

    def test_the_users_template_is_forced_back_in(self, project_with_both):
        found = _relative_posix_names(
            project_with_both, scan_set(source=str(project_with_both))
        )

        assert "cdk/out/Stack.template.json" in found, (
            "keeping the bundled CDK templates out also stopped forcing the user's "
            f"own template back in; scan set: {sorted(found)}"
        )

    def test_cdks_own_fixture_template_stays_out(self, project_with_both):
        found = _relative_posix_names(
            project_with_both, scan_set(source=str(project_with_both))
        )

        assert not any("aws-cdk" in name for name in found), (
            f"a bundled CDK template was scanned as the user's; scan set: {sorted(found)}"
        )

    def test_the_rest_of_the_excluded_directory_stays_excluded(self, project_with_both):
        """Control against the over-broad fix of re-including everything under an
        excluded directory, which would satisfy the first test too."""
        found = _relative_posix_names(
            project_with_both, scan_set(source=str(project_with_both))
        )

        assert "cdk/out/manifest.json" not in found, (
            f"'out/' stopped excluding a file ASH never named; scan set: {sorted(found)}"
        )
