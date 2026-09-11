# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Tests that each ignore file reports how many files it removed from the scan set.

Making nested ignore files work means ASH scans less than it did before. A
vendored directory that ships its own ``.gitignore`` now takes its own source out
of the scan set::

    before: ['app.py', 'vendor/.gitignore', 'vendor/lib/dep.py']
    after:  ['app.py', 'vendor/.gitignore']

That is correct by gitignore semantics and matches what a root-level
``.gitignore`` already did, so the behavior stays. But a security scanner that
quietly scans less after an upgrade is the worst outcome available, and vendored
dependencies very commonly ship ignore files, so the reduction has to be visible.

Every count assertion here names a specific ignore file. An assertion on a total
would pass while two ignore files' counts were wrong in opposite directions, and
it would not tell a user which file to go read -- which is the whole point of the
report.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.utils.get_scan_set import (
    ASH_INCLUSIONS_MARKER,
    get_ash_ignorespec_lines,
    get_ash_ignorespec_with_attribution,
    get_files_not_matching_spec,
    report_ignore_file_exclusions,
    scan_set,
)
from automated_security_helper.utils.log import ASH_LOGGER


def _relative_posix_names(scan_root: Path, files: list[str]) -> set[str]:
    """Scan-set paths as ``/``-separated paths relative to *scan_root*."""
    return {Path(f).relative_to(scan_root).as_posix() for f in files}


def _exclusion_counts(scan_root: Path) -> dict[str, int]:
    """The report for *scan_root*, driven the same way ``scan_set`` drives it.

    Returns the counts as data so the assertions can name one ignore file each,
    rather than matching substrings against log output.
    """
    discovered, all_files = _collect(scan_root)
    lines = get_ash_ignorespec_lines(
        str(scan_root), [], _discovered_ignore_files=discovered
    )
    spec, rule_ids_by_marker = get_ash_ignorespec_with_attribution(lines, scan_root)
    kept = get_files_not_matching_spec(str(scan_root), spec, _all_files=all_files)
    return report_ignore_file_exclusions(
        str(scan_root), spec, kept, rule_ids_by_marker, all_files
    )


def _collect(scan_root: Path):
    from automated_security_helper.utils.get_scan_set import (
        _collect_ignorefiles_and_all_files,
    )

    return _collect_ignorefiles_and_all_files(str(scan_root))


def _logged_counts(mock_info: MagicMock) -> dict[str, int]:
    """The (marker, count) pairs the report logged.

    Read out of the call arguments rather than a rendered string: ``ASH_LOGGER``
    is called with lazy ``%s`` formatting, so the interpolated message never
    exists unless a handler formats it, and a test that searched for "excluded 1
    file" in ``str(call)`` would fail against a correct log call.
    """
    counts = {}
    for call in mock_info.call_args_list:
        args = call.args
        if len(args) >= 3 and "excluded" in str(args[0]):
            counts[args[1]] = args[2]
    return counts


@pytest.fixture
def vendored_project(tmp_path):
    """The case that carried the decision to build this report.

    Structure::

        src/
        |-- app.py
        `-- vendor/
            |-- .gitignore   (lib/)
            `-- lib/
                `-- dep.py   no longer scanned
    """
    root = tmp_path / "src"
    root.mkdir()
    (root / "app.py").write_text("x = 1\n")

    vendor = root / "vendor"
    vendor.mkdir()
    (vendor / ".gitignore").write_text("lib/\n")

    lib = vendor / "lib"
    lib.mkdir()
    (lib / "dep.py").write_text("y = 2\n")

    return root


class TestPerIgnoreFileAttribution:
    def test_a_vendored_ignore_file_reports_the_count_it_removed(
        self, vendored_project
    ):
        counts = _exclusion_counts(vendored_project)

        assert counts["${SOURCE_DIR}/vendor/.gitignore"] == 1, (
            "vendor/.gitignore removed a file from the scan set without reporting "
            f"it; counts: {counts}"
        )

    def test_the_named_file_is_the_one_actually_missing(self, vendored_project):
        """The count is only meaningful if it describes the real scan set.

        Asserted on the exact path rather than on "anything under vendor/":
        ``vendor/.gitignore`` is itself under ``vendor/`` and stays in the scan
        set, so a predicate about the directory is satisfied by the wrong file and
        reports the vendored source as still scanned when it is not.
        """
        found = _relative_posix_names(
            vendored_project, scan_set(source=str(vendored_project))
        )

        assert "vendor/lib/dep.py" not in found, (
            f"expected the vendored source to be excluded; scan set: {sorted(found)}"
        )
        assert "vendor/.gitignore" in found, (
            f"the ignore file itself should still be scanned; scan set: {sorted(found)}"
        )

    def test_two_ignore_files_each_get_their_own_count(self, tmp_path):
        """Two files with different counts, asserted separately.

        The counts are 3 and 1 rather than equal, so a report that attributed
        every exclusion to one ignore file, or swapped the two, fails here
        instead of summing correctly and passing.
        """
        root = tmp_path / "src"
        root.mkdir()
        (root / "app.py").write_text("x = 1\n")

        vendor = root / "vendor"
        vendor.mkdir()
        (vendor / ".gitignore").write_text("lib/\n")
        (vendor / "lib").mkdir()
        (vendor / "lib" / "dep.py").write_text("y = 2\n")

        build = root / "build"
        build.mkdir()
        (build / ".gitignore").write_text("*.o\n")
        for name in ("a.o", "b.o", "c.o"):
            (build / name).write_text("obj\n")
        (build / "keep.txt").write_text("kept\n")

        counts = _exclusion_counts(root)

        assert counts["${SOURCE_DIR}/build/.gitignore"] == 3, (
            f"build/.gitignore should own its 3 object files; counts: {counts}"
        )
        assert counts["${SOURCE_DIR}/vendor/.gitignore"] == 1, (
            f"vendor/.gitignore should own exactly its 1 file; counts: {counts}"
        )

    def test_an_ignore_file_that_removed_nothing_reports_zero(self, tmp_path):
        """Zero has to be stated. Omitting the line would make "excluded nothing"
        indistinguishable from "there is no such ignore file"."""
        root = tmp_path / "src"
        root.mkdir()
        (root / "app.py").write_text("x = 1\n")
        sub = root / "sub"
        sub.mkdir()
        (sub / ".gitignore").write_text("*.nomatch\n")
        (sub / "keep.py").write_text("y = 2\n")

        counts = _exclusion_counts(root)

        assert counts["${SOURCE_DIR}/sub/.gitignore"] == 0, (
            f"an ignore file that excluded nothing is missing its zero; counts: {counts}"
        )


class TestZeroIsDistinguishableFromAbsent:
    def test_no_ignore_files_says_so_rather_than_reporting_zero(self, tmp_path):
        root = tmp_path / "src"
        root.mkdir()
        (root / "app.py").write_text("x = 1\n")

        mock_info = MagicMock()
        with patch.object(ASH_LOGGER, "info", mock_info):
            scan_set(source=str(root))

        messages = [str(call) for call in mock_info.call_args_list]
        assert any("No ignore files were found" in message for message in messages), (
            f"a tree with no ignore files did not say so; log calls: {messages}"
        )

    def test_a_zero_count_is_logged_and_not_only_returned(self, tmp_path):
        """Requirement 2 is a claim about the log, so it is asserted on the log.

        The sibling test in :class:`TestPerIgnoreFileAttribution` asserts the
        returned counts, and a report that computed the zero correctly but skipped
        the line for it would satisfy that and still leave the user with silence.
        Suppressing zero-count lines passes every data-level assertion in this
        file; only this one fails.
        """
        root = tmp_path / "src"
        root.mkdir()
        (root / "app.py").write_text("x = 1\n")
        sub = root / "sub"
        sub.mkdir()
        (sub / ".gitignore").write_text("*.nomatch\n")
        (sub / "keep.py").write_text("y = 2\n")

        mock_info = MagicMock()
        with patch.object(ASH_LOGGER, "info", mock_info):
            scan_set(source=str(root))

        logged = _logged_counts(mock_info)
        assert logged.get("${SOURCE_DIR}/sub/.gitignore") == 0, (
            "an ignore file that excluded nothing did not get a line, so silence "
            f"now means both 'excluded nothing' and 'no such file'; logged: {logged}"
        )

    def test_an_ignore_file_present_does_not_claim_none_were_found(self, tmp_path):
        """The control for the test above: the two states must not both emit it."""
        root = tmp_path / "src"
        root.mkdir()
        (root / "app.py").write_text("x = 1\n")
        sub = root / "sub"
        sub.mkdir()
        (sub / ".gitignore").write_text("*.nomatch\n")

        mock_info = MagicMock()
        with patch.object(ASH_LOGGER, "info", mock_info):
            scan_set(source=str(root))

        messages = [str(call) for call in mock_info.call_args_list]
        assert not any(
            "No ignore files were found" in message for message in messages
        ), (
            f"claimed no ignore files while sub/.gitignore was read; log calls: {messages}"
        )


class TestCountsAgreeWithTheScanSet:
    """A number that contradicts the artifact it describes is worse than none."""

    def test_a_template_re_included_by_ash_inclusions_is_not_counted(self, tmp_path):
        """``out/`` excludes two files; ``ASH_INCLUSIONS`` puts one back.

        The count has to be 1. Counting what the spec matched rather than what is
        missing from the scan set would report 2 while the scan set contains the
        template.
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

        counts = _exclusion_counts(root)
        found = _relative_posix_names(root, scan_set(source=str(root)))

        assert counts["${SOURCE_DIR}/cdk/.gitignore"] == 1, (
            "the re-included template was counted as excluded, so the count "
            f"contradicts the scan set; counts: {counts}"
        )
        assert "cdk/out/Stack.template.json" in found, (
            f"expected the template to be back in the scan set; got {sorted(found)}"
        )

    def test_the_counts_total_the_files_actually_removed(self, tmp_path):
        """Consistency check alongside the per-file assertions, not instead of them.

        Every file missing from the scan set is attributed to exactly one source,
        so nothing is double counted and nothing is dropped.
        """
        root = tmp_path / "src"
        root.mkdir()
        (root / "app.py").write_text("x = 1\n")
        vendor = root / "vendor"
        vendor.mkdir()
        (vendor / ".gitignore").write_text("lib/\n")
        (vendor / "lib").mkdir()
        (vendor / "lib" / "dep.py").write_text("y = 2\n")
        build = root / "build"
        build.mkdir()
        (build / ".gitignore").write_text("*.o\n")
        for name in ("a.o", "b.o"):
            (build / name).write_text("obj\n")

        _discovered, all_files = _collect(root)
        counts = _exclusion_counts(root)
        kept = scan_set(source=str(root))

        assert sum(counts.values()) == len(all_files) - len(kept), (
            f"counts {counts} do not add up to the {len(all_files) - len(kept)} "
            "files missing from the scan set"
        )

    def test_an_unattributed_exclusion_is_warned_about(self, vendored_project):
        """The report's own failure mode, made loud.

        If the attribution mapping and the parser ever disagree, every count reads
        zero -- the absent-reads-as-zero ambiguity this report exists to remove.
        An empty mapping stands in for that here.
        """
        discovered, all_files = _collect(vendored_project)
        lines = get_ash_ignorespec_lines(
            str(vendored_project), [], _discovered_ignore_files=discovered
        )
        spec, _rule_ids_by_marker = get_ash_ignorespec_with_attribution(
            lines, vendored_project
        )
        kept = get_files_not_matching_spec(
            str(vendored_project), spec, _all_files=all_files
        )

        mock_warning = MagicMock()
        with patch.object(ASH_LOGGER, "warning", mock_warning):
            report_ignore_file_exclusions(
                str(vendored_project), spec, kept, {}, all_files
            )

        messages = [str(call) for call in mock_warning.call_args_list]
        assert any(
            "without any ignore rule accounting for them" in message
            for message in messages
        ), (
            f"a broken attribution mapping reported zeros in silence; warnings: {messages}"
        )


class TestScanSetEmitsTheReport:
    """The report has to be wired into the scan, not merely correct in isolation."""

    def test_scan_set_logs_the_per_ignore_file_count(self, vendored_project):
        mock_info = MagicMock()
        with patch.object(ASH_LOGGER, "info", mock_info):
            scan_set(source=str(vendored_project))

        logged = _logged_counts(mock_info)
        assert logged.get("${SOURCE_DIR}/vendor/.gitignore") == 1, (
            f"scan_set did not log vendor/.gitignore's count; logged: {logged}"
        )

    def test_ash_inclusions_is_reported_too(self, vendored_project):
        """It removes files like any other source, so leaving it out would make the
        counts fail to add up to the number of files actually removed."""
        counts = _exclusion_counts(vendored_project)

        assert ASH_INCLUSIONS_MARKER in counts, (
            f"ASH_INCLUSIONS is missing from the report; counts: {counts}"
        )
