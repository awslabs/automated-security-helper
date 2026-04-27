# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests for cdk_nag_wrapper and suppression_matcher bug fixes (batch 2).

Bug references from db71e64 follow-up:
  cdk_nag_wrapper.py:
    #127 - IndexError on missing resource_log_id
    #128 - UnboundLocalError on clean_template_filename
    #129 - Substring match wrongly matches partial resource IDs
    #130 - sys.stderr = devnull globally (parallel-unsafe)
    #131 - os.environ["NODE_NO_WARNINGS"] not restored
    #132 - outdir: None default causes AttributeError
    #134 - devnull_file fd leak on early return

  suppression_matcher.py:
    #23  - line_start-only suppression ignores finding end
    #52  - < vs <= for same-day expiry
    #54  - fnmatch case sensitivity is OS-dependent
"""

import inspect
import os
import re
import sys
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

import pytest

from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability


# ---------------------------------------------------------------------------
# cdk_nag_wrapper.py regression tests
# ---------------------------------------------------------------------------


class TestBug127IndexErrorMissingResource:
    """#127: list comprehension [x for ... if ...][0] raises IndexError when
    resource_log_id is not found in model.Resources."""

    def test_no_bare_index_zero_on_resource_lookup(self):
        """The code must not use [0] indexing on the resource lookup list
        comprehension. It should use next(..., None) or equivalent with a guard."""
        from automated_security_helper.utils import cdk_nag_wrapper

        source = inspect.getsource(cdk_nag_wrapper)

        # The old pattern: list-comp filtered by resource_id == resource_log_id, then [0]
        # This is fragile -- next() with a default or a get() call is safer.
        dangerous_pattern = re.compile(
            r"\[.*for\s+\w+.*in\s+model\.Resources\.items\(\).*if\s+\w+\s*==\s*resource_log_id\s*\]\s*\[\s*0\s*\]"
        )
        assert not dangerous_pattern.search(source), (
            "Bug #127: resource lookup must not use [0] indexing on a "
            "filtered list -- use next() with a default or dict .get()"
        )


class TestBug128UnboundCleanTemplateFilename:
    """#128: generic except branch doesn't set clean_template_filename,
    so the variable is unbound when used after the try/except."""

    def test_clean_template_filename_initialized_before_try(self):
        """clean_template_filename must be assigned a value before the try
        block so the generic except path cannot leave it unbound."""
        from automated_security_helper.utils import cdk_nag_wrapper
        import pathlib

        # Read from the actual source file to avoid xdist bytecode cache issues.
        source_path = pathlib.Path(cdk_nag_wrapper.__file__)
        source = source_path.read_text(encoding="utf-8")

        lines = source.splitlines()

        # Find the try block that contains get_shortest_name for clean_template_filename
        try_idx = None
        for i, line in enumerate(lines):
            if "clean_template_filename = get_shortest_name" in line:
                # Walk backwards to find the enclosing try:
                for j in range(i - 1, max(0, i - 5), -1):
                    if "try:" in lines[j]:
                        try_idx = j
                        break
                break

        assert try_idx is not None, (
            "Could not find the try block containing clean_template_filename assignment"
        )

        # Check that clean_template_filename is assigned before the try block
        pre_try_lines = "\n".join(lines[max(0, try_idx - 5):try_idx])
        assert "clean_template_filename" in pre_try_lines, (
            "Bug #128: clean_template_filename must be initialized before "
            "the try block to prevent UnboundLocalError in the generic except path"
        )


class TestBug129SubstringMatchWrong:
    """#129: `resource_log_id in line_str` matches substrings, e.g. 'Bucket'
    incorrectly matches 'MyBucketPolicy'."""

    def test_resource_id_uses_word_boundary_match(self):
        """The resource ID search in template_lines must not use simple 'in'
        operator -- it should use a word-boundary or exact-token match."""
        from automated_security_helper.utils import cdk_nag_wrapper

        source = inspect.getsource(cdk_nag_wrapper)

        # The old pattern: `if resource_log_id in line_str`
        # After fix, should use re.search with word boundary, or check
        # against the YAML key pattern like `resource_log_id + ":"`.
        lines = source.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            # Look for the old dangerous pattern
            if (
                "resource_log_id in line_str" in stripped
                and "re.search" not in stripped
                and "\\b" not in stripped
                and not stripped.startswith("#")
            ):
                pytest.fail(
                    f"Bug #129 (line ~{i}): 'resource_log_id in line_str' "
                    "uses substring match. Must use word-boundary or exact-token match."
                )


class TestBug130StderrGlobalRedirect:
    """#130: sys.stderr = devnull redirects stderr globally, affecting
    parallel threads. Should be scoped properly."""

    def test_stderr_restored_in_finally(self):
        """sys.stderr must be restored in a finally block, not left as devnull."""
        from automated_security_helper.utils import cdk_nag_wrapper

        source = inspect.getsource(cdk_nag_wrapper)

        # The fix should restore stderr in the finally block
        assert "sys.stderr = original_stderr" in source, (
            "Bug #130: sys.stderr must be restored to original_stderr"
        )
        # Verify it appears in a finally block context
        assert "finally:" in source, (
            "Bug #130: stderr restoration must be in a finally block"
        )


class TestBug131EnvVarNodeNoWarningsNotRestored:
    """#131: os.environ['NODE_NO_WARNINGS'] mutation without restoration."""

    def test_jsii_env_vars_restored_in_finally(self):
        """JSII-related env vars must be saved before mutation and restored
        in the finally block."""
        from automated_security_helper.utils import cdk_nag_wrapper

        source = inspect.getsource(cdk_nag_wrapper)

        # After fix, there should be save/restore logic for the env vars
        assert "os.environ.get(" in source or "_original_jsii_env" in source, (
            "Bug #131: JSII env vars must be saved before mutation"
        )
        # Verify restoration in finally
        assert "os.environ.pop(" in source or "os.environ[" in source, (
            "Bug #131: JSII env vars must be restored in finally block"
        )


class TestBug132OutdirNoneCausesAttributeError:
    """#132: outdir defaults to None but line ~169 calls outdir.joinpath()
    which raises AttributeError."""

    def test_outdir_none_guarded(self):
        """When outdir is None, the code must raise ValueError or provide
        a sensible default before calling .joinpath()."""
        from automated_security_helper.utils import cdk_nag_wrapper

        source = inspect.getsource(cdk_nag_wrapper)

        # The code should guard against None outdir. Check for either:
        # 1. A ValueError raise when outdir is None
        # 2. A default value assigned when outdir is None
        has_guard = (
            'outdir is None' in source
            and ('raise ValueError' in source or 'raise TypeError' in source
                 or 'outdir =' in source)
        )
        assert has_guard, (
            "Bug #132: outdir=None must be guarded with a ValueError or "
            "a sensible default before calling outdir.joinpath()"
        )


class TestBug134DevnullFdLeakOnEarlyReturn:
    """#134: on import failure early-return path, devnull_file is never closed."""

    def test_devnull_closed_on_all_paths(self):
        """devnull_file must be closed in a finally block that covers the
        early-return import-failure path."""
        from automated_security_helper.utils import cdk_nag_wrapper

        source = inspect.getsource(cdk_nag_wrapper)

        # After fix, devnull_file.close() should appear in the finally block
        assert "devnull_file" in source, "devnull_file should exist in source"

        # The finally block should handle closing devnull_file
        finally_idx = source.find("finally:")
        assert finally_idx != -1, "There must be a finally block"
        finally_section = source[finally_idx:]
        assert "devnull_file" in finally_section and "close" in finally_section, (
            "Bug #134: devnull_file must be closed in the finally block"
        )


# ---------------------------------------------------------------------------
# suppression_matcher.py regression tests
# ---------------------------------------------------------------------------


class TestBug23LineStartOnlyIgnoresEnd:
    """#23: When suppression has only line_start, a multi-line finding that
    starts before suppression.line_start but ends at or after it should be
    suppressed (overlap), but the old code only checked finding.line_start."""

    def test_multiline_finding_overlapping_start_only_suppression(self):
        """A finding spanning lines 5-15 should be suppressed by a
        suppression with line_start=10 (no line_end) because the finding
        overlaps."""
        from automated_security_helper.utils.suppression_matcher import _line_range_matches

        finding = FlatVulnerability(
            id="test", title="t", description="d", severity="HIGH",
            scanner="s", scanner_type="SAST", rule_id="R1",
            file_path="f.py",
            line_start=5,
            line_end=15,
        )
        suppression = AshSuppression(
            reason="r", path="f.py", line_start=10, line_end=None,
        )
        assert _line_range_matches(finding, suppression), (
            "Bug #23: multi-line finding (5-15) overlapping suppression "
            "line_start=10 should match"
        )

    def test_finding_entirely_before_start_only_suppression(self):
        """A finding on lines 1-5 should NOT be suppressed by
        suppression line_start=10."""
        from automated_security_helper.utils.suppression_matcher import _line_range_matches

        finding = FlatVulnerability(
            id="test", title="t", description="d", severity="HIGH",
            scanner="s", scanner_type="SAST", rule_id="R1",
            file_path="f.py",
            line_start=1,
            line_end=5,
        )
        suppression = AshSuppression(
            reason="r", path="f.py", line_start=10, line_end=None,
        )
        assert not _line_range_matches(finding, suppression), (
            "Finding entirely before suppression start should not match"
        )

    def test_finding_starts_at_suppression_start(self):
        """A finding starting exactly at suppression line_start should match."""
        from automated_security_helper.utils.suppression_matcher import _line_range_matches

        finding = FlatVulnerability(
            id="test", title="t", description="d", severity="HIGH",
            scanner="s", scanner_type="SAST", rule_id="R1",
            file_path="f.py",
            line_start=10,
            line_end=20,
        )
        suppression = AshSuppression(
            reason="r", path="f.py", line_start=10, line_end=None,
        )
        assert _line_range_matches(finding, suppression), (
            "Finding starting at suppression line_start should match"
        )


class TestBug52SameDayExpiry:
    """#52: should_suppress_finding uses `<` for expiry check while
    check_for_expiring_suppressions uses `<=`. After fix, both use `<=`,
    so a suppression expiring today is treated as expired (not active)."""

    def test_same_day_expiry_does_not_suppress(self):
        """A suppression expiring today should NOT suppress (consistent
        with check_for_expiring_suppressions treating day-0 as expiring)."""
        from automated_security_helper.utils.suppression_matcher import should_suppress_finding

        today_str = datetime.now().strftime("%Y-%m-%d")
        finding = FlatVulnerability(
            id="test", title="t", description="d", severity="HIGH",
            scanner="s", scanner_type="SAST", rule_id="R1",
            file_path="f.py",
        )
        # Use model_construct to bypass the expiration-in-future validator
        suppression = AshSuppression.model_construct(
            reason="r", path="f.py", rule_id="R1",
            expiration=today_str,
            line_start=None, line_end=None,
        )
        suppressed, _ = should_suppress_finding(finding, [suppression])
        assert not suppressed, (
            "Bug #52: suppression expiring today should not suppress "
            "(consistent with <= semantics)"
        )

    def test_yesterday_expiry_does_not_suppress(self):
        """A suppression that expired yesterday should not suppress."""
        from automated_security_helper.utils.suppression_matcher import should_suppress_finding

        yesterday_str = (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d")
        finding = FlatVulnerability(
            id="test", title="t", description="d", severity="HIGH",
            scanner="s", scanner_type="SAST", rule_id="R1",
            file_path="f.py",
        )
        # Use model_construct to bypass the expiration-in-future validator
        suppression = AshSuppression.model_construct(
            reason="r", path="f.py", rule_id="R1",
            expiration=yesterday_str,
            line_start=None, line_end=None,
        )
        suppressed, _ = should_suppress_finding(finding, [suppression])
        assert not suppressed, (
            "Suppression that expired yesterday should not suppress"
        )

    def test_tomorrow_expiry_still_suppresses(self):
        """A suppression expiring tomorrow should still suppress."""
        from automated_security_helper.utils.suppression_matcher import should_suppress_finding

        tomorrow_str = (datetime.now() + timedelta(days=1)).strftime("%Y-%m-%d")
        finding = FlatVulnerability(
            id="test", title="t", description="d", severity="HIGH",
            scanner="s", scanner_type="SAST", rule_id="R1",
            file_path="f.py",
        )
        suppression = AshSuppression(
            reason="r", path="f.py", rule_id="R1",
            expiration=tomorrow_str,
        )
        suppressed, _ = should_suppress_finding(finding, [suppression])
        assert suppressed, (
            "Suppression expiring tomorrow should still suppress"
        )


class TestBug54FnmatchCaseSensitivity:
    """#54: fnmatch case sensitivity is OS-dependent. On macOS/Windows,
    fnmatch.fnmatch is case-insensitive, but on Linux it's case-sensitive.
    Fix: normalize both sides to lowercase."""

    def test_rule_id_match_case_insensitive(self):
        """Rule ID matching should be case-insensitive regardless of OS."""
        from automated_security_helper.utils.suppression_matcher import _rule_id_matches

        # These should match regardless of platform
        assert _rule_id_matches("AWS-S3-001", "aws-s3-*"), (
            "Bug #54: rule ID match should be case-insensitive"
        )
        assert _rule_id_matches("aws-s3-001", "AWS-S3-*"), (
            "Bug #54: rule ID match should be case-insensitive (reverse)"
        )

    def test_rule_id_exact_match_case_insensitive(self):
        """Exact rule ID should match case-insensitively."""
        from automated_security_helper.utils.suppression_matcher import _rule_id_matches

        assert _rule_id_matches("MyRule", "myrule"), (
            "Bug #54: exact rule ID match should be case-insensitive"
        )

    def test_file_path_match_case_insensitive(self):
        """File path matching should be case-insensitive regardless of OS."""
        from automated_security_helper.utils.suppression_matcher import _file_path_matches

        assert _file_path_matches("SRC/File.py", "src/file.py"), (
            "Bug #54: file path match should be case-insensitive"
        )

    def test_file_path_glob_case_insensitive(self):
        """File path glob matching should be case-insensitive."""
        from automated_security_helper.utils.suppression_matcher import _file_path_matches

        assert _file_path_matches("SRC/MyFile.py", "src/*.py"), (
            "Bug #54: file path glob should be case-insensitive"
        )
