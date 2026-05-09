# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""TDD tests for decomposed apply_suppressions_to_sarif helpers.

Covers:
- _normalize_sarif_uri: all 5 prefix-stripping variants
- _check_ignore_paths: match/no-match
- _apply_config_suppression: match, expired
- _apply_inline_suppression: found/not found
- top-level loop dispatch order (integration)
"""

from __future__ import annotations

import tempfile
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import List, Optional

import pytest

from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation2,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.sarif_utils import (
    _apply_config_suppression,
    _apply_inline_suppression,
    _check_ignore_paths,
    _normalize_sarif_uri,
    apply_suppressions_to_sarif,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_result(rule_id: str, uri: str, line: int = 10) -> Result:
    return Result(
        ruleId=rule_id,
        message=Message(text="test message"),
        locations=[
            Location(
                physicalLocation=PhysicalLocation2(
                    artifactLocation=ArtifactLocation(uri=uri),
                    region=Region(startLine=line, endLine=line),
                )
            )
        ],
    )


def _make_sarif(results: List[Result]) -> SarifReport:
    return SarifReport(
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name="test-scanner")),
                results=results,
            )
        ]
    )


# ---------------------------------------------------------------------------
# _normalize_sarif_uri
# ---------------------------------------------------------------------------


class TestNormalizeSarifUri:
    """All 5 URI-stripping cases."""

    def _call(self, uri: str, source_prefix: str) -> str:
        prefix_with_slash = "/" + source_prefix
        prefix_no_drive = (
            source_prefix[2:]
            if len(source_prefix) > 2 and source_prefix[1] == ":"
            else None
        )
        basename = PurePosixPath(source_prefix.rstrip("/")).name
        return _normalize_sarif_uri(
            uri, source_prefix, prefix_with_slash, prefix_no_drive, basename
        )

    def test_strips_source_dir_prefix(self):
        """Case 1: URI starts with source_dir_prefix directly."""
        result = self._call("/home/runner/work/repo/src/foo.py", "/home/runner/work/repo/src/")
        assert result == "foo.py"

    def test_strips_prefix_with_trailing_slash(self):
        """Case 2: URI starts with /+source_dir_prefix (Windows leading slash)."""
        result = self._call("//home/runner/work/repo/src/foo.py", "/home/runner/work/repo/src/")
        assert result == "foo.py"

    def test_handles_windows_drive_leading_slash(self):
        """Case 2 Windows variant: /D:/a/repo/file.py with prefix D:/a/repo/."""
        result = self._call("/D:/a/repo/src/file.py", "D:/a/repo/src/")
        assert result == "file.py"

    def test_handles_windows_no_drive(self):
        """Case 3: drive-letter stripped by scanner (e.g. /a/repo/ instead of D:/a/repo/)."""
        result = self._call("/a/repo/src/file.py", "D:/a/repo/src/")
        assert result == "file.py"

    def test_handles_backslashes(self):
        """Backslashes are normalized to forward slashes before matching."""
        result = self._call("D:\\a\\repo\\src\\file.py", "D:/a/repo/src/")
        assert result == "file.py"

    def test_basename_relative(self):
        """Case 4: offline opengrep emits paths prefixed with source basename."""
        # source_dir = /home/user/myrepo, prefix = /home/user/myrepo/
        # opengrep emits: myrepo/src/foo.py
        prefix = "/home/user/myrepo/"
        prefix_with_slash = "/" + prefix
        prefix_no_drive = None
        basename = PurePosixPath("/home/user/myrepo").name  # "myrepo"
        result = _normalize_sarif_uri(
            "myrepo/src/foo.py", prefix, prefix_with_slash, prefix_no_drive, basename
        )
        assert result == "src/foo.py"

    def test_no_match_returns_unchanged(self):
        """Case 5: URI doesn't match any prefix — returned as-is (normalized slashes)."""
        result = self._call("/other/project/file.py", "/home/runner/work/repo/src/")
        assert result == "/other/project/file.py"

    def test_no_match_different_drive(self):
        """Windows: URI on C: doesn't match prefix on D:."""
        result = self._call("C:/other/path/file.py", "D:/a/repo/src/")
        assert result == "C:/other/path/file.py"


# ---------------------------------------------------------------------------
# _check_ignore_paths
# ---------------------------------------------------------------------------


class TestCheckIgnorePaths:
    def _ignore(self, path: str, reason: str = "ignored") -> IgnorePathWithReason:
        return IgnorePathWithReason(path=path, reason=reason)

    def test_match_returns_reason(self):
        ignore_paths = [self._ignore("tests/**", "test files")]
        result = _check_ignore_paths("tests/unit/foo.py", ignore_paths)
        assert result == "test files"

    def test_no_match_returns_none(self):
        ignore_paths = [self._ignore("tests/**", "test files")]
        result = _check_ignore_paths("src/main.py", ignore_paths)
        assert result is None

    def test_empty_ignore_paths_returns_none(self):
        result = _check_ignore_paths("src/main.py", [])
        assert result is None

    def test_exact_match(self):
        ignore_paths = [self._ignore("src/secret.py", "secret")]
        assert _check_ignore_paths("src/secret.py", ignore_paths) == "secret"

    def test_first_matching_reason_returned(self):
        ignore_paths = [
            self._ignore("src/**", "broad"),
            self._ignore("src/main.py", "specific"),
        ]
        # First match wins
        result = _check_ignore_paths("src/main.py", ignore_paths)
        assert result == "broad"


# ---------------------------------------------------------------------------
# _apply_config_suppression
# ---------------------------------------------------------------------------


class TestApplyConfigSuppression:
    def _make_suppression(
        self,
        rule_id: str,
        path: str = "**",
        expired: bool = False,
    ) -> AshSuppression:
        expiry = "2000-01-01" if expired else None
        return AshSuppression(
            rule_id=rule_id,
            path=path,
            expiration=expiry,
            reason="test reason",
        )

    def test_matching_rule_and_path_returns_true_and_mutates(self):
        from automated_security_helper.models.flat_vulnerability import FlatVulnerability

        result = Result(
            ruleId="B108",
            message=Message(text="msg"),
        )
        suppression = self._make_suppression("B108", path="src/foo.py")
        flat = FlatVulnerability(
            id="abc",
            title="t",
            description="d",
            severity="MEDIUM",
            scanner="test",
            scanner_type="SAST",
            rule_id="B108",
            file_path="src/foo.py",
        )
        used = set()
        applied = _apply_config_suppression(result, [suppression], flat, used)
        assert applied is True
        assert result.suppressions is not None
        assert len(result.suppressions) >= 1
        assert suppression.id in used

    def test_expired_suppression_not_applied(self):
        from automated_security_helper.models.flat_vulnerability import FlatVulnerability

        result = Result(
            ruleId="B108",
            message=Message(text="msg"),
        )
        suppression = self._make_suppression("B108", path="src/foo.py", expired=True)
        flat = FlatVulnerability(
            id="abc",
            title="t",
            description="d",
            severity="MEDIUM",
            scanner="test",
            scanner_type="SAST",
            rule_id="B108",
            file_path="src/foo.py",
        )
        used = set()
        applied = _apply_config_suppression(result, [suppression], flat, used)
        assert applied is False
        assert not result.suppressions

    def test_no_matching_suppression_returns_false(self):
        from automated_security_helper.models.flat_vulnerability import FlatVulnerability

        result = Result(
            ruleId="B108",
            message=Message(text="msg"),
        )
        suppression = self._make_suppression("B999")
        flat = FlatVulnerability(
            id="abc",
            title="t",
            description="d",
            severity="MEDIUM",
            scanner="test",
            scanner_type="SAST",
            rule_id="B108",
            file_path="src/foo.py",
        )
        applied = _apply_config_suppression(result, [suppression], flat, set())
        assert applied is False


# ---------------------------------------------------------------------------
# _apply_inline_suppression
# ---------------------------------------------------------------------------


class TestApplyInlineSuppression:
    def _bare_result(self, rule_id: str) -> Result:
        # Minimal Result with no locations — _apply_inline_suppression only
        # needs ruleId and the suppressions list; locations are not consulted.
        return Result(ruleId=rule_id, message=Message(text="msg"))

    def test_finds_inline_comment_and_suppresses(self, tmp_path: Path):
        src = tmp_path / "foo.py"
        src.write_text("x = 1  # ash-ignore: B108 deliberate\n")
        result = self._bare_result("B108")
        cache: dict = {}
        applied = _apply_inline_suppression(result, "foo.py", tmp_path, 1, cache)
        assert applied is True
        assert result.suppressions is not None and len(result.suppressions) >= 1

    def test_no_comment_returns_false(self, tmp_path: Path):
        tmp_path / "bar.py"
        (tmp_path / "bar.py").write_text("x = 1\n")
        result = self._bare_result("B108")
        cache: dict = {}
        applied = _apply_inline_suppression(result, "bar.py", tmp_path, 1, cache)
        assert applied is False
        assert not result.suppressions

    def test_wrong_rule_id_returns_false(self, tmp_path: Path):
        (tmp_path / "baz.py").write_text("x = 1  # ash-ignore: B999 other\n")
        result = self._bare_result("B108")
        cache: dict = {}
        applied = _apply_inline_suppression(result, "baz.py", tmp_path, 1, cache)
        assert applied is False


# ---------------------------------------------------------------------------
# Integration: top-level dispatch order
# ---------------------------------------------------------------------------


class TestTopLevelDispatchOrder:
    """Integration tests verifying ignore > config > inline precedence."""

    def _make_context(self, source_dir: Path, output_dir: Path, suppressions=None, ignore_paths=None):
        from automated_security_helper.base.plugin_context import PluginContext
        from automated_security_helper.config.ash_config import AshConfig

        config = AshConfig.model_validate(
            {
                "global_settings": {
                    "suppressions": suppressions or [],
                    "ignore_paths": ignore_paths or [],
                }
            }
        )
        return PluginContext(
            config=config,
            source_dir=source_dir,
            output_dir=output_dir,
        )

    def test_ignore_path_takes_precedence_over_config_suppression(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        out.mkdir()

        suppression = AshSuppression(
            rule_id="B108",
            path="tests/foo.py",
            reason="config rule",
        )
        ignore_path = IgnorePathWithReason(path="tests/**", reason="ignore tests")
        ctx = self._make_context(src, out, suppressions=[suppression], ignore_paths=[ignore_path])

        sarif = _make_sarif([_make_result("B108", str(src / "tests/foo.py"))])
        result_sarif = apply_suppressions_to_sarif(sarif, ctx)

        # Result is dropped (ignore path filtered it out entirely)
        assert result_sarif.runs[0].results == []

    def test_config_suppression_applied_when_no_ignore_match(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        out.mkdir()

        (src / "foo.py").write_text("x = 1\n")
        suppression = AshSuppression(
            rule_id="B108",
            path="foo.py",
            reason="config rule",
        )
        ctx = self._make_context(src, out, suppressions=[suppression])

        sarif = _make_sarif([_make_result("B108", str(src / "foo.py"))])
        result_sarif = apply_suppressions_to_sarif(sarif, ctx)

        results = result_sarif.runs[0].results
        assert len(results) == 1
        assert results[0].suppressions and len(results[0].suppressions) >= 1

    def test_inline_suppression_applied_when_no_config_match(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        out.mkdir()

        (src / "inline.py").write_text("x = 1  # ash-ignore: B108 deliberate\n")
        ctx = self._make_context(src, out)

        sarif = _make_sarif([_make_result("B108", str(src / "inline.py"), line=1)])
        result_sarif = apply_suppressions_to_sarif(sarif, ctx)

        results = result_sarif.runs[0].results
        assert len(results) == 1
        assert results[0].suppressions and len(results[0].suppressions) >= 1

    def test_neither_config_nor_inline_leaves_result_unsuppressed(self, tmp_path: Path):
        src = tmp_path / "src"
        src.mkdir()
        out = tmp_path / "out"
        out.mkdir()

        (src / "clean.py").write_text("x = 1\n")
        ctx = self._make_context(src, out)

        sarif = _make_sarif([_make_result("B108", str(src / "clean.py"), line=1)])
        result_sarif = apply_suppressions_to_sarif(sarif, ctx)

        results = result_sarif.runs[0].results
        assert len(results) == 1
        assert not results[0].suppressions
