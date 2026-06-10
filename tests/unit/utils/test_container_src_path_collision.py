"""Regression test: container mode path collision when project has a src/ directory.

Bug: When ASH runs in container mode, source is mounted to /src. If the project
itself has a src/ directory, the _source_dir_basename fallback in
apply_suppressions_to_sarif() strips the real src/ prefix from finding paths,
causing suppressions with path "src/myfile.py" to fail matching.

Fix: Skip basename stripping when source_dir contains a child directory with the
same name as its own basename (collision detection).
"""

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.models.core import AshSuppression, IgnorePathWithReason
from automated_security_helper.schemas.sarif_schema_model import SarifReport, Run
from automated_security_helper.utils.sarif_utils import (
    apply_suppressions_to_sarif,
    sanitize_sarif_paths,
)


def _make_sarif(uri: str, rule_id: str = "python.lang.security.audit.exec-detected") -> SarifReport:
    """Create minimal SARIF with one finding at the given URI."""
    return SarifReport(runs=[Run(
        tool={"driver": {"name": "opengrep", "version": "1.0.0"}},
        results=[{
            "ruleId": rule_id,
            "message": {"text": "Use of exec detected"},
            "level": "warning",
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": 10, "endLine": 15},
                }
            }],
        }],
    )])


def _make_context(source_dir: str | Path, suppressions=None):
    """Create mock plugin context."""
    ctx = MagicMock()
    ctx.source_dir = Path(source_dir) if isinstance(source_dir, str) else source_dir
    ctx.output_dir = Path("/out")
    ctx.ignore_suppressions = False
    ctx.config = MagicMock()
    ctx.config.global_settings = MagicMock()
    ctx.config.global_settings.ignore_paths = []
    ctx.config.global_settings.suppressions = suppressions or []
    return ctx


def _suppression(path: str, rule_id: str = "python.lang.security.audit.exec-detected", line_start=10, line_end=15):
    """Create an AshSuppression with required fields."""
    return AshSuppression(
        path=path,
        reason="False positive",
        rule_id=rule_id,
        line_start=line_start,
        line_end=line_end,
    )


class TestContainerSrcPathCollision:
    """Bug: container mount /src collides with project's src/ directory."""

    def test_suppression_matches_with_collision(self, tmp_path):
        """Suppression with path 'src/app.py' must match when source_dir/src/ exists."""
        # Simulate: source_dir is "src" and contains a "src/" subdirectory (collision)
        source = tmp_path / "src"
        source.mkdir()
        (source / "src").mkdir()  # collision: source_dir basename == child dir name

        sarif = _make_sarif("src/app.py")
        ctx = _make_context(source, suppressions=[_suppression("src/app.py")])
        result = apply_suppressions_to_sarif(sarif, ctx)

        remaining = [r for r in result.runs[0].results if not r.suppressions]
        assert len(remaining) == 0, (
            f"Expected suppression to match, but {len(remaining)} remain. "
            f"URI was likely stripped from 'src/app.py' to 'app.py'"
        )

    def test_path_not_stripped_with_collision(self, tmp_path):
        """With collision, 'src/app.py' must NOT become 'app.py'."""
        source = tmp_path / "src"
        source.mkdir()
        (source / "src").mkdir()  # collision

        sarif = _make_sarif("src/app.py")
        ctx = _make_context(source, suppressions=[_suppression("app.py")])
        result = apply_suppressions_to_sarif(sarif, ctx)

        remaining = [r for r in result.runs[0].results if not r.suppressions]
        assert len(remaining) == 1, (
            "Suppression for 'app.py' should NOT match 'src/app.py' when collision detected"
        )

    def test_basename_stripping_works_without_collision(self, tmp_path):
        """Without collision, basename stripping works for scanner-prefixed paths."""
        # source_dir is "myproject" with NO "myproject/" child dir
        source = tmp_path / "myproject"
        source.mkdir()
        (source / "src").mkdir()  # has src/ but NOT myproject/ → no collision

        sarif = _make_sarif("myproject/src/app.py")
        ctx = _make_context(source, suppressions=[_suppression("src/app.py")])
        result = apply_suppressions_to_sarif(sarif, ctx)

        remaining = [r for r in result.runs[0].results if not r.suppressions]
        assert len(remaining) == 0, (
            "Without collision, basename stripping should enable matching"
        )

    def test_ignore_path_works_with_collision(self, tmp_path):
        """ignore_paths with 'src/**' must still match when collision exists."""
        source = tmp_path / "src"
        source.mkdir()
        (source / "src").mkdir()  # collision

        sarif = _make_sarif("src/app.py")
        ctx = _make_context(source)
        ctx.config.global_settings.ignore_paths = [
            IgnorePathWithReason(path="src/**", reason="test data")
        ]
        result = apply_suppressions_to_sarif(sarif, ctx)

        remaining = result.runs[0].results
        assert len(remaining) == 0, (
            f"ignore_paths 'src/**' should match 'src/app.py', but {len(remaining)} findings remain"
        )

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix absolute paths not valid on Windows")
    def test_sanitize_then_suppress_with_collision(self, tmp_path):
        """Full flow: sanitize absolute path, then suppress — with collision."""
        source = tmp_path / "src"
        source.mkdir()
        (source / "src").mkdir()  # collision

        # Scanner produces absolute path <source>/src/app.py
        abs_path = str(source / "src" / "app.py")
        sarif = _make_sarif(abs_path)

        # sanitize_sarif_paths strips the source prefix → "src/app.py"
        sanitized = sanitize_sarif_paths(sarif, str(source))
        uri = sanitized.runs[0].results[0].locations[0].physicalLocation.root.artifactLocation.uri
        assert uri == "src/app.py", f"sanitize produced: {uri}"

        # Now suppression should match (no further stripping due to collision)
        ctx = _make_context(source, suppressions=[_suppression("src/app.py")])
        result = apply_suppressions_to_sarif(sanitized, ctx)

        remaining = [r for r in result.runs[0].results if not r.suppressions]
        assert len(remaining) == 0, "Suppression should match after sanitize with collision"

    def test_codebuild_src_directory(self, tmp_path):
        """CodeBuild /codebuild/output/srcNNN/src — same collision pattern."""
        source = tmp_path / "src"
        source.mkdir()
        (source / "src").mkdir()  # collision

        sarif = _make_sarif("src/app.py")
        ctx = _make_context(source, suppressions=[_suppression("src/app.py")])
        result = apply_suppressions_to_sarif(sarif, ctx)

        remaining = [r for r in result.runs[0].results if not r.suppressions]
        assert len(remaining) == 0, (
            "CodeBuild src/ collision should not strip src/ from paths"
        )
