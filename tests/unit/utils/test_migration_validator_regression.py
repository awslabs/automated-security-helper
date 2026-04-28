"""Regression tests for migration_validator bug fixes (batch 2).

Covers bug: #146 -- "uv" in dep matches uvicorn
"""

import pytest


# ---------------------------------------------------------------------------
# Bug #146 -- "uv" in dep matches uvicorn
# ---------------------------------------------------------------------------
class TestBug146UvMatchesUvicorn:
    """Checking for 'uv' dependency must not match 'uvicorn'."""

    def test_uvicorn_not_matched_as_uv(self):
        from automated_security_helper.utils.migration_validator import (
            MigrationValidator,
        )

        validator = MigrationValidator()
        # Simulate a dependencies list that has uvicorn but NOT uv
        deps = ["uvicorn>=0.20.0", "fastapi>=0.100.0"]
        # The fix should check dep == "uv" or dep.startswith("uv[") or
        # use a precise match, not `"uv" in dep`
        uv_found = any(
            dep == "uv" or dep.startswith("uv[") or dep.startswith("uv>=") or dep.startswith("uv>") or dep.startswith("uv<") or dep.startswith("uv<=") or dep.startswith("uv==") or dep.startswith("uv!=") or dep.startswith("uv~=")
            for dep in deps
        )
        assert not uv_found, (
            "'uvicorn' should not be matched as 'uv' dependency"
        )

    def test_uv_exact_match_works(self):
        deps = ["uv>=0.5.0", "fastapi>=0.100.0"]
        uv_found = any(
            dep == "uv" or dep.startswith("uv[") or dep.startswith("uv>=") or dep.startswith("uv>") or dep.startswith("uv<") or dep.startswith("uv<=") or dep.startswith("uv==") or dep.startswith("uv!=") or dep.startswith("uv~=")
            for dep in deps
        )
        assert uv_found

    def test_validate_pyproject_uvicorn_not_flagged(self, tmp_path):
        """The actual validator should not flag uvicorn as uv."""
        from automated_security_helper.utils.migration_validator import (
            MigrationValidator,
        )

        pyproject_content = """
[project]
name = "test-project"
version = "1.0.0"
dependencies = ["uvicorn>=0.20.0", "fastapi>=0.100.0"]

[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"
"""
        pyproject_path = tmp_path / "pyproject.toml"
        pyproject_path.write_text(pyproject_content)

        validator = MigrationValidator(project_root=tmp_path)
        result = validator._validate_pyproject_structure()
        # Should warn that UV is NOT found (uvicorn should not count)
        warnings = result.get("warnings", [])
        has_uv_warning = any("UV not found" in w for w in warnings)
        assert has_uv_warning, (
            "Validator should warn that UV is not found when only uvicorn is present"
        )
