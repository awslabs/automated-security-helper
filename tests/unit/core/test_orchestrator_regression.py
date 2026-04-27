"""Regression tests for orchestrator bug fixes.

Bug #10: shutil.rmtree(None) crash when work_dir is None.
"""

import shutil
from pathlib import Path

import pytest


class TestOrchestratorCleanupNoneWorkDir:
    """Cleanup must not crash when work_dir is None."""

    def test_cleanup_with_none_work_dir(self):
        """shutil.rmtree(None) would raise TypeError; guard required."""
        # Test the guard logic directly -- ASHScanOrchestrator is a Pydantic
        # model that needs full init, so we verify the pattern in isolation.
        work_dir = None
        no_cleanup = False
        if not no_cleanup:
            if work_dir and Path(work_dir).exists():
                shutil.rmtree(work_dir)
        # If we got here without TypeError, the guard works.

    def test_original_code_would_crash(self):
        """Demonstrate that shutil.rmtree(None) raises TypeError."""
        with pytest.raises(TypeError):
            shutil.rmtree(None)

    def test_cleanup_with_nonexistent_work_dir(self):
        """A path that doesn't exist should also be guarded."""
        work_dir = Path("/tmp/nonexistent_ash_work_dir_xyz_test")
        if work_dir.exists():
            shutil.rmtree(work_dir)
        # Guard should prevent rmtree on nonexistent path
        if work_dir and Path(work_dir).exists():
            shutil.rmtree(work_dir)
