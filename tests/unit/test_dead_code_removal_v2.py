"""Regression tests: dead code removed in Batch 1 must stay removed.

These tests lock in four dead-code removals:

    Site 1: ProgressDisplay.complete_task — referenced attributes that __init__
            never creates (self.task_rows, self.task_table); no callers existed.

    Site 2: The commented-out git-clone block in run_ash_scan.py — a large
            block of dead commented code plus the now-unused original_dir
            guard. The live temp_clone_dir=None sentinel is preserved because
            the cleanup block at the end of the scan references it.

    Site 3: ExecutionEngine._register_custom_scanners — method body was
            entirely commented out and only one caller existed (inside the
            same file). Both the method and the call are removed.

    Site 4: SnykCodeScanner — env_vars was initialized to {} and never
            populated, so the `if env_vars:` branch was unreachable. The
            branch and the restore-environment code are removed.
"""

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


# ----- Site 1: ProgressDisplay.complete_task -----


def test_progress_display_does_not_have_complete_task():
    """complete_task referenced attributes __init__ never created."""
    from automated_security_helper.core.progress import LiveProgressDisplay

    assert not hasattr(LiveProgressDisplay, "complete_task"), (
        "LiveProgressDisplay.complete_task was dead code and should remain removed"
    )


def test_progress_py_does_not_reference_task_rows_or_task_table():
    """The phantom attributes should no longer appear in progress.py."""
    progress_py = (
        REPO_ROOT / "automated_security_helper" / "core" / "progress.py"
    ).read_text()
    assert "self.task_rows" not in progress_py, (
        "self.task_rows referenced a never-initialized attribute"
    )
    assert "self.task_table" not in progress_py, (
        "self.task_table referenced a never-initialized attribute"
    )


# ----- Site 2: commented-out git-clone block in run_ash_scan.py -----


def test_run_ash_scan_has_no_commented_git_clone_block():
    """The large commented-out git-clone scaffold should be gone."""
    run_ash_scan_py = (
        REPO_ROOT
        / "automated_security_helper"
        / "interactions"
        / "run_ash_scan.py"
    ).read_text()

    # Signatures of the commented-out block
    forbidden_markers = [
        "# is_git_repo = returncode == 0",
        "# temp_clone_dir = tempfile.mkdtemp",
        '# logger.info(f"Cloning git repository',
        '# ["git", "clone", str(source_dir)',
        "# os.chdir(original_dir)",
    ]
    for marker in forbidden_markers:
        assert marker not in run_ash_scan_py, (
            f"Dead commented marker still present: {marker!r}"
        )


def test_run_ash_scan_preserves_temp_clone_dir_sentinel():
    """temp_clone_dir=None is still referenced downstream and must survive."""
    run_ash_scan_py = (
        REPO_ROOT
        / "automated_security_helper"
        / "interactions"
        / "run_ash_scan.py"
    ).read_text()
    assert "temp_clone_dir = None" in run_ash_scan_py, (
        "temp_clone_dir=None is used by the cleanup block and must be kept"
    )


def test_run_ash_scan_drops_unused_original_dir_guard():
    """original_dir was only needed by the commented-out chdir path."""
    run_ash_scan_py = (
        REPO_ROOT
        / "automated_security_helper"
        / "interactions"
        / "run_ash_scan.py"
    ).read_text()
    assert "original_dir = os.getcwd()" not in run_ash_scan_py, (
        "original_dir guarded a chdir that no longer exists"
    )
    assert '"original_dir" in locals()' not in run_ash_scan_py, (
        "the locals() rollback for original_dir should also be gone"
    )


# ----- Site 3: ExecutionEngine._register_custom_scanners -----


def test_execution_engine_does_not_have_register_custom_scanners():
    """The method body was entirely commented out; the method is removed."""
    from automated_security_helper.core.execution_engine import (
        ScanExecutionEngine,
    )

    assert not hasattr(ScanExecutionEngine, "_register_custom_scanners"), (
        "ScanExecutionEngine._register_custom_scanners was dead and should stay removed"
    )


def test_execution_engine_has_no_call_to_register_custom_scanners():
    engine_py = (
        REPO_ROOT
        / "automated_security_helper"
        / "core"
        / "execution_engine.py"
    ).read_text()
    assert "_register_custom_scanners" not in engine_py, (
        "all references to _register_custom_scanners should be gone"
    )


# ----- Site 4: SnykCodeScanner unreachable env_vars branch -----


def test_snyk_code_scanner_has_no_unreachable_env_vars_branch():
    """env_vars = {} followed by `if env_vars:` is always False."""
    snyk_py = (
        REPO_ROOT
        / "automated_security_helper"
        / "plugin_modules"
        / "ash_snyk_plugins"
        / "snyk_code_scanner.py"
    ).read_text()

    assert "env_vars = {}" not in snyk_py, (
        "the always-empty env_vars initializer should be gone"
    )
    assert "if env_vars:" not in snyk_py, (
        "the unreachable `if env_vars:` branch should be gone"
    )


def test_snyk_code_scanner_still_runs_subprocess():
    """After removing the dead branch, the else-body behavior must remain.

    We import the class to ensure the module still parses cleanly and that
    _run_subprocess is still invoked from the execute path.
    """
    from automated_security_helper.plugin_modules.ash_snyk_plugins import (
        snyk_code_scanner,
    )

    assert hasattr(snyk_code_scanner, "SnykCodeScanner"), (
        "SnykCodeScanner class must still exist"
    )
    source = (
        REPO_ROOT
        / "automated_security_helper"
        / "plugin_modules"
        / "ash_snyk_plugins"
        / "snyk_code_scanner.py"
    ).read_text()
    assert "self._run_subprocess(" in source, (
        "_run_subprocess call must still be in the scanner"
    )
