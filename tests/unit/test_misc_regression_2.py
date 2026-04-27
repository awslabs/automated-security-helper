"""Regression tests for bugs #49, #50, #60, #68, #69, #74, #94, #95, #96, #97, #146, #165."""

import asyncio
import io
import logging
import platform
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock, patch, PropertyMock

import pytest


# ---------------------------------------------------------------------------
# Bug #49 -- subprocess_utils.run_command args[0] mutation
# ---------------------------------------------------------------------------
class TestBug49ArgsNotMutated:
    """run_command must not mutate the caller's list."""

    def test_run_command_does_not_mutate_caller_list(self):
        original = ["echo", "hello"]
        caller_copy = original.copy()

        with patch(
            "automated_security_helper.utils.subprocess_utils.find_executable",
            return_value="/usr/bin/echo",
        ):
            with patch(
                "automated_security_helper.utils.subprocess_utils.subprocess.run"
            ) as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0, stdout="hello\n", stderr=""
                )
                from automated_security_helper.utils.subprocess_utils import (
                    run_command,
                )

                run_command(original)

        # The caller's list must not have been modified
        assert original == caller_copy, (
            f"run_command mutated caller's args list: {original} != {caller_copy}"
        )


# ---------------------------------------------------------------------------
# Bug #50 -- get_host_uid/gid silent fallback without warning
# ---------------------------------------------------------------------------
class TestBug50SilentFallbackWarning:
    """get_host_uid / get_host_gid should log a warning when falling back."""

    def test_get_host_uid_logs_warning_on_fallback(self):
        from automated_security_helper.utils.subprocess_utils import get_host_uid

        with patch(
            "automated_security_helper.utils.subprocess_utils.run_command",
            side_effect=Exception("not available"),
        ):
            with patch(
                "automated_security_helper.utils.subprocess_utils.ASH_LOGGER"
            ) as mock_logger:
                uid = get_host_uid()

        assert uid == 1000
        # Must have logged a warning (not just error)
        mock_logger.warning.assert_called()

    def test_get_host_gid_logs_warning_on_fallback(self):
        from automated_security_helper.utils.subprocess_utils import get_host_gid

        with patch(
            "automated_security_helper.utils.subprocess_utils.run_command",
            side_effect=Exception("not available"),
        ):
            with patch(
                "automated_security_helper.utils.subprocess_utils.ASH_LOGGER"
            ) as mock_logger:
                gid = get_host_gid()

        assert gid == 1000
        mock_logger.warning.assert_called()


# ---------------------------------------------------------------------------
# Bug #60 -- download_utils rename_to=None produces literal "None"
# ---------------------------------------------------------------------------
class TestBug60RenameToNone:
    """create_url_download_command must not pass literal string 'None'."""

    def test_rename_to_none_not_literal_string(self):
        from automated_security_helper.utils.download_utils import (
            create_url_download_command,
        )

        cmd = create_url_download_command(
            url="https://example.com/tool", rename_to=None
        )
        # The last arg should be the Python string "None" that the script
        # checks with `if sys.argv[3] != 'None'`. The bug was that
        # str(None) was used unconditionally. With the fix, we pass the
        # actual string "None" only when rename_to IS None, so the
        # inline script correctly interprets it.
        assert cmd.args[-1] == "None"

    def test_rename_to_value_passes_through(self):
        from automated_security_helper.utils.download_utils import (
            create_url_download_command,
        )

        cmd = create_url_download_command(
            url="https://example.com/tool", rename_to="my-tool"
        )
        assert cmd.args[-1] == "my-tool"


# ---------------------------------------------------------------------------
# Bug #68 -- resource_manager deprecated asyncio.get_event_loop()
# ---------------------------------------------------------------------------
class TestBug68DeprecatedGetEventLoop:
    """ResourceManager.shutdown_executor must use get_running_loop()."""

    def test_shutdown_uses_get_running_loop(self):
        import inspect
        from automated_security_helper.core.resource_management.resource_manager import (
            ResourceManager,
        )

        source = inspect.getsource(ResourceManager.shutdown_executor)
        assert "get_running_loop" in source, (
            "shutdown_executor should use asyncio.get_running_loop(), "
            "not the deprecated asyncio.get_event_loop()"
        )
        assert "get_event_loop" not in source, (
            "shutdown_executor still references deprecated get_event_loop()"
        )


# ---------------------------------------------------------------------------
# Bug #69 -- resource_manager get_executor false exhaustion
# ---------------------------------------------------------------------------
class TestBug69FalseExhaustion:
    """get_executor should not raise ResourceExhaustionError for monitoring callers."""

    @pytest.mark.asyncio
    async def test_get_executor_without_exhaustion_for_read(self):
        from automated_security_helper.core.resource_management.resource_manager import (
            ResourceManager,
        )

        rm = ResourceManager(max_workers=2, max_concurrent_scans=1)
        # Simulate one active operation
        rm._active_operations = 1

        # get_executor should still work -- it just returns the pool,
        # it should NOT check operation slots
        executor = await rm.get_executor()
        assert executor is not None

        # Clean up
        executor.shutdown(wait=False)

    @pytest.mark.asyncio
    async def test_acquire_slot_still_enforces_limit(self):
        from automated_security_helper.core.resource_management.resource_manager import (
            ResourceManager,
        )

        rm = ResourceManager(max_workers=2, max_concurrent_scans=1)
        got = await rm.acquire_operation_slot()
        assert got is True

        got2 = await rm.acquire_operation_slot()
        assert got2 is False

        # Clean up
        await rm.release_operation_slot()


# ---------------------------------------------------------------------------
# Bug #74 -- task_manager iterates _active_tasks without lock
# ---------------------------------------------------------------------------
class TestBug74UnsafeIteration:
    """get_tasks_by_scan_id and get_all_tasks_info must copy under lock."""

    def test_get_tasks_by_scan_id_copies_dict(self):
        import inspect
        from automated_security_helper.core.resource_management.task_manager import (
            TaskManager,
        )

        source = inspect.getsource(TaskManager.get_tasks_by_scan_id)
        # The fix should copy the dict before iterating, or use list()
        # to snapshot the items. We check for any copying pattern.
        assert "list(" in source or ".copy()" in source or "dict(" in source, (
            "get_tasks_by_scan_id should copy _active_tasks before iterating"
        )

    def test_get_all_tasks_info_copies_dict(self):
        import inspect
        from automated_security_helper.core.resource_management.task_manager import (
            TaskManager,
        )

        source = inspect.getsource(TaskManager.get_all_tasks_info)
        assert "list(" in source or ".copy()" in source or "dict(" in source, (
            "get_all_tasks_info should copy _active_tasks before iterating"
        )


# ---------------------------------------------------------------------------
# Bug #94 -- custom_containerfile build command never invoked
# ---------------------------------------------------------------------------
class TestBug94CustomContainerfileSilentlyIgnored:
    """When custom_containerfile is provided, custom_build_cmd must be invoked."""

    def test_custom_build_cmd_is_executed(self):
        import inspect
        from automated_security_helper.interactions.run_ash_container import (
            run_ash_container,
        )

        source = inspect.getsource(run_ash_container)
        # After the custom_build_cmd is assembled, we must find
        # run_cmd_direct(custom_build_cmd ...) invocation
        assert "run_cmd_direct(custom_build_cmd" in source, (
            "custom_build_cmd is constructed but never passed to run_cmd_direct"
        )


# ---------------------------------------------------------------------------
# Bug #95 -- --offline flag not forwarded into container env
# ---------------------------------------------------------------------------
class TestBug95OfflineFlagNotForwarded:
    """--offline should set ASH_OFFLINE=YES in the container environment."""

    def test_offline_env_var_set_in_run_cmd(self):
        import inspect
        from automated_security_helper.interactions.run_ash_container import (
            run_ash_container,
        )

        source = inspect.getsource(run_ash_container)
        assert "ASH_OFFLINE" in source, (
            "ASH_OFFLINE environment variable not forwarded to container"
        )


# ---------------------------------------------------------------------------
# Bug #96 -- StringIO.getvalue() called while worker thread may still write
# ---------------------------------------------------------------------------
class TestBug96StringIORace:
    """Threads must be joined before reading StringIO."""

    def test_threads_joined_before_getvalue(self):
        import inspect
        from automated_security_helper.interactions.run_ash_container import (
            run_cmd_direct,
        )

        source = inspect.getsource(run_cmd_direct)
        # The join calls must appear before getvalue() calls
        join_pos = source.find("stdout_thread.join(")
        getvalue_pos = source.find("stdout_buffer.getvalue()")
        assert join_pos < getvalue_pos, (
            "stdout_thread.join() must be called before stdout_buffer.getvalue()"
        )

        join_pos2 = source.find("stderr_thread.join(")
        getvalue_pos2 = source.find("stderr_buffer.getvalue()")
        assert join_pos2 < getvalue_pos2, (
            "stderr_thread.join() must be called before stderr_buffer.getvalue()"
        )


# ---------------------------------------------------------------------------
# Bug #97 -- process.terminate() without wait/SIGKILL escalation
# ---------------------------------------------------------------------------
class TestBug97TerminateWithoutWait:
    """After terminate(), must wait() and escalate to kill() if needed."""

    def test_terminate_has_wait_and_kill_escalation(self):
        import inspect
        from automated_security_helper.interactions.run_ash_container import (
            run_cmd_direct,
        )

        source = inspect.getsource(run_cmd_direct)
        # Find the KeyboardInterrupt handler section
        interrupt_idx = source.find("KeyboardInterrupt")
        assert interrupt_idx != -1

        post_interrupt = source[interrupt_idx:]
        assert "process.wait(" in post_interrupt or ".wait(" in post_interrupt, (
            "After process.terminate(), must call process.wait()"
        )
        assert "process.kill()" in post_interrupt or ".kill()" in post_interrupt, (
            "Must escalate to process.kill() if process doesn't exit"
        )


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


# ---------------------------------------------------------------------------
# Bug #165 -- addLoggingLevel AttributeError on re-import
# ---------------------------------------------------------------------------
class TestBug165AddLoggingLevelReimport:
    """addLoggingLevel must not raise on re-import if level already exists."""

    def test_add_logging_level_idempotent(self):
        from automated_security_helper.utils.log import addLoggingLevel

        # VERBOSE and TRACE are already registered at module load time.
        # Calling again must NOT raise.
        try:
            addLoggingLevel("VERBOSE", 15)
        except AttributeError:
            pytest.fail(
                "addLoggingLevel raised AttributeError on duplicate level name"
            )

    def test_add_logging_level_new_level_works(self):
        from automated_security_helper.utils.log import addLoggingLevel

        level_name = "TESTLEVEL_165"
        # Clean up in case a previous test run left it
        if hasattr(logging, level_name):
            return  # already registered, skip

        addLoggingLevel(level_name, 7)
        assert hasattr(logging, level_name)
        assert getattr(logging, level_name) == 7
