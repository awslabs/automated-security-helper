#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Six workspace-scan gaps, each pinned by the order or the input that passed it.

* The output directory's ``.gitignore`` was written before the directory was
  created, so a first workspace scan never wrote it.
* Two workspace scans whose output directories resolve to one place were both
  admitted, and one run's cleanup and results overwrote the other's.
* The scan's timeout clock started before the wait for the session's lock, so a
  scan queued behind another timed out having scanned nothing.
* The worker gave the session's claim back before it settled previous results
  under the session's tree.
* An ``ASH_CONFIG`` that cannot be read raised out of both workspace tools
  instead of answering a config refusal.
* The plan's resolution and the committed-output check ran on the event loop.
"""

from __future__ import annotations

import asyncio
import threading
from pathlib import Path
from typing import List
from unittest.mock import patch

import pytest

from automated_security_helper.cli.mcp import workspace as workspace_module
from automated_security_helper.core.exceptions import ASHConfigSourceError
from automated_security_helper.core.previous_results import SettleHandoff
from automated_security_helper.core.resource_management.exceptions import (
    MCPResourceError,
)
from automated_security_helper.core.resource_management.scan_registry import (
    MCScanStatus,
    ScanRegistry,
)
from automated_security_helper.models.workspace import (
    ProjectRunStatus,
    WorkspaceProjectResult,
    WorkspaceResults,
)
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    WorkspaceRunResult,
)
from automated_security_helper.workspace.plan import ProjectPlan, WorkspacePlan

pytestmark = pytest.mark.unit


def _plan(tmp_path: Path) -> WorkspacePlan:
    root = tmp_path / "workspace"
    project_dir = root / "api"
    (project_dir / "src").mkdir(parents=True, exist_ok=True)
    workspace_file = root / "fixture.code-workspace"
    workspace_file.write_text('{"folders": [{"path": "api"}]}', encoding="utf-8")
    return WorkspacePlan(
        workspace_file=workspace_file.as_posix(),
        workspace_root=root.as_posix(),
        projects=[
            ProjectPlan(
                key="api",
                relative_path="api",
                path=project_dir.as_posix(),
                label="api",
                display_label="api",
                severity_threshold="MEDIUM",
            )
        ],
    )


def _settings(tmp_path: Path) -> ProjectScanSettings:
    return ProjectScanSettings(
        output_dir=tmp_path / "out", phases=("scan",), max_parallel_projects=1
    )


def _result(plan, settings) -> WorkspaceRunResult:
    payload = WorkspaceResults(
        workspace_file=plan.workspace_file,
        workspace_root=plan.workspace_root,
        status="completed",
        exit_code=0,
        projects=[
            WorkspaceProjectResult(
                project=p.key,
                relative_path=p.relative_path,
                display_label=p.display_label,
                status=ProjectRunStatus.COMPLETED,
                severity_threshold=p.gate_threshold,
                output_path=f"projects/{p.key}",
            )
            for p in plan.projects
        ],
        unconvertible_finding_paths=0,
    )
    return WorkspaceRunResult(
        results_path=Path(settings.output_dir) / "ash_workspace_results.json",
        exit_code=0,
        payload=payload,
    )


def _a_scan_that_must_not_run(*_args, **_kwargs):
    """Fail fast: the paths that use this never reach ``execute_workspace``, and a
    regression that did would otherwise start a real scan under the test."""
    raise AssertionError("execute_workspace ran on a path that must not reach it")


class _Claim:
    """The slice of ``_WorkspaceScanClaim`` that ``_execute`` touches, recording calls."""

    claimed = True

    def __init__(self, order: List[str]) -> None:
        self.order = order

    def worker_starts(self) -> bool:
        self.order.append("worker_starts")
        return True

    def worker_returns(self) -> None:
        self.order.append("worker_returns")

    def worker_declines(self) -> None:
        self.order.append("worker_declines")


def _same_path(first, second) -> bool:
    """Whether two spellings name one place, once resolved."""
    return Path(first).resolve() == Path(second).resolve()


@pytest.fixture
def _fresh_registry(monkeypatch):
    """A scan registry of this test's own, so another test's scans occupy nothing."""
    from automated_security_helper.core.resource_management import (
        scan_registry as scan_registry_module,
    )

    registry = ScanRegistry()
    monkeypatch.setattr(scan_registry_module, "_scan_registry", registry)
    return registry


class TestTheGitignoreIsWrittenOnceTheOutputDirectoryExists:
    def test_project_outputs_writes_no_gitignore(self, tmp_path):
        """Red at the base: ``_project_outputs`` called the writer before any mkdir.

        The writer refuses to write into a directory that is not there, so the
        call did nothing on a first scan. The write now follows
        ``_create_project_outputs`` at the call site.
        """
        plan = _plan(tmp_path)
        settings = _settings(tmp_path)

        with patch.object(workspace_module, "ignore_output_dir_in_git") as writer:
            outputs = workspace_module._project_outputs(plan, settings)

        assert set(outputs) == {"api"}
        writer.assert_not_called()

    def test_the_entry_point_writes_the_gitignore_after_it_creates_the_output_root(
        self, tmp_path, monkeypatch
    ):
        """The call-site order, read from the real entry point: ``mcp_scan_workspace``
        creates the output root, then writes the file into it, so a first scan
        gets its file.

        The earlier form of this test called the two steps itself, in the right
        order, and accepted a writer that wrote nothing; a call site put back to
        write-before-mkdir kept it green. Here the two steps are the production
        ones, recorded in the order the entry point calls them, with the scan
        itself stubbed.
        """
        for name in (
            "ASH_MCP_ALLOWED_ROOTS",
            "ASH_MCP_ALLOWED_CONFIG_ROOTS",
            "ASH_MCP_WORKSPACE_ROOT",
        ):
            monkeypatch.delenv(name, raising=False)
        # A networked transport in the environment makes the caller remote, and
        # the workspace is then confined as a remote caller's.
        monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
        plan = _plan(tmp_path)
        output_dir = Path(plan.workspace_root) / ".ash" / "ash_output"
        assert not output_dir.exists()
        order: List[str] = []
        real_create = workspace_module._create_project_outputs
        real_ignore = workspace_module.ignore_output_dir_in_git

        def create(outputs, root):
            order.append("create")
            return real_create(outputs, root)

        def ignore(source, output):
            wrote = real_ignore(source, output)
            order.append(f"gitignore wrote={wrote}")
            return wrote

        monkeypatch.setattr(workspace_module, "_create_project_outputs", create)
        monkeypatch.setattr(workspace_module, "ignore_output_dir_in_git", ignore)
        monkeypatch.setattr(
            workspace_module, "execute_workspace", lambda p, s, **k: _result(p, s)
        )

        answer = asyncio.run(
            workspace_module.mcp_scan_workspace(workspace_file=plan.workspace_file)
        )

        assert answer.get("success") is True, answer
        assert order == ["create", "gitignore wrote=True"], order
        assert output_dir.is_dir()
        assert (output_dir / ".gitignore").exists()

    def test_the_output_root_is_created_when_no_project_is_active(self, tmp_path):
        """Red at the base: the root existed only as a side effect of the project
        folders' mkdir(parents=True), so a run with no active project (every
        project missing under allow_missing_projects) created nothing, the writer
        wrote nothing, and execute_workspace later wrote the unified results
        beside no .gitignore."""
        plan = _plan(tmp_path)
        output_dir = Path(plan.workspace_root) / ".ash" / "ash_output"
        assert not output_dir.exists()

        workspace_module._create_project_outputs({}, output_dir)
        wrote = workspace_module.ignore_output_dir_in_git(
            plan.workspace_root, output_dir
        )

        assert output_dir.is_dir()
        assert wrote is True
        assert (output_dir / ".gitignore").exists()

    def test_a_link_at_the_gitignore_name_is_refused_and_makes_no_folder(
        self, tmp_path
    ):
        """The link check that _project_outputs runs before registration examines
        the .gitignore name under an output directory below the root
        (linked_output_component), so a refused call raises and creates no
        folder. Only that check is driven here; the order of the entry point's
        own steps is the test above."""
        plan = _plan(tmp_path)
        output_dir = Path(plan.workspace_root) / ".ash" / "ash_output"
        output_dir.mkdir(parents=True)
        elsewhere = tmp_path / "elsewhere"
        elsewhere.write_text("", encoding="utf-8")
        try:
            (output_dir / ".gitignore").symlink_to(elsewhere)
        except (OSError, NotImplementedError) as e:
            pytest.skip(f"this platform refuses to create a symlink: {e}")
        settings = ProjectScanSettings(
            output_dir=output_dir, phases=("scan",), max_parallel_projects=1
        )

        with pytest.raises(ValueError, match="gitignore"):
            workspace_module._project_outputs(plan, settings)
        assert not (output_dir / "projects").exists()

    @pytest.mark.asyncio
    async def test_the_scan_calls_the_writer_once_the_directories_exist(
        self, tmp_path, monkeypatch, _fresh_registry
    ):
        """The call site itself, driven through ``mcp_scan_workspace``.

        The two tests above build the order by hand and cannot see the call
        site: moving the writer back above ``_create_project_outputs`` or
        deleting it left them green. The writer is replaced by a recorder that
        notes, as it is called, whether the output directory and the project's
        directory under it exist yet.
        """
        monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp"))
        monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
        plan = _plan(tmp_path)
        output_dir = Path(plan.workspace_root) / "out"
        calls = []

        def recording_writer(source_dir, target_dir):
            target = Path(target_dir)
            calls.append(
                (
                    Path(source_dir),
                    target,
                    target.is_dir(),
                    (target / "projects" / "api").is_dir(),
                )
            )
            return True

        with (
            patch.object(
                workspace_module,
                "ignore_output_dir_in_git",
                side_effect=recording_writer,
            ),
            patch.object(workspace_module, "prewarm_plugin_registry"),
            patch.object(workspace_module, "refuse_unresolvable_scanner_selection"),
            patch.object(
                workspace_module,
                "execute_workspace",
                side_effect=lambda p, s, **k: _result(p, s),
            ),
        ):
            response = await workspace_module.mcp_scan_workspace(
                workspace_file=plan.workspace_file, output_dir=str(output_dir)
            )

        assert len(calls) == 1, (calls, response)
        source, target, directory_existed, project_existed = calls[0]
        assert _same_path(source, plan.workspace_root), calls
        assert _same_path(target, output_dir), calls
        assert (directory_existed, project_existed) == (True, True)

    @pytest.mark.asyncio
    async def test_a_linked_gitignore_refuses_the_call_before_anything_is_made(
        self, tmp_path, monkeypatch, _fresh_registry
    ):
        """A link at the output directory's ``.gitignore`` is a refused command line.

        It is named by the pre-registration link check (``linked_output_component``
        reads that name for a directory inside the workspace root), so the call
        registers nothing, creates no project directory and runs nothing; the
        writer, which follows creation, is never reached for it. The file the
        link names is left as it was.
        """
        monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp"))
        monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
        plan = _plan(tmp_path)
        output_dir = Path(plan.workspace_root) / "out"
        output_dir.mkdir()
        kept = tmp_path / "elsewhere.txt"
        kept.write_text("kept\n", encoding="utf-8")
        (output_dir / ".gitignore").symlink_to(kept)

        def must_not_run(*args, **kwargs):
            raise AssertionError("a refused workspace scan must not run")

        with patch.object(
            workspace_module, "execute_workspace", side_effect=must_not_run
        ):
            response = await workspace_module.mcp_scan_workspace(
                workspace_file=plan.workspace_file, output_dir=str(output_dir)
            )

        assert response["success"] is False, response
        assert response.get("exit_code") == 3, response
        assert ".gitignore" in str(response), response
        assert _fresh_registry.list_scans() == []
        assert [path.name for path in output_dir.iterdir()] == [".gitignore"]
        assert kept.read_text(encoding="utf-8") == "kept\n"


def _registered(registry: ScanRegistry, tmp_path: Path, output: Path, name: str) -> str:
    """Register a single scan of its own source directory writing into ``output``."""
    source = tmp_path / "sources" / name
    source.mkdir(parents=True, exist_ok=True)
    return registry.register_scan(str(source), str(output))


class TestAnOutputDirectoryAnotherScanWritesIsRefused:
    """Against the real ``ScanRegistry``: occupancy is the registry's own.

    The earlier form fed a stand-in whose entries were lowercase status strings
    under an ``output_directory`` key and never met the real shape; these tests
    register real scans and move them through the registry's own statuses.
    """

    def test_a_live_scan_on_the_same_output_directory_refuses_the_workspace(
        self, tmp_path
    ):
        """Red at the base: only the DIRECTORY scanned was compared, never the output."""
        plan = _plan(tmp_path)
        outputs = workspace_module._project_outputs(plan, _settings(tmp_path))
        registry = ScanRegistry()
        _registered(registry, tmp_path, outputs["api"], "other")

        with pytest.raises(MCPResourceError, match="being written by another scan"):
            workspace_module._refuse_outputs_another_scan_writes(
                registry, plan, outputs, tmp_path / "out"
            )

    def test_a_finished_scan_on_it_does_not(self, tmp_path):
        """Control: a completed or failed scan with no runner holds its directory no more."""
        plan = _plan(tmp_path)
        outputs = workspace_module._project_outputs(plan, _settings(tmp_path))
        registry = ScanRegistry()
        completed = _registered(registry, tmp_path, outputs["api"], "done")
        registry.update_scan_status(completed, MCScanStatus.COMPLETED)
        _registered(registry, tmp_path, tmp_path / "elsewhere", "elsewhere")

        workspace_module._refuse_outputs_another_scan_writes(
            registry, plan, outputs, tmp_path / "out"
        )

    def test_a_cancelled_entry_that_never_ran_does_not_refuse(self, tmp_path):
        """Red at the base: every CANCELLED entry blocked until the registry pruned it.

        ``_register_projects`` rolls a refused workspace registration back by
        marking its entries CANCELLED without a runner, and a user's cancel of a
        pending scan leaves the same shape; a retry was then told its own output
        directory was being written, when nothing was writing there.
        """
        plan = _plan(tmp_path)
        outputs = workspace_module._project_outputs(plan, _settings(tmp_path))
        registry = ScanRegistry()
        rolled_back = _registered(registry, tmp_path, outputs["api"], "rolled-back")
        registry.update_scan_status(rolled_back, MCScanStatus.CANCELLED)
        assert registry.get_scan(rolled_back).has_runner is False

        workspace_module._refuse_outputs_another_scan_writes(
            registry, plan, outputs, tmp_path / "out"
        )

    def test_a_failed_entry_whose_runner_still_writes_refuses(self, tmp_path):
        """Red at the base: a FAILED entry was skipped whatever its runner state.

        A timed-out workspace scan's entries are FAILED at once while its thread
        runs on for seconds, stopping scanners and putting previous results back;
        a second scan admitted into that window writes beside it.
        """
        plan = _plan(tmp_path)
        outputs = workspace_module._project_outputs(plan, _settings(tmp_path))
        registry = ScanRegistry()
        timed_out = _registered(registry, tmp_path, outputs["api"], "timed-out")
        entry = registry.get_scan(timed_out)
        entry.has_runner = True
        registry.update_scan_status(timed_out, MCScanStatus.FAILED, "timed out")

        with pytest.raises(MCPResourceError, match="being written by another scan"):
            workspace_module._refuse_outputs_another_scan_writes(
                registry, plan, outputs, tmp_path / "out"
            )

        # Once the runner has settled the directory, the same entry occupies nothing.
        entry.runner_done.set()
        workspace_module._refuse_outputs_another_scan_writes(
            registry, plan, outputs, tmp_path / "out"
        )


class TestAnOutputRootAnotherScanWritesIsRefused:
    """The output ROOT is asked about too, not only each project's own folder.

    The unified results, the reports and the spool go into ``settings.output_dir``
    itself, which no project folder is and no registry entry named, so two
    workspace scans with different projects and one root passed the per-project
    check and wrote beside each other, each run's cleanup removing the other's
    results. The question is now asked of the root through
    ``ScanRegistry.scan_writing_within``: a live scan whose output tree is the
    root, lies inside it, or contains it refuses the workspace.
    """

    def test_a_live_scan_on_the_output_root_refuses_the_workspace(self, tmp_path):
        """Red at the base: a scan writing the root itself was admitted beside this one."""
        plan = _plan(tmp_path)
        outputs = workspace_module._project_outputs(plan, _settings(tmp_path))
        registry = ScanRegistry()
        _registered(registry, tmp_path, tmp_path / "out", "root-writer")

        with pytest.raises(
            MCPResourceError, match="being written by another scan"
        ) as refused:
            workspace_module._refuse_outputs_another_scan_writes(
                registry, plan, outputs, tmp_path / "out"
            )
        assert refused.value.context["output_directory"] == str(tmp_path / "out")

    def test_another_workspaces_project_under_the_same_root_refuses(self, tmp_path):
        """Red at the base: two workspaces, different projects, one root; neither
        project folder matched, so both were admitted."""
        plan = _plan(tmp_path)
        outputs = workspace_module._project_outputs(plan, _settings(tmp_path))
        registry = ScanRegistry()
        _registered(
            registry, tmp_path, tmp_path / "out" / "projects" / "web", "other-ws"
        )

        with pytest.raises(MCPResourceError, match="being written by another scan"):
            workspace_module._refuse_outputs_another_scan_writes(
                registry, plan, outputs, tmp_path / "out"
            )

    def test_a_live_scan_whose_output_tree_contains_the_root_refuses(self, tmp_path):
        """A scan writing a directory above the root: its cleanup removes the
        whole tree, this run's output with it."""
        plan = _plan(tmp_path)
        nested = ProjectScanSettings(
            output_dir=tmp_path / "out" / "nested",
            phases=("scan",),
            max_parallel_projects=1,
        )
        outputs = workspace_module._project_outputs(plan, nested)
        registry = ScanRegistry()
        _registered(registry, tmp_path, tmp_path / "out", "above")

        with pytest.raises(MCPResourceError, match="being written by another scan"):
            workspace_module._refuse_outputs_another_scan_writes(
                registry, plan, outputs, nested.output_dir
            )

    def test_a_sibling_tree_and_a_finished_scan_on_the_root_do_not_refuse(
        self, tmp_path
    ):
        """Control: the relation is by path component, never string prefix
        (``out-backup`` shares nothing with ``out``), and a completed scan with
        no runner holds the root no more."""
        plan = _plan(tmp_path)
        outputs = workspace_module._project_outputs(plan, _settings(tmp_path))
        registry = ScanRegistry()
        _registered(registry, tmp_path, tmp_path / "out-backup", "sibling")
        done = _registered(registry, tmp_path, tmp_path / "out", "done")
        registry.update_scan_status(done, MCScanStatus.COMPLETED)

        workspace_module._refuse_outputs_another_scan_writes(
            registry, plan, outputs, tmp_path / "out"
        )


class TestTheClockStartsOnceTheSessionLockIsHeld:
    def test_on_locked_runs_after_the_lock_is_free(self, tmp_path):
        """Red at the base: ``_execute`` armed the clock before waiting for the lock."""
        from automated_security_helper.cli.mcp.sessions import (
            get_default_registry,
            reset_default_registry_for_tests,
        )

        reset_default_registry_for_tests()
        session = get_default_registry().session_for("clock-session")
        plan = _plan(tmp_path)
        settings = _settings(tmp_path)
        order: List[str] = []
        held = threading.Event()
        released = threading.Event()

        def hold_the_lock() -> None:
            with session.lock:
                order.append("lock held by another scan")
                held.set()
                released.wait(timeout=5)
                # Appended while the lock is still held, so it is ordered
                # before anything the runner does once it takes the lock. A
                # marker appended after the ``with`` raced the runner: the lock
                # is free the moment the block ends, and the runner could take
                # it and start its clock before this thread ran again.
                order.append("releasing")

        holder = threading.Thread(target=hold_the_lock)
        holder.start()
        assert held.wait(timeout=5)

        errors: List[BaseException] = []

        def run() -> None:
            try:
                with patch.object(
                    workspace_module,
                    "execute_workspace",
                    side_effect=lambda *a, **k: None,
                ):
                    workspace_module._under_session_lock(
                        "clock-session",
                        plan,
                        settings,
                        on_locked=lambda: order.append("clock started"),
                    )
            except BaseException as error:  # noqa: BLE001 -- re-raised below
                errors.append(error)

        runner = threading.Thread(target=run)
        try:
            runner.start()
            runner.join(timeout=0.5)
            assert "clock started" not in order, order
            released.set()
            runner.join(timeout=5)
            holder.join(timeout=5)

            assert errors == [], errors
            assert order.index("releasing") < order.index("clock started"), order
        finally:
            # A failed assertion above must not leave the holder with the lock or
            # the runner inside the patched execute_workspace, which is
            # process-global and would stay active for the tests that follow.
            released.set()
            if runner.is_alive():
                runner.join(timeout=5)
            holder.join(timeout=5)
            # The session claimed above does not stay in the shared registry
            # for the tests that follow.
            reset_default_registry_for_tests()

    def test_the_run_without_a_session_starts_its_clock_too(self, tmp_path):
        """Control: with no session there is no lock to wait for; the clock still starts."""
        order: List[str] = []
        with patch.object(
            workspace_module, "execute_workspace", side_effect=lambda *a, **k: None
        ):
            workspace_module._under_session_lock(
                None,
                _plan(tmp_path),
                _settings(tmp_path),
                on_locked=lambda: order.append("clock started"),
            )

        assert order == ["clock started"]

    def test_execute_hands_its_clock_to_the_lock(self, tmp_path):
        """``_execute`` starts the clock through the lock, once, for a claimed session.

        With no session the lock is skipped and the clock starts at once, so this
        test only counts the call; the next one gives ``_execute`` a real session.
        """
        order: List[str] = []
        plan = _plan(tmp_path)
        settings = _settings(tmp_path)

        with (
            patch.object(
                workspace_module,
                "execute_workspace",
                side_effect=lambda p, s, **k: _result(p, s),
            ),
            patch.object(workspace_module, "ScanPresence") as presence,
        ):
            presence.return_value.__enter__.return_value = None
            presence.return_value.__exit__.return_value = False
            asyncio.run(
                workspace_module._execute(
                    plan=plan,
                    settings=settings,
                    project_outputs={},
                    progress_reporter=None,
                    session_id=None,
                    claim=_Claim(order),
                    on_thread_start=lambda: order.append("clock started"),
                )
            )

        assert order.count("clock started") == 1

    def test_execute_waits_for_the_sessions_lock_before_its_clock(self, tmp_path):
        """Through ``_execute`` with a real session: the clock waits for the lock.

        The test above passes no session, so ``_under_session_lock`` never waits
        and a clock armed before the lock passes it. Here the session's lock is
        held by another thread, and the clock must not start until it is released.
        """
        from automated_security_helper.cli.mcp.sessions import (
            get_default_registry,
            reset_default_registry_for_tests,
        )

        reset_default_registry_for_tests()
        session = get_default_registry().session_for("clock-session")
        plan = _plan(tmp_path)
        settings = _settings(tmp_path)
        order: List[str] = []
        held = threading.Event()
        released = threading.Event()
        errors: List[BaseException] = []

        def hold_the_lock() -> None:
            with session.lock:
                order.append("lock held by another scan")
                held.set()
                released.wait(timeout=5)
                order.append("releasing")

        holder = threading.Thread(target=hold_the_lock)
        holder.start()
        assert held.wait(timeout=5)

        def run() -> None:
            try:
                with (
                    patch.object(
                        workspace_module,
                        "execute_workspace",
                        side_effect=lambda p, s, **k: _result(p, s),
                    ),
                    patch.object(workspace_module, "ScanPresence") as presence,
                ):
                    presence.return_value.__enter__.return_value = None
                    presence.return_value.__exit__.return_value = False
                    asyncio.run(
                        workspace_module._execute(
                            plan=plan,
                            settings=settings,
                            project_outputs={},
                            progress_reporter=None,
                            session_id="clock-session",
                            claim=_Claim(order),
                            on_thread_start=lambda: order.append("clock started"),
                        )
                    )
            except BaseException as error:  # noqa: BLE001 -- re-raised below
                errors.append(error)

        try:
            runner = threading.Thread(target=run)
            runner.start()
            runner.join(timeout=0.5)
            assert "clock started" not in order, order
            released.set()
            runner.join(timeout=5)
            holder.join(timeout=5)

            assert errors == [], errors
            assert order.count("clock started") == 1, order
            assert order.index("releasing") < order.index("clock started"), order
        finally:
            released.set()
            reset_default_registry_for_tests()


class TestTheWorkerSettlesBeforeItGivesTheClaimBack:
    def test_settle_runs_before_worker_returns(self, tmp_path):
        """Red at the base: the claim was released in the inner finally, settle after."""
        order: List[str] = []
        plan = _plan(tmp_path)
        settings = _settings(tmp_path)

        with (
            patch.object(
                workspace_module,
                "execute_workspace",
                side_effect=lambda p, s, **k: _result(p, s),
            ),
            patch.object(workspace_module, "ScanPresence") as presence,
        ):
            presence.return_value.__enter__.return_value = None
            presence.return_value.__exit__.return_value = False
            asyncio.run(
                workspace_module._execute(
                    plan=plan,
                    settings=settings,
                    project_outputs={},
                    progress_reporter=None,
                    session_id=None,
                    claim=_Claim(order),
                    settle=lambda: order.append("settle"),
                )
            )

        assert order.count("settle") == 1
        assert order.index("settle") < order.index("worker_returns"), order

    def test_settle_runs_once_when_the_run_raises(self, tmp_path):
        """Control: a failing run still settles exactly once, before the release."""
        order: List[str] = []

        def failing(p, s, **k):
            raise RuntimeError("scan failed")

        with (
            patch.object(workspace_module, "execute_workspace", side_effect=failing),
            patch.object(workspace_module, "ScanPresence") as presence,
            pytest.raises(RuntimeError, match="scan failed"),
        ):
            presence.return_value.__enter__.return_value = None
            presence.return_value.__exit__.return_value = False
            asyncio.run(
                workspace_module._execute(
                    plan=_plan(tmp_path),
                    settings=_settings(tmp_path),
                    project_outputs={},
                    progress_reporter=None,
                    session_id=None,
                    claim=_Claim(order),
                    settle=lambda: order.append("settle"),
                )
            )

        assert order == ["worker_starts", "settle", "worker_returns"]


class _Abandoned(SettleHandoff):
    """A handoff whose task gave up, and settled, before the thread started."""

    def thread_starts(self) -> bool:
        return False


class _Counted:
    """The per-session limit's view of a claim: how often its place was returned."""

    def __init__(self) -> None:
        self.returned = 0
        self.released = threading.Event()

    def scan_returned(self) -> None:
        self.returned += 1
        self.released.set()


class TestAThreadTheTaskAbandonedSettlesNothing:
    def test_a_thread_that_lost_the_handoff_runs_no_settle(self, tmp_path):
        """Red at the base: the early return sat inside the try whose finally settled.

        ``thread_starts`` answers False only after ``task_abandons`` answered
        True, and the task settles in that case. A second settle from the late
        thread restored previous results into directories ``_release_projects``
        had freed, which another scan may hold by then.
        """
        order: List[str] = []

        with (
            patch.object(
                workspace_module,
                "execute_workspace",
                side_effect=_a_scan_that_must_not_run,
            ),
            patch.object(workspace_module, "ScanPresence") as presence,
        ):
            presence.return_value.__enter__.return_value = None
            presence.return_value.__exit__.return_value = False
            result = asyncio.run(
                workspace_module._execute(
                    plan=_plan(tmp_path),
                    settings=_settings(tmp_path),
                    project_outputs={},
                    progress_reporter=None,
                    session_id=None,
                    claim=_Claim(order),
                    settle=lambda: order.append("settle"),
                    handoff=_Abandoned(),
                )
            )

        assert result is None
        # Nothing is settled by the late thread. It had taken the claim before
        # the handoff (so that no call can leave between the two) and gives it
        # back to the call, which releases it after the task's own settle.
        assert order == ["worker_starts", "worker_declines"], order


class TestAWorkerThatMissedTheClaimReleasesNothing:
    def test_worker_returns_after_a_lost_claim_releases_once(self):
        """Red at the base: worker_returns released whatever the holder was.

        The call left first (call_returns released the place); the worker then
        finds worker_starts False, and its finally still calls worker_returns.
        The place in the per-session limit is returned exactly once.
        """
        counted = _Counted()
        claim = workspace_module._WorkspaceScanClaim(None, counted=counted)

        claim.call_returns()
        assert claim.worker_starts() is False
        claim.worker_returns()

        assert counted.returned == 1

    def test_a_worker_that_started_holds_the_claim_until_it_returns(self):
        """Control: the ordinary order releases exactly once, from the worker."""
        counted = _Counted()
        claim = workspace_module._WorkspaceScanClaim(None, counted=counted)

        assert claim.worker_starts() is True
        claim.call_returns()
        assert counted.returned == 0
        claim.worker_returns()

        assert counted.returned == 1

    def test_the_run_itself_releases_once_when_the_call_left_first(self, tmp_path):
        """Through ``_run``: the raise for a lost claim does not release twice."""
        order: List[str] = []
        counted = _Counted()
        claim = workspace_module._WorkspaceScanClaim(None, counted=counted)
        claim.call_returns()

        with (
            patch.object(
                workspace_module,
                "execute_workspace",
                side_effect=_a_scan_that_must_not_run,
            ),
            patch.object(workspace_module, "ScanPresence") as presence,
            pytest.raises(RuntimeError, match="cancelled before it started"),
        ):
            presence.return_value.__enter__.return_value = None
            presence.return_value.__exit__.return_value = False
            asyncio.run(
                workspace_module._execute(
                    plan=_plan(tmp_path),
                    settings=_settings(tmp_path),
                    project_outputs={},
                    progress_reporter=None,
                    session_id=None,
                    claim=claim,
                    settle=lambda: order.append("settle"),
                )
            )

        assert counted.returned == 1
        # The thread had started, so the task did not settle: the thread must.
        assert order == ["settle"]


class _CallLeavesFirst(SettleHandoff):
    """A handoff the call's exit overtakes just as the thread asks for it.

    ``thread_starts`` runs ``call_leaves`` (``claim.call_returns``) before it
    answers: the window between the thread taking the handoff and the claim, in
    the order the worker once asked for them.
    """

    def __init__(self, call_leaves) -> None:
        super().__init__()
        self._call_leaves = call_leaves

    def thread_starts(self) -> bool:
        self._call_leaves()
        return super().thread_starts()


class TestTheSettleKeepsTheClaimWhenTheCallLeavesFirst:
    def test_a_call_that_leaves_as_the_thread_starts_does_not_unprotect_the_settle(
        self, tmp_path
    ):
        """Red at the base: the settle ran after the call's exit had released the claim.

        The thread won the handoff (so the task does not settle), the call then
        left and released the claim, and the thread found it gone and raised;
        the settle that followed ran with neither the claim nor the presence, on
        a tree the release may have had removed. The claim is taken first now,
        so the call's exit cannot release it under the thread.
        """
        counted = _Counted()
        claim = workspace_module._WorkspaceScanClaim(None, counted=counted)
        returned_at_settle = []

        with (
            patch.object(
                workspace_module,
                "execute_workspace",
                side_effect=lambda p, s, **k: _result(p, s),
            ),
            patch.object(workspace_module, "ScanPresence") as presence,
        ):
            presence.return_value.__enter__.return_value = None
            presence.return_value.__exit__.return_value = False
            asyncio.run(
                workspace_module._execute(
                    plan=_plan(tmp_path),
                    settings=_settings(tmp_path),
                    project_outputs={},
                    progress_reporter=None,
                    session_id=None,
                    claim=claim,
                    settle=lambda: returned_at_settle.append(counted.returned),
                    handoff=_CallLeavesFirst(claim.call_returns),
                )
            )

        assert returned_at_settle == [0], returned_at_settle
        assert counted.returned == 1

    def test_a_thread_that_lost_the_handoff_gives_the_claim_back_to_the_call(
        self, tmp_path
    ):
        """The task settles when it abandons before the thread starts; the claim
        stays held through that settle and goes when the call leaves."""
        counted = _Counted()
        claim = workspace_module._WorkspaceScanClaim(None, counted=counted)
        handoff = SettleHandoff()
        assert handoff.task_abandons() is True
        settled: List[str] = []

        with patch.object(workspace_module, "ScanPresence") as presence:
            presence.return_value.__enter__.return_value = None
            presence.return_value.__exit__.return_value = False
            result = asyncio.run(
                workspace_module._execute(
                    plan=_plan(tmp_path),
                    settings=_settings(tmp_path),
                    project_outputs={},
                    progress_reporter=None,
                    session_id=None,
                    claim=claim,
                    settle=lambda: settled.append("settle"),
                    handoff=handoff,
                )
            )

        assert result is None
        assert settled == []
        assert counted.returned == 0
        claim.call_returns()
        assert counted.returned == 1

    def test_a_thread_that_lost_it_after_the_call_left_releases_once(self, tmp_path):
        """Control: the call left while the thread held the claim and then lost
        the handoff; the thread's hand-back is the release, and only one."""
        counted = _Counted()
        claim = workspace_module._WorkspaceScanClaim(None, counted=counted)
        handoff = _CallLeavesFirst(claim.call_returns)
        assert handoff.task_abandons() is True

        with patch.object(workspace_module, "ScanPresence") as presence:
            presence.return_value.__enter__.return_value = None
            presence.return_value.__exit__.return_value = False
            result = asyncio.run(
                workspace_module._execute(
                    plan=_plan(tmp_path),
                    settings=_settings(tmp_path),
                    project_outputs={},
                    progress_reporter=None,
                    session_id=None,
                    claim=claim,
                    handoff=handoff,
                )
            )

        assert result is None
        assert counted.returned == 1


class TestAThreadThatReadsTheTreeHoldsTheClaim:
    def test_a_call_that_leaves_first_leaves_the_claim_to_the_thread(self):
        counted = _Counted()
        claim = workspace_module._WorkspaceScanClaim(None, counted=counted)

        assert claim.thread_starts() is True
        claim.call_returns()
        assert counted.returned == 0
        claim.thread_returns()

        assert counted.returned == 1

    def test_a_thread_that_returns_first_leaves_the_release_to_the_call(self):
        counted = _Counted()
        claim = workspace_module._WorkspaceScanClaim(None, counted=counted)

        assert claim.thread_starts() is True
        claim.thread_returns()
        assert counted.returned == 0
        claim.call_returns()

        assert counted.returned == 1

    def test_the_last_of_two_threads_releases(self):
        counted = _Counted()
        claim = workspace_module._WorkspaceScanClaim(None, counted=counted)

        assert claim.thread_starts() and claim.thread_starts()
        claim.call_returns()
        claim.thread_returns()
        assert counted.returned == 0
        claim.thread_returns()

        assert counted.returned == 1

    def test_a_thread_cannot_take_a_claim_the_call_released(self):
        """Control: with no thread holding, the call's exit releases at once, and
        a thread that starts afterwards finds nothing to hold."""
        counted = _Counted()
        claim = workspace_module._WorkspaceScanClaim(None, counted=counted)

        claim.call_returns()

        assert counted.returned == 1
        assert claim.thread_starts() is False

    @pytest.mark.asyncio
    async def test_a_call_cancelled_during_resolution_keeps_the_claim_to_the_end(
        self, tmp_path, monkeypatch, _fresh_registry
    ):
        """Red at the base: the call's exit released the claim under the thread.

        The resolution runs on a thread that reads every project's config and
        runs git; cancelling the call leaves it running. The claim is released
        when that thread returns, not when the call leaves.
        """
        monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp"))
        monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
        entered = threading.Event()
        release = threading.Event()

        def blocking_settings(options):
            entered.set()
            release.wait(timeout=10)
            raise RuntimeError("stand-in resolution ended")

        counted = _Counted()
        claim = workspace_module._WorkspaceScanClaim(None, counted=counted)
        plan = _plan(tmp_path)
        scan = workspace_module._in_a_run_log_scope_of_its_own(
            workspace_module._scan_workspace
        )

        with patch.object(
            workspace_module,
            "build_project_scan_settings",
            side_effect=blocking_settings,
        ):
            task = asyncio.ensure_future(
                scan(workspace_file=plan.workspace_file, claim=claim)
            )
            assert await asyncio.to_thread(entered.wait, 10)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            claim.call_returns()
            assert counted.returned == 0
            release.set()
            assert await asyncio.to_thread(counted.released.wait, 10)

        assert counted.returned == 1

    @pytest.mark.asyncio
    async def test_a_call_cancelled_during_the_selection_check_keeps_the_claim(
        self, tmp_path, monkeypatch, _fresh_registry
    ):
        """Red at the base: the selection check ran on a thread of its own, and
        the call's exit released the claim under it.

        The check prewarms the plugin registry, which imports plugin modules;
        cancelling the call leaves that thread running. The claim is released
        when the thread returns, as it is for the two reads before it.
        """
        monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp"))
        monkeypatch.delenv("ASH_MCP_ALLOWED_ROOTS", raising=False)
        entered = threading.Event()
        release = threading.Event()

        def blocking_prewarm(plan, settings):
            entered.set()
            release.wait(timeout=10)
            raise RuntimeError("stand-in prewarm ended")

        counted = _Counted()
        claim = workspace_module._WorkspaceScanClaim(None, counted=counted)
        plan = _plan(tmp_path)
        scan = workspace_module._in_a_run_log_scope_of_its_own(
            workspace_module._scan_workspace
        )

        with patch.object(
            workspace_module, "prewarm_plugin_registry", side_effect=blocking_prewarm
        ):
            task = asyncio.ensure_future(
                scan(
                    workspace_file=plan.workspace_file,
                    output_dir=str(tmp_path / "out"),
                    claim=claim,
                )
            )
            assert await asyncio.to_thread(entered.wait, 10)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            claim.call_returns()
            assert counted.returned == 0
            release.set()
            assert await asyncio.to_thread(counted.released.wait, 10)

        assert counted.returned == 1


class TestTheSettleRunsUnderTheSessionsPresence:
    def test_settle_runs_before_the_presence_is_given_up(self, tmp_path):
        """Red at the base: the settle ran after the ScanPresence block had closed.

        The settle writes previous results back under the session's tree, and the
        presence is what keeps another server's TTL sweep off that tree.
        """
        order: List[str] = []

        def _exit(*_args):
            order.append("presence_exit")
            return False

        with (
            patch.object(
                workspace_module,
                "execute_workspace",
                side_effect=lambda p, s, **k: _result(p, s),
            ),
            patch.object(workspace_module, "ScanPresence") as presence,
        ):
            presence.return_value.__enter__.return_value = None
            presence.return_value.__exit__.side_effect = _exit
            asyncio.run(
                workspace_module._execute(
                    plan=_plan(tmp_path),
                    settings=_settings(tmp_path),
                    project_outputs={},
                    progress_reporter=None,
                    session_id=None,
                    claim=_Claim(order),
                    settle=lambda: order.append("settle"),
                )
            )

        assert order.count("settle") == 1
        assert order.index("settle") < order.index("presence_exit"), order
        assert order.index("presence_exit") < order.index("worker_returns"), order


class TestAnUnreadableServerConfigIsARefusal:
    @pytest.mark.asyncio
    async def test_resolve_workspace_answers_exit_3(self, tmp_path, monkeypatch):
        """Red at the base: ASHConfigSourceError escaped the tool as an exception."""
        monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
        plan = _plan(tmp_path)

        with patch.object(
            workspace_module,
            "_resolve_session_config",
            side_effect=ASHConfigSourceError("ASH_CONFIG cannot be read"),
        ):
            response = await workspace_module.mcp_resolve_workspace(
                workspace_file=plan.workspace_file
            )

        assert response["success"] is False
        assert response.get("exit_code") == 3
        assert "ASH_CONFIG cannot be read" in str(response)

    @pytest.mark.asyncio
    async def test_scan_workspace_answers_exit_3(self, tmp_path, monkeypatch):
        """Exit 3 from the config read itself, not from an earlier exit-3 gate.

        ``_refuse_config_inputs_outside_the_permitted_roots`` also answers 3, so
        the exit code alone could come from it; the patched reader must be
        reached and its message must be the one answered.
        """
        monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
        plan = _plan(tmp_path)

        with patch.object(
            workspace_module,
            "_resolve_session_config",
            side_effect=ASHConfigSourceError("ASH_CONFIG cannot be read"),
        ) as reader:
            response = await workspace_module.mcp_scan_workspace(
                workspace_file=plan.workspace_file
            )

        reader.assert_called()
        assert response["success"] is False
        assert response.get("exit_code") == 3
        assert "ASH_CONFIG cannot be read" in str(response)


class TestResolutionRunsOffTheEventLoop:
    @pytest.mark.asyncio
    async def test_the_committed_output_check_runs_on_another_thread(
        self, tmp_path, monkeypatch
    ):
        """Red at the base: the check ran on the loop's thread."""
        monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp"))
        plan = _plan(tmp_path)
        threads: List[int] = []

        def record_thread(plan, settings) -> None:
            threads.append(threading.get_ident())

        with (
            patch.object(
                workspace_module, "_refuse_committed_output", side_effect=record_thread
            ),
            patch.object(
                workspace_module,
                "execute_workspace",
                side_effect=lambda p, s, **k: _result(p, s),
            ),
        ):
            response = await workspace_module.mcp_scan_workspace(
                workspace_file=plan.workspace_file,
                output_dir=str(tmp_path / "out"),
            )

        assert threads, response
        assert threads[0] != threading.get_ident()

    @pytest.mark.asyncio
    async def test_the_plans_resolution_and_the_settings_run_on_another_thread(
        self, tmp_path, monkeypatch
    ):
        """Red at the base: ``_resolve`` ran on the loop's thread in the scan tool.

        The committed-output check above is one of three reads that stalled the
        loop. The plan's resolution (the workspace file, the policy file and every
        project's config) and the settings builder are the other two; each is
        recorded here by wrapping the real function.
        """
        monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp"))
        plan = _plan(tmp_path)
        threads: dict = {}
        real_resolve = workspace_module._resolve
        real_settings = workspace_module.build_project_scan_settings

        def resolving(*args, **kwargs):
            threads.setdefault("resolve", threading.get_ident())
            return real_resolve(*args, **kwargs)

        def building(*args, **kwargs):
            threads.setdefault("settings", threading.get_ident())
            return real_settings(*args, **kwargs)

        with (
            patch.object(workspace_module, "_resolve", side_effect=resolving),
            patch.object(
                workspace_module, "build_project_scan_settings", side_effect=building
            ),
            patch.object(
                workspace_module,
                "execute_workspace",
                side_effect=lambda p, s, **k: _result(p, s),
            ),
        ):
            response = await workspace_module.mcp_scan_workspace(
                workspace_file=plan.workspace_file,
                output_dir=str(tmp_path / "out"),
            )

        assert set(threads) == {"resolve", "settings"}, (threads, response)
        assert threads["resolve"] != threading.get_ident()
        assert threads["settings"] != threading.get_ident()

    @pytest.mark.asyncio
    async def test_the_resolve_tool_resolves_on_another_thread(
        self, tmp_path, monkeypatch
    ):
        """The dry-run tool resolves the same plan and reads the same configs."""
        monkeypatch.setenv("ASH_MCP_TRANSPORT", "stdio")
        monkeypatch.setenv("ASH_MCP_WORKSPACE_ROOT", str(tmp_path / "mcp"))
        plan = _plan(tmp_path)
        threads: List[int] = []
        real_resolve = workspace_module._resolve

        def resolving(*args, **kwargs):
            threads.append(threading.get_ident())
            return real_resolve(*args, **kwargs)

        with patch.object(workspace_module, "_resolve", side_effect=resolving):
            response = await workspace_module.mcp_resolve_workspace(
                workspace_file=plan.workspace_file
            )

        assert threads, response
        assert threads[0] != threading.get_ident()
