# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The unit tests' tool guard, and fixtures a unit-test module takes by name.

``_unit_tool_guard``, ``_no_real_container_runtime`` and
``_the_source_delivery_pools_are_this_tests_own`` are autouse: every unit test runs
under them. The others are not. Each replaces something a tested function would
otherwise see, and the tests of that function have to see the real thing, so a module
opts in with ``pytestmark = pytest.mark.usefixtures(...)``.
"""

from __future__ import annotations

import itertools
import logging
import os
import shutil
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import NamedTuple, Optional

import pytest

from tests.utils.tool_guard import (
    ToolGuard,
    install_tool_guard,
    real_tools_opt_out_refusal,
    reset_tool_lookup_caches,
    run_own_directories,
    stub_tool_probes,
    tool_files_left_in,
)

UNIT_TESTS = Path(__file__).resolve().parent
#: Names each test's stand-in directory; see _unit_tool_guard.
_GUARD_COUNTER = itertools.count()

#: The modules, as paths under tests/unit, allowed to run a real tool. Each says why
#: with ``runs_real_tools(reason=...)``, on the module or on the tests that do.
REAL_TOOL_MODULES = frozenset(
    {
        "assets/test_install_pinned_tool.py",
        # The real uv, run from a tree holding a planted .venv and project: which of
        # the two uv looks at is what these measure (tests/utils/planted_uv.py).
        "base/test_scanner_uv_commands_discover_nothing_from_the_tree.py",
        # Runs the real npm and gem from an empty directory and from the planted
        # repository; a stand-in cannot read a .npmrc or a Gemfile.
        "cli/test_dependencies_install_commands_start_outside_the_tree.py",
        "cli/test_dependencies_uv_commands_discover_nothing_from_the_tree.py",
        "cli/test_genai_guide_ships_with_install.py",
        # Starts no tool: its two cells are unguarded on purpose, so the
        # autouse teardown cache reset is the only clearer between them and
        # the pair can discriminate it (the per-test guard's own setup reset
        # covers every guarded test).
        "utils/test_find_executable_cache_isolation.py",
        "plugin_modules/ash_builtin/converters/test_jupyter_conversion_runs_outside_tree.py",
        "plugin_modules/ash_builtin/scanners/test_nix_provided_scanner_selection.py",
        # One test each runs the real syft or trivy offline, in the CI job that
        # installs every scanner; the stand-in would answer for the tool and exit 1.
        "plugin_modules/test_offline_go_toolchain.py",
        "plugin_modules/test_offline_trivy_terraform_modules.py",
        # One test dry-runs the printed `python -m uv pip install` command through
        # the real uv, against this environment.
        "utils/test_ash_install.py",
        "utils/test_pre_installed_tool.py",
        "utils/test_uv_ignores_repository_config.py",
    }
)

#: The modules, as paths under tests/unit, allowed a ``real_home`` test. Its HOME is
#: the developer's, so the HOME check cannot read it, and anything it writes there
#: stays: a test marked real_home wrote ``$HOME/.ash`` and passed. Only the tests of
#: the marker itself: test_home_isolation.py, and the probe it runs in a pytest of its
#: own whose starting home is a sentinel directory.
REAL_HOME_MODULES = frozenset({"home_isolation_probe.py", "test_home_isolation.py"})

#: The modules, as paths under tests/unit, whose subject is a tool probe itself:
#: ``UVToolRunner.uv_availability`` and ``get_tool_version``, ``get_uv_tool_command``,
#: ``verify_pre_installed_tool``, trivy's ``--help`` and ``version`` reads, or
#: opengrep's version. ``_unit_tool_guard`` answers those probes for every other
#: guarded test (``stub_tool_probes``), because building a scanner runs them and
#: the stand-in records ``uv tool run ... <tool> --version`` as a start; a test
#: of a probe has to reach the real code under its own doubles, so these keep
#: the probes as they are. Each still runs under the guard: a probe that reaches
#: a stand-in is recorded as before. A module can be here and in REAL_TOOL_MODULES
#: at once: that list only permits the ``runs_real_tools`` marker, and the tests of
#: such a module that do not carry it are guarded and keep their real probes only
#: through this entry, so the dual listing is load-bearing, not a leftover
#: (tests/unit/test_unit_conftest_module_lists.py pins both lists).
PROBE_SUBJECT_MODULES = frozenset(
    {
        "base/test_failure_lines_carry_no_environment_value.py",
        "base/test_inject_invocation_resolves_the_deferred_version.py",
        "base/test_install_command_dispatch_is_exhaustive.py",
        "base/test_scanner_spawn_failure.py",
        "base/test_the_install_debug_line_hides_an_env_read_pin.py",
        "cli/mcp/test_list_scanners.py",
        "config/test_tool_version_is_a_version_specifier.py",
        "core/phases/test_scanner_threads_keep_the_tree_scope.py",
        "core/test_inventory_installs_nothing.py",
        "core/test_unselected_scanners_are_not_resolved.py",
        "plugin_modules/ash_builtin/converters/test_jupyter_converter_sandbox.py",
        "plugin_modules/ash_builtin/converters/test_notebook_conversion_launches_one_tool.py",
        "plugin_modules/ash_builtin/scanners/test_pre_installed_tool_offline.py",
        "plugin_modules/ash_builtin/test_cdk_nag_partial_install.py",
        "plugin_modules/ash_builtin/test_opengrep_scanner.py",
        "plugin_modules/ash_builtin/test_trivy_probe_isolation.py",
        "plugin_modules/ash_builtin/test_trivy_scanner.py",
        "plugin_modules/ash_ferret_plugins/test_ferret_scanner.py",
        "plugin_modules/test_offline_trivy_terraform_modules.py",
        "plugin_modules/test_trivy_misconfig_list_cache.py",
        "utils/test_a_bare_value_string_is_one_value.py",
        "utils/test_a_cache_reset_during_a_version_probe_drops_its_answer.py",
        "utils/test_a_parked_probe_waiter_stops_when_its_scan_is_cancelled.py",
        "utils/test_a_probe_failure_text_belongs_to_its_own_call.py",
        "utils/test_a_probe_runs_in_the_directory_its_context_declares.py",
        "utils/test_a_refused_stops_pid_rides_every_producer.py",
        "utils/test_a_shared_probe_answer_stays_in_its_own_scope.py",
        "utils/test_a_signaled_post_run_failure_keeps_both_flags.py",
        "utils/test_a_stopped_install_drops_its_memos.py",
        "utils/test_a_timeout_limit_is_its_own_quoted_token.py",
        "utils/test_a_version_probe_crossing_an_invalidation_is_not_remembered.py",
        "utils/test_concurrent_checks_of_one_copy_start_one_probe.py",
        "utils/test_content_db_refresh.py",
        "utils/test_content_db_staleness.py",
        "utils/test_parsed_child_output_ignores_the_callers_terminal.py",
        "utils/test_pre_installed_tool.py",
        "utils/test_pre_installed_tool_sandbox_grant.py",
        "utils/test_pre_installed_tool_verdict_causes.py",
        "utils/test_the_uv_runner_keeps_the_stop_state.py",
        "utils/test_the_uv_tool_version_carries_no_piece_of_a_value.py",
        "utils/test_tool_lookups_follow_path_and_bin_path.py",
        "utils/test_uv_availability_probe_errors_are_retried.py",
        "utils/test_uv_ignores_repository_config.py",
        "utils/test_uv_installed_with_ash.py",
        "utils/test_uv_memos_answer_for_the_probed_environment.py",
        "utils/test_uv_tool_command_whose_file_is_gone.py",
        "utils/test_uv_tool_runner.py",
        "utils/test_uv_tool_runner_bundled_uv_inside_the_scanned_tree.py",
        "utils/test_uv_tool_runner_extended.py",
        "utils/test_uv_tool_runner_memos_and_records.py",
        "utils/test_uv_tool_runner_probe_memo_and_specs.py",
        "utils/test_uv_tool_python_request.py",
    }
)


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "runs_real_tools(reason): the test runs a real tool on purpose, so the unit "
        "tests' tool guard is not installed for it; only the modules in "
        "REAL_TOOL_MODULES (tests/unit/conftest.py) may use it",
    )


@pytest.fixture
def capture(caplog):
    """Route ASH's logger at WARNING into caplog.

    ASH's configured handler renders to a console and leaves nothing in
    ``caplog.records``, so its handlers are swapped for pytest's capture handlers
    for the duration, and the logger's own level is set, since
    ``caplog.at_level`` with no ``logger=`` lowers the root logger only and a
    merge that ran earlier in the process may have left ``ash`` higher. A test
    that asserts ``records == []`` through plain ``caplog`` passes with no capture
    at all; through this fixture the absence is a measurement.

    Here, at the unit tests' root conftest, so every module under tests/unit gets
    it by name: the merge tests under tests/unit/cli, and
    tests/unit/test_ash_output_dirs_are_not_scanned.py beside them. It used to be
    defined in tests/unit/cli/test_merge.py, and a module that took it from there
    had to bind it under its own name for pytest to register it.
    """
    from automated_security_helper.utils.log import ASH_LOGGER

    saved_handlers = ASH_LOGGER.handlers
    saved_propagate = ASH_LOGGER.propagate
    capture_handlers = [
        handler
        for handler in saved_handlers
        if isinstance(handler, type(caplog.handler))
    ]
    if caplog.handler not in capture_handlers:
        capture_handlers.append(caplog.handler)
    ASH_LOGGER.handlers = capture_handlers
    ASH_LOGGER.propagate = False
    caplog.set_level(logging.WARNING, logger=ASH_LOGGER.name)
    try:
        yield caplog
    finally:
        ASH_LOGGER.handlers = saved_handlers
        ASH_LOGGER.propagate = saved_propagate


@pytest.fixture
def in_ci() -> bool:
    """Whether this is a CI run, for tests that fail instead of skipping when a tool
    the runner images ship is missing.

    CI sets CI=true, CI=1 or the like; only an empty value, "false" and "0" mean not
    CI, so a runner that spells it 1 does not skip such tests silently.
    """
    return any(
        os.environ.get(name, "").strip().lower() not in ("", "false", "0")
        for name in ("CI", "GITHUB_ACTIONS")
    )


class UnitTestGuard(NamedTuple):
    """What ``_unit_tool_guard`` set up for a test."""

    #: None for a test marked ``runs_real_tools``.
    guard: Optional[ToolGuard]
    #: The test's own HOME, which the check reads; None for a ``real_home`` test,
    #: whose HOME is the developer's.
    home: Optional[Path]


@pytest.fixture(autouse=True)
def _unit_tool_guard(request, tmp_path_factory, _isolated_home, monkeypatch):
    """Every unit test starts no real tool and leaves no tool's file in its HOME.

    A unit test that reaches a real scanner tool depends on the host it runs on, and
    what the tool writes lands in the HOME of the run. Before this fixture, a run of
    tests/unit started real tools from 26 modules: ``uv tool run ... <tool>
    --version`` and ``uv tool list`` from scanner, converter and inventory probes, a
    uv found on the run's PATH or beside the interpreter, run by its path, and the
    host's own bandit, checkov and semgrep from a module-scoped fixture. ``ash``
    children left uv's ``tools/.lock``, ``~/.cache/checkov`` and
    ``~/.cache/semgrep_version`` in four modules' homes. Only the scanner directory
    and a few modules of their own were guarded.

    So each test gets the tool guard (``tests/utils/tool_guard.py``): a stand-in
    first on PATH for each guarded tool, which answers a version probe and records
    anything else, and an audit hook that sees a start by path. At teardown the test
    fails if it started a guarded tool or asked a stand-in to run one
    (``ToolGuard.tool_starts``), or left any file in its HOME but ASH's own
    (``tool_files_left_in``), which is how a tool started by a child process shows.
    It fails too if a start that skips subprocess.Popen (os.posix_spawn, os.system,
    os.exec* and os.spawn*, a fork, multiprocessing's starts, a C function looked
    up through ctypes) broke tests/conftest.py's HOME rule
    (``ToolGuard.home_refusals``): the recorder refuses such a start before it
    happens, and code that swallows the refusal does not hide it.
    tests/conftest.py gives each test that HOME, with the XDG directories in it. uv
    reads UV_TOOL_DIR and UV_CACHE_DIR before them, and CI and developers set both, so
    both point into the home here too; UV_TOOL_DIR is where XDG_DATA_HOME would put
    it, and also holds on Windows, where uv's default is not under HOME. The run
    points UV_CACHE_DIR at the developer's cache, so that a real uv starts warm; no
    unit test starts one but the listed ones, and one that did would write its cache
    where the check reads.

    A module in ``REAL_TOOL_MODULES`` runs a real tool on purpose. It says so with
    ``runs_real_tools(reason=...)`` and keeps the HOME check, without the guard. The
    marker anywhere else, or without a reason, fails the test. A ``real_home`` test
    has the developer's HOME, so only the guard applies to it, and only a module in
    ``REAL_HOME_MODULES`` may have one.

    A guarded test also gets the probes answered without a process
    (``stub_tool_probes``): building a uv-run scanner asks uv for the tool's
    version (``uv tool run --from <spec> <tool> --version``), detect-secrets'
    dependency check runs ``uv tool run detect-secrets --version``, a trivy
    scanner reads ``trivy repository --help`` and ``trivy version``, and the
    stand-in records each of those as a start, by design: ``--version`` with
    anything after it is a start. Before this, 85 unit modules that build a real
    scanner class and never asked for the stub failed at teardown on exactly that
    line, on every host. The answers are a host without the tools (uv absent, the
    pre-installed tool not executable, no trivy help text or database, no
    opengrep version); a test that needs a tool present says so with its own
    double, which it applies after this fixture and so wins. A module whose
    subject is a probe is in ``PROBE_SUBJECT_MODULES`` and keeps the real probes.

    Not covered: a module- or session-scoped fixture is set up before any test's
    guard is in, so one that starts a process puts in a guard of its own, as
    cli/mcp/test_list_scanners.py and test_session_plugins_stay_in_their_session.py
    do. A child process is not audited; the stand-ins answer a bare name it looks up
    on the PATH it inherits, and the HOME check sees what it writes.
    """
    marker = request.node.get_closest_marker("runs_real_tools")
    module = request.node.path.resolve().relative_to(UNIT_TESTS).as_posix()
    if marker is not None:
        refusal = real_tools_opt_out_refusal(
            marker.kwargs.get("reason"), module, REAL_TOOL_MODULES
        )
        if refusal is not None:
            pytest.fail(refusal)
    home = None
    if request.node.get_closest_marker("real_home") is None:
        home = Path.home()
    elif module not in REAL_HOME_MODULES:
        pytest.fail(
            f"{module} is marked real_home, which gives it the developer's HOME with "
            "no check of what it leaves there, and is not one of the modules allowed "
            f"that: {sorted(REAL_HOME_MODULES)}"
        )
    # Every patch this fixture makes goes on the test's own ``monkeypatch``, never
    # on a private MonkeyPatch of its own. Autouse fixtures of tests/conftest.py
    # take ``monkeypatch`` too, so it is set up before this fixture and torn down
    # after it, whatever this fixture's signature says. A private patch here was
    # undone first, and a test that then patched the same target (PATH,
    # UV_CACHE_DIR, ``sys.platform``, the probe stubs) had recorded this
    # fixture's value as the original and put it back AFTER the real one was
    # restored: the stand-in directory, a finished test's uv cache or a stub
    # lambda leaked into every later test of the worker. On one instance the
    # undo is last-in first-out: the test's patch goes, then this fixture's.
    if home is not None:
        monkeypatch.setenv(
            "UV_TOOL_DIR", str(home / ".local" / "share" / "uv" / "tools")
        )
        monkeypatch.setenv("UV_CACHE_DIR", str(home / ".cache" / "uv"))
    guard = None
    if marker is None:
        # Named by a counter, not tmp_path_factory.mktemp, which lists the whole
        # base directory to pick its next number: once per test, that listing
        # grew with the run (tests/conftest.py names the homes the same way).
        guard = install_tool_guard(
            monkeypatch,
            tmp_path_factory.getbasetemp() / "guards" / str(next(_GUARD_COUNTER)),
            own_directories=run_own_directories(tmp_path_factory.getbasetemp()),
            basetemp=tmp_path_factory.getbasetemp(),
        )
        if module not in PROBE_SUBJECT_MODULES:
            stub_tool_probes(monkeypatch)
    yield UnitTestGuard(guard, home)
    # The checks below run at this fixture's finalization, before ``monkeypatch``
    # unwinds, so a test's own patches are still in force here: a test that sets
    # ``sys.platform`` scopes that patch to its call (see
    # test_results_paths_compare_names_as_the_filesystem_does.py).
    started = guard.tool_starts if guard is not None else []
    refused = guard.home_refusals if guard is not None else []
    # Unconditional, not only when a guard was installed: a runs_real_tools
    # test has no guard, and the executable paths and probe answers it
    # resolved must not leak into the next test. The find_executable cache
    # keys carry PATH and ASH_BIN_PATH and revalidate the remembered file,
    # and only an UNGUARDED reader can be handed a stale entry: a guarded
    # test's own guard setup resets the caches, and its private stand-in
    # directory on PATH keys every lookup under an environment no other
    # test repeats. A guardless reader under the writer's environment,
    # while the writer's fake file is still alive in the run's tmp root,
    # was served the stale entry and passed on it -- a false green that
    # only showed when it ran alone.
    reset_tool_lookup_caches()
    assert started == [], f"{request.node.nodeid} started a tool: {started}"
    assert refused == [], f"{request.node.nodeid} broke the HOME rule: " + "; ".join(
        refused
    )
    if home is not None:
        left = tool_files_left_in(home)
        assert left == [], f"{request.node.nodeid} left a tool's files in HOME: {left}"


@pytest.fixture(autouse=True)
def _no_real_container_runtime(tmp_path_factory, _isolated_home):
    """No unit test runs the developer's container runtime to remove a container.

    The sweep of leftover containers removes a recorded container with the runtime's
    ``rm -f``. The container runtimes are not in the tool guard, so nothing else
    would stop a test that plants a record from reaching a real ``docker``. Every
    runtime a test legitimately runs here is a stub it wrote under the run's base
    temp directory, so a runner that resolves anywhere else fails the test before any
    process starts.
    """
    from automated_security_helper.interactions import container_leftovers

    base = os.path.realpath(tmp_path_factory.getbasetemp())
    real_removed = container_leftovers._removed

    def checked(runner_command, name):
        runner = runner_command[0] if runner_command else ""
        resolved = os.path.realpath(shutil.which(runner) or runner)
        if resolved != base and not resolved.startswith(base + os.sep):
            pytest.fail(
                f"a unit test tried to run the container runtime {resolved!r} to "
                f"remove {name}; a test supplies a stub under {base} instead"
            )
        return real_removed(runner_command, name)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(container_leftovers, "_removed", checked)
        yield


@pytest.fixture(autouse=True)
def _the_source_delivery_pools_are_this_tests_own(monkeypatch):
    """Each test gets clone and delivery pools of its own, started on first use.

    A stdio server's lifespan and an HTTP app's shutdown close the two pools in
    ``cli/mcp_server``, as the server's exit does
    (``_begin_stopping_source_jobs``), and a closed pool takes no more jobs.
    The pools are module-global, so a test that closes an app or leaves the stdio
    lifespan would otherwise make every later test in its worker fail on submit.
    That reaches beyond tests/unit/cli: the docs tests close HTTP apps and then
    deliver sources too, so the fixture lives here, for every unit test.

    Left alone when the module has not been imported: there is no pool to close,
    and importing it here would load the MCP server for every unit test.
    """
    module = sys.modules.get("automated_security_helper.cli.mcp_server")
    if module is None:
        yield
        return
    from automated_security_helper.cli.mcp import source_delivery

    clone = ThreadPoolExecutor(
        max_workers=source_delivery.CLONE_MAX_WORKERS,
        thread_name_prefix="ash-mcp-clone",
    )
    delivery = ThreadPoolExecutor(
        max_workers=source_delivery.DELIVERY_MAX_WORKERS,
        thread_name_prefix="ash-mcp-delivery",
    )
    monkeypatch.setattr(module, "_CLONE_EXECUTOR", clone)
    monkeypatch.setattr(module, "_DELIVERY_EXECUTOR", delivery)
    yield
    clone.shutdown(wait=False, cancel_futures=True)
    delivery.shutdown(wait=False, cancel_futures=True)


#: What a uv-managed tool's version probe reports under ``no_tool_probes``.
PINNED_TOOL_VERSION = "9.0.0"


@pytest.fixture
def no_tool_probes(monkeypatch: pytest.MonkeyPatch) -> None:
    """The scanner plugins' tool probes answer without starting a tool.

    Building a bandit, checkov or semgrep scanner asks uv for the tool's version
    (``UVToolRunner.uv_availability``, then ``get_tool_version``, which runs ``uv
    tool run <tool> --version``). detect-secrets' dependency check resolves its CLI
    through ``get_uv_tool_command``, which runs ``uv tool run detect-secrets
    --version`` when it finds a uv (the one installed beside ASH, else PATH's).
    opengrep's argument builder runs ``opengrep --version`` to decide on
    ``--metrics``. Where uv and the tools are installed, each of those starts the
    tool, and the tools write their own state: a pytest run of the scan-set modules
    left ``$XDG_CACHE_HOME/checkov/update_checker_cache.json`` and
    ``~/.semgrep/settings.yml`` behind, which land in the test's own home
    (tests/conftest.py), and uv wrote to its cache, which is the developer's. Those
    writes come from the processes themselves; with no process started, nothing
    else in these tests makes them.

    Under this fixture:

    * uv is reported available, and every tool's version as
      :data:`PINNED_TOOL_VERSION`, as tests/snapshot/conftest.py does for the
      snapshot tests;
    * ``get_uv_tool_command`` finds no uv, so it looks the tool up on PATH and runs
      nothing, and its memo is the test's own, so that answer is not served to a
      later test;
    * opengrep's version is unknown, which the scanner reads as an opengrep that
      takes no ``--metrics``, its default.

    A test of a probe itself does not take this fixture.
    """
    from automated_security_helper.plugin_modules.ash_builtin.scanners.opengrep_scanner import (
        OpengrepScanner,
    )
    from automated_security_helper.utils import uv_tool_runner
    from automated_security_helper.utils.uv_tool_runner import UVToolRunner

    monkeypatch.setattr(UVToolRunner, "uv_availability", lambda self: (True, None))
    monkeypatch.setattr(
        UVToolRunner,
        "get_tool_version",
        lambda self, tool_name, package_name=None, *args, **kwargs: PINNED_TOOL_VERSION,
    )
    monkeypatch.setattr(uv_tool_runner, "find_uv_or_none", lambda: None)
    monkeypatch.setattr(uv_tool_runner, "_uv_command_cache", {})
    monkeypatch.setattr(uv_tool_runner, "_uv_command_binary", {})
    monkeypatch.setattr(OpengrepScanner, "_get_opengrep_version", lambda self: None)


@pytest.fixture
def no_checkout_above_tmp_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """git, and ASH's own search for a repository, look at nothing above tmp_path.

    pytest's base temporary directory can sit inside a git checkout, a developer's
    or a CI workspace's, and a tree a test builds there without ``git init`` is then
    in that checkout: ``tracked_files_in`` answers ``[]`` for it where the test
    expects None. With ``GIT_CEILING_DIRECTORIES`` naming tmp_path, which git and
    ``scan_output_dirs._repository_root_of`` both honor, such a tree is outside any
    checkout wherever tmp_path is, and a repository a test creates under tmp_path
    is found as before.

    semgrep does not honor the variable when it anchors an ``--exclude`` (measured
    on 1.180.0), so the tests of those patterns read where it anchors instead
    (``test_ash_output_dirs_are_not_scanned._semgrep_anchor``).
    """
    monkeypatch.setenv("GIT_CEILING_DIRECTORIES", str(tmp_path))


@pytest.fixture
def model_with_one_high_finding():
    """A factory for a results model carrying one HIGH SARIF result for one scanner.

    ``factory(reports, scanner="tool-a", uri="src/app.py", model=None)`` sets
    ``additional_reports`` to *reports* and a SARIF report holding one HIGH finding
    attributed to *scanner* at *uri*. The rolled-up status reads its finding count off
    the aggregated SARIF, not off a per-target report, so a FAILED row needs a real
    result there.

    The builder is tree-neutral: it says nothing about which tree the finding is on,
    and the per-target reports in *reports* do not either. The tree is the caller's
    story, told by *uri* (a path under the scanned tree, or one under the converted
    work dir) and by the status each tree's report carries. With *model* given, the
    SARIF and the reports are set on it, for a caller whose model is a stand-in with
    its own config; otherwise a real ``AshAggregatedResults`` is built.
    """

    def factory(
        reports: dict,
        scanner: str = "tool-a",
        uri: str = "src/app.py",
        model=None,
    ):
        from automated_security_helper.models.asharp_model import AshAggregatedResults
        from automated_security_helper.schemas.sarif_schema_model import (
            ArtifactLocation,
            Level,
            Location,
            Message,
            Message1,
            PhysicalLocation,
            PhysicalLocation2,
            PropertyBag,
            Region,
            Result,
            Run,
            SarifReport,
            Tool,
            ToolComponent,
        )

        if model is None:
            model = AshAggregatedResults()
        model.sarif = SarifReport(
            version="2.1.0",
            runs=[
                Run(
                    tool=Tool(driver=ToolComponent(name="ASH", version="test")),
                    results=[
                        Result(
                            ruleId=f"{scanner}-RULE-1",
                            level=Level("error"),
                            message=Message(root=Message1(text=f"{scanner} finding")),
                            properties=PropertyBag(
                                scanner_name=scanner, issue_severity="HIGH"
                            ),
                            locations=[
                                Location(
                                    physicalLocation=PhysicalLocation(
                                        root=PhysicalLocation2(
                                            artifactLocation=ArtifactLocation(uri=uri),
                                            region=Region(startLine=1),
                                        )
                                    )
                                )
                            ],
                        )
                    ],
                    invocations=[],
                    properties=PropertyBag(),
                )
            ],
        )
        model.additional_reports = reports
        return model

    return factory
