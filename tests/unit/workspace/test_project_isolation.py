# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Cross-project state leakage, driven through ``execute_workspace`` concurrently.

Why these tests exist
---------------------
A scanner plugin instance is mutable and the scan phase mutates it in place:
``.context`` and ``.results_dir`` are reassigned immediately before each call
(``core/phases/scanner_executor.py``), and ``.start_time``, ``.end_time``,
``.errors``, ``.output`` and ``.config`` are written during the scan itself.
Projects run as threads in one process, not subprocesses, so an instance that
outlived one project would carry its state into the next -- and the observable
symptom is a finding filed against the wrong project, which is the worst
available way for this to fail. It is a silent false negative on a security
scanner, on exactly the axis the central invariant protects:

    For any project P, the findings reported for P and the pass/fail verdict for
    P are identical to what ``ash --source-dir P`` would produce.

What an earlier version of this file got wrong, and why it is recorded here
--------------------------------------------------------------------------
The first version built ``ScanPhase`` directly in a sequential
``for key in ("api", "web")`` loop and never called ``execute_workspace`` at all.
It passed, and it would have gone on passing if the executor had been refactored
to share one orchestrator across projects -- the precise defect it claimed to
guard. It was also blind to both concurrency defects found in this phase: the
global plugin registry deciding every project's scanner set, and the
registration race inside ``plugin_modules``.

Worse, its ``config`` assertion compared two objects the *test double* had just
minted in its own ``model_post_init`` fallback (``if self.config is None``), so
it was satisfied without any production config plumbing running. Three separate
tests in this phase turned out to have that shape -- an assertion that cannot
fail, passing -- so the rule applied here is: do not accept a test until it has
been seen to fail. ``TestTheIsolationCheckItselfFires`` is that demonstration,
and it runs the same assertion helper the passing tests use, against a
deliberately leaky executor.

How this version forces the failure it is looking for
-----------------------------------------------------
* It drives the real ``execute_workspace``, so the scoping under test is the
  scoping that ships. The orchestrator is substituted, because that is the
  documented injection point, but it runs a real ``ScanPhase`` over a real
  ``PluginContext`` built from a real per-project config.
* Every project rendezvouses at a barrier *inside* its scan, so all of them are
  demonstrably in flight simultaneously. Setting ``max_parallel_projects`` and
  hoping for overlap proves nothing: the work is fast enough to serialise by
  accident, which is how the first attempt at reproducing the registration race
  collected zero errors and asserted the absence of something it never produced.
  A barrier that does not trip is a test failure, not a slow pass.
* The per-project discriminator is a value in each project's own
  ``.ash/ash.yaml``, read back through ``resolve_config`` and
  ``AshConfig.get_plugin_config``. A leak shows up as the wrong project's value,
  and no fallback inside the test double can supply it.

Constraints and assumptions
---------------------------
* ``ScannerConfigSegment`` sets ``extra="allow"``, which is what lets a
  test-only ``scanners.recording`` block reach the scanner as its ``config``.
  If that ever becomes ``extra="forbid"``, these tests fail loudly at config
  load rather than quietly stopping being meaningful.
* The plan comes from the real ``resolve_workspace`` rather than being
  hand-built, so ``config_source`` and the project keys are the ones production
  computes. A hand-built plan would let a key/path confusion pass unnoticed.
* One project is nested (``apps/admin``, key ``apps-admin``) because
  ``_project_output_dir`` keys the output subtree by key and not by path, and
  that distinction only shows up when a project is more than one level deep.

Failure modes and known limitations
-----------------------------------
* The barrier makes concurrency observable, not exhaustive. It proves the
  projects overlap; it cannot prove every interleaving is safe.
* ``TestPluginManagerSingletonState`` is a static sweep, so it sees only direct
  attribute access. It cannot see state reached through a *method* -- and the
  registry defect in this phase arrived that way, through
  ``ash_plugin_manager.plugin_modules()``. That is covered by
  ``test_plugin_registry_scoping.py`` instead; neither file subsumes the other.
* That sweep also cannot reach an out-of-tree plugin module. Any check that
  reads this repository is blind to an ``ash_plugins.*`` package installed
  beside it, and no static test can close that -- the guarantee there is the
  refusal in ``resolver._validate_plugin_modules`` plus the pre-warm, not this.
"""

from __future__ import annotations

import ast
import sys
import json
import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Barrier, BrokenBarrierError, Lock
from typing import Any, Dict, List, Literal, Optional, Tuple
from unittest.mock import MagicMock, create_autospec

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.phases import scan_phase as scan_phase_module
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.models.scanner_validation import (
    ScannerValidationManager,
    ValidationCheckpoint,
)
from automated_security_helper.models.workspace import ProjectRunStatus
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from automated_security_helper.workspace.resolver import resolve_workspace
from tests.utils.helpers import ASH_TEST_TEMP_ROOT, iter_repo_files

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

#: How long a project waits at the rendezvous for its siblings. Bounded, because a
#: barrier that will never complete must fail the test rather than hang it, and
#: small because only the *failing* path ever waits this long -- when the projects
#: really do overlap, the barrier completes as soon as the last one arrives.
#: Measured at 15.0 first, which made a single regression in this file cost two
#: minutes of wall clock; five seconds is still ample for three threads that are
#: already running on a loaded box.
_RENDEZVOUS_TIMEOUT_SECONDS = 5.0

#: The projects every test in this file uses, and the marker each one declares in
#: its own config. Distinct values, because a marker shared between two projects
#: would let a leak between exactly those two pass unnoticed. Three projects
#: rather than two, because a check that only compares a pair cannot see a third
#: project disagreeing -- a hole found in this phase's CI gate.
PROJECT_MARKERS: Dict[str, str] = {
    "api": "marker-from-api",
    "web": "marker-from-web",
    "apps/admin": "marker-from-apps-admin",
}

#: Project relative path -> the key resolution derives from it.
PROJECT_KEYS: Dict[str, str] = {
    "api": "api",
    "web": "web",
    "apps/admin": "apps-admin",
}


@dataclass(frozen=True)
class Observation:
    """What one ``scan()`` call saw, from inside the scan.

    Recorded from inside rather than inspected afterwards because the leak this
    file is about is a value being *correct at one moment and wrong at another*.
    Reading ``instance.context`` after every project has finished samples only
    the last writer, which is how a reused instance can look innocent.
    """

    instance_id: int
    source_dir: str
    output_dir: str
    results_dir: str
    marker: str


_RECORD_LOCK = Lock()
OBSERVATIONS: List[Observation] = []

# Every instance the scan phase constructed. A list rather than a counter because
# the assertions need identity: a count alone cannot tell a fresh instance from a
# reused one.
CONSTRUCTED: List["RecordingScanner"] = []


class _Rendezvous:
    """Holds every project inside its scan until all of them have arrived.

    Without this the projects are free to run one after another and every
    isolation assertion still passes, having tested nothing about concurrency.
    ``arrived`` and ``broke`` are recorded so a test can assert that the overlap
    actually happened rather than assuming it.
    """

    def __init__(self, parties: int, timeout: float) -> None:
        self._barrier = Barrier(parties)
        self._timeout = timeout
        self.arrived: List[str] = []
        self.broke = False

    def wait(self, who: str) -> None:
        with _RECORD_LOCK:
            self.arrived.append(who)
        try:
            self._barrier.wait(timeout=self._timeout)
        except BrokenBarrierError:
            # Not enough projects were in flight at once. Recorded rather than
            # raised here so the failure is reported by an assertion that names
            # the cause, instead of arriving as one project's opaque error.
            self.broke = True


_RENDEZVOUS: Optional[_Rendezvous] = None


def _set_rendezvous(parties: int) -> _Rendezvous:
    global _RENDEZVOUS
    _RENDEZVOUS = _Rendezvous(parties, _RENDEZVOUS_TIMEOUT_SECONDS)
    return _RENDEZVOUS


class RecordingScannerConfig(ScannerPluginConfigBase):
    name: str = "recording"
    enabled: bool = True
    #: The per-project discriminator, set in each project's own ``.ash/ash.yaml``.
    #: A plain field rather than something under ``options`` so that a wrong value
    #: is a wrong value and not a missing key.
    marker: str = "no-marker-reached-this-scanner"


class RecordingScanner(ScannerPluginBase[RecordingScannerConfig]):
    """A scanner that records the mutable state it was handed, and mutates it.

    A real plugin rather than a ``MagicMock``: the point is that these attributes
    are ordinary pydantic fields on one object, and a mock would prove nothing
    about whether they can leak between projects.
    """

    def model_post_init(self, context):
        # No `if self.config is None` fallback. An earlier version of this file
        # had one, and it silently answered the config-isolation assertion by
        # itself -- the assertion passed without any production config plumbing
        # running. If config does not arrive, the marker stays at its sentinel
        # and the assertion says so.
        result = super().model_post_init(context)
        with _RECORD_LOCK:
            CONSTRUCTED.append(self)
        return result

    def validate_plugin_dependencies(self) -> bool:
        return True

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[dict]]:
        raise NotImplementedError("RecordingScanner overrides scan() directly")

    def scan(
        self,
        target,
        target_type="source",
        global_ignore_paths=None,
        config=None,
        *args,
        **kwargs,
    ):
        source_name = self.context.source_dir.name
        if _RENDEZVOUS is not None:
            # Hold here until every sibling project is also inside its scan, so
            # any shared state is being touched by all of them at once.
            _RENDEZVOUS.wait(source_name)

        # Mutate every attribute the executor and the scan template touch, so a
        # reused instance would be observable afterwards.
        self.start_time = datetime.now(timezone.utc)
        self.errors.append(f"error from {source_name}")
        self.output.append(f"output from {source_name}")
        self.end_time = datetime.now(timezone.utc)
        self.exit_code = 0

        marker = getattr(self.config, "marker", None) or "no-config-on-this-scanner"
        observation = Observation(
            instance_id=id(self),
            source_dir=self.context.source_dir.as_posix(),
            output_dir=self.context.output_dir.as_posix(),
            results_dir=Path(self.results_dir).as_posix(),
            marker=str(marker),
        )
        with _RECORD_LOCK:
            OBSERVATIONS.append(observation)

        return {
            "status": "passed",
            "seen_source_dir": observation.source_dir,
            "seen_marker": observation.marker,
        }


def _write_project(root: Path, relative_path: str, marker: str) -> None:
    """One project directory with its own config declaring its own marker."""
    project = root / relative_path
    (project / "src").mkdir(parents=True, exist_ok=True)
    (project / "src" / "app.py").write_text("print('x')\n", encoding="utf-8")
    config_dir = project / ".ash"
    config_dir.mkdir(parents=True, exist_ok=True)
    # A real config file, loaded by resolve_config, carrying a value only this
    # project declares. This is the whole reason the marker assertion is not
    # vacuous: nothing in the test double can invent this string.
    config_dir.joinpath("ash.yaml").write_text(
        "\n".join(
            [
                f"project_name: {relative_path}",
                "scanners:",
                "  recording:",
                "    name: recording",
                "    enabled: true",
                f"    marker: {marker}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )


def _write_workspace(root: Path) -> Path:
    for relative_path, marker in PROJECT_MARKERS.items():
        _write_project(root, relative_path, marker)
    workspace_file = root / "dev.code-workspace"
    workspace_file.write_text(
        json.dumps(
            {"folders": [{"path": path} for path in PROJECT_MARKERS]},
        ),
        encoding="utf-8",
    )
    return workspace_file


def _run_scan_phase(context: PluginContext) -> AshAggregatedResults:
    """Run one project's real scan phase with the recording scanner registered.

    Runs on a project's worker thread, so it replaces the phase's own validation
    manager rather than patching ``scan_phase.ScannerValidationManager``: a patch
    of a module attribute is process-wide, and two projects' patches overlapping
    left one project's mock in place for every later test on the worker.
    """
    progress = MagicMock()
    progress.add_task.return_value = 1
    phase = ScanPhase(
        plugin_context=context,
        plugins=[RecordingScanner],
        progress_display=progress,
    )
    phase.validation_manager = _validation_manager_double()
    return phase.execute(aggregated_results=AshAggregatedResults())


def _validation_manager_double():
    """The scan phase's validation manager, answering with a real, empty checkpoint.

    Autospecced with spec_set: a method the manager does not have fails where it
    is configured instead of being configured and never called, an assignment to
    a misspelled attribute fails, and so does a call the real signature refuses.
    The checkpoint is real because the phase formats its values.
    """
    manager = create_autospec(ScannerValidationManager, instance=True, spec_set=True)
    checkpoint = ValidationCheckpoint(checkpoint_name="project-isolation")
    manager.validate_task_queue.return_value = checkpoint
    manager.validate_execution_completion.return_value = checkpoint
    manager.ensure_complete_results.return_value = checkpoint
    manager.report_execution_discrepancies.return_value = {}
    manager.report_result_completeness.return_value = {}
    return manager


class ScanningOrchestrator:
    """Stands in for ``ASHScanOrchestrator``, running a real scan phase.

    Substituted rather than used directly because ``ASHScanOrchestrator`` would
    run the nine real scanners against three fixture trees, which is an
    integration test and not this one. Everything it does downstream of the
    substitution is production code: ``resolve_config`` loads the project's own
    config, ``PluginContext`` carries it, and ``ScanPhase`` decides what the
    scanner instance receives.
    """

    def __init__(self, **kwargs: Any) -> None:
        self.source_dir = Path(kwargs["source_dir"])
        self.output_dir = Path(kwargs["output_dir"])
        self.config_path = kwargs.get("config_path")

    @classmethod
    def create(cls, **kwargs: Any) -> "ScanningOrchestrator":
        return cls(**kwargs)

    def execute_scan(self, phases: Optional[List[str]] = None) -> AshAggregatedResults:
        config = resolve_config(
            config_path=self.config_path, source_dir=self.source_dir
        )
        return _run_scan_phase(
            PluginContext(
                source_dir=self.source_dir,
                output_dir=self.output_dir,
                config=config,
            )
        )


class LeakyOrchestrator:
    """Models the defect: one scanner instance reused across every project.

    Deliberately bypasses ``ScanPhase``, because ``ScanPhase`` constructing a
    fresh instance per invocation is exactly the property being removed. What it
    does to the shared instance -- reassign ``.context`` and ``.results_dir``
    immediately before calling it -- is what ``scanner_executor.py`` does today;
    the only change is that the instance outlives one project.

    This exists so the isolation assertions can be seen failing. A guard that has
    never been observed to fail is not a guard.
    """

    _shared: Optional[RecordingScanner] = None
    _shared_lock = Lock()

    def __init__(self, **kwargs: Any) -> None:
        self.source_dir = Path(kwargs["source_dir"])
        self.output_dir = Path(kwargs["output_dir"])
        self.config_path = kwargs.get("config_path")

    @classmethod
    def create(cls, **kwargs: Any) -> "LeakyOrchestrator":
        return cls(**kwargs)

    @classmethod
    def reset(cls) -> None:
        cls._shared = None

    def execute_scan(self, phases: Optional[List[str]] = None) -> AshAggregatedResults:
        config = resolve_config(
            config_path=self.config_path, source_dir=self.source_dir
        )
        context = PluginContext(
            source_dir=self.source_dir,
            output_dir=self.output_dir,
            config=config,
        )
        with LeakyOrchestrator._shared_lock:
            if LeakyOrchestrator._shared is None:
                LeakyOrchestrator._shared = RecordingScanner(
                    config=config.get_plugin_config(
                        plugin_type="scanner", plugin_name="recordingscanner"
                    ),
                    context=context,
                )
            scanner = LeakyOrchestrator._shared
        # The in-place reassignment the executor performs, on an instance that
        # belongs to another project.
        scanner.context = context
        scanner.results_dir = context.output_dir / "scanners" / "recording"
        scanner.scan(target=self.source_dir, target_type="source")
        return AshAggregatedResults()


def _assert_projects_were_isolated(observations: List[Observation]) -> None:
    """The isolation contract, as one helper both the real and mutation tests run.

    Shared deliberately. A mutation test that re-implements the check proves the
    re-implementation fires, not the check the passing test relies on.
    """
    assert len(observations) == len(PROJECT_MARKERS), (
        f"expected one scan per project, got {len(observations)}: {observations}"
    )

    # One instance per project. A reused instance collapses this set.
    instance_ids = {observation.instance_id for observation in observations}
    assert len(instance_ids) == len(PROJECT_MARKERS), (
        "scanner instances were shared between projects: "
        f"{len(instance_ids)} instance(s) served {len(observations)} project(s)"
    )

    # No instance saw more than one project's tree.
    per_instance: Dict[int, set] = {}
    for observation in observations:
        per_instance.setdefault(observation.instance_id, set()).add(
            observation.source_dir
        )
    shared = {
        instance_id: sorted(seen)
        for instance_id, seen in per_instance.items()
        if len(seen) > 1
    }
    assert shared == {}, f"one scanner instance saw several projects: {shared}"

    # Each project read its own config, through production config plumbing.
    by_source = {
        Path(observation.source_dir).name: observation for observation in observations
    }
    for relative_path, marker in PROJECT_MARKERS.items():
        leaf = Path(relative_path).name
        assert leaf in by_source, f"project '{relative_path}' never scanned"
        assert by_source[leaf].marker == marker, (
            f"project '{relative_path}' scanned with marker "
            f"'{by_source[leaf].marker}' instead of its own '{marker}'; a "
            f"different project's config reached it"
        )

    # Distinct output subtrees, so the same scanner on two projects cannot
    # overwrite the other's raw output.
    results_dirs = {observation.results_dir for observation in observations}
    assert len(results_dirs) == len(PROJECT_MARKERS), (
        f"projects shared a scanner results_dir: {sorted(results_dirs)}"
    )


@pytest.fixture(autouse=True)
def _reset_recorders():
    CONSTRUCTED.clear()
    OBSERVATIONS.clear()
    LeakyOrchestrator.reset()
    global _RENDEZVOUS
    _RENDEZVOUS = None
    yield
    CONSTRUCTED.clear()
    OBSERVATIONS.clear()
    LeakyOrchestrator.reset()
    _RENDEZVOUS = None
    leaked = _put_back_a_leaked_manager()
    assert leaked is None, leaked


def _put_back_a_leaked_manager() -> Optional[str]:
    """What replaced ``scan_phase.ScannerValidationManager``, or None if nothing did.

    Projects run on worker threads, and a patch of a module attribute is not
    thread-safe: when two threads' patches overlap, the later one restores the
    earlier one's mock, and every later test on the worker builds its ScanPhase
    with it. Checked after each test here, where the leak would start, and the
    class is put back, so the test that leaked fails and the ones after it do not.
    """
    current = scan_phase_module.ScannerValidationManager
    if current is ScannerValidationManager:
        return None
    scan_phase_module.ScannerValidationManager = ScannerValidationManager
    return f"a test left scan_phase.ScannerValidationManager replaced: {current!r}"


def _execute(tmp_path: Path, factory, *, bound: int = len(PROJECT_MARKERS)):
    """Resolve and execute the fixture workspace, concurrently."""
    workspace_file = _write_workspace(tmp_path)
    plan = resolve_workspace(workspace_file)
    settings = ProjectScanSettings(
        output_dir=tmp_path / "out",
        phases=("scan",),
        max_parallel_projects=bound,
    )
    return plan, execute_workspace(plan, settings, orchestrator_factory=factory)


class TestTheFixtureCanDiscriminate:
    """The fixture data has to be able to tell the projects apart.

    Every marker assertion in this file compares a value written from
    ``PROJECT_MARKERS`` against a value read back from ``PROJECT_MARKERS``. That
    is only meaningful because a long production path runs in between -- YAML on
    disk, ``resolve_workspace``, ``execute_workspace``, ``resolve_config``,
    ``get_plugin_config``, ``ScanPhase`` -- and because the markers are distinct,
    so arriving at the wrong project is visible.

    If two projects ever shared a marker, a leak between exactly those two would
    pass silently, and the comparison would look just as green. Asserted here
    because that is a one-character edit away and nothing else would notice.
    """

    def test_every_project_declares_a_distinct_marker(self):
        markers = list(PROJECT_MARKERS.values())
        assert len(set(markers)) == len(markers), (
            "two projects share a marker, so a leak between them cannot be "
            f"detected by any assertion in this file: {markers}"
        )

    def test_every_project_has_a_distinct_leaf_directory_name(self):
        """Observations are keyed by leaf name, so two ``admin`` folders would merge."""
        leaves = [Path(path).name for path in PROJECT_MARKERS]
        assert len(set(leaves)) == len(leaves), leaves

    def test_the_key_map_covers_the_same_projects(self):
        assert set(PROJECT_KEYS) == set(PROJECT_MARKERS)


class TestProjectsAreIsolatedUnderConcurrency:
    """The contract, driven through ``execute_workspace`` with projects overlapping."""

    def test_every_project_ran_concurrently(self, tmp_path):
        """The premise. If this fails, nothing else in the class means anything.

        A test whose concurrency never materialises is a sequential test with a
        misleading name, and it will keep passing after the property it claims to
        check has been removed.
        """
        rendezvous = _set_rendezvous(len(PROJECT_MARKERS))
        _execute(tmp_path, ScanningOrchestrator.create)
        assert not rendezvous.broke, (
            "projects did not overlap: at least one reached the rendezvous after "
            "the others had given up waiting, so this suite exercised sequential "
            f"execution. Arrived: {rendezvous.arrived}"
        )
        assert sorted(rendezvous.arrived) == sorted(
            Path(path).name for path in PROJECT_MARKERS
        )

    def test_projects_do_not_share_scanner_state(self, tmp_path):
        _set_rendezvous(len(PROJECT_MARKERS))
        _execute(tmp_path, ScanningOrchestrator.create)
        _assert_projects_were_isolated(OBSERVATIONS)

    def test_each_project_read_its_own_config(self, tmp_path):
        """The assertion the previous version of this file could not make.

        The marker arrives from the project's own ``.ash/ash.yaml`` by way of
        ``resolve_config`` and ``AshConfig.get_plugin_config``. Nothing in the
        test double can supply it, so a wrong value means a real leak and a
        missing value means the config never arrived at all.
        """
        _set_rendezvous(len(PROJECT_MARKERS))
        _execute(tmp_path, ScanningOrchestrator.create)
        seen = {
            Path(observation.source_dir).name: observation.marker
            for observation in OBSERVATIONS
        }
        assert seen == {
            Path(path).name: marker for path, marker in PROJECT_MARKERS.items()
        }

    def test_mutable_attributes_do_not_accumulate_across_projects(self, tmp_path):
        """A shared mutable default, or a shared instance, would concatenate these."""
        _set_rendezvous(len(PROJECT_MARKERS))
        _execute(tmp_path, ScanningOrchestrator.create)
        assert len(CONSTRUCTED) == len(PROJECT_MARKERS)
        for instance in CONSTRUCTED:
            assert len(instance.errors) == 1, (
                f"scanner accumulated {instance.errors} across projects"
            )
            assert len(instance.output) == 1, (
                f"scanner accumulated {instance.output} across projects"
            )

    def test_each_project_wrote_its_own_output_subtree(self, tmp_path):
        """Requirement 3, keyed by project key rather than by path."""
        _set_rendezvous(len(PROJECT_MARKERS))
        _, result = _execute(tmp_path, ScanningOrchestrator.create)
        for relative_path, key in PROJECT_KEYS.items():
            expected = (
                tmp_path / "out" / "projects" / key / "scanners" / "recording"
            ).as_posix()
            matching = [
                observation
                for observation in OBSERVATIONS
                if observation.results_dir == expected
            ]
            assert matching, (
                f"project '{relative_path}' did not write to "
                f"projects/{key}/scanners/recording; saw "
                f"{sorted(o.results_dir for o in OBSERVATIONS)}"
            )
        assert result.exit_code == 0, result.payload

    def test_a_nested_project_becomes_one_directory_not_two(self, tmp_path):
        """``apps/admin`` is ``apps-admin``, so it cannot collide with ``apps``."""
        _set_rendezvous(len(PROJECT_MARKERS))
        _execute(tmp_path, ScanningOrchestrator.create)
        nested = [
            observation
            for observation in OBSERVATIONS
            if observation.source_dir.endswith("apps/admin")
        ]
        assert len(nested) == 1
        assert "projects/apps-admin/scanners/recording" in nested[0].results_dir
        assert "projects/apps/admin" not in nested[0].results_dir

    def test_every_project_completed(self, tmp_path):
        """Guards against the isolation checks passing because nothing ran.

        A project that failed produces no observations, and an assertion over an
        empty list is an assertion that cannot fail. Both of the other holes
        found in this phase had that shape.
        """
        _set_rendezvous(len(PROJECT_MARKERS))
        _, result = _execute(tmp_path, ScanningOrchestrator.create)
        statuses = {entry.project: entry.status for entry in result.payload.projects}
        assert statuses == dict.fromkeys(
            PROJECT_KEYS.values(), ProjectRunStatus.COMPLETED
        ), [
            (entry.project, entry.status, entry.error)
            for entry in result.payload.projects
        ]


class TestTheIsolationCheckItselfFires:
    """The demonstration: the same helper, against an executor that does leak.

    Every assertion in ``_assert_projects_were_isolated`` is only worth its line
    count if it can be made to fail. This class makes it fail, using the shape of
    the real hazard -- one plugin instance reused across projects, with
    ``.context`` reassigned in place -- rather than a strawman.
    """

    def test_a_reused_instance_is_caught(self, tmp_path):
        _set_rendezvous(len(PROJECT_MARKERS))
        _execute(tmp_path, LeakyOrchestrator.create)
        with pytest.raises(AssertionError) as excinfo:
            _assert_projects_were_isolated(OBSERVATIONS)
        message = str(excinfo.value)
        # Named so a future reader can tell which invariant broke, and so this
        # test cannot be satisfied by an unrelated assertion failing.
        assert "shared between projects" in message or "saw several projects" in message

    def test_the_leak_is_observable_in_the_recorded_state(self, tmp_path):
        """What the leak looks like from outside, stated once so it is recognisable."""
        _set_rendezvous(len(PROJECT_MARKERS))
        _execute(tmp_path, LeakyOrchestrator.create)
        assert len({observation.instance_id for observation in OBSERVATIONS}) == 1
        shared = LeakyOrchestrator._shared
        assert shared is not None
        # One instance carrying every project's errors, which under the real
        # executor would be reported against whichever project finished last.
        assert len(shared.errors) == len(PROJECT_MARKERS), shared.errors

    def test_the_marker_check_catches_a_config_from_the_wrong_project(self, tmp_path):
        """The specific assertion the previous version of this file lacked.

        The leaky executor keeps the first project's config on the shared
        instance, so later projects scan with a marker they never declared. That
        is precisely a project's own configuration being silently overridden.
        """
        _set_rendezvous(len(PROJECT_MARKERS))
        _execute(tmp_path, LeakyOrchestrator.create)
        markers = {observation.marker for observation in OBSERVATIONS}
        assert len(markers) == 1, (
            "the leaky executor was expected to serve one config to every "
            f"project, but produced {markers}"
        )
        wrong = [
            observation
            for observation in OBSERVATIONS
            if observation.marker
            != PROJECT_MARKERS[_relative_path_for(observation.source_dir)]
        ]
        assert wrong, "no project scanned with another project's marker"

    def test_the_results_dir_check_catches_a_shared_subtree(self, tmp_path):
        """A single project, so a shared results_dir is the only way to fail.

        Runs the helper against one observation to show the count assertion
        fires too -- otherwise a suite could satisfy every other check while
        silently scanning fewer projects than the workspace declares.
        """
        _set_rendezvous(1)
        with pytest.raises(AssertionError) as excinfo:
            _assert_projects_were_isolated(
                [
                    Observation(
                        instance_id=1,
                        source_dir=(tmp_path / "api").as_posix(),
                        output_dir=(tmp_path / "out").as_posix(),
                        results_dir="shared",
                        marker=PROJECT_MARKERS["api"],
                    )
                ]
            )
        assert "expected one scan per project" in str(excinfo.value)


def _relative_path_for(source_dir: str) -> str:
    """Which fixture project a scanned directory belongs to."""
    for relative_path in PROJECT_MARKERS:
        if source_dir.endswith(relative_path):
            return relative_path
    raise AssertionError(f"unrecognised project directory: {source_dir}")


class TestAScannerWithNoConfigIsExcluded:
    """A config that fails to arrive silences the scanner; it does not default it.

    Found by removing the ``if self.config is None`` fallback that made the old
    config assertion vacuous. Without a config the scanner is not run with
    defaults -- ``ScanPhase`` filters it out, because enablement is decided by
    ``bool(plugin_instance.config.enabled)`` and a ``None`` config has no
    ``enabled``. So the fallback was not merely making one assertion meaningless;
    it was the only reason the scanner ran at all in the single-directory case.

    Pinned because of what it means for workspace mode: if a project's config
    failed to reach its scanners, the symptom would be a scanner quietly not
    running, reported as a clean project rather than as an error. That is a false
    negative with no message, on the same axis as the registry defect.
    """

    def test_no_config_means_no_scan(self, tmp_path):
        source_dir = tmp_path / "unconfigured"
        (source_dir / "src").mkdir(parents=True)
        (source_dir / "src" / "app.py").write_text("print('x')\n", encoding="utf-8")
        output_dir = tmp_path / "unconfigured-out"
        output_dir.mkdir()
        # A default AshConfig has no `scanners.recording` entry, so
        # get_plugin_config returns None for this scanner.
        _run_scan_phase(
            PluginContext(
                source_dir=source_dir,
                output_dir=output_dir,
                config=AshConfig(project_name="unconfigured"),
            )
        )
        assert OBSERVATIONS == [], (
            "a scanner with no resolved config was run anyway; enablement no "
            "longer depends on the config reaching it, which changes what a "
            "config-plumbing failure looks like"
        )

    def test_a_config_that_arrives_enables_the_scan(self, tmp_path):
        """The other half, so the test above cannot pass because nothing works."""
        _write_project(tmp_path, "configured", "marker-from-configured")
        source_dir = tmp_path / "configured"
        output_dir = tmp_path / "configured-out"
        output_dir.mkdir()
        _run_scan_phase(
            PluginContext(
                source_dir=source_dir,
                output_dir=output_dir,
                config=resolve_config(
                    config_path=source_dir / ".ash" / "ash.yaml",
                    source_dir=source_dir,
                ),
            )
        )
        assert len(OBSERVATIONS) == 1
        assert OBSERVATIONS[0].marker == "marker-from-configured"


class TestTheScanPhaseDoublesAreTheRealShapes:
    """The phase runs against its validation manager double without an error.

    The double was a bare MagicMock that configured a method the manager does not
    have, and its checkpoint a MagicMock whose ``metadata.get`` returned another,
    so the phase's ``{completion_rate:.1%}`` raised inside its own try and logged
    "Error during execution completion validation" on every scan here.
    """

    def test_one_project_scan_logs_no_error(self, tmp_path, caplog):
        _write_project(tmp_path, "checked", "marker-from-checked")
        source_dir = tmp_path / "checked"
        output_dir = tmp_path / "checked-out"
        output_dir.mkdir()

        with caplog.at_level(logging.ERROR):
            _run_scan_phase(
                PluginContext(
                    source_dir=source_dir,
                    output_dir=output_dir,
                    config=resolve_config(
                        config_path=source_dir / ".ash" / "ash.yaml",
                        source_dir=source_dir,
                    ),
                )
            )

        errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
        assert errors == [], errors
        assert len(OBSERVATIONS) == 1

    def test_the_manager_double_refuses_an_attribute_the_manager_lacks(self):
        """A misspelled assignment would configure nothing, and the test would pass."""
        manager = _validation_manager_double()

        with pytest.raises(AttributeError):
            manager.validate_task_queu = MagicMock()

    def test_the_manager_double_refuses_a_call_the_manager_would(self):
        """validate_task_queue takes the queue's contents; a call without them fails."""
        manager = _validation_manager_double()

        with pytest.raises(TypeError):
            manager.validate_task_queue()


class TestALeakedManagerIsPutBack:
    """A leak fails the test that made it, and stops there."""

    def test_a_leaked_manager_is_named_and_the_class_put_back(self):
        leaked = MagicMock(name="leaked-manager")
        scan_phase_module.ScannerValidationManager = leaked

        message = _put_back_a_leaked_manager()

        assert scan_phase_module.ScannerValidationManager is ScannerValidationManager
        assert message is not None and "leaked-manager" in message, message


class TestSingleProjectPathsAreUnchanged:
    """Requirement 9. Nothing branches on workspace mode, so nothing can drift.

    A single-directory scan hands the scanner base an ``output_dir`` with no
    ``projects/`` component, and the base builds ``scanners/<name>`` under it
    exactly as it always did. This is why single-project mode cannot regress:
    there is no conditional to take.
    """

    def test_single_project_paths_have_no_projects_component(self, tmp_path):
        _write_project(tmp_path, "single", "marker-from-single")
        source_dir = tmp_path / "single"
        output_dir = tmp_path / "single-out"
        output_dir.mkdir()
        _run_scan_phase(
            PluginContext(
                source_dir=source_dir,
                output_dir=output_dir,
                config=resolve_config(
                    config_path=source_dir / ".ash" / "ash.yaml",
                    source_dir=source_dir,
                ),
            )
        )
        assert len(OBSERVATIONS) == 1
        results_dir = Path(OBSERVATIONS[0].results_dir)
        assert results_dir == output_dir / "scanners" / "recording"
        assert "projects" not in results_dir.parts

    def test_the_per_target_subdirectory_is_still_the_scanner_s_own(self, tmp_path):
        """The base sets ``scanners/<name>``; the target_type layer is the scanner's.

        Pinned because the requirement names the full
        ``scanners/<scanner>/<target_type>`` path, and the split between who
        contributes which segment is easy to get wrong when reading only the base.
        """
        _set_rendezvous(len(PROJECT_MARKERS))
        _execute(tmp_path, ScanningOrchestrator.create)
        for observation in OBSERVATIONS:
            assert (
                (Path(observation.results_dir) / "source")
                .as_posix()
                .endswith("scanners/recording/source")
            )


class TestPluginManagerSingletonState:
    """The process-global mutable state on ``ash_plugin_manager``, and who touches it.

    ``ash_plugin_manager`` is a module-level singleton (``plugins/__init__.py``)
    and workspace mode runs several differently-configured scans against it in
    one process. Three pieces of its state are mutable and process-wide:

    * ``context``, overwritten by every ``ScanExecutionEngine.__init__`` through
      ``set_context``. Under parallel projects the last writer wins, so any
      consumer that read it would see an arbitrary project's context. Nothing
      reads it, which is why parallel projects are safe there -- safety by
      accident, which these tests convert into safety by assertion.
    * ``plugin_library`` and ``_resolved_plugins``, which is where the registry
      defect in this phase lived: the first project to build an engine froze the
      scanner class list for every project.

    Why a sweep for module-level mutable *bindings* would have missed all of it:
    ``ash_plugin_manager = AshPluginManager()`` is an assignment of an object, so
    it matches no mutable-literal pattern, and ``.context`` is never assigned at
    module level at all. Any future search for shared state has to cover
    singleton instances and attributes set on them later, not just bindings.

    The blind spot, stated plainly: this is a static sweep over direct attribute
    access. It cannot see state reached through a method, and the registry defect
    arrived exactly that way, via ``ash_plugin_manager.plugin_modules()``. That
    one is covered by ``test_plugin_registry_scoping.py``. Neither file replaces
    the other, and a reviewer should not read a green sweep here as evidence that
    the registry is scoped.
    """

    #: Directory names never worth walking: build output, caches, and virtualenvs.
    _SKIP_DIRS = frozenset(
        {
            "__pycache__",
            "build",
            "dist",
            "node_modules",
            "site",
            "htmlcov",
        }
    )

    #: Spellings of a direct read or write. ``set_context`` is excluded because it
    #: is the sanctioned writer; anything else touching the attribute by name is
    #: treating process-global state as if it were per-scan.
    _CONTEXT_PATTERNS = (
        "ash_plugin_manager.context",
        'getattr(ash_plugin_manager, "context"',
        "getattr(ash_plugin_manager, 'context'",
    )

    #: The files the registry sweep allows in, with the reasons the sweep
    #: test's docstring gives. plugin_manager.py is the registry's production
    #: owner; the rest are test files, and every registry-reaching helper they
    #: define must be a _REGISTRY_HELPERS key (the completeness test below).
    _REGISTRY_SWEEP_ALLOWED = (
        "automated_security_helper/plugins/plugin_manager.py",
        "test_plugin_system.py",
        "tests/snapshot/conftest.py",
        "tests/snapshot/test_snapshot_plugin_registry.py",
        "tests/conftest.py",
        "tests/unit/test_conftest_tool_state_isolation.py",
        "tests/unit/cli/test_report_refuses_invalid_plugin_options.py",
        "tests/unit/cli/test_operator_text_is_not_markup.py",
    )

    _REGISTRY_PATTERNS = (
        "ash_plugin_manager.plugin_library",
        "ash_plugin_manager._resolved_plugins",
        'getattr(ash_plugin_manager, "plugin_library"',
        "getattr(ash_plugin_manager, 'plugin_library'",
        'getattr(ash_plugin_manager, "_resolved_plugins"',
        "getattr(ash_plugin_manager, '_resolved_plugins'",
        # A write by name: monkeypatch.setattr, setattr and patch.object.
        'setattr(ash_plugin_manager, "plugin_library"',
        "setattr(ash_plugin_manager, 'plugin_library'",
        'setattr(ash_plugin_manager, "_resolved_plugins"',
        "setattr(ash_plugin_manager, '_resolved_plugins'",
        'patch.object(ash_plugin_manager, "plugin_library"',
        "patch.object(ash_plugin_manager, 'plugin_library'",
        'patch.object(ash_plugin_manager, "_resolved_plugins"',
        "patch.object(ash_plugin_manager, '_resolved_plugins'",
    )

    @classmethod
    def _source_files(cls):
        """Every Python file in the repository, not only the package.

        Widened from a package-only walk because a plugin, a script or a helper
        under ``tests/`` can reach the same singleton, and the package walk would
        not have seen it. Out-of-tree plugin modules remain outside the reach of
        any check that reads this repository; see the class docstring.

        The tests' own scratch root is excluded, and it is the one exclusion that
        is about correctness rather than speed. ``rglob`` is materialised in full
        before the first ``read_text``, so the window between enumerating a path
        and reading it is the whole duration of the sweep. The ``ash_temp_path``
        fixture creates ``tests/pytest-temp/<uuid>/`` and ``shutil.rmtree``s it on
        teardown, so under ``-n auto`` another worker's teardown deletes a file
        this walk has already listed and ``read_text`` raises
        ``FileNotFoundError``. Measured once on ``macos-latest`` py3.12, on
        ``tests/pytest-temp/<uuid>/source/test.py``.

        Excluded by path containment against the constant the fixture itself
        uses, so the two cannot drift; a second literal ``"pytest-temp"`` in
        ``_SKIP_DIRS`` would be free to.

        Deliberately *not* fixed by catching ``FileNotFoundError`` around the
        read. That would convert "a file vanished" into "no match found", which
        is precisely the blindness-reads-as-cleanliness failure this class exists
        to rule out -- see ``test_the_sweep_is_not_blind``.

        The other in-tree gitignored paths were checked and are not exposed:
        every ``output/``, ``ash_output`` and ``.ash/`` directory the tests build
        lives under ``tmp_path`` or ``tempfile.mkdtemp()``, both outside the
        repository, and the generated files inside the package
        (``assets/tool_downloads.py``, ``assets/exceptions.py``) are stable for a
        run's whole duration, so they cannot race a reader. ``tests/pytest-temp``
        is the only in-tree directory with a concurrent create-and-delete
        lifecycle.
        """
        root = Path(__file__).resolve().parents[3]
        this_file = Path(__file__).resolve()
        # iter_repo_files rather than root.rglob("*.py"). The exclusion below was
        # added first and is not sufficient on its own: rglob raises from inside
        # its own descent, before it yields, when another worker's ash_temp_path
        # teardown removes a directory rglob has already listed. That is a
        # separate race from the read-after-enumerate one, it survived the first
        # fix, and it failed on macos-14 py3.11 three hours later. Pruning during
        # the walk is what actually removes it.
        for path in sorted(iter_repo_files(root, skip_dirs=cls._SKIP_DIRS)):
            if path.suffix != ".py":
                continue
            if path == this_file:
                continue
            parts = set(path.relative_to(root).parts)
            if any(part.startswith(".") for part in parts):
                continue
            if parts & cls._SKIP_DIRS:
                continue
            yield path

    @classmethod
    def _shown_name(cls, path: Path) -> str:
        """The one spelling a file is reported by: its repo-relative POSIX path
        inside the repository, its resolved POSIX path outside. as_posix both
        ways, so the spelling carries no backslashes for a repr to double on
        Windows. _hits' relative_names keys, the helper enforcement, the
        completeness check and both planted controls all read this one rule,
        so a --basetemp inside the checkout changes every reader together."""
        resolved = path.resolve()
        repo_root = Path(__file__).resolve().parents[3]
        if resolved.is_relative_to(repo_root):
            return resolved.relative_to(repo_root).as_posix()
        return resolved.as_posix()

    @classmethod
    def _hits(cls, patterns, *, skip_files=(), relative_names=False) -> Dict[str, str]:
        """With ``relative_names``, hits are keyed by ``_shown_name`` (the
        repo-relative path, a file outside the repo by its resolved POSIX
        path), so two files sharing a basename stay two entries."""
        found: Dict[str, str] = {}
        skipped = set(skip_files)
        repo_root = Path(__file__).resolve().parents[3]
        for path in cls._source_files():
            # A bare name skips that file anywhere; a path with a "/" skips only the
            # file at that repo-relative path (for a name as common as conftest.py).
            resolved = path.resolve()
            relative = (
                resolved.relative_to(repo_root).as_posix()
                if resolved.is_relative_to(repo_root)
                else None
            )
            if path.name in skipped or relative in skipped:
                continue
            shown = path.name
            if relative_names:
                shown = cls._shown_name(path)
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if any(pattern in stripped for pattern in patterns):
                    found[f"{shown}:{number}"] = stripped
        return found

    def test_the_sweep_looks_at_more_than_the_package(self):
        """Guards the widening itself.

        The previous version walked only ``automated_security_helper/``. If this
        collapses back to that, the sweep silently stops covering scripts and
        tests, and nothing else would notice.
        """
        walked = {
            path.resolve().parts[-2]
            for path in self._source_files()
            if len(path.resolve().parts) > 1
        }
        assert walked, "the sweep found no source files at all"
        top_level = {
            path.resolve().relative_to(Path(__file__).resolve().parents[3]).parts[0]
            for path in self._source_files()
        }
        assert "automated_security_helper" in top_level
        assert "tests" in top_level, sorted(top_level)

    def test_the_sweep_is_not_blind(self):
        """The companion assertion: an empty result must mean absence, not blindness.

        Without this, a sweep that matched nothing -- because a pattern was
        misspelled, or the walk yielded no files, or a skip rule swallowed the
        tree -- would read exactly like a clean repository. That is the shape of
        every false pass found in this phase, so the matcher is checked from both
        sides: something that is present must be found, and something that is
        absent must not be.
        """
        present = self._hits(("ash_plugin_manager.set_context",))
        assert present, (
            "the sweep cannot find ash_plugin_manager.set_context, which "
            "execution_engine.py calls, so its walk or its matcher is broken and "
            "every clean result in this class is meaningless"
        )
        absent = self._hits(("ash_plugin_manager.no_such_attribute_exists",))
        assert absent == {}, absent

    def test_prose_about_the_hazard_is_not_counted_as_the_hazard(self):
        """``resolver.py`` and ``execution.py`` explain the defect at length.

        Both docstrings name ``plugin_library`` and ``_resolved_plugins``. If the
        sweep matched the bare names it would flag that prose, and the cheapest
        way to get green would be to delete the explanation -- the wrong direction
        entirely. The patterns require the qualified attribute spelling, so the
        prose is invisible to them; asserted rather than assumed, because the
        temptation to loosen a pattern to "catch more" arrives later.
        """
        assert self._hits(("plugin_library",)), (
            "the bare name does not appear anywhere, so this test is checking "
            "nothing about how the sweep treats prose"
        )
        assert self._hits(("ash_plugin_manager._resolved_plugins",)) == {}

    def test_nothing_reads_the_singleton_context(self):
        readers = self._hits(self._CONTEXT_PATTERNS)
        assert readers == {}, (
            "ash_plugin_manager.context is now touched outside set_context. It is "
            "a module-level singleton overwritten by every ScanExecutionEngine, "
            "so under parallel workspace projects the reader sees an arbitrary "
            "project's context. Give it thread-local storage, or pass the context "
            "explicitly, before relying on it: " + repr(readers)
        )

    def test_nothing_outside_the_manager_touches_the_registry(self):
        """``plugin_library`` and ``_resolved_plugins`` stay the manager's own.

        Every access in ``automated_security_helper/`` is ``self.``-qualified
        inside ``plugin_manager.py``. A module reaching in from outside is the
        shape that reintroduces the registry defect, so it has to be a deliberate
        decision rather than a drive-by.

        Six files are allowed in; the widened walk surfaced the first two:

        * ``plugin_manager.py`` owns the attributes.
        * ``tests/unit/plugins/test_plugin_system.py`` is the test *of* the plugin
          system, and clears ``plugin_library.event_handlers`` between cases.
          There is no manager API for "forget every handler", and a test resetting
          process-global state is the opposite of the hazard here -- it prevents
          leakage between cases rather than causing it between projects. It also
          holds ``registry_changes_left_behind``, the check
          ``test_plugin_system_leaves_the_registry.py`` runs after this file in a
          pytest process of its own.
        * ``tests/snapshot/conftest.py`` (by path, not by name) narrows the
          registry to ASH's built-in plugins for each snapshot test and puts it
          back afterwards, so a snapshot shows what a fresh ``ash`` process
          registers rather than whatever earlier tests in the worker imported.
          Same category as the one above: it stops leakage between tests.
        * ``tests/snapshot/test_snapshot_plugin_registry.py`` is the test of that
          conftest code: it reads the registry to prove a plugin first imported
          inside a snapshot test is merged back afterwards, and that a module an
          earlier test imported has its real registrations put back when a
          snapshot test's run loads it, and removes the probe plugins it
          registered. It also holds ``registry_state`` and
          ``registry_changes_since``, the record and the check
          ``test_snapshot_plugin_registry_leaves_the_registry.py`` takes around
          this file in a pytest process of its own - and that companion also
          calls both directly from its own in-process tests, which read and
          change the live registry and restore it only through ``finally`` and
          ``monkeypatch``.
        * ``tests/conftest.py`` (by path) restores the resolved-plugin memo, the
          event handlers and the registrations after every test, so a plugin one
          test registers by hand does not reach the next. Same category: it stops
          leakage between tests.
        * ``tests/unit/test_conftest_tool_state_isolation.py`` is the test of that
          conftest code, and removes the probe plugin it registers.
        * ``tests/unit/cli/test_report_refuses_invalid_plugin_options.py`` gives
          each of its tests an empty ``_resolved_plugins`` and puts the previous
          one back afterwards. An earlier ``ash report`` in the worker had
          memoised the reporters before ``ash_aws_plugins`` registered, so the
          module failed in some orders. Same category: it stops leakage between
          tests, and it leaves ``plugin_library`` alone.
        * ``tests/unit/cli/test_operator_text_is_not_markup.py`` runs ash report,
          scan and merge in-process and gives each test its own copy of the
          registry and an empty lookup cache. ``plugin_modules()`` memoizes what it
          found per process, and without the copy a later test in the same worker
          (test_report_refuses_invalid_plugin_options.py, which loads the AWS
          reporters from its config) got the memoized list and not its reporter.
          It stops leakage between tests, like the snapshot conftest.

        The sweep matches writes by name (``setattr``, ``patch.object``) as well
        as reads; matching reads alone leaves the snapshot conftest's ``setattr``
        unmatched.

        Anything else, in production or in a new test, fails this and has to
        justify itself.
        """
        offenders = self._hits(
            self._REGISTRY_PATTERNS,
            skip_files=self._REGISTRY_SWEEP_ALLOWED,
        )
        assert offenders == {}, (
            "the plugin manager's registry state is now reached from outside the "
            "class that owns it. Both attributes are process-global, and the "
            "first workspace project to touch them decides the scanner set for "
            "every project -- a silent false negative on a security scanner. "
            "Route this through the manager's own API, and read "
            "test_plugin_registry_scoping.py first: " + repr(offenders)
        )

    def test_the_temp_root_exclusion_is_the_one_the_fixture_writes_to(self):
        """The exclusion and the thing excluded must come from one constant.

        A literal ``"pytest-temp"`` here would be free to drift from
        ``tests/utils/helpers.py``, and the drift would be invisible: the sweep
        would simply go back to reading other workers' scratch trees and start
        raising ``FileNotFoundError`` again, intermittently, on one leg.
        """
        from tests.utils.helpers import get_ash_temp_path

        created = get_ash_temp_path()
        try:
            assert created.parent == ASH_TEST_TEMP_ROOT, (
                f"the fixture writes to {created.parent} but the sweep excludes "
                f"{ASH_TEST_TEMP_ROOT}; the exclusion no longer covers the race"
            )
            assert ASH_TEST_TEMP_ROOT.resolve().is_relative_to(
                Path(__file__).resolve().parents[3]
            ), "the temp root is outside the repository, so nothing would sweep it"
        finally:
            created.rmdir()

    def test_a_file_under_the_temp_root_is_invisible_to_the_sweep(self):
        """The fix, demonstrated: a planted match under the scratch root is not read.

        Plants a pattern that the matcher provably *does* find elsewhere, so a
        pass here means the file was excluded rather than the pattern being
        unmatchable. Without that pairing this test would pass against a matcher
        that finds nothing at all.
        """
        from tests.utils.helpers import get_ash_temp_path

        pattern = "ash_plugin_manager.set_context"
        scratch = get_ash_temp_path()
        planted = scratch / "leaky_scratch_module.py"
        planted.write_text(f"{pattern}(None)\n", encoding="utf-8")
        try:
            # The control: this pattern is findable, so an empty result below is
            # the exclusion working and not a broken matcher.
            assert self._hits((pattern,)), (
                "the matcher cannot find this pattern anywhere in the repository, "
                "so it cannot demonstrate that the planted copy was excluded"
            )
            assert planted.read_text(encoding="utf-8").strip() == f"{pattern}(None)"

            hits = self._hits((pattern,))
            assert planted.name not in {location.split(":")[0] for location in hits}, (
                f"the sweep read a file under {ASH_TEST_TEMP_ROOT}: {sorted(hits)}"
            )
        finally:
            planted.unlink()
            scratch.rmdir()

    def test_the_exclusion_removes_nothing_but_the_temp_root(self):
        """Narrowness, asserted as a set difference rather than assumed.

        An exclusion that quietly dropped real source would make every clean
        result in this class meaningless, and it would look identical to a clean
        repository. So the swept set is compared against the same walk with the
        exclusion removed: the only permitted difference is files under the
        scratch root.
        """
        root = Path(__file__).resolve().parents[3]
        this_file = Path(__file__).resolve()
        temp_root = ASH_TEST_TEMP_ROOT.resolve()

        def walk_without_the_temp_exclusion():
            # prune_scratch=False: this control has to see the scratch tree, or the
            # set difference below is empty for the wrong reason. It tolerates a
            # vanished directory rather than raising, which is correct only here.
            for path in sorted(
                iter_repo_files(root, skip_dirs=self._SKIP_DIRS, prune_scratch=False)
            ):
                if path.suffix != ".py":
                    continue
                if path == this_file:
                    continue
                parts = set(path.relative_to(root).parts)
                if any(part.startswith(".") for part in parts):
                    continue
                if parts & self._SKIP_DIRS:
                    continue
                yield path

        from tests.utils.helpers import get_ash_temp_path

        scratch = get_ash_temp_path()
        planted = scratch / "excluded_probe.py"
        planted.write_text("x = 1\n", encoding="utf-8")
        try:
            swept = set(self._source_files())
            unfiltered = set(walk_without_the_temp_exclusion())
            removed = unfiltered - swept

            assert planted.resolve() in {p.resolve() for p in removed}, (
                "the planted scratch file was not excluded, so this test is not "
                "measuring the exclusion at all"
            )
            outside_temp_root = {
                path for path in removed if not path.resolve().is_relative_to(temp_root)
            }
            assert outside_temp_root == set(), (
                "the exclusion dropped files outside the tests' scratch root, so "
                f"the sweep is now blind to real source: {sorted(outside_temp_root)}"
            )
            assert swept, "the sweep found no source files at all"
        finally:
            planted.unlink()
            scratch.rmdir()

    def test_the_registry_sweep_would_catch_a_new_offender(self):
        """The companion assertion: prove the allowlist is narrow, not the matcher.

        ``test_nothing_outside_the_manager_touches_the_registry`` passes partly
        because six files are excluded. If the matcher were broken it would pass
        for the wrong reason and look identical. So assert that the same patterns
        do find the accesses in the excluded files -- an empty result there would
        mean the sweep is blind rather than the tree clean.
        """
        without_allowlist = self._hits(self._REGISTRY_PATTERNS)
        assert without_allowlist, (
            "the registry patterns match nothing anywhere, including in the files "
            "allowed in, which are known to contain such accesses, so the sweep is "
            "blind and the clean result next door is meaningless"
        )
        assert any(
            location.startswith("test_plugin_system.py")
            for location in without_allowlist
        ), sorted(without_allowlist)

    #: Registry helpers an allowed file keeps, each with the files that may
    #: name it. This comment is the one home of the reasoning; the tests and
    #: controls below point here instead of restating it.
    #:
    #: Why a table: an allowed file may keep a module-level helper that
    #: reaches the registry, and a caller anywhere else then reaches it
    #: through the helper with no registry spelling on the caller's own line,
    #: where the pattern sweep cannot see it. Two tests enforce the two
    #: directions:
    #:
    #: * the name sweep (test_a_registry_helper_is_named_only_in_its_files):
    #:   the set of files naming each key equals exactly its listed files, so
    #:   a borrower anywhere in the repository is caught by the helper's name
    #:   alone, whatever basename its file carries;
    #: * the derivation (test_every_registry_reaching_helper_is_in_the_table):
    #:   the keys are derived from the allowed files, not hand-trusted. Every
    #:   module-level definition there - function, class, or assignment, also
    #:   under module-level control flow - whose own text (decorators
    #:   included; docstrings and comment lines excluded; string values that
    #:   are not docstrings included) spells a registry pattern or the name of
    #:   another definition already so flagged, iterated to a fixed point that
    #:   STARTS EMPTY (never from these keys, which would let hand-typed keys
    #:   justify each other), must be a key. The fixed point is what catches a
    #:   helper that reaches the registry only through another helper. Exempt:
    #:   test_* functions and Test* classes, which pytest collects and nothing
    #:   imports, and pytest fixtures, which pytest offers only inside their
    #:   own file - except fixtures in a conftest.py, offered to the whole
    #:   tree, which are exempt only when autouse (nothing requests an autouse
    #:   fixture by name). usefixtures marks a user, not a definition, and
    #:   exempts nothing.
    #:
    #: Two documented limits, each with a pin that turns red if it moves. The
    #: fixture exemption is import-blind: a fixture function imported by name
    #: into another module resolves there too, which the sweep does not see
    #: (pinned by test_a_file_bound_fixture_and_docstring_prose_are_not_
    #: derived). And both sweeps match names as written: a name aliased,
    #: joined from adjacent literals, assembled with ``+`` or an f-string,
    #: computed and looked up through ``globals()``, or spelled across lines
    #: is not matched - a hygiene check against accidental access, not a
    #: boundary (the name sweep's own docstring says the same; pinned by
    #: test_an_aliased_assembled_or_line_split_reach_is_not_derived).
    #:
    #: The entries, every one of which the derivation reaches (the test
    #: asserts both directions, so a hand-typed key that enforces nothing
    #: cannot sit here). _handler_modules and _loaded_inside are private to
    #: their file; registry_changes_since reaches the registry only THROUGH
    #: registry_state, the shape the fixed point exists for.
    #: _registration_state (the same file) is deliberately NOT here: it
    #: formats a registration its caller already holds, so a borrower gets a
    #: formatter and no registry, and its only registry mentions are docstring
    #: prose. The readers (registry_state,
    #: registry_changes_since, registry_changes_left_behind) serve the one
    #: test that runs their file in a pytest process of its own, AND the
    #: companion file's own in-process tests, which call them directly while
    #: changing the live registry. ``a_scanner_registration`` is a
    #: live-registration handle those in-process tests borrow and restore.
    #: ``builtin_plugin_registry`` (tests/snapshot/conftest.py, a context
    #: manager, not a fixture) swaps the whole registry for a copy.
    #: ``_LOADS_TRIVY`` is source text for a child test file: run, that text
    #: imports builtin_plugin_registry, so a module borrowing the constant
    #: hands its caller the registry the same way a helper would.
    #: ``_ProcessWideToolState`` (tests/conftest.py) snapshots and restores the
    #: plugin manager's registrations around a test, so it reaches the
    #: registry by design; its own isolation test is the other file naming it.
    _REGISTRY_HELPERS = {
        "_LOADS_TRIVY": ("tests/snapshot/test_snapshot_plugin_registry.py",),
        "_ProcessWideToolState": (
            "tests/conftest.py",
            "tests/unit/test_conftest_tool_state_isolation.py",
        ),
        "_handler_modules": ("tests/snapshot/test_snapshot_plugin_registry.py",),
        "_loaded_inside": ("tests/snapshot/test_snapshot_plugin_registry.py",),
        "a_scanner_registration": (
            "tests/snapshot/test_snapshot_plugin_registry.py",
            "tests/snapshot/test_snapshot_plugin_registry_leaves_the_registry.py",
        ),
        "builtin_plugin_registry": (
            "tests/snapshot/conftest.py",
            "tests/snapshot/test_snapshot_plugin_registry.py",
        ),
        "registry_changes_left_behind": (
            "tests/unit/plugins/test_plugin_system.py",
            "tests/unit/plugins/test_plugin_system_leaves_the_registry.py",
        ),
        "registry_state": (
            "tests/snapshot/test_snapshot_plugin_registry.py",
            "tests/snapshot/test_snapshot_plugin_registry_leaves_the_registry.py",
        ),
        "registry_changes_since": (
            "tests/snapshot/test_snapshot_plugin_registry.py",
            "tests/snapshot/test_snapshot_plugin_registry_leaves_the_registry.py",
        ),
    }

    def test_a_registry_helper_is_named_only_in_its_files(self):
        """Each _REGISTRY_HELPERS key may be named only in its listed files;
        the reasoning is at the table's comment. A caller anywhere else
        reaches the registry through a helper with no registry spelling on
        its own line, so the helper's name is what this sweep matches. It
        matches names as written: a hygiene check against accidental live
        registry access from tests, not a boundary against a name assembled
        at run time."""
        self._assert_each_helper_named_only_in_its_files()

    def _assert_each_helper_named_only_in_its_files(self) -> Dict[str, Dict[str, int]]:
        """The one enforcement the check and the planted controls share: the
        set of files naming each _REGISTRY_HELPERS key equals exactly its
        listed files (why: the table's comment), compared by _shown_name.
        Returns ``{helper: {shown name: first line naming it}}``, so a control
        asserts what was and was not found rather than only that nothing
        raised. Names match as whole words, so an identifier that merely
        starts or ends with a helper's name is not read as the helper, and
        one pass over the tree records every helper's hits. Extra files and
        missing files are reported apart - a symmetric difference cannot say
        which side a path is wrong on - extras with the first line that names
        the helper. The failure message is a plain string, which pytest
        passes through whole: a repr'd message is truncated and doubles a
        Windows path's backslashes. The controls call this same method, so
        gutting the assertion fails them rather than leaving a mirror of the
        data to agree with itself."""
        matchers = {
            name: re.compile(rf"(?<!\w){re.escape(name)}(?!\w)")
            for name in self._REGISTRY_HELPERS
        }
        naming: Dict[str, Dict[str, int]] = {name: {} for name in matchers}
        for path in self._source_files():
            shown = self._shown_name(path)
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                for name, matcher in matchers.items():
                    if matcher.search(stripped):
                        naming[name].setdefault(shown, number)
        problems = []
        for name, allowed in self._REGISTRY_HELPERS.items():
            extra = set(naming[name]) - set(allowed)
            missing = set(allowed) - set(naming[name])
            if extra:
                problems.append(
                    f"{name} is named beyond its files: "
                    + ", ".join(
                        f"{shown}:{naming[name][shown]}" for shown in sorted(extra)
                    )
                )
            if missing:
                problems.append(
                    f"{name} is not named in: " + ", ".join(sorted(missing))
                )
        assert not problems, "\n".join(problems)
        return naming

    def test_a_live_registration_borrowed_elsewhere_is_caught(
        self, tmp_path, monkeypatch
    ):
        """The must-fire for the name sweep (reasoning: the table's comment):
        a borrower with no registry spelling on any line is flagged by the
        helper's name. Planted through the walk of this process only, so no
        other worker's sweep sees it. The planted file carries the same
        basename as a file the table allows, so an enforcement comparing
        basenames instead of paths would read it as the allowed file and go
        quiet; the path comparison is what flags it."""
        planted = tmp_path / "test_snapshot_plugin_registry.py"
        planted.write_text(
            "from tests.snapshot.test_snapshot_plugin_registry import (\n"
            "    a_scanner_registration,\n"
            ")\n"
            "\n"
            "name, registration = a_scanner_registration()\n"
            "registration.enabled = False\n",
            encoding="utf-8",
        )
        walked = list(type(self)._source_files())
        monkeypatch.setattr(
            type(self), "_source_files", classmethod(lambda cls: [*walked, planted])
        )

        # The enforcement the check runs must itself flag the planted file, so
        # the control goes red when the enforcement's assertion is gone. The
        # expected spelling comes from _shown_name, the same rule the
        # enforcement keys by (POSIX both ways, so no backslash a repr could
        # double on Windows; the plain-string message is never truncated), and
        # a --basetemp inside the checkout moves both sides together.
        with pytest.raises(AssertionError) as flagged:
            self._assert_each_helper_named_only_in_its_files()
        assert self._shown_name(planted) in str(flagged.value), flagged.value

        # The control: the registry spellings themselves do not find it. Keyed
        # by _shown_name, since the planted file shares the allowed basename.
        assert self._shown_name(planted) not in {
            location.rsplit(":", 1)[0]
            for location in self._hits(self._REGISTRY_PATTERNS, relative_names=True)
        }

    def test_a_name_sharing_a_suffix_is_not_a_borrower(self, tmp_path, monkeypatch):
        """Substring matching would read ``lambda_scanner_registration`` as
        ``a_scanner_registration`` and fail an innocent file with a message
        that names no false positive; the sweep matches each helper as a whole
        word. Asserted on the returned naming map, not only on the absence of
        a failure, so a sweep that found nothing at all could not pass."""
        planted = tmp_path / "test_lambda_registrations.py"
        planted.write_text("lambda_scanner_registration = object()\n", encoding="utf-8")
        walked = list(type(self)._source_files())
        monkeypatch.setattr(
            type(self), "_source_files", classmethod(lambda cls: [*walked, planted])
        )

        naming = self._assert_each_helper_named_only_in_its_files()

        shown = self._shown_name(planted)
        assert all(shown not in named for named in naming.values()), naming
        assert naming["a_scanner_registration"], (
            "the sweep found no real naming at all, so it proved nothing"
        )

    def test_a_name_sharing_a_prefix_is_not_a_borrower(self, tmp_path, monkeypatch):
        """The other side of the whole-word rule: an identifier that merely
        starts with a helper's name (``registry_state_snapshot``) is not the
        helper either."""
        planted = tmp_path / "test_prefixed_names.py"
        planted.write_text("registry_state_snapshot = object()\n", encoding="utf-8")
        walked = list(type(self)._source_files())
        monkeypatch.setattr(
            type(self), "_source_files", classmethod(lambda cls: [*walked, planted])
        )

        naming = self._assert_each_helper_named_only_in_its_files()

        shown = self._shown_name(planted)
        assert all(shown not in named for named in naming.values()), naming
        assert naming["registry_state"], (
            "the sweep found no real naming at all, so it proved nothing"
        )

    @staticmethod
    def _pytest_fixture_decorator(node):
        """node's pytest.fixture decorator, or None. Read from the decorator's
        own shape, never a substring: ``usefixtures`` marks a user of a
        fixture, not a definition, and must exempt nothing."""
        for decorator in node.decorator_list:
            target = decorator.func if isinstance(decorator, ast.Call) else decorator
            if isinstance(target, ast.Attribute):
                name = target.attr
            elif isinstance(target, ast.Name):
                name = target.id
            else:
                continue
            if name == "fixture":
                return decorator
        return None

    @staticmethod
    def _is_autouse(decorator) -> bool:
        return isinstance(decorator, ast.Call) and any(
            keyword.arg == "autouse" and getattr(keyword.value, "value", None) is True
            for keyword in decorator.keywords
        )

    @staticmethod
    def _searchable_text(source_lines, node) -> str:
        """The definition's own lines with every docstring and comment line
        removed: prose about a helper is not a reach for it (the principle
        test_prose_about_the_hazard_is_not_counted_as_the_hazard pins), while
        a string value that is not a docstring - source text for a child test
        file - still is."""
        skipped = set()
        for inner in ast.walk(node):
            if isinstance(inner, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                first = inner.body[0] if inner.body else None
                if (
                    isinstance(first, ast.Expr)
                    and isinstance(first.value, ast.Constant)
                    and isinstance(first.value.value, str)
                ):
                    skipped.update(range(first.lineno, first.end_lineno + 1))
        # From the first decorator, not the def line: a reach that lives only
        # in a decorator (a patch of a registry attribute) is a reach.
        start = node.lineno
        for decorator in getattr(node, "decorator_list", []):
            start = min(start, decorator.lineno)
        kept = []
        for number in range(start, node.end_lineno + 1):
            if number in skipped:
                continue
            line = source_lines[number - 1].strip()
            if line.startswith("#"):
                continue
            kept.append(line)
        return "\n".join(kept)

    @staticmethod
    def _module_level_nodes(tree):
        """The module-level statements of *tree*, looked for inside module-level
        control flow too (if/try/for/while/with/match): a definition there
        binds a module name just the same, so one holding a registry reach
        cannot hide behind a version check, an import guard or a case arm.
        Function and class bodies are not entered; their inner names are not
        module-level."""
        flow = (ast.If, ast.Try, ast.For, ast.While, ast.With)
        try_star = getattr(ast, "TryStar", None)
        if try_star is not None:
            flow = (*flow, try_star)
        pending = list(tree.body)
        while pending:
            node = pending.pop(0)
            if isinstance(node, ast.Match):
                for case in node.cases:
                    pending.extend(case.body)
                continue
            if isinstance(node, flow):
                for field in ("body", "orelse", "finalbody"):
                    pending.extend(getattr(node, field, None) or [])
                for handler in getattr(node, "handlers", None) or []:
                    pending.extend(handler.body)
                continue
            yield node

    @classmethod
    def _registry_reaching_definitions(cls, files) -> Dict[str, List[str]]:
        """``{name: files (by _shown_name) defining it}`` for every module-level
        definition in *files* that reaches the registry. The rules and the
        exemptions are at the _REGISTRY_HELPERS comment: functions, classes
        and assignments; a definition reaches by spelling a registry pattern,
        or the name of another definition already flagged, to a fixed point
        rooted at the patterns alone - never seeded from the table, so a
        hand-typed key cannot justify itself."""
        definitions = []
        for path in files:
            shown = cls._shown_name(path)
            source = path.read_text(encoding="utf-8")
            source_lines = source.splitlines()
            in_conftest = path.name == "conftest.py"
            for node in cls._module_level_nodes(ast.parse(source)):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if node.name.startswith("test_"):
                        continue
                    fixture = cls._pytest_fixture_decorator(node)
                    if fixture is not None and (
                        not in_conftest or cls._is_autouse(fixture)
                    ):
                        continue
                    names = [node.name]
                elif isinstance(node, ast.ClassDef):
                    if node.name.startswith("Test"):
                        continue
                    names = [node.name]
                elif isinstance(node, ast.Assign):
                    names = [
                        target.id
                        for target in node.targets
                        if isinstance(target, ast.Name)
                    ]
                elif isinstance(node, ast.AnnAssign):
                    names = (
                        [node.target.id] if isinstance(node.target, ast.Name) else []
                    )
                else:
                    continue
                if not names:
                    continue
                text = cls._searchable_text(source_lines, node)
                for name in names:
                    definitions.append((name, shown, text))
        reached: Dict[str, List[str]] = {}
        # The fixed point starts EMPTY, never from the table's own keys: seeded
        # with them, two hand-typed keys that reach nothing but name each other
        # would read as derived, and the both-directions check below would
        # enforce nothing for them. Every chain roots at a registry pattern.
        reach_names: set = set()
        while True:
            grew = False
            matchers = {
                name: re.compile(rf"(?<!\w){re.escape(name)}(?!\w)")
                for name in reach_names
            }
            for name, shown, text in definitions:
                if shown in reached.get(name, ()):
                    continue
                direct = any(pattern in text for pattern in cls._REGISTRY_PATTERNS)
                through = any(
                    other != name and matcher.search(text)
                    for other, matcher in matchers.items()
                )
                if direct or through:
                    reached.setdefault(name, []).append(shown)
                    if name not in reach_names:
                        reach_names.add(name)
                        grew = True
            if not grew:
                return reached

    @classmethod
    def _allowed_sweep_files(cls):
        """The file behind each _REGISTRY_SWEEP_ALLOWED test entry, matched
        exactly once per entry and in both directions: a count comparison
        reads one entry matched twice and another not at all as complete, and
        the no-match it hides is a file the table reasons about going unswept.
        plugin_manager.py is the registry's production owner, not a borrowable
        test helper, and is not scanned here."""
        allowed = tuple(
            entry
            for entry in cls._REGISTRY_SWEEP_ALLOWED
            if entry != "automated_security_helper/plugins/plugin_manager.py"
        )
        matches = {entry: [] for entry in allowed}
        for path in cls._source_files():
            for entry in allowed:
                if ("/" in entry and cls._shown_name(path) == entry) or (
                    "/" not in entry and path.name == entry
                ):
                    matches[entry].append(path)
        wrong = {
            entry: sorted(cls._shown_name(path) for path in found)
            for entry, found in matches.items()
            if len(found) != 1
        }
        assert wrong == {}, (
            "each allowed entry must match exactly one swept file: " + repr(wrong)
        )
        return [found[0] for found in matches.values()]

    def _assert_every_reaching_definition_is_in_the_table(self, files):
        """The one enforcement the completeness test and its controls share:
        the derivation over *files* equals the table in both directions. The
        controls call this same method, so gutting either assertion fails
        them rather than leaving the test to agree with itself."""
        reached = self._registry_reaching_definitions(files)
        unlisted = {
            name: files_naming
            for name, files_naming in reached.items()
            if name not in self._REGISTRY_HELPERS
        }
        assert unlisted == {}, (
            "definitions reaching the registry but not in _REGISTRY_HELPERS: "
            + repr(unlisted)
        )
        # Both directions: a table key the derivation does not reach is a
        # hand-typed entry that enforces nothing, and deleting a derived key
        # turns the assertion above red instead of nothing.
        underived = sorted(set(self._REGISTRY_HELPERS) - set(reached))
        assert underived == [], (
            "table keys the derivation does not reach: " + ", ".join(underived)
        )
        return reached

    def test_every_registry_reaching_helper_is_in_the_table(self):
        """The table is derived, not hand-trusted; the rules are at the
        _REGISTRY_HELPERS comment. Every reaching definition in an allowed
        file either joins the table (and the name sweep above) or loses the
        access, so the next a_scanner_registration - and the next wrapper
        around one - is caught at the commit that writes it."""
        self._assert_every_reaching_definition_is_in_the_table(
            self._allowed_sweep_files()
        )

    def test_an_unlisted_reaching_definition_fails_the_table_check(self, tmp_path):
        """The must-fire for the check's unlisted side: a reaching definition
        the table does not key fails the shared enforcement by name."""
        planted = tmp_path / "handout.py"
        planted.write_text(
            "from automated_security_helper.plugins import ash_plugin_manager\n"
            "\n"
            "\n"
            "def hands_out():\n"
            "    return ash_plugin_manager.plugin_library\n",
            encoding="utf-8",
        )

        with pytest.raises(AssertionError) as flagged:
            self._assert_every_reaching_definition_is_in_the_table(
                [*self._allowed_sweep_files(), planted]
            )

        assert "hands_out" in str(flagged.value), flagged.value

    def test_an_underived_table_key_fails_the_table_check(self, monkeypatch):
        """The must-fire for the check's underived side: a key the derivation
        does not reach fails the shared enforcement by name."""
        with_fake = dict(self._REGISTRY_HELPERS)
        with_fake["a_key_nothing_derives"] = ("tests/snapshot/conftest.py",)
        monkeypatch.setattr(type(self), "_REGISTRY_HELPERS", with_fake)

        with pytest.raises(AssertionError) as flagged:
            self._assert_every_reaching_definition_is_in_the_table(
                self._allowed_sweep_files()
            )

        assert "a_key_nothing_derives" in str(flagged.value), flagged.value

    def test_hand_typed_keys_cannot_justify_each_other(self, tmp_path, monkeypatch):
        """The fixed point starts empty, never from the table's own keys:
        seeded with them, two hand-typed keys that reach nothing but name each
        other would read as derived, and the both-directions check would
        enforce nothing for them."""
        planted = tmp_path / "mutual.py"
        planted.write_text(
            "def first_of_a_pair():\n"
            "    return second_of_a_pair()\n"
            "\n"
            "\n"
            "def second_of_a_pair():\n"
            "    return first_of_a_pair()\n",
            encoding="utf-8",
        )
        shown = self._shown_name(planted)
        with_pair = dict(self._REGISTRY_HELPERS)
        with_pair["first_of_a_pair"] = (shown,)
        with_pair["second_of_a_pair"] = (shown,)
        monkeypatch.setattr(type(self), "_REGISTRY_HELPERS", with_pair)

        with pytest.raises(AssertionError) as flagged:
            self._assert_every_reaching_definition_is_in_the_table(
                [*self._allowed_sweep_files(), planted]
            )

        message = str(flagged.value)
        assert "first_of_a_pair" in message, message
        assert "second_of_a_pair" in message, message

    def test_a_wrapper_reaching_the_registry_through_a_helper_is_derived(
        self, tmp_path
    ):
        """The fixed point's must-fire: a helper whose body spells no registry
        pattern and only calls a reaching helper is a reach, and so is a
        wrapper around that wrapper. The chain roots at a pattern in the same
        scan, as every real chain roots at one in the allowed files."""
        planted = tmp_path / "helpers.py"
        planted.write_text(
            "from automated_security_helper.plugins import ash_plugin_manager\n"
            "\n"
            "\n"
            "def reaches_directly():\n"
            "    return ash_plugin_manager.plugin_library\n"
            "\n"
            "\n"
            "def borrows():\n"
            "    return reaches_directly()\n"
            "\n"
            "\n"
            "def wraps_the_borrower():\n"
            "    return borrows()\n",
            encoding="utf-8",
        )

        reached = self._registry_reaching_definitions([planted])

        assert set(reached) >= {
            "reaches_directly",
            "borrows",
            "wraps_the_borrower",
        }, reached

    def test_a_name_sharing_a_prefix_is_not_derived_through(self, tmp_path):
        """The derivation matches a flagged name as a whole word, like the
        name sweep: an identifier that merely starts with one is not a reach,
        and neither is a definition that only names that identifier."""
        planted = tmp_path / "prefixes.py"
        planted.write_text(
            "from automated_security_helper.plugins import ash_plugin_manager\n"
            "\n"
            "anchor_point = object()\n"
            "\n"
            "\n"
            "def anchor():\n"
            "    return ash_plugin_manager.plugin_library\n"
            "\n"
            "\n"
            "def innocent():\n"
            "    return anchor_point\n",
            encoding="utf-8",
        )

        reached = self._registry_reaching_definitions([planted])

        assert "anchor" in reached, reached
        assert "innocent" not in reached, reached
        assert "anchor_point" not in reached, reached

    def test_a_reach_only_in_a_decorator_is_derived(self, tmp_path):
        """A patch of a registry attribute written as a decorator reaches the
        registry for whoever calls the decorated helper; the definition's text
        starts at its first decorator, not at the def line."""
        planted = tmp_path / "decorated.py"
        planted.write_text(
            "from unittest.mock import patch\n"
            "\n"
            "from automated_security_helper.plugins import ash_plugin_manager\n"
            "\n"
            "\n"
            '@patch.object(ash_plugin_manager, "_resolved_plugins", new=None)\n'
            "def swaps_the_cache():\n"
            "    return None\n",
            encoding="utf-8",
        )

        reached = self._registry_reaching_definitions([planted])

        assert "swaps_the_cache" in reached, reached

    def test_a_definition_inside_module_level_control_flow_is_derived(self, tmp_path):
        """A definition under a module-level if or try binds a module name just
        the same, so a reach there cannot hide behind a version check or an
        import guard."""
        planted = tmp_path / "guarded.py"
        planted.write_text(
            "from automated_security_helper.plugins import ash_plugin_manager\n"
            "\n"
            "if True:\n"
            "\n"
            "    def behind_an_if():\n"
            "        return ash_plugin_manager.plugin_library\n"
            "\n"
            "\n"
            "try:\n"
            "    behind_a_try = ash_plugin_manager.plugin_library\n"
            "except Exception:\n"
            "    behind_a_try = None\n",
            encoding="utf-8",
        )

        reached = self._registry_reaching_definitions([planted])

        assert "behind_an_if" in reached, reached
        assert "behind_a_try" in reached, reached

    def test_a_definition_inside_a_module_level_match_arm_is_derived(self, tmp_path):
        """A def under a module-level match/case binds a module name like one
        under an if, and ast.Match is not one of the body-carrying flow nodes
        the generic walk reads, so it needs its own arm in the walker."""
        planted = tmp_path / "matched.py"
        planted.write_text(
            "import sys\n"
            "from automated_security_helper.plugins import ash_plugin_manager\n"
            "\n"
            "match sys.platform:\n"
            "    case 'linux':\n"
            "\n"
            "        def behind_a_case():\n"
            "            return ash_plugin_manager.plugin_library\n"
            "\n"
            "    case _:\n"
            "\n"
            "        def behind_the_default_case():\n"
            "            return ash_plugin_manager.plugin_library\n",
            encoding="utf-8",
        )

        reached = self._registry_reaching_definitions([planted])

        assert "behind_a_case" in reached, reached
        assert "behind_the_default_case" in reached, reached

    @pytest.mark.skipif(
        sys.version_info < (3, 11), reason="the star form of except needs Python 3.11"
    )
    def test_a_definition_inside_an_except_star_handler_is_derived(self, tmp_path):
        """ast.TryStar carries its handlers like Try does, but it is its own
        node type: dropped from the walker's flow tuple, a def under
        ``except*`` would go unseen while every try/except cell stays green."""
        planted = tmp_path / "grouped.py"
        planted.write_text(
            "from automated_security_helper.plugins import ash_plugin_manager\n"
            "\n"
            "try:\n"
            "    pass\n"
            "except* ValueError:\n"
            "    def behind_an_except_star():\n"
            "        return ash_plugin_manager.plugin_library\n",
            encoding="utf-8",
        )

        reached = self._registry_reaching_definitions([planted])

        assert "behind_an_except_star" in reached, reached

    def test_every_flow_body_and_arm_is_walked(self, tmp_path):
        """One definition per flow construct and arm beyond if-body and
        try-body: for, while and with bodies, a for's else, a try's else, an
        except handler and a finally. A walker reading only If and Try bodies
        passes the existing cells; each name here pins one of the others."""
        planted = tmp_path / "flows.py"
        planted.write_text(
            "from automated_security_helper.plugins import ash_plugin_manager\n"
            "\n"
            "for _item in []:\n"
            "    def in_a_for():\n"
            "        return ash_plugin_manager.plugin_library\n"
            "else:\n"
            "    def in_a_for_else():\n"
            "        return ash_plugin_manager.plugin_library\n"
            "while False:\n"
            "    def in_a_while():\n"
            "        return ash_plugin_manager.plugin_library\n"
            "with open('/dev/null') as _handle:\n"
            "    def in_a_with():\n"
            "        return ash_plugin_manager.plugin_library\n"
            "try:\n"
            "    pass\n"
            "except Exception:\n"
            "    def in_an_except():\n"
            "        return ash_plugin_manager.plugin_library\n"
            "else:\n"
            "    def in_a_try_else():\n"
            "        return ash_plugin_manager.plugin_library\n"
            "finally:\n"
            "    def in_a_finally():\n"
            "        return ash_plugin_manager.plugin_library\n",
            encoding="utf-8",
        )

        reached = self._registry_reaching_definitions([planted])

        for name in (
            "in_a_for",
            "in_a_for_else",
            "in_a_while",
            "in_a_with",
            "in_an_except",
            "in_a_try_else",
            "in_a_finally",
        ):
            assert name in reached, (name, sorted(reached))

    def test_an_aliased_assembled_or_line_split_reach_is_not_derived(self, tmp_path):
        """The pin for the documented limit at _REGISTRY_HELPERS: both sweeps
        match names as written, so a reach through an import alias, a split
        or assembled registry spelling, or a name computed at run time is not
        matched. If any of them starts being derived, the limit comment above
        the table is stale and moves with this cell. The three attribute
        forms sit in a pattern shape on the real registry name, so a sweep
        that started joining adjacent literals would derive exactly the
        joined form, one joining ``+`` concatenations exactly the plus form,
        and the f-string form stays unseen either way. The ``globals()``
        lookup is the computed-name limit: no pattern has that shape, so it
        stays underived whatever the text sweep reads. The direct reach in
        the same file is the must-fire: a derivation gone blind reds here
        instead of passing vacuously."""
        planted = tmp_path / "unseen.py"
        planted.write_text(
            "from automated_security_helper.plugins import (\n"
            "    ash_plugin_manager as apm,\n"
            ")\n"
            "from automated_security_helper.plugins import ash_plugin_manager\n"
            "\n"
            "\n"
            "def reaches_directly():\n"
            "    return ash_plugin_manager.plugin_library\n"
            "\n"
            "\n"
            "def via_an_alias():\n"
            "    return apm.plugin_library\n"
            "\n"
            "\n"
            "def via_joined_attribute():\n"
            '    return getattr(ash_plugin_manager, "plugin" "_library")\n'
            "\n"
            "\n"
            "def via_plus_attribute():\n"
            '    return getattr(ash_plugin_manager, "plugin" + "_library")\n'
            "\n"
            "\n"
            "def via_fstring_attribute():\n"
            '    part = "library"\n'
            '    return getattr(ash_plugin_manager, f"plugin_{part}")\n'
            "\n"
            "\n"
            "def via_computed_name_lookup():\n"
            '    name = "ash_plugin" + "_manager"\n'
            '    return getattr(globals()[name], "plugin" + "_library")\n'
            "\n"
            "\n"
            "def via_a_line_split():\n"
            "    return (\n"
            "        ash_plugin_manager\n"
            "        .plugin_library\n"
            "    )\n",
            encoding="utf-8",
        )

        reached = self._registry_reaching_definitions([planted])

        assert "reaches_directly" in reached, reached
        assert "via_an_alias" not in reached, reached
        assert "via_joined_attribute" not in reached, reached
        assert "via_plus_attribute" not in reached, reached
        assert "via_fstring_attribute" not in reached, reached
        assert "via_computed_name_lookup" not in reached, reached
        assert "via_a_line_split" not in reached, reached

    def test_the_production_owner_is_named_by_its_full_path(self):
        """plugin_manager.py's allowlist entry spells the repo-relative path,
        so a same-named file elsewhere cannot take the production owner's
        exemption, and the entry names the file that exists there."""
        entry = "automated_security_helper/plugins/plugin_manager.py"
        assert entry in self._REGISTRY_SWEEP_ALLOWED
        assert "plugin_manager.py" not in self._REGISTRY_SWEEP_ALLOWED
        root = Path(__file__).resolve().parents[3]
        assert (root / entry).is_file()

    def test_a_module_level_binding_and_class_are_derived(self, tmp_path):
        """An assignment aliasing the registry and a class whose method reads
        it hand the registry out with no function definition to scan."""
        planted = tmp_path / "handout.py"
        planted.write_text(
            "from automated_security_helper.plugins import ash_plugin_manager\n"
            "\n"
            "shared_registry = ash_plugin_manager.plugin_library\n"
            "\n"
            "\n"
            "class Handout:\n"
            "    def registry(self):\n"
            "        return ash_plugin_manager.plugin_library\n",
            encoding="utf-8",
        )

        reached = self._registry_reaching_definitions([planted])

        assert set(reached) >= {"shared_registry", "Handout"}, reached

    def test_a_conftest_fixture_is_derived_unless_autouse(self, tmp_path):
        """A conftest fixture is requestable tree-wide, so one that reaches
        the registry is a borrowable helper unless it is autouse; and a
        usefixtures decorator marks a user, not a fixture definition, so it
        exempts nothing."""
        planted = tmp_path / "conftest.py"
        planted.write_text(
            "import pytest\n"
            "from automated_security_helper.plugins import ash_plugin_manager\n"
            "\n"
            "\n"
            "@pytest.fixture\n"
            "def requestable_registry():\n"
            "    return ash_plugin_manager.plugin_library\n"
            "\n"
            "\n"
            "@pytest.fixture(autouse=True)\n"
            "def _resets_quietly():\n"
            "    ash_plugin_manager.plugin_library\n"
            "\n"
            "\n"
            '@pytest.mark.usefixtures("requestable_registry")\n'
            "def decorated_helper():\n"
            "    return ash_plugin_manager.plugin_library\n",
            encoding="utf-8",
        )

        reached = self._registry_reaching_definitions([planted])

        assert "requestable_registry" in reached, reached
        assert "_resets_quietly" not in reached, reached
        assert "decorated_helper" in reached, reached

    def test_a_file_bound_fixture_and_docstring_prose_are_not_derived(self, tmp_path):
        """The exemptions' control, and the pin of a DOCUMENTED LIMIT: a
        fixture in a non-conftest file is exempt although pytest fixtures can
        be imported by name into another module and resolve there, so the
        exemption is import-blind (the table comment names this). This pin
        turns red if the exemption ever narrows, so the comment moves with the
        behavior. The docstring-prose half is the plain control: a definition
        whose only mention of the registry is its docstring documents the
        hazard rather than reaching it."""
        planted = tmp_path / "test_module.py"
        planted.write_text(
            "import pytest\n"
            "from automated_security_helper.plugins import ash_plugin_manager\n"
            "\n"
            "\n"
            "@pytest.fixture\n"
            "def own_registry():\n"
            "    return ash_plugin_manager.plugin_library\n"
            "\n"
            "\n"
            "def documents_only():\n"
            '    """Explains builtin_plugin_registry and\n'
            '    ash_plugin_manager.plugin_library at length."""\n'
            "    return None\n",
            encoding="utf-8",
        )

        reached = self._registry_reaching_definitions([planted])

        assert reached == {}, reached

    def test_a_double_match_cannot_hide_a_missing_allowed_file(
        self, tmp_path, monkeypatch
    ):
        """A count comparison (len(files) == len(allowed)) reads one entry
        matched twice and another matched not at all as complete. One match
        per entry, and both failures named."""
        extra = tmp_path / "test_plugin_system.py"
        extra.write_text("x = 1\n", encoding="utf-8")
        walked = [
            path
            for path in type(self)._source_files()
            if self._shown_name(path) != "tests/snapshot/conftest.py"
        ]
        monkeypatch.setattr(
            type(self), "_source_files", classmethod(lambda cls: [*walked, extra])
        )

        with pytest.raises(AssertionError) as flagged:
            self._allowed_sweep_files()

        message = str(flagged.value)
        assert "test_plugin_system.py" in message, message
        assert "tests/snapshot/conftest.py" in message, message
