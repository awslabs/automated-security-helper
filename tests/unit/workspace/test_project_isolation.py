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

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from threading import Barrier, BrokenBarrierError, Lock
from typing import Any, Dict, List, Literal, Optional, Tuple
from unittest.mock import MagicMock, patch

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.phases.scan_phase import ScanPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.models.workspace import ProjectRunStatus
from automated_security_helper.workspace.execution import (
    ProjectScanSettings,
    execute_workspace,
)
from automated_security_helper.workspace.resolver import resolve_workspace

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
    """Run one project's real scan phase with the recording scanner registered."""
    progress = MagicMock()
    progress.add_task.return_value = 1
    with patch(
        "automated_security_helper.core.phases.scan_phase.ScannerValidationManager"
    ) as MockValMgr:
        manager = MagicMock()
        checkpoint = MagicMock()
        checkpoint.has_issues.return_value = False
        checkpoint.get_missing_scanners.return_value = []
        checkpoint.get_unexpected_scanners.return_value = []
        checkpoint.errors = []
        checkpoint.discrepancies = []
        manager.validate_task_queue.return_value = checkpoint
        manager.validate_execution_completion.return_value = checkpoint
        manager.validate_result_completeness.return_value = checkpoint
        manager.report_execution_discrepancies.return_value = {}
        MockValMgr.return_value = manager

        phase = ScanPhase(
            plugin_context=context,
            plugins=[RecordingScanner],
            progress_display=progress,
        )
        phase.validation_manager = manager
        return phase.execute(aggregated_results=AshAggregatedResults())


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
        assert statuses == {
            key: ProjectRunStatus.COMPLETED for key in PROJECT_KEYS.values()
        }, [
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

    _REGISTRY_PATTERNS = (
        "ash_plugin_manager.plugin_library",
        "ash_plugin_manager._resolved_plugins",
        'getattr(ash_plugin_manager, "plugin_library"',
        "getattr(ash_plugin_manager, 'plugin_library'",
        'getattr(ash_plugin_manager, "_resolved_plugins"',
        "getattr(ash_plugin_manager, '_resolved_plugins'",
    )

    @classmethod
    def _source_files(cls):
        """Every Python file in the repository, not only the package.

        Widened from a package-only walk because a plugin, a script or a helper
        under ``tests/`` can reach the same singleton, and the package walk would
        not have seen it. Out-of-tree plugin modules remain outside the reach of
        any check that reads this repository; see the class docstring.
        """
        root = Path(__file__).resolve().parents[3]
        this_file = Path(__file__).resolve()
        for path in sorted(root.rglob("*.py")):
            if path == this_file:
                continue
            parts = set(path.relative_to(root).parts)
            if any(part.startswith(".") for part in parts):
                continue
            if parts & cls._SKIP_DIRS:
                continue
            yield path

    @classmethod
    def _hits(cls, patterns, *, skip_files=()) -> Dict[str, str]:
        found: Dict[str, str] = {}
        skipped = set(skip_files)
        for path in cls._source_files():
            if path.name in skipped:
                continue
            for number, line in enumerate(
                path.read_text(encoding="utf-8").splitlines(), start=1
            ):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if any(pattern in stripped for pattern in patterns):
                    found[f"{path.name}:{number}"] = stripped
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

        Two files are allowed in, and the widened walk is what surfaced them:

        * ``plugin_manager.py`` owns the attributes.
        * ``tests/unit/plugins/test_plugin_system.py`` is the test *of* the plugin
          system, and clears ``plugin_library.event_handlers`` between cases.
          There is no manager API for "forget every handler", and a test resetting
          process-global state is the opposite of the hazard here -- it prevents
          leakage between cases rather than causing it between projects.

        Anything else, in production or in a new test, fails this and has to
        justify itself.
        """
        offenders = self._hits(
            self._REGISTRY_PATTERNS,
            skip_files=("plugin_manager.py", "test_plugin_system.py"),
        )
        assert offenders == {}, (
            "the plugin manager's registry state is now reached from outside the "
            "class that owns it. Both attributes are process-global, and the "
            "first workspace project to touch them decides the scanner set for "
            "every project -- a silent false negative on a security scanner. "
            "Route this through the manager's own API, and read "
            "test_plugin_registry_scoping.py first: " + repr(offenders)
        )

    def test_the_registry_sweep_would_catch_a_new_offender(self):
        """The companion assertion: prove the allowlist is narrow, not the matcher.

        ``test_nothing_outside_the_manager_touches_the_registry`` passes partly
        because two files are excluded. If the matcher were broken it would pass
        for the wrong reason and look identical. So assert that the same patterns
        do find the accesses in the excluded files -- an empty result there would
        mean the sweep is blind rather than the tree clean.
        """
        without_allowlist = self._hits(self._REGISTRY_PATTERNS)
        assert without_allowlist, (
            "the registry patterns match nothing anywhere, including in the two "
            "files known to contain such accesses, so the sweep is blind and the "
            "clean result next door is meaningless"
        )
        assert any(
            location.startswith("test_plugin_system.py")
            for location in without_allowlist
        ), sorted(without_allowlist)
