"""Under a scanner sandbox, the convert phase confines every converter's spawns.

The jupyter converter confines its own nbconvert runs
(``tests/unit/plugin_modules/ash_builtin/converters/test_jupyter_converter_sandbox.py``).
The phase does the same for any converter, a third-party one included: what a converter
starts while it is constructed, while its dependencies are checked, and from
``convert()`` is planned by the sandbox backend, and refused when no backend can be
used. With ``sandbox.mode: off`` nothing is planned.

The converter here starts a short Python process through ``run_command`` at each of
those three points, which creates a marker file named after the point, so a spawn that
ran is visible whether or not anything planned it. The backend is a stand-in
registered as ``bwrap`` that records each spawn and runs it unchanged.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Literal
from unittest.mock import MagicMock

import pytest

from automated_security_helper.base.converter_plugin import (
    ConverterPluginBase,
    ConverterPluginConfigBase,
)
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig, SandboxConfig
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.phases.convert_phase import ConvertPhase
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.utils.sandbox import scope as scope_module
from automated_security_helper.utils.sandbox.backends import SpawnPlan
from automated_security_helper.utils.subprocess_utils import run_command
from tests.utils.helpers import CHILD_TIMEOUT_SECONDS

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()


class SpawningConverterConfig(ConverterPluginConfigBase):
    name: Literal["spawning"] = "spawning"


MARKERS: dict = {}


def _spawn(stage: str) -> None:
    marker = Path(MARKERS["dir"], stage)
    run_command(
        [
            sys.executable,
            "-c",
            "import pathlib, sys; pathlib.Path(sys.argv[1]).touch()",
            str(marker),
        ],
        log_level=10,
        timeout=CHILD_TIMEOUT_SECONDS,
    )


class SpawningConverter(ConverterPluginBase[SpawningConverterConfig]):
    def model_post_init(self, context):
        if self.config is None:
            self.config = SpawningConverterConfig()
        super().model_post_init(context)
        _spawn("construct")

    def validate_plugin_dependencies(self) -> bool:
        _spawn("validate")
        return True

    def convert(self) -> List[Path]:
        _spawn("convert")
        return []


@pytest.fixture
def backend(monkeypatch):
    class Recorder:
        name = "recorder"
        unavailable_reason = None
        spawns: list = []

        def probe(self):
            return type(self).unavailable_reason

        def plan(self, argv, env, policy):
            type(self).spawns.append((list(argv), policy))
            return SpawnPlan(argv=list(argv), env=dict(env))

    scope_module.clear_backend_cache()
    monkeypatch.setitem(scope_module.BACKENDS, "bwrap", Recorder)
    yield Recorder
    scope_module.clear_backend_cache()


def _context(tmp_path, mode):
    MARKERS["dir"] = tmp_path / "markers"
    MARKERS["dir"].mkdir()
    source = tmp_path / "source"
    source.mkdir()
    (source / "app.py").write_text("x = 1\n")
    output = tmp_path / "output"
    (output / ASH_WORK_DIR_NAME).mkdir(parents=True)
    return PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / ASH_WORK_DIR_NAME,
        config=AshConfig(project_name="convert", sandbox=SandboxConfig(mode=mode)),
    )


def _run(context) -> AshAggregatedResults:
    results = AshAggregatedResults()
    ConvertPhase(
        plugin_context=context,
        plugins=[SpawningConverter],
        progress_display=MagicMock(),
    )._execute_phase(aggregated_results=results)
    return results


def _stages(spawns) -> List[str]:
    return [Path(argv[-1]).name for argv, _policy in spawns]


def _ran() -> List[str]:
    return sorted(p.name for p in MARKERS["dir"].iterdir())


def test_every_spawn_of_a_converter_is_planned_by_the_sandbox(tmp_path, backend):
    context = _context(tmp_path, "bwrap")

    _run(context)

    stages = _stages(backend.spawns)
    assert _ran() == ["construct", "convert", "validate"], "the harness ran nothing"
    assert {"construct", "validate", "convert"} <= set(stages), (
        f"spawns ran without the sandbox backend planning them; planned: {stages}"
    )
    convert_policies = [
        p for argv, p in backend.spawns if Path(argv[-1]).name == "convert"
    ]
    assert convert_policies
    for policy in convert_policies:
        assert policy.network is False
        assert [Path(w) for w in policy.writable] == [
            Path(context.work_dir, "spawning").absolute()
        ]


def test_an_unavailable_sandbox_refuses_the_converters_spawns(tmp_path, backend):
    backend.unavailable_reason = "bwrap: cannot create a user namespace"

    _run(_context(tmp_path, "bwrap"))

    assert backend.spawns == []
    assert _ran() == [], (
        f"converter spawns ran although the sandbox is unavailable: {_ran()}"
    )


def test_without_a_sandbox_nothing_is_planned(tmp_path, backend):
    """Control: sandbox mode off runs the converter as before."""
    _run(_context(tmp_path, "off"))

    assert backend.spawns == []
    assert _ran() == ["construct", "convert", "validate"]


class TestRefusedSpawnsAreLostCoverage:
    """A converter whose spawns the sandbox refused converted nothing it was asked to.

    A scanner in the same position is recorded MISSING and the scan exits 1; the
    converter's row has to say the same, so the completeness gate lists it.
    """

    def test_an_unavailable_sandbox_makes_the_converter_incomplete(
        self, tmp_path, backend
    ):
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_converters,
        )

        backend.unavailable_reason = "bwrap: cannot create a user namespace"

        results = _run(_context(tmp_path, "bwrap"))

        assert _ran() == []
        assert [row.name for row in incomplete_converters(results)] == ["spawning"], (
            results.converter_results["spawning"].model_dump(mode="json")
        )

    def test_a_spawn_the_backend_refuses_makes_the_converter_incomplete(
        self, tmp_path, backend, monkeypatch
    ):
        """The scope builds, but the backend cannot express this one spawn."""
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_converters,
        )
        from automated_security_helper.utils.sandbox.policy import SandboxUnavailable

        def refuse_conversion(self, argv, env, policy):
            if Path(argv[-1]).name == "convert":
                raise SandboxUnavailable("cannot express a path in the profile")
            return SpawnPlan(argv=list(argv), env=dict(env))

        monkeypatch.setattr(backend, "plan", refuse_conversion)

        results = _run(_context(tmp_path, "bwrap"))

        assert "convert" not in _ran()
        listed = incomplete_converters(results)
        assert [row.name for row in listed] == ["spawning"], listed
        assert "refused" in listed[0][1]

    def test_a_converter_whose_spawns_ran_is_complete(self, tmp_path, backend):
        """Control: every spawn planned and run, nothing lost."""
        from automated_security_helper.interactions.run_ash_scan import (
            incomplete_converters,
        )

        results = _run(_context(tmp_path, "bwrap"))

        assert _ran() == ["construct", "convert", "validate"]
        assert incomplete_converters(results) == []
