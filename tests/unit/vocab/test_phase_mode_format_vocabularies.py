"""The phase, run-mode, export-format and sandbox-mode vocabularies are spelled once.

Each vocabulary has one home (``core/enums.py``) and every other file reaches it
through the enum. Two drift gates enforce that, with the strength each
vocabulary's spellings allow:

* a NEGATIVE gate for distinctive spellings (``flat-json``, ``unused-suppressions``,
  ``bedrock-summary-reporter``): an AST scan of the cured files for a string
  constant equal to a member value, docstrings and comments excluded;
* a POSITIVE gate for ambiguous words (``scan``, ``report``, ``local``, ``off``),
  where a scan of every string constant would drown in false positives: the
  inventoried copy sites are pinned gone by (file, fragment), and the derived
  tables are pinned equal to their derivation.

A planted-positive control feeds each gate a file that spells a vocabulary by hand
and asserts the gate flags it, so a scan that silently stopped looking cannot read
as clean.
"""

import ast
import inspect
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

import pytest

import automated_security_helper
from automated_security_helper.base.engine_phase import EnginePhase
from automated_security_helper.core.enums import (
    DEFAULT_EXECUTION_PHASES,
    ExecutionPhase,
    ExecutionStrategy,
    ExportFormat,
    RunMode,
    SandboxMode,
    ScannerToolType,
    phase_values,
)
from automated_security_helper.plugins.events import AshEventType

pytestmark = pytest.mark.unit

PACKAGE = Path(inspect.getfile(automated_security_helper)).parent


# ---------------------------------------------------------------------------
# The scanners
# ---------------------------------------------------------------------------


def _docstring_nodes(tree: ast.AST) -> set:
    """The ids of the string constants that sit in a docstring position."""
    found = set()
    for node in ast.walk(tree):
        if isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            body = getattr(node, "body", [])
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                found.add(id(body[0].value))
    return found


def stray_spellings(source: str, values: Iterable[str]) -> List[Tuple[int, str]]:
    """The (line, value) of every string constant in *source* equal to one of *values*.

    A docstring is not a spelling, and a comment never reaches the AST.
    """
    wanted = set(values)
    tree = ast.parse(source)
    docstrings = _docstring_nodes(tree)
    return [
        (node.lineno, node.value)
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
        and node.value in wanted
    ]


def surviving_fragments(
    root: Path, pins: Sequence[Tuple[str, str]]
) -> List[Tuple[str, str]]:
    """The (path, fragment) pins whose fragment is still in the file."""
    return [
        (path, fragment)
        for path, fragment in pins
        if fragment in (root / path).read_text(encoding="utf-8")
    ]


# ---------------------------------------------------------------------------
# Negative gate: distinctive spellings
# ---------------------------------------------------------------------------

#: ExportFormat values no other word in the cured files shares. ``cli/report.py``
#: and ``core/constants.py`` are the files B3 cured; both read formats only through
#: the enum now.
_DISTINCTIVE_FORMATS = (
    ExportFormat.FLAT_JSON,
    ExportFormat.GITHUB_GHAS,
    ExportFormat.GITLAB_SAST,
    ExportFormat.GITLAB_CYCLONEDX,
    ExportFormat.UNUSED_SUPPRESSIONS,
    ExportFormat.BEDROCK_SUMMARY,
    ExportFormat.AWS_SECURITY_HUB,
    ExportFormat.CLOUDWATCH_LOGS,
)
_FORMAT_SCOPE = ("cli/report.py", "core/constants.py")


@pytest.mark.parametrize("path", _FORMAT_SCOPE)
def test_the_cured_files_hold_no_hand_spelled_distinctive_export_format(path):
    source = (PACKAGE / path).read_text(encoding="utf-8")
    found = stray_spellings(source, (fmt.value for fmt in _DISTINCTIVE_FORMATS))
    assert found == [], (
        f"{path} spells an ExportFormat value by hand at {found}; "
        "read it from the member (ExportFormat.X.value)"
    )


def test_planted_control_the_negative_scan_flags_a_hand_spelled_format(tmp_path):
    planted = tmp_path / "planted.py"
    planted.write_text(
        '"""A docstring may say flat-json."""\n'
        "# a comment may say unused-suppressions\n"
        'FORMATS = frozenset({"flat-json"})\n',
        encoding="utf-8",
    )
    found = stray_spellings(
        planted.read_text(encoding="utf-8"),
        (fmt.value for fmt in _DISTINCTIVE_FORMATS),
    )
    assert found == [(3, "flat-json")], (
        "the scan must flag the code constant and skip the docstring and comment"
    )


# ---------------------------------------------------------------------------
# Positive gate: ambiguous words
# ---------------------------------------------------------------------------

#: (file, fragment) pairs from the catalog: each copy site a unit cured, pinned gone.
_GONE_FRAGMENTS = (
    # B2: the phase Literal duplicate, the keyword literals, the match arms, the
    # list builds, the orchestrator and surface copies.
    ("core/progress.py", "ExecutionPhaseType"),
    ("core/execution_engine.py", "ExecutionPhaseType"),
    ("core/orchestrator.py", "ExecutionPhaseType"),
    ("interactions/run_ash_scan.py", "ExecutionPhaseType"),
    ("core/phases/scan_phase.py", 'phase="scan"'),
    ("core/phases/scan_phase.py", '{"phase": "scan"}'),
    ("core/phases/report_phase.py", 'phase="report"'),
    ("core/phases/convert_phase.py", 'phase="convert"'),
    ("core/execution_engine.py", 'case "convert"'),
    ("core/execution_engine.py", 'case "scan"'),
    ("core/execution_engine.py", 'case "report"'),
    ("core/execution_engine.py", 'case "inspect"'),
    ("core/execution_engine.py", 'ordered_phases.append("'),
    ("core/orchestrator.py", '["convert", "scan", "report"]'),
    ("core/execution_engine.py", '["convert", "scan", "report"]'),
    ("interactions/run_ash_scan.py", 'phases_to_run.append("'),
    ("interactions/run_ash_scan.py", '["convert", "scan", "report"]'),
    ("workspace/execution.py", '_REPORT_PHASE = "report"'),
    ("workspace/execution.py", '("convert", "scan", "report")'),
    ("base/engine_phase.py", "self.phase_name.upper()"),
    # B3: the format sets and the precommit tuple.
    ("core/constants.py", '"text",\n    "sarif",'),
    ("cli/report.py", '"markdown", "bedrock-summary-reporter"'),
    # B4: the inline tag set, the UNKNOWN default, the table's spellings.
    ("models/asharp_model.py", '"CONTAINER",'),
    ("models/asharp_model.py", 'tool_type = "UNKNOWN"'),
    ("utils/scanner_names.py", '": "IAC"'),
    ("utils/scanner_names.py", '": "SAST"'),
    ("utils/scanner_names.py", '": "SCA"'),
    ("utils/scanner_names.py", '": "SBOM"'),
    ("utils/scanner_tool_types.py", 'UNKNOWN_TOOL_TYPE = "UNKNOWN"'),
    # B5: the config Literal and the mixed member/.value compares.
    ("config/ash_config.py", 'Literal["off", "auto"'),
    ("utils/sandbox/scope.py", "SandboxMode.off.value"),
    ("utils/sandbox/scope.py", "SandboxMode.auto.value"),
    ("config/sandbox_grants.py", 'trusted.mode != "off"'),
    ("config/client_config_policy.py", 'trusted.mode != "off"'),
    # B8: the double spelling, the str-typed mode helper, the nix argv spelling,
    # the bare strategy field and its .value rehydration.
    ("cli/scan.py", 'str(mode).lower() == "precommit"'),
    ("cli/scan.py", 'str(log_level).lower() == "simple"'),
    ("interactions/run_ash_scan.py", 'mode == "container"'),
    ("interactions/run_ash_scan.py", "mode: str,\n    output_file"),
    ("interactions/run_ash_nix.py", '"--mode", "local"'),
    ("interactions/run_ash_nix.py", '"--mode=local"'),
    ("workspace/execution.py", 'strategy: str = "parallel"'),
    ("workspace/execution.py", "ExecutionStrategy.PARALLEL.value"),
)


def test_the_cured_copy_sites_stay_gone():
    survivors = surviving_fragments(PACKAGE, _GONE_FRAGMENTS)
    assert survivors == [], f"re-spelled vocabulary at {survivors}"


def test_planted_control_the_positive_pins_flag_a_surviving_fragment(tmp_path):
    (tmp_path / "planted.py").write_text('phase="scan"\n', encoding="utf-8")
    assert surviving_fragments(tmp_path, [("planted.py", 'phase="scan"')]) == [
        ("planted.py", 'phase="scan"')
    ]
    assert surviving_fragments(tmp_path, [("planted.py", 'phase="report"')]) == []


# ---------------------------------------------------------------------------
# B2 ExecutionPhase
# ---------------------------------------------------------------------------


def test_member_order_is_execution_order():
    assert list(ExecutionPhase) == [
        ExecutionPhase.CONVERT,
        ExecutionPhase.SCAN,
        ExecutionPhase.REPORT,
        ExecutionPhase.INSPECT,
    ]
    assert DEFAULT_EXECUTION_PHASES == (
        ExecutionPhase.CONVERT,
        ExecutionPhase.SCAN,
        ExecutionPhase.REPORT,
    )


def test_the_phase_event_names_derive_from_the_enum_product():
    """``<PHASE>_PHASE_START`` and ``_COMPLETE`` exist in AshEventType for every phase.

    EnginePhase.execute builds them from ``phase_name.value`` and looks them up by
    NAME; a phase added to the enum without its two events would fall back to the
    string path with a warning at run time.
    """
    expected = {
        f"{phase.value.upper()}_PHASE_{edge}"
        for phase in ExecutionPhase
        for edge in ("START", "COMPLETE")
    }
    assert len(expected) == 8
    assert expected <= set(AshEventType.__members__)


def test_every_phase_class_names_its_own_member():
    from automated_security_helper.core.phases.convert_phase import ConvertPhase
    from automated_security_helper.core.phases.inspect_phase import InspectPhase
    from automated_security_helper.core.phases.report_phase import ReportPhase
    from automated_security_helper.core.phases.scan_phase import ScanPhase

    named = {
        cls.phase_name.fget(None)  # a constant property; it reads nothing of self
        for cls in (ConvertPhase, ScanPhase, ReportPhase, InspectPhase)
    }
    assert named == set(ExecutionPhase)
    assert all(isinstance(name, ExecutionPhase) for name in named)
    assert EnginePhase.phase_name.fget.__annotations__["return"] is ExecutionPhase


def test_phase_values_spells_members_and_plain_strings_alike():
    assert phase_values([ExecutionPhase.SCAN, "report"]) == ["scan", "report"]
    assert phase_values(DEFAULT_EXECUTION_PHASES) == ["convert", "scan", "report"]


def test_ordering_derives_from_member_order_and_ignores_unknown_names():
    asked = ["report", "bogus", ExecutionPhase.CONVERT]
    assert [p for p in ExecutionPhase if p in asked] == [
        ExecutionPhase.CONVERT,
        ExecutionPhase.REPORT,
    ]


def test_project_scan_settings_defaults_are_the_enum_members():
    from pathlib import Path as _Path

    from automated_security_helper.workspace.execution import ProjectScanSettings

    settings = ProjectScanSettings(output_dir=_Path("out"))
    assert settings.phases == DEFAULT_EXECUTION_PHASES
    assert all(isinstance(phase, ExecutionPhase) for phase in settings.phases)
    assert settings.strategy is ExecutionStrategy.PARALLEL


# ---------------------------------------------------------------------------
# B3 ExportFormat
# ---------------------------------------------------------------------------


def test_the_report_format_sets_are_export_format_values():
    from automated_security_helper.cli.report import (
        JSON_STDOUT_FORMATS,
        MARKDOWN_STDOUT_FORMATS,
        TEXT_OR_JSON_FORMATS,
    )
    from automated_security_helper.core.constants import (
        PRECOMMIT_MODE_OUTPUT_FORMATS,
    )

    every = {fmt.value for fmt in ExportFormat}
    for table in (
        JSON_STDOUT_FORMATS,
        MARKDOWN_STDOUT_FORMATS,
        TEXT_OR_JSON_FORMATS,
        set(PRECOMMIT_MODE_OUTPUT_FORMATS),
    ):
        assert table <= every
        assert all(type(name) is str for name in table)
    assert JSON_STDOUT_FORMATS == {
        "asff",
        "aws-security-hub",
        "cloudwatch-logs",
        "cyclonedx",
        "flat-json",
        "github-ghas",
        "gitlab-cyclonedx",
        "gitlab-sast",
        "ocsf",
        "s3",
        "sarif",
        "spdx",
        "unused-suppressions",
    }
    assert MARKDOWN_STDOUT_FORMATS == {"markdown", "bedrock-summary-reporter"}
    assert TEXT_OR_JSON_FORMATS == {"unused-suppressions"}
    assert PRECOMMIT_MODE_OUTPUT_FORMATS == ("text", "sarif")


# ---------------------------------------------------------------------------
# B4 ScannerToolType
# ---------------------------------------------------------------------------


def test_the_tagged_tool_types_are_every_member_a_tag_can_state():
    from automated_security_helper.models.asharp_model import _TAGGED_TOOL_TYPES

    assert _TAGGED_TOOL_TYPES == {
        "SAST",
        "DAST",
        "SCA",
        "IAC",
        "SECRETS",
        "CONTAINER",
        "SBOM",
    }
    assert ScannerToolType.CUSTOM.value not in _TAGGED_TOOL_TYPES
    assert ScannerToolType.UNKNOWN.value not in _TAGGED_TOOL_TYPES


def test_the_scanner_tool_type_table_holds_only_member_values():
    from automated_security_helper.utils.scanner_names import SCANNER_TOOL_TYPES
    from automated_security_helper.utils.scanner_tool_types import (
        SECRETS_TOOL_TYPE,
        UNKNOWN_TOOL_TYPE,
    )

    assert set(SCANNER_TOOL_TYPES.values()) <= {m.value for m in ScannerToolType}
    assert all(type(value) is str for value in SCANNER_TOOL_TYPES.values())
    assert SECRETS_TOOL_TYPE == ScannerToolType.SECRETS.value
    assert UNKNOWN_TOOL_TYPE == ScannerToolType.UNKNOWN.value


# ---------------------------------------------------------------------------
# B5 SandboxMode on the config
# ---------------------------------------------------------------------------


def test_the_sandbox_mode_validates_to_a_member_and_dumps_as_its_name():
    import yaml

    from automated_security_helper.config.ash_config import SandboxConfig

    config = SandboxConfig.model_validate({"mode": "bwrap"}, strict=True)
    assert config.mode is SandboxMode.bwrap
    assert SandboxConfig().mode is SandboxMode.off
    for dumped in (config.model_dump(), config.model_dump(mode="json")):
        assert dumped["mode"] == "bwrap"
        assert type(dumped["mode"]) is str
    assert yaml.safe_dump(config.model_dump())  # a member would be refused


@pytest.mark.parametrize("bad", ["bogus", True, 1, None])
def test_a_value_that_is_no_mode_is_refused_as_the_literal_was(bad):
    from pydantic import ValidationError

    from automated_security_helper.config.ash_config import SandboxConfig

    with pytest.raises(ValidationError) as caught:
        SandboxConfig.model_validate({"mode": bad}, strict=True)
    (error,) = caught.value.errors()
    assert error["type"] == "literal_error"
    assert error["loc"] == ("mode",)
    assert error["msg"] == (
        "Input should be 'off', 'auto', 'bwrap', 'firejail', 'landlock' "
        "or 'sandbox-exec'"
    )


def test_the_published_modes_are_the_enum_values():
    from automated_security_helper.config.ash_config import SandboxConfig

    schema = SandboxConfig.model_json_schema()
    spelled = schema["$defs"]["SandboxMode"]["enum"]
    assert spelled == [mode.value for mode in SandboxMode]


# ---------------------------------------------------------------------------
# B8 RunMode and friends
# ---------------------------------------------------------------------------


def test_the_nix_inner_argv_spells_the_local_mode_from_the_enum():
    from automated_security_helper.interactions import run_ash_nix

    source = inspect.getsource(run_ash_nix)
    assert RunMode.local.value == "local"
    assert '"--mode", RunMode.local.value' in source
