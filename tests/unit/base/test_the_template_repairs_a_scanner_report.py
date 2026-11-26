"""The scan template repairs a scanner's report before it grades it.

One value the SARIF model refuses used to cost a scanner its whole report: the
template validated the tool's file with ``SarifReport.model_validate`` and turned
the first refusal into a ``ScannerError``. The template now reads the file and the
document through the ingest step, so a region that starts on line 0, a key the spec
does not define or a file with a byte-order mark costs only itself. Each repair is
counted on the scanner's record, said once in the log, and carried as a warning
notification on ASH's invocation of the tool; a report the step cannot repair is
refused with the same words as before.
"""

from __future__ import annotations

import copy
import json
import logging
from pathlib import Path
from typing import ClassVar, Literal
from unittest.mock import patch

import pytest

from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.asset import ImageLocator
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from tests.unit.plugin_modules.ash_betterleaks_plugins.test_betterleaks_scanner import (
    CAPTURED,
    FakeBetterleaks,
    _run,
    _scanner as _betterleaks,
    no_config_env,  # noqa: F401 -- an autouse fixture the betterleaks helpers need
    on_path,  # noqa: F401
    tree,  # noqa: F401
)

pytestmark = pytest.mark.unit

IMAGE_REF = "registry.example.com/team/app:1.2.3"
_REGION = "runs/0/results/0/locations/0/physicalLocation/region"
_SENTENCE = (
    "ASH repaired 1 part of stub's report that SARIF does not allow "
    "(a region with no readable line)."
)


class _Config(ScannerPluginConfigBase):
    name: Literal["stub"] = "stub"


def _result(rule: str, line: int) -> dict:
    return {
        "ruleId": rule,
        "message": {"text": f"{rule} was found"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": f"src/{rule}.py"},
                    "region": {"startLine": line, "startColumn": 1},
                }
            }
        ],
    }


def _report(*results: dict, invocations: list | None = None) -> dict:
    run: dict = {
        "tool": {"driver": {"name": "stub-tool", "version": "1.0.0"}},
        "results": list(results),
    }
    if invocations is not None:
        run["invocations"] = invocations
    return {"version": "2.1.0", "runs": [run]}


def _text(content: str | bytes | dict) -> bytes:
    if isinstance(content, dict):
        content = json.dumps(content)
    return content.encode("utf-8") if isinstance(content, str) else content


def _make_scanner(plugin_context, content, *, extras=None):
    """A template scanner whose tool wrote *content* as its results file.

    The bytes are read from ``StubScanner.written[0]`` at each run, so a test
    that scans one instance twice can change what its tool writes.
    """

    def write(scanner):
        results = scanner.results_dir / "source" / "stub.sarif"
        results.parent.mkdir(parents=True, exist_ok=True)
        results.write_bytes(type(scanner).written[0])
        return ["stub-tool", "--scan"], results, None

    class StubScanner(ScannerPluginBase):
        offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
        written: ClassVar[list] = [_text(content)]

        def model_post_init(self, context):
            self.command = "stub-tool"
            self.tool_type = ScannerToolType.SAST
            super().model_post_init(context)

        def validate_plugin_dependencies(self) -> bool:
            return True

        def _execute_scan(self, target, target_type, global_ignore_paths):
            return write(self)

        def _execute_image_scan(self, image):
            return write(self)

        if extras is not None:

            def _invocation_extras(self, sarif_report, final_args, target):
                return extras

    return StubScanner(config=_Config(), context=plugin_context)


def _logged(scanner, monkeypatch) -> list:
    lines: list = []
    original = type(scanner)._plugin_log

    def recording(self, *message, **kwargs):
        lines.append((" ".join(str(part) for part in message), kwargs.get("level")))
        return original(self, *message, **kwargs)

    monkeypatch.setattr(type(scanner), "_plugin_log", recording)
    return lines


def _scan(scanner, tmp_path, *, image: bool = False):
    target = tmp_path / "target"
    target.mkdir(exist_ok=True)
    (target / "app.py").write_text("x = 1\n")
    with patch.object(scanner, "_pre_scan", return_value=True):
        scanner.dependencies_satisfied = True
        with patch.object(
            scanner,
            "_run_subprocess",
            return_value={"returncode": 0, "stdout": "", "stderr": ""},
        ):
            if image:
                return scanner.scan_image(ImageLocator(ref=IMAGE_REF))
            return scanner.scan(target=target, target_type="source")


def _warnings(report: SarifReport) -> list:
    return [
        note
        for invocation in report.runs[0].invocations
        for note in invocation.toolExecutionNotifications or []
        if getattr(note.level, "value", note.level) == "warning"
    ]


def _repaired_report() -> dict:
    return _report(_result("r-one", 0), _result("r-two", 7))


@pytest.mark.parametrize("image", [False, True], ids=["scan", "scan_image"])
def test_a_region_at_line_zero_costs_the_report_nothing(
    plugin_context, tmp_path, monkeypatch, image
):
    scanner = _make_scanner(plugin_context, _repaired_report())
    lines = _logged(scanner, monkeypatch)

    report = _scan(scanner, tmp_path, image=image)

    assert [r.ruleId for r in report.runs[0].results] == ["r-one", "r-two"]
    first, second = report.runs[0].results
    assert first.locations[0].physicalLocation.root.region is None
    assert second.locations[0].physicalLocation.root.region.startLine == 7
    summary = scanner.output_ingest_record
    assert summary["repaired"] == 1 and summary["results_read"] == 2
    assert [(e["code"], e["pointer"], e["rule_id"]) for e in summary["elements"]] == [
        ("region_line_unreadable", _REGION, "r-one")
    ]
    (note,) = _warnings(report)
    assert note.message.root.text == _SENTENCE
    assert str(tmp_path) not in note.message.root.text
    assert [(m, lvl) for m, lvl in lines if "repaired" in m] == [
        (_SENTENCE, logging.WARNING)
    ]


@pytest.mark.parametrize(
    ("content", "code"),
    [
        (b"\xef\xbb\xbf" + json.dumps(_report(_result("r-one", 3))).encode(), "bom"),
        (
            json.dumps(_report(_result("r-one", 3)))
            .replace("r-one was found", "a raw\ttab")
            .encode(),
            "control_character",
        ),
        (
            json.dumps(_report(_result("r-one", 3)))
            .replace("r-one was found", "caf-X")
            .encode()
            .replace(b"-X", b"\xe9"),
            "bytes_not_utf8",
        ),
    ],
    ids=["byte-order mark", "control character", "byte that is not UTF-8"],
)
def test_a_file_that_strict_reading_refuses_is_read_and_noted(
    plugin_context, tmp_path, content, code
):
    scanner = _make_scanner(plugin_context, content)

    report = _scan(scanner, tmp_path)

    assert [r.ruleId for r in report.runs[0].results] == ["r-one"]
    assert [e["code"] for e in scanner.output_ingest_record["elements"]] == [code]
    assert len(_warnings(report)) == 1


def test_a_clean_report_notes_nothing_and_logs_nothing(
    plugin_context, tmp_path, monkeypatch
):
    scanner = _make_scanner(plugin_context, _report(_result("r-one", 3)))
    lines = _logged(scanner, monkeypatch)

    report = _scan(scanner, tmp_path)

    assert scanner.output_ingest_record is None
    assert _warnings(report) == []
    assert not [m for m, _ in lines if "repaired" in m]


def test_a_report_that_cannot_be_repaired_is_refused_with_the_same_words(
    plugin_context, tmp_path
):
    broken = _result("r-one", 3)
    del broken["message"]
    scanner = _make_scanner(plugin_context, _report(_result("r-two", 0), broken))

    with pytest.raises(ScannerError) as refused:
        _scan(scanner, tmp_path)

    assert "its results file is not SARIF ASH can read" in str(refused.value)
    assert scanner.output_ingest_record["repaired"] == 1


def test_a_scanners_record_starts_again_with_each_target(plugin_context, tmp_path):
    scanner = _make_scanner(plugin_context, _repaired_report())
    first = _scan(scanner, tmp_path)
    assert scanner.output_ingest_record["repaired"] == 1 and len(_warnings(first)) == 1

    type(scanner).written[0] = _text(_report(_result("r-one", 3)))
    second = _scan(scanner, tmp_path)

    assert scanner.output_ingest_record is None
    assert _warnings(second) == []


def test_a_scan_that_returns_before_the_tool_leaves_no_record_of_the_last_one(
    plugin_context, tmp_path
):
    scanner = _make_scanner(plugin_context, _repaired_report())
    _scan(scanner, tmp_path)
    assert scanner.output_ingest_record is not None

    empty = tmp_path / "empty"
    empty.mkdir()
    assert scanner.scan(target=empty, target_type="source") is True

    assert scanner.output_ingest_record is None


def test_the_tools_own_notifications_and_the_repair_note_both_stay(
    plugin_context, tmp_path
):
    own = {
        "executionSuccessful": True,
        "toolExecutionNotifications": [
            {"level": "note", "message": {"text": "the tool's own note"}}
        ],
    }
    scanner = _make_scanner(
        plugin_context,
        _report(_result("r-one", 0), invocations=[own]),
    )

    report = _scan(scanner, tmp_path)

    texts = [
        n.message.root.text
        for n in report.runs[0].invocations[0].toolExecutionNotifications
    ]
    assert texts == ["the tool's own note", _SENTENCE]


def test_a_scanner_that_overrides_the_invocation_extras_cannot_drop_the_note(
    plugin_context, tmp_path
):
    mine = [{"level": "note", "message": {"text": "mine"}}]
    scanner = _make_scanner(
        plugin_context,
        _repaired_report(),
        extras={"toolExecutionNotifications": mine},
    )

    report = _scan(scanner, tmp_path)

    texts = [
        n.message.root.text
        for n in report.runs[0].invocations[0].toolExecutionNotifications
    ]
    assert texts == ["mine", _SENTENCE]


def test_a_second_injection_on_one_report_does_not_say_it_twice(
    plugin_context, tmp_path
):
    scanner = _make_scanner(plugin_context, _repaired_report())
    report = _scan(scanner, tmp_path)

    scanner._inject_invocation(report, ["stub-tool", "--scan"], Path(tmp_path))

    assert len(_warnings(report)) == 1


def test_the_note_is_a_warning_and_the_run_is_still_successful(
    plugin_context, tmp_path
):
    """Only an ``error`` notification fails a run outside the completeness gate."""
    scanner = _make_scanner(plugin_context, _repaired_report())
    report = _scan(scanner, tmp_path)

    (note,) = report.runs[0].invocations[0].toolExecutionNotifications
    assert getattr(note.level, "value", note.level) == "warning"
    assert report.runs[0].invocations[0].executionSuccessful is True


# --------------------------------------------------------------------------- #
# Scanners that read through the template's own reader
# --------------------------------------------------------------------------- #


def test_betterleaks_keeps_its_findings_through_the_shared_reader(
    tree,  # noqa: F811
    tmp_path,
    on_path,  # noqa: F811
    monkeypatch,
):
    doc = json.loads((CAPTURED / "positive.sarif").read_text(encoding="utf-8"))
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"][
        "startLine"
    ] = 0
    scanner = _betterleaks(tree, tmp_path)
    fake = FakeBetterleaks(sarif_text=json.dumps(doc))

    report = _run(scanner, fake, monkeypatch)

    results = report.runs[0].results
    assert len(results) == len(doc["runs"][0]["results"]) == 2
    assert results[0].locations[0].physicalLocation.root.region is None
    summary = scanner.output_ingest_record
    assert [e["code"] for e in summary["elements"]] == ["region_line_unreadable"]
    assert len(_warnings(report)) == 1


def test_bandit_reads_its_results_file_through_the_shared_reader(tmp_path):
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.plugin_modules.ash_builtin.scanners.bandit_scanner import (
        BanditScanner,
        BanditScannerConfig,
    )

    for name in ("src", "out", "work"):
        (tmp_path / name).mkdir()
    scanner = BanditScanner(
        context=PluginContext(
            source_dir=tmp_path / "src",
            output_dir=tmp_path / "out",
            work_dir=tmp_path / "work",
            config=get_default_config(),
        ),
        config=BanditScannerConfig(),
    )
    results = tmp_path / "bandit.sarif"
    results.write_bytes(b"\xef\xbb\xbf" + json.dumps(_repaired_report()).encode())

    raw = scanner._read_results_file(results)

    assert raw["runs"][0]["results"][0]["ruleId"] == "r-one"
    assert [e["code"] for e in scanner.output_ingest_record["elements"]] == ["bom"]


def test_the_control_without_the_ingest_step_the_report_is_lost(
    plugin_context, tmp_path
):
    """The same file, with the template reading it through the model alone."""
    scanner = _make_scanner(plugin_context, _repaired_report())

    with patch(
        "automated_security_helper.base.scanner_plugin.ingest_sarif",
        side_effect=lambda raw, record: SarifReport.model_validate(copy.deepcopy(raw)),
    ):
        with pytest.raises(ScannerError):
            _scan(scanner, tmp_path)
