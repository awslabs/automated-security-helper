# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A scan-set list in the output directory is read back only by the run that wrote it.

``scan_set`` writes the scan set to ``ash-scan-set-files-list.txt`` and the ignore
rules to ``ash-ignore-report.txt`` in the output directory, and every later caller in
the run reads them back instead of walking the tree again. Reading whatever pair is
found there would also read one an earlier run left, or one a repository committed
to its ``.ash/ash_output``, and a committed list naming one file would make
detect-secrets scan that file alone.

Each scan has a run ID (``ASHScanOrchestrator``, carried to the plugins on
``PluginContext.run_id``). ``scan_set`` records it, with the SHA-256 of both files,
in ``ash-scan-set-run.json`` beside them, and reads the pair back only for a caller
that passes the same ID and only while both files are as written. Any other caller
walks the tree.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path
from unittest.mock import patch

import pytest

import automated_security_helper
from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.utils import get_scan_set as gss
from automated_security_helper.utils.get_scan_set import scan_set
from automated_security_helper.utils.scan_output_dirs import tracked_files_in
from tests.unit.workspace.test_execution import _git

AshConfig.model_rebuild()
PluginContext.model_rebuild()

#: The scanner built here starts no tool (tests/unit/conftest.py).
pytestmark = pytest.mark.usefixtures("no_tool_probes")

IGNORE_REPORT = "ash-ignore-report.txt"
SCAN_SET_LIST = "ash-scan-set-files-list.txt"
RUN_RECORD = "ash-scan-set-run.json"
RUN_A = "a" * 32
RUN_B = "b" * 32


def _tree(tmp_path: Path) -> tuple[Path, Path]:
    source = tmp_path / "src"
    source.mkdir()
    for name in ("app.py", "other.py"):
        (source / name).write_text("x = 1\n", encoding="utf-8")
    return source, tmp_path / "out"


def _names(files) -> set[str]:
    return {Path(f).name for f in files}


def _plant_lists(output: Path, listed) -> None:
    """The pair an earlier run, or a commit, leaves in the output directory."""
    output.mkdir(parents=True, exist_ok=True)
    (output / IGNORE_REPORT).write_text(
        "######### START CONTENTS: ASH_INCLUSIONS #########\n", encoding="utf-8"
    )
    (output / SCAN_SET_LIST).write_text(
        "\n".join(str(path) for path in listed), encoding="utf-8"
    )


def _no_walk():
    return patch.object(
        gss,
        "_collect_ignorefiles_and_all_files",
        side_effect=AssertionError("walked the tree"),
    )


@pytest.mark.unit
def test_a_list_left_in_the_output_dir_does_not_decide_the_scan_set(tmp_path):
    source, output = _tree(tmp_path)
    _plant_lists(output, [source / "app.py"])

    found = scan_set(source=str(source), output=str(output))

    assert _names(found) == {"app.py", "other.py"}


@pytest.mark.unit
def test_a_list_another_run_wrote_is_not_read(tmp_path):
    source, output = _tree(tmp_path)
    scan_set(source=str(source), output=str(output), run_id=RUN_A)
    (source / "new.py").write_text("n = 1\n", encoding="utf-8")

    found = scan_set(source=str(source), output=str(output), run_id=RUN_B)

    assert _names(found) == {"app.py", "other.py", "new.py"}
    assert json.loads((output / RUN_RECORD).read_text())["run_id"] == RUN_B


@pytest.mark.unit
def test_the_list_this_run_wrote_is_read_back_without_a_walk(tmp_path):
    source, output = _tree(tmp_path)
    written = scan_set(source=str(source), output=str(output), run_id=RUN_A)
    (source / "new.py").write_text("n = 1\n", encoding="utf-8")

    with _no_walk():
        found = scan_set(source=str(source), output=str(output), run_id=RUN_A)

    assert found == written
    assert _names(found) == {"app.py", "other.py"}


@pytest.mark.unit
@pytest.mark.parametrize("changed", [SCAN_SET_LIST, IGNORE_REPORT])
def test_a_list_changed_after_this_run_wrote_it_is_not_read(tmp_path, changed):
    source, output = _tree(tmp_path)
    scan_set(source=str(source), output=str(output), run_id=RUN_A)
    path = output / changed
    path.write_text(path.read_text() + "\n# changed\n", encoding="utf-8")
    (source / "new.py").write_text("n = 1\n", encoding="utf-8")

    found = scan_set(source=str(source), output=str(output), run_id=RUN_A)

    assert _names(found) == {"app.py", "other.py", "new.py"}


@pytest.mark.unit
@pytest.mark.parametrize(
    "record",
    [
        "not json",
        json.dumps(["a list"]),
        json.dumps({"run_id": RUN_A}),
        json.dumps({"run_id": RUN_A, "sha256": "not a mapping"}),
    ],
)
def test_a_damaged_run_record_is_not_trusted(tmp_path, record):
    source, output = _tree(tmp_path)
    scan_set(source=str(source), output=str(output), run_id=RUN_A)
    (output / RUN_RECORD).write_text(record, encoding="utf-8")
    (source / "new.py").write_text("n = 1\n", encoding="utf-8")

    found = scan_set(source=str(source), output=str(output), run_id=RUN_A)

    assert "new.py" in _names(found)


@pytest.mark.unit
def test_the_run_record_names_the_run_and_the_digest_of_each_file(tmp_path):
    import hashlib

    source, output = _tree(tmp_path)
    scan_set(source=str(source), output=str(output), run_id=RUN_A)

    record = json.loads((output / RUN_RECORD).read_text())
    assert record["run_id"] == RUN_A
    for name in (IGNORE_REPORT, SCAN_SET_LIST):
        digest = hashlib.sha256((output / name).read_bytes()).hexdigest()
        assert record["sha256"][name] == digest, name


@pytest.mark.integration
def test_a_committed_list_does_not_decide_what_detect_secrets_scans(tmp_path):
    """A repository commits a list naming one file to its default output
    directory; detect-secrets, run on its own, does not read it and walks the
    tree."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScanner,
        DetectSecretsScannerConfig,
    )
    from tests.unit.plugin_modules.ash_builtin.test_detect_secrets_scanner_behavior import (
        PLANTED_KEY,
    )

    source = tmp_path / "repo"
    output = source / ".ash" / "ash_output"
    secret = f"AWS_ACCESS_KEY_ID = '{PLANTED_KEY}'\n"
    for name in ("settings.py", "config.py"):
        (source / name).parent.mkdir(parents=True, exist_ok=True)
        (source / name).write_text(secret, encoding="utf-8")
    _plant_lists(output, [source / "settings.py"])
    assert _git(source, "init", "-q").returncode == 0
    added = _git(
        source,
        "add",
        "settings.py",
        "config.py",
        f".ash/ash_output/{IGNORE_REPORT}",
        f".ash/ash_output/{SCAN_SET_LIST}",
    )
    assert added.returncode == 0, added.stderr
    # A control: git tracks the planted pair, so the pair is a committed one.
    assert sorted(tracked_files_in(output) or []) == [
        output / IGNORE_REPORT,
        output / SCAN_SET_LIST,
    ]
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=AshConfig(),
    )
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())

    report = scanner.scan(target=source, target_type="source")

    uris = {
        r.locations[0].physicalLocation.root.artifactLocation.uri
        for r in report.runs[0].results
    }
    assert uris == {"settings.py", "config.py"}, uris


@pytest.mark.unit
def test_a_scanner_reads_back_the_list_its_run_wrote(tmp_path):
    from automated_security_helper.utils.scan_output_dirs import scan_set_of

    source, output = _tree(tmp_path)
    context = PluginContext(
        source_dir=source, output_dir=output, config=AshConfig(), run_id=RUN_A
    )
    written = scan_set(source=str(source), output=str(output), run_id=RUN_A)

    with _no_walk():
        assert scan_set_of(context) == written


class _EngineStub:
    def __init__(self, context):
        from automated_security_helper.models.asharp_model import AshAggregatedResults

        self.context = context
        self._asharp_model = AshAggregatedResults()

    def execute_phases(self, phases=None):
        return self._asharp_model


def _scanned_by_orchestrator(source: Path, output: Path):
    from automated_security_helper.core.orchestrator import ASHScanOrchestrator

    orchestrator = ASHScanOrchestrator(
        source_dir=source,
        output_dir=output,
        config_path=None,
        config_overrides=None,
        no_cleanup=True,
        metadata=None,
        ash_plugin_modules=[],
    )
    with (
        patch(
            "automated_security_helper.core.orchestrator.resolve_config",
            return_value=AshConfig(project_name="test"),
        ),
        patch(
            "automated_security_helper.core.orchestrator.ScanExecutionEngine",
            side_effect=lambda **kwargs: _EngineStub(kwargs["context"]),
        ),
    ):
        orchestrator.initialize()
        orchestrator.execute_scan(phases=["scan"])
    return orchestrator.execution_engine.context


@pytest.mark.unit
def test_each_scan_writes_its_list_under_its_own_run_id(tmp_path, monkeypatch):
    """The ID the plugins get is the one the orchestrator wrote the list under, and
    two scans get two IDs, so neither reads the other's list."""
    monkeypatch.chdir(tmp_path)
    source, output = _tree(tmp_path)

    first = _scanned_by_orchestrator(source, output)
    record = json.loads((output / RUN_RECORD).read_text())
    second = _scanned_by_orchestrator(source, output)

    assert re.fullmatch(r"[0-9a-f]{32}", first.run_id or ""), first.run_id
    assert record["run_id"] == first.run_id
    assert second.run_id != first.run_id
    with _no_walk():
        assert _names(
            scan_set(source=str(source), output=str(output), run_id=second.run_id)
        ) == {"app.py", "other.py"}


@pytest.mark.unit
def test_every_call_to_scan_set_in_ash_passes_its_runs_id():
    """A caller that does not pass the ID walks the tree on every call. Each one in
    ASH has the plugin context, or is the orchestrator, so each passes it."""
    package = Path(automated_security_helper.__file__).parent
    missing = []
    for path in sorted(package.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            if name != "scan_set" or path.name == "get_scan_set.py":
                continue
            if not any(keyword.arg == "run_id" for keyword in node.keywords):
                missing.append(f"{path.relative_to(package)}:{node.lineno}")
    assert not missing, missing
