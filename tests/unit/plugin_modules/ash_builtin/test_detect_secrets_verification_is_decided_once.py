# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Whether detect-secrets verifies is one reading, wherever it is asked.

Three places decide it: ``sandbox_requirements`` (does the sandbox need a
network), ``_apply_settings_trust`` (may this scan verify at all) and ``scan``
(is the worker told to verify). The first two read the settings model, whose
filter entries carry a ``path`` attribute; the third reads the dictionary dumped
for the worker, whose entries are mappings. Each used to spell the check for
its own shape, and the spellings could drift: a sandbox asked for no network
while the worker was told to verify, or the reverse. ``_verifies`` is the one
helper every site calls, and it reads both shapes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScanSettingsFiltersUsed,
)

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]

MODULE_SPELLING = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)
FILE_SPELLING = "file:///opt/filters/mine.py::is_ignored_due_to_verification_policies"
HEURISTIC = "detect_secrets.filters.heuristic.is_potential_uuid"


@pytest.mark.parametrize("spelling", [MODULE_SPELLING, FILE_SPELLING])
def test_model_entries_and_dumped_entries_read_the_same(spelling):
    model = [
        DetectSecretsScanSettingsFiltersUsed(path=HEURISTIC),
        DetectSecretsScanSettingsFiltersUsed(path=spelling, min_level=2),
    ]
    dumped = [item.model_dump(exclude_none=True) for item in model]

    assert DetectSecretsScanner._verifies(model) is True
    assert DetectSecretsScanner._verifies(dumped) is True
    assert DetectSecretsScanner._verifies(model) is DetectSecretsScanner._verifies(
        dumped
    )


def test_settings_without_the_filter_do_not_verify_in_either_shape():
    model = [DetectSecretsScanSettingsFiltersUsed(path=HEURISTIC)]
    dumped = [item.model_dump(exclude_none=True) for item in model]

    assert DetectSecretsScanner._verifies(model) is False
    assert DetectSecretsScanner._verifies(dumped) is False


def test_entries_of_no_known_shape_enable_nothing():
    # No filters, an entry with no path, a path that is not a string, and a
    # bare string (which has neither a ``path`` attribute nor a ``path`` key):
    # none of them is read as the verification filter.
    assert DetectSecretsScanner._verifies(None) is False
    assert DetectSecretsScanner._verifies([]) is False
    assert DetectSecretsScanner._verifies([{}]) is False
    assert DetectSecretsScanner._verifies([{"path": None}]) is False
    assert DetectSecretsScanner._verifies([{"path": 7}]) is False
    assert DetectSecretsScanner._verifies([MODULE_SPELLING]) is False


@pytest.mark.parametrize(
    ("case", "expected"),
    [
        ("operator_filter", True),
        ("no_filter", False),
        ("offline", False),
        ("operator_baseline", True),
        ("repository_baseline", False),
    ],
)
def test_sandbox_requirements_and_the_worker_decision_agree(
    tmp_path, monkeypatch, case, expected
):
    """The real ``scan`` writes the worker's request; its ``verify`` flag and
    the filters it dumps agree with ``sandbox_requirements.network``. The
    request is read from the file the scanner hands the process runner, so the
    test cannot drift from how ``scan`` builds it.

    The filter reaches the settings from five places, and the three readings
    must agree for each: the operator's own settings name it (network and
    verify on); nothing names it (both off); offline mode, which drops it
    whatever its source (both off); a baseline the operator names outside the
    tree, which the operator's trust admits (both on); and the tree's own
    committed baseline, which the repository wrote and trust refuses (both
    off)."""
    from automated_security_helper.base.plugin_context import PluginContext
    from automated_security_helper.config.default_config import get_default_config
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        DetectSecretsScannerConfig,
        DetectSecretsScannerConfigOptions,
        DetectSecretsScanSettings,
    )
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        DetectSecretsScanner, "_scanner_offline", lambda self: case == "offline"
    )
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    (context.source_dir / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    baseline = {
        "version": "1.5.0",
        "plugins_used": [{"name": "AWSKeyDetector"}],
        "filters_used": [{"path": MODULE_SPELLING, "min_level": 2}],
        "results": {},
        "generated_at": "2026-01-01T00:00:00Z",
    }
    if case in ("operator_filter", "offline", "no_filter"):
        path = HEURISTIC if case == "no_filter" else MODULE_SPELLING
        options = DetectSecretsScannerConfigOptions(
            scan_settings=DetectSecretsScanSettings(
                plugins_used=[{"name": "AWSKeyDetector"}],
                filters_used=[{"path": path, "min_level": 2}],
            )
        )
    elif case == "operator_baseline":
        named = tmp_path / "operator.baseline"
        named.write_text(json.dumps(baseline), encoding="utf-8")
        options = DetectSecretsScannerConfigOptions(baseline_file=str(named))
    else:
        (context.source_dir / ".secrets.baseline").write_text(
            json.dumps(baseline), encoding="utf-8"
        )
        options = DetectSecretsScannerConfigOptions()
    scanner = DetectSecretsScanner(
        context=context, config=DetectSecretsScannerConfig(options=options)
    )
    assert scanner._verification_permitted is expected, (
        "precondition: the settings' source decides whether verification is on"
    )
    requests: list[dict] = []

    def record(*, command, **_kwargs):
        requests.append(json.loads(Path(command[-2]).read_text(encoding="utf-8")))
        Path(command[-1]).write_text("[]", encoding="utf-8")
        return {"returncode": 0, "timed_out": False, "stdout": "", "stderr": ""}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", record)

    scanner.scan(target=context.source_dir, target_type="source")

    assert len(requests) == 1, requests
    request = requests[0]
    filters = request["settings"].get("filters_used", [])
    assert scanner.sandbox_requirements.network is expected
    assert request["verify"] is expected
    assert DetectSecretsScanner._verifies(filters) is expected
    assert scanner.sandbox_requirements.network is request["verify"]
