# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The baseline a repository commits is scanned like any file; only the echoes of its own entries are dropped.

A baseline the scanned repository controls is handed to the worker as an
ordinary file, because leaving it out of the scan set let a repository hide
anything it put in a file of that name (``{"results": {}, "notes": "<key>"}``).
detect-secrets reads such a file as it reads any other, and it reads every
``hashed_secret`` the baseline lists twice: the hex detectors take the value
as a high-entropy string, and the keyword detector takes it as the value of a
key whose name contains ``secret``. The scan has to drop what those detectors
make of the entries and nothing else on the file, whichever detector made it.

The first group replaces the worker with a stand-in that returns findings of
several types on a hash the baseline lists. The second group runs the real
worker over a baseline with two entries, which is the only way to see what the
detectors really make of the file.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    HEX_HIGH_ENTROPY_TYPE,
    IS_BASELINE_FILE_FILTER,
    SHOULD_EXCLUDE_FILE_FILTER,
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
    DetectSecretsScanSettings,
    DetectSecretsScanSettingsFiltersUsed,
    _detect_secrets_api,
)

pytestmark = pytest.mark.usefixtures("no_tool_probes")

BASELINE_NAME = ".secrets.baseline"
# Assembled at runtime so this file holds no key-shaped literal for ASH's own
# self-scan to report. AWS's documentation placeholders.
LISTED_ONE = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002
LISTED_TWO = "".join(["AKIA", "I44QH8DHB", "EXAMPLE"])  # noqa: FLY002
PLANTED = "".join(["AKIA", "ZZZZZZZZZ", "EXAMPLE"])  # noqa: FLY002
AWS_RULE = "SECRET-AWS-ACCESS-KEY"

# The filter detect-secrets writes into every baseline it updates with
# ``--baseline``, naming the baseline: it skips every file of that name.
SKIP_BY_NAME = {"path": IS_BASELINE_FILE_FILTER, "filename": BASELINE_NAME}
# A pattern a baseline carries that matches the baseline's own name.
EXCLUDE_THE_BASELINE = {
    "path": SHOULD_EXCLUDE_FILE_FILTER,
    "pattern": [r"^\.secrets\.baseline$"],
}
UUID_FILTER = {"path": "detect_secrets.filters.heuristic.is_potential_uuid"}


def _hash(secret: str) -> str:
    from detect_secrets.core.potential_secret import PotentialSecret

    return PotentialSecret.hash_secret(secret)


def _context(tmp_path: Path) -> PluginContext:
    context = PluginContext(
        source_dir=tmp_path / "src",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.source_dir.mkdir(parents=True)
    context.output_dir.mkdir(parents=True)
    return context


def _write_baseline(
    source: Path,
    *,
    notes: str | None = None,
    filters_used: list | None = None,
    path: Path | None = None,
) -> str:
    """A baseline of the shape ``detect-secrets scan`` writes: two listed
    entries, one per line, and the detectors a repository ordinarily has on.
    ``filters_used`` is what the file carries as its filters, and ``path`` is
    the file it is written to (the tree's own, by default). Returns the text,
    so a test can find the line a key sits on."""
    document: dict = {
        "version": "1.5.0",
        "plugins_used": [
            {"name": "AWSKeyDetector"},
            {"name": "HexHighEntropyString", "limit": 3.0},
            {"name": "KeywordDetector", "keyword_exclude": ""},
        ],
        "filters_used": filters_used or [],
        "results": {
            "settings.py": [
                {
                    "type": "AWS Access Key",
                    "filename": "settings.py",
                    "hashed_secret": _hash(LISTED_ONE),
                    "is_verified": False,
                    "line_number": 1,
                },
                {
                    "type": "AWS Access Key",
                    "filename": "settings.py",
                    "hashed_secret": _hash(LISTED_TWO),
                    "is_verified": False,
                    "line_number": 2,
                },
            ]
        },
        "generated_at": "2026-01-01T00:00:00Z",
    }
    if notes is not None:
        document["notes"] = notes
    text = json.dumps(document, indent=2) + "\n"
    (path or source / BASELINE_NAME).write_text(text, encoding="utf-8")
    return text


def _on_the_baseline(report) -> list[tuple[str, int | None]]:
    """(rule id, line) of every finding located in the baseline file."""
    found = []
    for result in report.runs[0].results:
        location = result.locations[0].physicalLocation.root
        if location.artifactLocation.uri == BASELINE_NAME:
            found.append((result.ruleId, location.region.startLine))
    return sorted(found)


@pytest.mark.unit
@pytest.mark.parametrize(
    "echo_type",
    [HEX_HIGH_ENTROPY_TYPE, "Secret Keyword", "Base64 High Entropy String"],
)
def test_a_finding_on_a_listed_hash_is_dropped_whichever_detector_made_it(
    tmp_path, monkeypatch, echo_type
):
    """The finding the keyword detector makes on ``"hashed_secret": "<hex>"``
    is keyed by the hash of the hex, as the hex detectors' is. Both are the
    baseline's own entries read back, and neither is a finding. A value the
    baseline does not list, found by the same detector, stays: the drop is by
    the value, not by the type. Before, only the hex type was dropped, and every
    entry of a committed baseline came back as a keyword finding on the file."""
    from detect_secrets.core.potential_secret import PotentialSecret

    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    _write_baseline(source)
    listed = _hash(LISTED_ONE)
    unlisted = _hash(LISTED_TWO + "-not-listed")
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    assert scanner._baseline_in_use()
    assert scanner._baseline_entries_trusted() is False

    def scanned(self, *, baseline, scan_paths, scan_settings_dict, **kwargs):
        collection_cls, _, _ = _detect_secrets_api()
        collection = collection_cls()
        collection.root = self._secrets_collection.root
        for secret, line in ((listed, 9), (unlisted, 3)):
            collection[BASELINE_NAME].add(
                PotentialSecret(
                    echo_type, BASELINE_NAME, secret=secret, line_number=line
                )
            )
        return collection

    monkeypatch.setattr(type(scanner), "_scan_in_worker", scanned)

    report = scanner.scan(target=source, target_type="source")

    rule = "SECRET-" + "-".join(echo_type.upper().split())
    assert _on_the_baseline(report) == [(rule, 3)]


@pytest.mark.integration
def test_the_real_worker_reports_only_what_the_baseline_hides_in_a_key_of_its_own(
    tmp_path, monkeypatch
):
    """A baseline of two listed entries and a ``notes`` key holding a live key:
    the finding set on the file is exactly the key under ``notes``. The
    entries' echoes, from the hex detector and from the keyword detector, are
    not in it. Run by the real worker, because the detectors' reading of the
    file is the thing under test."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    text = _write_baseline(source, notes=PLANTED)
    line = next(
        number
        for number, content in enumerate(text.splitlines(), 1)
        if PLANTED in content
    )
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    assert scanner._baseline_in_use()
    assert scanner._baseline_entries_trusted() is False

    report = scanner.scan(target=source, target_type="source")

    assert report is not False
    assert _on_the_baseline(report) == [(AWS_RULE, line)]


@pytest.mark.integration
def test_the_real_worker_reports_nothing_on_a_baseline_that_only_lists(
    tmp_path, monkeypatch
):
    """The common case: a committed baseline of two entries and nothing else.
    Scanned by the real worker with the default detectors it reports nothing on
    the file, as it did before the baseline was scanned at all."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    _write_baseline(source)
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())

    report = scanner.scan(target=source, target_type="source")

    assert report is not False
    assert _on_the_baseline(report) == []


def _recording_worker(scanner, monkeypatch) -> dict:
    """Replace the worker with one that returns nothing and records what the
    scan handed it: the names of the files and the paths of the filters."""
    seen: dict = {}

    def scanned(self, *, baseline, scan_paths, scan_settings_dict, **kwargs):
        seen["names"] = sorted(Path(path).name for path in scan_paths)
        seen["filters"] = [
            item.get("path") for item in scan_settings_dict.get("filters_used", [])
        ]
        collection_cls, _, _ = _detect_secrets_api()
        collection = collection_cls()
        collection.root = self._secrets_collection.root
        return collection

    monkeypatch.setattr(type(scanner), "_scan_in_worker", scanned)
    return seen


@pytest.mark.unit
def test_the_filter_that_skips_files_by_name_is_not_taken_from_the_repositorys_baseline(
    tmp_path, monkeypatch
):
    """``detect-secrets scan --baseline`` writes ``is_baseline_file`` into the
    baseline, naming it, and the worker skips every file of that name. Read
    from a baseline the repository controls, the name is the repository's
    choice, so the file is in the scan set and never scanned. The worker is not
    handed the filter; the baseline's other filters still reach it."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    _write_baseline(source, filters_used=[SKIP_BY_NAME, UUID_FILTER])
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    assert scanner._baseline_entries_trusted() is False
    seen = _recording_worker(scanner, monkeypatch)

    scanner.scan(target=source, target_type="source")

    assert BASELINE_NAME in seen["names"]
    assert UUID_FILTER["path"] in seen["filters"]
    assert IS_BASELINE_FILE_FILTER not in seen["filters"]


@pytest.mark.unit
def test_the_operators_own_name_filter_still_reaches_the_worker(tmp_path, monkeypatch):
    """The same filter written in the operator's own settings is the operator's
    to use, and a baseline entry for the same path yields to it."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    _write_baseline(source, filters_used=[SKIP_BY_NAME])
    settings = DetectSecretsScanSettings(
        filters_used=[
            DetectSecretsScanSettingsFiltersUsed(
                path=IS_BASELINE_FILE_FILTER, filename="vendored.baseline"
            )
        ]
    )
    scanner = DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(scan_settings=settings)
        ),
    )
    seen = _recording_worker(scanner, monkeypatch)

    scanner.scan(target=source, target_type="source")

    assert seen["filters"].count(IS_BASELINE_FILE_FILTER) == 1


@pytest.mark.unit
def test_the_operators_own_baseline_keeps_its_name_filter(tmp_path, monkeypatch):
    """A baseline the operator names outside the tree is the operator's file,
    so what it carries is the operator's choice: the filter reaches the worker."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    baseline = tmp_path / "operator.baseline"
    _write_baseline(
        source,
        filters_used=[{"path": IS_BASELINE_FILE_FILTER, "filename": baseline.name}],
        path=baseline,
    )
    scanner = DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=str(baseline))
        ),
    )
    assert scanner._baseline_entries_trusted() is True
    seen = _recording_worker(scanner, monkeypatch)

    scanner.scan(target=source, target_type="source")

    assert IS_BASELINE_FILE_FILTER in seen["filters"]


@pytest.mark.unit
def test_a_pattern_in_the_repositorys_baseline_does_not_drop_the_baseline_from_the_scan(
    tmp_path, monkeypatch
):
    """The baseline's own ``should_exclude_file`` patterns leave files out of
    the scan set, and a repository could name the baseline itself. Its patterns
    apply to the other files and not to it."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    (source / "kept.py").write_text("x = 1\n", encoding="utf-8")
    (source / "skipped.py").write_text("x = 2\n", encoding="utf-8")
    _write_baseline(
        source,
        filters_used=[
            {
                "path": SHOULD_EXCLUDE_FILE_FILTER,
                "pattern": [r"^\.secrets\.baseline$", r"^skipped\.py$"],
            }
        ],
    )
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    assert scanner._baseline_entries_trusted() is False
    seen = _recording_worker(scanner, monkeypatch)

    scanner.scan(target=source, target_type="source")

    assert seen["names"] == [BASELINE_NAME, "kept.py"]


@pytest.mark.unit
def test_a_pattern_the_operator_wrote_still_drops_the_baseline_from_the_scan(
    tmp_path, monkeypatch
):
    """The operator's own exclusion patterns are theirs to write: one that names
    the repository's baseline leaves it out of the scan set."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    (source / "kept.py").write_text("x = 1\n", encoding="utf-8")
    _write_baseline(source)
    settings = DetectSecretsScanSettings(
        filters_used=[
            DetectSecretsScanSettingsFiltersUsed(
                path=SHOULD_EXCLUDE_FILE_FILTER, pattern=[r"^\.secrets\.baseline$"]
            )
        ]
    )
    scanner = DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(scan_settings=settings)
        ),
    )
    seen = _recording_worker(scanner, monkeypatch)

    scanner.scan(target=source, target_type="source")

    assert seen["names"] == ["kept.py"]


@pytest.mark.integration
@pytest.mark.parametrize(
    "filter_entry",
    [SKIP_BY_NAME, EXCLUDE_THE_BASELINE],
    ids=["skip_by_name", "exclude_pattern"],
)
def test_the_real_worker_reads_a_key_in_a_baseline_that_carries_a_filter_naming_itself(
    tmp_path, monkeypatch, filter_entry
):
    """A baseline that carries a filter naming itself, by file name or by
    exclusion pattern, with a live key under a key of its own. The real worker
    reports the key: the file is neither left out of the scan set nor skipped
    by the worker."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    text = _write_baseline(source, notes=PLANTED, filters_used=[filter_entry])
    line = next(
        number
        for number, content in enumerate(text.splitlines(), 1)
        if PLANTED in content
    )
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    assert scanner._baseline_entries_trusted() is False

    report = scanner.scan(target=source, target_type="source")

    assert report is not False
    assert _on_the_baseline(report) == [(AWS_RULE, line)]
