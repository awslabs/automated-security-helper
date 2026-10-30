# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A detect-secrets baseline marks its entries known; what happens to them depends on whose baseline it is.

A baseline is the record of the findings its author has seen: audited real and
kept, audited false positive, or since removed from the file. detect-secrets
reports against one only what it does not hold, by filename, hash and type.
The scanner loaded the baseline into the collection the worker scans with, and
then reported every entry of that collection as an error-level finding: each
baseline entry once as itself, and a secret still in its file a second time,
under the scan's spelling of the path. An entry without a line number (a
``--slim`` baseline's) became a SARIF region starting at line 0, which the model
refuses, and the whole scan failed.

A baseline's entries are a suppression surface, so whose file it is decides
what "known" does. The worker is never seeded with the baseline, so the scan's
own findings are the one copy of each candidate, at the scan's line. A baseline
the operator names (``baseline_file`` in the operator's own settings) may DROP
its known candidates from the report, as ``detect-secrets scan --baseline``
would. A baseline the scanned repository controls, its own in-tree
``.secrets.baseline``, may only MARK: its known candidates stay in the report
suppressed with the baseline named as the reason, so the count stays visible
and a repository cannot hide a secret still in its files by listing the hash in
a file it commits. Under either baseline an entry audited as a real secret
(``is_secret: true``) that is still in the file is reported as an ordinary
finding: the record of a confirmed secret does not clear it. The worker is told
the same answer as ``baseline_trusted`` in its request, so its own drop of
accepted entries, for a request that carries a baseline, follows the rule.

The scan is driven in-process: ``_scan_in_worker`` is replaced by a stand-in
that returns what the worker returns, the baseline's entries (when it is
handed one) plus the scan's; one test runs the real ``_scan_in_worker`` against
a process runner stand-in to read the request it writes.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
)

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]

SECRET_TYPE = "AWS Access Key"
# Assembled at runtime so this file holds no key-shaped literal for ASH's own
# self-scan to report. AWS's documentation placeholders.
KEPT_SECRET = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002
GONE_SECRET = "".join(["AKIA", "I44QH8DHB", "EXAMPLE"])  # noqa: FLY002
NEW_SECRET = "".join(["AKIA", "ZZZZZZZZZ", "EXAMPLE"])  # noqa: FLY002


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


def _baseline(entries: dict) -> dict:
    return {
        "version": "1.5.0",
        "plugins_used": [{"name": "AWSKeyDetector"}],
        "filters_used": [],
        "results": entries,
        "generated_at": "2026-01-01T00:00:00Z",
    }


def _scanner_with_baseline(
    tmp_path, monkeypatch, entries: dict, *, operator_named: bool = False
):
    """A scanner over a tree of two files, with a baseline holding ``entries``.

    ``operator_named`` puts the baseline outside the tree and names it through
    the ``baseline_file`` option (the operator's own settings here: the default
    config carries no repository files), which is the trusted shape. Otherwise
    the baseline is the tree's own ``.secrets.baseline``, the repository's.
    """
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    (source / "settings.py").write_text(f"KEY = '{KEPT_SECRET}'\n", encoding="utf-8")
    (source / "other.py").write_text(f"KEY = '{NEW_SECRET}'\n", encoding="utf-8")
    if operator_named:
        baseline = tmp_path / "operator.baseline"
        config = DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=str(baseline))
        )
    else:
        baseline = source / ".secrets.baseline"
        config = DetectSecretsScannerConfig()
    baseline.write_text(json.dumps(_baseline(entries)), encoding="utf-8")
    scanner = DetectSecretsScanner(context=context, config=config)
    assert scanner._baseline_in_use()
    assert scanner._baseline_entries_trusted() is operator_named
    return scanner, source


def _worker_returning(scanner, monkeypatch, found: dict):
    """A worker that returns the baseline's entries plus ``found``.

    ``found`` maps a path relative to the source to the secrets the scan found
    in it, keyed as a multi-file scan keys them: relative to the root.
    """
    from detect_secrets.core.potential_secret import PotentialSecret

    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        _detect_secrets_api,
    )

    def scanned(self, *, baseline, scan_paths, scan_settings_dict, **kwargs):
        collection_cls, _, _ = _detect_secrets_api()
        collection = (
            collection_cls.load_from_baseline(baseline=baseline)
            if baseline is not None
            else collection_cls()
        )
        collection.root = self._secrets_collection.root
        for relative, secrets in found.items():
            for line, secret in secrets:
                collection[relative].add(
                    PotentialSecret(
                        SECRET_TYPE, relative, secret=secret, line_number=line
                    )
                )
        return collection

    monkeypatch.setattr(type(scanner), "_scan_in_worker", scanned)


def _findings(report) -> list[tuple[str, int | None]]:
    return sorted(
        (
            result.locations[0].physicalLocation.root.artifactLocation.uri,
            result.locations[0].physicalLocation.root.region.startLine,
        )
        for result in report.runs[0].results
    )


def _suppressed(report) -> dict[str, list[str]]:
    """URI -> the justifications of its suppressions ([] for an unsuppressed finding)."""
    return {
        result.locations[0].physicalLocation.root.artifactLocation.uri: [
            item.justification for item in (result.suppressions or [])
        ]
        for result in report.runs[0].results
    }


KNOWN_ENTRIES = {
    "settings.py": [
        # Audited as a false positive, still in the file.
        {
            "type": SECRET_TYPE,
            "hashed_secret": _hash(KEPT_SECRET),
            "line_number": 1,
            "is_secret": False,
        },
        # Audited as real, since removed from the file.
        {
            "type": SECRET_TYPE,
            "hashed_secret": _hash(GONE_SECRET),
            "line_number": 7,
            "is_secret": True,
        },
    ]
}


def test_the_repositorys_baseline_entries_stay_in_the_report_as_suppressed(
    tmp_path, monkeypatch
):
    """The tree's own baseline lists the secret still in settings.py. It is
    reported, at the scan's line, marked suppressed with the baseline as the
    reason; the entry whose secret left the file is not reported at all; the
    new secret is an ordinary finding."""
    scanner, source = _scanner_with_baseline(tmp_path, monkeypatch, KNOWN_ENTRIES)
    _worker_returning(
        scanner,
        monkeypatch,
        {"settings.py": [(1, KEPT_SECRET)], "other.py": [(1, NEW_SECRET)]},
    )

    report = scanner.scan(target=source, target_type="source")

    assert _findings(report) == [("other.py", 1), ("settings.py", 1)]
    suppressed = _suppressed(report)
    assert suppressed["other.py"] == []
    (reason,) = suppressed["settings.py"]
    assert ".secrets.baseline" in reason
    assert "repository controls" in reason
    assert "baseline_file" in reason


@pytest.mark.parametrize("operator_named", [True, False], ids=["operator", "repo"])
def test_the_worker_is_never_seeded_with_the_baseline(
    tmp_path, monkeypatch, operator_named
):
    """The worker gets no baseline to load, whoever's it is, so a listed secret
    that left its file cannot come back as a finding at the baseline's stale
    line, and a secret still in its file is found once, at the scan's line.
    The operator's baseline used to be handed over and its entries then removed
    from the report, audited real or not."""
    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        _detect_secrets_api,
    )

    seen = {}

    def record(self, *, baseline, **kwargs):
        seen["baseline"] = baseline
        collection_cls, _, _ = _detect_secrets_api()
        collection = collection_cls()
        collection.root = self._secrets_collection.root
        return collection

    scanner, source = _scanner_with_baseline(
        tmp_path, monkeypatch, KNOWN_ENTRIES, operator_named=operator_named
    )
    monkeypatch.setattr(type(scanner), "_scan_in_worker", record)
    scanner.scan(target=source, target_type="source")
    assert seen["baseline"] is None


def test_the_operators_baseline_entries_leave_the_report_and_a_new_secret_stays(
    tmp_path, monkeypatch
):
    """The operator's baseline: a listed candidate still in its file leaves the
    report, the entry whose secret left the file is not reported (the worker
    was not seeded with it), and a new secret is reported as before."""
    scanner, source = _scanner_with_baseline(
        tmp_path, monkeypatch, KNOWN_ENTRIES, operator_named=True
    )
    _worker_returning(
        scanner,
        monkeypatch,
        {"settings.py": [(1, KEPT_SECRET)], "other.py": [(1, NEW_SECRET)]},
    )

    report = scanner.scan(target=source, target_type="source")

    assert _findings(report) == [("other.py", 1)]
    assert _suppressed(report)["other.py"] == []


@pytest.mark.parametrize("operator_named", [True, False], ids=["operator", "repo"])
def test_the_worker_is_told_whose_baseline_the_scan_runs_under(
    tmp_path, monkeypatch, operator_named
):
    """The request the real ``_scan_in_worker`` writes carries
    ``baseline_trusted``: true for the operator's baseline, false for the
    repository's, and no baseline either way. The worker drops an entry the
    baseline accepted only when the flag is true, so a request with the flag
    absent or false can only mark."""
    from automated_security_helper.utils import subprocess_utils

    scanner, source = _scanner_with_baseline(
        tmp_path, monkeypatch, KNOWN_ENTRIES, operator_named=operator_named
    )
    requests: list[dict] = []

    def record(*, command, **_kwargs):
        requests.append(json.loads(Path(command[-2]).read_text(encoding="utf-8")))
        Path(command[-1]).write_text("[]", encoding="utf-8")
        return {"returncode": 0, "timed_out": False, "stdout": "", "stderr": ""}

    monkeypatch.setattr(subprocess_utils, "run_command_with_output_handling", record)

    scanner.scan(target=source, target_type="source")

    assert len(requests) == 1, requests
    assert requests[0]["baseline"] is None
    assert requests[0]["baseline_trusted"] is operator_named


@pytest.mark.parametrize("operator_named", [True, False], ids=["operator", "repo"])
def test_an_entry_audited_as_a_real_secret_is_reported_unsuppressed(
    tmp_path, monkeypatch, operator_named
):
    """The baseline audits the secret still in settings.py as real
    (``is_secret: true``). Whoever's baseline it is, the candidate is reported
    as an ordinary finding, with no suppression: the record of a confirmed
    secret does not clear it. Before, the operator's baseline removed it and
    the repository's marked it suppressed."""
    scanner, source = _scanner_with_baseline(
        tmp_path,
        monkeypatch,
        {
            "settings.py": [
                {
                    "type": SECRET_TYPE,
                    "hashed_secret": _hash(KEPT_SECRET),
                    "line_number": 1,
                    "is_secret": True,
                },
            ]
        },
        operator_named=operator_named,
    )
    _worker_returning(scanner, monkeypatch, {"settings.py": [(1, KEPT_SECRET)]})

    report = scanner.scan(target=source, target_type="source")

    assert _findings(report) == [("settings.py", 1)]
    assert _suppressed(report)["settings.py"] == []


@pytest.mark.parametrize("operator_named", [True, False], ids=["operator", "repo"])
def test_a_baseline_entry_without_a_line_number_fails_nothing(
    tmp_path, monkeypatch, operator_named
):
    """A ``--slim`` baseline records no line numbers. Its entry is known: the
    operator's removes the finding, the repository's keeps it at the scan's own
    line, suppressed. Before, the entry became a region at line 0 and failed the
    scan, whichever baseline it came from."""
    scanner, source = _scanner_with_baseline(
        tmp_path,
        monkeypatch,
        {
            "settings.py": [
                {"type": SECRET_TYPE, "hashed_secret": _hash(KEPT_SECRET)},
            ]
        },
        operator_named=operator_named,
    )
    _worker_returning(scanner, monkeypatch, {"settings.py": [(1, KEPT_SECRET)]})

    report = scanner.scan(target=source, target_type="source")

    if operator_named:
        assert _findings(report) == []
    else:
        assert _findings(report) == [("settings.py", 1)]
        assert len(_suppressed(report)["settings.py"]) == 1


def test_without_a_baseline_every_secret_is_reported(tmp_path, monkeypatch):
    """Control: the known set is empty when no baseline is in use."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    (source / "settings.py").write_text(f"KEY = '{KEPT_SECRET}'\n", encoding="utf-8")
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    assert not scanner._baseline_in_use()
    _worker_returning(scanner, monkeypatch, {"settings.py": [(1, KEPT_SECRET)]})

    report = scanner.scan(target=source, target_type="source")

    assert _findings(report) == [("settings.py", 1)]
