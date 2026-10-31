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
import os
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    SHOULD_EXCLUDE_FILE_FILTER,
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
    DetectSecretsScanSettings,
    DetectSecretsScanSettingsFiltersUsed,
)

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]

SECRET_TYPE = "AWS Access Key"
# The filter detect-secrets writes into every baseline it generates; it sends
# each candidate to the service that issued it, so only the operator's own
# settings may turn it on.
VERIFICATION_FILTER = (
    "detect_secrets.filters.common.is_ignored_due_to_verification_policies"
)
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
@pytest.mark.parametrize("mismatch", ["other_file", "other_type"])
def test_a_baseline_entry_matches_only_its_own_file_and_type(
    tmp_path, monkeypatch, operator_named, mismatch
):
    """A known candidate is keyed by file, hash and type. The baseline lists
    the kept secret's hash, but under ``other.py`` or under another detector's
    type, so the finding in ``settings.py`` is not known: it is reported, and
    carries no suppression, whoever's baseline it is. A rule that matched on
    the hash alone would drop it (operator) or mark it (repository)."""
    entry = {
        "type": SECRET_TYPE,
        "hashed_secret": _hash(KEPT_SECRET),
        "line_number": 1,
        "is_secret": False,
    }
    if mismatch == "other_file":
        entries = {"other.py": [entry]}
    else:
        entries = {"settings.py": [{**entry, "type": "Secret Keyword"}]}
    scanner, source = _scanner_with_baseline(
        tmp_path, monkeypatch, entries, operator_named=operator_named
    )
    _worker_returning(scanner, monkeypatch, {"settings.py": [(1, KEPT_SECRET)]})

    report = scanner.scan(target=source, target_type="source")

    assert _findings(report) == [("settings.py", 1)]
    assert _suppressed(report)["settings.py"] == []


@pytest.mark.parametrize("inside", [True, False], ids=["inside-the-tree", "outside"])
def test_a_baseline_the_operator_names_inside_the_scanned_tree_only_marks(
    tmp_path, monkeypatch, inside
):
    """An org-wide ``baseline_file: .secrets.baseline`` names each repository's
    own committed baseline. The operator wrote the name, but the file is the
    repository's, so its entries may mark a candidate and never remove it;
    the settings-trust rule already reads the file that way. Named outside the
    tree and its checkout, the same baseline removes its candidates (the
    control)."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    (source / "settings.py").write_text(f"KEY = '{KEPT_SECRET}'\n", encoding="utf-8")
    (source / "other.py").write_text(f"KEY = '{NEW_SECRET}'\n", encoding="utf-8")
    if inside:
        baseline = source / ".secrets.baseline"
        name = ".secrets.baseline"
    else:
        baseline = tmp_path / "operator.baseline"
        name = str(baseline)
    baseline.write_text(json.dumps(_baseline(KNOWN_ENTRIES)), encoding="utf-8")
    scanner = DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=name)
        ),
    )
    assert scanner._baseline_in_use()
    assert scanner._baseline_from_option is True
    assert scanner._baseline_entries_trusted() is (not inside)
    _worker_returning(
        scanner,
        monkeypatch,
        {"settings.py": [(1, KEPT_SECRET)], "other.py": [(1, NEW_SECRET)]},
    )

    report = scanner.scan(target=source, target_type="source")

    if inside:
        assert _findings(report) == [("other.py", 1), ("settings.py", 1)]
        (reason,) = _suppressed(report)["settings.py"]
        assert "repository controls" in reason
    else:
        assert _findings(report) == [("other.py", 1)]


@pytest.mark.parametrize("spelling", ["in_tree", "linked_name"])
def test_a_repository_baseline_is_scanned_and_only_its_hash_echoes_are_dropped(
    tmp_path, monkeypatch, spelling
):
    """The tree's own baseline is handed to the worker like any file. The
    entropy detectors read each ``hashed_secret`` it lists, and those findings
    (the hex type, on a value the baseline lists) are dropped; a hex string it
    does not list and a key under an extra top-level key are reported. Left out
    of the scan set, a repository could hide a key under a key of its own.

    The ``linked_name`` spelling has the operator name a path outside the tree
    that is a link to the tree's baseline: the file read is the repository's
    under either name, so it is scanned, and its echoes are dropped, the same."""
    from detect_secrets.core.potential_secret import PotentialSecret

    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        HEX_HIGH_ENTROPY_TYPE,
        _detect_secrets_api,
    )

    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    (source / "settings.py").write_text(f"KEY = '{KEPT_SECRET}'\n", encoding="utf-8")
    listed = _hash(KEPT_SECRET)
    unlisted = _hash(GONE_SECRET)
    document = _baseline(
        {
            "settings.py": [
                {
                    "type": SECRET_TYPE,
                    "hashed_secret": listed,
                    "line_number": 1,
                    "is_secret": False,
                }
            ]
        }
    )
    document["notes"] = NEW_SECRET
    (source / ".secrets.baseline").write_text(json.dumps(document), encoding="utf-8")
    config = DetectSecretsScannerConfig()
    if spelling == "linked_name":
        link = tmp_path / "ci" / "proj.baseline"
        link.parent.mkdir()
        try:
            link.symlink_to(source / ".secrets.baseline")
        except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
            pytest.skip(f"symlinks unavailable on this platform: {exc}")
        config = DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=str(link))
        )
    scanner = DetectSecretsScanner(context=context, config=config)
    assert scanner._baseline_in_use()
    assert scanner._baseline_entries_trusted() is False

    seen: dict = {}

    def scanned(self, *, baseline, scan_paths, scan_settings_dict, **kwargs):
        seen["names"] = sorted(Path(path).name for path in scan_paths)
        collection_cls, _, _ = _detect_secrets_api()
        collection = collection_cls()
        collection.root = self._secrets_collection.root
        name = ".secrets.baseline"
        for kind, secret, line in (
            (HEX_HIGH_ENTROPY_TYPE, listed, 9),
            (HEX_HIGH_ENTROPY_TYPE, unlisted, 3),
            (SECRET_TYPE, NEW_SECRET, 2),
        ):
            collection[name].add(
                PotentialSecret(kind, name, secret=secret, line_number=line)
            )
        return collection

    monkeypatch.setattr(type(scanner), "_scan_in_worker", scanned)

    report = scanner.scan(target=source, target_type="source")

    assert ".secrets.baseline" in seen["names"]
    assert _findings(report) == [(".secrets.baseline", 2), (".secrets.baseline", 3)]


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


def test_the_repositorys_baseline_is_never_the_operators_whatever_the_scan_root(
    tmp_path, monkeypatch
):
    """A baseline the scan found in the tree may only mark, by structure.

    The answer used to fall through to the settings-trust rule for a baseline
    that did not come from the ``baseline_file`` option. That rule reads the
    configured scan root (``_scanned_root``, the workspace root in workspace
    mode), and when that root did not hold the source directory and no other
    checkout did, it found nothing to say against the tree's own
    ``.secrets.baseline`` and read it as the operator's: its known candidates
    left the report. Now a baseline the operator did not name is never trusted,
    and the configured root changes nothing.

    The same structural rule holds for the baseline's SETTINGS: the file
    carries the verification filter detect-secrets writes into every baseline
    it generates, and under the same configured root the settings-trust rule
    read it as the operator's too, so candidate secrets would have been sent
    to the services that issued them. Offline mode would drop the filter
    whatever its source, so it is off here."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    (source / "settings.py").write_text(f"KEY = '{KEPT_SECRET}'\n", encoding="utf-8")
    document = _baseline(KNOWN_ENTRIES)
    document["filters_used"] = [{"path": VERIFICATION_FILTER, "min_level": 2}]
    (source / ".secrets.baseline").write_text(json.dumps(document), encoding="utf-8")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    context.config._scanned_root = elsewhere

    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())

    assert scanner._baseline_in_use()
    assert scanner._baseline_entries_trusted() is False
    reason = scanner._untrusted_baseline_reason(None)
    assert reason is not None and "found in the scanned tree" in reason, reason
    assert not any(
        item.path == VERIFICATION_FILTER
        for item in scanner.config.options.scan_settings.filters_used
    ), scanner.config.options.scan_settings.filters_used
    assert scanner._verification_permitted is False
    _worker_returning(scanner, monkeypatch, {"settings.py": [(1, KEPT_SECRET)]})
    report = scanner.scan(target=source, target_type="source")
    assert _findings(report) == [("settings.py", 1)]
    assert len(_suppressed(report)["settings.py"]) == 1


def test_a_baseline_in_an_enclosing_checkout_is_read_relative_to_its_own_directory(
    tmp_path, monkeypatch
):
    """A monorepo: ``repo/service`` is scanned and its ``.secrets.baseline`` is a
    link to the checkout's own ``repo/.secrets.baseline``, which detect-secrets
    wrote from ``repo``: its result keys read ``service/settings.py`` and its
    ``should_exclude_file`` pattern ``^service/tests/``. Matched relative to the
    scanned subdirectory, no key met a finding (the listed candidate was
    reported unsuppressed) and no pattern met a file (``service/tests`` was
    scanned). Both are now matched relative to the baseline's own directory."""
    from detect_secrets.core.potential_secret import PotentialSecret

    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        SHOULD_EXCLUDE_FILE_FILTER,
        _detect_secrets_api,
    )

    monkeypatch.chdir(tmp_path)
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    (checkout / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    service = checkout / "service"
    (service / "tests").mkdir(parents=True)
    (service / "settings.py").write_text(f"KEY = '{KEPT_SECRET}'\n", encoding="utf-8")
    (service / "tests" / "fixture.py").write_text(
        f"KEY = '{NEW_SECRET}'\n", encoding="utf-8"
    )
    shared = _baseline(
        {
            "service/settings.py": [
                {
                    "type": SECRET_TYPE,
                    "hashed_secret": _hash(KEPT_SECRET),
                    "line_number": 1,
                    "is_secret": False,
                }
            ]
        }
    )
    shared["filters_used"] = [
        {"path": SHOULD_EXCLUDE_FILE_FILTER, "pattern": ["^service/tests/"]}
    ]
    (checkout / ".secrets.baseline").write_text(json.dumps(shared), encoding="utf-8")
    try:
        (service / ".secrets.baseline").symlink_to(Path("..") / ".secrets.baseline")
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlinks unavailable on this platform: {exc}")
    context = PluginContext(
        source_dir=service,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.output_dir.mkdir(parents=True)
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    assert scanner._baseline_in_use()
    assert scanner._baseline_entries_trusted() is False

    seen: dict = {}

    def scanned(self, *, baseline, scan_paths, scan_settings_dict, **kwargs):
        seen["paths"] = list(scan_paths)
        collection_cls, _, _ = _detect_secrets_api()
        collection = collection_cls()
        collection.root = self._secrets_collection.root
        collection["settings.py"].add(
            PotentialSecret(
                SECRET_TYPE, "settings.py", secret=KEPT_SECRET, line_number=1
            )
        )
        return collection

    monkeypatch.setattr(type(scanner), "_scan_in_worker", scanned)

    report = scanner.scan(target=service, target_type="source")

    # The listed candidate is known: kept, suppressed, under the scan's URI.
    assert _findings(report) == [("settings.py", 1)]
    assert len(_suppressed(report)["settings.py"]) == 1
    # The checkout-relative exclude pattern took the tests directory out.
    assert seen["paths"], seen
    assert not any(Path(path).name == "fixture.py" for path in seen["paths"]), seen[
        "paths"
    ]
    assert any(Path(path).name == "settings.py" for path in seen["paths"]), seen[
        "paths"
    ]


def _monorepo_service(tmp_path: Path, shared_text: str) -> tuple[Path, PluginContext]:
    """``repo/service`` under a git-shaped ``repo``, its ``.secrets.baseline`` a link
    to ``repo/.secrets.baseline`` holding ``shared_text``; three files: ``settings.py``
    (the kept secret), ``tests/fixture.py`` and ``docs/notes.py`` (new secrets)."""
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    (checkout / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    service = checkout / "service"
    (service / "tests").mkdir(parents=True)
    (service / "docs").mkdir()
    (service / "settings.py").write_text(f"KEY = '{KEPT_SECRET}'\n", encoding="utf-8")
    (service / "tests" / "fixture.py").write_text(
        f"KEY = '{NEW_SECRET}'\n", encoding="utf-8"
    )
    (service / "docs" / "notes.py").write_text(
        f"KEY = '{NEW_SECRET}'\n", encoding="utf-8"
    )
    (checkout / ".secrets.baseline").write_text(shared_text, encoding="utf-8")
    try:
        (service / ".secrets.baseline").symlink_to(Path("..") / ".secrets.baseline")
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlinks unavailable on this platform: {exc}")
    context = PluginContext(
        source_dir=service,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.output_dir.mkdir(parents=True)
    return service, context


#: A filter under a path the operator's settings in these tests never name, so
#: the baseline's entry for it is the only one there is.
HEURISTIC_FILTER = "detect_secrets.filters.heuristic.is_likely_id_string"


def _shared_baseline_excluding(pattern: str) -> dict:
    """The checkout's baseline: ``service/settings.py`` known, one exclude pattern,
    and a second filter (``HEURISTIC_FILTER``) under another path."""
    document = _baseline(
        {
            "service/settings.py": [
                {
                    "type": SECRET_TYPE,
                    "hashed_secret": _hash(KEPT_SECRET),
                    "line_number": 1,
                    "is_secret": False,
                }
            ]
        }
    )
    document["filters_used"] = [
        {"path": SHOULD_EXCLUDE_FILE_FILTER, "pattern": [pattern]},
        {"path": HEURISTIC_FILTER},
    ]
    return document


def _operator_excluding(pattern: str, **settings) -> DetectSecretsScannerConfig:
    """The operator's own config: one ``should_exclude_file`` pattern, written
    relative to the scanned directory, plus any other scan setting."""
    return DetectSecretsScannerConfig(
        options=DetectSecretsScannerConfigOptions(
            scan_settings=DetectSecretsScanSettings(
                filters_used=[
                    DetectSecretsScanSettingsFiltersUsed(
                        path=SHOULD_EXCLUDE_FILE_FILTER, pattern=[pattern]
                    )
                ],
                **settings,
            )
        )
    )


def _recording_known_worker(scanner, monkeypatch) -> dict:
    """A worker that records the scan paths and returns the kept secret in
    ``settings.py`` (so the known-entry rule is exercised too)."""
    from detect_secrets.core.potential_secret import PotentialSecret

    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        _detect_secrets_api,
    )

    seen: dict = {}

    def scanned(self, *, baseline, scan_paths, scan_settings_dict, **kwargs):
        seen["paths"] = list(scan_paths)
        collection_cls, _, _ = _detect_secrets_api()
        collection = collection_cls()
        collection.root = self._secrets_collection.root
        collection["settings.py"].add(
            PotentialSecret(
                SECRET_TYPE, "settings.py", secret=KEPT_SECRET, line_number=1
            )
        )
        return collection

    monkeypatch.setattr(type(scanner), "_scan_in_worker", scanned)
    return seen


def _relative(seen: dict, root: Path) -> list[str]:
    """The scan paths relative to ``root``, the baseline file itself left out:
    the repository's own baseline is scanned like any file (see
    test_a_repository_baseline_is_scanned_and_only_its_hash_echoes_are_dropped),
    and these tests read which OTHER files the exclude patterns removed."""
    return sorted(
        Path(path).relative_to(root).as_posix()
        for path in seen["paths"]
        if Path(path).name != ".secrets.baseline"
    )


def test_the_operators_own_exclude_patterns_keep_the_scan_root_under_a_re_anchored_baseline(
    tmp_path, monkeypatch
):
    """The monorepo above, with the operator's own ``^tests/`` and the
    baseline's ``^service/docs/``. The operator's ``should_exclude_file`` entry
    takes precedence over the baseline's for that path (the baseline's entry is
    not loaded beside it; test_detect_secrets_operator_filters_keep_precedence),
    so the one pattern in play is the operator's, written relative to the
    scanned directory, and it is matched there. Matched against the checkout,
    the anchor of the baseline's keys, ``^tests/`` was tested against
    ``service/tests/fixture.py``, stopped matching, and that file was scanned
    with no warning. ``docs/notes.py`` stays scanned: the baseline's pattern
    yielded to the operator's entry by the precedence rule, not by the anchor."""
    monkeypatch.chdir(tmp_path)
    service, context = _monorepo_service(
        tmp_path, json.dumps(_shared_baseline_excluding("^service/docs/"))
    )
    scanner = DetectSecretsScanner(
        context=context, config=_operator_excluding("^tests/")
    )
    assert scanner._baseline_in_use()
    assert scanner._baseline_document is not None
    assert [
        item.pattern
        for item in scanner.config.options.scan_settings.filters_used
        if item.path == SHOULD_EXCLUDE_FILE_FILTER
    ] == [["^tests/"]], "the operator's exclude entry should be the only one in play"
    # The precedence is per path: the baseline's filter under another path is
    # loaded beside the operator's entry. The pinned-settings test below drops
    # it, which tells "the baseline's filters were not loaded" from "the
    # baseline had none".
    assert any(
        item.path == HEURISTIC_FILTER
        for item in scanner.config.options.scan_settings.filters_used
    )
    seen = _recording_known_worker(scanner, monkeypatch)

    report = scanner.scan(target=service, target_type="source")

    assert _relative(seen, service) == ["docs/notes.py", "settings.py"], seen
    # The baseline's key is still read relative to the checkout: known, marked.
    assert _findings(report) == [("settings.py", 1)]
    assert len(_suppressed(report)["settings.py"]) == 1


def test_an_operators_pinned_scan_settings_keep_their_patterns_at_the_scan_root(
    tmp_path, monkeypatch
):
    """The operator named detectors (``scan_settings.plugins_used``), so the
    baseline's own filters are never loaded (the settings gate takes the
    baseline's settings only for an empty plugin list; ``version`` alone does
    not gate) and every pattern in play is the operator's. The anchor still
    moves for the baseline's KEYS, which the baseline wrote from the checkout;
    the operator's ``^tests/`` must not move with it. It did: ``tests/fixture.py``
    was scanned, and ``docs/notes.py`` stays scanned because the baseline's
    pattern was never loaded."""
    monkeypatch.chdir(tmp_path)
    service, context = _monorepo_service(
        tmp_path, json.dumps(_shared_baseline_excluding("^service/docs/"))
    )
    scanner = DetectSecretsScanner(
        context=context,
        config=_operator_excluding(
            "^tests/", version="1.5.0", plugins_used=[{"name": "AWSKeyDetector"}]
        ),
    )
    assert scanner._baseline_in_use()
    assert scanner._baseline_document is not None
    assert not any(
        item.pattern == ["^service/docs/"]
        for item in scanner.config.options.scan_settings.filters_used
    ), "the baseline's filters were loaded past the operator's pinned settings"
    assert not any(
        item.path == HEURISTIC_FILTER
        for item in scanner.config.options.scan_settings.filters_used
    ), "the baseline's filter under another path was loaded past the pin"
    seen = _recording_known_worker(scanner, monkeypatch)

    report = scanner.scan(target=service, target_type="source")

    assert _relative(seen, service) == ["docs/notes.py", "settings.py"], seen
    assert _findings(report) == [("settings.py", 1)]
    assert len(_suppressed(report)["settings.py"]) == 1


def test_a_malformed_linked_baseline_moves_no_anchor(tmp_path, monkeypatch):
    """The same link, to a file that is not a baseline. The chosen path stays
    recorded (``_baseline_real``) but there is no document, so no baseline path
    is in play; the anchor used to move to the file's directory anyway, and the
    operator's ``^tests/`` was matched there. Nothing is anchored without a
    document, and the operator's pattern excludes from the scanned directory."""
    monkeypatch.chdir(tmp_path)
    service, context = _monorepo_service(tmp_path, json.dumps([]))
    scanner = DetectSecretsScanner(
        context=context, config=_operator_excluding("^tests/")
    )
    assert scanner._baseline_in_use()
    assert scanner._baseline_real is not None
    assert scanner._baseline_document is None

    assert scanner._baseline_anchor(service, "source") == service

    seen = _recording_known_worker(scanner, monkeypatch)
    scanner.scan(target=service, target_type="source")
    names = _relative(seen, service)
    # The operator's pattern excluded from the scanned directory; the baseline's
    # (never loaded) excluded nothing. Whether the link itself is in the scan set
    # is the scan set's call, not this test's.
    assert "tests/fixture.py" not in names, names
    assert {"docs/notes.py", "settings.py"} <= set(names), names


def test_a_scan_root_reached_through_a_link_below_the_baselines_directory_keeps_the_scan_root(
    tmp_path, monkeypatch
):
    """``repo/api`` is a link to ``repo/packages/api`` and the baseline sits in
    ``repo``. Resolved, the scan root is two levels below the baseline's
    directory; spelled, it is one. The walk up the spelled path by the resolved
    gap left the checkout (a deeper link could reach ``/``), and no key or
    pattern met anything. The directory the walk lands on is now checked
    against the baseline's: when it is not that directory, the baseline's paths
    are read relative to the scan root, the shape before the re-anchoring. The
    control is the same baseline under the real directory, where the walk is
    right and the anchor is the checkout.

    The checkout has a ``.git`` holding ``HEAD`` (a bare ``.git`` directory is
    no checkout to the trust rules), and the scanner finds the baseline itself:
    the tree's ``.secrets.baseline`` is a link up to the checkout's file, which
    is admitted as the repository's."""
    monkeypatch.chdir(tmp_path)
    checkout = tmp_path / "repo"
    (checkout / ".git").mkdir(parents=True)
    (checkout / ".git" / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    real_api = checkout / "packages" / "api"
    real_api.mkdir(parents=True)
    (real_api / "settings.py").write_text(f"KEY = '{KEPT_SECRET}'\n", encoding="utf-8")
    (checkout / ".secrets.baseline").write_text(
        json.dumps(_baseline({})), encoding="utf-8"
    )
    try:
        (checkout / "api").symlink_to(
            Path("packages") / "api", target_is_directory=True
        )
        (real_api / ".secrets.baseline").symlink_to(
            Path("..") / ".." / ".secrets.baseline"
        )
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlinks unavailable on this platform: {exc}")
    context = PluginContext(
        source_dir=checkout / "api",
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    context.output_dir.mkdir(parents=True)
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    # The scan found the checkout's baseline through the tree's own link.
    assert scanner._baseline_in_use()
    assert scanner._baseline_from_option is False
    assert scanner._baseline_real == Path(
        os.path.realpath(checkout / ".secrets.baseline")
    )

    assert scanner._baseline_anchor(checkout / "api", "source") == checkout / "api"
    assert scanner._baseline_anchor(real_api, "source") == checkout


def test_an_operator_baseline_beside_the_tree_is_read_relative_to_the_scanned_directory(
    tmp_path, monkeypatch
):
    """The operator names a baseline that sits in the directory ABOVE the scanned
    tree, keyed as the known-entries tests key it: relative to the scanned
    directory (``settings.py``), with an exclude pattern anchored there too
    (``^tests/``). Its known candidate leaves the report and the pattern takes
    ``tests/fixture.py`` out of the scan paths. Only a baseline the scan FOUND in
    the tree, read through a link into the enclosing checkout, is re-anchored to
    its own directory; a first cut re-anchored this one as well, and its
    candidate was reported as new."""
    from detect_secrets.core.potential_secret import PotentialSecret

    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        SHOULD_EXCLUDE_FILE_FILTER,
        _detect_secrets_api,
    )

    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path)
    source = Path(context.source_dir)
    (source / "tests").mkdir()
    (source / "settings.py").write_text(f"KEY = '{KEPT_SECRET}'\n", encoding="utf-8")
    (source / "tests" / "fixture.py").write_text(
        f"KEY = '{NEW_SECRET}'\n", encoding="utf-8"
    )
    document = _baseline(
        {
            "settings.py": [
                {
                    "type": SECRET_TYPE,
                    "hashed_secret": _hash(KEPT_SECRET),
                    "line_number": 1,
                    "is_secret": False,
                }
            ]
        }
    )
    document["filters_used"] = [
        {"path": SHOULD_EXCLUDE_FILE_FILTER, "pattern": ["^tests/"]}
    ]
    baseline = tmp_path / "operator.baseline"
    baseline.write_text(json.dumps(document), encoding="utf-8")
    scanner = DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(baseline_file=str(baseline))
        ),
    )
    assert scanner._baseline_in_use()
    assert scanner._baseline_entries_trusted() is True

    seen: dict = {}

    def scanned(self, *, baseline, scan_paths, scan_settings_dict, **kwargs):
        seen["paths"] = list(scan_paths)
        collection_cls, _, _ = _detect_secrets_api()
        collection = collection_cls()
        collection.root = self._secrets_collection.root
        collection["settings.py"].add(
            PotentialSecret(
                SECRET_TYPE, "settings.py", secret=KEPT_SECRET, line_number=1
            )
        )
        return collection

    monkeypatch.setattr(type(scanner), "_scan_in_worker", scanned)

    report = scanner.scan(target=source, target_type="source")

    assert _findings(report) == []
    assert seen["paths"], seen
    assert not any(Path(path).name == "fixture.py" for path in seen["paths"]), seen[
        "paths"
    ]


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
