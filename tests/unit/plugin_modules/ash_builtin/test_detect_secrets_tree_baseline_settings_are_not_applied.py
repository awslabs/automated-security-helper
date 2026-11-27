"""A baseline found in the scanned tree sets neither the plugins nor the filters.

The scanner looks for ``.ash/.secrets.baseline`` and ``.secrets.baseline`` in
the scanned tree. Its ``results`` mark known candidates (they stay in the
report as suppressed findings), and that is all a baseline the repository
carries may do. Its ``plugins_used`` and ``filters_used`` decide what the scan
detects and what it leaves out, so they are applied only when the operator
named the baseline file from outside the scanned tree and any git checkout
holding the scan root, in a config the operator wrote.

The same holds for a baseline the operator names that sits inside the tree, for
one that sits beside a scan root that does not hold the source directory, and
for one outside the tree that a config the operator did not write names. Each
case is asserted on what the scan runs with: the scanner's effective plugins
and filters, the warning it logs, and the candidates it marks.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.config.resolve_config import resolve_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
    DetectSecretsScanSettings,
    DetectSecretsScanSettingsPluginsUsed,
)

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]

SECRET_TYPE = "AWS Access Key"  # pragma: allowlist secret
EXCLUDE_SECRET_FILTER = "detect_secrets.filters.regex.should_exclude_secret"
EXCLUDE_LINE_FILTER = "detect_secrets.filters.regex.should_exclude_line"
NOT_APPLIED = "plugins and filters were not applied"
READ_FAILED = "Failed to read baseline file settings"
# Assembled at runtime so this file holds no key-shaped literal for ASH's own
# self-scan to report. AWS's documentation placeholder.
KEPT_SECRET = "".join(["AKIA", "IOSFODNN7", "EXAMPLE"])  # noqa: FLY002


@pytest.fixture(autouse=True)
def _checkouts_below_the_temporary_directory(monkeypatch, tmp_path):
    """Let the trust rules see only the git checkouts at or below ``tmp_path``."""
    from automated_security_helper.config import path_trust
    from automated_security_helper.config.sandbox_grants import is_within

    real = path_trust._checkouts_holding
    monkeypatch.setattr(
        path_trust,
        "_checkouts_holding",
        lambda scan_root: [c for c in real(scan_root) if is_within(c, tmp_path)],
    )


def _baseline_document(results: dict | None = None) -> dict:
    return {
        "version": "1.5.0",
        "plugins_used": [
            {"name": "KeywordDetector"},
            {"name": "Base64HighEntropyString", "limit": 8.0},
        ],
        "filters_used": [
            {"path": EXCLUDE_SECRET_FILTER, "pattern": [".*"]},
            {"path": EXCLUDE_LINE_FILTER, "pattern": [".*"]},
        ],
        "results": results or {},
        "generated_at": "2026-01-01T00:00:00Z",
    }


def _scanner(
    tmp_path,
    monkeypatch,
    *,
    baseline_file: str | None = None,
    scanned_root: Path | None = None,
    scan_settings: DetectSecretsScanSettings | None = None,
):
    monkeypatch.chdir(tmp_path)
    context = PluginContext(
        source_dir=tmp_path,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    if scanned_root is not None:
        context.config._scanned_root = scanned_root
    values: dict = {}
    if baseline_file:
        values["baseline_file"] = baseline_file
    if scan_settings is not None:
        values["scan_settings"] = scan_settings
    return DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(**values)
        ),
    )


def _plugin_names(scanner) -> set[str]:
    return {item.name for item in scanner.config.options.scan_settings.plugins_used}


def _filter_paths(scanner) -> set[str]:
    return {item.path for item in scanner.config.options.scan_settings.filters_used}


def _default_plugin_names(tmp_path_factory, monkeypatch) -> set[str]:
    empty = tmp_path_factory.mktemp("empty-tree")
    return _plugin_names(_scanner(empty, monkeypatch))


def _not_applied_warnings(caplog) -> list[str]:
    return [
        record.getMessage()
        for record in caplog.records
        if NOT_APPLIED in record.getMessage()
    ]


def _assert_the_baselines_settings_were_not_applied(
    scanner, defaults: set[str], caplog
) -> None:
    """The scan runs the default plugins and none of the baseline's filters,
    and says so once."""
    assert scanner._baseline_in_use()
    assert _plugin_names(scanner) == defaults
    assert "AWSKeyDetector" in _plugin_names(scanner)
    assert not any(
        getattr(item, "limit", None) == 8.0
        for item in scanner.config.options.scan_settings.plugins_used
    )
    assert EXCLUDE_SECRET_FILTER not in _filter_paths(scanner)
    assert EXCLUDE_LINE_FILTER not in _filter_paths(scanner)
    warnings = _not_applied_warnings(caplog)
    assert len(warnings) == 1, warnings
    assert "Base64HighEntropyString" in warnings[0]
    assert EXCLUDE_SECRET_FILTER in warnings[0]


def test_a_baseline_in_the_tree_leaves_the_default_plugins_and_filters(
    tmp_path, tmp_path_factory, monkeypatch, caplog
):
    (tmp_path / ".secrets.baseline").write_text(
        json.dumps(_baseline_document()), encoding="utf-8"
    )
    defaults = _default_plugin_names(tmp_path_factory, monkeypatch)
    assert "AWSKeyDetector" in defaults

    with caplog.at_level(logging.WARNING):
        scanner = _scanner(tmp_path, monkeypatch)

    _assert_the_baselines_settings_were_not_applied(scanner, defaults, caplog)
    assert ".secrets.baseline" in _not_applied_warnings(caplog)[0]


@pytest.mark.parametrize("named", [".secrets.baseline", "config/team.baseline"])
def test_a_baseline_the_operator_names_inside_the_tree_sets_neither(
    tmp_path, tmp_path_factory, monkeypatch, caplog, named
):
    """Naming the file does not make it the operator's when it sits in the
    scanned tree: it is the repository's file, so an org-wide
    ``baseline_file: .secrets.baseline`` does not let each repository choose
    its plugins and filters."""
    target = tmp_path / named
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(_baseline_document()), encoding="utf-8")
    defaults = _default_plugin_names(tmp_path_factory, monkeypatch)

    with caplog.at_level(logging.WARNING):
        scanner = _scanner(tmp_path, monkeypatch, baseline_file=named)

    assert scanner._baseline_from_option
    assert scanner._baseline_entries_trusted() is False
    _assert_the_baselines_settings_were_not_applied(scanner, defaults, caplog)


def test_a_found_baseline_under_a_scan_root_that_does_not_hold_the_source(
    tmp_path, tmp_path_factory, monkeypatch, caplog
):
    """The scan root the configuration names (the workspace root, in workspace
    mode) may not hold the source directory, and then no checkout reason
    speaks against the tree's own baseline. It is still the repository's: a
    baseline the scan found is never the operator's."""
    (tmp_path / ".secrets.baseline").write_text(
        json.dumps(_baseline_document()), encoding="utf-8"
    )
    elsewhere = tmp_path_factory.mktemp("elsewhere")
    defaults = _default_plugin_names(tmp_path_factory, monkeypatch)

    with caplog.at_level(logging.WARNING):
        scanner = _scanner(tmp_path, monkeypatch, scanned_root=elsewhere)

    assert not scanner._baseline_from_option
    assert scanner._baseline_entries_trusted() is False
    _assert_the_baselines_settings_were_not_applied(scanner, defaults, caplog)


def test_a_baseline_the_operator_names_outside_the_tree_still_sets_them(
    tmp_path, tmp_path_factory, monkeypatch, caplog
):
    operator_dir = tmp_path_factory.mktemp("operator")
    named = operator_dir / "shared.baseline"
    named.write_text(json.dumps(_baseline_document()), encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        scanner = _scanner(tmp_path, monkeypatch, baseline_file=str(named))

    assert scanner._baseline_entries_trusted()
    assert _plugin_names(scanner) == {"KeywordDetector", "Base64HighEntropyString"}
    assert EXCLUDE_SECRET_FILTER in _filter_paths(scanner)
    assert EXCLUDE_LINE_FILTER in _filter_paths(scanner)
    assert _not_applied_warnings(caplog) == []


def test_a_trusted_baseline_does_not_replace_the_plugins_the_operator_pinned(
    tmp_path, tmp_path_factory, monkeypatch, caplog
):
    """A trusted baseline fills in the settings the operator left empty. The
    operator who named plugins has chosen them, and the option's documentation
    gives ``scan_settings`` precedence over the baseline, so neither the
    baseline's plugins nor its filters are loaded."""
    operator_dir = tmp_path_factory.mktemp("operator")
    named = operator_dir / "shared.baseline"
    named.write_text(json.dumps(_baseline_document()), encoding="utf-8")
    pinned = DetectSecretsScanSettings(
        plugins_used=[DetectSecretsScanSettingsPluginsUsed(name="JwtTokenDetector")]
    )

    with caplog.at_level(logging.WARNING):
        scanner = _scanner(
            tmp_path, monkeypatch, baseline_file=str(named), scan_settings=pinned
        )

    assert scanner._baseline_entries_trusted()
    assert _plugin_names(scanner) == {"JwtTokenDetector"}
    assert EXCLUDE_SECRET_FILTER not in _filter_paths(scanner)
    assert EXCLUDE_LINE_FILTER not in _filter_paths(scanner)
    assert _not_applied_warnings(caplog) == []


def test_a_baseline_outside_the_tree_named_by_a_config_the_operator_did_not_write(
    tmp_path, tmp_path_factory, monkeypatch, caplog
):
    """The scanned repository carries a config of its own, so the
    ``baseline_file`` handed to the scanner is not recorded as the operator's.
    The baseline sits outside the tree and every checkout, yet neither its
    settings nor its entries are trusted."""
    monkeypatch.chdir(tmp_path)
    source = tmp_path / "repo"
    source.mkdir()
    (source / ".ash.yaml").write_text("project_name: repository\n", encoding="utf-8")
    output = tmp_path / "out"
    work = output / ASH_WORK_DIR_NAME
    work.mkdir(parents=True)
    named = tmp_path_factory.mktemp("operator") / "shared.baseline"
    named.write_text(json.dumps(_baseline_document()), encoding="utf-8")
    defaults = _plugin_names(
        DetectSecretsScanner(
            context=PluginContext(
                source_dir=source,
                output_dir=output,
                work_dir=work,
                config=resolve_config(source_dir=source),
            ),
            config=DetectSecretsScannerConfig(),
        )
    )

    with caplog.at_level(logging.WARNING):
        scanner = DetectSecretsScanner(
            config=DetectSecretsScannerConfig(
                options=DetectSecretsScannerConfigOptions(baseline_file=str(named))
            ),
            config_from_context=True,
            context=PluginContext(
                source_dir=source,
                output_dir=output,
                work_dir=work,
                config=resolve_config(source_dir=source),
            ),
        )

    assert scanner._baseline_from_option
    assert scanner._baseline_checkout_reason() is None
    assert scanner._baseline_entries_trusted() is False
    _assert_the_baselines_settings_were_not_applied(scanner, defaults, caplog)


def test_a_baseline_in_the_tree_still_marks_its_known_candidates(tmp_path, monkeypatch):
    scanner = _scanner_over_a_marking_baseline(tmp_path, monkeypatch)

    report = _scan_with_the_candidate_found(scanner, tmp_path, monkeypatch)

    (result,) = report.runs[0].results
    assert result.suppressions


@pytest.mark.parametrize("key", ["plugins_used", "filters_used"])
@pytest.mark.parametrize("value", [1, True, 2.5])
def test_a_baseline_whose_settings_are_not_lists_still_marks_its_candidates(
    tmp_path, monkeypatch, caplog, key, value
):
    """A tree baseline's settings are never applied, so their shape is not a
    reason to drop the baseline: a ``plugins_used`` or ``filters_used`` that is
    a number or a flag leaves the parsed document in place and its ``results``
    still mark, with no read failure reported."""
    pinned = DetectSecretsScanSettings(
        plugins_used=[DetectSecretsScanSettingsPluginsUsed(name="AWSKeyDetector")]
    )

    with caplog.at_level(logging.WARNING):
        scanner = _scanner_over_a_marking_baseline(
            tmp_path, monkeypatch, settings={key: value}, scan_settings=pinned
        )

    assert not any(READ_FAILED in record.getMessage() for record in caplog.records)
    assert scanner._baseline_document is not None
    report = _scan_with_the_candidate_found(scanner, tmp_path, monkeypatch)
    (result,) = report.runs[0].results
    assert result.suppressions


def _scanner_over_a_marking_baseline(
    tmp_path, monkeypatch, *, settings: dict | None = None, scan_settings=None
):
    """A scanner over a tree whose ``.secrets.baseline`` lists the candidate in
    ``settings.py``, with *settings* written over the baseline's own."""
    from detect_secrets.core.potential_secret import PotentialSecret

    (tmp_path / "settings.py").write_text(f"KEY = '{KEPT_SECRET}'\n", encoding="utf-8")
    entries = {
        "settings.py": [
            {
                "type": SECRET_TYPE,
                "hashed_secret": PotentialSecret.hash_secret(KEPT_SECRET),
                "line_number": 1,
                "is_secret": False,
            }
        ]
    }
    document = _baseline_document(entries)
    document.update(settings or {})
    (tmp_path / ".secrets.baseline").write_text(json.dumps(document), encoding="utf-8")
    return _scanner(tmp_path, monkeypatch, scan_settings=scan_settings)


def _scan_with_the_candidate_found(scanner, tmp_path, monkeypatch):
    from detect_secrets.core.potential_secret import PotentialSecret

    from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
        _detect_secrets_api,
    )

    def scanned(self, **kwargs):
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
    return scanner.scan(target=Path(tmp_path), target_type="source")


# ---------------------------------------------------------------------------
# What the warning prints
# ---------------------------------------------------------------------------


def test_the_warning_prints_no_plugin_parameter_and_no_filter_pattern(
    tmp_path, monkeypatch, caplog
):
    document = _baseline_document()
    document["plugins_used"] = [
        {"name": "Base64HighEntropyString", "limit": 7.77},
        {"name": "KeywordDetector", "keyword_exclude": "PLANTED-KEYWORD-PATTERN"},
    ]
    document["filters_used"] = [
        {"path": EXCLUDE_SECRET_FILTER, "pattern": ["PLANTED-FILTER-PATTERN"]}
    ]
    (tmp_path / ".secrets.baseline").write_text(json.dumps(document), encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        _scanner(tmp_path, monkeypatch)

    (warning,) = _not_applied_warnings(caplog)
    assert "Base64HighEntropyString" in warning
    assert "KeywordDetector" in warning
    assert EXCLUDE_SECRET_FILTER in warning
    for planted in ("7.77", "PLANTED-KEYWORD-PATTERN", "PLANTED-FILTER-PATTERN"):
        assert planted not in warning


def test_the_warning_prints_no_name_or_path_that_is_not_a_string(
    tmp_path, monkeypatch, caplog
):
    """A baseline's entry can hold anything. A name or a path that is not a
    string is counted at most, and no value of it is printed."""
    document = _baseline_document()
    document["plugins_used"] = [
        {"name": "Base64HighEntropyString"},
        {"name": {"limit": 5.55, "note": "PLANTED-NAME-MAPPING"}},
        {"name": ["PLANTED-NAME-LIST"]},
        {"name": 424242},
    ]
    document["filters_used"] = [
        {"path": EXCLUDE_SECRET_FILTER, "pattern": ["PLANTED-FILTER-PATTERN"]},
        {"path": {"pattern": "PLANTED-PATH-MAPPING"}},
        {"path": 737373},
    ]
    (tmp_path / ".secrets.baseline").write_text(json.dumps(document), encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        scanner = _scanner(tmp_path, monkeypatch)

    assert scanner._baseline_document is not None
    assert not any(READ_FAILED in record.getMessage() for record in caplog.records)
    (warning,) = _not_applied_warnings(caplog)
    assert "Base64HighEntropyString" in warning
    assert EXCLUDE_SECRET_FILTER in warning
    for planted in (
        "5.55",
        "PLANTED-NAME-MAPPING",
        "PLANTED-NAME-LIST",
        "424242",
        "PLANTED-FILTER-PATTERN",
        "PLANTED-PATH-MAPPING",
        "737373",
    ):
        assert planted not in warning


@pytest.mark.parametrize(
    "document, named, absent",
    [
        (
            {"plugins_used": [{"name": "Base64HighEntropyString"}]},
            "Plugins not applied: Base64HighEntropyString",
            EXCLUDE_SECRET_FILTER,
        ),
        (
            {"filters_used": [{"path": EXCLUDE_SECRET_FILTER, "pattern": [".*"]}]},
            f"Filters not applied: {EXCLUDE_SECRET_FILTER}",
            "Base64HighEntropyString",
        ),
    ],
    ids=["only-plugins", "only-filters"],
)
def test_the_warning_fires_for_a_baseline_that_lists_only_one_kind(
    tmp_path, monkeypatch, caplog, document, named, absent
):
    (tmp_path / ".secrets.baseline").write_text(
        json.dumps({"version": "1.5.0", "results": {}, **document}), encoding="utf-8"
    )

    with caplog.at_level(logging.WARNING):
        _scanner(tmp_path, monkeypatch)

    (warning,) = _not_applied_warnings(caplog)
    assert named in warning
    assert absent not in warning


@pytest.mark.parametrize("spelling", ["parent-segment", "dot-segment", "link"])
def test_the_warning_hides_a_baseline_path_read_from_the_environment(
    tmp_path, tmp_path_factory, monkeypatch, caplog, spelling
):
    """``baseline_file`` written from an environment value that resolves into
    the scanned tree through ``..``, a ``.`` segment or a link: the warning
    prints the path the scan reads, which is not the text the operator wrote,
    so hiding the written value alone leaves the resolved path in clear."""
    name = "operator-baseline-from-environment.json"
    target = tmp_path / name
    target.write_text(json.dumps(_baseline_document()), encoding="utf-8")
    if spelling == "parent-segment":
        written = f"../{tmp_path.name}/{name}"
    elif spelling == "dot-segment":
        written = f"{tmp_path}{os.sep}.{os.sep}{name}"
    else:
        alias = tmp_path_factory.mktemp("links") / "alias-to-the-tree"
        try:
            alias.symlink_to(tmp_path, target_is_directory=True)
        except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
            pytest.skip(f"symlinks unavailable on this platform: {exc}")
        written = f"{alias}{os.sep}{name}"
    monkeypatch.setattr(
        DetectSecretsScanner, "_environment_values", lambda self: (written,)
    )

    with caplog.at_level(logging.WARNING):
        scanner = _scanner(tmp_path, monkeypatch, baseline_file=written)

    assert scanner._baseline_in_use()
    (warning,) = _not_applied_warnings(caplog)
    assert "Base64HighEntropyString" in warning
    assert written not in warning
    assert name not in warning
    for printed in (target, target.resolve()):
        assert str(printed) not in warning
        assert printed.as_posix() not in warning
