# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Regression tests: configuration must not silently remove detect-secrets coverage.

Two independent routes by which a detect-secrets scan reported clean at exit 0
while having nothing to detect with, or nothing to detect in.

1. ``scan_settings.version`` on its own. The default-plugin installation in
   ``_process_config_options`` was gated on ``version is None`` *and*
   ``plugins_used == []``, so naming a version -- which reads as a compatibility
   knob rather than a coverage switch -- skipped it. ``model_dump`` with
   ``exclude_defaults`` then dropped the still-default empty ``plugins_used``,
   so ``transient_settings`` received ``{'version': ...}`` and nothing else:
   detect-secrets ran with zero plugins, found nothing, and the run passed.
   ``plugins_used`` is the only condition that decides this, so it is the only
   one tested now.

2. The converted target. The scan set was filtered by the hardcoded substring
   ``/.ash/``, and under the documented default layout ``work_dir`` is
   ``<source>/.ash/ash_output/converted`` -- so every path the converted branch
   globs contains that substring and the entire branch was dropped. The
   exclusion exists to keep ASH's own output out of a *source* scan. Expressed
   against the resolved ``output_dir`` it still does that, without emptying the
   converted scan and without depending on a separator that is ``\\`` on
   Windows, where the substring form matched nothing at all.

The existing converted-target coverage in
``tests/unit/plugin_modules/test_detect_secrets_scan_root.py`` builds
``work_dir`` as ``out/converted``, which contains no ``.ash`` segment, so it
could not observe defect 2. The layout is the load-bearing part of the fixture
here.
"""

from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.core.constants import ASH_WORK_DIR_NAME
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.plugin_modules.ash_builtin.scanners import (
    detect_secrets_scanner,
)
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
    DetectSecretsScanSettings,
)

# A fake value. Written to a file it trips detect-secrets' keyword plugin, which
# is all these tests need from it.
_KEYWORD_LINE = 'secret = "base64_encoded_secret=="'  # pragma: allowlist secret

#: Where :func:`_write_secret_files` puts them, relative to the given directory.
_EXPECTED_KEYS = {"first.py", "nested/second.py"}


def _write_secret_files(directory: Path) -> None:
    """Write two secret-bearing files, one of them nested.

    Two is the load-bearing number: a scan set of one file takes
    ``SecretsCollection.scan_file()``, which keys findings by the name it was
    handed rather than relative to ``root``, so the keys these tests assert on
    only appear once the multiprocessing branch is reached.
    """
    nested = directory / "nested"
    nested.mkdir(parents=True, exist_ok=True)
    (directory / "first.py").write_text(_KEYWORD_LINE)
    (nested / "second.py").write_text(_KEYWORD_LINE)


def _scanner(
    source_dir: Path,
    output_dir: Path,
    *,
    scan_settings: DetectSecretsScanSettings | None = None,
    work_dir: Path | None = None,
) -> DetectSecretsScanner:
    options = DetectSecretsScannerConfigOptions()
    if scan_settings is not None:
        options = DetectSecretsScannerConfigOptions(scan_settings=scan_settings)
    return DetectSecretsScanner(
        context=PluginContext(
            source_dir=source_dir,
            output_dir=output_dir,
            work_dir=work_dir
            if work_dir is not None
            else output_dir / ASH_WORK_DIR_NAME,
            config=get_default_config(),
        ),
        config=DetectSecretsScannerConfig(options=options),
    )


def _keys(scanner: DetectSecretsScanner) -> set:
    """Collection keys, separator-normalised."""
    return {Path(key).as_posix() for key in scanner._secrets_collection.data}


# --------------------------------------------------------------------------
# Defect 1: scan_settings.version alone left the scanner with no plugins
# --------------------------------------------------------------------------


def test_version_alone_still_resolves_the_default_plugin_set(tmp_path, monkeypatch):
    """Naming a version must not be a way to switch every detector off.

    ``_process_config_options`` runs from ``model_post_init``, so constructing
    the scanner is what resolves the plugin set.
    """
    # The baseline probe resolves its candidate paths against the working
    # directory, so anchor it somewhere with no .secrets.baseline in it.
    monkeypatch.chdir(tmp_path)
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    scanner = _scanner(
        source_dir,
        output_dir,
        scan_settings=DetectSecretsScanSettings(version="1.5.0"),
    )

    assert len(scanner.config.options.scan_settings.plugins_used) > 0, (
        "setting scan_settings.version alone left detect-secrets with zero "
        "plugins, so the scan could only ever report clean"
    )


def test_installing_the_default_plugins_preserves_the_operator_settings(
    tmp_path, monkeypatch
):
    """The default plugins must be merged in, not swapped for the whole object.

    Replacing ``scan_settings`` discards the operator's ``version``,
    ``generated_at``, any ``filters_used`` loaded from a baseline, and any extra
    keys the model accepts -- a second silent loss on the way to fixing the
    first.
    """
    monkeypatch.chdir(tmp_path)
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    output_dir = tmp_path / "out"
    output_dir.mkdir()

    scanner = _scanner(
        source_dir,
        output_dir,
        scan_settings=DetectSecretsScanSettings(
            version="1.5.0",
            generated_at="2026-01-01T00:00:00Z",
        ),
    )

    resolved = scanner.config.options.scan_settings
    assert resolved.plugins_used, "the default plugin set was not installed"
    assert resolved.version == "1.5.0", (
        "the operator's version was discarded while installing default plugins"
    )
    assert resolved.generated_at == "2026-01-01T00:00:00Z", (
        "the operator's generated_at was discarded while installing default plugins"
    )


def test_transient_settings_receives_a_nonempty_plugin_list(tmp_path, monkeypatch):
    """The end of the chain, which is what actually governs the scan.

    Asserting on the resolved model is not sufficient on its own: the dict
    handed to ``transient_settings`` is built by ``model_dump`` with
    ``exclude_defaults``/``exclude_unset``, which is where the empty list was
    being dropped. This asserts the value that reaches detect-secrets, and that
    findings come back with it.
    """
    monkeypatch.chdir(tmp_path)
    source_dir = tmp_path / "src"
    output_dir = tmp_path / "out"
    _write_secret_files(source_dir)
    output_dir.mkdir()

    scanner = _scanner(
        source_dir,
        output_dir,
        scan_settings=DetectSecretsScanSettings(version="1.5.0"),
    )

    captured: dict = {}
    real_transient_settings = detect_secrets_scanner.transient_settings

    def capturing(settings):
        captured["settings"] = settings
        return real_transient_settings(settings)

    monkeypatch.setattr(detect_secrets_scanner, "transient_settings", capturing)

    report = scanner.scan(target=source_dir, target_type="source")

    assert captured["settings"].get("plugins_used"), (
        "transient_settings was handed no plugins_used, so detect-secrets had "
        f"no detectors configured: {captured['settings']!r}"
    )
    assert report is not False
    assert report.runs[0].results, (
        "a version-only detect-secrets config reported no findings against a "
        "tree containing two"
    )
    assert _keys(scanner) == _EXPECTED_KEYS


def test_an_empty_plugin_set_raises_rather_than_reporting_clean(tmp_path, monkeypatch):
    """Fail closed on the general case, not just on the one route into it.

    ``_process_config_options`` now guarantees a non-empty plugin set, so this
    drives the guard by emptying the list afterwards. The point of the guard is
    that any future path reaching ``transient_settings`` with no detectors
    raises instead of producing an authoritative-looking clean report.
    """
    monkeypatch.chdir(tmp_path)
    source_dir = tmp_path / "src"
    output_dir = tmp_path / "out"
    _write_secret_files(source_dir)
    output_dir.mkdir()

    scanner = _scanner(source_dir, output_dir)
    assert scanner.config.options.scan_settings.plugins_used, (
        "precondition: the default plugin set should have been installed"
    )
    scanner.config.options.scan_settings.plugins_used = []

    with pytest.raises(ScannerError, match="no detect-secrets plugins"):
        scanner.scan(target=source_dir, target_type="source")


# --------------------------------------------------------------------------
# Defect 2: the converted branch dropped every path it globbed
# --------------------------------------------------------------------------


def test_converted_target_under_the_default_layout_is_scanned(tmp_path):
    """The documented default layout, which is where the substring bit.

    ``output_dir`` defaults to ``<source>/.ash/ash_output`` and ``work_dir`` to
    ``<output_dir>/converted``, so every converted path contains ``/.ash/``.
    """
    source_dir = tmp_path / "src"
    output_dir = source_dir / ".ash" / "ash_output"
    work_dir = output_dir / ASH_WORK_DIR_NAME
    source_dir.mkdir()
    _write_secret_files(work_dir)

    scanner = _scanner(source_dir, output_dir, work_dir=work_dir)
    report = scanner.scan(target=work_dir, target_type="converted")

    assert report is not False
    assert report.runs[0].results, (
        "the converted scan set was emptied by the '/.ash/' path exclusion, so "
        "everything the converters produced went unscanned"
    )
    assert _keys(scanner) == _EXPECTED_KEYS


def test_source_scan_still_excludes_ashs_own_output_directory(tmp_path):
    """The exclusion's real job, which the fix has to keep doing.

    A control rather than a reproducer: this passes before and after, and exists
    so that narrowing the exclusion to the converted-safe form cannot quietly
    turn ASH's own previous output into scan input. Findings from a stale report
    would be attributed to the source tree.
    """
    source_dir = tmp_path / "src"
    output_dir = source_dir / ".ash" / "ash_output"
    _write_secret_files(source_dir)
    output_dir.mkdir(parents=True)
    (output_dir / "previous_run.py").write_text(_KEYWORD_LINE)

    scanner = _scanner(source_dir, output_dir)
    report = scanner.scan(target=source_dir, target_type="source")

    assert report is not False
    keys = _keys(scanner)
    assert _EXPECTED_KEYS <= keys, f"the source tree itself went unscanned: {keys}"
    assert not [key for key in keys if "ash_output" in key], (
        f"ASH's own output directory was scanned as source input: {keys}"
    )
