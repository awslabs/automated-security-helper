# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""detect-secrets file filters match the path relative to the scan root.

A baseline's ``should_exclude_file`` patterns and the config's
``global_settings.ignore_paths`` name files as a repository does, relative to
its root: ``^tests/``, ``build/``. The scanner matched the patterns against the
scan set's absolute paths and cut a resolved source prefix from them for the
ignore paths, so:

* an anchored pattern excluded nothing;
* an unanchored pattern that matched a directory above the checkout excluded
  every file, and the scan reported clean;
* the filter still reached the worker, where detect-secrets applied it to the
  absolute path the same way, and read a pattern written as one string as one
  pattern per character;
* ignore paths matched nothing for a relative source directory, whose scan set
  paths have no resolved prefix to cut;
* the baseline in use was itself in the scan set, and its hashed entries were
  reported by the entropy detectors.

Every match is now made against the path relative to the scan root, the filter
is applied by ASH alone, and the findings that are only the detectors reading
the hashes a baseline lists are dropped (the baseline itself is scanned when the
repository controls it). The scan
is driven in-process: ``_scan_in_worker`` is replaced by a recorder, so what
the worker would have been given is what the tests read.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_builtin.scanners.detect_secrets_scanner import (
    SHOULD_EXCLUDE_FILE_FILTER,
    DetectSecretsScanner,
    DetectSecretsScannerConfig,
    DetectSecretsScannerConfigOptions,
    DetectSecretsScanSettings,
    DetectSecretsScanSettingsFiltersUsed,
)

pytestmark = [pytest.mark.unit, pytest.mark.usefixtures("no_tool_probes")]


def _context(tmp_path: Path, source: Path | None = None) -> PluginContext:
    source = source if source is not None else tmp_path / "src"
    context = PluginContext(
        source_dir=source,
        output_dir=tmp_path / "out",
        work_dir=tmp_path / "out" / "converted",
        config=get_default_config(),
    )
    Path(source).mkdir(parents=True, exist_ok=True)
    context.output_dir.mkdir(parents=True, exist_ok=True)
    return context


def _write(root: Path, name: str, text: str = "value = 1\n") -> Path:
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _record_worker(scanner, monkeypatch) -> dict:
    """Replace the worker with a recorder of what it would have been given."""
    seen: dict = {}

    def recorded(self, **kwargs):
        seen.update(kwargs)
        return None

    monkeypatch.setattr(type(scanner), "_scan_in_worker", recorded)
    return seen


def _relative_scan_paths(seen: dict, root: Path) -> list[str]:
    return sorted(
        Path(path).resolve().relative_to(root.resolve()).as_posix()
        for path in seen["scan_paths"]
    )


# ---------------------------------------------------------------------------
# The helpers
# ---------------------------------------------------------------------------


def test_root_relative_gives_the_posix_path_under_the_root(tmp_path):
    root = tmp_path / "repo"
    assert (
        DetectSecretsScanner._root_relative(str(root / "tests" / "a.py"), root)
        == "tests/a.py"
    )


def test_root_relative_keeps_a_path_outside_the_root_absolute(tmp_path):
    root = tmp_path / "repo"
    outside = tmp_path / "elsewhere" / "a.py"
    assert (
        DetectSecretsScanner._root_relative(str(outside), root)
        == Path(outside).absolute().as_posix()
    )


def test_root_relative_without_a_root_returns_the_path_as_given():
    assert DetectSecretsScanner._root_relative("tests/a.py", None) == "tests/a.py"


def test_an_anchored_pattern_excludes_by_the_root_relative_path(tmp_path):
    """The root's own path has a ``tests-tree`` directory in it, which only a
    match that is not anchored could reach. Against the absolute path the
    anchored ``^tests/`` meets the leading slash and excludes nothing; against
    the path relative to the root it removes ``tests/`` and keeps ``src/``."""
    root = tmp_path / "tests-tree" / "repo"
    files = [str(root / "src" / "app.py"), str(root / "tests" / "test_app.py")]

    kept = DetectSecretsScanner._apply_file_exclusions(
        files, [re.compile(r"^tests/")], root
    )

    assert kept == [str(root / "src" / "app.py")]


def test_an_unanchored_pattern_naming_a_directory_above_the_root_excludes_nothing(
    tmp_path,
):
    root = tmp_path / "tests-tree" / "repo"
    files = [str(root / "src" / "app.py"), str(root / "src" / "settings.py")]

    kept = DetectSecretsScanner._apply_file_exclusions(
        files, [re.compile(r"tests-tree")], root
    )

    assert kept == files


def test_an_unanchored_pattern_still_excludes_a_directory_below_the_root(tmp_path):
    """The other side of the test above: an unanchored pattern is not turned
    into an anchored one. ``fixtures/`` matches anywhere in the path relative
    to the root, so it takes out ``tests/fixtures/a.py`` and nothing else."""
    root = tmp_path / "repo"
    files = [
        str(root / "tests" / "fixtures" / "a.py"),
        str(root / "src" / "app.py"),
    ]

    kept = DetectSecretsScanner._apply_file_exclusions(
        files, [re.compile(r"fixtures/")], root
    )

    assert kept == [str(root / "src" / "app.py")]


# ---------------------------------------------------------------------------
# The scan
# ---------------------------------------------------------------------------


def test_the_worker_gets_neither_the_excluded_files_nor_the_filter(
    tmp_path, monkeypatch
):
    context = _context(tmp_path)
    source = Path(context.source_dir)
    _write(source, "settings.py")
    _write(source, "tests/fixture.py")
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    scanner.config.options.scan_settings.filters_used = [
        DetectSecretsScanSettingsFiltersUsed(
            path=SHOULD_EXCLUDE_FILE_FILTER, pattern=[r"^tests/"]
        )
    ]
    seen = _record_worker(scanner, monkeypatch)

    scanner.scan(target=source, target_type="source")

    assert seen, "the worker was not reached"
    assert _relative_scan_paths(seen, source) == ["settings.py"]
    assert not any(
        item.get("path") == SHOULD_EXCLUDE_FILE_FILTER
        for item in seen["scan_settings_dict"].get("filters_used", [])
    ), seen["scan_settings_dict"]


def test_a_scan_root_reached_through_a_link_is_matched_as_spelled(
    tmp_path, monkeypatch
):
    """The scanned directory is a link to ``real-tree/repo``. Patterns are
    matched against the path relative to the root as the scan set spells it,
    so ``^tests/`` still anchors at the root, and an unanchored pattern naming
    the directory the link points into (``real-tree``) matches nothing. Matched
    against the resolved path, that pattern would have matched every file and
    the scan would have read clean."""
    real = tmp_path / "real-tree" / "repo"
    real.mkdir(parents=True)
    link = tmp_path / "linked"
    try:
        link.symlink_to(real, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlinks unavailable on this platform: {exc}")
    _write(real, "settings.py")
    _write(real, "tests/fixture.py")
    context = _context(tmp_path, source=link)
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    scanner.config.options.scan_settings.filters_used = [
        DetectSecretsScanSettingsFiltersUsed(
            path=SHOULD_EXCLUDE_FILE_FILTER, pattern=[r"^tests/", r"real-tree"]
        )
    ]
    seen = _record_worker(scanner, monkeypatch)

    scanner.scan(target=link, target_type="source")

    assert seen, "the worker was not reached"
    assert _relative_scan_paths(seen, link) == ["settings.py"]


def test_the_operators_patterns_are_not_labeled_as_the_baselines(
    tmp_path, monkeypatch, caplog
):
    """A baseline is in use, and the pattern in play is the operator's own. The
    two filter runs shared one label, so a timeout in the operator's pattern was
    reported as 'loaded with the baseline ...', and the count of excluded files
    was logged as the baseline's."""
    context = _context(tmp_path)
    tree = Path(context.source_dir)
    _write(tree, "settings.py")
    _write(tree, "tests/fixture.py")
    _write(
        tree,
        ".secrets.baseline",
        json.dumps(
            {
                "version": "1.5.0",
                "plugins_used": [{"name": "AWSKeyDetector"}],
                "filters_used": [],
                "results": {},
                "generated_at": "2026-01-01T00:00:00Z",
            }
        ),
    )
    monkeypatch.chdir(tmp_path)
    scanner = DetectSecretsScanner(
        context=context,
        config=DetectSecretsScannerConfig(
            options=DetectSecretsScannerConfigOptions(
                scan_settings=DetectSecretsScanSettings(
                    filters_used=[
                        DetectSecretsScanSettingsFiltersUsed(
                            path=SHOULD_EXCLUDE_FILE_FILTER, pattern=[r"^tests/"]
                        )
                    ]
                )
            )
        ),
    )
    assert scanner._baseline_in_use()
    seen = _record_worker(scanner, monkeypatch)
    labels: list[str] = []
    real = DetectSecretsScanner._apply_file_exclusions

    def recording(files, patterns, root=None, timeout=None, source=""):
        if patterns:
            labels.append(source)
        return real(files, patterns, root, timeout, source)

    monkeypatch.setattr(
        DetectSecretsScanner, "_apply_file_exclusions", staticmethod(recording)
    )

    with caplog.at_level("DEBUG"):
        scanner.scan(target=tree, target_type="source")

    assert len(labels) == 1, labels
    assert "loaded with the baseline" not in labels[0]
    assert "tests/fixture.py" not in _relative_scan_paths(seen, tree)
    assert "based on baseline exclude patterns" not in caplog.text


def test_a_pattern_written_as_one_string_is_one_pattern(tmp_path, monkeypatch):
    """detect-secrets read ``"^tests/"`` as the patterns ``^``, ``t``, ``e``...,
    which excluded every file with a ``t`` in its path."""
    context = _context(tmp_path)
    source = Path(context.source_dir)
    _write(source, "settings.py")
    _write(source, "tests/fixture.py")
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    scanner.config.options.scan_settings.filters_used = [
        DetectSecretsScanSettingsFiltersUsed(
            path=SHOULD_EXCLUDE_FILE_FILTER, pattern=r"^tests/"
        )
    ]
    seen = _record_worker(scanner, monkeypatch)

    scanner.scan(target=source, target_type="source")

    assert _relative_scan_paths(seen, source) == ["settings.py"]
    assert not any(
        item.get("path") == SHOULD_EXCLUDE_FILE_FILTER
        for item in seen["scan_settings_dict"].get("filters_used", [])
    )


def test_other_filters_still_reach_the_worker(tmp_path, monkeypatch):
    """Control: only the file filter is applied by ASH and withheld."""
    context = _context(tmp_path)
    source = Path(context.source_dir)
    _write(source, "settings.py")
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    heuristic = "detect_secrets.filters.heuristic.is_likely_id_string"
    scanner.config.options.scan_settings.filters_used = [
        DetectSecretsScanSettingsFiltersUsed(path=heuristic),
        DetectSecretsScanSettingsFiltersUsed(
            path=SHOULD_EXCLUDE_FILE_FILTER, pattern=[r"^tests/"]
        ),
    ]
    seen = _record_worker(scanner, monkeypatch)

    scanner.scan(target=source, target_type="source")

    assert [
        item.get("path") for item in seen["scan_settings_dict"]["filters_used"]
    ] == [heuristic]


def test_a_baseline_the_repository_controls_is_scanned_like_any_file(
    tmp_path, monkeypatch
):
    """The tree's own baseline is the repository's file, so it is handed to
    the worker. Left out of the scan set, whatever the repository put in a
    file of that name under a key the shape check admits was never read."""
    context = _context(tmp_path)
    source = Path(context.source_dir)
    _write(source, "settings.py")
    _write(
        source,
        ".secrets.baseline",
        json.dumps(
            {
                "version": "1.5.0",
                "plugins_used": [{"name": "AWSKeyDetector"}],
                "filters_used": [],
                "results": {},
                "notes": "an extra top-level key the shape check admits",
                "generated_at": "2026-01-01T00:00:00Z",
            }
        ),
    )
    monkeypatch.chdir(tmp_path)
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    assert scanner._baseline_in_use()
    assert scanner._baseline_entries_trusted() is False
    seen = _record_worker(scanner, monkeypatch)

    scanner.scan(target=source, target_type="source")

    assert _relative_scan_paths(seen, source) == [".secrets.baseline", "settings.py"]


def test_ignore_paths_apply_to_a_relative_source_directory(tmp_path, monkeypatch):
    """A relative source directory's scan set has no resolved prefix to cut, so
    the ignore paths matched nothing against it."""
    monkeypatch.chdir(tmp_path)
    context = _context(tmp_path, source=Path("src"))
    source = Path(context.source_dir)
    _write(source, "keep.py")
    _write(source, "generated/made.py")
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    seen = _record_worker(scanner, monkeypatch)

    scanner.scan(
        target=source,
        target_type="source",
        global_ignore_paths=[
            IgnorePathWithReason(path="generated/", reason="generated code")
        ],
    )

    assert _relative_scan_paths(seen, tmp_path / "src") == ["keep.py"]


def test_an_ignore_path_for_a_source_file_does_not_drop_a_converted_file(
    tmp_path, monkeypatch
):
    """The anchor of an ignore path is the source directory for a converted file
    too, as it was before the relative-path fix. Anchored at the work directory it
    was scanned from, a converted file ``config.py`` (an archive member) read as
    ``config.py`` and an ignore path written for the source file ``config.py``
    dropped it as well."""
    context = _context(tmp_path)
    work = Path(context.work_dir)
    _write(work, "config.py")
    _write(work, "keep.py")
    scanner = DetectSecretsScanner(context=context, config=DetectSecretsScannerConfig())
    seen = _record_worker(scanner, monkeypatch)

    scanner.scan(
        target=work,
        target_type="converted",
        global_ignore_paths=[IgnorePathWithReason(path="config.py", reason="source")],
    )

    assert seen, "the worker was not reached"
    assert sorted(Path(item).name for item in seen["scan_paths"]) == [
        "config.py",
        "keep.py",
    ]
