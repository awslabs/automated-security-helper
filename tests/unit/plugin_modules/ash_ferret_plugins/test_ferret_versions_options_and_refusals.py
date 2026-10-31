# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Readings of the ferret-scan plugin that went wrong before.

- ``parse_version`` dropped a pre-release suffix, so ``2.4.5-rc1`` read as the
  release ``2.4.5`` and passed a minimum it is older than; then every pre-release
  of one version read as equal, the bare tuples did not order under ``<``, and the
  exclusive maximum admitted its own pre-releases (``2.6.0-rc1`` under ``2.6.0``).
- ``enable_preprocessors: false`` passed no flag, and both the bundled config and
  ferret-scan's own default turn preprocessing on, so the option did nothing.
- An option key that is not a string raised ``AttributeError`` out of the
  unsupported-options validator.
- ``--version`` output with no ``X.Y.Z`` in it was recorded as the version and
  parsed as ``(0,)``, so such a build read as older than the minimum.
- An ``exclude_patterns`` entry holding a comma reached ferret-scan as two
  patterns, and an empty entry as a pattern 2.4.x matches against every path.
- A link leaving the tree from inside an ignored directory was given a pattern,
  or refused the target, although the directory's own pattern leaves it out; and
  an ignored file counted as "another walked file" in the substring test.
- The reverse: a link under an ignored path was given no pattern of its own on the
  strength of that path's ignore pattern, which the ignore step then left out (a
  comma, no room, a kept path holding it), so nothing excluded the link.
- The mandatory ``--exclude`` value (the operator's patterns, ASH's output
  directories, the links leaving the tree) had no bound, past which ferret-scan
  cannot be started at all.
- A run the subprocess layer flagged was graded on its file and exit code.
- A target refused before the tool ran reported exit code 0; a scan that raised
  kept the previous target's end time.
- An error raised after the SARIF validated (attaching the scanner details) was
  reported as a results file that is not SARIF.
- With ``use_default_config`` off, the refused-config warning said ferret-scan
  would run with the bundled default, which it does not.
- ``_resolve_sarif_uri_base_ids`` rewrote the results' locations alone, then
  dropped the base table every other reference pointed at.
- A ferret-scan found only inside the scanned tree was reported as "not found".
"""

from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import IgnorePathWithReason
from automated_security_helper.plugin_modules.ash_ferret_plugins import (
    ferret_scanner,
)
from automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner import (
    FerretScannerConfig,
    FerretScannerConfigOptions,
    FerretScanScanner,
    _ignored_relatives,
    _link_exclude_patterns,
    _resolve_sarif_uri_base_ids,
    compare_versions,
    is_version_compatible,
    parse_version,
)
from automated_security_helper.schemas.sarif_schema_model import SarifReport

pytestmark = pytest.mark.unit

POSIX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="POSIX paths")

EMPTY_SARIF = {
    "version": "2.1.0",
    "runs": [{"tool": {"driver": {"name": "ferret-scan"}}, "results": []}],
}


def _scanner(context, **options) -> FerretScanScanner:
    scanner = FerretScanScanner(
        context=context,
        config=FerretScannerConfig(options=FerretScannerConfigOptions(**options)),
    )
    scanner.dependencies_satisfied = True
    return scanner


def _tree(root: Path, files: list[str]) -> Path:
    for relative in files:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("x = 1\n", encoding="utf-8")
    return root


def _run_double(response: dict, document: dict | None, started: list | None = None):
    def run(command, results_dir=None, **kwargs):
        if started is not None:
            started.append(list(command))
        if document is not None:
            Path(results_dir, "ferret-scan.sarif").write_text(
                json.dumps(document), encoding="utf-8"
            )
        return response

    return run


def _scan(scanner, run, target: Path, ignore_paths: list | None = None):
    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_post_scan"),
        patch.object(scanner, "_run_subprocess", side_effect=run),
        patch.object(scanner, "_plugin_log"),
    ):
        return scanner.scan(
            target=target, target_type="source", global_ignore_paths=ignore_paths or []
        )


# --- versions -------------------------------------------------------------------------


def test_a_pre_release_sorts_below_its_release():
    """A release carries a trailing 0 and a pre-release a -1 in that place, so
    the bare tuples order under ``<`` as compare_versions orders them (which pads
    the shorter tuple with zeros); a bare (2, 4, 5, -1) ranked above (2, 4, 5)."""
    assert parse_version("2.4.5-rc1") == (2, 4, 5, -1, 1)
    assert parse_version("2.4.5") == (2, 4, 5, 0)
    assert parse_version("2.4.5-rc1") < parse_version("2.4.5")
    assert compare_versions("2.4.5-rc1", "2.4.5") == -1
    assert compare_versions("2.4.5", "2.4.5-rc1") == 1
    assert compare_versions("2.4.5-rc1", "2.4.4") == 1
    assert compare_versions("1.0.0-beta", "1.0.0") == -1


def test_pre_releases_of_one_version_order_by_their_number():
    """A bare -1 read rc1 and rc2 as the same version."""
    assert compare_versions("2.4.5-rc1", "2.4.5-rc2") == -1
    assert compare_versions("2.4.5-rc2", "2.4.5-rc1") == 1
    assert compare_versions("2.4.5-rc2", "2.4.5-rc2") == 0


def test_build_metadata_ranks_with_its_release():
    assert parse_version("1.2.3+build7") == (1, 2, 3, 0)
    assert compare_versions("1.2.3+build7", "1.2.3") == 0


def test_a_pre_release_of_the_maximum_is_outside_the_range():
    """``<2.6.0`` excludes 2.6.0's own pre-releases, as PEP 440 reads it: the
    release part is compared at the upper bound. Compared as a pre-release,
    2.6.0-rc1 sorted below 2.6.0 and was admitted."""
    assert is_version_compatible("2.6.0-rc1", "2.4.5", "2.6.0") is False
    assert is_version_compatible("2.5.9-rc1", "2.4.5", "2.6.0") is True
    assert is_version_compatible("2.5.9", "2.4.5", "2.6.0") is True
    assert is_version_compatible("2.4.5", "2.4.5", "2.6.0") is True
    assert is_version_compatible("2.4.5-rc1", "2.4.5", "2.6.0") is False


@patch(
    "automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.find_executable"
)
def test_version_output_without_a_version_number_is_unknown(
    mock_find_executable, mock_plugin_context
):
    mock_find_executable.return_value = "/usr/local/bin/ferret-scan"
    scanner = FerretScanScanner(context=mock_plugin_context)

    with patch(
        "automated_security_helper.plugin_modules.ash_ferret_plugins.ferret_scanner.spawn_run"
    ) as mock_run:
        mock_run.return_value = MagicMock(
            returncode=0, stdout="ferret-scan development build"
        )
        version = scanner._get_installed_version()

    assert version is None


# --- options --------------------------------------------------------------------------


def test_preprocessors_off_is_passed_as_an_explicit_false(mock_plugin_context):
    """The bundled config and ferret-scan's own default both turn preprocessing
    on, so leaving the flag out changed nothing."""
    scanner = _scanner(mock_plugin_context, enable_preprocessors=False)
    scanner._process_config_options()

    keys = [arg.key for arg in scanner.args.extra_args]
    assert "--enable-preprocessors=false" in keys
    assert "--enable-preprocessors" not in keys


def test_control_preprocessors_on_is_passed_as_the_bare_flag(mock_plugin_context):
    scanner = _scanner(mock_plugin_context, enable_preprocessors=True)
    scanner._process_config_options()

    keys = [arg.key for arg in scanner.args.extra_args]
    assert "--enable-preprocessors" in keys
    assert "--enable-preprocessors=false" not in keys


def test_an_option_key_that_is_not_a_string_does_not_crash_the_validator():
    """The validator is called as the model calls it, with the raw mapping, so
    the test can fail two ways: an AttributeError out of ``str`` methods on an
    int key (the defect), or an unsupported key that is no longer refused (the
    control). The earlier form let any outcome pass."""
    data = {1: "x", "checks": "all"}

    assert FerretScannerConfigOptions.validate_no_unsupported_options(data) is data

    with pytest.raises(ValueError, match="Unsupported option 'FORMAT'"):
        FerretScannerConfigOptions.validate_no_unsupported_options({"FORMAT": "json"})


@pytest.mark.parametrize(
    ("patterns", "word"),
    [
        (["{a,b}"], "comma"),
        (["*.log", "vendor,build"], "comma"),
        ([""], "empty"),
        (["*.log", "   "], "empty"),
    ],
)
def test_an_exclude_pattern_the_value_cannot_carry_is_refused(patterns, word):
    with pytest.raises(ValidationError, match=word):
        FerretScannerConfigOptions(exclude_patterns=patterns)


def test_control_plain_exclude_patterns_are_accepted():
    options = FerretScannerConfigOptions(exclude_patterns=["*.log", "vendor/**"])

    assert options.exclude_patterns == ["*.log", "vendor/**"]


# --- links under ignored paths ------------------------------------------------------


@POSIX_ONLY
def test_the_walked_paths_under_an_ignored_directory_are_named(mock_plugin_context):
    root = mock_plugin_context.source_dir
    files = ["a.py", "vendor/x.py", "vendor/sub/leaving.py"]

    entries, ignored = _ignored_relatives(
        root, root, [IgnorePathWithReason(path="vendor/", reason="x")], files
    )

    assert entries == ["vendor/"]
    assert ignored == {"vendor/x.py", "vendor/sub/leaving.py"}


def _walk(files: list[str], links: list[str]) -> tuple[list[str], list[str]]:
    """A walk tuple as ``walked_files`` returns one: ``files`` is every file the
    walk found, the links among them, and ``links`` the links that leave the tree.
    Each test here builds its tuple through this, so none feeds a link that is
    absent from the files."""
    return sorted({*files, *links}), sorted(links)


@POSIX_ONLY
def test_a_link_under_an_ignored_directory_needs_no_pattern(tmp_path):
    target = tmp_path / "src"
    walk = _walk(["a.py", "vendor/x.py"], ["vendor/leaving.py"])

    patterns = _link_exclude_patterns(
        target, walk, ignored={"vendor/x.py", "vendor/leaving.py"}
    )

    assert patterns == []


@POSIX_ONLY
def test_control_a_link_nothing_ignores_gets_its_pattern(tmp_path):
    target = tmp_path / "src"
    walk = _walk(["a.py", "vendor/x.py"], ["vendor/leaving.py"])

    patterns = _link_exclude_patterns(target, walk, ignored=set())

    assert patterns == [os.fspath(target / "vendor" / "leaving.py")]


@POSIX_ONLY
def test_an_ignored_file_is_not_another_walked_file_in_the_substring_test(tmp_path):
    """2.4.x also leaves out every path a pattern is a substring of; a path the
    ignore paths cover is not read by ferret-scan, so it does not refuse the link."""
    target = tmp_path / "src"
    walk = _walk(["conf.py.bak"], ["conf.py"])

    with pytest.raises(ScannerError, match="another file's path holds its path"):
        _link_exclude_patterns(target, walk, ignored=set())

    assert _link_exclude_patterns(target, walk, ignored={"conf.py.bak"}) == [
        os.fspath(target / "conf.py")
    ]


@POSIX_ONLY
def test_a_scan_with_a_link_leaving_the_tree_under_an_ignored_directory_runs(
    mock_plugin_context, tmp_path
):
    root = _tree(mock_plugin_context.source_dir, ["src/a.js", "vendor/x.js"])
    outside = tmp_path / "outside.js"
    outside.write_text("x\n", encoding="utf-8")
    (root / "vendor" / "leaving.js").symlink_to(outside)
    started: list[list[str]] = []

    _scan(
        _scanner(mock_plugin_context),
        _run_double({"returncode": 0}, EMPTY_SARIF, started),
        root,
        [IgnorePathWithReason(path="vendor/", reason="third party")],
    )

    (argv,) = started
    patterns = argv[argv.index("--exclude") + 1].split(",")
    assert os.fspath(root / "vendor") + os.sep + "*" in patterns
    assert os.fspath(root / "vendor" / "leaving.js") not in patterns


@POSIX_ONLY
def test_a_link_whose_ignored_directory_got_no_pattern_is_refused_like_any_other(
    mock_plugin_context, tmp_path
):
    """The directory's path holds a comma, so its ignore pattern cannot be written;
    the link under it then leaves the tree with nothing excluding it, and its own
    path holds the comma too, so the target is refused rather than run."""
    root = _tree(mock_plugin_context.source_dir, ["src/a.js", "ven,dor/x.js"])
    outside = tmp_path / "outside.js"
    outside.write_text("x\n", encoding="utf-8")
    (root / "ven,dor" / "leaving.js").symlink_to(outside)
    started: list[list[str]] = []

    with pytest.raises(ScannerError, match="cannot carry its path"):
        _scan(
            _scanner(mock_plugin_context),
            _run_double({"returncode": 0}, EMPTY_SARIF, started),
            root,
            [IgnorePathWithReason(path="ven,dor/", reason="third party")],
        )

    assert started == []


@POSIX_ONLY
def test_an_ignored_link_whose_own_pattern_was_left_out_gets_one_as_a_link(
    mock_plugin_context, tmp_path
):
    """The ignored link's pattern is held by a kept file's path (``conf.js.bak``
    starts with it), so the ignore step leaves it out; on the 2.5.x line a pattern
    names one path only, so the link is excluded as a link leaving the tree."""
    root = _tree(mock_plugin_context.source_dir, ["conf.js.bak"])
    outside = tmp_path / "outside.js"
    outside.write_text("x\n", encoding="utf-8")
    (root / "conf.js").symlink_to(outside)
    scanner = _scanner(mock_plugin_context)
    scanner.tool_version = "2.5.3"
    started: list[list[str]] = []

    _scan(
        scanner,
        _run_double({"returncode": 0}, EMPTY_SARIF, started),
        root,
        [IgnorePathWithReason(path="conf.js", reason="generated")],
    )

    (argv,) = started
    patterns = argv[argv.index("--exclude") + 1].split(",")
    assert os.fspath(root / "conf.js") in patterns


@POSIX_ONLY
def test_control_the_same_link_on_the_substring_line_refuses_the_target(
    mock_plugin_context, tmp_path
):
    """2.4.x would leave ``conf.js.bak`` out with the link's pattern, and nothing
    else excludes the link, so the target is refused as for a link nothing ignores."""
    root = _tree(mock_plugin_context.source_dir, ["conf.js.bak"])
    outside = tmp_path / "outside.js"
    outside.write_text("x\n", encoding="utf-8")
    (root / "conf.js").symlink_to(outside)
    scanner = _scanner(mock_plugin_context)
    scanner.tool_version = "2.4.5"
    started: list[list[str]] = []

    with pytest.raises(ScannerError, match="another file's path holds its path"):
        _scan(
            scanner,
            _run_double({"returncode": 0}, EMPTY_SARIF, started),
            root,
            [IgnorePathWithReason(path="conf.js", reason="generated")],
        )

    assert started == []


@POSIX_ONLY
def test_a_link_whose_ignored_directory_fell_past_the_budget_refuses_the_target(
    mock_plugin_context, tmp_path, monkeypatch
):
    """The budget admits the mandatory value (nothing: no operator patterns, no
    output directory inside the target) but not the ignored directory's pattern, so
    the ignore step leaves it out; the link under it then needs its own pattern,
    which is longer still, so the value is past the budget and the target is
    refused with the count rather than run with the link readable."""
    root = _tree(mock_plugin_context.source_dir, ["vendor/x.js"])
    outside = tmp_path / "outside.js"
    outside.write_text("x\n", encoding="utf-8")
    (root / "vendor" / "leaving.js").symlink_to(outside)
    directory_pattern = os.fspath(root / "vendor") + os.sep + "*"
    monkeypatch.setattr(
        ferret_scanner, "_EXCLUDE_VALUE_BUDGET", len(directory_pattern) - 1
    )
    scanner = _scanner(mock_plugin_context)
    started: list[list[str]] = []

    with pytest.raises(ScannerError, match="leaving the tree under ignored paths"):
        _scan(
            scanner,
            _run_double({"returncode": 0}, EMPTY_SARIF, started),
            root,
            [IgnorePathWithReason(path="vendor/", reason="third party")],
        )

    assert started == []
    assert scanner.exit_code is None


@POSIX_ONLY
def test_a_written_ignore_pattern_gives_way_to_the_pattern_of_a_link_that_needs_room(
    mock_plugin_context, tmp_path, monkeypatch
):
    """``conf.js`` is an ignored link whose own ignore pattern is held by a kept
    file's path (``conf.js.bak``), so it needs a pattern of its own. ``other/`` is
    an ignored directory whose pattern was written and took the room: the two
    together are one byte past the budget. The ignore pattern is optional (ASH drops
    the findings under it after the scan), the link's is not, so the target is
    scanned with the link excluded and no refusal blaming the patterns."""
    root = _tree(mock_plugin_context.source_dir, ["conf.js.bak", "other/x.js"])
    outside = tmp_path / "outside.js"
    outside.write_text("x\n", encoding="utf-8")
    (root / "conf.js").symlink_to(outside)
    directory_pattern = os.fspath(root / "other") + os.sep + "*"
    link_pattern = os.fspath(root / "conf.js")
    monkeypatch.setattr(
        ferret_scanner,
        "_EXCLUDE_VALUE_BUDGET",
        len(directory_pattern) + len(link_pattern),
    )
    scanner = _scanner(mock_plugin_context)
    scanner.tool_version = "2.5.3"
    started: list[list[str]] = []

    _scan(
        scanner,
        _run_double({"returncode": 0}, EMPTY_SARIF, started),
        root,
        [
            IgnorePathWithReason(path="conf.js", reason="generated"),
            IgnorePathWithReason(path="other/", reason="third party"),
        ],
    )

    (argv,) = started
    patterns = argv[argv.index("--exclude") + 1].split(",")
    assert link_pattern in patterns
    assert directory_pattern not in patterns


@POSIX_ONLY
def test_an_ignored_file_under_a_left_out_entry_is_not_another_walked_file(
    mock_plugin_context, tmp_path, monkeypatch
):
    """On the 2.4.x line a pattern also leaves out every path it is a substring of,
    so a link ``vendor/conf.js`` next to ``vendor/conf.js.bak`` is refused when the
    second file counts as one that must stay readable. It is ignored, with the
    directory: its ignore pattern was left out for want of room, ferret-scan reads
    it, and ASH drops its findings, so leaving it out too costs nothing."""
    root = _tree(mock_plugin_context.source_dir, ["a/x.js", "vendor/conf.js.bak"])
    outside = tmp_path / "outside.js"
    outside.write_text("x\n", encoding="utf-8")
    (root / "vendor" / "conf.js").symlink_to(outside)
    link_pattern = os.fspath(root / "vendor" / "conf.js")
    monkeypatch.setattr(ferret_scanner, "_EXCLUDE_VALUE_BUDGET", len(link_pattern))
    scanner = _scanner(mock_plugin_context)
    scanner.tool_version = "2.4.5"
    started: list[list[str]] = []

    _scan(
        scanner,
        _run_double({"returncode": 0}, EMPTY_SARIF, started),
        root,
        [
            IgnorePathWithReason(path="a/", reason="generated"),
            IgnorePathWithReason(path="vendor/", reason="third party"),
        ],
    )

    (argv,) = started
    patterns = argv[argv.index("--exclude") + 1].split(",")
    assert link_pattern in patterns


# --- the mandatory exclude budget -----------------------------------------------------


def test_a_mandatory_exclude_value_past_the_budget_refuses_the_target(
    mock_plugin_context, monkeypatch
):
    root = _tree(mock_plugin_context.source_dir, ["a.txt"])
    monkeypatch.setattr(ferret_scanner, "_EXCLUDE_VALUE_BUDGET", 10, raising=False)
    scanner = _scanner(mock_plugin_context, exclude_patterns=["a" * 16])
    started: list[list[str]] = []

    with pytest.raises(ScannerError, match="could not be started"):
        _scan(scanner, _run_double({"returncode": 0}, EMPTY_SARIF, started), root)

    assert started == []
    assert scanner.exit_code is None


# --- flagged responses and times -----------------------------------------------------


def test_a_run_whose_output_could_not_be_recorded_is_not_graded_on_its_file(
    mock_plugin_context,
):
    root = _tree(mock_plugin_context.source_dir, ["a.txt"])

    with pytest.raises(ScannerError) as raised:
        _scan(
            _scanner(mock_plugin_context),
            _run_double(
                {"returncode": 0, "post_run_error": True, "error": "disk full"},
                EMPTY_SARIF,
            ),
            root,
        )

    assert "could not record" in str(raised.value)


def test_a_timed_out_run_is_reported_as_a_timeout(mock_plugin_context):
    root = _tree(mock_plugin_context.source_dir, ["a.txt"])

    with pytest.raises(ScannerError) as raised:
        _scan(
            _scanner(mock_plugin_context),
            _run_double({"returncode": -9, "timed_out": True}, None),
            root,
        )

    assert "timed out" in str(raised.value)
    assert "No such file" not in str(raised.value)


def test_a_scan_that_raises_records_its_own_end_time(mock_plugin_context):
    root = _tree(mock_plugin_context.source_dir, ["a.txt"])
    scanner = _scanner(mock_plugin_context)
    scanner.end_time = None

    with (
        patch.object(scanner, "_pre_scan", return_value=True),
        patch.object(scanner, "_resolve_arguments", side_effect=RuntimeError("boom")),
    ):
        with pytest.raises(ScannerError, match="boom"):
            scanner.scan(target=root, target_type="source")

    assert scanner.end_time is not None


def test_an_empty_target_does_not_keep_the_previous_targets_start_time(
    mock_plugin_context, tmp_path
):
    scanner = _scanner(mock_plugin_context)
    scanner.start_time = datetime.now(timezone.utc)
    empty = tmp_path / "empty"
    empty.mkdir()

    with patch.object(scanner, "_post_scan"):
        assert scanner.scan(target=empty, target_type="converted") is True

    assert scanner.start_time is None


def test_an_error_after_the_sarif_validated_is_not_called_a_bad_results_file(
    mock_plugin_context, monkeypatch
):
    root = _tree(mock_plugin_context.source_dir, ["a.txt"])
    with pytest.raises(ValidationError) as built:
        SarifReport.model_validate({"runs": "not a list"})
    validation_error = built.value
    attached: list[dict] = []

    def attach(**kwargs):
        attached.append(kwargs)
        raise validation_error

    monkeypatch.setattr(ferret_scanner, "attach_scanner_details", attach)

    with pytest.raises(ScannerError) as raised:
        _scan(
            _scanner(mock_plugin_context),
            _run_double({"returncode": 0}, EMPTY_SARIF),
            root,
        )

    # The error reached the catch-all FROM the attach step, not from the results
    # file read: any wrapped error satisfied the two text assertions alone.
    assert len(attached) == 1
    assert raised.value.__context__ is validation_error
    assert "not SARIF" not in str(raised.value)
    assert "Ferret scan failed" in str(raised.value)


# --- the refused-config warning ------------------------------------------------------


def test_the_refused_config_warning_names_the_empty_config_when_no_default_is_used(
    mock_plugin_context, mock_ferret_config_file
):
    scanner = _scanner(mock_plugin_context, use_default_config=False)
    messages: list[str] = []

    with patch.object(
        scanner, "_plugin_log", side_effect=lambda m, **k: messages.append(str(m))
    ):
        chosen = scanner._find_config_file(mock_ferret_config_file)

    assert chosen is None
    (warning,) = [m for m in messages if "repository-influenced" in m]
    assert "use_default_config is false" in warning
    assert "bundled with ASH" not in warning


def test_control_the_refused_config_warning_names_the_bundled_default(
    mock_plugin_context, mock_ferret_config_file
):
    scanner = _scanner(mock_plugin_context)
    messages: list[str] = []

    with patch.object(
        scanner, "_plugin_log", side_effect=lambda m, **k: messages.append(str(m))
    ):
        chosen = scanner._find_config_file(mock_ferret_config_file)

    assert chosen is not None
    (warning,) = [m for m in messages if "repository-influenced" in m]
    assert "bundled with ASH" in warning


# --- base ids everywhere in the run --------------------------------------------------


def test_every_artifact_location_in_the_run_is_resolved():
    base = "file:///work/src/"
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ferret-scan"}},
                "originalUriBaseIds": {"%SRCROOT%": {"uri": base}},
                "artifacts": [{"location": {"uri": "a.txt", "uriBaseId": "%SRCROOT%"}}],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "toolExecutionNotifications": [
                            {
                                "message": {"text": "x"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": "b.txt",
                                                "uriBaseId": "%SRCROOT%",
                                            }
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ],
                "results": [],
            }
        ],
    }

    _resolve_sarif_uri_base_ids(document)

    run = document["runs"][0]
    assert run["artifacts"][0]["location"] == {"uri": base + "a.txt"}
    notified = run["invocations"][0]["toolExecutionNotifications"][0]["locations"][0]
    assert notified["physicalLocation"]["artifactLocation"] == {"uri": base + "b.txt"}
    assert "originalUriBaseIds" not in run


def _at(name: str) -> dict:
    return {"uri": name, "uriBaseId": "%SRCROOT%"}


def test_every_artifact_location_of_a_result_is_resolved():
    """The places a result keeps a location besides ``locations``: its related
    locations, its analysis target, its code flows and its fixes."""
    base = "file:///work/src/"
    result = {
        "ruleId": "r",
        "message": {"text": "x"},
        "locations": [{"physicalLocation": {"artifactLocation": _at("c.txt")}}],
        "relatedLocations": [{"physicalLocation": {"artifactLocation": _at("d.txt")}}],
        "analysisTarget": _at("e.txt"),
        "codeFlows": [
            {
                "threadFlows": [
                    {
                        "locations": [
                            {
                                "location": {
                                    "physicalLocation": {
                                        "artifactLocation": _at("f.txt")
                                    }
                                }
                            }
                        ]
                    }
                ]
            }
        ],
        "fixes": [
            {
                "artifactChanges": [
                    {"artifactLocation": _at("g.txt"), "replacements": []}
                ]
            }
        ],
    }
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ferret-scan"}},
                "originalUriBaseIds": {"%SRCROOT%": {"uri": base}},
                "results": [result],
            }
        ],
    }

    _resolve_sarif_uri_base_ids(document)

    assert result["locations"][0]["physicalLocation"]["artifactLocation"] == {
        "uri": base + "c.txt"
    }
    assert result["relatedLocations"][0]["physicalLocation"]["artifactLocation"] == {
        "uri": base + "d.txt"
    }
    assert result["analysisTarget"] == {"uri": base + "e.txt"}
    flow = result["codeFlows"][0]["threadFlows"][0]["locations"][0]["location"]
    assert flow["physicalLocation"]["artifactLocation"] == {"uri": base + "f.txt"}
    assert result["fixes"][0]["artifactChanges"][0]["artifactLocation"] == {
        "uri": base + "g.txt"
    }
    assert "originalUriBaseIds" not in document["runs"][0]


def test_a_location_with_an_undeclared_base_is_left_as_written_and_the_table_kept():
    base = "file:///work/src/"
    document = {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "ferret-scan"}},
                "originalUriBaseIds": {"%SRCROOT%": {"uri": base}},
                "artifacts": [
                    {"location": _at("a.txt")},
                    {"location": {"uri": "h.txt", "uriBaseId": "%ELSEWHERE%"}},
                ],
                "results": [],
            }
        ],
    }

    _resolve_sarif_uri_base_ids(document)

    run = document["runs"][0]
    assert run["artifacts"][0]["location"] == {"uri": base + "a.txt"}
    assert run["artifacts"][1]["location"] == {
        "uri": "h.txt",
        "uriBaseId": "%ELSEWHERE%",
    }
    assert run["originalUriBaseIds"] == {"%SRCROOT%": {"uri": base}}


# --- dependencies ---------------------------------------------------------------------


def test_a_ferret_scan_refused_inside_the_scanned_tree_is_recorded_as_refused(
    mock_plugin_context, monkeypatch
):
    monkeypatch.setattr(ferret_scanner, "find_executable", lambda name: None)
    monkeypatch.setattr(
        ferret_scanner,
        "in_tree_refusal",
        lambda command: f"a {command} inside the scanned tree was refused",
    )
    scanner = FerretScanScanner(context=mock_plugin_context)

    assert scanner.validate_plugin_dependencies() is False
    assert scanner.dependency_unavailable_reason == (
        "a ferret-scan inside the scanned tree was refused"
    )
