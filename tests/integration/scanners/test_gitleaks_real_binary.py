# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The real, pinned gitleaks binary under ASH.

These run in the ``integration-test`` CI job. The binary is never assumed: the
``gitleaks`` fixture uses one on PATH only if it reports the pinned version, and
otherwise installs the pinned release asset through ASH's own verified
installer (``install_pinned_tool``), which checks the SHA256 in
``utils/tool_downloads.py``. A failure to provision it FAILS the test rather
than skipping it, so this file cannot pass in CI without running gitleaks.

What is covered here and nowhere else:

* the committed capture ``gitleaks-8.30.1.sarif`` still matches what the pinned
  binary writes for the fixture repo (materialized by ``tests/utils/gitleaks_fixture.py``), so the unit tests parse real output;
* the fixture repo's own ``.gitleaks.toml`` allowlist and ``.gitleaksignore``
  fingerprint hide nothing from ASH, though gitleaks run on its own honors both
  (the positive control), and an operator's config file still applies;
* a full ``ash scan --scanners gitleaks`` -- CRITICAL findings, no secret value
  in any file ASH writes, ASH's output directory excluded, line-pinned and
  symbol-scoped suppressions, a broken config failing the run, and an
  enabled-but-missing binary failing the completeness gate;
* gitleaks makes no network calls: the scan passes with every proxy pointed at
  a closed port.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess  # nosec B404 - runs the real gitleaks binary and ash CLI under test
import sys
from pathlib import Path

import pytest
import yaml

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.gitleaks_scanner import (
    REDACTED,
    GitleaksScanner,
    GitleaksScannerConfig,
    GitleaksScannerConfigOptions,
)
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.secret_masking import MASKED_LINE
from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS
from tests.utils.gitleaks_fixture import TEMPLATE, fabricated_tokens, materialize

PluginContext.model_rebuild()

pytestmark = pytest.mark.integration

DATA = Path(__file__).parents[2] / "test_data" / "scanners" / "gitleaks"
CAPTURED_SARIF = DATA / "gitleaks-8.30.1.sarif"
PINNED = TOOL_VERSIONS["gitleaks"].lstrip("v")

#: What gitleaks writes for the fixture with ASH's argv, which is the committed
#: capture. The tree's .gitleaks.toml is not passed, so docs/example.md is in it;
#: gitleaks applies the tree's root .gitleaksignore itself, so
#: app/fingerprint_ignored.py is not. ASH passes --ignore-gitleaks-allow, so
#: app/inline_allowed.py is.
EXPECTED = {
    ("aws-access-token", "app/settings.py", 5),
    ("github-pat", "app/inline_allowed.py", 2),
    ("github-pat", "app/settings.py", 4),
    ("github-pat", "docs/example.md", 5),
    ("slack-bot-token", "app/settings.py", 6),
}

#: What ASH reports: the above plus the finding ASH's re-scan adds back past the
#: tree's .gitleaksignore.
REPORTED = EXPECTED | {("github-pat", "app/fingerprint_ignored.py", 2)}

#: The findings the fixture repo's own gitleaks config and comments hide from
#: gitleaks left to its defaults.
HIDDEN_BY_THE_TREE = {
    ("github-pat", "docs/example.md", 5),
    ("github-pat", "app/fingerprint_ignored.py", 2),
    ("github-pat", "app/inline_allowed.py", 2),
}


def _fixture_secrets() -> set[str]:
    """The six fabricated credential values the materialized fixture holds."""
    found = set(fabricated_tokens().values())
    assert len(found) == 6, found
    return found


def _arch() -> str:
    machine = platform.machine().lower()
    return {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}[
        machine
    ]


def _platform() -> str:
    return {"linux": "linux", "darwin": "darwin", "win32": "windows"}[sys.platform]


def _version_of(binary: str) -> str | None:
    try:
        out = subprocess.run(  # nosec B603 - fixed argv, asks the binary under test for its version
            [binary, "--version"], capture_output=True, text=True, timeout=30
        ).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    match = re.search(r"\d+\.\d+\.\d+", out)
    return match.group(0) if match else None


@pytest.fixture(scope="module")
def gitleaks_bin_dir(tmp_path_factory) -> Path:
    """A directory holding the pinned gitleaks, provisioned if need be."""
    on_path = shutil.which("gitleaks")
    if on_path and _version_of(on_path) == PINNED:
        return Path(on_path).parent
    from automated_security_helper.utils.download_utils import install_pinned_tool

    bin_dir = tmp_path_factory.mktemp("gitleaks-bin")
    try:
        installed = install_pinned_tool("gitleaks", _platform(), _arch(), bin_dir)
    except Exception as exc:  # pragma: no cover - network-dependent
        pytest.fail(
            f"could not provision gitleaks {PINNED} through ASH's pinned installer "
            f"({exc}). These tests must run, not skip."
        )
    assert _version_of(str(installed)) == PINNED
    return bin_dir


@pytest.fixture
def path_with_gitleaks(gitleaks_bin_dir, monkeypatch):
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setenv("PATH", f"{gitleaks_bin_dir}{os.pathsep}{os.environ['PATH']}")
    # find_executable caches per process, including a miss.
    monkeypatch.setattr(subprocess_utils, "_find_executable_cache", {})
    return gitleaks_bin_dir


def _copy_fixture(tmp_path: Path) -> Path:
    return materialize(tmp_path / "src")


def _scan_direct(source: Path, output: Path, **options):
    """Scan with ``options`` set by the operator (a config outside the tree)."""
    config = AshConfig()
    record_provenance(config, in_tree=[])
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=config,
    )
    scanner = GitleaksScanner(
        context=context,
        config=GitleaksScannerConfig(
            enabled=True, options=GitleaksScannerConfigOptions(**options)
        ),
    )
    report = scanner.scan(target=source, target_type="source")
    return scanner, report


def _findings(report) -> set:
    return {
        (
            r.ruleId,
            r.locations[0].physicalLocation.root.artifactLocation.uri,
            r.locations[0].physicalLocation.root.region.startLine,
        )
        for r in report.get_all_results()
    }


def _raw_findings(sarif: dict) -> set:
    return {
        (
            r["ruleId"],
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
        )
        for r in sarif["runs"][0]["results"]
    }


# --------------------------------------------------------------------------- #
# The scanner against the binary
# --------------------------------------------------------------------------- #


def test_the_binary_is_the_pinned_version(path_with_gitleaks):
    assert _version_of(shutil.which("gitleaks")) == PINNED


def test_the_committed_capture_matches_the_pinned_binary(tmp_path, path_with_gitleaks):
    source = _copy_fixture(tmp_path)
    scanner, report = _scan_direct(source, tmp_path / "out")
    assert scanner.exit_code == 2
    written = json.loads(
        (scanner.results_dir / "source" / "gitleaks.sarif").read_text(encoding="utf-8")
    )
    captured = json.loads(CAPTURED_SARIF.read_text(encoding="utf-8"))
    assert _raw_findings(written) == _raw_findings(captured) == EXPECTED
    # The rule catalog is part of the capture too: a new gitleaks with new rules
    # is a new capture, not a silent drift.
    assert [r["id"] for r in written["runs"][0]["tool"]["driver"]["rules"]] == [
        r["id"] for r in captured["runs"][0]["tool"]["driver"]["rules"]
    ]
    assert _findings(report) == REPORTED


def test_a_clean_tree_exits_zero_with_no_findings(tmp_path, path_with_gitleaks):
    source = tmp_path / "src"
    source.mkdir()
    shutil.copy(TEMPLATE / "app" / "clean.py", source / "clean.py")
    scanner, report = _scan_direct(source, tmp_path / "out")
    assert scanner.exit_code == 0
    assert _findings(report) == set()


def test_a_symlink_out_of_the_tree_is_not_followed(tmp_path, path_with_gitleaks):
    """gitleaks walks the target itself and, without --follow-symlinks (which ASH
    never passes), reads no file a symlink names; measured with 8.30.1."""
    source = tmp_path / "src"
    source.mkdir()
    shutil.copy(TEMPLATE / "app" / "clean.py", source / "clean.py")
    secrets = _copy_fixture(tmp_path / "secrets")
    try:
        (source / "linked-settings.py").symlink_to(secrets / "app" / "settings.py")
        (source / "linked-dir").symlink_to(secrets, target_is_directory=True)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")
    # The control: the same files scanned in place are found.
    _, direct = _scan_direct(secrets, tmp_path / "out-direct")
    assert _findings(direct)
    scanner, report = _scan_direct(source, tmp_path / "out")
    assert "--follow-symlinks" not in scanner._build_arguments(source, tmp_path / "x")
    assert _findings(report) == set()


def test_the_trees_own_gitleaks_config_and_ignore_file_hide_nothing(
    tmp_path, path_with_gitleaks
):
    source = _copy_fixture(tmp_path)
    # The positive control: gitleaks left to its own discovery honors both files.
    plain = tmp_path / "plain.sarif"
    subprocess.run(  # nosec B603 B607 - control run of gitleaks by name, as a user would
        [
            "gitleaks",
            "dir",
            "--report-format=sarif",
            f"--report-path={plain}",
            "--exit-code=0",
            "--no-banner",
            ".",
        ],
        cwd=source,
        check=True,
        capture_output=True,
        timeout=120,
    )
    hidden_by_gitleaks = HIDDEN_BY_THE_TREE - _raw_findings(
        json.loads(plain.read_text(encoding="utf-8"))
    )
    assert hidden_by_gitleaks == HIDDEN_BY_THE_TREE

    _, report = _scan_direct(source, tmp_path / "out")
    assert HIDDEN_BY_THE_TREE <= _findings(report)


def _located(report) -> list:
    """(rule, uri, line, column) of every result, sorted; duplicates kept."""
    return sorted(
        (
            r.ruleId,
            r.locations[0].physicalLocation.root.artifactLocation.uri,
            r.locations[0].physicalLocation.root.region.startLine,
            r.locations[0].physicalLocation.root.region.startColumn,
        )
        for r in report.get_all_results()
    )


def _two_tokens_on_one_line(source: Path) -> list:
    """Write app/two.py with two github-pat matches on line 1; return them located."""
    token = fabricated_tokens()["settings_github_pat"]
    other = token[:-4] + ("YYYY" if token.endswith("ZZZZ") else "ZZZZ")
    (source / "app").mkdir(parents=True)
    (source / "app" / "two.py").write_text(
        f'A = "{token}"; B = "{other}"\n', encoding="utf-8"
    )
    return [("github-pat", "app/two.py", 1, 6), ("github-pat", "app/two.py", 1, 54)]


def test_one_gitleaksignore_entry_hiding_two_secrets_reports_both(
    tmp_path, path_with_gitleaks
):
    """gitleaks' dir fingerprint is <file>:<rule>:<line>, so one entry hides both."""
    source = tmp_path / "src"
    both = _two_tokens_on_one_line(source)
    # The control: with no ignore file, gitleaks reports both, at two columns.
    _, plain = _scan_direct(source, tmp_path / "out-plain")
    assert _located(plain) == both
    (source / ".gitleaksignore").write_text("app/two.py:github-pat:1\n")
    _, report = _scan_direct(source, tmp_path / "out")
    assert _located(report) == both


def test_an_entry_spelled_with_a_dot_slash_adds_no_duplicate(
    tmp_path, path_with_gitleaks
):
    """gitleaks matches no ``./`` entry, and reports a file in the spelling it is
    given, so a re-scan under the entry's spelling duplicated every finding."""
    source = _copy_fixture(tmp_path)
    with (source / ".gitleaksignore").open("a", encoding="utf-8") as handle:
        handle.write("./app/settings.py:github-pat:4\n")
    _, report = _scan_direct(source, tmp_path / "out")
    located = _located(report)
    assert len(located) == len(set(located)) == len(REPORTED), located
    assert _findings(report) == REPORTED


def _plant_token(path: Path, line: int = 1) -> None:
    """Write a fabricated github-pat at ``line`` of ``path``."""
    token = fabricated_tokens()["settings_github_pat"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "\n" * (line - 1) + f"url = https://x:{token}@github.com/o/r.git\n",
        encoding="utf-8",
    )


def _gitleaks_alone(cwd: Path, scan: str, report: Path, *extra: str) -> set:
    """``gitleaks dir`` run directly, for a control: its (rule, uri, line)s."""
    subprocess.run(  # nosec B603 B607 - control run of gitleaks by name, as a user would
        [
            "gitleaks",
            "dir",
            "--report-format=sarif",
            f"--report-path={report}",
            "--redact=100",
            "--exit-code=0",
            "--no-banner",
            f"--gitleaks-ignore-path={report.parent}",
            *extra,
            "--",
            scan,
        ],
        cwd=cwd,
        check=True,
        capture_output=True,
        timeout=120,
    )
    return _raw_findings(json.loads(report.read_text(encoding="utf-8")))


@pytest.mark.parametrize("named", [".git/config", "vendor/lib/.git/config"])
def test_an_entry_under_a_dot_git_directory_adds_nothing(
    tmp_path, path_with_gitleaks, named
):
    """gitleaks' default allowlist skips every directory named .git, so the
    directory scan never reads a file there and an entry naming one hid nothing.
    gitleaks given the file on its own reads it, which is the control."""
    source = tmp_path / "src"
    _plant_token(source / named, line=2)
    (source / "app.py").write_text("x = 1\n", encoding="utf-8")
    assert _gitleaks_alone(source, named, tmp_path / "alone.sarif") == {
        ("github-pat", named, 2)
    }
    _, plain = _scan_direct(source, tmp_path / "out-plain")
    assert _findings(plain) == set()

    (source / ".gitleaksignore").write_text(f"{named}:github-pat:2\n")
    _, report = _scan_direct(source, tmp_path / "out")
    assert _findings(report) == set()


def test_an_operator_config_that_reads_dot_git_has_its_drops_added_back(
    tmp_path, path_with_gitleaks
):
    """The directory rules are the active config's: one with no allowlist reads
    .git, so there the tree's .gitleaksignore does hide a finding, and ASH adds it
    back."""
    source = tmp_path / "src"
    _plant_token(source / ".git" / "config", line=2)
    operator_config = tmp_path / "operator.toml"
    operator_config.write_text(
        "[[rules]]\nid = \"github-pat\"\nregex = '''ghp_[0-9a-zA-Z]{36}'''\n",
        encoding="utf-8",
    )
    _, plain = _scan_direct(
        source, tmp_path / "out-plain", config_file=str(operator_config)
    )
    assert _findings(plain) == {("github-pat", ".git/config", 2)}

    (source / ".gitleaksignore").write_text(".git/config:github-pat:2\n")
    _, report = _scan_direct(source, tmp_path / "out", config_file=str(operator_config))
    assert _findings(report) == {("github-pat", ".git/config", 2)}


def test_an_entry_through_a_symlinked_directory_adds_nothing(
    tmp_path, path_with_gitleaks
):
    """gitleaks follows no symlink, a symlinked directory included, so the
    directory scan never read linked/one.py; the file it points at is reported
    once, under its own path."""
    source = tmp_path / "src"
    _plant_token(source / "app" / "one.py")
    try:
        (source / "linked").symlink_to("app", target_is_directory=True)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")
    (source / ".gitleaksignore").write_text("linked/one.py:github-pat:1\n")
    _, report = _scan_direct(source, tmp_path / "out")
    assert _findings(report) == {("github-pat", "app/one.py", 1)}


def test_a_secret_in_the_gitleaksignore_it_hides_is_added_back(
    tmp_path, path_with_gitleaks
):
    """The ignore file is scanned like any file, and may name itself."""
    source = tmp_path / "src"
    token = fabricated_tokens()["settings_github_pat"]
    (source).mkdir()
    (source / ".gitleaksignore").write_text(
        f".gitleaksignore:github-pat:2\n# {token}\n", encoding="utf-8"
    )
    _, report = _scan_direct(source, tmp_path / "out")
    assert _findings(report) == {("github-pat", ".gitleaksignore", 2)}


MARKER = "ash-marker-5d1e9a"


def test_gitleaks_log_does_not_keep_the_lines_it_quotes_from_gitleaksignore(
    tmp_path, path_with_gitleaks
):
    """gitleaks logs each line it cannot parse; the tree's file is not ASH's log's."""
    source = _copy_fixture(tmp_path)
    with (source / ".gitleaksignore").open("a", encoding="utf-8") as handle:
        handle.write(f"not a fingerprint {MARKER}\n")
    scanner, report = _scan_direct(source, tmp_path / "out")
    log = scanner.results_dir / "source" / "GitleaksScanner.stderr.log"
    text = log.read_text(encoding="utf-8")
    assert "Invalid .gitleaksignore entry" in text  # the control: gitleaks said so
    quoted = MARKER in text
    assert not quoted, "gitleaks' log still quotes the .gitleaksignore line"
    assert "INF" in text  # the rest of the log is kept
    assert _findings(report) == REPORTED


def test_a_gitleaksignore_entry_with_a_nul_byte_is_skipped(
    tmp_path, path_with_gitleaks
):
    """Python cannot open a name with a NUL byte; that entry names nothing."""
    source = _copy_fixture(tmp_path)
    with (source / ".gitleaksignore").open("a", encoding="utf-8") as handle:
        handle.write("app/a\x00b.py:github-pat:1\n")
    scanner, report = _scan_direct(source, tmp_path / "out")
    assert scanner.exit_code == 2
    assert _findings(report) == REPORTED


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file names")
@pytest.mark.parametrize(
    "file_name, entry",
    [
        ("app/a\vb.py", "app/a\vb.py"),
        ("app/a\u2028b.py", "app/a\u2028b.py"),
        ("app/a\x1cb.py", "app/a\x1cb.py"),
        ("app/a\rb.py", "app/a\rb.py"),
        ("\x1fapp.py", "\x1fapp.py"),
        ("app/one.py", "app\\one.py"),
    ],
    ids=[
        "vertical tab",
        "U+2028",
        "U+001C",
        "carriage return",
        "leading U+001F",
        "backslash",
    ],
)
def test_an_entry_gitleaks_reads_differently_from_python_is_added_back(
    tmp_path, path_with_gitleaks, file_name, entry
):
    """gitleaks splits .gitleaksignore on newlines alone, trims Go's whitespace and
    turns backslashes into slashes. ASH parsed it with Python's splitlines() and
    strip(), so these entries hid a finding ASH never re-scanned."""
    source = tmp_path / "src"
    _plant_token(source / file_name)
    (source / ".gitleaksignore").write_text(
        f"{entry}:github-pat:1\n", encoding="utf-8", newline=""
    )
    # The control: gitleaks, reading the tree's file, hides the finding.
    alone = tmp_path / "alone.sarif"
    subprocess.run(  # nosec B603 B607 - control run of gitleaks by name, as a user would
        [
            "gitleaks",
            "dir",
            "--report-format=sarif",
            f"--report-path={alone}",
            "--redact=100",
            "--exit-code=0",
            "--no-banner",
            "--",
            ".",
        ],
        cwd=source,
        check=True,
        capture_output=True,
        timeout=120,
    )
    assert _raw_findings(json.loads(alone.read_text(encoding="utf-8"))) == set()
    _, report = _scan_direct(source, tmp_path / "out")
    assert _findings(report) == {("github-pat", file_name, 1)}


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks")
@pytest.mark.parametrize("option", ["config_file", "baseline_path"])
@pytest.mark.parametrize("shape", ["file", "directory"])
def test_an_operator_path_in_the_tree_that_links_out_is_not_read(
    tmp_path, path_with_gitleaks, option, shape
):
    """gitleaks read the file a link in the tree pointed at, and named it in its
    log; now gitleaks is not run and nothing outside the tree is read."""
    from automated_security_helper.core.exceptions import ScannerError

    source = _copy_fixture(tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "notes.txt").write_text(f"line one {MARKER}\n", encoding="utf-8")
    if shape == "file":
        (source / "named").symlink_to(outside / "notes.txt")
        value = "named"
    else:
        (source / "linked").symlink_to(outside, target_is_directory=True)
        value = "linked/notes.txt"
    output = tmp_path / "out"
    with pytest.raises(ScannerError, match="through a symbolic link"):
        _scan_direct(source, output, **{option: value})
    touched = [
        str(path.relative_to(output))
        for path in output.rglob("*")
        if path.is_file()
        and (
            outside.as_posix() in path.read_text(encoding="utf-8", errors="replace")
            or MARKER in path.read_text(encoding="utf-8", errors="replace")
        )
    ]
    assert touched == []


def test_an_operator_config_file_still_applies(tmp_path, path_with_gitleaks):
    source = _copy_fixture(tmp_path)
    operator_config = tmp_path / "operator.toml"
    shutil.copy(source / ".gitleaks.toml", operator_config)
    _, report = _scan_direct(source, tmp_path / "out", config_file=str(operator_config))
    assert ("github-pat", "docs/example.md", 5) not in _findings(report)
    assert ("github-pat", "app/settings.py", 4) in _findings(report)


def test_an_inline_allow_comment_hides_nothing_by_default(tmp_path, path_with_gitleaks):
    """ASH passes --ignore-gitleaks-allow: the comment is the tree's to write."""
    source = _copy_fixture(tmp_path)
    _, report = _scan_direct(source, tmp_path / "out")
    assert ("github-pat", "app/inline_allowed.py", 2) in _findings(report)


def test_the_operator_can_honor_inline_allow_comments(tmp_path, path_with_gitleaks):
    source = _copy_fixture(tmp_path)
    _, report = _scan_direct(source, tmp_path / "out", honor_inline_ignores=True)
    assert ("github-pat", "app/inline_allowed.py", 2) not in _findings(report)
    # The control: the same file without the comment is reported.
    target = source / "app" / "inline_allowed.py"
    target.write_text(
        target.read_text(encoding="utf-8").replace("  # gitleaks:allow", ""),
        encoding="utf-8",
    )
    _, report = _scan_direct(source, tmp_path / "out2", honor_inline_ignores=True)
    assert ("github-pat", "app/inline_allowed.py", 2) in _findings(report)


def test_an_unparseable_operator_config_fails_rather_than_reports_clean(
    tmp_path, path_with_gitleaks
):
    from automated_security_helper.core.exceptions import ScannerError

    source = _copy_fixture(tmp_path)
    broken = tmp_path / "broken.toml"
    broken.write_text("this is [ not toml\n", encoding="utf-8")
    # The scanner template refuses the run before gitleaks' own results reader.
    with pytest.raises(ScannerError, match="exited with code 1"):
        _scan_direct(source, tmp_path / "out", config_file=str(broken))


def test_no_network_is_needed(tmp_path, path_with_gitleaks, monkeypatch):
    """Every proxy points at a closed port; a network call would fail the scan."""
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY"):
        monkeypatch.setenv(name, "http://127.0.0.1:9")
    monkeypatch.setenv("NO_PROXY", "")
    monkeypatch.setenv("ASH_OFFLINE", "YES")
    source = _copy_fixture(tmp_path)
    scanner, report = _scan_direct(source, tmp_path / "out")
    assert scanner.exit_code == 2
    assert _findings(report) == REPORTED


# --------------------------------------------------------------------------- #
# ash scan, end to end
# --------------------------------------------------------------------------- #


def _ash() -> str:
    ash = shutil.which("ash", path=str(Path(sys.executable).parent))
    assert ash, f"no ash entry point beside {sys.executable}"
    return ash


def _run_ash(source: Path, output: Path, config: dict, env: dict, *extra: str):
    config_path = source.parent / "ash.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")
    proc = subprocess.run(  # nosec B603 - starts the real ash CLI under test, fixed argv
        [
            _ash(),
            "scan",
            "--mode",
            "local",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--config",
            str(config_path),
            "--scanners",
            "gitleaks",
            "--no-progress",
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=600,
        env=env,
    )
    log = f"exit {proc.returncode}\nSTDOUT:\n{proc.stdout[-4000:]}\nSTDERR:\n{proc.stderr[-4000:]}"
    return proc, log


def _env(bin_dir: Path | None) -> dict:
    env = dict(os.environ)
    if bin_dir is not None:
        env["PATH"] = f"{bin_dir}{os.pathsep}{env['PATH']}"
    return env


def _gitleaks_row(output: Path) -> dict:
    data = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    rows = data.get("scanner_results") or {}
    return rows.get("gitleaks") or {}


def test_ash_scan_reports_critical_findings_and_writes_no_secret(
    tmp_path, gitleaks_bin_dir
):
    source = _copy_fixture(tmp_path)
    # ASH's output directory inside the source tree, holding a copy of a secret
    # from an earlier run: gitleaks reads it, and ASH must drop the finding.
    output = source / ".ash" / "ash_output"
    # Not under reports/ or scanners/, which ASH clears when a scan starts.
    (output / "previous").mkdir(parents=True)
    shutil.copy(source / "app" / "settings.py", output / "previous" / "stale.py")

    proc, log = _run_ash(
        source,
        output,
        {"project_name": "gitleaks-e2e", "fail_on_findings": True},
        _env(gitleaks_bin_dir),
    )
    assert proc.returncode == 2, log  # actionable findings

    sarif = json.loads((output / "reports" / "ash.sarif").read_text(encoding="utf-8"))
    results = [
        r
        for run in sarif["runs"]
        for r in run.get("results", [])
        if "gitleaks" in (r.get("properties", {}).get("tags") or [])
    ]
    assert {
        (
            r["ruleId"],
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
            r["locations"][0]["physicalLocation"]["region"]["startLine"],
        )
        for r in results
    } == REPORTED, log
    assert {r["level"] for r in results} == {"error"}, log
    # A gitleaks finding is a secret finding, so its line is masked in the reports,
    # its own snippet included, over the REDACTED gitleaks writes.
    assert all(
        r["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
        == MASKED_LINE
        for r in results
    ), [r["locations"][0]["physicalLocation"]["region"]["snippet"] for r in results]

    # The control for the exclusion: gitleaks itself did report the planted copy.
    raw = json.loads(
        (output / "scanners" / "gitleaks" / "source" / "gitleaks.sarif").read_text(
            encoding="utf-8"
        )
    )
    assert any(
        uri.startswith(".ash/ash_output/previous/") for _, uri, _ in _raw_findings(raw)
    ), raw
    # And gitleaks' own report holds its redaction, not the value.
    assert {
        r["locations"][0]["physicalLocation"]["region"]["snippet"]["text"]
        for run in raw["runs"]
        for r in run.get("results", [])
    } == {REDACTED}, raw

    row = _gitleaks_row(output)
    assert row.get("status") == "FAILED", row
    assert row.get("severity_counts", {}).get("critical") == len(REPORTED), row

    # No file ASH wrote holds a fixture secret. The stale copy planted above is
    # the one exception, so it is excluded by name -- and it is a positive
    # control: the leak check must find the values in it.
    secrets = _fixture_secrets()
    planted = output / "previous" / "stale.py"
    assert any(s in planted.read_text(encoding="utf-8") for s in secrets)
    leaked = {}
    for path in output.rglob("*"):
        if path.is_file() and path != planted:
            text = path.read_text(encoding="utf-8", errors="replace")
            hits = [s for s in secrets if s in text]
            if hits:
                leaked[str(path.relative_to(output))] = len(hits)
    assert leaked == {}, leaked


def test_ash_scan_reports_a_secret_in_an_archive_once(tmp_path, gitleaks_bin_dir):
    """One token in a zip is one finding.

    ASH extracts the archive under ``<output>/converted`` and gitleaks scans that
    directory as the converted target. With the output directory inside the source
    tree (the default), the source run walks the same copy, and it used to be
    reported a second time.
    """
    import zipfile

    source = tmp_path / "src"
    source.mkdir()
    (source / "main.py").write_text("x = 1\n", encoding="utf-8")
    token = fabricated_tokens()["settings_github_pat"]
    with zipfile.ZipFile(source / "bundle.zip", "w") as archive:
        archive.writestr("conf/settings.py", f'TOKEN = "{token}"\n')
    output = source / ".ash" / "ash_output"

    proc, log = _run_ash(
        source,
        output,
        {"project_name": "gitleaks-archive", "fail_on_findings": True},
        _env(gitleaks_bin_dir),
    )
    assert proc.returncode == 2, log

    sarif = json.loads((output / "reports" / "ash.sarif").read_text(encoding="utf-8"))
    uris = [
        r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for run in sarif["runs"]
        for r in run.get("results", [])
        if r.get("ruleId") == "github-pat"
    ]
    assert len(uris) == 1, (uris, log)
    assert uris[0].endswith("conf/settings.py"), uris
    assert "/converted/" in f"/{uris[0]}", uris
    assert _gitleaks_row(output).get("severity_counts", {}).get("critical") == 1, log


#: A field name in every Linux ``/proc/<pid>/status``, and in no file of the fixture.
STATUS_FIELD = "TracerPid:"


@pytest.mark.parametrize("pointed_at", ["regular-file-outside-tree", "special-file"])
def test_ash_scan_refuses_a_symlinked_gitleaksignore_and_quotes_nothing(
    tmp_path, gitleaks_bin_dir, pointed_at
):
    """A .gitleaksignore that is a link is refused whatever it points at.

    gitleaks would read whatever the link names and log its lines, and the
    failure used to copy that log into ASH's results. The special file is
    ``/proc/self/status``: stat calls it an empty regular file, and its content
    is made for each process that reads it, so what ASH could read there is not
    what gitleaks would.
    """
    if pointed_at == "special-file":
        target = Path("/proc/self/status")
        if not target.exists():
            pytest.skip("no /proc on this platform")
        marker = STATUS_FIELD
    else:
        target = tmp_path / "outside.txt"
        target.write_text(f"{MARKER}\nline two {MARKER}\n", encoding="utf-8")
        marker = MARKER
    # The control: a reader of the link's target gets the marker.
    assert marker in target.read_text(encoding="utf-8")
    source = _copy_fixture(tmp_path)
    (source / ".gitleaksignore").unlink()
    try:
        (source / ".gitleaksignore").symlink_to(target)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")
    output = tmp_path / "out"
    proc, log = _run_ash(
        source,
        output,
        {"project_name": "gitleaks-link", "fail_on_findings": False},
        _env(gitleaks_bin_dir),
    )
    assert proc.returncode == 1, log  # gitleaks did not run: incomplete
    row = _gitleaks_row(output)
    assert row.get("status") == "ERROR", row
    in_console = marker in proc.stdout + proc.stderr
    assert not in_console, "the linked file's content reached ASH's console output"
    leaked = [
        str(path.relative_to(output))
        for path in output.rglob("*")
        if path.is_file()
        and marker in path.read_text(encoding="utf-8", errors="replace")
    ]
    assert leaked == []
    said_why = "is refused: it is a symbolic link" in (output / "ash.log").read_text(
        encoding="utf-8"
    )
    assert said_why, "ash.log does not say why gitleaks was not run"


def test_ash_suppressions_apply_to_gitleaks_findings(tmp_path, gitleaks_bin_dir):
    source = _copy_fixture(tmp_path)
    output = tmp_path / "out"
    config = {
        "project_name": "gitleaks-suppressions-e2e",
        "fail_on_findings": False,
        "global_settings": {
            "suppressions": [
                {
                    "rule_id": "github-pat",
                    "path": "app/settings.py",
                    "line_start": 4,
                    "line_end": 4,
                    "reason": "fixture",
                }
            ]
        },
    }
    proc, log = _run_ash(source, output, config, _env(gitleaks_bin_dir))
    assert proc.returncode == 0, log
    sarif = json.loads((output / "reports" / "ash.sarif").read_text(encoding="utf-8"))
    state = {
        (
            r["ruleId"],
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        ): bool(r.get("suppressions"))
        for run in sarif["runs"]
        for r in run.get("results", [])
        if "gitleaks" in (r.get("properties", {}).get("tags") or [])
    }
    assert state == {
        ("github-pat", "app/settings.py"): True,
        ("github-pat", "docs/example.md"): False,
        ("github-pat", "app/fingerprint_ignored.py"): False,
        ("github-pat", "app/inline_allowed.py"): False,
        ("aws-access-token", "app/settings.py"): False,
        ("slack-bot-token", "app/settings.py"): False,
    }, log


def _require_symbols_extra() -> None:
    try:
        import tree_sitter  # noqa: F401
        import tree_sitter_python  # noqa: F401
    except ImportError as exc:  # pragma: no cover - environment-dependent
        if os.environ.get("ASH_REQUIRE_SYMBOLS_EXTRA", "").strip().upper() in (
            "1",
            "YES",
            "TRUE",
        ):
            pytest.fail(
                "ASH_REQUIRE_SYMBOLS_EXTRA is set but the [symbols] extra is not "
                f"importable ({exc}). This test must run in CI, not skip."
            )
        pytest.skip(f"[symbols] extra not installed ({exc})")


def test_a_symbol_scoped_suppression_applies_to_a_gitleaks_finding(
    tmp_path, gitleaks_bin_dir
):
    """A credential inside one function is suppressed; the same rule elsewhere is not."""
    _require_symbols_extra()
    source = tmp_path / "src"
    source.mkdir()
    token = fabricated_tokens()["settings_github_pat"]
    (source / "client.py").write_text(
        "# Fixture: a fabricated token, never issued.\n"
        "def build_client():\n"
        f'    return "{token}"\n'
        "\n"
        f'MODULE_TOKEN = "{token}"\n',
        encoding="utf-8",
    )
    config = {
        "project_name": "gitleaks-symbol-e2e",
        "fail_on_findings": False,
        "global_settings": {
            "suppressions": [
                {
                    "rule_id": "github-pat",
                    "path": "client.py",
                    "symbol": "build_client",
                    "reason": "fixture",
                }
            ]
        },
    }
    proc, log = _run_ash(source, tmp_path / "out", config, _env(gitleaks_bin_dir))
    assert proc.returncode == 0, log
    sarif = json.loads(
        (tmp_path / "out" / "reports" / "ash.sarif").read_text(encoding="utf-8")
    )
    by_line = {
        r["locations"][0]["physicalLocation"]["region"]["startLine"]: bool(
            r.get("suppressions")
        )
        for run in sarif["runs"]
        for r in run.get("results", [])
        if r.get("ruleId") == "github-pat"
    }
    assert by_line == {3: True, 5: False}, log


def test_enabled_but_missing_is_missing_and_fails_the_scan(tmp_path):
    """No gitleaks anywhere on PATH: MISSING, and the completeness gate exits 1."""
    source = _copy_fixture(tmp_path)
    output = tmp_path / "out"
    env = dict(os.environ)
    # Keep only the directory holding this interpreter (for `ash` itself) and
    # drop any that holds a gitleaks.
    keep = [str(Path(sys.executable).parent)]
    env["PATH"] = os.pathsep.join(
        [
            *keep,
            *(
                p
                for p in env["PATH"].split(os.pathsep)
                if p and not shutil.which("gitleaks", path=p)
            ),
        ]
    )
    assert shutil.which("gitleaks", path=env["PATH"]) is None
    # find_executable also looks in ASH's bin directory and /usr/local/bin.
    env["ASH_BIN_PATH"] = str(tmp_path / "empty-ash-bin")
    if Path("/usr/local/bin/gitleaks").exists():  # pragma: no cover - host-dependent
        pytest.fail(
            "/usr/local/bin/gitleaks exists, and ASH always looks there, so this "
            "host cannot produce an enabled-but-missing gitleaks."
        )
    proc, log = _run_ash(
        source,
        output,
        {"project_name": "gitleaks-missing", "fail_on_findings": False},
        env,
    )
    assert proc.returncode == 1, log
    assert _gitleaks_row(output).get("status") == "MISSING", log
