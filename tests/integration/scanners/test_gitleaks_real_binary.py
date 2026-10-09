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
import subprocess
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
#: app/fingerprint_ignored.py is not.
EXPECTED = {
    ("aws-access-token", "app/settings.py", 5),
    ("github-pat", "app/settings.py", 4),
    ("github-pat", "docs/example.md", 5),
    ("slack-bot-token", "app/settings.py", 6),
}

#: What ASH reports: the above plus the finding ASH's re-scan adds back past the
#: tree's .gitleaksignore. Only inline_allowed.py's gitleaks:allow still hides one.
REPORTED = EXPECTED | {("github-pat", "app/fingerprint_ignored.py", 2)}

#: The two findings the fixture repo's own gitleaks config hides from gitleaks.
HIDDEN_BY_THE_TREE = {
    ("github-pat", "docs/example.md", 5),
    ("github-pat", "app/fingerprint_ignored.py", 2),
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
        out = subprocess.run(
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


def test_the_trees_own_gitleaks_config_and_ignore_file_hide_nothing(
    tmp_path, path_with_gitleaks
):
    source = _copy_fixture(tmp_path)
    # The positive control: gitleaks left to its own discovery honors both files.
    plain = tmp_path / "plain.sarif"
    subprocess.run(
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


def test_an_operator_config_file_still_applies(tmp_path, path_with_gitleaks):
    source = _copy_fixture(tmp_path)
    operator_config = tmp_path / "operator.toml"
    shutil.copy(source / ".gitleaks.toml", operator_config)
    _, report = _scan_direct(source, tmp_path / "out", config_file=str(operator_config))
    assert ("github-pat", "docs/example.md", 5) not in _findings(report)
    assert ("github-pat", "app/settings.py", 4) in _findings(report)


def test_the_inline_allow_comment_is_what_hides_its_finding(
    tmp_path, path_with_gitleaks
):
    source = _copy_fixture(tmp_path)
    target = source / "app" / "inline_allowed.py"
    target.write_text(
        target.read_text(encoding="utf-8").replace("  # gitleaks:allow", ""),
        encoding="utf-8",
    )
    _, report = _scan_direct(source, tmp_path / "out")
    assert ("github-pat", "app/inline_allowed.py", 2) in _findings(report)


def test_an_unparseable_operator_config_fails_rather_than_reports_clean(
    tmp_path, path_with_gitleaks
):
    from automated_security_helper.core.exceptions import ScannerError

    source = _copy_fixture(tmp_path)
    broken = tmp_path / "broken.toml"
    broken.write_text("this is [ not toml\n", encoding="utf-8")
    with pytest.raises(ScannerError, match="gitleaks exited 1"):
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
    proc = subprocess.run(
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
    assert all(
        r["locations"][0]["physicalLocation"]["region"]["snippet"]["text"] == REDACTED
        for r in results
    )

    # The control for the exclusion: gitleaks itself did report the planted copy.
    raw = json.loads(
        (output / "scanners" / "gitleaks" / "source" / "gitleaks.sarif").read_text(
            encoding="utf-8"
        )
    )
    assert any(
        uri.startswith(".ash/ash_output/previous/") for _, uri, _ in _raw_findings(raw)
    ), raw

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
