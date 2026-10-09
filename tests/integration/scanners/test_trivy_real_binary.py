# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The real, pinned trivy binary under ASH, for the builtin scanner and trivy-repo.

These run in the ``integration-test`` CI job. The binary is never assumed: the
``trivy_bin_dir`` fixture uses one on PATH only if it reports the pinned version,
and otherwise installs the pinned release asset through ASH's own verified
installer, which checks the SHA256 in ``utils/tool_downloads.py``. The
vulnerability database is downloaded once per module into a private cache. A
failure to provision either FAILS the tests rather than skipping them, so this
file cannot pass in CI without running trivy.

What is covered here and nowhere else:

* the advisories the committed capture (``trivy-0.69.3.vuln.sarif``) is built
  around are still what the pinned binary reports for the fixture repo, and its
  negatives (six, ms) and the off-by-default misconfiguration scanner still report
  nothing;
* ASH's output directory inside the target is skipped by trivy itself;
* ``ash scan --scanners trivy`` end to end, online and offline: the content
  database record, the offline flags, a stale database failing the scan (and
  passing under ``--allow-stale-content-db``), and an offline scan with no
  database at all reported MISSING;
* ``trivy`` and ``trivy-repo`` enabled together: both run, each reports the same
  advisory under its own name, and one rule-id suppression covers both.
"""

from __future__ import annotations

import json
import os
import platform
import re
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from tests.utils.trivy_fixture import materialize
import yaml

from automated_security_helper.base.plugin_context import PluginContext
from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.plugin_modules.ash_builtin.scanners.trivy_scanner import (
    TrivyScanner,
    TrivyScannerConfig,
    TrivyScannerConfigOptions,
)
from automated_security_helper.utils.config_trust import record_provenance
from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

PluginContext.model_rebuild()

pytestmark = pytest.mark.integration

DATA = Path(__file__).parents[2] / "test_data" / "scanners" / "trivy"
CAPTURED_SARIF = DATA / "trivy-0.69.3.vuln.sarif"
PINNED = TOOL_VERSIONS["trivy"].lstrip("v")

#: Advisories old enough that the database will keep them: one per manifest.
STABLE = {
    ("CVE-2018-18074", "requirements.txt"),
    ("CVE-2021-23337", "package-lock.json"),
}


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
def trivy_bin_dir(tmp_path_factory) -> Path:
    """A directory holding the pinned trivy, provisioned if need be."""
    on_path = shutil.which("trivy")
    if on_path and _version_of(on_path) == PINNED:
        return Path(on_path).parent
    from automated_security_helper.utils.download_utils import install_pinned_tool

    bin_dir = tmp_path_factory.mktemp("trivy-bin")
    try:
        installed = install_pinned_tool("trivy", _platform(), _arch(), bin_dir)
    except Exception as exc:  # pragma: no cover - network-dependent
        pytest.fail(
            f"could not provision trivy {PINNED} through ASH's pinned installer "
            f"({exc}). These tests must run, not skip."
        )
    assert _version_of(str(installed)) == PINNED
    return bin_dir


@pytest.fixture(scope="module")
def trivy_cache(trivy_bin_dir, tmp_path_factory) -> Path:
    """A private trivy cache holding a freshly downloaded vulnerability database."""
    cache = tmp_path_factory.mktemp("trivy-cache")
    trivy = shutil.which("trivy", path=str(trivy_bin_dir))
    proc = subprocess.run(
        [trivy, "image", "--download-db-only", "--cache-dir", str(cache)],
        capture_output=True,
        text=True,
        timeout=600,
    )
    if proc.returncode != 0:  # pragma: no cover - network-dependent
        pytest.fail(
            "could not download trivy's vulnerability database; these tests must "
            f"run, not skip: {proc.stderr[-2000:]}"
        )
    return cache


@pytest.fixture
def trivy_env(trivy_bin_dir, trivy_cache, monkeypatch):
    from automated_security_helper.utils import subprocess_utils

    monkeypatch.setenv("PATH", f"{trivy_bin_dir}{os.pathsep}{os.environ['PATH']}")
    monkeypatch.setenv("TRIVY_CACHE_DIR", str(trivy_cache))
    monkeypatch.delenv("ASH_OFFLINE", raising=False)
    # find_executable caches per process, including a miss.
    monkeypatch.setattr(subprocess_utils, "_find_executable_cache", {})
    return dict(os.environ)


def _copy_fixture(tmp_path: Path) -> Path:
    source = tmp_path / "src"
    materialize(source)
    return source


def _scan_direct(source: Path, output: Path, *, operator: bool = False, **options):
    """A direct scan whose config is the scanned tree's, or the operator's."""
    config = AshConfig()
    record_provenance(
        config,
        in_tree=[] if operator else [source / ".ash" / ".ash.yaml"],
        trusted=AshConfig(),
    )
    context = PluginContext(
        source_dir=source,
        output_dir=output,
        work_dir=output / "converted",
        config=config,
    )
    options.setdefault("offline", False)
    scanner = TrivyScanner(
        context=context,
        config=TrivyScannerConfig(
            enabled=True, options=TrivyScannerConfigOptions(**options)
        ),
    )
    scanner.dependencies_satisfied = scanner.validate_plugin_dependencies()
    report = scanner.scan(target=source, target_type="source")
    return scanner, report


def _pairs(report) -> set:
    return {
        (r.ruleId, r.locations[0].physicalLocation.root.artifactLocation.uri)
        for r in report.get_all_results()
    }


# --------------------------------------------------------------------------- #
# The scanner against the binary
# --------------------------------------------------------------------------- #


def test_the_binary_is_the_pinned_version(trivy_env):
    assert _version_of(shutil.which("trivy")) == PINNED


def test_the_capture_still_describes_the_pinned_binary(tmp_path, trivy_env):
    source = _copy_fixture(tmp_path)
    scanner, report = _scan_direct(source, tmp_path / "out")
    assert scanner.exit_code == 0
    live = _pairs(report)
    captured = json.loads(CAPTURED_SARIF.read_text(encoding="utf-8"))
    captured_pairs = {
        (r["ruleId"], r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])
        for r in captured["runs"][0]["results"]
    }
    assert STABLE <= captured_pairs
    assert STABLE <= live
    # Only the two manifests with a vulnerable package are reported: the
    # negatives (six, ms) have no advisory and the Dockerfile is a misconfig
    # target, which the default scanner set does not run.
    assert {uri for _, uri in live} == {"requirements.txt", "package-lock.json"}
    packages = {r.properties.package_name for r in report.get_all_results()}
    assert packages == {"requests", "lodash"}
    lodash = [
        r for r in report.get_all_results() if r.properties.package_name == "lodash"
    ]
    assert {r.properties.package_path for r in lodash} == {"node_modules/lodash"}


def test_misconfig_runs_when_enabled(tmp_path, trivy_env):
    source = _copy_fixture(tmp_path)
    _, report = _scan_direct(source, tmp_path / "out", scanners=["vuln", "misconfig"])
    assert ("DS-0002", "Dockerfile") in _pairs(report)


def test_the_output_dir_inside_the_target_is_skipped_by_trivy(tmp_path, trivy_env):
    source = _copy_fixture(tmp_path)
    output = source / ".ash" / "ash_output"
    planted = output / "previous"
    planted.mkdir(parents=True)
    (planted / "requirements.txt").write_text("urllib3==1.24.1\n", encoding="utf-8")
    _, report = _scan_direct(source, output)
    assert not [uri for _, uri in _pairs(report) if "ash_output" in uri]
    # The control: the same file outside the output directory is reported.
    shutil.move(str(planted), str(source / "previous"))
    _, report = _scan_direct(source, tmp_path / "out2")
    assert any(uri == "previous/requirements.txt" for _, uri in _pairs(report))


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
            "--ash-plugin-modules",
            "automated_security_helper.plugin_modules.ash_trivy_plugins",
            "--mode",
            "local",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--config",
            str(config_path),
            "--no-progress",
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=900,
        env=env,
    )
    log = f"exit {proc.returncode}\nSTDOUT:\n{proc.stdout[-6000:]}\nSTDERR:\n{proc.stderr[-4000:]}"
    return proc, log


def _aggregated(output: Path) -> dict:
    return json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )


def _content_db_records(data: dict) -> list:
    found = []
    for run in data["sarif"]["runs"]:
        for invocation in run.get("invocations") or []:
            found.extend(
                (invocation.get("properties") or {}).get("ash_content_databases") or []
            )
    return found


def _command_lines(data: dict) -> list:
    return [
        invocation.get("commandLine", "")
        for run in data["sarif"]["runs"]
        for invocation in run.get("invocations") or []
    ]


# trivy is on by default; set here so these tests do not depend on that default.
CONFIG = {
    "project_name": "trivy-e2e",
    "fail_on_findings": True,
    "scanners": {"trivy": {"enabled": True}},
}


def test_ash_scan_runs_trivy_and_records_its_database(tmp_path, trivy_env):
    source = _copy_fixture(tmp_path)
    output = tmp_path / "out"
    proc, log = _run_ash(source, output, CONFIG, trivy_env, "--scanners", "trivy")
    assert proc.returncode == 2, log  # actionable findings
    data = _aggregated(output)
    assert data["scanner_results"]["trivy"]["status"] == "FAILED", log
    records = [r for r in _content_db_records(data) if r["name"] == "trivy-db"]
    assert records and {r["scanner"] for r in records} == {"trivy"}, records
    assert not any(r["stale"] for r in records), records
    # Online: ASH updated the database first, under its lock, so the scan itself
    # skipped the update; it is not an offline scan.
    lines = _command_lines(data)
    assert any("--skip-db-update" in c for c in lines), lines
    assert not any("--offline-scan" in c for c in lines), lines


def test_ash_scan_offline_uses_the_cached_database(tmp_path, trivy_env):
    source = _copy_fixture(tmp_path)
    output = tmp_path / "out"
    proc, log = _run_ash(
        source, output, CONFIG, trivy_env, "--scanners", "trivy", "--offline"
    )
    assert proc.returncode == 2, log
    data = _aggregated(output)
    assert any("--skip-db-update" in c for c in _command_lines(data)), log
    assert STABLE <= {
        (
            r["ruleId"],
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        )
        for run in data["sarif"]["runs"]
        for r in run.get("results") or []
    }


def _stale_cache(trivy_cache: Path, tmp_path: Path, age: timedelta) -> Path:
    """A copy of the cache whose database says it was built *age* ago."""
    stale = tmp_path / "stale-cache"
    (stale / "db").mkdir(parents=True)
    shutil.copy(trivy_cache / "db" / "trivy.db", stale / "db" / "trivy.db")
    meta = json.loads((trivy_cache / "db" / "metadata.json").read_text("utf-8"))
    built = datetime.now(timezone.utc) - age
    meta["UpdatedAt"] = built.strftime("%Y-%m-%dT%H:%M:%SZ")
    meta["NextUpdate"] = (built + timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    (stale / "db" / "metadata.json").write_text(json.dumps(meta), "utf-8")
    return stale


def test_offline_a_stale_database_fails_the_scan(tmp_path, trivy_env, trivy_cache):
    env = {
        **trivy_env,
        "TRIVY_CACHE_DIR": str(_stale_cache(trivy_cache, tmp_path, timedelta(days=3))),
    }
    source = _copy_fixture(tmp_path)
    output = tmp_path / "out"
    proc, log = _run_ash(
        source, output, CONFIG, env, "--scanners", "trivy", "--offline"
    )
    assert proc.returncode == 1, log
    assert "trivy-db" in proc.stdout + proc.stderr, log
    stale = [r for r in _content_db_records(_aggregated(output)) if r["stale"]]
    assert [(r["name"], r["scanner"], r["enforced"]) for r in stale] == [
        ("trivy-db", "trivy", True)
    ], stale

    # The opt-out: the scan reports its findings and passes the staleness gate.
    output2 = tmp_path / "out2"
    proc, log = _run_ash(
        source,
        output2,
        CONFIG,
        env,
        "--scanners",
        "trivy",
        "--offline",
        "--allow-stale-content-db",
    )
    assert proc.returncode == 2, log


def test_offline_with_no_database_is_missing(tmp_path, trivy_env):
    empty = tmp_path / "empty-cache"
    empty.mkdir()
    env = {**trivy_env, "TRIVY_CACHE_DIR": str(empty)}
    source = _copy_fixture(tmp_path)
    output = tmp_path / "out"
    proc, log = _run_ash(
        source, output, CONFIG, env, "--scanners", "trivy", "--offline"
    )
    assert proc.returncode == 1, log
    assert _aggregated(output)["scanner_results"]["trivy"]["status"] == "MISSING", log
    assert "no vulnerability database" in proc.stdout + proc.stderr, log
    # Nothing was downloaded: offline means offline.
    assert not any(empty.iterdir())


def test_trivy_and_trivy_repo_together_report_each_under_its_own_name(
    tmp_path, trivy_env
):
    source = _copy_fixture(tmp_path)
    output = tmp_path / "out"
    config = {
        **CONFIG,
        "ash_plugin_modules": [
            "automated_security_helper.plugin_modules.ash_trivy_plugins"
        ],
        "global_settings": {
            "suppressions": [
                {
                    "rule_id": "CVE-2018-18074",
                    "path": "requirements.txt",
                    "reason": "one suppression, both scanners",
                }
            ]
        },
    }
    proc, log = _run_ash(
        source, output, config, trivy_env, "--scanners", "trivy,trivy-repo"
    )
    assert proc.returncode == 2, log
    data = _aggregated(output)
    assert {"trivy", "trivy-repo"} <= set(data["scanner_results"]), log
    by_scanner: dict[str, list] = {}
    for run in data["sarif"]["runs"]:
        for r in run.get("results") or []:
            name = (r.get("properties") or {}).get("scanner_name")
            by_scanner.setdefault(name, []).append(r)
    for name in ("trivy", "trivy-repo"):
        hits = [r for r in by_scanner.get(name, []) if r["ruleId"] == "CVE-2018-18074"]
        assert len(hits) == 1, (name, log)
        assert hits[0].get("suppressions"), (name, hits[0])
    # Both measured the one database, each under its own name.
    readers = {
        r["scanner"] for r in _content_db_records(data) if r["name"] == "trivy-db"
    }
    assert readers == {"trivy", "trivy-repo"}


def test_the_scanned_repos_own_trivy_config_cannot_shrink_the_report(
    tmp_path, trivy_env
):
    """trivy.yaml and .trivyignore in the target are not read unless opted in."""
    source = _copy_fixture(tmp_path)
    _, baseline = _scan_direct(source, tmp_path / "out0")
    (source / "trivy.yaml").write_text("severity:\n  - CRITICAL\n", encoding="utf-8")
    (source / ".trivyignore").write_text("CVE-2018-18074\n", encoding="utf-8")
    _, report = _scan_direct(source, tmp_path / "out1")
    assert _pairs(report) == _pairs(baseline)
    # Named by the tree's ASH config, neither file is passed either.
    _, in_tree = _scan_direct(
        source, tmp_path / "out2", ignore_file=".trivyignore", config_file="trivy.yaml"
    )
    assert _pairs(in_tree) == _pairs(baseline)
    # Each is honored only from the operator, for a file outside the tree, and then
    # does what trivy says it does.
    operator_ignore = tmp_path / "operator-ignore" / ".trivyignore"
    operator_ignore.parent.mkdir()
    operator_ignore.write_text("CVE-2018-18074\n", encoding="utf-8")
    _, ignored = _scan_direct(
        source, tmp_path / "out3", operator=True, ignore_file=str(operator_ignore)
    )
    assert _pairs(ignored) == _pairs(baseline) - {
        ("CVE-2018-18074", "requirements.txt")
    }
    operator_config = tmp_path / "operator" / "trivy.yaml"
    operator_config.parent.mkdir()
    operator_config.write_text("severity:\n  - CRITICAL\n", encoding="utf-8")
    _, critical = _scan_direct(
        source, tmp_path / "out4", operator=True, config_file=str(operator_config)
    )
    assert _pairs(critical) < _pairs(baseline)


def test_an_output_dir_name_trivy_reads_as_a_list_and_glob_is_still_skipped(
    tmp_path, trivy_env
):
    source = _copy_fixture(tmp_path)
    output = source / "out,[1]"
    planted = output / "previous"
    planted.mkdir(parents=True)
    (planted / "requirements.txt").write_text("urllib3==1.24.1\n", encoding="utf-8")
    _, report = _scan_direct(source, output)
    assert not [uri for _, uri in _pairs(report) if uri.startswith("out,[1]")]


def test_the_scanned_repos_secret_config_cannot_disable_rules(tmp_path, trivy_env):
    """trivy-secret.yaml in the target is not read unless opted in."""
    import secrets
    import string

    source = tmp_path / "src"
    source.mkdir()
    # Generated per run so no credential-shaped string is committed.
    key_id = "AKIA" + "".join(
        secrets.choice(string.ascii_uppercase + "234567") for _ in range(16)
    )
    secret = "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(40)
    )
    (source / "creds.env").write_text(
        f"AWS_ACCESS_KEY_ID={key_id}\nAWS_SECRET_ACCESS_KEY={secret}\n",
        encoding="utf-8",
    )
    _, baseline = _scan_direct(source, tmp_path / "out0", scanners=["secret"])
    assert baseline.get_all_results(), "the control: trivy finds the credential"
    repo_rules_file = "trivy-secret.yaml"
    (source / repo_rules_file).write_text(
        "disable-rules:\n  - aws-access-key-id\n  - aws-secret-access-key\n",
        encoding="utf-8",
    )
    _, report = _scan_direct(source, tmp_path / "out1", scanners=["secret"])
    assert _pairs(report) == _pairs(baseline)
    # Named by the tree's ASH config, it is still not passed.
    _, named = _scan_direct(
        source,
        tmp_path / "out2",
        scanners=["secret"],
        secret_config_file=repo_rules_file,
    )
    assert _pairs(named) == _pairs(baseline)
    # The operator's, outside the tree, applies.
    operator_rules = tmp_path / "operator" / repo_rules_file
    operator_rules.parent.mkdir()
    shutil.copy(source / repo_rules_file, operator_rules)
    _, opted = _scan_direct(
        source,
        tmp_path / "out3",
        operator=True,
        scanners=["secret"],
        secret_config_file=str(operator_rules),
    )
    assert _pairs(opted) < _pairs(baseline)


#: A Rego ignore policy (trivy's --ignore-policy) that drops one fixture CVE. trivy
#: evaluates it with Rego v0 syntax.
_IGNORE_POLICY = (
    "package trivy\n\ndefault ignore = false\n\n"
    'ignore {\n\tinput.VulnerabilityID == "CVE-2023-32681"\n}\n'
)
_DROPPED_BY_THE_POLICY = ("CVE-2023-32681", "requirements.txt")


def _plant_ignore_policy(root: Path) -> None:
    """A trivy.yaml in ``root`` that names an ignore policy beside it."""
    (root / "policy.rego").write_text(_IGNORE_POLICY, encoding="utf-8")
    (root / "trivy.yaml").write_text("ignore-policy: policy.rego\n", encoding="utf-8")


def _trivy_on_its_own(source: Path, out: Path, subcommand: str) -> set:
    """``trivy <subcommand>`` in ``source`` with trivy's own config discovery."""
    proc = subprocess.run(
        [
            "trivy",
            subcommand,
            "--scanners",
            "vuln",
            "--skip-db-update",
            "--format",
            "json",
            "--output",
            str(out),
            ".",
        ],
        cwd=source,
        capture_output=True,
        text=True,
        timeout=600,
    )
    assert proc.returncode == 0, proc.stderr[-2000:]
    data = json.loads(out.read_text(encoding="utf-8"))
    return {
        (v["VulnerabilityID"], r["Target"])
        for r in data.get("Results") or []
        for v in r.get("Vulnerabilities") or []
    }


def test_an_ignore_policy_named_by_the_trees_trivy_yaml_does_not_apply(
    tmp_path, trivy_env
):
    source = _copy_fixture(tmp_path)
    _, baseline = _scan_direct(source, tmp_path / "out0", scanners=["vuln"])
    assert _DROPPED_BY_THE_POLICY in _pairs(baseline)
    _plant_ignore_policy(source)
    # The positive control: trivy left to read that trivy.yaml drops the CVE.
    assert _DROPPED_BY_THE_POLICY not in _trivy_on_its_own(
        source, tmp_path / "plain.json", "fs"
    )

    _, report = _scan_direct(source, tmp_path / "out1", scanners=["vuln"])

    assert _pairs(report) == _pairs(baseline)
    # The operator's config, outside the tree, naming a policy outside it: applies.
    operator = tmp_path / "operator"
    operator.mkdir()
    (operator / "policy.rego").write_text(_IGNORE_POLICY, encoding="utf-8")
    (operator / "trivy.yaml").write_text(
        f"ignore-policy: {(operator / 'policy.rego').as_posix()}\n", encoding="utf-8"
    )
    _, opted = _scan_direct(
        source,
        tmp_path / "out2",
        operator=True,
        scanners=["vuln"],
        config_file=str(operator / "trivy.yaml"),
    )
    assert _pairs(opted) == _pairs(baseline) - {_DROPPED_BY_THE_POLICY}


def _repo_pairs(output: Path) -> set:
    data = _aggregated(output)
    return {
        (
            r.get("ruleId"),
            r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"],
        )
        for run in data["sarif"]["runs"]
        for r in run.get("results") or []
        if (r.get("properties") or {}).get("scanner_name") == "trivy-repo"
    }


def test_trivy_repo_does_not_load_the_scanned_repos_trivy_yaml(tmp_path, trivy_env):
    """The pinned binary, through ``ash scan``: a cwd trivy.yaml changes nothing."""
    source = _copy_fixture(tmp_path)
    config = {
        "project_name": "trivy-repo-e2e",
        "ash_plugin_modules": [
            "automated_security_helper.plugin_modules.ash_trivy_plugins"
        ],
        "scanners": {"trivy-repo": {"options": {"scanners": ["vuln"]}}},
    }
    proc, log = _run_ash(
        source, tmp_path / "out0", config, trivy_env, "--scanners", "trivy-repo"
    )
    baseline = _repo_pairs(tmp_path / "out0")
    assert baseline, log
    (source / "trivy.yaml").write_text("severity:\n  - CRITICAL\n", encoding="utf-8")

    proc, log = _run_ash(
        source, tmp_path / "out1", config, trivy_env, "--scanners", "trivy-repo"
    )

    assert _repo_pairs(tmp_path / "out1") == baseline, log
    # The control: the same file, named by the operator from outside the tree, does
    # filter, so the comparison above can see a trivy.yaml take effect.
    operator_config = tmp_path / "operator-trivy.yaml"
    operator_config.write_text("severity:\n  - CRITICAL\n", encoding="utf-8")
    proc, log = _run_ash(
        source,
        tmp_path / "out2",
        config,
        trivy_env,
        "--scanners",
        "trivy-repo",
        "--config-overrides",
        f"scanners.trivy-repo.options.config_file={operator_config.as_posix()}",
    )
    assert _repo_pairs(tmp_path / "out2") < baseline, log


def _trivy_repo_config(scanners: list) -> dict:
    return {
        "project_name": "trivy-repo-e2e",
        "ash_plugin_modules": [
            "automated_security_helper.plugin_modules.ash_trivy_plugins"
        ],
        "scanners": {"trivy-repo": {"options": {"scanners": scanners}}},
    }


def test_trivy_repo_does_not_apply_an_ignore_policy_from_the_trees_trivy_yaml(
    tmp_path, trivy_env
):
    source = _copy_fixture(tmp_path)
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    config = _trivy_repo_config(["vuln"])
    proc, log = _run_ash(
        source, tmp_path / "out0", config, trivy_env, "--scanners", "trivy-repo"
    )
    baseline = _repo_pairs(tmp_path / "out0")
    assert _DROPPED_BY_THE_POLICY in baseline, log
    _plant_ignore_policy(source)
    # The positive control: trivy repository left to read it drops the CVE.
    assert _DROPPED_BY_THE_POLICY not in _trivy_on_its_own(
        source, tmp_path / "plain.json", "repository"
    )

    proc, log = _run_ash(
        source, tmp_path / "out1", config, trivy_env, "--scanners", "trivy-repo"
    )

    assert _repo_pairs(tmp_path / "out1") == baseline, log


def test_trivy_repo_does_not_read_the_trees_trivy_secret_yaml(tmp_path, trivy_env):
    """trivy reads trivy-secret.yaml from its working directory unless told not to."""
    import secrets
    import string

    source = tmp_path / "src"
    source.mkdir()
    key_id = "AKIA" + "".join(
        secrets.choice(string.ascii_uppercase + "234567") for _ in range(16)
    )
    secret = "".join(
        secrets.choice(string.ascii_letters + string.digits) for _ in range(40)
    )
    (source / "creds.env").write_text(
        f"AWS_ACCESS_KEY_ID={key_id}\nAWS_SECRET_ACCESS_KEY={secret}\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q"], cwd=source, check=True)
    config = _trivy_repo_config(["secret"])
    proc, log = _run_ash(
        source, tmp_path / "out0", config, trivy_env, "--scanners", "trivy-repo"
    )
    baseline = _repo_pairs(tmp_path / "out0")
    assert baseline, log
    rules = "disable-rules:\n  - aws-access-key-id\n  - aws-secret-access-key\n"
    (source / "trivy-secret.yaml").write_text(rules, encoding="utf-8")

    proc, log = _run_ash(
        source, tmp_path / "out1", config, trivy_env, "--scanners", "trivy-repo"
    )

    assert _repo_pairs(tmp_path / "out1") == baseline, log
    # The control: the same rules, named by the operator from outside the tree.
    operator_rules = tmp_path / "operator-trivy-secret.yaml"
    operator_rules.write_text(rules, encoding="utf-8")
    proc, log = _run_ash(
        source,
        tmp_path / "out2",
        config,
        trivy_env,
        "--scanners",
        "trivy-repo",
        "--config-overrides",
        f"scanners.trivy-repo.options.secret_config_file={operator_rules.as_posix()}",
    )
    assert _repo_pairs(tmp_path / "out2") < baseline, log


def test_trivy_and_trivy_repo_share_an_empty_cache_without_racing(
    tmp_path, trivy_bin_dir
):
    """Both scanners, concurrently, against an empty shared cache, three times.

    Each used to download the vulnerability database itself, and one could read
    metadata.json or the mapped trivy.db while the other rewrote it ("unable to get
    metadata: json decode error: unexpected EOF" in CI, a SIGBUS in bbolt locally).
    The race does not fire every time, so one clean round proves little; three
    empty-cache rounds with both scanners ERROR-free is the regression guard.
    """
    source = _copy_fixture(tmp_path)
    config = {
        "project_name": "trivy-race",
        "ash_plugin_modules": [
            "automated_security_helper.plugin_modules.ash_trivy_plugins"
        ],
        "scanners": {
            "trivy": {"enabled": True},
            "trivy-repo": {"options": {"scanners": ["vuln"]}},
        },
    }
    for round_ in range(3):
        cache = tmp_path / f"cache-{round_}"
        cache.mkdir()
        env = {
            **os.environ,
            "PATH": f"{trivy_bin_dir}{os.pathsep}{os.environ['PATH']}",
            "TRIVY_CACHE_DIR": str(cache),
        }
        env.pop("ASH_OFFLINE", None)
        output = tmp_path / f"out-{round_}"
        proc, log = _run_ash(
            source, output, config, env, "--scanners", "trivy,trivy-repo"
        )
        statuses = {
            name: info.get("status")
            for name, info in _aggregated(output)["scanner_results"].items()
        }
        assert statuses.get("trivy") not in (None, "ERROR", "MISSING"), (round_, log)
        assert statuses.get("trivy-repo") not in (None, "ERROR", "MISSING"), (
            round_,
            log,
        )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_both_scanners_scan_from_a_read_only_prepared_cache(tmp_path, trivy_bin_dir):
    """What a sandbox that mounts trivy's cache read-only leaves them.

    ASH updates the database (and the checks bundle) outside the sandbox; the
    scanners then only read the cache. Here the cache is prepared once, made
    read-only, and both scanners scan with it; trivy's own update step finds the
    database current and writes nothing.
    """
    source = _copy_fixture(tmp_path)
    cache = tmp_path / "cache"
    env = {
        **os.environ,
        "PATH": f"{trivy_bin_dir}{os.pathsep}{os.environ['PATH']}",
        "TRIVY_CACHE_DIR": str(cache),
    }
    env.pop("ASH_OFFLINE", None)
    config = {
        "project_name": "trivy-read-only-cache",
        "ash_plugin_modules": [
            "automated_security_helper.plugin_modules.ash_trivy_plugins"
        ],
        "scanners": {"trivy": {"enabled": True}},
    }
    proc, log = _run_ash(
        source, tmp_path / "out0", config, env, "--scanners", "trivy,trivy-repo"
    )
    assert (cache / "db").is_dir(), log
    for path in [cache, *cache.rglob("*")]:
        path.chmod(path.stat().st_mode & ~0o222)
    try:
        proc, log = _run_ash(
            source, tmp_path / "out1", config, env, "--scanners", "trivy,trivy-repo"
        )
        statuses = {
            name: info.get("status")
            for name, info in _aggregated(tmp_path / "out1")["scanner_results"].items()
        }
    finally:
        for path in [cache, *cache.rglob("*")]:
            path.chmod(path.stat().st_mode | 0o200)
    assert statuses.get("trivy") == "FAILED", (statuses, log)
    assert statuses.get("trivy-repo") == "FAILED", (statuses, log)
