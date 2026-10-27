# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A whole offline ``ash scan``: a path the operator ignores is read by no scanner.

ASH drops the findings in ``global_settings.ignore_paths`` from its reports after
the scan (``apply_suppressions_to_sarif``). Measured before the change, every
scanner that walks the tree itself still read the ignored files, and its own
results under ``scanners/<tool>/`` in the output directory held them: bandit,
checkov, grype, syft, trivy-repo, semgrep and opengrep. Only detect-secrets and
ferret-scan received the ignore paths.

The tree has a finding for each scanner under ``thirdparty/``, which the config
ignores (``thirdparty/**``), each carrying a marker, and the same kinds of finding
outside it as controls. For each scanner in ``CHECKED`` that ran, no file under its
``scanners/<tool>/`` directory may hold a marker, report a result located under
``thirdparty/``, or list a path there as not scanned.

Tools the test uses when the environment provides them, none required: the
scanner binaries on ``PATH`` and the grype and trivy databases
(``GRYPE_DB_CACHE_DIR``, ``TRIVY_CACHE_DIR``). semgrep and opengrep get an offline
rule cache the test writes. A scanner whose tool is missing here is skipped.
"""

from __future__ import annotations

import json
import os
import subprocess  # nosec B404 -- runs this interpreter's ASH on a fixture tree
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.utils.helpers import importing_this_checkout

pytestmark = [pytest.mark.integration]

IGNORED = "thirdparty"
MARKER = "IGNORED-5e2a"
# Built at run time, so this file holds no key-shaped literal.
IGNORED_KEY = "AKIA" + "IGNORED5E2A00001"
IN_TREE_KEY = "AKIA" + "INTREE5E2A000001"
#: A package only the ignored requirements file names.
IGNORED_PACKAGE = "pyyaml"
MARKERS = [MARKER, MARKER.lower(), IGNORED_KEY, IGNORED_PACKAGE]

#: The scanners whose own results are checked; each is one test. snyk-code is not
#: here: it needs Snyk's service, so it never runs in this offline scan.
CHECKED = [
    "bandit",
    "cdk-nag",
    "cfn-nag",
    "checkov",
    "detect-secrets",
    "ferret-scan",
    "grype",
    "npm-audit",
    "opengrep",
    "semgrep",
    "syft",
    "trivy-repo",
]

SHELL_TRUE_RULE = """rules:
  - id: ignore-e2e-shell-true
    languages: [python]
    severity: WARNING
    message: subprocess with shell=True
    pattern: subprocess.call(..., shell=True)
"""

INSECURE_BUCKET = """
resource "aws_s3_bucket" "b" {{
  bucket = "{name}"
  acl    = "public-read"
}}
"""

#: The child imports ASH from this checkout (see importing_this_checkout).
DRIVER = importing_this_checkout(
    textwrap.dedent(
        """
        import sys
        from automated_security_helper.cli.main import app

        sys.argv = ["ash", "scan", *sys.argv[1:]]
        app()
        """
    )
)


def _template(bucket: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"BucketName": bucket, "AccessControl": "PublicRead"},
                }
            },
        },
        indent=2,
    )


def _package(directory: Path, name: str) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "package.json").write_text(
        json.dumps({"name": name, "version": "1.0.0"}), encoding="utf-8"
    )
    (directory / "package-lock.json").write_text(
        json.dumps(
            {
                "name": name,
                "version": "1.0.0",
                "lockfileVersion": 3,
                "requires": True,
                "packages": {"": {"name": name, "version": "1.0.0"}},
            }
        ),
        encoding="utf-8",
    )


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def _build(base: Path) -> Path:
    tree = base / "tree"
    ignored = tree / IGNORED
    _write(
        ignored / "bad.py",
        f"import subprocess\nsubprocess.call('{MARKER}', shell=True)\n",
    )
    _write(ignored / "main.tf", INSECURE_BUCKET.format(name=MARKER.lower()))
    _write(ignored / "stack.template.json", _template(MARKER.lower()))
    _write(ignored / "requirements.txt", f"{IGNORED_PACKAGE}==3.10\n")
    _write(ignored / "creds.yml", f"aws_access_key_id: {IGNORED_KEY}\n")
    _package(ignored / "pkg", MARKER.lower())

    _write(
        tree / "real.py", "import subprocess\nsubprocess.call('in-tree', shell=True)\n"
    )
    _write(tree / "real.tf", INSECURE_BUCKET.format(name="in-tree-bucket"))
    _write(tree / "templates" / "real.template.json", _template("in-tree-bucket"))
    _write(tree / "requirements.txt", "django==1.2\n")
    _write(tree / "settings.yml", f"aws_access_key_id: {IN_TREE_KEY}\n")
    _package(tree / "pkg", "in-tree-pkg")
    return tree


def _config(base: Path) -> Path:
    config = base / "ash-config" / ".ash.yaml"
    _write(
        config,
        "project_name: ignore-paths\n"
        "ash_plugin_modules:\n"
        "  - automated_security_helper.plugin_modules.ash_trivy_plugins\n"
        "  - automated_security_helper.plugin_modules.ash_ferret_plugins\n"
        "  - automated_security_helper.plugin_modules.ash_snyk_plugins\n"
        "global_settings:\n"
        "  ignore_paths:\n"
        f"    - path: '{IGNORED}/**'\n"
        "      reason: 'vendored code'\n",
    )
    return config


def _env(base: Path) -> dict[str, str]:
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("AWS_") and key not in ("ASH_CONFIG", "ASH_BIN_PATH")
    }
    home = base / "home"
    for directory in (".cache", ".config", ".local/share"):
        (home / directory).mkdir(parents=True)
    rules = base / "rules"
    _write(rules / "shell-true.yaml", SHELL_TRUE_RULE)
    _write(
        rules / ".ash-rules-fetched-at",
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") + "\n",
    )
    env.update(
        {
            "ASH_OFFLINE": "YES",
            "NO_COLOR": "1",
            "COLUMNS": "200",
            "AWS_CONFIG_FILE": os.devnull,
            "AWS_SHARED_CREDENTIALS_FILE": os.devnull,
            "AWS_EC2_METADATA_DISABLED": "true",
            "AWS_ENDPOINT_URL": "http://127.0.0.1:9",
            "AWS_REGION": "us-east-1",
            "HOME": str(home),
            "XDG_CACHE_HOME": str(home / ".cache"),
            "XDG_DATA_HOME": str(home / ".local" / "share"),
            "XDG_CONFIG_HOME": str(home / ".config"),
            "ASH_BIN_PATH": str(home / "ash-bin"),
            "UV_OFFLINE": "1",
            "SEMGREP_RULES_CACHE_DIR": str(rules),
            "OPENGREP_RULES_CACHE_DIR": str(rules),
        }
    )
    env.pop("SNYK_TOKEN", None)
    return env


@pytest.fixture(scope="module")
def scan(tmp_path_factory):
    base = tmp_path_factory.mktemp("ignore-paths")
    tree = _build(base)
    output = base / "out"
    completed = subprocess.run(  # nosec B603 -- fixed argv, the test's own interpreter
        [
            sys.executable,
            "-I",
            "-c",
            DRIVER,
            "--source-dir",
            str(tree),
            "--output-dir",
            str(output),
            "--config",
            str(_config(base)),
            "--mode",
            "local",
            "--no-progress",
            "--no-fail-on-findings",
            "--no-fail-on-incomplete-scanners",
            "--allow-stale-content-db",
        ],
        capture_output=True,
        text=True,
        timeout=3600,
        env=_env(base),
        cwd=base,
    )
    assert completed.returncode == 0, (
        completed.stdout[-4000:] + completed.stderr[-4000:]
    )
    results = json.loads((output / "ash_aggregated_results.json").read_text())
    return output, results


def _status(results, scanner: str) -> str | None:
    info = (results.get("scanner_results") or {}).get(scanner) or {}
    targets = [v for v in info.values() if isinstance(v, dict)]
    status = info.get("status") or next(
        (t.get("status") for t in targets if t.get("status")), None
    )
    return None if status is None else str(status)


def _sarif_locations(data) -> list[str]:
    uris = []
    for run in (data.get("runs") or []) if isinstance(data, dict) else []:
        for result in run.get("results") or []:
            for location in result.get("locations") or []:
                physical = location.get("physicalLocation") or {}
                uri = (physical.get("artifactLocation") or {}).get("uri") or ""
                uris.append(uri)
    return uris


def _not_scanned_paths(data) -> list[str]:
    """Every inputs_not_scanned path anywhere in a JSON document."""
    found = []
    stack = [data]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            for key, value in item.items():
                if key == "inputs_not_scanned" and isinstance(value, list):
                    found += [
                        str(row.get("path", ""))
                        for row in value
                        if isinstance(row, dict)
                    ]
                else:
                    stack.append(value)
        elif isinstance(item, list):
            stack.extend(item)
    return found


def _under_ignored(path: str) -> bool:
    return path == IGNORED or f"{IGNORED}/" in path


def _holding(directory: Path) -> dict[str, list[str]]:
    """What each file under ``directory`` holds from the ignored directory."""
    holding: dict[str, list[str]] = {}
    for path in sorted(directory.rglob("*")):
        if not path.is_file() or path.is_symlink():
            continue
        data = path.read_bytes()
        hits = [m for m in MARKERS if m.encode() in data]
        try:
            document = json.loads(data)
        except ValueError:
            document = None
        if document is not None:
            hits += [
                f"result at {uri}"
                for uri in _sarif_locations(document)
                if _under_ignored(uri)
            ]
            hits += [
                f"not scanned: {p}"
                for p in _not_scanned_paths(document)
                if _under_ignored(p)
            ]
        if hits:
            holding[str(path.relative_to(directory))] = hits
    return holding


def _recorded_inputs(directory: Path) -> bool:
    """Whether any file under ``directory`` lists an input as not scanned."""
    for path in directory.rglob("*.json"):
        try:
            if _not_scanned_paths(json.loads(path.read_bytes())):
                return True
        except ValueError:
            continue
    return False


@pytest.mark.parametrize("scanner", CHECKED)
def test_no_scanner_output_holds_an_ignored_path(scan, scanner):
    output, results = scan
    status = _status(results, scanner)
    directory = output / "scanners" / scanner
    # npm-audit offline audits nothing but still lists each lockfile it found.
    if status not in ("PASSED", "FAILED") and not _recorded_inputs(directory):
        pytest.skip(f"{scanner} did not run here ({status})")
    assert _holding(directory) == {}, status


def test_no_report_holds_an_ignored_path(scan):
    """The reports, the SBOMs among them, hold nothing from the ignored directory."""
    output, results = scan
    reports = {
        name: hits
        for name, hits in _holding(output).items()
        if not name.startswith("scanners/")
    }
    assert reports == {}
