# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A whole offline ``ash scan`` with every scanner: nothing behind a link that leaves
the tree is read.

The tree commits links to a ``.py``, a ``.tf``, a ``Dockerfile``, a ``config.yml``
standing in for a credentials file and a ``package.json``, all outside it, each
holding a marker string; the ``.py`` and the ``.yml`` also hold secret-shaped
strings. Measured before the change, bandit's snippet of the outside ``.py`` reached
ash.sarif, ash_aggregated_results.json, the CSV, flat JSON and GitLab SAST reports
and ash.summary.md, and checkov's results held the outside ``.tf``. The scan enables
every plugin module, so every registered scanner takes part; the ones whose tool is
not installed where the test runs are MISSING. Every file the scan wrote is checked,
and no finding may sit at a link's path.

In-tree controls show the scanners ran: ``real.py`` and ``real.tf`` hold what bandit,
checkov and the semgrep rule report, and ``in_tree_link.py`` is a link to
``real.py``, which is still scanned.

Tools the test can use when the environment provides them, none required: the
grype and trivy databases (``GRYPE_DB_CACHE_DIR``, ``TRIVY_CACHE_DIR``), and the
scanner binaries on ``PATH``. semgrep and opengrep get an offline rule cache the
test writes.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 -- runs this interpreter's ASH on a fixture tree
import sys
import textwrap
from datetime import datetime, timezone
from pathlib import Path

import pytest

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        sys.platform == "win32", reason="creating symlinks needs privileges on Windows"
    ),
]

MARKER = "OUTSIDE-CONTENT-7c41"
# Built at run time, so the test file holds no secret-shaped literal. AWS-key-shaped
# and GitHub-token-shaped, so a secret scanner reports each wherever it reads it.
OUTSIDE_KEY = "AKIA" + "OUTSIDE7C4100001"
OUTSIDE_TOKEN = "ghp_" + "7c41" + "Q" * 32
NEEDLES = [MARKER, MARKER.lower(), OUTSIDE_KEY, OUTSIDE_TOKEN]
#: In the tree, for the secret scanners' control.
IN_TREE_KEY = "AKIA" + "INTREE7C41000001"

#: The links that leave the tree, by their path in it.
LINKS_OUT = {
    "link_out.py": "secret.py",
    "infra/main.tf": "main.tf",
    "docker/Dockerfile": "Dockerfile",
    "config.yml": "hosts.yml",
    "pkg/package.json": "package.json",
    "cfn/stack.template.json": "stack.template.json",
}


def _template(bucket_name: str) -> str:
    """A CloudFormation template with a public-read bucket, which cfn-nag reports."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {
                        "BucketName": bucket_name,
                        "AccessControl": "PublicRead",
                    },
                }
            },
        },
        indent=2,
    )


INSECURE_BUCKET = """
resource "aws_s3_bucket" "b" {{
  bucket = "{name}"
  acl    = "public-read"
}}
"""

SHELL_TRUE_RULE = """rules:
  - id: links-e2e-shell-true
    languages: [python]
    severity: WARNING
    message: subprocess with shell=True
    pattern: subprocess.call(..., shell=True)
"""

DRIVER = textwrap.dedent(
    """
    import sys
    from automated_security_helper.cli.main import app

    sys.argv = ["ash", "scan", *sys.argv[1:]]
    app()
    """
)

PLUGIN_MODULES = [
    "automated_security_helper.plugin_modules.ash_trivy_plugins",
    "automated_security_helper.plugin_modules.ash_ferret_plugins",
    "automated_security_helper.plugin_modules.ash_snyk_plugins",
]


def _build(base: Path) -> Path:
    outside = base / "outside"
    tree = base / "tree"
    outside.mkdir()
    tree.mkdir()
    (outside / "secret.py").write_text(
        "import subprocess\n"
        f"MARKER = '{MARKER}'\n"
        f"KEY = '{OUTSIDE_KEY}'\n"
        "subprocess.call(MARKER, shell=True)\n",
        encoding="utf-8",
    )
    (outside / "main.tf").write_text(
        INSECURE_BUCKET.format(name=MARKER.lower()), encoding="utf-8"
    )
    (outside / "Dockerfile").write_text(
        f"FROM alpine:3.20\n# {MARKER}\nUSER root\n", encoding="utf-8"
    )
    (outside / "hosts.yml").write_text(
        "github.com:\n"
        f"    oauth_token: {OUTSIDE_TOKEN}\n"
        f"    user: {MARKER}\n"
        f"aws_access_key_id: {OUTSIDE_KEY}\n",
        encoding="utf-8",
    )
    (outside / "package.json").write_text(
        json.dumps(
            {
                "name": MARKER.lower(),
                "version": "1.0.0",
                "dependencies": {"minimist": "0.0.8"},
            }
        ),
        encoding="utf-8",
    )
    (outside / "stack.template.json").write_text(
        _template(MARKER.lower()), encoding="utf-8"
    )

    (tree / "app.py").write_text("print('hello')\n", encoding="utf-8")
    (tree / "templates").mkdir()
    (tree / "templates" / "real.template.json").write_text(
        _template("in-tree-bucket"), encoding="utf-8"
    )
    (tree / "real.py").write_text(
        "import subprocess\nsubprocess.call('in-tree', shell=True)\n",
        encoding="utf-8",
    )
    (tree / "real.tf").write_text(
        INSECURE_BUCKET.format(name="in-tree-bucket"), encoding="utf-8"
    )
    (tree / "requirements.txt").write_text("django==1.2\n", encoding="utf-8")
    (tree / "settings.yml").write_text(
        f"aws_access_key_id: {IN_TREE_KEY}\n", encoding="utf-8"
    )
    for link, name in LINKS_OUT.items():
        (tree / link).parent.mkdir(parents=True, exist_ok=True)
        (tree / link).symlink_to(outside / name)
    # The package whose package.json leaves the tree has a lockfile of its own.
    (tree / "pkg" / "package-lock.json").write_text(
        json.dumps(
            {
                "name": "pkg",
                "version": "1.0.0",
                "lockfileVersion": 3,
                "requires": True,
                "packages": {"": {"name": "pkg", "version": "1.0.0"}},
            }
        ),
        encoding="utf-8",
    )
    (tree / "in_tree_link.py").symlink_to("real.py")
    return tree


def _config(base: Path) -> Path:
    """An ASH config outside the tree that loads every plugin module."""
    config = base / "ash-config" / ".ash.yaml"
    config.parent.mkdir()
    lines = ["project_name: links-leaving-the-tree", "ash_plugin_modules:"]
    lines += [f"  - {module}" for module in PLUGIN_MODULES]
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return config


def _rule_cache(base: Path) -> Path:
    """An offline semgrep/opengrep rule cache holding one rule, fetched now."""
    rules = base / "rules"
    rules.mkdir()
    (rules / "shell-true.yaml").write_text(SHELL_TRUE_RULE, encoding="utf-8")
    (rules / ".ash-rules-fetched-at").write_text(
        datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") + "\n",
        encoding="utf-8",
    )
    return rules


def _isolated_env(base: Path) -> dict[str, str]:
    """No cloud credentials, a refusing endpoint, and a home of the test's own."""
    env = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith("AWS_") and key not in ("ASH_CONFIG", "ASH_BIN_PATH")
    }
    home = base / "home"
    # opengrep stops when XDG_CONFIG_HOME names a directory that does not exist.
    for directory in (".cache", ".config", ".local/share"):
        (home / directory).mkdir(parents=True)
    rules = _rule_cache(base)
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
    # snyk-code needs a token to start; none is given, so it cannot reach Snyk.
    env.pop("SNYK_TOKEN", None)
    return env


@pytest.fixture(scope="module")
def scan(tmp_path_factory):
    base = tmp_path_factory.mktemp("links-leaving-the-tree")
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
        env=_isolated_env(base),
        cwd=base,
    )
    assert completed.returncode == 0, (
        completed.stdout[-4000:] + completed.stderr[-4000:]
    )
    results = json.loads((output / "ash_aggregated_results.json").read_text())
    return output, results, completed.stdout


def _statuses(results) -> dict[str, str]:
    statuses = {}
    for name, info in (results.get("scanner_results") or {}).items():
        if isinstance(info, dict):
            targets = [v for v in info.values() if isinstance(v, dict)]
            status = info.get("status") or next(
                (t.get("status") for t in targets if t.get("status")), None
            )
            statuses[name] = str(status)
    return statuses


def _uris(output: Path) -> dict[str, set[str]]:
    sarif = json.loads((output / "reports" / "ash.sarif").read_text())
    found: dict[str, set[str]] = {}
    for run in sarif.get("runs", []):
        for result in run.get("results", []) or []:
            tool = (result.get("properties") or {}).get("scanner_name") or ""
            for location in result.get("locations", []) or []:
                uri = location["physicalLocation"]["artifactLocation"].get("uri", "")
                found.setdefault(tool, set()).add(uri)
    return found


def test_no_output_file_holds_anything_from_outside_the_tree(scan):
    output, results, console = scan
    holding = {
        str(path.relative_to(output)): [n for n in NEEDLES if n.encode() in data]
        for path in output.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and any(n.encode() in (data := path.read_bytes()) for n in NEEDLES)
    }
    assert holding == {}, (holding, _statuses(results))
    assert not any(n in console for n in NEEDLES)


def test_no_finding_sits_at_a_link_leaving_the_tree(scan):
    output, results, _ = scan
    at_links = {
        scanner: sorted(
            uri
            for uri in uris
            if any(uri == link or uri.endswith("/" + link) for link in LINKS_OUT)
        )
        for scanner, uris in _uris(output).items()
    }
    assert {k: v for k, v in at_links.items() if v} == {}, _statuses(results)


def test_each_link_leaving_the_tree_is_listed_as_not_scanned(scan):
    _, results, _ = scan
    rows = results["metadata"].get("inputs_not_scanned") or []
    assert {row["path"] for row in rows} >= set(LINKS_OUT)
    assert {row["reason"] for row in rows} == {"link leaves the scanned tree"}


@pytest.mark.parametrize(
    "scanner, command, in_tree_uri",
    [
        ("bandit", "bandit", "real.py"),
        ("checkov", "checkov", "real.tf"),
        ("detect-secrets", "detect-secrets", "settings.yml"),
    ],
)
def test_the_measured_readers_ran_and_still_scan_the_tree(
    scan, scanner, command, in_tree_uri
):
    """The control: each ran, and found what is in the tree."""
    if shutil.which(command) is None:
        pytest.skip(f"{command} is not installed here")
    output, results, _ = scan
    status = _statuses(results).get(scanner)
    # FAILED is a scanner that ran and reported findings over the threshold.
    assert status in ("PASSED", "FAILED"), status
    if in_tree_uri is not None:
        assert any(in_tree_uri in uri for uri in _uris(output).get(scanner, set())), (
            _uris(output)
        )


def test_every_registered_scanner_took_part(scan):
    _, results, _ = scan
    assert set(_statuses(results)) >= {
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
        "snyk-code",
        "syft",
        "trivy-repo",
    }


def test_an_in_tree_link_is_still_scanned_by_bandit(scan):
    if shutil.which("bandit") is None:
        pytest.skip("bandit is not installed here")
    output, _, _ = scan
    assert any("in_tree_link.py" in uri for uri in _uris(output).get("bandit", set()))
