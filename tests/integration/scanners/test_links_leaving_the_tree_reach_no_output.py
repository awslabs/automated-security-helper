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
every plugin module, so every registered scanner is in its results. Every file the
scan wrote is checked, and no finding may sit at a link's path.

That proves something only for the scanners that ran, so each one that can run here
must also have scanned the tree: be PASSED, or FAILED on its findings, and report
the in-tree finding ``CONTROLS`` names (``real.py`` for bandit and the semgrep
rule, ``real.tf`` for checkov, and so on). ``in_tree_link.py`` is a link to
``real.py``, which is still scanned. A scanner that cannot run here (its tool or
database is absent, or it needs the network) does not count as taking part: its
test is skipped with its status and what it lacks, so the run's report lists it.

Tools the test can use when the environment provides them, none required: the
grype and trivy databases (``GRYPE_DB_CACHE_DIR`` naming grype's ``db`` directory,
``TRIVY_CACHE_DIR``), the cfn-guard rules directory (``ASH_CFN_GUARD_RULES_DIR``), and
the scanner binaries on ``PATH``. semgrep and opengrep get an offline rule cache the test writes.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess  # nosec B404 -- runs this interpreter's ASH on a fixture tree
import sys
import textwrap
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tests.utils.gitleaks_fixture import fabricated_tokens
from tests.utils.helpers import importing_this_checkout

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

#: An in-tree workflow that actionlint (an unknown runner label) and zizmor (the issue
#: title expanded into a ``run:`` script) each report.
WORKFLOW = """name: real
on:
  issues:
    types: [opened]
jobs:
  greet:
    runs-on: not-a-runner-label
    steps:
      - run: echo "${{ github.event.issue.title }}"
"""

#: The template cfn-lint and cfn-guard report known positives on (their own
#: integration tests' fixture), copied into the tree.
CFN_FIXTURE_TEMPLATE = (
    Path(__file__).resolve().parents[2]
    / "test_data"
    / "scanners"
    / "cfn_lint_guard"
    / "repo"
    / "templates"
    / "insecure.yaml"
)

SHELL_TRUE_RULE = """rules:
  - id: links-e2e-shell-true
    languages: [python]
    severity: WARNING
    message: subprocess with shell=True
    pattern: subprocess.call(..., shell=True)
"""

#: The child imports ASH from this checkout, not from wherever the interpreter's
#: installed copy points (see importing_this_checkout).
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
    workflows = tree / ".github" / "workflows"
    workflows.mkdir(parents=True)
    (workflows / "real.yml").write_text(WORKFLOW, encoding="utf-8")
    shutil.copy(CFN_FIXTURE_TEMPLATE, tree / "templates" / "insecure.yaml")
    # A fabricated token gitleaks reports (see tests/utils/gitleaks_fixture.py).
    (tree / "deploy.cfg").write_text(
        f"url = https://x:{fabricated_tokens()['settings_github_pat']}"
        "@github.com/o/r.git\n",
        encoding="utf-8",
    )
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


@dataclass(frozen=True)
class Control:
    """When a scanner can run in this scan, and what it must find in the tree.

    ``commands`` must all be found, on PATH or beside this interpreter, ``module``
    importable and ``database`` set in the environment. ``offline`` says why the
    scanner never runs in this offline scan. ``in_tree`` is a path a finding of
    the scanner's must sit at; None with no ``sbom_package`` means any finding at
    a path in the tree.
    """

    commands: tuple[str, ...] = ()
    module: str | None = None
    database: str | None = None
    offline: str | None = None
    in_tree: str | None = None
    sbom_package: str | None = None


#: One for every registered scanner. The in-tree findings were measured with
#: bandit 1.9.4, checkov 3.3.26, detect-secrets, semgrep 1.180.0, opengrep 1.30.2,
#: cfn-nag, cdk-nag, grype 0.120.1, trivy 0.75.0 and syft 1.54.1; ferret-scan's,
#: actionlint's, cfn-lint's, cfn-guard's, gitleaks's, trivy's and zizmor's have not
#: been measured in this scan. The last six read the findings their own integration
#: tests record on the same fixtures (tests/integration/scanners/
#: test_actionlint_real_binary.py, test_cfn_lint_and_cfn_guard_real.py,
#: test_gitleaks_real_binary.py and test_zizmor_real_binary.py).
CONTROLS = {
    "bandit": Control(commands=("bandit",), in_tree="real.py"),
    "checkov": Control(commands=("checkov",), in_tree="real.tf"),
    "detect-secrets": Control(commands=("detect-secrets",), in_tree="settings.yml"),
    "semgrep": Control(commands=("semgrep",), in_tree="real.py"),
    "opengrep": Control(commands=("opengrep",), in_tree="real.py"),
    "cfn-nag": Control(
        commands=("cfn_nag_scan",), in_tree="templates/real.template.json"
    ),
    "cdk-nag": Control(module="cdk_nag", in_tree="templates/real.template.json"),
    "grype": Control(
        commands=("grype",), database="GRYPE_DB_CACHE_DIR", in_tree="requirements.txt"
    ),
    "trivy-repo": Control(
        commands=("trivy",), database="TRIVY_CACHE_DIR", in_tree="requirements.txt"
    ),
    "syft": Control(commands=("syft",), sbom_package="django"),
    "ferret-scan": Control(commands=("ferret-scan",)),
    "actionlint": Control(
        commands=("actionlint",), in_tree=".github/workflows/real.yml"
    ),
    "zizmor": Control(commands=("zizmor",), in_tree=".github/workflows/real.yml"),
    "cfn-lint": Control(commands=("cfn-lint",), in_tree="templates/insecure.yaml"),
    # cfn-guard reads its rules from ASH_CFN_GUARD_RULES_DIR, or from beside
    # ASH_BIN_PATH, which this scan points at an empty directory of its own.
    "cfn-guard": Control(
        commands=("cfn-guard",),
        database="ASH_CFN_GUARD_RULES_DIR",
        in_tree="templates/insecure.yaml",
    ),
    "gitleaks": Control(commands=("gitleaks",), in_tree="deploy.cfg"),
    "trivy": Control(
        commands=("trivy",), database="TRIVY_CACHE_DIR", in_tree="requirements.txt"
    ),
    "npm-audit": Control(
        offline="npm audit asks the package registry, which an offline scan does "
        "not reach"
    ),
    "snyk-code": Control(
        offline="Snyk Code analyzes on Snyk's service, which an offline scan does "
        "not reach"
    ),
}

TOOK_PART = ("PASSED", "FAILED")
PLUGIN_ROOT = Path(__file__).resolve().parents[3] / (
    "automated_security_helper/plugin_modules"
)


def _registered_scanner_names() -> set[str]:
    names = set()
    for path in PLUGIN_ROOT.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "@ash_scanner_plugin" in text:
            names.update(re.findall(r'name: Literal\["([^"]+)"\] = "', text))
    return names


def _why_it_cannot_run(control: Control) -> str | None:
    """None when the scanner can run here; otherwise what it lacks."""
    if control.offline:
        return control.offline
    path = os.pathsep.join(
        [os.environ.get("PATH", ""), str(Path(sys.executable).parent)]
    )
    # PATH only, because that is all the scan can see: it runs with a home of its own,
    # so a uv tool a test installed under this session's private home (which `uv tool
    # list` shows here) is not one the scan finds, and the scanner records MISSING.
    # CI installs the uv tools the suite needs before it starts, onto PATH.
    missing = [
        command for command in control.commands if not shutil.which(command, path=path)
    ]
    if missing:
        return f"{', '.join(missing)} is not installed here"
    if control.module and importlib.util.find_spec(control.module) is None:
        return f"the {control.module} module is not installed here"
    if control.database and not os.environ.get(control.database):
        return f"{control.database} names no database here"
    return None


def _sbom_packages(output: Path, scanner: str) -> set[str]:
    names = set()
    for sbom in (output / "scanners" / scanner).rglob("*.cdx.json"):
        document = json.loads(sbom.read_text(encoding="utf-8"))
        names.update(c.get("name") for c in document.get("components") or [])
    return names


def test_every_registered_scanner_has_a_control():
    assert _registered_scanner_names() == set(CONTROLS)


@pytest.mark.parametrize("scanner", sorted(CONTROLS))
def test_each_scanner_that_can_run_here_scanned_the_tree(scan, scanner):
    """Ran (PASSED, or FAILED on its findings), and found what is in the tree.

    A scanner that cannot run here is skipped with what it lacks and the status the
    scan gave it, so the run's report lists every scanner that did not take part.
    """
    output, results, _ = scan
    status = _statuses(results).get(scanner)
    control = CONTROLS[scanner]
    reason = _why_it_cannot_run(control)
    if reason is not None:
        assert status not in TOOK_PART, (scanner, status, reason)
        pytest.skip(f"{scanner} did not take part ({status}): {reason}")

    assert status in TOOK_PART, (scanner, status)
    if control.sbom_package is not None:
        assert control.sbom_package in _sbom_packages(output, scanner)
        return
    uris = _uris(output).get(scanner, set())
    if control.in_tree is not None:
        assert any(uri.endswith(control.in_tree) for uri in uris), uris
    else:
        assert uris, f"{scanner} reported nothing in the tree"


def test_the_scanners_that_took_part_are_the_ones_that_can_run_here(scan):
    """Every registered scanner is in the results, and only those that can run took part.

    The ones that did not take part are each listed by the skipped test above.
    """
    _, results, _ = scan
    statuses = _statuses(results)
    can_run = {name for name, c in CONTROLS.items() if _why_it_cannot_run(c) is None}
    took_part = {name for name, status in statuses.items() if status in TOOK_PART}
    not_taking_part = {
        name: f"{statuses.get(name)}: {_why_it_cannot_run(CONTROLS[name])}"
        for name in sorted(set(CONTROLS) - took_part)
    }

    assert set(statuses) == set(CONTROLS)
    assert took_part == can_run, not_taking_part


def test_npm_audit_finds_the_package_whose_manifest_links_out(scan):
    """pkg/package.json leaves the tree; npm-audit still finds pkg by its lockfile.

    Offline it audits nothing and is MISSING, and the lockfile it would have
    audited is listed as not scanned, with the reason.
    """
    _, results, _ = scan
    reports = (results.get("additional_reports") or {}).get("npm-audit") or {}
    rows = [
        row
        for report in reports.values()
        if isinstance(report, dict)
        for row in report.get("inputs_not_scanned") or []
    ]

    assert _statuses(results).get("npm-audit") == "MISSING"
    assert [row["path"] for row in rows] == ["pkg/package-lock.json"]
    assert "offline" in rows[0]["reason"]


def test_an_in_tree_link_is_still_scanned_by_bandit(scan):
    if shutil.which("bandit") is None:
        pytest.skip("bandit is not installed here")
    output, _, _ = scan
    assert any("in_tree_link.py" in uri for uri in _uris(output).get("bandit", set()))
