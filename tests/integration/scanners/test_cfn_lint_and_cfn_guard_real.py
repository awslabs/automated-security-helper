# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""cfn-lint and cfn-guard, run for real by ``ash scan`` against the fixture repository.

Every scan here is a subprocess of the installed ``ash`` entry point, so config
resolution, opt-in selection, template discovery, the real tools, suppressions and the
reporters are all the code a user runs. The fixture is
``tests/test_data/scanners/cfn_lint_guard/repo``: one template with known positives for
both tools, one compliant template (which also carries a cfn-guard native suppression),
a YAML file that is not CloudFormation, and a file that is not valid YAML.

The skip is env-gated, as in ``test_cfn_nag_custom_rules.py``: a test that silently
skips when its tools are missing protects nothing. ``ASH_REQUIRE_CFN_TOOLS=1`` turns the
skip into a failure; the integration-test job installs both tools with
``ash dependencies install --tool cfn-lint --tool cfn-guard`` and sets it.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess  # nosec B404 - the CLI under test is a separate process
import sys
from pathlib import Path

import pytest
import yaml

from automated_security_helper.utils.rules_bundles import RulesBundleUnavailable
from automated_security_helper.utils.subprocess_utils import find_executable

pytestmark = [pytest.mark.integration]

FIXTURE_REPO = (
    Path(__file__).resolve().parents[2]
    / "test_data"
    / "scanners"
    / "cfn_lint_guard"
    / "repo"
)

#: (rule id, line) per tool on templates/insecure.yaml, as the unit tests' captured
#: output records them. The real tools must still produce exactly these.
CFN_LINT_EXPECTED = {("W2001", 4), ("E3002", 10), ("E2533", 14)}
CFN_GUARD_EXPECTED_RULES = {
    "LAMBDA_INSIDE_VPC",
    "S3_BUCKET_LEVEL_PUBLIC_ACCESS_PROHIBITED",
    "S3_BUCKET_LOGGING_ENABLED",
    "S3_BUCKET_PUBLIC_READ_PROHIBITED",
    "S3_BUCKET_PUBLIC_WRITE_PROHIBITED",
    "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED",
    "S3_BUCKET_VERSIONING_ENABLED",
    "S3_DEFAULT_ENCRYPTION_KMS",
}


def _required() -> bool:
    return os.environ.get("ASH_REQUIRE_CFN_TOOLS", "").strip().upper() in (
        "1",
        "YES",
        "TRUE",
    )


def _require_tools() -> None:
    from automated_security_helper.utils.rules_bundles import verify_installed_bundle
    from automated_security_helper.utils.tool_downloads import get_rules_bundle

    problems = []
    if find_executable("cfn-guard") is None:
        problems.append("cfn-guard is not on PATH or in ASH_BIN_PATH")
    try:
        verify_installed_bundle(get_rules_bundle("aws-guard-rules-registry"))
    except RulesBundleUnavailable as exc:
        problems.append(str(exc))
    if find_executable("cfn-lint") is None:
        problems.append("cfn-lint is not on PATH")
    if problems:
        message = "; ".join(problems)
        if _required():
            pytest.fail(
                f"ASH_REQUIRE_CFN_TOOLS is set but {message}. These tests must RUN "
                "where the tools are provisioned."
            )
        pytest.skip(message)


def _ash() -> str:
    ash = shutil.which("ash", path=str(Path(sys.executable).parent))
    assert ash, f"no ash entry point beside {sys.executable}"
    return ash


def _scan(
    tmp_path: Path,
    scanners: str,
    config: dict | None = None,
    env=None,
):
    source = tmp_path / "repo"
    if not source.exists():
        shutil.copytree(FIXTURE_REPO, source)
    output = (
        tmp_path / f"out-{scanners.replace(',', '-')}-{len(list(tmp_path.iterdir()))}"
    )
    config_path = tmp_path / "ash.yaml"
    config_path.write_text(
        yaml.safe_dump({"project_name": "cfn-tools-e2e", **(config or {})}),
        encoding="utf-8",
    )
    proc = subprocess.run(  # nosec B603 - fixed argv
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
            scanners,
            "--no-progress",
            "--no-fail-on-findings",
        ],
        capture_output=True,
        text=True,
        timeout=900,
        env={**os.environ, **(env or {})},
    )
    log = (
        f"exit {proc.returncode}\nSTDOUT:\n{proc.stdout[-4000:]}\n"
        f"STDERR:\n{proc.stderr[-4000:]}"
    )
    return proc, output, log


def _results(output: Path, scanner: str) -> list:
    sarif = json.loads((output / "reports" / "ash.sarif").read_text(encoding="utf-8"))
    out = []
    for run in sarif["runs"]:
        for result in run.get("results", []):
            tags = (result.get("properties") or {}).get("tags") or []
            if scanner in tags:
                out.append(result)
    return out


def _where(result) -> tuple:
    physical = result["locations"][0]["physicalLocation"]
    return physical["artifactLocation"]["uri"], physical["region"]["startLine"]


def _scanner_results(output: Path) -> dict:
    data = json.loads(
        (output / "ash_aggregated_results.json").read_text(encoding="utf-8")
    )
    return data["scanner_results"]


def test_both_scanners_report_the_known_positives_and_nothing_else(tmp_path):
    _require_tools()
    proc, output, log = _scan(tmp_path, "cfn-lint,cfn-guard")
    assert proc.returncode == 0, log

    lint = _results(output, "cfn-lint")
    assert {(r["ruleId"], _where(r)[1]) for r in lint} == CFN_LINT_EXPECTED, log
    assert {_where(r)[0] for r in lint} == {"templates/insecure.yaml"}
    # ash.sarif defines no uriBaseId, so no location may name one.
    assert not any(
        "uriBaseId" in location["physicalLocation"]["artifactLocation"]
        for r in lint
        for location in r["locations"]
    ), log

    guard = _results(output, "cfn-guard")
    assert {r["ruleId"] for r in guard} == CFN_GUARD_EXPECTED_RULES, log
    # compliant.yaml produces nothing, including the LogBucket whose missing access
    # logging is suppressed in the template with cfn-guard's own Metadata.
    assert {_where(r)[0] for r in guard} == {"templates/insecure.yaml"}

    statuses = _scanner_results(output)
    assert statuses["cfn-lint"]["status"] == "FAILED", statuses["cfn-lint"]
    assert statuses["cfn-guard"]["status"] == "FAILED", statuses["cfn-guard"]


def test_a_repository_cfnlintrc_cannot_switch_cfn_lint_off(tmp_path):
    """Unless the ASH config names it, the scanned tree's .cfnlintrc is not read."""
    _require_tools()
    shutil.copytree(FIXTURE_REPO, tmp_path / "repo")
    (tmp_path / "repo" / ".cfnlintrc").write_text("ignore_checks: [E, W]\n")
    proc, output, log = _scan(tmp_path, "cfn-lint")
    assert proc.returncode == 0, log
    lint = _results(output, "cfn-lint")
    assert {(r["ruleId"], _where(r)[1]) for r in lint} == CFN_LINT_EXPECTED, log


#: A resource type that us-east-1 has and af-south-1 lacks in cfn-lint 1.57.2's
#: schemas, so an E3006 on it says which region cfn-lint validated against.
_BEDROCK_AGENT = """AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Agent:
    Type: AWS::Bedrock::Agent
    Properties:
      AgentName: a
"""


@pytest.mark.parametrize("aws_region", ["", "af-south-1"])
def test_the_default_region_is_us_east_1_whatever_the_environment_says(
    tmp_path, aws_region
):
    """``regions`` unset validates against us-east-1, not ``AWS_REGION``.

    An empty ``AWS_REGION``, which CI gets from an unset variable, made cfn-lint exit
    32 on every template, and another region changed the findings. A template that
    names its own regions in ``Metadata: cfn-lint: config`` still gets them.
    """
    _require_cfn_lint()
    source = tmp_path / "repo"
    shutil.copytree(FIXTURE_REPO, source)
    (source / "templates" / "bedrock.yaml").write_text(_BEDROCK_AGENT)
    (source / "templates" / "names-its-region.yaml").write_text(
        _BEDROCK_AGENT.replace(
            "Resources:",
            "Metadata:\n  cfn-lint:\n    config:\n      regions: [af-south-1]\n"
            "Resources:",
        )
    )

    proc, output, log = _scan(
        tmp_path,
        "cfn-lint",
        env={"AWS_REGION": aws_region, "AWS_DEFAULT_REGION": aws_region},
    )

    assert proc.returncode == 0, log
    assert _scanner_results(output)["cfn-lint"]["status"] == "FAILED", log
    lint = _results(output, "cfn-lint")
    assert {
        (r["ruleId"], _where(r)[1])
        for r in lint
        if _where(r)[0] == "templates/insecure.yaml"
    } == CFN_LINT_EXPECTED, log
    assert {_where(r)[0] for r in lint if r["ruleId"] == "E3006"} == {
        "templates/names-its-region.yaml"
    }, log


def test_a_rule_in_two_selected_rule_sets_is_reported_once(tmp_path):
    """wa-Security-Pillar and cis-aws-benchmark-level-1 share rules. cfn-guard
    reports a shared rule's results once per set (42 on insecure.yaml, 29
    distinct); ASH reports each once."""
    _require_tools()
    proc, output, log = _scan(
        tmp_path,
        "cfn-guard",
        config={
            "scanners": {
                "cfn-guard": {
                    "options": {
                        "rule_sets": ["wa-Security-Pillar", "cis-aws-benchmark-level-1"]
                    }
                }
            }
        },
    )
    assert proc.returncode == 0, log
    findings = [
        (r["ruleId"], r["message"]["text"], _where(r))
        for r in _results(output, "cfn-guard")
    ]
    assert len(findings) == len(set(findings)) == 29, log


def test_ash_suppressions_apply_by_rule_path_and_line(tmp_path):
    _require_tools()
    suppressions = [
        {
            "rule_id": "E2533",
            "path": "templates/insecure.yaml",
            "line_start": 14,
            "line_end": 14,
            "reason": "line-scoped: the deprecated runtime is the fixture's point",
        },
        {
            "rule_id": "LAMBDA_INSIDE_VPC",
            "path": "templates/insecure.yaml",
            "reason": "rule-and-path scoped",
        },
    ]
    proc, output, log = _scan(
        tmp_path,
        "cfn-lint,cfn-guard",
        config={"global_settings": {"suppressions": suppressions}},
    )
    assert proc.returncode == 0, log
    suppressed = {
        (r["ruleId"], _where(r)[1])
        for scanner in ("cfn-lint", "cfn-guard")
        for r in _results(output, scanner)
        if r.get("suppressions")
    }
    assert ("E2533", 14) in suppressed, log
    assert ("LAMBDA_INSIDE_VPC", 13) in suppressed, log
    # The same file's other findings stay visible: the entries are narrow.
    assert ("E3002", 10) not in suppressed
    assert not any(rule.startswith("S3_") for rule, _ in suppressed)


def test_offline_mode_gives_the_same_findings(tmp_path):
    _require_tools()
    _, online, log_online = _scan(tmp_path, "cfn-lint,cfn-guard")
    proc, offline, log = _scan(
        tmp_path, "cfn-lint,cfn-guard", env={"ASH_OFFLINE": "true"}
    )
    assert proc.returncode == 0, log
    for scanner in ("cfn-lint", "cfn-guard"):
        assert sorted(
            (r["ruleId"], _where(r)) for r in _results(offline, scanner)
        ) == sorted((r["ruleId"], _where(r)) for r in _results(online, scanner)), log


def test_missing_rules_are_missing_and_the_scan_is_incomplete(tmp_path):
    _require_tools()
    empty = tmp_path / "no-rules"
    empty.mkdir()
    proc, output, log = _scan(
        tmp_path, "cfn-guard", env={"ASH_CFN_GUARD_RULES_DIR": str(empty)}
    )
    assert proc.returncode == 1, log
    assert _scanner_results(output)["cfn-guard"]["status"] == "MISSING", log
    assert "rules are not installed" in (output / "ash.log").read_text(
        encoding="utf-8", errors="replace"
    )


def test_disabled_in_config_they_do_not_run(tmp_path):
    """Builtin and on by default, so the off switch is the config: SKIPPED, no findings."""
    proc, output, log = _scan(
        tmp_path,
        "cfn-nag,cfn-lint,cfn-guard",
        config={
            "scanners": {
                "cfn-lint": {"enabled": False},
                "cfn-guard": {"enabled": False},
            }
        },
    )
    assert (output / "ash_aggregated_results.json").exists(), log
    results = _scanner_results(output)
    for name in ("cfn-lint", "cfn-guard"):
        assert results[name]["status"] == "SKIPPED", (name, results[name])
        assert not results[name].get("finding_count"), (name, results[name])


# --------------------------------------------------------------------------- #
# A .cfnlintrc's append_rules makes cfn-lint import Python files as rules. The
# scanned tree's config cannot name one. Each rules file leaves a marker when it
# is imported; the operator case is the control that proves cfn-lint does import
# it when it is allowed to.
# --------------------------------------------------------------------------- #


def _require_cfn_lint() -> None:
    if find_executable("cfn-lint") is None:
        if _required():
            pytest.fail("ASH_REQUIRE_CFN_TOOLS is set but cfn-lint is not on PATH")
        pytest.skip("cfn-lint is not on PATH")


def _rules_that_mark(directory: Path, marker: Path) -> Path:
    directory.mkdir(parents=True)
    (directory / "planted_rule.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n", encoding="utf-8"
    )
    return directory


def _cfnlintrc(path: Path, rules: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(f"append_rules:\n  - {rules.as_posix()}\n", encoding="utf-8")
    return path


def _scan_with_tree_config(
    tmp_path: Path, tree_config: dict, *extra: str, scanners: str = "cfn-lint"
):
    """``ash scan`` with no --config, so the tree's .ash/.ash.yaml is the config."""
    source = tmp_path / "repo"
    if not source.exists():
        shutil.copytree(FIXTURE_REPO, source)
    (source / ".ash").mkdir(exist_ok=True)
    (source / ".ash" / ".ash.yaml").write_text(
        yaml.safe_dump(
            {
                "project_name": "scanned",
                **tree_config,
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / f"out-{len(list(tmp_path.iterdir()))}"
    proc = subprocess.run(  # nosec B603 - fixed argv
        [
            _ash(),
            "scan",
            "--mode",
            "local",
            "--source-dir",
            str(source),
            "--output-dir",
            str(output),
            "--scanners",
            scanners,
            "--no-progress",
            "--no-fail-on-findings",
            *extra,
        ],
        capture_output=True,
        text=True,
        timeout=900,
        env={**os.environ, "ASH_OFFLINE": "true"},
    )
    return proc, output


def test_a_cfnlintrc_named_by_the_scanned_tree_never_loads_its_rules(tmp_path):
    _require_cfn_lint()
    source = tmp_path / "repo"
    shutil.copytree(FIXTURE_REPO, source)
    marker = tmp_path / "rule-imported"
    rules = _rules_that_mark(source / "rules", marker)
    _cfnlintrc(source / ".cfnlintrc", rules)

    proc, output = _scan_with_tree_config(
        tmp_path, {"scanners": {"cfn-lint": {"options": {"config_file": ".cfnlintrc"}}}}
    )

    assert not marker.exists(), "cfn-lint imported a rule the scanned tree planted"
    log = (output / "ash.log").read_text(encoding="utf-8", errors="replace")
    assert "Ignoring scanners.cfn-lint.options.config_file" in log, (
        proc.stdout[-3000:] + proc.stderr[-3000:]
    )
    assert _scanner_results(output)["cfn-lint"]["status"] != "MISSING"


def test_a_relative_path_in_the_operators_cfnlintrc_never_reaches_the_tree(tmp_path):
    """cfn-lint resolves a config file's relative paths against its working
    directory, not against the file. Run in the source directory, the operator's
    ``append_rules: [rules]`` imported the scanned tree's rules/*.py."""
    _require_cfn_lint()
    source = tmp_path / "repo"
    shutil.copytree(FIXTURE_REPO, source)
    marker = tmp_path / "tree-rule-imported"
    _rules_that_mark(source / "rules", marker)
    rc = tmp_path / "operator" / ".cfnlintrc"
    rc.parent.mkdir()
    rc.write_text("append_rules:\n  - rules\n", encoding="utf-8")

    proc, output = _scan_with_tree_config(
        tmp_path,
        {},
        "--config-overrides",
        f"scanners.cfn-lint.options.config_file={rc.as_posix()}",
    )

    assert not marker.exists(), "cfn-lint imported a rule from the scanned tree"
    # The relative path names nothing where cfn-lint runs, so the run fails
    # loudly rather than linting without the operator's rules.
    assert _scanner_results(output)["cfn-lint"]["status"] == "ERROR", (
        proc.stdout[-3000:] + proc.stderr[-3000:]
    )


def test_a_relative_path_in_the_operators_cfnlintrc_names_nothing(tmp_path):
    """Run from the filesystem root, cfn-lint read a relative ``append_rules``
    entry from there: ``tmp/x`` named /tmp/x. The entry below names a rules
    directory when read from the root, and nothing from the empty directory ASH
    runs cfn-lint in."""
    _require_cfn_lint()
    marker = tmp_path / "rule-imported-from-root"
    rules = _rules_that_mark(tmp_path / "rules-named-from-root", marker)
    rc = tmp_path / "operator" / ".cfnlintrc"
    rc.parent.mkdir()
    rc.write_text(
        f"append_rules:\n  - {rules.relative_to(rules.anchor).as_posix()}\n",
        encoding="utf-8",
    )

    proc, output = _scan_with_tree_config(
        tmp_path,
        {},
        "--config-overrides",
        f"scanners.cfn-lint.options.config_file={rc.as_posix()}",
    )

    assert not marker.exists(), "cfn-lint read a relative path from the root"
    assert _scanner_results(output)["cfn-lint"]["status"] == "ERROR", (
        proc.stdout[-3000:] + proc.stderr[-3000:]
    )


def test_the_scanned_trees_config_cannot_narrow_what_is_reported(tmp_path):
    """ignore_checks and rule_sets drop findings before ASH sees them, and
    tool_version picks the cfn-lint release. Set by the tree's .ash/.ash.yaml,
    each is ignored with a warning and the default is used."""
    _require_tools()
    proc, output = _scan_with_tree_config(
        tmp_path,
        {
            "scanners": {
                "cfn-lint": {
                    "options": {"ignore_checks": ["E", "W"], "tool_version": "==1.43.3"}
                },
                "cfn-guard": {"options": {"rule_sets": ["wa-Reliability-Pillar"]}},
            }
        },
        scanners="cfn-lint,cfn-guard",
    )

    log = proc.stdout[-3000:] + proc.stderr[-3000:]
    lint = _results(output, "cfn-lint")
    assert {(r["ruleId"], _where(r)[1]) for r in lint} == CFN_LINT_EXPECTED, log
    guard = _results(output, "cfn-guard")
    assert {r["ruleId"] for r in guard} == CFN_GUARD_EXPECTED_RULES, log
    ash_log = (output / "ash.log").read_text(encoding="utf-8", errors="replace")
    for option in (
        "cfn-lint.options.ignore_checks",
        "cfn-lint.options.tool_version",
        "cfn-guard.options.rule_sets",
    ):
        assert f"Ignoring scanners.{option}" in ash_log, option


def _template_that_ignores_its_findings(source: Path) -> Path:
    """insecure.yaml, ignoring E and W for itself and each rule on its resource."""
    text = (source / "templates" / "insecure.yaml").read_text(encoding="utf-8")
    text = text.replace(
        "Resources:",
        "Metadata:\n  cfn-lint:\n    config:\n      ignore_checks: [E, W]\nResources:",
        1,
    )
    for resource, rule in (("OpenBucket", "E3002"), ("LegacyFunction", "E2533")):
        text = text.replace(
            f"  {resource}:\n",
            f"  {resource}:\n    Metadata:\n      cfn-lint:\n        config:\n"
            f"          ignore_checks: [{rule}]\n",
            1,
        )
    hiding = source / "templates" / "hides-its-findings.yaml"
    hiding.write_text(text, encoding="utf-8")
    return hiding


@pytest.mark.parametrize(
    "who, extra, expected",
    [
        # Off by default: the template's own ignores do not apply.
        ("nobody", (), {"W2001", "E3002", "E2533"}),
        # The tree's config cannot turn them on.
        ("tree", (), {"W2001", "E3002", "E2533"}),
        # The operator can; then the template-level [E, W] hides everything.
        (
            "operator",
            (
                "--config-overrides",
                "scanners.cfn-lint.options.honor_inline_ignores=true",
            ),
            set(),
        ),
        # The operator's own ignores still apply.
        (
            "nobody",
            ("--config-overrides", "scanners.cfn-lint.options.ignore_checks=[W2001]"),
            {"E3002", "E2533"},
        ),
    ],
)
def test_a_template_cannot_ignore_its_own_findings(tmp_path, who, extra, expected):
    """cfn-lint drops what a template's Metadata ignore_checks names, at the
    template or the resource level, before ASH sees it."""
    _require_cfn_lint()
    source = tmp_path / "repo"
    shutil.copytree(FIXTURE_REPO, source)
    _template_that_ignores_its_findings(source)
    tree = (
        {"scanners": {"cfn-lint": {"options": {"honor_inline_ignores": True}}}}
        if who == "tree"
        else {}
    )

    proc, output = _scan_with_tree_config(tmp_path, tree, *extra)

    log = proc.stdout[-3000:] + proc.stderr[-3000:]
    lint = _results(output, "cfn-lint")
    assert {
        r["ruleId"] for r in lint if _where(r)[0] == "templates/hides-its-findings.yaml"
    } == expected, log
    if who == "tree":
        ash_log = (output / "ash.log").read_text(encoding="utf-8", errors="replace")
        assert "Ignoring scanners.cfn-lint.options.honor_inline_ignores" in ash_log


#: A bucket name cfn-lint reports as E3031 (and, from 1.5x, E1161), and a
#: ``${AWS::Region}`` outside Fn::Sub, which it reports as E1029. The metadata
#: configures E3031 and E1029 so that neither reports anything.
_CONFIGURES_ITS_RULES = """AWSTemplateFormatVersion: "2010-09-09"
Metadata:
  cfn-lint:
    config:
      configure_rules:
        E3031:
          exceptions: ['.*']
        E1029:
          custom_excludes: '.*'
Resources:
  NamedBucket:
    Type: AWS::S3::Bucket
    Properties:
      BucketName: Bad_Name
  Topic:
    Type: AWS::SNS::Topic
    Properties:
      DisplayName: "arn:aws:sns:${AWS::Region}:x"
"""


def test_a_template_cannot_configure_its_findings_away(tmp_path):
    """cfn-lint applies a template's ``Metadata: cfn-lint: config:
    configure_rules`` ahead of the config file, and --mandatory-checks does not
    stop it. Unless the operator opts in, ASH passes configure_rules on the
    command line, which cfn-lint takes instead of the template's. The operator's
    own configure_rules still apply."""
    _require_cfn_lint()
    source = tmp_path / "repo"
    shutil.copytree(FIXTURE_REPO, source)
    (source / "templates" / "configures-its-rules.yaml").write_text(
        _CONFIGURES_ITS_RULES, encoding="utf-8"
    )
    rc = tmp_path / "operator" / ".cfnlintrc"
    rc.parent.mkdir()
    rc.write_text("configure_rules:\n  E3031:\n    exceptions: ['Bad_.*']\n")

    def found(*extra: str) -> set:
        proc, output = _scan_with_tree_config(tmp_path, {}, *extra)
        assert _scanner_results(output)["cfn-lint"]["status"] == "FAILED", (
            proc.stdout[-3000:] + proc.stderr[-3000:]
        )
        return {
            r["ruleId"]
            for r in _results(output, "cfn-lint")
            if _where(r)[0] == "templates/configures-its-rules.yaml"
        }

    by_default = found()
    honored = found(
        "--config-overrides", "scanners.cfn-lint.options.honor_inline_ignores=true"
    )
    with_operator_rules = found(
        "--config-overrides", f"scanners.cfn-lint.options.config_file={rc.as_posix()}"
    )

    assert {"E3031", "E1029"} <= by_default, by_default
    # Opted in, the template's settings apply and both are gone.
    assert honored == by_default - {"E3031", "E1029"}, honored
    # The operator's E3031 exception applies; the template's E1029 setting does not.
    assert with_operator_rules == by_default - {"E3031"}, with_operator_rules


#: Two resources under one name: cfn-lint cannot decode the template and reports
#: E0000, which ASH's template discovery does not check for.
_DUPLICATE_KEYS = """AWSTemplateFormatVersion: "2010-09-09"
Resources:
  Topic:
    Type: AWS::SNS::Topic
  Topic:
    Type: AWS::SNS::Topic
"""

#: Ignores parse errors and W2001 for itself, and has an unused parameter (W2001).
#: cfn-lint sorts the templates it is given by path, so this one is linted just
#: before the duplicate-keys template.
_IGNORES_PARSE_ERRORS = """AWSTemplateFormatVersion: "2010-09-09"
Metadata:
  cfn-lint:
    config:
      ignore_checks: [E0000, W2001]
Parameters:
  Unused:
    Type: String
Resources:
  Topic:
    Type: AWS::SNS::Topic
"""


@pytest.mark.parametrize("honored", [False, True], ids=["default", "honored"])
def test_a_template_cannot_hide_the_next_templates_parse_errors(tmp_path, honored):
    """cfn-lint keeps the last decoded template's Metadata config while it reads
    the next template, and drops that template's E0000 when the kept
    ignore_checks name it, without consulting --mandatory-checks (measured with
    1.43.3 and 1.57.2). So a template that ignores E0000 for itself made the
    next template's parse errors disappear. With template ignores honored, the
    template's own W2001 is still hidden, and only its own."""
    _require_cfn_lint()
    extra = (
        ("--config-overrides", "scanners.cfn-lint.options.honor_inline_ignores=true")
        if honored
        else ()
    )

    def findings(*names: str) -> dict:
        root = tmp_path / "-".join(names)
        source = root / "repo"
        (source / "templates").mkdir(parents=True)
        texts = {
            "a-ignores-parse-errors": _IGNORES_PARSE_ERRORS,
            "b-duplicate-keys": _DUPLICATE_KEYS,
        }
        for name in names:
            (source / "templates" / f"{name}.yaml").write_text(
                texts[name], encoding="utf-8"
            )
        proc, output = _scan_with_tree_config(root, {}, *extra)
        log = proc.stdout[-3000:] + proc.stderr[-3000:]
        assert _scanner_results(output)["cfn-lint"]["status"] != "ERROR", log
        by_template: dict = {}
        for r in _results(output, "cfn-lint"):
            by_template.setdefault(_where(r)[0], []).append(r["ruleId"])
        return {name: sorted(ids) for name, ids in by_template.items()}

    alone = findings("b-duplicate-keys")["templates/b-duplicate-keys.yaml"]
    assert alone == ["E0000", "E0000"], alone
    together = findings("a-ignores-parse-errors", "b-duplicate-keys")
    assert together.get("templates/b-duplicate-keys.yaml") == alone, together
    own = together.get("templates/a-ignores-parse-errors.yaml", [])
    assert own == ([] if honored else ["W2001"]), together


def test_the_operator_can_name_a_cfnlintrc_outside_the_tree(tmp_path):
    """The control: the same kind of rules file is imported when the operator names it."""
    _require_cfn_lint()
    marker = tmp_path / "operator-rule-imported"
    rules = _rules_that_mark(tmp_path / "operator-rules", marker)
    rc = _cfnlintrc(tmp_path / "operator" / ".cfnlintrc", rules)

    _scan_with_tree_config(
        tmp_path,
        {},
        "--config-overrides",
        f"scanners.cfn-lint.options.config_file={rc.as_posix()}",
    )

    assert marker.exists(), "cfn-lint never imported the operator's rules"


# --------------------------------------------------------------------------- #
# cfn-guard prints a rules file it cannot parse, whole, and follows a symlinked
# .guard in a rules directory (both measured with 3.2.1). A file outside every
# rules directory carries a marker that must appear nowhere ASH writes.
# --------------------------------------------------------------------------- #

_LEAK_MARKER = "ash-cfn-guard-leak-marker-5c1e"


def _outside_file(tmp_path: Path) -> Path:
    outside_file = tmp_path / "elsewhere" / "notes.txt"
    outside_file.parent.mkdir(parents=True)
    outside_file.write_text(f"not a rule {_LEAK_MARKER}\n", encoding="utf-8")
    return outside_file


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError) as exc:  # pragma: no cover - Windows
        pytest.skip(f"symlink creation unavailable on this platform: {exc}")


def _files_mentioning(output: Path, text: str) -> list:
    return [
        path
        for path in output.rglob("*")
        if path.is_file() and text.encode() in path.read_bytes()
    ]


def test_rules_paths_named_by_the_scanned_tree_are_not_read(tmp_path):
    """The tree empties rule_sets and names its own rules: a link to a file outside
    the tree, and the file itself. Neither is read; the default set runs instead."""
    _require_tools()
    outside_file = _outside_file(tmp_path)
    source = tmp_path / "repo"
    shutil.copytree(FIXTURE_REPO, source)
    (source / "policy").mkdir()
    _symlink_or_skip(source / "policy" / "leak.guard", outside_file)

    proc, output = _scan_with_tree_config(
        tmp_path,
        {
            "scanners": {
                "cfn-guard": {
                    "options": {
                        "rule_sets": [],
                        "rules_paths": ["policy", outside_file.as_posix()],
                    }
                }
            }
        },
        scanners="cfn-guard",
    )

    log = proc.stdout[-3000:] + proc.stderr[-3000:]
    assert _files_mentioning(output, _LEAK_MARKER) == [], log
    ash_log = (output / "ash.log").read_text(encoding="utf-8", errors="replace")
    assert "Ignoring scanners.cfn-guard.options.rules_paths entry" in ash_log, log
    guard = _results(output, "cfn-guard")
    assert {r["ruleId"] for r in guard} == CFN_GUARD_EXPECTED_RULES, log


def test_an_operator_rules_directory_is_read_but_not_a_link_out_of_it(tmp_path):
    """The control: the operator's directory is honored, so its rule reports, and
    the link in it that leaves the directory is refused."""
    _require_tools()
    outside_file = _outside_file(tmp_path)
    rules = tmp_path / "operator-rules"
    (rules / "nested").mkdir(parents=True)
    (rules / "nested" / "mine.guard").write_text(
        'rule ash_operator_rule { Resources.*.Type == "AWS::SQS::Queue" }\n',
        encoding="utf-8",
    )
    _symlink_or_skip(rules / "leak.guard", outside_file)

    proc, output = _scan_with_tree_config(
        tmp_path,
        {},
        "--config-overrides",
        "scanners.cfn-guard.options.rule_sets=[]",
        "--config-overrides",
        f'scanners.cfn-guard.options.rules_paths=["{rules.as_posix()}"]',
        scanners="cfn-guard",
    )

    log = proc.stdout[-3000:] + proc.stderr[-3000:]
    assert _files_mentioning(output, _LEAK_MARKER) == [], log
    ash_log = (output / "ash.log").read_text(encoding="utf-8", errors="replace")
    assert "resolves outside the rules directory" in ash_log, log
    guard = _results(output, "cfn-guard")
    assert {r["ruleId"] for r in guard} == {"ASH_OPERATOR_RULE"}, log


@pytest.mark.parametrize("named", ["file", "directory"])
def test_an_operator_rules_path_in_the_tree_cannot_be_a_link_out_of_it(tmp_path, named):
    """The operator may name rules inside the scanned tree, but the tree decides
    what is at that path. A link there that leaves the tree is refused, so the
    file it points at never reaches cfn-guard, which would print it whole."""
    _require_tools()
    outside_file = _outside_file(tmp_path)
    source = tmp_path / "repo"
    shutil.copytree(FIXTURE_REPO, source)
    if named == "file":
        _symlink_or_skip(source / "policy.guard", outside_file)
        value = "policy.guard"
    else:
        outside = tmp_path / "elsewhere" / "rules"
        outside.mkdir()
        _symlink_or_skip(outside / "linked.guard", outside_file)
        (outside / "plain.guard").write_text(outside_file.read_text(), encoding="utf-8")
        _symlink_or_skip(source / "policy", outside)
        value = "policy"

    proc, output = _scan_with_tree_config(
        tmp_path,
        {},
        "--config-overrides",
        f'scanners.cfn-guard.options.rules_paths=["{value}"]',
        scanners="cfn-guard",
    )

    log = proc.stdout[-3000:] + proc.stderr[-3000:]
    assert _files_mentioning(output, _LEAK_MARKER) == [], log
    assert _LEAK_MARKER not in proc.stdout + proc.stderr
    assert _scanner_results(output)["cfn-guard"]["status"] == "MISSING", log
    ash_log = (output / "ash.log").read_text(encoding="utf-8", errors="replace")
    assert "outside the scanned tree" in ash_log, log
