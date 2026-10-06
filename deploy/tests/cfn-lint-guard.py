#!/usr/bin/env python3
"""Runs cfn-lint and cfn-guard over the committed CloudFormation templates.

WHY THIS EXISTS
---------------
The templates under deploy/cdk/templates/ are what an adopter launches, and
until this check the only things that read them were cdk synth (which wrote
them), the drift gate (which compares them to a fresh synth), cdk-nag (which
inspects the CDK constructs, not the rendered JSON) and the Terraform
equivalence census (which compares resource kinds). None of those validates the
rendered template against the CloudFormation resource specification, and none
states a security property of the rendered JSON. A template can pass all four
and still fail at launch on a property CloudFormation rejects. cfn-lint covers
the first gap and cfn-guard, with the rules in guard-rules/ash-deploy.guard,
covers the second.

Nothing here deploys or calls an AWS API. Both tools read local files.

WHAT COUNTS AS A FAILURE
------------------------
cfn-lint: any match at all, warnings and informational ones included, from any
rule. No rule is ignored, and a template or config file that asks cfn-lint or
cfn-guard to ignore something is itself a failure (`find_suppressions`): the
point is to fix the template, not to quiet the tool. The W3005 warnings CDK used
to produce are fixed in the stacks; see deploy/cdk/lib/ash-implied-dependencies.ts.

cfn-guard: any rule reported non-compliant for any template. Also a failure: a
rule that no template exercises. cfn-guard reports a rule with no matching
resources as not applicable, which reads exactly like a pass, so a rule whose
resource type stops appearing would keep the gate green while checking nothing.
EXPECTED_UNEXERCISED lists the rules allowed to be in that state, each with the
reason, and an entry there that starts being exercised is reported so the list
does not go stale.

NEGATIVE CONTROL (--self-test)
------------------------------
Every check proves it can fail, on every run, against templates this script
breaks on purpose. Each mutant is a copy of a committed template with one
property changed, written to a scratch directory and never committed (a
committed broken template would be scanned by ASH's own self-scan and by every
other tool that walks the tree):

  * cfn-lint must reject an unknown resource property (an E-class error) and a
    re-added redundant DependsOn (W3005, a warning, which proves warnings fail
    the gate);
  * for every guard rule, a mutant must fail THAT rule and only that rule, so a
    rule that has stopped matching, or a mutation that broke the template in
    some unrelated way, both show up;
  * EKS_CLUSTER_ENDPOINT_NOT_OPEN also gets two compliant mutants (a private
    endpoint, and a public one restricted to a private range) that must pass,
    because a rule that always fails would pass the first half of this test;
  * the suppression detector must flag planted cfn-lint and cfn-guard
    suppressions.

A guard rule with no mutant is a self-test failure, so a new rule cannot land
without its negative control.

USAGE
-----
    python3 deploy/tests/cfn-lint-guard.py check --cfn-lint PATH --cfn-guard PATH
    python3 deploy/tests/cfn-lint-guard.py self-test --cfn-lint PATH --cfn-guard PATH

Both tools are pinned by the workflow: cfn-lint from
deploy/tests/cfn-lint-requirements.txt (hash-locked), cfn-guard as a release
binary verified by sha256.
"""

from __future__ import annotations

import argparse
import copy
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
TEMPLATE_DIR = REPO_ROOT / "deploy" / "cdk" / "templates"
RULES_FILE = REPO_ROOT / "deploy" / "tests" / "guard-rules" / "ash-deploy.guard"

# The EKS stack is the reason this gate exists in the e2e plan, so its absence is
# a failure in its own right rather than one fewer file in a glob.
REQUIRED_TEMPLATES = ("AshEksOperator.template.json",)

EXPECTED_UNEXERCISED = {
    "EKS_CLUSTER_ENDPOINT_NOT_OPEN": (
        "No stack creates an EKS cluster: AshEksOperator installs into one the adopter already runs. "
        "The rule is kept so a stack that does create one cannot ship an endpoint open to the internet."
    ),
}

CFN_LINT_CONFIG_FILES = (
    ".cfnlintrc",
    ".cfnlintrc.yaml",
    ".cfnlintrc.yml",
    ".cfnlintrc.json",
)

Template = dict[str, Any]


class GateError(Exception):
    """A tool could not run, or produced output this script cannot read."""


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Tools:
    cfn_lint: str
    cfn_guard: str


def run(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, check=False)  # noqa: S603
    except OSError as exc:
        # FileNotFoundError for a missing tool, but also PermissionError (POSIX, no
        # execute bit) and WinError 193 (Windows, not a program): each means the tool
        # never ran, which is a gate error and not a traceback.
        raise GateError(f"cannot run {cmd[0]}: {exc}") from exc


def cfn_lint_matches(tools: Tools, templates: list[Path]) -> list[dict[str, Any]]:
    """Every cfn-lint match for `templates`. Exit code and output must agree."""
    proc = run([tools.cfn_lint, "--format", "json", "--", *map(str, templates)])
    try:
        matches = json.loads(proc.stdout) if proc.stdout.strip() else []
    except json.JSONDecodeError as exc:
        raise GateError(
            f"cfn-lint printed non-JSON output (rc={proc.returncode}): {proc.stdout[:500]}{proc.stderr[:500]}"
        ) from exc
    if not isinstance(matches, list):
        raise GateError(f"cfn-lint JSON output is not a list: {proc.stdout[:500]}")
    # cfn-lint's exit code is a bitmask of the severities it found (2 error, 4
    # warning, 8 informational). 0 with matches, or non-zero with none, means the
    # output and the verdict disagree, and neither can be trusted.
    if (proc.returncode == 0) != (not matches):
        raise GateError(
            f"cfn-lint exit code {proc.returncode} disagrees with its {len(matches)} match(es). stderr: {proc.stderr[:500]}"
        )
    return matches


def rule_names(rules_file: Path) -> list[str]:
    names = re.findall(
        r"^rule\s+([A-Za-z0-9_]+)",
        rules_file.read_text(encoding="utf-8"),
        flags=re.MULTILINE,
    )
    if not names:
        raise GateError(f"no rules found in {rules_file}")
    return names


@dataclass(frozen=True)
class GuardResult:
    template: str
    failed: frozenset[str]
    passed: frozenset[str]
    not_applicable: frozenset[str]


def guard_rule_name(entry: Any) -> str:
    """The rule name in one `not_compliant` entry: `{"Rule": {"name": ...}}` in cfn-guard 3.2.1."""
    if isinstance(entry, dict):
        rule = entry.get("Rule")
        if isinstance(rule, dict) and isinstance(rule.get("name"), str):
            return rule["name"]
    raise GateError(
        f"cannot read a rule name from cfn-guard output entry: {json.dumps(entry)[:300]}"
    )


def cfn_guard(tools: Tools, rules_file: Path, template: Path) -> GuardResult:
    proc = run(
        [
            tools.cfn_guard,
            "validate",
            "--rules",
            str(rules_file),
            "--data",
            str(template),
            "--output-format",
            "json",
            "--show-summary",
            "none",
        ]
    )
    try:
        report = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        raise GateError(
            f"cfn-guard printed non-JSON output for {template.name} (rc={proc.returncode}): {proc.stdout[:500]}{proc.stderr[:500]}"
        ) from exc
    if isinstance(report, list):
        if len(report) != 1:
            raise GateError(
                f"cfn-guard returned {len(report)} reports for one template"
            )
        report = report[0]
    failed = frozenset(guard_rule_name(e) for e in report.get("not_compliant", []))
    result = GuardResult(
        template=template.name,
        failed=failed,
        passed=frozenset(report.get("compliant", [])),
        not_applicable=frozenset(report.get("not_applicable", [])),
    )
    status = report.get("status")
    # Same agreement check as for cfn-lint: the status, the exit code and the
    # rule lists must tell one story.
    if (status == "FAIL") != bool(failed) or (proc.returncode == 0) != (
        status != "FAIL"
    ):
        raise GateError(
            f"cfn-guard output for {template.name} is inconsistent: status={status} rc={proc.returncode} failed={sorted(failed)}. stderr: {proc.stderr[:500]}"
        )
    return result


# --------------------------------------------------------------------------- #
# Suppressions
# --------------------------------------------------------------------------- #


def find_suppressions(template: Template) -> list[str]:
    """Places in `template` that ask cfn-lint or cfn-guard to skip something."""
    found = []
    metadata = template.get("Metadata")
    if isinstance(metadata, dict) and "cfn-lint" in metadata:
        found.append("template Metadata.cfn-lint")
    for logical_id, resource in (template.get("Resources") or {}).items():
        meta = resource.get("Metadata") if isinstance(resource, dict) else None
        if not isinstance(meta, dict):
            continue
        if "cfn-lint" in meta:
            found.append(f"{logical_id} Metadata.cfn-lint")
        guard = meta.get("guard")
        if isinstance(guard, dict) and "SuppressedRules" in guard:
            found.append(f"{logical_id} Metadata.guard.SuppressedRules")
    return found


def config_files(directories: list[Path]) -> list[Path]:
    return [
        d / name
        for d in directories
        for name in CFN_LINT_CONFIG_FILES
        if (d / name).exists()
    ]


# --------------------------------------------------------------------------- #
# check
# --------------------------------------------------------------------------- #


def committed_templates(template_dir: Path) -> list[Path]:
    templates = sorted(template_dir.glob("*.template.json"))
    if not templates:
        raise GateError(
            f"no *.template.json under {template_dir}; nothing would be checked"
        )
    missing = [
        name for name in REQUIRED_TEMPLATES if not (template_dir / name).is_file()
    ]
    if missing:
        raise GateError(
            f"required template(s) missing from {template_dir}: {', '.join(missing)}"
        )
    return templates


def check(tools: Tools, template_dir: Path, rules_file: Path) -> list[str]:
    problems: list[str] = []
    templates = committed_templates(template_dir)

    for path in config_files([Path.cwd(), REPO_ROOT, template_dir]):
        problems.append(
            f"{path} is a cfn-lint config file; this gate runs with no rule ignored, so remove it"
        )
    for path in templates:
        for where in find_suppressions(json.loads(path.read_text(encoding="utf-8"))):
            problems.append(
                f"{path.name}: {where} suppresses a check; fix the template instead"
            )

    matches = cfn_lint_matches(tools, templates)
    for m in matches:
        loc = m.get("Location", {}).get("Start", {})
        problems.append(
            f"cfn-lint {m.get('Rule', {}).get('Id')} {Path(m.get('Filename', '?')).name}:{loc.get('LineNumber')}: {m.get('Message')}"
        )
    print(f"cfn-lint: {len(templates)} template(s), {len(matches)} match(es)")

    names = rule_names(rules_file)
    exercised: set[str] = set()
    for path in templates:
        result = cfn_guard(tools, rules_file, path)
        unknown = (result.failed | result.passed | result.not_applicable) - set(names)
        if unknown:
            raise GateError(
                f"cfn-guard reported rules not in {rules_file.name}: {sorted(unknown)}"
            )
        exercised |= result.passed | result.failed
        for rule in sorted(result.failed):
            problems.append(f"cfn-guard {rule} fails for {path.name}")
        print(
            f"cfn-guard {path.name}: {len(result.passed)} pass, {len(result.failed)} fail, {len(result.not_applicable)} not applicable"
        )

    for rule in names:
        if rule in exercised and rule in EXPECTED_UNEXERCISED:
            problems.append(
                f"cfn-guard {rule} now matches a template; remove it from EXPECTED_UNEXERCISED"
            )
        elif rule not in exercised and rule not in EXPECTED_UNEXERCISED:
            problems.append(
                f"cfn-guard {rule} matched no resource in any template, so it checked nothing"
            )
    for rule in sorted(set(EXPECTED_UNEXERCISED) - set(names)):
        problems.append(
            f"EXPECTED_UNEXERCISED names {rule}, which is not a rule in {rules_file.name}"
        )
    return problems


# --------------------------------------------------------------------------- #
# self-test: mutants
# --------------------------------------------------------------------------- #


def resource_of_type(template: Template, resource_type: str) -> dict[str, Any]:
    for resource in template["Resources"].values():
        if resource.get("Type") == resource_type:
            return resource
    raise GateError(f"no {resource_type} in the template a mutant needs")


def first_with(template: Template, resource_type: str, prop: str) -> dict[str, Any]:
    for resource in template["Resources"].values():
        if resource.get("Type") == resource_type and prop in resource.get(
            "Properties", {}
        ):
            return resource
    raise GateError(f"no {resource_type} with {prop} in the template a mutant needs")


def add_statement(statement: dict[str, Any]) -> Callable[[Template], None]:
    def mutate(t: Template) -> None:
        first_with(t, "AWS::IAM::Policy", "PolicyDocument")["Properties"][
            "PolicyDocument"
        ]["Statement"].append(statement)

    return mutate


def set_prop(
    resource_type: str, path: tuple[str, ...], value: Any
) -> Callable[[Template], None]:
    def mutate(t: Template) -> None:
        node = resource_of_type(t, resource_type)["Properties"]
        for key in path[:-1]:
            node = node[key]
        node[path[-1]] = value

    return mutate


def del_prop(resource_type: str, prop: str) -> Callable[[Template], None]:
    def mutate(t: Template) -> None:
        resource = first_with(t, resource_type, prop)
        del resource["Properties"][prop]

    return mutate


def wildcard_in_role_inline_policy(t: Template) -> None:
    roles = [r for r in t["Resources"].values() if r.get("Type") == "AWS::IAM::Role"]
    if len(roles) < 2:
        raise GateError(
            "the role-inline mutant needs a template with at least two roles"
        )
    # Only the LAST role gets an inline policy, so the others have none. That is the
    # shape that made an unfiltered query skip the whole block.
    roles[-1]["Properties"]["Policies"] = [
        {
            "PolicyName": "planted",
            "PolicyDocument": {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
            },
        }
    ]


def drop_resources_of_type(*resource_types: str) -> Callable[[Template], None]:
    def mutate(t: Template) -> None:
        doomed = {
            name
            for name, resource in t["Resources"].items()
            if resource.get("Type") in resource_types
        }
        if not doomed:
            raise GateError(f"no {' or '.join(resource_types)} in the template to drop")
        for name in doomed:
            del t["Resources"][name]
        # Keep the template well-formed for the resources that remain.
        for resource in t["Resources"].values():
            depends = resource.get("DependsOn")
            if isinstance(depends, list):
                resource["DependsOn"] = [d for d in depends if d not in doomed]
                if not resource["DependsOn"]:
                    del resource["DependsOn"]
            elif depends in doomed:
                del resource["DependsOn"]

    return mutate


def chain(*mutations: Callable[[Template], None]) -> Callable[[Template], None]:
    def mutate(t: Template) -> None:
        for mutation in mutations:
            mutation(t)

    return mutate


def open_sg_rule_v6(t: Template) -> None:
    props = resource_of_type(t, "AWS::EC2::SecurityGroupIngress")["Properties"]
    props.pop("CidrIp", None)
    props.pop("SourceSecurityGroupId", None)
    props["CidrIpv6"] = "::/0"


def open_inline_sg(t: Template) -> None:
    resource_of_type(t, "AWS::EC2::SecurityGroup")["Properties"][
        "SecurityGroupIngress"
    ] = [{"IpProtocol": "tcp", "FromPort": 443, "ToPort": 443, "CidrIp": "0.0.0.0/0"}]


def add_eks_cluster(vpc_config_extra: dict[str, Any]) -> Callable[[Template], None]:
    def mutate(t: Template) -> None:
        t["Resources"]["PlantedCluster"] = {
            "Type": "AWS::EKS::Cluster",
            "Properties": {
                "RoleArn": {
                    "Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:role/planted"
                },
                "ResourcesVpcConfig": {
                    "SubnetIds": ["subnet-11111111", "subnet-22222222"],
                    **vpc_config_extra,
                },
            },
        }

    return mutate


@dataclass(frozen=True)
class GuardMutant:
    name: str
    template: str
    mutate: Callable[[Template], None]
    # The exact set of rules that must fail. Empty means the mutant is compliant.
    expect_failed: frozenset[str]


def guard_mutants() -> list[GuardMutant]:
    def m(
        name: str, template: str, mutate: Callable[[Template], None], *rules: str
    ) -> GuardMutant:
        return GuardMutant(name, template, mutate, frozenset(rules))

    pipeline = "AshDistributedPipeline.template.json"
    fargate = "AshFargate.template.json"
    eks = "AshEksOperator.template.json"
    return [
        m(
            "bucket allows public policies",
            pipeline,
            set_prop(
                "AWS::S3::Bucket",
                ("PublicAccessBlockConfiguration", "BlockPublicPolicy"),
                False,
            ),
            "S3_BUCKET_BLOCKS_PUBLIC_ACCESS",
        ),
        # A missing property must fail like a wrong one. cfn-guard skips a whole
        # query when one match lacks the queried path, so each rule that reads a
        # property gets a mutant that deletes it from one resource of several.
        m(
            "bucket with no public access block",
            pipeline,
            del_prop("AWS::S3::Bucket", "PublicAccessBlockConfiguration"),
            "S3_BUCKET_BLOCKS_PUBLIC_ACCESS",
        ),
        m(
            "bucket without encryption",
            pipeline,
            del_prop("AWS::S3::Bucket", "BucketEncryption"),
            "S3_BUCKET_ENCRYPTED",
        ),
        m(
            "key rotation off",
            pipeline,
            set_prop("AWS::KMS::Key", ("EnableKeyRotation",), False),
            "KMS_KEY_ROTATION_ENABLED",
        ),
        m(
            "key rotation unset",
            pipeline,
            del_prop("AWS::KMS::Key", "EnableKeyRotation"),
            "KMS_KEY_ROTATION_ENABLED",
        ),
        m(
            "log group kept forever",
            eks,
            del_prop("AWS::Logs::LogGroup", "RetentionInDays"),
            "LOG_GROUP_RETAINED_AND_ENCRYPTED",
        ),
        m(
            "log group unencrypted",
            eks,
            del_prop("AWS::Logs::LogGroup", "KmsKeyId"),
            "LOG_GROUP_RETAINED_AND_ENCRYPTED",
        ),
        m(
            'Action "*" as a string',
            eks,
            add_statement({"Effect": "Allow", "Action": "*", "Resource": "*"}),
            "IAM_NO_WILDCARD_OR_NEGATED_ALLOW",
        ),
        m(
            "service wildcard in a list",
            eks,
            add_statement(
                {
                    "Effect": "Allow",
                    "Action": ["logs:PutLogEvents", "iam:*"],
                    "Resource": "*",
                }
            ),
            "IAM_NO_WILDCARD_OR_NEGATED_ALLOW",
        ),
        m(
            "Allow with NotAction",
            eks,
            add_statement(
                {"Effect": "Allow", "NotAction": "iam:CreateUser", "Resource": "*"}
            ),
            "IAM_NO_WILDCARD_OR_NEGATED_ALLOW",
        ),
        m(
            'Action "*" in a role\'s inline policy',
            "AshDistributedPipeline.template.json",
            wildcard_in_role_inline_policy,
            "IAM_NO_WILDCARD_OR_NEGATED_ALLOW",
        ),
        # The inline-policy check must not depend on the template also having a
        # standalone policy resource for the rule to run at all.
        m(
            'Action "*" in a role\'s inline policy, no policy resources',
            "AshDistributedPipeline.template.json",
            chain(
                drop_resources_of_type("AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"),
                wildcard_in_role_inline_policy,
            ),
            "IAM_NO_WILDCARD_OR_NEGATED_ALLOW",
        ),
        m(
            "ingress rule open to 0.0.0.0/0",
            fargate,
            set_prop("AWS::EC2::SecurityGroupIngress", ("CidrIp",), "0.0.0.0/0"),
            "SECURITY_GROUP_INGRESS_NOT_OPEN_TO_THE_INTERNET",
        ),
        m(
            "ingress rule open to ::/0",
            fargate,
            open_sg_rule_v6,
            "SECURITY_GROUP_INGRESS_NOT_OPEN_TO_THE_INTERNET",
        ),
        m(
            "inline ingress open to 0.0.0.0/0",
            fargate,
            open_inline_sg,
            "SECURITY_GROUP_INGRESS_NOT_OPEN_TO_THE_INTERNET",
        ),
        m(
            "inline ingress open to 0.0.0.0/0, no ingress resources",
            fargate,
            chain(
                drop_resources_of_type("AWS::EC2::SecurityGroupIngress"),
                open_inline_sg,
            ),
            "SECURITY_GROUP_INGRESS_NOT_OPEN_TO_THE_INTERNET",
        ),
        m(
            "internet-facing load balancer",
            fargate,
            set_prop(
                "AWS::ElasticLoadBalancingV2::LoadBalancer",
                ("Scheme",),
                "internet-facing",
            ),
            "LOAD_BALANCER_IS_INTERNAL",
        ),
        # CloudFormation's default Scheme is internet-facing, so an absent one is public.
        m(
            "load balancer with no Scheme",
            fargate,
            del_prop("AWS::ElasticLoadBalancingV2::LoadBalancer", "Scheme"),
            "LOAD_BALANCER_IS_INTERNAL",
        ),
        m(
            "lambda permission for any principal",
            "AshCodeCommitGate.template.json",
            set_prop("AWS::Lambda::Permission", ("Principal",), "*"),
            "LAMBDA_PERMISSION_NAMES_A_PRINCIPAL",
        ),
        m(
            "EKS cluster with default (public) endpoint",
            eks,
            add_eks_cluster({}),
            "EKS_CLUSTER_ENDPOINT_NOT_OPEN",
        ),
        m(
            "EKS cluster public to 0.0.0.0/0",
            eks,
            add_eks_cluster(
                {
                    "EndpointPublicAccess": True,
                    "PublicAccessCidrs": ["10.0.0.0/8", "0.0.0.0/0"],
                }
            ),
            "EKS_CLUSTER_ENDPOINT_NOT_OPEN",
        ),
        m(
            "EKS cluster public with no allowlist",
            eks,
            add_eks_cluster({"EndpointPublicAccess": True}),
            "EKS_CLUSTER_ENDPOINT_NOT_OPEN",
        ),
        m(
            "EKS cluster with a private endpoint (compliant)",
            eks,
            add_eks_cluster(
                {"EndpointPublicAccess": False, "EndpointPrivateAccess": True}
            ),
        ),
        m(
            "EKS cluster public to a private range only (compliant)",
            eks,
            add_eks_cluster(
                {"EndpointPublicAccess": True, "PublicAccessCidrs": ["10.0.0.0/8"]}
            ),
        ),
    ]


def lint_mutants() -> list[tuple[str, str, Callable[[Template], None], str]]:
    def unknown_property(t: Template) -> None:
        resource_of_type(t, "AWS::Lambda::Function")["Properties"][
            "PlantedUnknownProperty"
        ] = "x"

    def redundant_depends_on(t: Template) -> None:
        fn = resource_of_type(t, "AWS::Lambda::Function")
        role_id = fn["Properties"]["Role"]["Fn::GetAtt"][0]
        deps = fn.setdefault("DependsOn", [])
        if isinstance(deps, str):
            deps = fn["DependsOn"] = [deps]
        deps.append(role_id)

    eks = "AshEksOperator.template.json"
    return [
        ("unknown Lambda property", eks, unknown_property, "E3002"),
        (
            "DependsOn the role the function already GetAtts",
            eks,
            redundant_depends_on,
            "W3005",
        ),
    ]


def write_mutant(
    work: Path,
    template_dir: Path,
    source: str,
    mutate: Callable[[Template], None],
    index: int,
) -> Path:
    template = json.loads((template_dir / source).read_text(encoding="utf-8"))
    mutated = copy.deepcopy(template)
    mutate(mutated)
    if mutated == template:
        raise GateError(f"mutant {index} on {source} changed nothing")
    path = work / f"mutant-{index:02d}-{source}"
    path.write_text(json.dumps(mutated, indent=1), encoding="utf-8")
    return path


def self_test(
    tools: Tools, template_dir: Path, rules_file: Path, work_root: Path | None
) -> list[str]:
    problems: list[str] = []
    names = set(rule_names(rules_file))

    with tempfile.TemporaryDirectory(prefix="cfn-lint-guard-", dir=work_root) as tmp:
        work = Path(tmp)
        index = 0

        for label, source, mutate, rule_id in lint_mutants():
            index += 1
            path = write_mutant(work, template_dir, source, mutate, index)
            ids = sorted(
                {m.get("Rule", {}).get("Id") for m in cfn_lint_matches(tools, [path])}
            )
            if rule_id not in ids:
                problems.append(
                    f"cfn-lint did not report {rule_id} for planted '{label}' (reported: {ids})"
                )
            else:
                print(f"negative control ok: cfn-lint reports {rule_id} for '{label}'")

        covered: set[str] = set()
        for mutant in guard_mutants():
            index += 1
            path = write_mutant(
                work, template_dir, mutant.template, mutant.mutate, index
            )
            result = cfn_guard(tools, rules_file, path)
            covered |= mutant.expect_failed
            if result.failed != mutant.expect_failed:
                problems.append(
                    f"cfn-guard on planted '{mutant.name}': expected failing rules {sorted(mutant.expect_failed)}, got {sorted(result.failed)}"
                )
            else:
                verdict = (
                    f"fails {sorted(result.failed)}" if result.failed else "passes"
                )
                print(f"negative control ok: cfn-guard {verdict} for '{mutant.name}'")

        for rule in sorted(names - covered):
            problems.append(
                f"guard rule {rule} has no planted template that must fail it"
            )

    planted_template: Template = {
        "Metadata": {"cfn-lint": {"config": {"ignore_checks": ["W3005"]}}},
        "Resources": {
            "A": {
                "Type": "AWS::SQS::Queue",
                "Metadata": {"cfn-lint": {"config": {"ignore_checks": ["E3002"]}}},
            },
            "B": {
                "Type": "AWS::SQS::Queue",
                "Metadata": {"guard": {"SuppressedRules": ["S3_BUCKET_ENCRYPTED"]}},
            },
            "C": {"Type": "AWS::SQS::Queue", "Metadata": {"aws:cdk:path": "x"}},
        },
    }
    found = find_suppressions(planted_template)
    if len(found) != 3:
        problems.append(
            f"suppression detector found {found} in a template with exactly three planted suppressions"
        )
    else:
        print(
            "negative control ok: suppression detector flags all three planted suppressions"
        )
    return problems


# --------------------------------------------------------------------------- #


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=("check", "self-test"))
    parser.add_argument("--cfn-lint", default=os.environ.get("CFN_LINT", "cfn-lint"))
    parser.add_argument("--cfn-guard", default=os.environ.get("CFN_GUARD", "cfn-guard"))
    parser.add_argument("--templates", type=Path, default=TEMPLATE_DIR)
    parser.add_argument("--rules", type=Path, default=RULES_FILE)
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help="where self-test writes its mutants (default: system temp)",
    )
    args = parser.parse_args(argv)
    tools = Tools(args.cfn_lint, args.cfn_guard)

    try:
        if args.mode == "check":
            problems = check(tools, args.templates, args.rules)
        else:
            problems = self_test(tools, args.templates, args.rules, args.work_dir)
    except GateError as exc:
        print(f"::error::{exc}")
        return 1

    for problem in problems:
        print(f"::error::{problem}")
    if problems:
        print(f"{args.mode}: {len(problems)} problem(s)")
        return 1
    print(f"{args.mode}: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
