#!/usr/bin/env python3
"""Fail when the CDK and Terraform deployment targets diverge on encryption at rest.

WHY THIS EXISTS
---------------
deploy/cdk and deploy/terraform are two implementations of the same deployment
targets, and they are meant to offer the same security posture. They stopped
doing so silently: the CDK side was hardened to encrypt every log group and every
secret with a customer-managed key, and the Terraform side was not. Nothing
noticed. Measured at the time: zero aws_kms_key resources under deploy/terraform,
no kms_key_id on any of its six log groups, none on either of its two secrets,
while all twelve CDK log groups and all four CDK secrets had one.

The absence of this check is why that drift was invisible, so the check is the
durable part of the work, not the fix.

WHAT IT COMPARES, AND WHAT IT DOES NOT
--------------------------------------
Read `--scope`. It is printed on every run, pass or fail, because a gate that
claims more than it checks is worse than no gate: its green gets read as evidence
about properties it never looked at.

The short version: encryption at rest, and the key policy that makes encryption
at rest actually deployable. Not IAM policy contents, not networking, not
retention, not naming, not tags, and not anything that needs a plan.

THE TRAP THIS GATE IS BUILT TO AVOID
------------------------------------
The obvious design is "extract property X from both sides and assert the two
agree". That gate passes when BOTH sides are wrong -- if a future change dropped
kms_key_id from CDK and from Terraform together, the two would agree perfectly
and the gate would go green on an unencrypted fleet. Agreement between two signals
cannot establish that either is correct.

So every check here is a POSITIVE assertion evaluated independently per side:
"every log group on the CDK side is encrypted" and "every log group on the
Terraform side is encrypted". Parity then falls out of both holding, and a
one-sided regression is reported as the side that broke rather than as a
disagreement. The counts are printed per side so a reader can see which side
carries which resources.

NON-VACUITY
-----------
"every log group is encrypted" is trivially true of a tree with no log groups, and
a rename that stopped the extractor finding any would pass in silence. Each check
therefore carries a floor, taken from the measurement above, and finding fewer
resources than the floor is a failure in its own right with its own message.

WHY IT READS THE COMMITTED TEMPLATES RATHER THAN SYNTHESIZING
------------------------------------------------------------
The cdk-template-drift job in the same workflow already proves the committed
templates are byte-identical to a fresh synth, so reading them is equivalent and
costs no npm install and no toolchain. THE COUPLING IS REAL AND WORTH STATING: if
that job is ever removed or made non-blocking, this gate starts reading an
artifact that may be stale, and would report parity against a template nobody
generated. It is checked here that the templates exist and parse; it is not
checked here that they are current.

WHY IT PARSES HCL BY HAND
-------------------------
`terraform show -json` needs a plan, a plan needs credentials, and this gate must
run with none. There is no HCL parser in the standard library and this repository
adds no dependency for a CI script. So the Terraform side is read with a
brace-matching block extractor, which is enough for the handful of top-level
resource attributes in scope and nothing more.

That is a real limitation, and it is handled by FAILING CLOSED. A resource type
that yields no blocks, a file that will not read, an attribute whose value cannot
be recognized -- each is a failure, never a skip. The extractor is deliberately
dumb: it finds top-level `resource "type" "name" {` blocks and top-level
attributes within them. It does not evaluate expressions, follow variables, or
resolve count/for_each, and it never needs to: presence of a key reference is the
property, not the ARN it resolves to.

THE POSITIVE CONTROL RUNS EVERY TIME
------------------------------------
`--self-test` copies the Terraform tree, perturbs it, and asserts this gate turns
red and names the perturbed resource. Two perturbations, because they exercise
different code paths:

  1. Remove kms_key_id from one log group -- the drift that actually happened.
  2. Widen the key policy's encryption-context condition to "*" -- a change that
     leaves every resource "encrypted" and still weakens the boundary, so it
     catches a gate that only counts attributes.

CI runs the self-test alongside the real check. A gate whose ability to fail is
demonstrated once, by hand, at review time, is a gate nobody knows still works.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
from pathlib import Path

# ---------------------------------------------------------------------------
# Scope. Printed on every run.
# ---------------------------------------------------------------------------

IN_SCOPE = [
    (
        "Every CloudWatch log group sets a customer-managed KMS key "
        "(CDK: KmsKeyId, Terraform: kms_key_id)."
    ),
    "Every Secrets Manager secret sets a customer-managed KMS key.",
    (
        "Every CodeBuild project sets a customer-managed KMS key "
        "(CDK: EncryptionKey, Terraform: encryption_key)."
    ),
    "Every customer-managed key enables rotation.",
    (
        "Every customer-managed key's policy grants the CloudWatch Logs service "
        "principal the encrypt/decrypt/describe action set, with an ArnLike "
        "condition on kms:EncryptionContext:aws:logs:arn, using the REGIONAL "
        "principal form logs.<region>.amazonaws.com."
    ),
    (
        "Every customer-managed key's policy keeps a statement granting the account "
        "root kms:*, without which the key cannot be administered."
    ),
]

OUT_OF_SCOPE = [
    (
        "WHERE a secret-decrypt grant is placed. CDK puts the AgentCore runtime "
        "role's grant in the key policy and the CodeBuild roles' grants in identity "
        "policies -- two placements for one key in one stack -- so placement cannot "
        "be a parity criterion. Terraform grants identity-side with a "
        "kms:ViaService condition. Both work, because the account-root statement "
        "delegates to IAM for same-account principals. This gate does NOT compute "
        "effective permissions, so it would not notice if one side granted decrypt "
        "to a principal the other did not."
    ),
    (
        "Anything about the VPC, including map_public_ip_on_launch. The CDK Fargate "
        "stack creates its own VPC, subnets and NAT gateway; the Terraform fargate "
        "module takes vpc_id and subnet ids as inputs and creates none of them. "
        "There is no Terraform resource to compare against, so this is a structural "
        "asymmetry rather than a gap, and reporting a pass on it would be a lie."
    ),
    "IAM policy contents, statement counts and cfn-nag SPCM. cfn-nag owns those.",
    (
        "S3 bucket configuration, load balancer configuration, log retention "
        "periods, resource naming and tags."
    ),
    (
        "Anything that requires a terraform plan: computed values, count/for_each "
        "expansion, and whether a variable's default is what an adopter will pass."
    ),
    (
        "Whether the committed CDK templates are current. The cdk-template-drift job "
        "owns that, and this gate depends on it."
    ),
]

# Floors, from the measurement that prompted this gate. Fewer than this means the
# extractor stopped finding things, not that the tree got smaller.
FLOORS = {
    "cdk log groups": 12,
    "terraform log groups": 6,
    "cdk secrets": 4,
    "terraform secrets": 2,
    "cdk codebuild projects": 11,
    "terraform codebuild projects": 4,
    "cdk kms keys": 5,
    "terraform kms keys": 5,
}

# The action set CloudWatch Logs needs on the key. Compared as a set, because
# order in a policy document is not meaningful.
REQUIRED_LOGS_ACTIONS = {
    "kms:Encrypt",
    "kms:Decrypt",
    "kms:ReEncrypt*",
    "kms:GenerateDataKey*",
    "kms:Describe*",
}

ENCRYPTION_CONTEXT_KEY = "kms:EncryptionContext:aws:logs:arn"


class Failure(Exception):
    """A parse problem. Raised rather than returned so nothing can be skipped."""


# ---------------------------------------------------------------------------
# Terraform side: a deliberately small HCL block reader.
# ---------------------------------------------------------------------------


def _match_brace(text: str, open_index: int) -> int:
    """Index of the `}` closing the `{` at open_index.

    String literals are skipped so a brace inside one cannot unbalance the count.
    Heredocs are not handled; none of the blocks read here contain one, and a
    stray heredoc brace would make the block over-run and its attributes go
    missing, which fails closed.
    """
    depth = 0
    i = open_index
    while i < len(text):
        char = text[i]
        if char == '"':
            i += 1
            while i < len(text) and text[i] != '"':
                i += 2 if text[i] == "\\" else 1
        elif char == "#":
            while i < len(text) and text[i] != "\n":
                i += 1
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    raise Failure(f"unbalanced braces starting at offset {open_index}")


def tf_files(root: Path) -> list[Path]:
    """Every module .tf, excluding vendored modules and examples.

    `.terraform/` holds registry modules this repository neither owns nor can
    fix, and they ship their own log groups -- counting those would make the
    Terraform side look compliant because somebody else's module is. `examples/`
    is excluded for the same reason in reverse: an example is a consumer, not an
    implementation, and its resources are not part of the posture being compared.
    """
    found = [
        path
        for path in sorted((root / "modules").rglob("*.tf"))
        if ".terraform" not in path.parts and "examples" not in path.parts
    ]
    if not found:
        raise Failure(f"no module .tf files under {root / 'modules'}")
    return found


def tf_resources(paths: list[Path], resource_type: str) -> list[tuple[str, str]]:
    """`[(where, body)]` for every top-level resource block of one type."""
    out: list[tuple[str, str]] = []
    pattern = re.compile(
        r'^resource\s+"' + re.escape(resource_type) + r'"\s+"([^"]+)"\s*\{', re.MULTILINE
    )
    for path in paths:
        try:
            text = path.read_text()
        except OSError as exc:
            raise Failure(f"cannot read {path}: {exc}") from exc
        for match in pattern.finditer(text):
            open_index = match.end() - 1
            close = _match_brace(text, open_index)
            out.append((f"{path}:{resource_type}.{match.group(1)}", text[open_index : close + 1]))
    return out


def tf_attribute(body: str, name: str) -> str | None:
    """A top-level `name = value` in a block body, or None.

    Top level only: nested blocks are skipped by tracking depth, so an
    `encryption_key` inside a `dynamic` block is not mistaken for the resource's
    own attribute.
    """
    depth = 0
    for raw in body.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if depth == 1:
            match = re.match("^" + re.escape(name) + r"\s*=\s*(.+)$", line)
            if match:
                return match.group(1).strip()
        depth += line.count("{") - line.count("}")
    return None


def tf_policy_documents(paths: list[Path]) -> list[tuple[str, str]]:
    """`[(where, body)]` for every `data "aws_iam_policy_document"` block."""
    out: list[tuple[str, str]] = []
    pattern = re.compile(r'^data\s+"aws_iam_policy_document"\s+"([^"]+)"\s*\{', re.MULTILINE)
    for path in paths:
        text = path.read_text()
        for match in pattern.finditer(text):
            open_index = match.end() - 1
            close = _match_brace(text, open_index)
            out.append((f"{path}:data.{match.group(1)}", text[open_index : close + 1]))
    return out


def tf_sub_blocks(body: str, name: str) -> list[str]:
    """Bodies of every immediately-nested `name {` block."""
    out = []
    pattern = re.compile(r"^\s*" + re.escape(name) + r"\s*\{", re.MULTILINE)
    for match in pattern.finditer(body):
        # Only immediate children: a `condition` inside a nested `statement`
        # would otherwise be attributed to the outer block.
        prefix = body[: match.start()]
        if prefix.count("{") - prefix.count("}") != 1:
            continue
        out.append(body[match.end() - 1 : _match_brace(body, match.end() - 1) + 1])
    return out


def tf_list_attribute(body: str, name: str) -> list[str]:
    """A top-level `name = [ ... ]` as its elements, each still raw HCL.

    Elements are returned as written -- a quoted string keeps its quotes, and a
    reference like `local.logs_service_principal` comes back as that text. Stripping
    to quoted strings only was this reader's first shape and it silently dropped
    every element that was a reference, which made the gate report "no logs grant"
    for four modules that had one. Returning raw and resolving later means an
    element this gate cannot understand can be NAMED rather than vanish.
    """
    match = re.search(r"^\s*" + re.escape(name) + r"\s*=\s*\[", body, re.MULTILINE)
    if not match:
        return []
    start = body.index("[", match.start())
    depth, i = 0, start
    while i < len(body):
        if body[i] == "[":
            depth += 1
        elif body[i] == "]":
            depth -= 1
            if depth == 0:
                break
        i += 1
    inner = body[start + 1 : i]
    # Split on commas that are not inside a string or a nested bracket.
    elements, current, in_string, bracket = [], "", False, 0
    for char in inner:
        if char == '"':
            in_string = not in_string
        if not in_string:
            if char in "[({":
                bracket += 1
            elif char in "])}":
                bracket -= 1
            elif char == "," and bracket == 0:
                elements.append(current.strip())
                current = ""
                continue
        current += char
    if current.strip():
        elements.append(current.strip())
    return [e for e in elements if e]


def tf_locals(paths: list[Path]) -> dict[str, str]:
    """`name -> raw expression` for every top-level `locals { }` entry.

    One hop of resolution, deliberately. These modules put the CloudWatch Logs
    service principal in a local so the region interpolation is written once, and
    following that one reference is the difference between reading the key policy
    and guessing at it. Anything deeper -- a local referring to another local, a
    variable, a function call -- is left unresolved and reported, not assumed.
    """
    out: dict[str, str] = {}
    for path in paths:
        text = path.read_text()
        for match in re.finditer(r"^locals\s*\{", text, re.MULTILINE):
            open_index = match.end() - 1
            body = text[open_index : _match_brace(text, open_index) + 1]
            depth = 0
            for raw in body.splitlines():
                line = raw.split("#", 1)[0].strip()
                if depth == 1:
                    entry = re.match(r"^([A-Za-z_][A-Za-z0-9_-]*)\s*=\s*(.+)$", line)
                    if entry:
                        out[entry.group(1)] = entry.group(2).strip()
                depth += line.count("{") - line.count("}")
    return out


def tf_resolve(element: str, locals_map: dict[str, str]) -> str | None:
    """A list element as a comparable string, or None if it cannot be resolved.

    None is the signal to FAIL, never to skip: a principal this gate cannot read is
    a principal it cannot vouch for.
    """
    element = element.strip()
    if element.startswith('"') and element.endswith('"'):
        return element[1:-1]
    reference = re.fullmatch(r"local\.([A-Za-z_][A-Za-z0-9_-]*)", element)
    if reference:
        target = locals_map.get(reference.group(1))
        if target is None:
            return None
        if target.startswith('"') and target.endswith('"'):
            return target[1:-1]
        return None
    return None


# ---------------------------------------------------------------------------
# CDK side: the committed templates.
# ---------------------------------------------------------------------------


def cdk_templates(root: Path) -> dict[str, dict]:
    paths = sorted(root.glob("*.template.json"))
    if not paths:
        raise Failure(f"no *.template.json under {root}")
    out = {}
    for path in paths:
        try:
            out[path.name] = json.loads(path.read_text())
        except (OSError, json.JSONDecodeError) as exc:
            raise Failure(f"cannot parse {path}: {exc}") from exc
    return out


def cdk_resources(templates: dict[str, dict], resource_type: str) -> list[tuple[str, dict]]:
    out = []
    for name, template in templates.items():
        for logical_id, resource in (template.get("Resources") or {}).items():
            if resource.get("Type") == resource_type:
                out.append((f"{name}:{logical_id}", resource.get("Properties") or {}))
    return out


# ---------------------------------------------------------------------------
# The checks.
# ---------------------------------------------------------------------------


class Report:
    def __init__(self) -> None:
        self.problems: list[str] = []
        self.lines: list[str] = []

    def note(self, text: str) -> None:
        self.lines.append(text)

    def fail(self, text: str) -> None:
        self.problems.append(text)

    def counted(self, label: str, found: int) -> None:
        floor = FLOORS[label]
        if found < floor:
            self.fail(
                f"{label}: found {found}, expected at least {floor}. Either resources "
                f"were removed, or this gate's extractor stopped finding them -- and "
                f"an extractor that finds nothing reports every property as satisfied. "
                f"Fix the extractor or lower the floor deliberately."
            )
        self.note(f"  {label:34s} {found:3d}  (floor {floor})")


def check_encrypted(report: Report, label: str, items, attribute) -> None:
    """Every item must configure a key. Evaluated per side, independently."""
    missing = [where for where, body in items if not attribute(body)]
    report.counted(label, len(items))
    for where in missing:
        report.fail(f"{label}: {where} sets no customer-managed key")


def check_key_rotation(report: Report, label: str, items, rotation) -> None:
    for where, body in items:
        value = rotation(body)
        if value is not True:
            report.fail(
                f"{label}: {where} does not enable key rotation (found {value!r})"
            )


def check_cdk_key_policies(report: Report, templates: dict[str, dict]) -> None:
    """Per stack, because whether the logs grant is REQUIRED depends on the unit.

    A key that encrypts only a secret does not need CloudWatch Logs named in its
    policy -- Secrets Manager encrypts using the caller's own credentials, which
    the account-root statement already delegates to IAM. A key that encrypts a log
    group does need it, because CloudWatch Logs acts on its own service principal
    and cannot be granted through an identity policy.

    Requiring it unconditionally was this gate's first shape and it was wrong: it
    red-lined the Terraform agentcore module, which owns a secret and no log group,
    for correctly omitting a grant it has no use for.
    """
    keys = cdk_resources(templates, "AWS::KMS::Key")
    report.counted("cdk kms keys", len(keys))

    for name, template in templates.items():
        resources = template.get("Resources") or {}
        encrypted_log_groups = [
            logical_id
            for logical_id, resource in resources.items()
            if resource.get("Type") == "AWS::Logs::LogGroup"
            and (resource.get("Properties") or {}).get("KmsKeyId") is not None
        ]
        stack_keys = [
            (logical_id, resource.get("Properties") or {})
            for logical_id, resource in resources.items()
            if resource.get("Type") == "AWS::KMS::Key"
        ]
        _check_unit_key_policies(
            report,
            unit=f"cdk {name}",
            needs_logs_grant=bool(encrypted_log_groups),
            log_group_count=len(encrypted_log_groups),
            policies=[
                (
                    logical_id,
                    [
                        _cdk_statement_view(s)
                        for s in ((props.get("KeyPolicy") or {}).get("Statement") or [])
                    ],
                )
                for logical_id, props in stack_keys
            ],
        )


def _check_unit_key_policies(
    report: Report,
    unit: str,
    needs_logs_grant: bool,
    log_group_count: int,
    policies: list[tuple[str, list[dict]]],
) -> None:
    """One deployable unit -- a CDK stack or a Terraform module -- checked whole."""
    if not policies:
        if needs_logs_grant:
            report.fail(
                f"{unit}: has {log_group_count} KMS-encrypted log group(s) but no "
                f"customer-managed key. The log groups point at a key this unit does "
                f"not declare."
            )
        return

    for where, views in policies:
        if not views:
            report.fail(f"{unit}: key policy for {where} has no statements at all")
            continue
        # Fail closed on anything the reader could not turn into a comparable
        # value. An unread principal or condition value is not a satisfied one.
        for view in views:
            if view["unresolved"]:
                report.fail(
                    f"{unit}: key policy {where} has element(s) this gate cannot "
                    f"resolve to a value: {view['unresolved']}. It resolves quoted "
                    f"strings and one hop of `local.` references and nothing else, so "
                    f"either simplify the expression or extend tf_resolve. Reported "
                    f"rather than skipped, because a principal that cannot be read "
                    f"cannot be vouched for."
                )
        _check_root_statement(report, f"{unit} key policy {where}", views)

    if not needs_logs_grant:
        report.note(f"  {unit}: no encrypted log group, so no logs grant required")
        return

    granting = [(where, views) for where, views in policies if any(_grants_logs(v) for v in views)]
    if not granting:
        report.fail(
            f"{unit}: has {log_group_count} KMS-encrypted log group(s), but no key "
            f"policy grants the CloudWatch Logs service principal. Setting the key on "
            f"a log group creates no key policy, so this synthesizes and validates "
            f"cleanly and then fails at CreateLogGroup."
        )
        return

    for where, views in granting:
        _check_logs_statements(report, f"{unit} key policy {where}", views)


def _cdk_statement_view(statement: dict) -> dict:
    actions = statement.get("Action")
    actions = actions if isinstance(actions, list) else [actions]
    principal = statement.get("Principal") or {}
    services = principal.get("Service")
    services = services if isinstance(services, list) else ([services] if services else [])
    aws = principal.get("AWS")
    aws = aws if isinstance(aws, list) else ([aws] if aws else [])
    conditions = []
    for operator, entries in (statement.get("Condition") or {}).items():
        for variable, values in (entries or {}).items():
            values = values if isinstance(values, list) else [values]
            conditions.append((operator, variable, [_flatten(v) for v in values]))
    return {
        "actions": [a for a in actions if isinstance(a, str)],
        "services": [_flatten(s) for s in services],
        "aws": [_flatten(a) for a in aws],
        "conditions": conditions,
        "unresolved": [],
    }


def _flatten(node) -> str:
    """An intrinsic rendered as the string it will become, well enough to match on.

    `{"Fn::Join": ["", ["logs.", {"Ref": "AWS::Region"}, ".amazonaws.com"]]}`
    becomes `logs.<AWS::Region>.amazonaws.com`. Only used for pattern matching --
    "does this name the regional logs principal", "is this the account root" --
    never for equality against a Terraform string.
    """
    if isinstance(node, str):
        return node
    if isinstance(node, dict):
        if "Fn::Join" in node:
            separator, parts = node["Fn::Join"]
            return separator.join(_flatten(p) for p in parts)
        if "Ref" in node:
            return f"<{node['Ref']}>"
        if "Fn::GetAtt" in node:
            return f"<{'.'.join(node['Fn::GetAtt'])}>"
    return str(node)


def check_tf_key_policies(report: Report, tf_dir: Path, paths: list[Path]) -> None:
    """Per module, for the same reason the CDK side is per stack.

    A key's `policy` argument names a document by HCL reference, and resolving that
    would mean evaluating HCL. Instead the unit is the module directory: a module's
    key policy documents are the `data "aws_iam_policy_document"` blocks in the
    same module that are referenced as a key policy. Those are identified by
    carrying the account-root `kms:*` statement, which every key policy here must
    have and no identity policy in these modules does -- an identity policy grants
    specific actions on specific resources, never `kms:*` to a root principal.
    """
    keys = tf_resources(paths, "aws_kms_key")
    report.counted("terraform kms keys", len(keys))

    documents = tf_policy_documents(paths)
    if not documents:
        report.fail(
            "terraform: no data.aws_iam_policy_document blocks found at all. Either "
            "the key policies moved to a shape this gate cannot read, or they are "
            "gone. Both are failures, and neither is a pass."
        )
        return

    modules = sorted({path.parent for path in paths if path.parent.parent.name == "modules"})
    if not modules:
        report.fail(f"terraform: found no module directories under {tf_dir / 'modules'}")
        return

    for module in modules:
        module_paths = [p for p in paths if p.parent == module]
        log_groups = tf_resources(module_paths, "aws_cloudwatch_log_group")
        encrypted = [
            where for where, body in log_groups if tf_attribute(body, "kms_key_id") is not None
        ]
        module_keys = tf_resources(module_paths, "aws_kms_key")
        locals_map = tf_locals(module_paths)
        key_policies = [
            (where, views)
            for where, body in tf_policy_documents(module_paths)
            for views in [
                [_tf_statement_view(s, locals_map) for s in tf_sub_blocks(body, "statement")]
            ]
            if _has_root_statement(views)
        ]
        if module_keys and not key_policies:
            report.fail(
                f"terraform {module.name}: declares {len(module_keys)} aws_kms_key but "
                f"no policy document granting the account root kms:*. The `policy` "
                f"argument REPLACES the key's default policy, so a key without that "
                f"statement cannot be administered by anyone, including the next apply."
            )
            continue
        _check_unit_key_policies(
            report,
            unit=f"terraform {module.name}",
            needs_logs_grant=bool(encrypted),
            log_group_count=len(encrypted),
            policies=key_policies,
        )


def _tf_statement_view(body: str, locals_map: dict[str, str]) -> dict:
    unresolved: list[str] = []

    def resolve_all(elements: list[str]) -> list[str]:
        out = []
        for element in elements:
            value = tf_resolve(element, locals_map)
            if value is None:
                unresolved.append(element)
            else:
                out.append(value)
        return out

    services: list[str] = []
    aws: list[str] = []
    for principal in tf_sub_blocks(body, "principals"):
        kind = (tf_attribute(principal, "type") or "").strip('"')
        identifiers = resolve_all(tf_list_attribute(principal, "identifiers"))
        if kind == "Service":
            services.extend(identifiers)
        elif kind == "AWS":
            aws.extend(identifiers)
    conditions = []
    for condition in tf_sub_blocks(body, "condition"):
        test = (tf_attribute(condition, "test") or "").strip('"')
        variable = (tf_attribute(condition, "variable") or "").strip('"')
        conditions.append((test, variable, resolve_all(tf_list_attribute(condition, "values"))))
    return {
        "actions": resolve_all(tf_list_attribute(body, "actions")),
        "services": services,
        "aws": aws,
        "conditions": conditions,
        "unresolved": unresolved,
    }


def _grants_logs(view: dict) -> bool:
    return any("logs." in s and "amazonaws.com" in s for s in view["services"])


def _has_root_statement(views: list[dict]) -> bool:
    return any(
        any(identifier.rstrip('"').endswith(":root") for identifier in view["aws"])
        and "kms:*" in view["actions"]
        for view in views
    )


def _check_root_statement(report: Report, label: str, views: list[dict]) -> None:
    if not _has_root_statement(views):
        report.fail(
            f"{label}: no statement grants the account root kms:*. A key policy that "
            f"omits it cannot be administered -- not by an operator and not by the "
            f"next deploy, which can then neither read the policy nor schedule the "
            f"key for deletion."
        )


def _check_logs_statements(report: Report, label: str, views: list[dict]) -> None:
    """The CloudWatch Logs grant, on whichever dialect produced the views."""
    logs_statements = [v for v in views if _grants_logs(v)]
    for view in logs_statements:
        missing = REQUIRED_LOGS_ACTIONS - set(view["actions"])
        if missing:
            report.fail(
                f"{label}: the CloudWatch Logs statement is missing "
                f"{sorted(missing)}. Encryption needs the whole set; a partial one "
                f"fails at write time rather than at create time."
            )
        # The regional principal form. logs.amazonaws.com is documented as wrong
        # here and fails, so a change to it is a real regression.
        for service in view["services"]:
            if service == "logs.amazonaws.com":
                report.fail(
                    f"{label}: uses the global principal logs.amazonaws.com. AWS "
                    f"documents the regional form logs.<region>.amazonaws.com and "
                    f"requires it to be in the same region as the key."
                )
        matching = [c for c in view["conditions"] if c[1] == ENCRYPTION_CONTEXT_KEY]
        if not matching:
            report.fail(
                f"{label}: the CloudWatch Logs statement has no condition on "
                f"{ENCRYPTION_CONTEXT_KEY}, so the grant is not confined to log "
                f"data at all."
            )
        for operator, _variable, values in matching:
            if operator != "ArnLike":
                report.fail(
                    f"{label}: the {ENCRYPTION_CONTEXT_KEY} condition uses "
                    f"{operator!r}, not ArnLike."
                )
            for value in values:
                if value.strip() == "*" or not value.startswith("arn:"):
                    report.fail(
                        f"{label}: the {ENCRYPTION_CONTEXT_KEY} condition value "
                        f"{value!r} is not an ARN pattern. Widening it to a bare "
                        f"wildcard leaves every resource nominally encrypted while "
                        f"removing the boundary the condition exists to draw."
                    )
                elif ":log-group:" in value and value.endswith(":log-group:*"):
                    # Narrower than account-scoped is fine and stricter; noted so a
                    # reader can see the two sides may legitimately differ here.
                    report.note(f"  {label}: log-group-scoped condition {value!r}")


# ---------------------------------------------------------------------------
# Driver.
# ---------------------------------------------------------------------------


def run(cdk_dir: Path, tf_dir: Path) -> Report:
    report = Report()
    templates = cdk_templates(cdk_dir)
    paths = tf_files(tf_dir)
    report.note(f"CDK: {len(templates)} committed template(s) from {cdk_dir}")
    report.note(f"Terraform: {len(paths)} module .tf file(s) from {tf_dir}")
    report.note("")
    report.note("resource counts per side:")

    check_encrypted(
        report,
        "cdk log groups",
        cdk_resources(templates, "AWS::Logs::LogGroup"),
        lambda props: props.get("KmsKeyId") is not None,
    )
    check_encrypted(
        report,
        "terraform log groups",
        tf_resources(paths, "aws_cloudwatch_log_group"),
        lambda body: tf_attribute(body, "kms_key_id") is not None,
    )
    check_encrypted(
        report,
        "cdk secrets",
        cdk_resources(templates, "AWS::SecretsManager::Secret"),
        lambda props: props.get("KmsKeyId") is not None,
    )
    check_encrypted(
        report,
        "terraform secrets",
        tf_resources(paths, "aws_secretsmanager_secret"),
        lambda body: tf_attribute(body, "kms_key_id") is not None,
    )
    check_encrypted(
        report,
        "cdk codebuild projects",
        cdk_resources(templates, "AWS::CodeBuild::Project"),
        lambda props: props.get("EncryptionKey") is not None,
    )
    check_encrypted(
        report,
        "terraform codebuild projects",
        tf_resources(paths, "aws_codebuild_project"),
        lambda body: tf_attribute(body, "encryption_key") is not None,
    )

    check_key_rotation(
        report,
        "cdk kms keys",
        cdk_resources(templates, "AWS::KMS::Key"),
        lambda props: props.get("EnableKeyRotation"),
    )
    check_key_rotation(
        report,
        "terraform kms keys",
        tf_resources(paths, "aws_kms_key"),
        lambda body: (tf_attribute(body, "enable_key_rotation") or "").strip() == "true",
    )

    report.note("")
    check_cdk_key_policies(report, templates)
    check_tf_key_policies(report, tf_dir, paths)
    return report


def print_scope() -> None:
    print("### What this gate compares")
    print()
    for item in IN_SCOPE:
        print(f"  IN   {item}")
    print()
    print("### What this gate does NOT compare")
    print()
    for item in OUT_OF_SCOPE:
        print(f"  OUT  {item}")
    print()


def self_test(cdk_dir: Path, tf_dir: Path, work_dir: Path | None) -> int:
    """Prove the gate can fail. Two perturbations, each expected to be caught."""
    print("=" * 72)
    print("POSITIVE CONTROL")
    print("=" * 72)
    print()
    print("A parity gate that cannot fail is worse than none, because its green is")
    print("read as evidence. Each case below perturbs a copy of deploy/terraform and")
    print("requires this gate to go red and name the perturbation.")
    print()

    cases = [
        (
            "remove kms_key_id from one log group (the drift that actually happened)",
            _perturb_drop_log_group_key,
            "sets no customer-managed key",
        ),
        (
            "widen the key policy encryption-context condition to a bare wildcard",
            _perturb_widen_condition,
            "is not an ARN pattern",
        ),
    ]

    failures = 0
    for description, perturb, expected in cases:
        with tempfile.TemporaryDirectory(dir=work_dir) as work:
            copy = Path(work) / "terraform"
            shutil.copytree(tf_dir, copy, ignore=shutil.ignore_patterns(".terraform"))
            touched = perturb(copy)
            print(f"CASE: {description}")
            print(f"  perturbed: {touched}")
            try:
                report = run(cdk_dir, copy)
                problems = report.problems
            except Failure as exc:
                problems = [f"parse failure: {exc}"]
            named = [p for p in problems if expected in p]
            if not problems:
                print("  RESULT: the gate reported NO problem. The control FAILED.")
                failures += 1
            elif not named:
                print(f"  RESULT: the gate failed, but not with {expected!r}:")
                for problem in problems[:4]:
                    print(f"    {problem}")
                print("  The control FAILED: it went red for the wrong reason.")
                failures += 1
            else:
                print(f"  RESULT: caught, {len(problems)} problem(s). First match:")
                print(f"    {named[0]}")
                print("  Control PASSED.")
            print()

    if failures:
        print(f"POSITIVE CONTROL FAILED: {failures} of {len(cases)} case(s) went undetected.")
        print("Nothing this gate reports green can be trusted until that is fixed.")
        return 1
    print(f"POSITIVE CONTROL PASSED: {len(cases)} of {len(cases)} perturbations caught.")
    return 0


def _perturb_drop_log_group_key(tf_root: Path) -> str:
    for path in tf_files(tf_root):
        text = path.read_text()
        for _where, body in tf_resources([path], "aws_cloudwatch_log_group"):
            if tf_attribute(body, "kms_key_id") is None:
                continue
            stripped = re.sub(r"^\s*kms_key_id\s*=.*$", "", body, count=1, flags=re.MULTILINE)
            path.write_text(text.replace(body, stripped, 1))
            return f"{path}: dropped kms_key_id from one aws_cloudwatch_log_group"
    raise Failure("no log group with kms_key_id to perturb; the control cannot run")


def _perturb_widen_condition(tf_root: Path) -> str:
    for path in tf_files(tf_root):
        text = path.read_text()
        if ENCRYPTION_CONTEXT_KEY not in text:
            continue
        widened = re.sub(
            r'(values\s*=\s*\[)"arn:[^"]*logs[^"]*"',
            r'\1"*"',
            text,
            count=1,
        )
        if widened == text:
            continue
        path.write_text(widened)
        return f"{path}: widened the {ENCRYPTION_CONTEXT_KEY} condition to \"*\""
    raise Failure("no encryption-context condition to widen; the control cannot run")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    root = Path(__file__).resolve().parent.parent
    parser.add_argument("--cdk-templates", type=Path, default=root / "cdk" / "templates")
    parser.add_argument("--terraform", type=Path, default=root / "terraform")
    parser.add_argument("--scope", action="store_true", help="print the scope and exit")
    parser.add_argument("--self-test", action="store_true", help="run the positive control")
    parser.add_argument(
        "--work-dir",
        type=Path,
        default=None,
        help=(
            "Where --self-test writes its perturbed copies. Defaults to the "
            "platform temporary directory, which honours TMPDIR. CI passes "
            "RUNNER_TEMP so the copies land on the runner's own scratch space "
            "rather than a shared /tmp."
        ),
    )
    args = parser.parse_args()

    print_scope()
    if args.scope:
        return 0

    if args.self_test:
        return self_test(args.cdk_templates, args.terraform, args.work_dir)

    try:
        report = run(args.cdk_templates, args.terraform)
    except Failure as exc:
        # Fail closed. A gate that cannot read its inputs has not proved parity.
        print(f"::error::iac-parity could not read its inputs: {exc}")
        print("Failing closed: an unreadable tree is not a tree in parity.")
        return 1

    for line in report.lines:
        print(line)
    print()

    if report.problems:
        print(f"::error::CDK and Terraform diverge on {len(report.problems)} property check(s).")
        for problem in report.problems:
            print(f"::error title=iac-parity::{problem}")
        return 1

    print("CDK and Terraform agree on every property listed above as IN scope.")
    print("That is not a statement about the OUT items. Read them.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
