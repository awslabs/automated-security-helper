#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Render and verify the CloudFormation quick-create links for the committed templates.

WHY THIS IS GENERATED AND NOT WRITTEN BY HAND
---------------------------------------------
A quick-create link is a URL that prepopulates the CloudFormation console's create-stack
page. Its shape is documented at
AWSCloudFormation/latest/UserGuide/cfn-console-create-stacks-quick-create-links.html:

    https://<region>.console.aws.amazon.com/cloudformation/home?region=<region>
      #/stacks/create/review?templateURL=<url>&stackName=<name>&param_<Name>=<value>

Two properties of that format make a hand-written link a bad bet.

First, ``templateURL`` is REQUIRED and must be an S3 URL. Only three forms are accepted
-- ``https://s3.<region>.amazonaws.com/<bucket>/<key>``,
``https://<bucket>.s3.<region>.amazonaws.com/<key>``, and the legacy
``https://s3-<region>.amazonaws.com/<bucket>/<key>``. A GitHub raw URL does not work, and
pointing at the repository is the obvious wrong thing to reach for.

Which of the first two this renderer emits depends on the bucket name. The
virtual-hosted form is the default, because S3 prefers it and the path-style form is
slated for eventual deprecation. But S3's wildcard certificate for
``*.s3.<region>.amazonaws.com`` matches a single DNS label, so a bucket whose name
contains a period cannot be reached virtual-hosted over HTTPS: the TLS handshake fails
before CloudFormation reads the template (AmazonS3/latest/userguide/VirtualHosting.html,
and the "Avoid using periods" note in bucketnamingrules.html). A dotted bucket therefore
gets the path-style form, which the quick-create page lists as supported and which S3
still serves in every Region.

Second, and this is the whole reason a gate exists rather than just a document:
**CloudFormation silently ignores a ``param_`` name that the template does not declare**,
and silently ignores any parameter whose ``NoEcho`` is true. A typo is not an error. The
console opens, the field is absent, the template's default quietly takes effect, and the
adopter deploys something other than what the link said. Nothing anywhere reports it.

So every value in every link here is derived from the template it launches, and
``check`` re-reads the rendered document and asserts that derivation held.

WHAT IS DERIVED, AND FROM WHERE
-------------------------------
* the stack list -- the ``*.template.json`` files actually committed under
  ``deploy/cdk/templates/``, not a hardcoded array. ``deploy/cdk/scripts/synth-templates.sh``
  once iterated a hardcoded five-stack array and reported a tree the drift gate red-lined;
  a list is the failure mode this file is built to avoid repeating.
* every parameter name -- the template's own ``Parameters`` block.
* every parameter VALUE -- that parameter's own declared ``Default``.

That last point is what keeps the version out of the staleness problem. The links carry
``param_AshVersion=v3.7.0`` today, and a literal version in a committed document is
normally something that has to join ``[tool.commitizen] version_files`` to stay current.
It does not here, because the value is copied from the template's declared default rather
than typed, and ``check`` asserts the two are equal on every pull request. A
``version_files`` entry is only rewritten at a release; this is verified continuously,
which is strictly stronger.

WHAT IS NOT DERIVED, AND WILL NOT BE
------------------------------------
The bucket, read from ``deploy/quick-create-hosting.json``.

ASH publishes these templates to no S3 bucket, and that is a settled position rather than
a pending one: it is the same stance the project takes on container images, for the reason
given in ``docs/content/docs/building-your-own-image.md``. So an EMPTY bucket is the
shipping default of this repository, not a placeholder awaiting a value, and the committed
``quick-create-links.md`` is expected to carry no URLs indefinitely.

The links are for an adopter to render against a bucket they own. That is the whole
workflow this script exists to support, and the rendered document documents it.

While the bucket is empty this renderer emits NO URL -- an explicit
``NO-BUCKET-CONFIGURED`` and a warning instead. Specifically NOT an example URL with a
sample bucket name: that is how someone ends up publishing a link that points at a bucket
they do not control, and a dead link that looks real costs the reader an account-permissions
investigation before they conclude it was never real.

The general rule, which is worth stating because it is not obvious: a placeholder standing
in for a security-relevant value should be UNUSABLE rather than plausible, so that a wrong
value fails loudly instead of resolving to something. A syntactically valid stand-in gets
deployed; an obviously broken one gets replaced. That applies to a bucket in a launch URL the
same way it applies to a digest, a certificate subject, or an account id.

THE POSITIVE CONTROL
--------------------
``--self-test`` runs the validator over deliberately broken links -- a misspelled
parameter, a ``NoEcho`` parameter, a value that disagrees with the template, a GitHub raw
URL, a dotted bucket addressed virtual-hosted, an illegal stack name, and a declared
parameter outside the plan -- and fails unless every one is REJECTED. It runs two
classification cases the same way: a template nobody classified, and a stack classified
as taking no prepopulated parameters while declaring them. It also runs a correct link
through and fails unless that one is ACCEPTED, because a validator that rejects
everything would otherwise pass every negative case and prove nothing.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import urllib.parse
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_DIR = REPO_ROOT / "deploy" / "cdk" / "templates"
# JSON rather than TOML deliberately: requires-python is >=3.10, tomllib arrived in 3.11,
# and tomli is not a dependency of this repository -- so a TOML config would raise
# ModuleNotFoundError on the 3.10 leg of the unit-test matrix.
HOSTING_CONFIG = REPO_ROOT / "deploy" / "quick-create-hosting.json"
DOC_TEMPLATE = REPO_ROOT / "deploy" / "quick-create-links.md.template"
DOC_OUTPUT = REPO_ROOT / "deploy" / "quick-create-links.md"

# The parameters a link prepopulates, in the order they appear in the URL.
#
# An explicit list rather than "every parameter with a default", because a link is a
# recommendation and most defaults do not need restating. These three do: AshVersion
# because deploy/README.md tells adopters to pin it so a rebuild reproduces the same
# scanner set, RebuildSchedule because it is the parameter that decides whether the
# rebuild obligation in the trust note is actually met, and AshOfflineMode because it
# changes what the image contains.
#
# A name here that a template does not declare is the exact defect this file's gate
# exists to catch, so the list is checked against every template rather than trusted.
PREPOPULATED = ("AshVersion", "AshOfflineMode", "RebuildSchedule")

# How each committed template's link is built. Every template under TEMPLATE_DIR must
# appear here, and an UNCLASSIFIED one is a hard failure rather than a default.
#
# WHY A CLASSIFICATION AND NOT AN ASSUMPTION
# ------------------------------------------
# The three names above are image-build parameters, and not every target builds an image. A
# target that consumes a prebuilt image URI declares none of them -- correctly. Before this
# existed, such a template tripped MIN_PARAMS_PER_STACK with the message "Either the
# template's Parameters block moved or PREPOPULATED no longer matches it", and NEITHER cause
# was true. The repair that message invites is lowering or deleting the floor, which would
# remove the vacuity guard for every other stack. That is a worse outcome than the false
# alarm.
#
# So the shape is: the floor still applies, but only to stacks declared to be subject to it,
# and adding a template forces the decision instead of silently picking one. This is a list,
# and a list is the failure mode this file's docstring warns about -- which is why the
# missing-entry case FAILS rather than skipping. An unclassified template is not excluded by
# default; nothing is advertised until someone says how.
WITH_PREPOPULATED = "with-prepopulated-parameters"
WITHOUT_PREPOPULATED = "without-prepopulated-parameters"

STACK_CLASSES: dict[str, str] = {
    "AshAgentCore": WITH_PREPOPULATED,
    "AshCodeCommitGate": WITH_PREPOPULATED,
    "AshDistributedPipeline": WITH_PREPOPULATED,
    "AshEksOperator": WITHOUT_PREPOPULATED,
    "AshFargate": WITH_PREPOPULATED,
    "AshImagePipeline": WITH_PREPOPULATED,
}

# Floors for the positive controls. Without them a derivation that silently produced
# nothing -- a moved template directory, a renamed Parameters key -- would leave `check`
# validating an empty set and reporting success.
#
# MIN_PARAMS_PER_STACK applies only to WITH_PREPOPULATED stacks. MIN_STACKS counts every
# committed template; MIN_PREPOPULATED_STACKS counts the subset that carries parameters, so
# reclassifying every stack to WITHOUT_PREPOPULATED cannot empty the gate quietly.
MIN_STACKS = 5
MIN_PREPOPULATED_STACKS = 5
MIN_PARAMS_PER_STACK = 3
MIN_TOTAL_PARAM_ASSERTIONS = 15

# CloudFormation's documented stack-name rule: alphanumeric and hyphens, leading
# alphabetic character, at most 128 characters.
STACK_NAME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,127}$")

# The three S3 URL forms CloudFormation accepts in templateURL. Anchored, because a
# substring match would accept a GitHub URL that merely mentions one of them.
S3_URL_PATTERNS = (
    re.compile(r"^https://s3\.[a-z0-9-]+\.amazonaws\.com/[^/]+/.+$"),
    re.compile(r"^https://[^/.]+\.s3\.[a-z0-9-]+\.amazonaws\.com/.+$"),
    re.compile(r"^https://s3-[a-z0-9-]+\.amazonaws\.com/[^/]+/.+$"),
)

# S3 general purpose bucket naming rules, from AmazonS3/latest/userguide/bucketnamingrules.html.
# Checked so that a typo in quick-create-hosting.json fails at render time with a reason,
# rather than producing a link that opens the console and then cannot fetch its template.
BUCKET_CHARS_RE = re.compile(r"^[a-z0-9.-]+$")
BUCKET_IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
BUCKET_RESERVED_PREFIXES = ("xn--", "sthree-", "amzn-s3-demo-")
BUCKET_RESERVED_SUFFIXES = ("-s3alias", "--ol-s3", ".mrap", "--x-s3", "--table-s3")

# A Region code in the standard ``aws`` partition. The console host this renderer builds
# (``<region>.console.aws.amazon.com``) and the S3 endpoint suffix (``amazonaws.com``)
# are both specific to that partition; China and GovCloud use different hosts for each,
# so a link built here for one of those Regions would point at a console that does not
# serve it. Rejected rather than guessed at.
AWS_PARTITION_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d+$")
NON_AWS_PARTITION_PREFIXES = ("cn-", "us-gov-", "us-iso", "eusc-")

# Every console URL the renderer emits, for `check` to find in the rendered document.
# Deliberately loose about what follows the fragment so that a MALFORMED link is still
# found and then reported, rather than not matching and reading as absent.
CONSOLE_URL_RE = re.compile(
    r"https://[a-z0-9-]+\.console\.aws\.amazon\.com/cloudformation/home\?[^\s)\]]+"
)

# What the link column says while no bucket is configured. It is not a URL and cannot be
# clicked, which is the point -- see the module docstring.
NO_LINK_PLACEHOLDER = "`NO-BUCKET-CONFIGURED`"


def load_hosting() -> dict[str, Any]:
    """Read the hosting configuration, defaulting every key to "not configured"."""
    hosting = json.loads(HOSTING_CONFIG.read_text(encoding="utf-8"))
    return {
        "bucket": str(hosting.get("bucket") or "").strip(),
        "bucket_region": str(hosting.get("bucket_region") or "").strip(),
        "key_prefix": str(hosting.get("key_prefix") or "").strip(),
        "launch_regions": [str(r) for r in (hosting.get("launch_regions") or [])],
    }


def _region_problem(field: str, region: str) -> str | None:
    if not AWS_PARTITION_REGION_RE.match(region):
        return (
            f"{field} {region!r} is not an AWS Region code (for example us-east-1 or "
            "eu-west-2)."
        )
    if region.startswith(NON_AWS_PARTITION_PREFIXES):
        return (
            f"{field} {region!r} is outside the standard aws partition. Its console and "
            "S3 endpoints use different host names, which this renderer does not build."
        )
    return None


def hosting_problems(hosting: dict[str, Any]) -> list[str]:
    """Every reason the hosting configuration cannot produce a working link.

    An empty bucket is valid: it is the shipping default and renders no links. Once a
    bucket is set, the name must be one S3 would have accepted at creation, and the
    regions must be ones the generated host names exist for.
    """
    problems: list[str] = []
    bucket = str(hosting.get("bucket") or "")
    raw_regions = hosting.get("launch_regions") or []
    regions = [str(r) for r in raw_regions] if isinstance(raw_regions, list) else []

    for region in regions:
        problem = _region_problem("launch_regions entry", region)
        if problem:
            problems.append(problem)

    if not bucket:
        return problems

    where = f"bucket {bucket!r}"
    if not 3 <= len(bucket) <= 63:
        problems.append(f"{where} must be between 3 and 63 characters long.")
    if not BUCKET_CHARS_RE.match(bucket):
        problems.append(
            f"{where} may contain only lowercase letters, numbers, periods and hyphens."
        )
    if not (bucket[0].isalnum() and bucket[-1].isalnum()):
        problems.append(f"{where} must begin and end with a letter or number.")
    if ".." in bucket:
        problems.append(f"{where} must not contain two adjacent periods.")
    if BUCKET_IP_RE.match(bucket):
        problems.append(f"{where} must not be formatted as an IP address.")
    if bucket.startswith(BUCKET_RESERVED_PREFIXES):
        problems.append(f"{where} starts with a prefix S3 reserves.")
    if bucket.endswith(BUCKET_RESERVED_SUFFIXES):
        problems.append(f"{where} ends with a suffix S3 reserves.")

    bucket_region = str(hosting.get("bucket_region") or "")
    if not bucket_region:
        problems.append(
            f"{where} is set but bucket_region is empty. The template URL names the "
            "bucket's Region endpoint, so it cannot be built without one."
        )
    else:
        problem = _region_problem("bucket_region", bucket_region)
        if problem:
            problems.append(problem)

    if not regions:
        problems.append(
            f"{where} is set but launch_regions is empty, so no link would be rendered."
        )

    key_prefix = str(hosting.get("key_prefix") or "")
    if key_prefix.startswith("/"):
        problems.append(
            f"key_prefix {key_prefix!r} starts with '/'. S3 keys have no leading slash; "
            "the template URL would name a different object."
        )
    return problems


def _display(path: Path) -> str:
    """A path for a message: repository-relative when it is inside the repository."""
    try:
        return str(path.relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def load_templates() -> dict[str, dict[str, dict[str, Any]]]:
    """Every committed template's Parameters block, keyed by stack name.

    Discovered by glob rather than listed. A stack added to the CDK app and committed is
    covered the day it lands, and a stack removed stops being advertised.
    """
    stacks: dict[str, dict[str, dict[str, Any]]] = {}
    for path in sorted(TEMPLATE_DIR.glob("*.template.json")):
        stack = path.name[: -len(".template.json")]
        document = json.loads(path.read_text(encoding="utf-8"))
        stacks[stack] = document.get("Parameters") or {}
    return stacks


def is_noecho(spec: dict[str, Any]) -> bool:
    """Whether a parameter is NoEcho, accepting both the JSON and string spellings.

    CloudFormation accepts ``"NoEcho": true`` and ``"NoEcho": "true"``; cdk emits the
    former. Treating only the boolean as NoEcho would let a hand-written template's
    string form through, and the consequence is a link naming a credential parameter
    that CloudFormation then ignores.
    """
    value = spec.get("NoEcho")
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() == "true"


def parameter_plan(
    stacks: dict[str, dict[str, dict[str, Any]]],
) -> tuple[dict[str, list[tuple[str, str]]], list[str]]:
    """The (name, value) pairs each stack's link will carry, plus any problems found.

    This is the single derivation. `render` writes it into URLs and `check` compares the
    written URLs back against it, so the document and the verdict cannot come from two
    implementations that drift apart.
    """
    plan: dict[str, list[tuple[str, str]]] = {}
    problems: list[str] = []

    # Every committed template must be classified, and a stale classification must not
    # outlive its template. Both directions are checked because each hides a different
    # thing: an unclassified template would be advertised on a guess, and a classification
    # for a template that no longer exists suggests coverage that is not there.
    for stack in sorted(set(stacks) - set(STACK_CLASSES)):
        declared = sorted(set(PREPOPULATED) & set(stacks[stack]))
        problems.append(
            f"{stack} is a committed template that STACK_CLASSES does not classify, so how "
            f"its link should be built is undecided. It declares {len(declared)} of the "
            f"{len(PREPOPULATED)} prepopulated parameters "
            f"({', '.join(declared) if declared else 'none'}). Add it to STACK_CLASSES as "
            f"{WITH_PREPOPULATED!r} if its link should carry them, or "
            f"{WITHOUT_PREPOPULATED!r} if it legitimately has none -- a target that "
            "consumes a prebuilt image declares no AshVersion, and that is a real case "
            "rather than a defect. Do NOT lower or delete MIN_PARAMS_PER_STACK to make "
            "this pass: that floor is the vacuity guard for the stacks it does apply to."
        )
    for stack in sorted(set(STACK_CLASSES) - set(stacks)):
        problems.append(
            f"STACK_CLASSES classifies {stack}, which has no committed template under "
            f"{TEMPLATE_DIR.relative_to(REPO_ROOT)}. Remove the entry -- a classification "
            "for a stack that does not exist reads as coverage and checks nothing."
        )

    for stack, params in stacks.items():
        stack_class = STACK_CLASSES.get(stack)
        declared = sorted(set(PREPOPULATED) & set(params))

        if stack_class == WITHOUT_PREPOPULATED:
            # Checked in the other direction too: a stack parked here that DOES declare
            # them would have its link silently omit parameters adopters are told to pin.
            if declared:
                problems.append(
                    f"{stack} is classified {WITHOUT_PREPOPULATED} but declares "
                    f"{', '.join(declared)}. Its link would omit parameters the template "
                    f"accepts. Reclassify it as {WITH_PREPOPULATED}."
                )
            plan[stack] = []
            continue

        if stack_class is None:
            # Already reported above. No plan entry, so nothing is advertised for it.
            plan[stack] = []
            continue

        pairs: list[tuple[str, str]] = []
        for name in PREPOPULATED:
            spec = params.get(name)
            if spec is None:
                # Reported by the floor below, which now only applies to stacks declared
                # to be subject to it.
                continue
            if is_noecho(spec):
                problems.append(
                    f"{stack}: {name} is NoEcho, so CloudFormation ignores it in a "
                    "quick-create link. Remove it from PREPOPULATED -- a link that "
                    "names it silently does nothing."
                )
                continue
            default = spec.get("Default")
            if default is None or str(default) == "":
                problems.append(
                    f"{stack}: {name} has no non-empty Default, so there is no value "
                    "to prepopulate from. Give it a default or drop it from "
                    "PREPOPULATED."
                )
                continue
            pairs.append((name, str(default)))

        if len(pairs) < MIN_PARAMS_PER_STACK:
            problems.append(
                f"{stack} is classified {WITH_PREPOPULATED} but yields only {len(pairs)} "
                f"parameter(s), below the floor of {MIN_PARAMS_PER_STACK}. It declares "
                f"{len(declared)} of the {len(PREPOPULATED)} "
                f"({', '.join(declared) if declared else 'none'}), so either the template's "
                f"Parameters block moved, or it belongs in {WITHOUT_PREPOPULATED}, or a "
                "declared one was skipped for being NoEcho or defaultless -- the messages "
                "above say which. Reclassify it rather than lowering the floor."
            )
        plan[stack] = pairs

    total = sum(len(pairs) for pairs in plan.values())
    prepopulated_stacks = sum(
        1 for stack in plan if STACK_CLASSES.get(stack) == WITH_PREPOPULATED
    )
    if len(plan) < MIN_STACKS:
        problems.append(
            f"found {len(plan)} template(s) under {TEMPLATE_DIR.relative_to(REPO_ROOT)}, "
            f"below the floor of {MIN_STACKS}. Nothing would be advertised."
        )
    if prepopulated_stacks < MIN_PREPOPULATED_STACKS:
        problems.append(
            f"only {prepopulated_stacks} stack(s) are classified {WITH_PREPOPULATED}, below "
            f"the floor of {MIN_PREPOPULATED_STACKS}. Reclassifying stacks as "
            f"{WITHOUT_PREPOPULATED} empties this gate without tripping anything else, so "
            "the count is checked."
        )
    if total < MIN_TOTAL_PARAM_ASSERTIONS:
        problems.append(
            f"the plan carries {total} parameter assertion(s), below the floor of "
            f"{MIN_TOTAL_PARAM_ASSERTIONS}. A gate with nothing to assert passes "
            "without checking anything."
        )
    return plan, problems


def required_without_default(params: dict[str, dict[str, Any]]) -> list[str]:
    """Parameters the adopter must still type, because the template gives no default.

    A quick-create link cannot supply these -- there is no value to derive -- so the
    console opens with the field blank and stack creation fails until it is filled. Worth
    naming in the document rather than leaving the reader to discover it.
    """
    return sorted(
        name
        for name, spec in params.items()
        if spec.get("Default") is None and not is_noecho(spec)
    )


def template_url(hosting: dict[str, Any], stack: str) -> str:
    """The S3 URL for one stack's template.

    Virtual-hosted for a bucket name without periods, path-style for one with them. The
    virtual-hosted wildcard certificate cannot match a dotted bucket name, so that form
    fails TLS for it; see the module docstring. The key is percent-encoded as a path, so a
    prefix with a space or ``+`` names the object it says.
    """
    bucket = str(hosting["bucket"])
    region = str(hosting["bucket_region"])
    key = urllib.parse.quote(f"{hosting['key_prefix']}{stack}.template.json", safe="/")
    if "." in bucket:
        return f"https://s3.{region}.amazonaws.com/{bucket}/{key}"
    return f"https://{bucket}.s3.{region}.amazonaws.com/{key}"


def quick_create_url(
    hosting: dict[str, Any],
    stack: str,
    region: str,
    pairs: list[tuple[str, str]],
) -> str:
    """One quick-create link.

    Every value is percent-encoded. That is not defensive padding: RebuildSchedule's
    default is ``cron(0 6 * * ? *)``, whose spaces and ``?`` would otherwise terminate or
    corrupt the query string, and the resulting link would silently carry a different
    schedule than the one printed beside it. `check` decodes what it finds and compares
    against the template's default, which is what proves this encoding is right.
    """
    encoded_template = urllib.parse.quote(template_url(hosting, stack), safe="")
    query = [f"templateURL={encoded_template}", f"stackName={stack}"]
    query.extend(
        f"param_{name}={urllib.parse.quote(value, safe='')}" for name, value in pairs
    )
    return (
        f"https://{region}.console.aws.amazon.com/cloudformation/home"
        f"?region={region}#/stacks/create/review?" + "&".join(query)
    )


def validate_url(
    url: str,
    stacks: dict[str, dict[str, dict[str, Any]]],
    plan: dict[str, list[tuple[str, str]]],
) -> list[str]:
    """Every problem with one rendered quick-create link.

    Returns an empty list for a correct link. This is the function ``--self-test`` drives
    with deliberately broken input, so it must report rather than raise.
    """
    problems: list[str] = []

    if "#" not in url:
        return [
            f"{url}: no '#' fragment, so it carries no create-stack request at all."
        ]
    prefix, fragment = url.split("#", 1)

    marker = "/stacks/create/review?"
    if not fragment.startswith(marker):
        return [
            (
                f"{url}: fragment is {fragment!r}, expected it to start with "
                f"{marker!r}. The console opens its own start page rather than the "
                "quick-create form."
            )
        ]

    fields = urllib.parse.parse_qsl(
        fragment[len(marker) :], keep_blank_values=True, strict_parsing=False
    )
    seen = dict(fields)

    # The region in the host and the region in the query must agree; the console reads
    # the query one and a mismatch silently launches somewhere other than the link says.
    host_region = urllib.parse.urlsplit(prefix).hostname or ""
    host_region = host_region.split(".", 1)[0]
    query_region = dict(
        urllib.parse.parse_qsl(urllib.parse.urlsplit(prefix).query)
    ).get("region", "")
    if host_region != query_region:
        problems.append(
            f"{url}: host region {host_region!r} and ?region= {query_region!r} disagree."
        )

    raw_template = seen.get("templateURL", "")
    if not raw_template:
        problems.append(
            f"{url}: no templateURL. It is REQUIRED -- the console cannot resolve a "
            "template without it."
        )
        return problems

    template_host = urllib.parse.urlsplit(raw_template).hostname or ""
    virtual_bucket = template_host.partition(".s3.")[0]
    if ".s3." in template_host and "." in virtual_bucket:
        problems.append(
            f"{url}: templateURL {raw_template!r} addresses bucket {virtual_bucket!r} "
            "virtual-hosted, but the name contains a period, so S3's wildcard "
            "certificate does not match it and the HTTPS fetch fails. Use the "
            "path-style form https://s3.<region>.amazonaws.com/<bucket>/<key>."
        )
        return problems

    if not any(pattern.match(raw_template) for pattern in S3_URL_PATTERNS):
        problems.append(
            f"{url}: templateURL {raw_template!r} is not one of the three S3 forms "
            "CloudFormation accepts. A GitHub raw URL does not work here."
        )
        return problems

    # Which stack this link launches, taken from the key rather than from the link text,
    # so a link whose label and target disagree is caught.
    key_basename = raw_template.rstrip("/").rsplit("/", 1)[-1]
    if not key_basename.endswith(".template.json"):
        problems.append(
            f"{url}: templateURL key {key_basename!r} does not end in '.template.json'."
        )
        return problems
    stack = key_basename[: -len(".template.json")]
    if stack not in stacks:
        problems.append(
            f"{url}: templateURL names stack {stack!r}, which has no committed template "
            f"under {TEMPLATE_DIR.relative_to(REPO_ROOT)}."
        )
        return problems

    stack_name = seen.get("stackName", "")
    if not STACK_NAME_RE.match(stack_name):
        problems.append(
            f"{url}: stackName {stack_name!r} is not a legal CloudFormation stack name "
            "(alphanumeric and hyphens, leading letter, at most 128 characters)."
        )

    params = stacks[stack]
    expected = dict(plan.get(stack, []))
    supplied = [key for key, _ in fields if key.startswith("param_")]

    for key in supplied:
        name = key[len("param_") :]
        spec = params.get(name)
        if spec is None:
            problems.append(
                f"{url}: param_{name} is not a parameter of {stack}. CloudFormation "
                "IGNORES an unknown param_ name silently, so this link deploys the "
                f"template's own default instead. Declared parameters: "
                f"{', '.join(sorted(params)) or '(none)'}."
            )
            continue
        if is_noecho(spec):
            problems.append(
                f"{url}: param_{name} is NoEcho on {stack}. CloudFormation ignores "
                "NoEcho parameters in a quick-create link, so the link claims to set "
                "something it cannot set."
            )
            continue
        if name not in expected:
            # Declared by the template, so the two checks above pass -- but not a name
            # this link is supposed to carry. The renderer emits exactly the plan, so an
            # extra one is a hand edit or a stale document, and its VALUE is unchecked by
            # anything: there is no declared default to compare it against. Rejecting is
            # what makes the module's claim that every value is derived actually hold,
            # rather than holding only for the planned names.
            problems.append(
                f"{url}: param_{name} is a real parameter of {stack} but not one this "
                "link is supposed to set. The plan for this stack is "
                f"{', '.join(sorted(expected)) or '(no parameters)'}. A generated link "
                "carries exactly the plan, so an extra parameter means the document was "
                "hand-edited; its value is checked by nothing."
            )
            continue
        if seen.get(key) != expected[name]:
            problems.append(
                f"{url}: param_{name} is {seen.get(key)!r} but {stack} declares the "
                f"default {expected[name]!r}. Every value in a generated link is copied "
                "from the template; a disagreement means the document was hand-edited "
                "or is stale."
            )

    missing = sorted(set(expected) - {key[len("param_") :] for key in supplied})
    if missing:
        carried = "it" if len(missing) == 1 else "them"
        problems.append(
            f"{url}: the plan prepopulates {', '.join(missing)} for {stack} but the "
            f"link does not carry {carried}. The document is stale; re-render it."
        )
    return problems


def render_tables(
    hosting: dict[str, Any],
    stacks: dict[str, dict[str, dict[str, Any]]],
    plan: dict[str, list[tuple[str, str]]],
) -> dict[str, str]:
    """The generated regions of the document."""
    bucket = str(hosting["bucket"])
    regions = [str(region) for region in hosting["launch_regions"]]

    link_rows = []
    for stack in sorted(stacks):
        if not bucket:
            cell = NO_LINK_PLACEHOLDER
        else:
            cell = " <br> ".join(
                f"[Launch in {region}]({quick_create_url(hosting, stack, region, plan[stack])})"
                for region in regions
            )
        required = required_without_default(stacks[stack])
        must_fill = ", ".join(f"`{name}`" for name in required) if required else "—"
        link_rows.append(f"| `{stack}` | {cell} | {must_fill} |")

    param_rows = []
    for stack in sorted(stacks):
        values = ", ".join(f"`{name}`=`{value}`" for name, value in plan[stack])
        param_rows.append(f"| `{stack}` | {values or '—'} |")

    config_name = HOSTING_CONFIG.name
    if not bucket:
        note = (
            "> **No links below, because ASH hosts no template bucket — by design.**\n"
            ">\n"
            "> A quick-create link requires `templateURL`, and CloudFormation accepts\n"
            "> only an S3 URL there; a GitHub raw URL will not work. ASH publishes these\n"
            "> templates to no bucket, for the same reason it publishes no container\n"
            "> image — see [Why there is no upstream\n"
            "> bucket](#why-there-is-no-upstream-bucket).\n"
            ">\n"
            f"> So the link column reads {NO_LINK_PLACEHOLDER} rather than an example\n"
            "> URL naming a bucket you do not control. This is the shipping state of\n"
            "> this file, not a gap waiting to be filled.\n"
            ">\n"
            "> **The links are for you to render.** Copy the templates to a bucket\n"
            f"> you own, set it in `{config_name}`, and re-render — {len(stacks)}\n"
            "> working links, in your account, for you to use or publish internally.\n"
            "> See [Rendering links for your own\n"
            "> bucket](#rendering-links-for-your-own-bucket). To launch without any of\n"
            "> that, `cdk/README.md` has the console and CLI paths."
        )
    else:
        prefix = str(hosting["key_prefix"]) or "(bucket root)"
        note = (
            f"Rendered against `s3://{bucket}/{str(hosting['key_prefix'])}` in "
            f"`{hosting['bucket_region']}`, set in `{config_name}`. Key prefix: "
            f"`{prefix}`.\n\n"
            "These links are specific to that bucket. They work for anyone who can read "
            "it, so they are yours to publish internally rather than something to send "
            "upstream.\n\n"
            "Following one opens the console's **Quick create stack** page with the "
            "template and the parameters below already filled in. You can change any of "
            "them, and change the region, before choosing **Create stack**."
        )

    return {
        "{{HOSTING_NOTE}}": note,
        "{{LAUNCH_LINK_TABLE}}": "\n".join(link_rows),
        "{{PREPOPULATED_PARAMETER_TABLE}}": "\n".join(param_rows),
    }


def render_text() -> tuple[str, list[str]]:
    """The document the committed inputs imply, without writing anything.

    Separate from `render` so a test can compare the committed file against a fresh
    render in memory. A test that called the writing path would repair the drift it was
    looking for and pass on the second run -- the same reasoning
    tests/unit/test_version_template_round_trip.py records for not invoking `generate`.
    """
    hosting = load_hosting()
    stacks = load_templates()
    plan, problems = parameter_plan(stacks)
    problems = hosting_problems(hosting) + problems
    if problems:
        return "", problems

    text = DOC_TEMPLATE.read_text(encoding="utf-8")
    for token, value in render_tables(hosting, stacks, plan).items():
        text = text.replace(token, value)

    # Any surviving {{...}} is a token this script does not know about. Writing it out
    # would produce a document that looks rendered and carries a literal placeholder.
    leftovers = sorted(
        {part.split("}}")[0] + "}}" for part in text.split("{{")[1:] if "}}" in part}
    )
    if leftovers:
        return "", [
            f"unsubstituted placeholder {token} would ship as literal text"
            for token in leftovers
        ]
    return text, []


def render(write: bool) -> int:
    text, problems = render_text()
    if problems:
        sys.stderr.write(
            "Refusing to render:\n" + "".join(f"  - {line}\n" for line in problems)
        )
        return 1

    if write:
        DOC_OUTPUT.write_text(text, encoding="utf-8")
        sys.stdout.write(f"rendered {_display(DOC_OUTPUT)}\n")
    else:
        sys.stdout.write(text)
    return 0


def check() -> int:
    """Verify the committed document against the committed templates."""
    hosting = load_hosting()
    stacks = load_templates()
    plan, problems = parameter_plan(stacks)
    problems = hosting_problems(hosting) + problems

    if not DOC_OUTPUT.exists():
        sys.stderr.write(
            f"{_display(DOC_OUTPUT)} does not exist. Run "
            "'python3 scripts/render_quick_create_links.py render'.\n"
        )
        return 1

    text = DOC_OUTPUT.read_text(encoding="utf-8")
    urls = CONSOLE_URL_RE.findall(text)
    for url in urls:
        problems.extend(validate_url(url, stacks, plan))

    bucket = str(hosting["bucket"])
    expected_urls = len(stacks) * len(hosting["launch_regions"]) if bucket else 0

    # The vacuous-pass guard. With no bucket configured there are no URLs to validate,
    # so "0 problems over 0 URLs" must not read as a link check that passed. The plan
    # assertions above are real in both modes and are what this reports instead.
    if len(urls) != expected_urls:
        problems.append(
            f"the document carries {len(urls)} console URL(s) but the configuration "
            f"implies {expected_urls}. Re-render it."
        )
    if bucket and not urls:
        problems.append(
            "a bucket is configured but the document carries no console URL, so "
            "nothing was validated."
        )
    if not bucket and NO_LINK_PLACEHOLDER not in text:
        problems.append(
            f"no bucket is configured but {NO_LINK_PLACEHOLDER} is absent from the "
            "document, so it does not say the links are unavailable."
        )

    total_assertions = sum(len(pairs) for pairs in plan.values())
    mode = (
        f"bucket configured ({bucket})"
        if bucket
        else "placeholder -- no bucket configured, which is this repository's default"
    )
    sys.stdout.write(
        f"mode: {mode}\n"
        f"templates: {len(stacks)} ({', '.join(sorted(stacks))})\n"
        f"parameter assertions in the plan: {total_assertions}\n"
        f"console URLs validated: {len(urls)}\n"
    )
    if not bucket:
        # Worth stating every run, because 0 URLs at exit 0 is byte-identical to what a
        # validator that had stopped working would report. The wording deliberately does
        # not call this mode temporary: ASH hosts no template bucket by design, so the
        # committed document carries no URLs indefinitely and this is the normal path
        # rather than an interim one.
        sys.stdout.write(
            "NOTE: 0 URLs is the correct result here and is NOT a link check that "
            "passed -- there are no links in the committed document to check, because "
            "ASH hosts no template bucket. The parameter plan above WAS verified "
            "against every template's Parameters block, and the link validator itself "
            "is covered by --self-test. Point quick-create-hosting.json at your own "
            "bucket and re-run to validate real URLs.\n"
        )

    if problems:
        sys.stderr.write(
            "\nquick-create link check FAILED:\n"
            + "".join(f"  - {line}\n" for line in problems)
        )
        return 1
    sys.stdout.write("every param_ name matches a declared, non-NoEcho parameter.\n")
    return 0


def self_test() -> int:
    """Prove the validator rejects the failures it exists to catch.

    Without this, `check` reporting no problems would be indistinguishable from `check`
    being unable to report a problem at all.
    """
    stacks = load_templates()
    plan, problems = parameter_plan(stacks)
    if problems:
        sys.stderr.write(
            "self-test cannot run: the parameter plan is already broken.\n"
            + "".join(f"  - {line}\n" for line in problems)
        )
        return 1

    hosting = {
        "bucket": "example-bucket",
        "bucket_region": "us-east-1",
        "key_prefix": "",
        "launch_regions": ["us-east-1"],
    }
    stack = "AshAgentCore"
    if stack not in stacks:
        sys.stderr.write(f"self-test needs {stack}, which is not committed.\n")
        return 1
    good = quick_create_url(hosting, stack, "us-east-1", plan[stack])

    # The stale-value case is built from the plan's own AshVersion default, never a
    # literal. `cz bump` rewrites that default, and a case naming today's version would
    # plant nothing after the bump and report a correct link as an accepted defect.
    planned = dict(plan[stack])
    if "AshVersion" not in planned:
        sys.stderr.write(
            f"self-test needs {stack} to plan AshVersion, and it does not.\n"
        )
        return 1
    current_version = planned["AshVersion"]
    stale_version = "v0.0.0" if current_version != "v0.0.0" else "v0.0.1"
    current_pair = f"param_AshVersion={urllib.parse.quote(current_version, safe='')}"
    stale_pair = f"param_AshVersion={urllib.parse.quote(stale_version, safe='')}"

    # Each case is (name, url, substring the rejection must mention). The substring is
    # checked so that a case cannot pass by being rejected for an unrelated reason.
    cases: list[tuple[str, str, str]] = [
        (
            "misspelled parameter name",
            good + f"&param_AshVerison={current_version}",
            "not a parameter",
        ),
        (
            "NoEcho parameter",
            good + "&param_McpAuthHeaderValue=hunter2",
            "NoEcho",
        ),
        (
            "value disagreeing with the template default",
            good.replace(current_pair, stale_pair),
            "declares the default",
        ),
        (
            "GitHub raw templateURL",
            quick_create_url(hosting, stack, "us-east-1", plan[stack]).replace(
                urllib.parse.quote(template_url(hosting, stack), safe=""),
                urllib.parse.quote(
                    "https://raw.githubusercontent.com/awslabs/"
                    "automated-security-helper/main/deploy/cdk/templates/"
                    f"{stack}.template.json",
                    safe="",
                ),
            ),
            "not one of the three S3 forms",
        ),
        (
            "dotted bucket addressed virtual-hosted",
            good.replace(
                urllib.parse.quote(template_url(hosting, stack), safe=""),
                urllib.parse.quote(
                    f"https://my.dotted.bucket.s3.us-east-1.amazonaws.com/"
                    f"{stack}.template.json",
                    safe="",
                ),
            ),
            "contains a period",
        ),
        (
            "illegal stack name",
            good.replace(f"stackName={stack}", "stackName=9 bad name"),
            "not a legal CloudFormation stack name",
        ),
        # A parameter the template really declares, but that the plan does not include.
        # This one passes the unknown-name and NoEcho checks, so before it was added a
        # hand edit could put an arbitrary value in a committed link and be accepted --
        # its value has no declared default to be compared against.
        (
            "declared parameter outside the plan",
            good + "&param_KmsKeyArn=arn:aws:kms:us-east-1:111111111111:key/whatever",
            "not one this link is supposed to set",
        ),
    ]

    failures: list[str] = []

    # The negative control for the positive control: a validator that rejected
    # everything would pass every case above and be useless.
    accepted = validate_url(good, stacks, plan)
    if accepted:
        failures.append(
            "a correctly generated link was REJECTED, so the cases below prove nothing: "
            + "; ".join(accepted)
        )
    else:
        sys.stdout.write("control: a correctly generated link is accepted\n")

    for name, url, expected_substring in cases:
        if url == good:
            failures.append(
                f"{name}: the case is identical to the correct link, so it plants no "
                "defect. Its replacement target is no longer in the generated link."
            )
            continue
        found = validate_url(url, stacks, plan)
        if not found:
            failures.append(
                f"{name}: ACCEPTED, but it must be rejected. CloudFormation would "
                "silently ignore it and the adopter would deploy the wrong thing."
            )
            continue
        if not any(expected_substring in line for line in found):
            failures.append(
                f"{name}: rejected, but for the wrong reason -- no message mentioned "
                f"{expected_substring!r}. Got: {'; '.join(found)}"
            )
            continue
        sys.stdout.write(f"rejected as required: {name}\n")

    # The classification controls, which exercise parameter_plan rather than validate_url.
    #
    # The first is the case that used to misdiagnose itself: a new target declaring none of
    # the prepopulated parameters, which is what a stack consuming a prebuilt image URI
    # looks like. It must be reported as UNCLASSIFIED, naming the decision -- not as the
    # per-stack floor, whose message blamed the Parameters block and invited deleting the
    # guard.
    unclassified_name = "AshSelfTestUnclassifiedTarget"
    probe = dict(stacks)
    probe[unclassified_name] = {
        "SomeClusterName": {"Type": "String"},
        "SomeImageUri": {"Type": "String"},
    }
    _, probe_problems = parameter_plan(probe)
    about = [p for p in probe_problems if unclassified_name in p]
    if not about:
        failures.append(
            "an unclassified template was ACCEPTED. A template nobody classified would be "
            "advertised with no parameters, or trip the floor with a message naming the "
            "wrong cause."
        )
    elif not any("does not classify" in p for p in about):
        failures.append(
            "an unclassified template was rejected, but not as unclassified -- the "
            f"message must name the decision. Got: {'; '.join(about)}"
        )
    else:
        sys.stdout.write("rejected as required: unclassified template\n")

    # The other direction: a stack parked in WITHOUT_PREPOPULATED that does declare them
    # would silently drop parameters adopters are told to pin.
    misclassified = {stack: dict(params) for stack, params in stacks.items()}
    saved = STACK_CLASSES.get(stack)
    try:
        STACK_CLASSES[stack] = WITHOUT_PREPOPULATED
        _, mis_problems = parameter_plan(misclassified)
        if not any("Reclassify it as" in p for p in mis_problems):
            failures.append(
                f"{stack} classified {WITHOUT_PREPOPULATED} while declaring "
                "prepopulated parameters was ACCEPTED; its link would omit them silently."
            )
        else:
            sys.stdout.write("rejected as required: misclassified stack\n")
    finally:
        if saved is None:
            STACK_CLASSES.pop(stack, None)
        else:
            STACK_CLASSES[stack] = saved

    if failures:
        sys.stderr.write(
            "\nself-test FAILED:\n" + "".join(f"  - {line}\n" for line in failures)
        )
        return 1
    sys.stdout.write(
        f"self-test passed: {len(cases)} link rejection(s), 2 classification "
        "rejection(s), plus 1 control\n"
    )
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "action",
        choices=["render", "check", "print"],
        help=(
            "render: write the document. print: render to stdout without writing. "
            "check: verify the committed document against the committed templates."
        ),
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="prove the validator rejects a malformed link, and check nothing else",
    )
    args = parser.parse_args(argv[1:])

    if args.self_test:
        return self_test()
    if args.action == "check":
        return check()
    return render(write=args.action == "render")


if __name__ == "__main__":
    sys.exit(main(sys.argv))
