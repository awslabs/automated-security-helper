#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Offline mode is described as what it is: an image setting, not a network control.

Why this file exists
--------------------
``AshOfflineMode`` (Terraform: ``ash_offline_mode``) builds the image with the
Dockerfile's ``OFFLINE=YES`` and sets ``ASH_OFFLINE``, so scanner databases and rulesets
are baked in and ASH does not fetch them at scan time. It changes nothing about where
the workload can connect. The CDK Fargate task keeps TCP 443 egress to any address
through a NAT gateway, AgentCore runs in PUBLIC network mode, the CodeBuild projects
have no VPC, and the Terraform Fargate module allows all egress. So the descriptions
call offline mode an image setting and point at VPC placement for egress; phrases such
as "need no network egress" and "cannot reach out from inside your account" are
rejected.

The descriptions state the limit rather than offline mode imposing one: restricting
egress per target needs VPC
endpoints (an hourly charge per endpoint per Availability Zone) and a network layout
these templates cannot choose for an adopter, and the gate's opt-in VPC placement
already exists for operators who want it.

What is checked: every parameter description of offline mode (the five committed CDK
templates, every Terraform module's variable) and every README paragraph or table row
that mentions it. The committed templates are checked rather than the TypeScript,
because they are what an adopter launches; ``synth-templates.sh --check`` keeps them
equal to the source.
"""

from __future__ import annotations

import json
import pathlib
import re
from typing import Iterator, List, Tuple

import pytest

from tests.utils.helpers import iter_repo_files

pytestmark = pytest.mark.unit

REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]
DEPLOY = REPO_ROOT / "deploy"
CDK_TEMPLATES = DEPLOY / "cdk" / "templates"

#: Statements that the network is restricted. Each matched a real sentence on the base.
NETWORK_CLAIM = re.compile(
    r"no network egress"
    r"|needs? no network"
    r"|cannot reach out"
    r"|without (?:any )?network egress"
    r"|no egress at scan time",
    re.IGNORECASE,
)

_MENTIONS_OFFLINE = re.compile(r"AshOfflineMode|ash_offline_mode", re.IGNORECASE)


def _readme_passages() -> Iterator[Tuple[str, str]]:
    """Paragraphs and table rows of every deploy README that mention offline mode."""
    # Pruned as it walks: deploy/cdk/node_modules is installed per run.
    for path in sorted(
        p
        for p in iter_repo_files(
            DEPLOY, skip_dirs=frozenset({"node_modules", ".terraform"})
        )
        if p.suffix == ".md"
    ):
        text = path.read_text(encoding="utf-8")
        passages: List[str] = []
        current: List[str] = []
        for line in text.splitlines():
            if line.startswith("|"):
                if current:
                    passages.append(" ".join(current))
                    current = []
                passages.append(line)
            elif line.strip() == "":
                if current:
                    passages.append(" ".join(current))
                    current = []
            else:
                current.append(line.strip())
        if current:
            passages.append(" ".join(current))
        for passage in passages:
            if _MENTIONS_OFFLINE.search(passage):
                yield f"{path.relative_to(REPO_ROOT)}", passage


def _template_descriptions() -> Iterator[Tuple[str, str]]:
    templates = sorted(CDK_TEMPLATES.glob("*.template.json"))
    assert templates, f"no committed templates under {CDK_TEMPLATES}"
    for path in templates:
        parameters = json.loads(path.read_text(encoding="utf-8")).get("Parameters", {})
        assert "AshOfflineMode" in parameters, f"{path.name} declares no AshOfflineMode"
        yield path.name, parameters["AshOfflineMode"].get("Description", "")


_TF_OFFLINE_VARIABLE = re.compile(
    r'variable\s+"ash_offline_mode"\s*\{(?P<body>.*?)\n\}', re.DOTALL
)


def _terraform_descriptions() -> Iterator[Tuple[str, str]]:
    variable_files = sorted((DEPLOY / "terraform" / "modules").glob("*/variables.tf"))
    found = 0
    for path in variable_files:
        match = _TF_OFFLINE_VARIABLE.search(path.read_text(encoding="utf-8"))
        if match:
            found += 1
            yield str(path.relative_to(REPO_ROOT)), match.group("body")
    assert found >= 5, f"expected ash_offline_mode in every module, found {found}"


def test_the_claim_pattern_matches_a_claim_and_not_an_honest_description():
    """Positive and negative control on the instrument the tests below use."""
    assert NETWORK_CLAIM.search("Run ASH with no network egress at scan time.")
    assert NETWORK_CLAIM.search("so scans need no network egress.")
    assert NETWORK_CLAIM.search("and cannot reach out from inside your account.")
    assert not NETWORK_CLAIM.search(
        "Bakes scanner databases into the image so ASH does not fetch them at scan "
        "time. It does not restrict the network; place the workload in a VPC without "
        "a NAT path to do that."
    )


def test_the_passages_checked_are_found():
    """Not vacuous: the READMEs do describe offline mode, in more than one place."""
    assert len(list(_readme_passages())) >= 3


def test_no_offline_mode_description_claims_a_network_restriction():
    claims = [
        f"{where}: {text.strip()[:200]}"
        for where, text in (
            *_template_descriptions(),
            *_terraform_descriptions(),
            *_readme_passages(),
        )
        if NETWORK_CLAIM.search(text)
    ]
    assert claims == [], "\n".join(claims)
