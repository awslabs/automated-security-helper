# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The reusable scan workflow installs the tools of the scanners ASH enables by default.

Why this file exists
--------------------
actionlint, cfn-guard, gitleaks and trivy are builtin scanners, on by default, whose
tools ASH does not install for itself. ``.github/workflows/run-ash-security-scan.yml``
installs them in one step, "Install actionlint, cfn-guard, gitleaks and trivy", one
``install-*`` input per tool. Those inputs first shipped defaulting to false, so a caller
that upgraded ASH without adding them got four MISSING scanners in the default
``ash-mode: local``, and the incomplete-scan gate failed every run with nothing in the
caller's own change to explain it. They default to true instead, at the cost of the
download (about 180 MB for trivy and its database on 2026-10-11), which a caller that
does not need a tool turns off by setting its input to false.

The same held for the older install-grype, install-syft, install-opengrep and
install-cfn-nag inputs, which defaulted to false although grype, syft, opengrep and
cfn-nag are on by default too. Measured on 2026-10-11, a local-mode scan of a small
repository on a host without those tools reported all four MISSING and exited 1.
So every ``install-*`` input defaults to true.

What it checks
--------------
Every input that step reads defaults to true. The inputs are read from the step's own
``if:`` expression rather than listed here, so a tool added to that step is held to the
same default; the four names are also pinned, so a step that stopped being found could
not pass by checking nothing. Every ``install-*`` input of the workflow defaults to true,
names a scanner the default config enables, and says what it downloads and how to turn
it off.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SCAN_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "run-ash-security-scan.yml"
INSTALL_STEP = "Install actionlint, cfn-guard, gitleaks and trivy"


def _workflow() -> dict[str, Any]:
    return yaml.safe_load(SCAN_WORKFLOW.read_text(encoding="utf-8"))


def _inputs() -> dict[str, Any]:
    # PyYAML reads the bare key `on` as the boolean True.
    triggers = _workflow().get(True) or _workflow().get("on")
    return triggers["workflow_call"]["inputs"]


def _install_step() -> dict[str, Any]:
    found = [
        step
        for job in _workflow()["jobs"].values()
        for step in job.get("steps") or []
        if step.get("name") == INSTALL_STEP
    ]
    assert len(found) == 1, f"expected one step named {INSTALL_STEP!r}, found {found}"
    return found[0]


def _inputs_the_step_reads() -> list[str]:
    return sorted(
        set(re.findall(r"inputs\.(install-[a-z0-9-]+)", _install_step()["if"]))
    )


def test_the_install_step_reads_the_four_default_scanners_inputs() -> None:
    assert _inputs_the_step_reads() == [
        "install-actionlint",
        "install-cfn-guard",
        "install-gitleaks",
        "install-trivy",
    ]


def test_every_input_the_install_step_reads_defaults_to_true() -> None:
    inputs = _inputs()
    wrong = {
        name: inputs[name].get("default")
        for name in _inputs_the_step_reads()
        if inputs[name].get("default") is not True
    }
    assert not wrong, (
        "these install-* inputs of run-ash-security-scan.yml do not default to true, so "
        f"a caller that does not set them gets those scanners MISSING: {wrong}"
    )


def test_each_of_those_inputs_says_what_it_downloads_and_how_to_turn_it_off() -> None:
    inputs = _inputs()
    for name in _inputs_the_step_reads():
        description = inputs[name]["description"]
        assert "false" in description, (name, description)
    assert "MB" in inputs["install-trivy"]["description"]


def _install_inputs() -> dict[str, Any]:
    return {
        name: spec for name, spec in _inputs().items() if name.startswith("install-")
    }


def test_every_install_input_is_pinned() -> None:
    assert sorted(_install_inputs()) == [
        "install-actionlint",
        "install-cfn-guard",
        "install-cfn-nag",
        "install-gitleaks",
        "install-grype",
        "install-opengrep",
        "install-syft",
        "install-trivy",
    ]


def test_every_install_input_defaults_to_true_and_says_how_to_turn_it_off() -> None:
    wrong = {
        name: spec.get("default")
        for name, spec in _install_inputs().items()
        if spec.get("default") is not True
    }
    assert not wrong, wrong
    for name, spec in _install_inputs().items():
        assert "false" in spec["description"], (name, spec["description"])
        assert "MB" in spec["description"], (name, spec["description"])


def test_every_install_input_names_a_scanner_on_by_default() -> None:
    from automated_security_helper.config.default_config import get_default_config

    scanners = get_default_config().scanners
    enabled = {
        (field.alias or name)
        for name, field in type(scanners).model_fields.items()
        if getattr(getattr(scanners, name), "enabled", False)
    }
    named = {name.removeprefix("install-") for name in _install_inputs()}
    assert named <= enabled, named - enabled
