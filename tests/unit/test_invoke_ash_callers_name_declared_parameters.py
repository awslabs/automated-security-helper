# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Every ``Invoke-ASH`` call in the repository names only parameters it declares.

Why this file exists
--------------------
The run-scan-test action's community-config leg called
``Invoke-ASH ... -ConfigFile ".ash/.ash_community_plugins.yaml"``. ``Invoke-ASH``
(utils/ash_helpers.ps1) declares ``-Config``, not ``-ConfigFile``, and its last parameter
takes the remaining arguments, so PowerShell raised no error: ``-ConfigFile`` and the
path went into ``$AshArgs``, whose ``-c`` match also read as ``--no-color``, and the scan
ran without the community config the leg is named for.

What this asserts
-----------------
1. Each ``-Name`` an ``Invoke-ASH`` call in .github/ or the docs passes is a parameter
   ``Invoke-ASH`` declares, or a common parameter ``[CmdletBinding()]`` adds, by its full
   name. PowerShell binds an unambiguous prefix of a declared name to that parameter, but
   this test does not accept one: a call spells the full name. A name that is not a
   declared one, and not a prefix of one, falls into ``$AshArgs``.
2. The community-config leg passes ``-Config`` with a config file that exists.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
HELPERS = REPO_ROOT / "utils" / "ash_helpers.ps1"
RUN_SCAN_TEST = REPO_ROOT / ".github" / "actions" / "run-scan-test" / "action.yml"

# The common parameters [CmdletBinding()] gives every advanced function.
COMMON = {
    "verbose",
    "debug",
    "erroraction",
    "warningaction",
    "informationaction",
    "progressaction",
    "errorvariable",
    "warningvariable",
    "informationvariable",
    "outvariable",
    "outbuffer",
    "pipelinevariable",
}


def _declared() -> set[str]:
    text = HELPERS.read_text(encoding="utf-8")
    body = text[text.index("function Invoke-ASH") :]
    block = body[body.index("param(") : body.index("    begin {")]
    return {name.lower() for name in re.findall(r"^\s*\$(\w+)", block, re.MULTILINE)}


def _calls() -> list[tuple[str, int, str]]:
    sources = [
        *sorted((REPO_ROOT / ".github").rglob("*.yml")),
        *sorted((REPO_ROOT / "docs" / "content").rglob("*.md")),
        *sorted((REPO_ROOT / "docs" / "content").rglob("*.template")),
        REPO_ROOT / "README.md",
    ]
    found = []
    for path in sources:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            # `Get-Help Invoke-ASH -Full` passes -Full to Get-Help, not to Invoke-ASH.
            if re.search(r"(^|[\s;({|])Invoke-ASH\s+-", line) and not re.search(
                r"Get-(Help|Command)\s+Invoke-ASH", line
            ):
                found.append((str(path.relative_to(REPO_ROOT)), number, line))
    return found


def _parameter_names(line: str) -> list[str]:
    call = line[line.index("Invoke-ASH") :]
    unquoted = re.sub(r'"[^"]*"|\'[^\']*\'', '""', call)
    return re.findall(r"\s-([A-Za-z]\w*)", unquoted)


def test_every_call_names_only_declared_parameters():
    declared = _declared()
    assert {"config", "sourcedir", "outputdir", "ocirunner"} <= declared, declared
    calls = _calls()
    assert len(calls) >= 2, calls
    wrong = [
        f"{where}:{number}: -{name}"
        for where, number, line in calls
        for name in _parameter_names(line)
        if name.lower() not in declared | COMMON
    ]
    assert not wrong, (
        "these Invoke-ASH calls pass a parameter it does not declare; PowerShell puts it "
        "and its value into $AshArgs instead of binding it:\n" + "\n".join(wrong)
    )


def test_the_community_leg_passes_its_config_with_config():
    action = str(RUN_SCAN_TEST.relative_to(REPO_ROOT))
    lines = [
        line
        for where, _, line in _calls()
        if where == action and "ash_community_plugins" in line
    ]
    assert lines, "the community-config leg's Invoke-ASH call was not found"
    for line in lines:
        match = re.search(r"\s-Config\s+\"([^\"]+)\"", line)
        assert match, line
        assert (REPO_ROOT / match.group(1)).is_file(), match.group(1)
