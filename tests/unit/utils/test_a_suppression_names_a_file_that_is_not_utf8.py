# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""A suppression names a file whose name is not UTF-8 the way a config can write it.

The finding names the file in its record form, the surrogate as the six characters
``\\udcNN`` (utils/undecodable_text.py), and that is how every report shows it. A
suppression for it can be written:

- as the report shows the name, the six characters (a YAML single-quoted string, or
  any string that escapes its backslash);
- as a YAML double-quoted or JSON escape, ``"\\udce9"``, which the loader reads as the
  surrogate the file name holds.

Each suppresses the file's finding and no other file's: the escape's backslash is not a
path separator there, so neither form reaches ``secr/udce9t.py``. suggest_suppression,
asked for the finding, gives a path that suppresses it in the same way.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from automated_security_helper.cli.mcp_tools import mcp_suggest_suppression
from automated_security_helper.config.resolve_config import load_config_file
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.core import AshSuppression
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.suppression_matcher import should_suppress_finding

# The constants below are file names that are not UTF-8.
if os.name == "nt":
    pytest.skip(
        "a file name that is not UTF-8 cannot exist on NTFS (names are UTF-16)",
        allow_module_level=True,
    )

pytestmark = pytest.mark.unit

ODD = os.fsdecode(b"secr\xe9t.py")
RECORDED = "secr\\udce9t.py"
#: Files a suppression for ODD must not reach: the escape's backslash read as a
#: separator, another surrogate, and the plain neighbor.
OTHERS = (
    "secr/udce9t.py",
    "secr\\udce8t.py",
    os.fsdecode(b"secr\xe8t.py"),
    "secret.py",
)


def _finding(file_path: str) -> FlatVulnerability:
    return FlatVulnerability(
        id=f"finding-{abs(hash(file_path))}",
        title="A secret",
        description="A secret-like line",
        severity="HIGH",
        scanner="scripted",
        scanner_type="SECRETS",
        rule_id="R1",
        file_path=file_path,
        line_start=3,
        line_end=3,
    )


def _suppressed(suppression: AshSuppression, file_path: str) -> bool:
    return should_suppress_finding(_finding(file_path), [suppression])[0]


@pytest.mark.parametrize(
    "path",
    [RECORDED, f"**/{RECORDED}", ODD, f"**/{ODD}"],
    ids=["as-reported", "as-reported-recursive", "escape", "escape-recursive"],
)
def test_a_suppression_for_the_file_suppresses_it_and_no_other(path):
    suppression = AshSuppression(path=path, rule_id="R1", reason="reviewed")

    assert _suppressed(suppression, ODD)
    for other in OTHERS:
        # ascii(): a report holding a lone surrogate cannot be sent between workers.
        assert not _suppressed(suppression, other), ascii(other)


def test_control_a_plain_suppression_suppresses_its_file():
    suppression = AshSuppression(path="secret.py", rule_id="R1", reason="reviewed")

    assert _suppressed(suppression, "secret.py")
    assert not _suppressed(suppression, ODD)


@pytest.mark.parametrize(
    "written",
    ['"secr\\udce9t.py"', "'secr\\udce9t.py'"],
    ids=["yaml-double-quoted-escape", "yaml-single-quoted-as-reported"],
)
def test_a_suppression_read_from_a_config_file_suppresses_the_file(tmp_path, written):
    config = tmp_path / ".ash.yaml"
    config.write_text(
        "global_settings:\n"
        "  suppressions:\n"
        f"    - path: {written}\n"
        "      rule_id: R1\n"
        "      reason: reviewed\n",
        encoding="utf-8",
    )

    _, loaded = load_config_file(config)
    (suppression,) = loaded.global_settings.suppressions

    assert _suppressed(suppression, ODD)
    for other in OTHERS:
        assert not _suppressed(suppression, other), ascii(other)


def _results_file(tmp_path: Path) -> Path:
    """Saved results holding one finding in the file and one in its plain neighbor."""
    results = [
        Result(
            ruleId="R1",
            message=Message(text="A secret"),
            locations=[
                Location(
                    physicalLocation=PhysicalLocation(
                        artifactLocation=ArtifactLocation(uri=uri),
                        region=Region(startLine=3, endLine=3),
                    )
                )
            ],
            properties=PropertyBag(scanner_name="scripted"),
        )
        for uri in (ODD, "secret.py")
    ]
    model = AshAggregatedResults(
        sarif=SarifReport(
            runs=[
                Run(tool=Tool(driver=ToolComponent(name="scripted")), results=results)
            ]
        )
    )
    out = tmp_path / "out"
    model.save_model(out)
    return out / "ash_aggregated_results.json"


def test_suggest_suppression_gives_a_path_that_suppresses_the_file(tmp_path):
    results_file = _results_file(tmp_path)
    findings = AshAggregatedResults.model_validate_json(
        results_file.read_bytes()
    ).to_flat_vulnerabilities()
    (finding,) = [f for f in findings if f.file_path != "secret.py"]

    suggested = mcp_suggest_suppression(
        finding_id=finding.id, results_path=str(results_file)
    )

    assert suggested["success"] is True, suggested
    suppression = AshSuppression(**suggested["json"])
    assert should_suppress_finding(finding, [suppression])[0], ascii(suggested)
    for other in [f for f in findings if f is not finding]:
        assert not should_suppress_finding(other, [suppression])[0], ascii(other)
