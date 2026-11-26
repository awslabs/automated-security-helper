# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Characterization of the ASFF findings the formatter builds.

``AsffFormatter.build_asff_findings`` and ``_unique_by_id`` are pinned here in two
ways.

* Scenarios whose expected value is written by hand as a literal: the exact finding
  for one result, the field order, which ProductFields are left out, what is cut at
  the documented limits, and which of two results of one Id survives.
* A differential against ``_oracle_build`` and ``_oracle_unique_by_id``, verbatim
  copies of the per-finding loop and of the Id de-duplication as they stood before
  the mapping moved onto a frame. The oracle never changes: a red here means the
  change is not behavior-identical. It runs over seeded random runs built from small
  alphabets, so that colliding Ids, blank and whitespace-only text, fenced code,
  multi-byte text (whose length in characters differs from its length in bytes) and
  lone surrogates are the common case.

A golden is never edited to make a change pass.
"""

from __future__ import annotations

import json
import random
from typing import Any

import pytest

from automated_security_helper.config.ash_config import AshConfig
from automated_security_helper.config.default_config import get_default_config
from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.models.flat_vulnerability import (
    FlatVulnerability,
    correlation_id_for,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.asff_formatter import (
    ASFF_SCHEMA_VERSION,
    COMPANY_NAME,
    MAX_DESCRIPTION_LENGTH,
    MAX_GENERATOR_ID_LENGTH,
    MAX_PRODUCT_FIELD_VALUE_LENGTH,
    MAX_RESOURCE_ID_LENGTH,
    MAX_TITLE_LENGTH,
    PRODUCT_NAME,
    AsffFormatError,
    AsffFormatter,
    _ASFF_SEVERITY_LABELS,
    _CVE_PATTERN,
    _RESOURCE_TYPE,
    _TYPE_CVE,
    _TYPE_VULNERABILITY,
    _asff_timestamp,
    _finding_id,
    _model_project,
    _offline_partition,
    _product_arn,
    _str_or_none,
    _target_key,
    _truncate,
    _unique_by_id,
    _without_code_blocks,
)
from automated_security_helper.schemas.sarif_schema_model import (
    ArtifactLocation,
    Location,
    Message,
    PhysicalLocation,
    PhysicalLocation2,
    PropertyBag,
    Region,
    Result,
    Run,
    SarifReport,
    Suppression,
    Tool,
    ToolComponent,
)
from automated_security_helper.utils.finding_identity import (
    correlation_target,
    identity_keys,
    relative_path,
    relative_to_scan_root,
)
from automated_security_helper.utils.sarif_utils import _resolve_result_severity

pytestmark = pytest.mark.unit

AshConfig.model_rebuild()
AshAggregatedResults.model_rebuild()

ACCOUNT = "123456789012"
REGION = "us-east-1"
GENERATED_AT = "2026-01-15T12:00:00.000Z"


# ---------------------------------------------------------------------------
# The oracle: the formatter's per-finding loop before it moved onto a frame.
# ---------------------------------------------------------------------------


def _oracle_prepare(
    formatter: AsffFormatter,
    result: Any,
    *,
    tool_name: str,
    target: str,
    model_project: str | None,
    source_dir: Any,
    correlation_scope: str,
) -> dict[str, Any]:
    flat = FlatVulnerability.from_sarif_result(result, tool_name, "UNKNOWN")
    identity = flat.identity
    if identity is None:
        raise formatter.error_type(
            f"{formatter.reporter}: the {tool_name} result "
            f"{flat.rule_id or 'unknown'} has no finding identity, so no "
            f"finding Id can be derived for it; {formatter.nothing}"
        )
    project = flat.workspace_project or model_project
    identity = relative_to_scan_root(
        identity, source_dir, resolve_root=not formatter.offline
    )
    # The correlation id: the one deliberate extension of the oracle since it
    # was frozen, mirrored here the way the package fields were when they were
    # added. The formatter now reads the flatten-assigned id off the model
    # (utils/sarif_utils.shared_correlation_ids); the oracle keeps the
    # per-result spelling, whose value agrees on the differential's inputs
    # (no run-tag-only secret classification, no secret stored under an
    # absolute path with a scan root — the two shapes where the per-result
    # recomputation diverged, pinned in test_correlation_id_surfaces).
    flat.correlation_id = correlation_id_for(
        flat,
        target=correlation_scope,
        identity=identity,
        default_project=model_project,
    )
    return {
        "flat": flat,
        "result": result,
        "scanner": flat.scanner or tool_name,
        "rule_id": flat.rule_id or "unknown",
        "file_path": relative_path(
            flat.file_path, source_dir, resolve_root=not formatter.offline
        ),
        "project": project,
        "target_key": _target_key(target, project),
        "identity": identity,
        "message": _without_code_blocks(flat.description or ""),
    }


def _oracle_to_asff(
    entry: dict[str, Any],
    *,
    key: dict[str, Any],
    target: str,
    scope: str | None,
    account_id: str,
    product_arn: str,
    timestamp: str,
) -> dict[str, Any]:
    flat = entry["flat"]
    ash_severity = _resolve_result_severity(entry["result"])
    label = _ASFF_SEVERITY_LABELS.get(ash_severity, "INFORMATIONAL")
    original = ash_severity.upper()

    scanner = entry["scanner"]
    rule_id = entry["rule_id"]
    file_path = entry["file_path"]
    project = entry["project"]
    target_key = entry["target_key"]

    message = entry["message"]
    first_line = next(
        (line.strip() for line in message.splitlines() if line.strip()), ""
    )
    location = file_path or target_key
    if file_path and flat.line_start is not None:
        location = f"{file_path}:{flat.line_start}"
    title = f"{rule_id}: {first_line}" if first_line else rule_id
    description = (
        message if first_line else f"{scanner} reported {rule_id} at {location}"
    )

    types = [_TYPE_CVE if _CVE_PATTERN.search(rule_id) else _TYPE_VULNERABILITY]
    severity = {"Label": label, "Original": original}
    resource_id = f"{target_key}/{file_path}" if file_path else target_key

    product_fields = {
        "ash/target": target_key,
        "ash/scope": scope,
        "ash/scanner": scanner,
        "ash/ruleId": rule_id,
        "ash/severity": original,
        "ash/suppressed": "true" if flat.is_suppressed else "false",
        "ash/file": file_path,
        "ash/startLine": _str_or_none(flat.line_start),
        "ash/endLine": _str_or_none(flat.line_end),
        "ash/workspaceProject": project,
        "ash/suppressionJustification": (
            flat.suppression_justification if flat.is_suppressed else None
        ),
        "ash/packageName": flat.package_name,
        "ash/packageVersion": flat.package_version,
        "ash/correlationId": flat.correlation_id,
    }

    return {
        "SchemaVersion": ASFF_SCHEMA_VERSION,
        "Id": _finding_id(target, key),
        "ProductArn": product_arn,
        "GeneratorId": _truncate(f"ash/{scanner}/{rule_id}", MAX_GENERATOR_ID_LENGTH),
        "AwsAccountId": account_id,
        "Types": types,
        "CreatedAt": timestamp,
        "UpdatedAt": timestamp,
        "Severity": dict(severity),
        "Title": _truncate(title, MAX_TITLE_LENGTH),
        "Description": _truncate(description, MAX_DESCRIPTION_LENGTH),
        "Resources": [
            {
                "Type": _RESOURCE_TYPE,
                "Id": _truncate(resource_id, MAX_RESOURCE_ID_LENGTH),
            }
        ],
        "FindingProviderFields": {"Severity": dict(severity), "Types": list(types)},
        "ProductFields": {
            key: _truncate(value, MAX_PRODUCT_FIELD_VALUE_LENGTH)
            for key, value in product_fields.items()
            if isinstance(value, str) and value.strip()
        },
        "ProductName": PRODUCT_NAME,
        "CompanyName": COMPANY_NAME,
        "RecordState": "ARCHIVED" if flat.is_suppressed else "ACTIVE",
    }


def _oracle_build(
    formatter: AsffFormatter, model: AshAggregatedResults
) -> list[dict[str, Any]]:
    product_arn = _product_arn(
        REGION, ACCOUNT, partition=(formatter.partition_of or _offline_partition)
    )
    timestamp = _asff_timestamp(
        model.metadata.generated_at,
        reporter=formatter.reporter,
        nothing=formatter.nothing,
        error_type=formatter.error_type,
    )
    target = formatter.target
    model_project = _model_project(model)
    correlation_scope = correlation_target(
        getattr(model.metadata, "project_name", None)
    )
    prepared: list[dict[str, Any]] = []
    for run in (model.sarif.runs if model.sarif else None) or []:
        tool_name = "unknown"
        if run.tool and run.tool.driver and run.tool.driver.name:
            tool_name = run.tool.driver.name
        for result in run.results or []:
            prepared.append(
                _oracle_prepare(
                    formatter,
                    result,
                    tool_name=tool_name,
                    target=target,
                    model_project=model_project,
                    source_dir=formatter.source_dir,
                    correlation_scope=correlation_scope,
                )
            )
    keys = identity_keys(
        [entry["identity"] for entry in prepared], default_project=model_project
    )
    return [
        _oracle_to_asff(
            entry,
            key=key,
            target=target,
            scope=formatter.scope,
            account_id=ACCOUNT,
            product_arn=product_arn,
            timestamp=timestamp,
        )
        for entry, key in zip(prepared, keys)
    ]


def _oracle_unique_by_id(
    findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    seen: set[str] = set()
    kept: list[dict[str, Any]] = []
    for finding in findings:
        if finding["Id"] in seen:
            continue
        seen.add(finding["Id"])
        kept.append(finding)
    return kept, len(findings) - len(kept)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


def _result(
    rule: str | None = "R1",
    *,
    text: str | None = "found it",
    level: str | None = "error",
    uri: str | None = "src/app.py",
    start: int | None = 3,
    end: int | None = None,
    scanner: str | None = None,
    suppressed: str | None = None,
    package: tuple[str, str] | None = None,
    fingerprint: str | None = None,
) -> Result:
    props: dict[str, Any] = {}
    if scanner:
        props["scanner_name"] = scanner
    if package:
        props["package_name"], props["package_version"] = package
    kwargs: dict[str, Any] = {}
    if rule is not None:
        kwargs["ruleId"] = rule
    if level is not None:
        kwargs["level"] = level
    if text is not None:
        kwargs["message"] = Message(text=text)
    else:
        kwargs["message"] = Message(text="")
    if uri is not None:
        kwargs["locations"] = [
            Location(
                physicalLocation=PhysicalLocation(
                    root=PhysicalLocation2(
                        artifactLocation=ArtifactLocation(uri=uri),
                        region=(
                            Region(startLine=start, endLine=end)
                            if start is not None
                            else None
                        ),
                    )
                )
            )
        ]
    if suppressed is not None:
        kwargs["suppressions"] = [
            Suppression(kind="external", justification=suppressed)
        ]
    if fingerprint is not None:
        kwargs["fingerprints"] = {"k/v1": fingerprint}
    kwargs["properties"] = PropertyBag(**props)
    return Result(**kwargs)


def _model(
    runs: list[tuple[str | None, list[Result]]],
    *,
    generated_at: str = GENERATED_AT,
    project: str | None = None,
) -> AshAggregatedResults:
    model = AshAggregatedResults()
    model.ash_config = get_default_config()
    model.metadata.generated_at = generated_at
    if project is not None:
        model.metadata.workspace_project = project
    model.sarif = SarifReport(
        version="2.1.0",
        runs=[
            Run(
                tool=Tool(driver=ToolComponent(name=name))
                if name
                else Tool(driver=ToolComponent(name="x")),
                results=results,
                properties=PropertyBag(),
            )
            for name, results in runs
        ],
    )
    return model


def _formatter(
    scope: str | None = "source=/s;converted=no",
    *,
    root: str | None = None,
    target: str = "tgt",
) -> AsffFormatter:
    return AsffFormatter(target, scope, root, offline=True)


def _outcome(call) -> Any:
    try:
        return ("ok", call())
    except Exception as error:  # the type and text are part of the contract
        return ("raised", type(error).__name__, str(error))


def _dumped(value: Any) -> str:
    """The findings as the reporter writes them; order and escapes included."""
    return json.dumps(value)


def _both(formatter: AsffFormatter, model: AshAggregatedResults) -> tuple[Any, Any]:
    new = _outcome(
        lambda: _dumped(
            formatter.build_asff_findings(model, account_id=ACCOUNT, region=REGION)
        )
    )
    old = _outcome(lambda: _dumped(_oracle_build(formatter, model)))
    return new, old


# ---------------------------------------------------------------------------
# Scenarios with the expected value written out
# ---------------------------------------------------------------------------


def test_one_result_is_this_exact_finding():
    model = _model(
        [
            (
                "bandit",
                [_result("B101", text="assert used", scanner="bandit", level="note")],
            )
        ]
    )
    (finding,) = _formatter().build_asff_findings(
        model, account_id=ACCOUNT, region=REGION
    )
    assert list(finding) == [
        "SchemaVersion",
        "Id",
        "ProductArn",
        "GeneratorId",
        "AwsAccountId",
        "Types",
        "CreatedAt",
        "UpdatedAt",
        "Severity",
        "Title",
        "Description",
        "Resources",
        "FindingProviderFields",
        "ProductFields",
        "ProductName",
        "CompanyName",
        "RecordState",
    ]
    assert finding["SchemaVersion"] == "2018-10-08"
    assert finding["Id"].startswith("ash/") and len(finding["Id"]) == 68
    assert finding["ProductArn"] == (
        "arn:aws:securityhub:us-east-1:123456789012:product/123456789012/default"
    )
    assert finding["GeneratorId"] == "ash/bandit/B101"
    assert finding["AwsAccountId"] == ACCOUNT
    assert finding["Types"] == ["Software and Configuration Checks/Vulnerabilities"]
    assert finding["CreatedAt"] == finding["UpdatedAt"] == "2026-01-15T12:00:00.000Z"
    assert finding["Severity"] == {"Label": "LOW", "Original": "LOW"}
    assert finding["Title"] == "B101: assert used"
    assert finding["Description"] == "assert used"
    assert finding["Resources"] == [{"Type": "Other", "Id": "tgt/src/app.py"}]
    assert finding["FindingProviderFields"] == {
        "Severity": {"Label": "LOW", "Original": "LOW"},
        "Types": ["Software and Configuration Checks/Vulnerabilities"],
    }
    assert list(finding["ProductFields"]) == [
        "ash/target",
        "ash/scope",
        "ash/scanner",
        "ash/ruleId",
        "ash/severity",
        "ash/suppressed",
        "ash/file",
        "ash/startLine",
    ]
    assert finding["ProductFields"] == {
        "ash/target": "tgt",
        "ash/scope": "source=/s;converted=no",
        "ash/scanner": "bandit",
        "ash/ruleId": "B101",
        "ash/severity": "LOW",
        "ash/suppressed": "false",
        "ash/file": "src/app.py",
        "ash/startLine": "3",
    }
    assert finding["ProductName"] == "Automated Security Helper"
    assert finding["CompanyName"] == "AWS Labs"
    assert finding["RecordState"] == "ACTIVE"


def test_a_suppressed_cve_with_a_package_is_archived_and_typed_as_a_cve():
    model = _model(
        [
            (
                "grype",
                [
                    _result(
                        "CVE-2024-12345",
                        text="bad pkg",
                        scanner="grype",
                        level="error",
                        suppressed="reviewed",
                        package=("left-pad", "1.0.0"),
                        end=9,
                    )
                ],
            )
        ]
    )
    (finding,) = _formatter(scope=None).build_asff_findings(
        model, account_id=ACCOUNT, region=REGION
    )
    assert finding["Types"] == ["Software and Configuration Checks/Vulnerabilities/CVE"]
    assert finding["FindingProviderFields"]["Types"] == finding["Types"]
    assert finding["RecordState"] == "ARCHIVED"
    assert finding["Severity"] == {"Label": "CRITICAL", "Original": "CRITICAL"}
    fields = finding["ProductFields"]
    assert "ash/scope" not in fields
    assert fields["ash/suppressed"] == "true"
    assert fields["ash/suppressionJustification"] == "reviewed"
    assert fields["ash/packageName"] == "left-pad"
    assert fields["ash/packageVersion"] == "1.0.0"
    assert fields["ash/startLine"] == "3" and fields["ash/endLine"] == "9"


def test_an_empty_message_describes_the_finding_from_where_it_is():
    model = _model([("t", [_result("R9", text="", scanner="t")])])
    (finding,) = _formatter().build_asff_findings(
        model, account_id=ACCOUNT, region=REGION
    )
    assert finding["Title"] == "R9"
    assert finding["Description"] == "t reported R9 at src/app.py:3"


def test_fenced_code_is_left_out_and_the_first_non_blank_line_is_the_title():
    model = _model(
        [("t", [_result("R9", text="\n  \n  headline  \nmore\n```\nsecret\n```\n")])]
    )
    (finding,) = _formatter().build_asff_findings(
        model, account_id=ACCOUNT, region=REGION
    )
    assert finding["Title"] == "R9: headline"
    assert finding["Description"] == "headline  \nmore"


def test_the_limits_cut_in_characters_not_bytes():
    long_rule = "r" * 300
    wide = "é" * 700
    model = _model([("t", [_result(long_rule, text=wide)])])
    (finding,) = _formatter().build_asff_findings(
        model, account_id=ACCOUNT, region=REGION
    )
    assert len(finding["Title"]) == MAX_TITLE_LENGTH
    assert finding["Title"].endswith("...")
    assert len(finding["GeneratorId"]) <= MAX_GENERATOR_ID_LENGTH
    assert len(finding["Description"]) == 700 and finding["Description"] == wide
    model = _model([("t", [_result("R", text="é" * 1500)])])
    (finding,) = _formatter().build_asff_findings(
        model, account_id=ACCOUNT, region=REGION
    )
    assert len(finding["Description"]) == MAX_DESCRIPTION_LENGTH
    assert finding["Description"] == "é" * (MAX_DESCRIPTION_LENGTH - 3) + "..."
    assert all(
        len(value) <= MAX_PRODUCT_FIELD_VALUE_LENGTH
        for value in finding["ProductFields"].values()
    )


def test_an_unknown_severity_is_informational():
    assert _ASFF_SEVERITY_LABELS == {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFORMATIONAL",
    }
    for level, label in [("none", "INFORMATIONAL"), ("warning", "MEDIUM")]:
        model = _model([("t", [_result("R", level=level)])])
        (finding,) = _formatter().build_asff_findings(
            model, account_id=ACCOUNT, region=REGION
        )
        assert finding["Severity"]["Label"] == label, level


def test_a_lone_surrogate_in_a_message_survives_into_the_findings():
    model = _model(
        [("t", [_result("R\udcff", text="bad \udcff byte", uri="a/\udcfe.py")])]
    )
    new, old = _both(_formatter(), model)
    assert new == old
    assert new[0] == "ok"


def test_the_first_of_two_findings_with_one_id_is_kept_and_the_drops_are_counted():
    a = {"Id": "ash/1", "n": 1}
    b = {"Id": "ash/2", "n": 2}
    c = {"Id": "ash/1", "n": 3}
    d = {"Id": "ash/2", "n": 4}
    e = {"Id": "ash/3", "n": 5}
    kept, dropped = _unique_by_id([a, b, c, d, e])
    assert kept == [a, b, e] and dropped == 2
    assert kept[0] is a
    assert _unique_by_id([]) == ([], 0)


def test_a_result_without_an_identity_is_refused_by_the_callers_error():
    class Mine(RuntimeError):
        pass

    formatter = AsffFormatter(
        "tgt",
        None,
        None,
        offline=True,
        reporter="rep",
        nothing="none sent",
        error_type=Mine,
    )
    model = _model([("t", [_result("R")])])
    original = FlatVulnerability.identity
    try:
        FlatVulnerability.identity = property(lambda self: None)  # type: ignore[assignment]
        new = _outcome(
            lambda: formatter.build_asff_findings(
                model, account_id=ACCOUNT, region=REGION
            )
        )
        old = _outcome(lambda: _oracle_build(formatter, model))
    finally:
        FlatVulnerability.identity = original  # type: ignore[assignment]
    assert new == old
    assert new[0] == "raised" and new[1] == "Mine"
    assert "no finding identity" in new[2] and "none sent" in new[2]


def test_a_generated_at_that_is_not_a_time_is_refused_before_any_finding():
    model = _model([("t", [_result("R")])], generated_at="not a time")
    new, old = _both(_formatter(), model)
    assert new == old
    assert new[0] == "raised" and new[1] == "AsffFormatError"
    assert issubclass(AsffFormatError, RuntimeError)


def test_no_results_build_no_findings():
    for model in (_model([("t", [])]), _model([])):
        assert (
            _formatter().build_asff_findings(model, account_id=ACCOUNT, region=REGION)
            == []
        )


# ---------------------------------------------------------------------------
# The differential
# ---------------------------------------------------------------------------

_RULES = [
    "R1",
    "R2",
    "CVE-2024-12345",
    "cve-2023-0001x",
    "é-CVE-2024-12345",
    "",
    None,
    "r" * 300,
    "x\udcffy",
]
_TEXTS = [
    "found it",
    "",
    "   \n \n",
    "head\nbody",
    "\n\n  lead blank\nafter",
    "x```code```y",
    "pre\n```\nunterminated",
    "é" * 400,
    "é" * 1100,
    "ß ǅ ﬁ",
    "tab\tsep  line  ",
    "bad \udcff byte",
    "w" * 1500,
    "a\u0085b\n\u0085\nc",
]
_URIS = [
    "src/a.py",
    "src/b.py",
    "a/ü.py",
    "x/" + "d" * 2100 + ".py",
    "a/\udcfe.py",
    None,
]
_LEVELS = ["error", "warning", "note", "none", None]
_SCANNERS = [None, "bandit", "grype", "Étool"]
_JUST = [None, "ok", "   ", "é" * 2100, "a\u0085"]
_PACKAGES = [None, ("left-pad", "1.0.0"), ("é", "2")]
_LINES = [None, 1, 2, 9, 70000]
_FINGERPRINTS = [None, None, "f1", "f2"]
_PROJECTS = [None, "proj", "p/é"]
_SCOPES = [None, "source=/s;converted=no", "é" * 2100]
_TARGETS = ["tgt", "é", "t" * 40]
_ROOTS = [None, "/work", "/other"]


def _random_run(rng: random.Random) -> tuple[AshAggregatedResults, AsffFormatter]:
    runs = []
    for _ in range(rng.randint(1, 3)):
        results = []
        for _ in range(rng.randint(0, 7)):
            uri = rng.choice(_URIS)
            if uri and rng.random() < 0.3:
                uri = "/work/" + uri
            results.append(
                _result(
                    rng.choice(_RULES),
                    text=rng.choice(_TEXTS),
                    level=rng.choice(_LEVELS),
                    uri=uri,
                    start=rng.choice(_LINES),
                    end=rng.choice(_LINES),
                    scanner=rng.choice(_SCANNERS),
                    suppressed=rng.choice(_JUST),
                    package=rng.choice(_PACKAGES),
                    fingerprint=rng.choice(_FINGERPRINTS),
                )
            )
        runs.append((rng.choice([None, "bandit", "grype", "É"]), results))
    model = _model(runs, project=rng.choice(_PROJECTS))
    formatter = _formatter(
        rng.choice(_SCOPES), root=rng.choice(_ROOTS), target=rng.choice(_TARGETS)
    )
    return model, formatter


@pytest.mark.parametrize("seed", range(60))
def test_the_findings_equal_the_oracles_on_seeded_runs(seed):
    rng = random.Random(seed)
    for _ in range(4):
        model, formatter = _random_run(rng)
        new, old = _both(formatter, model)
        assert new == old
        if new[0] == "ok":
            built = json.loads(new[1])
            assert _unique_by_id(built) == _oracle_unique_by_id(built)


@pytest.mark.parametrize("seed", range(40))
def test_the_id_de_duplication_equals_the_oracles(seed):
    rng = random.Random(1000 + seed)
    ids = ["ash/a", "ash/b", "ash/é", "ash/\udcff", "ash/" + "c" * 60]
    findings = [
        {"Id": rng.choice(ids), "n": index} for index in range(rng.randint(0, 30))
    ]
    kept, dropped = _unique_by_id(findings)
    expected, expected_dropped = _oracle_unique_by_id(findings)
    assert kept == expected and dropped == expected_dropped
    assert all(a is b for a, b in zip(kept, expected))
