# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Builds ASFF findings from ASH results, for the offline export and Security Hub.

Shared by the built-in ``asff`` reporter, which writes the findings to a file, and
the ``aws-security-hub`` reporter in ``ash_aws_plugins``, which imports them. It sits
here, in the built-in package, so the built-in reporter never imports the opt-in AWS
package (that import registers the AWS reporters as a side effect). Nothing here
touches the network or needs AWS credentials, which is also why the partition of a
region is read from botocore's bundled data file rather than through a botocore
session.

``ProductFields`` carries ASH's own keys, ``ash/target`` through
``ash/packageVersion`` plus ``ash/correlationId``, the cross-scanner correlation
id (``utils/finding_identity``, "Correlation ids"). The correlation pair is
absent for a finding that carries none (SAST and IaC findings, and a secret or
dependency finding missing its family's key fields); the finding ``Id`` stays
the scanner-inclusive identity contract v2 hash, untouched.

The frame boundary
------------------

A run's results are projected on a polars frame, one row per result in the order
the runs list them (:func:`_derived`), and the Id de-duplication is a ``unique``
over a frame of the ids (:func:`_unique_by_id`). On the frame, from three columns
the host reads off each result (its severity, whether it is suppressed, whether
its rule id names a CVE): the severity label (a lookup, with ``INFORMATIONAL``
for a severity the table does not name), the finding type (a case-when), and
``RecordState`` and the ``ash/suppressed`` text (case-whens over the suppressed
flag). The Id de-duplication keeps the first row of each Id, as Security Hub does.

What stays on the host, a result at a time, is the text, and the nested document
built from it: the message with its fenced code removed, its first non-blank
line, the title and description sentences, the regular expression that tells a
CVE rule, the cut at each documented limit, whether a field is blank, and the
finding's nested ``Severity``, ``Resources``, ``FindingProviderFields`` and
``ProductFields`` objects with their documented field order. Text operations are
defined on characters: Python's ``len``, ``str.strip`` and a regular expression's
word boundary see a character as one unit, and polars strings are UTF-8, so a
column of them sees a multi-byte character as several. A frame holds text through
:func:`~automated_security_helper.utils.frame_text.wire` (a path or a message can
hold a lone surrogate, which a polars string cannot), which is one-to-one and
keeps equality and order but not a character count, a whitespace test or a word
boundary: a cut or a blank test run on such a column would differ from the text's
for non-ASCII input. And a finding is one JSON object, not a row, so building it
from its pieces has nothing to group, join or count.

``AsffFormatter._to_asff`` is the per-finding assembly and stays a static method
over one prepared result: the Security Hub reporter's tests wrap it to make a
finding botocore refuses.
"""

import functools
import hashlib
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, TYPE_CHECKING

from automated_security_helper.core.report_identity import ASFF_PRODUCT_NAME
from automated_security_helper.models.flat_vulnerability import FlatVulnerability
from automated_security_helper.utils.finding_identity import (
    CORRELATION_ID_PROPERTY,
    SECRET_CORRELATION_PREFIX,
    correlation_id,
    identity_keys,
    relative_path,
    relative_to_scan_root,
)
from automated_security_helper.utils.frame_text import wire
from automated_security_helper.utils.sarif_utils import (
    _resolve_result_severity,
    shared_correlation_ids,
)

if TYPE_CHECKING:
    import polars as pl

    from automated_security_helper.models.asharp_model import AshAggregatedResults
    from automated_security_helper.schemas.sarif_schema_model import Result


# Limits the findings are built on. Each is quoted from the AWS documentation page
# named beside it; none is from memory.
#
# https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_AwsSecurityFinding.html
#   Id, GeneratorId: "Maximum length of 512". Title: "Maximum length of 256".
#   Description: "Maximum length of 1024". ProductFields: "Can contain up to 50
#   key-value pairs. For each key-value pair, the key can contain up to 128
#   characters, and the value can contain up to 2048 characters."
#   SchemaVersion: "The value is 2018-10-08."
MAX_GENERATOR_ID_LENGTH = 512
MAX_TITLE_LENGTH = 256
MAX_DESCRIPTION_LENGTH = 1024
MAX_PRODUCT_FIELD_VALUE_LENGTH = 2048
ASFF_SCHEMA_VERSION = "2018-10-08"

# https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Severity.html
#   Original: "Maximum length of 64". Label valid values: INFORMATIONAL | LOW |
#   MEDIUM | HIGH | CRITICAL.
_ASFF_SEVERITY_LABELS = {
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFORMATIONAL",
}

# https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_Resource.html
#   Type: "If the resource does not match any of the provided types, then set Type
#   to Other." Id has no documented length limit; this reporter bounds it at the
#   ProductFields value length so the finding size stays bounded.
_RESOURCE_TYPE = "Other"
MAX_RESOURCE_ID_LENGTH = 2048

# https://docs.aws.amazon.com/securityhub/latest/userguide/asff-required-attributes.html
#   Types: "One or more finding types in the format of namespace/category/classifier".
_TYPE_VULNERABILITY = "Software and Configuration Checks/Vulnerabilities"
_TYPE_CVE = "Software and Configuration Checks/Vulnerabilities/CVE"
_CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

# Set on every finding so the Security Hub console and filters name ASH instead of
# the "Personal" / "Default" a custom integration otherwise shows. The ASFF page
# for CompanyName and ProductName: "You cannot update this attribute with
# BatchImportFindings or BatchUpdateFindings. The exception to this is a custom
# integration."
PRODUCT_NAME = ASFF_PRODUCT_NAME
COMPANY_NAME = "AWS Labs"

# An ISO 8601 timestamp, split so it can be rewritten into the forms
# datetime.fromisoformat accepts on Python 3.10: no "Z", and a fraction of exactly
# 3 or 6 digits. Security Hub returns "2026-01-15T12:00:00.000Z".
_ISO_TIMESTAMP = re.compile(
    r"^(?P<head>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})"
    r"(?:\.(?P<fraction>\d+))?"
    r"(?P<zone>[Zz]|[+-]\d{2}:?\d{2})?$"
)

# A fenced code block in a finding message. FlatVulnerability reads one as the
# finding's code snippet, and snippets are not sent. An unterminated fence runs to
# the end of the message.
_FENCED_BLOCK = re.compile(r"```.*?(?:```|\Z)", re.DOTALL)


class AsffFormatError(RuntimeError):
    """The results cannot be turned into ASFF findings.

    The Security Hub reporter passes its own ``SecurityHubImportError`` to the
    formatter instead, so its callers keep catching that.
    """


class AsffFormatter:
    """ASFF findings for one set of results.

    ``offline`` is the export that runs where the scan's checkout may be gone: paths
    are compared with ``source_dir`` as spelled, never resolved on this host (see
    ``utils/finding_identity.py``), and the region's partition comes from
    ``partition_of``, by default botocore's bundled endpoint data. The Security Hub
    reporter passes its own partition lookup.

    ``reporter`` and ``error_type`` name the caller in a refusal, and ``nothing``
    says what did not happen ("nothing was sent", "nothing was written").
    """

    def __init__(
        self,
        target: str,
        scope: str | None,
        source_dir: str | Path | None,
        *,
        offline: bool = False,
        partition_of: Callable[[str], str] | None = None,
        reporter: str = "asff",
        nothing: str = "nothing was written",
        error_type: type[Exception] = AsffFormatError,
    ) -> None:
        self.target = target
        self.scope = scope
        self.source_dir = source_dir
        self.offline = offline
        self.partition_of = partition_of
        self.reporter = reporter
        self.nothing = nothing
        self.error_type = error_type

    def build_asff_findings(
        self, model: "AshAggregatedResults", *, account_id: str, region: str
    ) -> list[dict[str, Any]]:
        product_arn = _product_arn(
            region, account_id, partition=(self.partition_of or _offline_partition)
        )
        timestamp = _asff_timestamp(
            model.metadata.generated_at,
            reporter=self.reporter,
            nothing=self.nothing,
            error_type=self.error_type,
        )
        target = self.target
        model_project = _model_project(model)
        scope = self.scope
        source_dir = self.source_dir

        prepared: list[dict[str, Any]] = []
        for run in (model.sarif.runs if model.sarif else None) or []:
            tool_name = "unknown"
            if run.tool and run.tool.driver and run.tool.driver.name:
                tool_name = run.tool.driver.name
            for result in run.results or []:
                prepared.append(
                    self._prepare(
                        result,
                        tool_name=tool_name,
                        target=target,
                        model_project=model_project,
                        source_dir=source_dir,
                    )
                )

        keys = identity_keys(
            [entry["identity"] for entry in prepared], default_project=model_project
        )
        # The cross-scanner correlation id each result's flattened finding was
        # assigned at flatten time (models/flat_vulnerability
        # .assign_correlation_ids), read by the same positional pairing every
        # reporter uses (utils/sarif_utils.shared_correlation_ids): every
        # reporter of one run must export one value for one finding, so this
        # formatter never re-derives the key. Re-deriving here diverged from
        # the model's value twice: the per-result flatten had no run in hand,
        # so a scanner classified as SECRETS only by its run driver's tags lost
        # the pair, and the key was computed over the rebased identity while
        # the flatten keys the raw one. None (the pair omitted) at every
        # position when the flattening fails, as the other reporters leave it.
        if prepared:
            correlation_ids = shared_correlation_ids(
                model, [entry["result"] for entry in prepared]
            )
            for entry, correlation_id in zip(prepared, correlation_ids):
                entry["flat"].correlation_id = correlation_id
        for entry, derived in zip(prepared, _derived(prepared)):
            entry["derived"] = derived
        return [
            self._to_asff(
                entry,
                key=key,
                target=target,
                scope=scope,
                account_id=account_id,
                product_arn=product_arn,
                timestamp=timestamp,
            )
            for entry, key in zip(prepared, keys)
        ]

    def _prepare(
        self,
        result: "Result",
        *,
        tool_name: str,
        target: str,
        model_project: str | None,
        source_dir: str | Path | None,
    ) -> dict[str, Any]:
        flat = FlatVulnerability.from_sarif_result(result, tool_name, "UNKNOWN")
        identity = flat.identity
        if identity is None:
            raise self.error_type(
                f"{self.reporter}: the {tool_name} result "
                f"{flat.rule_id or 'unknown'} has no finding identity, so no "
                f"finding Id can be derived for it; {self.nothing}"
            )
        project = flat.workspace_project or model_project
        identity = relative_to_scan_root(
            identity, source_dir, resolve_root=not self.offline
        )
        return {
            "flat": flat,
            "result": result,
            "scanner": flat.scanner or tool_name,
            "rule_id": flat.rule_id or "unknown",
            "file_path": relative_path(
                flat.file_path, source_dir, resolve_root=not self.offline
            ),
            "project": project,
            "target_key": _target_key(target, project),
            "identity": identity,
            "message": _without_code_blocks(flat.description or ""),
            "severity": _resolve_result_severity(result),
            "is_cve": bool(_CVE_PATTERN.search(flat.rule_id or "unknown")),
        }

    @staticmethod
    def _to_asff(
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
        derived = entry["derived"]
        original = entry["severity"].upper()

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

        types = [derived["type"]]
        severity = {"Label": derived["label"], "Original": original}
        resource_id = f"{target_key}/{file_path}" if file_path else target_key

        product_fields = {
            "ash/target": target_key,
            "ash/scope": scope,
            "ash/scanner": scanner,
            "ash/ruleId": rule_id,
            "ash/severity": original,
            "ash/suppressed": derived["suppressed_text"],
            "ash/file": file_path,
            "ash/startLine": _str_or_none(flat.line_start),
            "ash/endLine": _str_or_none(flat.line_end),
            "ash/workspaceProject": project,
            "ash/suppressionJustification": (
                flat.suppression_justification if flat.is_suppressed else None
            ),
            "ash/packageName": flat.package_name,
            "ash/packageVersion": flat.package_version,
            # The cross-scanner correlation id (utils/finding_identity,
            # "Correlation ids"). The pair is omitted for a finding that
            # carries none, by the None filter below: an always-present key
            # would make every non-carrying finding "correlate" in a filter.
            CORRELATION_ID_PROPERTY: flat.correlation_id,
        }

        return {
            "SchemaVersion": ASFF_SCHEMA_VERSION,
            "Id": _finding_id(target, key),
            "ProductArn": product_arn,
            "GeneratorId": _truncate(
                f"ash/{scanner}/{rule_id}", MAX_GENERATOR_ID_LENGTH
            ),
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
            "RecordState": derived["record_state"],
        }


def _derived_schema() -> dict[str, Any]:
    """The declared shape of the frame :func:`_derived` reads: the prepared
    severity, the finding's ``is_suppressed`` (the model field's name) and
    whether its rule names a CVE. The drift gate pins the built frame against
    this dict."""
    import polars as pl

    return {
        "severity": pl.String,
        "is_suppressed": pl.Boolean,
        "is_cve": pl.Boolean,
    }


def _derived_frame(prepared: list[dict[str, Any]]) -> "pl.DataFrame":
    """One row per entry of *prepared*, in order, as :func:`_derived_schema`."""
    import polars as pl

    return pl.DataFrame(
        {
            "severity": [wire(entry["severity"]) for entry in prepared],
            "is_suppressed": [bool(entry["flat"].is_suppressed) for entry in prepared],
            "is_cve": [entry["is_cve"] for entry in prepared],
        },
        schema=_derived_schema(),
    )


def _derived(prepared: list[dict[str, Any]]) -> list[dict[str, str]]:
    """What a result's severity and two flags give, for every result at once.

    One row per entry of *prepared*, in order, with the severity ``label``, the
    finding ``type``, the ``record_state`` and the ``suppressed_text`` the finding
    carries. All four are ASCII constants or keys, so ``wire`` leaves them as
    they are.
    """
    if not prepared:
        return []
    import polars as pl

    frame = _derived_frame(prepared)
    suppressed = pl.col("is_suppressed")
    return frame.select(
        # A severity the table does not name is informational.
        pl.col("severity")
        .replace_strict(_ASFF_SEVERITY_LABELS, default="INFORMATIONAL")
        .alias("label"),
        pl.when(pl.col("is_cve"))
        .then(pl.lit(_TYPE_CVE))
        .otherwise(pl.lit(_TYPE_VULNERABILITY))
        .alias("type"),
        pl.when(suppressed)
        .then(pl.lit("ARCHIVED"))
        .otherwise(pl.lit("ACTIVE"))
        .alias("record_state"),
        pl.when(suppressed)
        .then(pl.lit("true"))
        .otherwise(pl.lit("false"))
        .alias("suppressed_text"),
    ).to_dicts()


def _target_key(target: str, project: str | None) -> str:
    """The scan target, with a workspace project's key when it adds anything."""
    return target if not project or project == target else f"{target}/{project}"


def _model_project(model: "AshAggregatedResults") -> str | None:
    project = getattr(model.metadata, "workspace_project", None)
    return project if isinstance(project, str) and project.strip() else None


def _without_code_blocks(message: str) -> str:
    """``message`` with every fenced code block removed."""
    stripped = _FENCED_BLOCK.sub("", message)
    return re.sub(r"\n{3,}", "\n\n", stripped).strip()


def _parse_timestamp(value: Any) -> datetime | None:
    """An ISO 8601 timestamp as an aware datetime, on every supported Python.

    Python 3.10's ``datetime.fromisoformat`` accepts neither a trailing ``Z`` nor
    a fraction of other than 3 or 6 digits, and GetFindings returns
    ``2026-01-15T12:00:00.000Z``. Both are rewritten first: ``Z`` to ``+00:00``,
    and the fraction padded or cut to 6 digits.
    """
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    match = _ISO_TIMESTAMP.match(text)
    if match:
        text = match["head"]
        if match["fraction"]:
            text += "." + (match["fraction"] + "000000")[:6]
        zone = match["zone"]
        if zone in ("Z", "z"):
            zone = "+00:00"
        elif zone and ":" not in zone:
            zone = f"{zone[:3]}:{zone[3:]}"
        text += zone or ""
    try:
        moment = datetime.fromisoformat(text)
    except ValueError:
        return None
    return moment if moment.tzinfo else moment.replace(tzinfo=timezone.utc)


def _unique_by_id(
    findings: list[dict[str, Any]],
) -> tuple[list[dict[str, Any]], int]:
    """Drop findings whose Id an earlier one has; return (kept, dropped count).

    Security Hub's guidance for custom products: "If the custom product sends
    multiple findings with the same finding ID, Security Hub CSPM only processes
    the first finding."
    (https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-custom-providers.html)
    Doing the same here keeps the counts in the receipt honest.
    """
    if not findings:
        return [], 0
    import polars as pl

    ids = pl.DataFrame(
        {
            "i": list(range(len(findings))),
            "id": [wire(finding["Id"]) for finding in findings],
        },
        schema={"i": pl.Int64, "id": pl.String},
    )
    first = ids.unique(subset="id", keep="first", maintain_order=True)["i"]
    kept = [findings[index] for index in first.to_list()]
    return kept, len(findings) - len(kept)


def _secret_correlation_id(target: str, key: dict[str, Any] | None) -> str | None:
    """``secret/<sha256>`` of the scan target and a secret's location key: the
    ``ash/correlationId`` of a secret detection, from the one registry every
    reporter reads (``utils/finding_identity.correlation_id``)."""
    return correlation_id(SECRET_CORRELATION_PREFIX, target, key)


def _finding_id(target: str, key: dict[str, Any]) -> str:
    """``ash/<sha256>`` of the scan target and the identity key; 68 characters.

    Identity contract v2: ``"ash/" + sha256(json.dumps([target, key],
    sort_keys=True))``, the hash the Security Hub reporter takes over the key
    ``utils/finding_identity.py`` defines.
    """
    canonical = json.dumps([target, key], sort_keys=True)
    return "ash/" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _scan_scope(model: "AshAggregatedResults") -> str | None:
    source = getattr(model.metadata, "scan_source", None)
    if not isinstance(source, str) or not source.strip():
        return None
    converted = any(
        "converted" in report
        for report in (getattr(model, "additional_reports", None) or {}).values()
        if isinstance(report, dict)
    )
    return f"source={source};converted={'yes' if converted else 'no'}"


@functools.lru_cache(maxsize=None)
def _offline_partition(region: str) -> str:
    """The AWS partition for ``region``, read from botocore's bundled endpoint data.

    The same answer as ``_partition`` in ``ash_aws_plugins/security_hub_reporter.py``
    (botocore's ``get_partition_for_region``: the first partition that lists the
    region or whose ``regionRegex`` matches it, else ``aws``), without importing
    botocore, so this module reaches no network library.
    """
    from importlib.resources import files

    data = json.loads(
        files("botocore").joinpath("data/endpoints.json").read_text(encoding="utf-8")
    )
    for partition in data["partitions"]:
        if region in partition["regions"]:
            return partition["partition"]
        pattern = partition.get("regionRegex")
        if pattern and region and re.compile(pattern).match(region):
            return partition["partition"]
    return "aws"


def _product_arn(
    region: str, account_id: str, *, partition: Callable[[str], str]
) -> str:
    """The account's default product ARN, for findings it imports itself.

    https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-custom-providers.html:
    "This product ARN has the following format:
    arn:aws:securityhub:<region>:<account-id>:product/<account-id>/default".
    """
    return (
        f"arn:{partition(region)}:securityhub:{region}:{account_id}:"
        f"product/{account_id}/default"
    )


def _asff_timestamp(
    value: str | None,
    *,
    reporter: str = "asff",
    nothing: str = "nothing was written",
    error_type: type[Exception] = AsffFormatError,
) -> str:
    """``value`` as ``YYYY-MM-DDTHH:MM:SS.mmmZ``, a form the API reference lists.

    https://docs.aws.amazon.com/securityhub/1.0/APIReference/Welcome.html#timestamps
    """
    moment = _parse_timestamp(value) if value else None
    if moment is None:
        # Refused rather than replaced with the current time: now is later than
        # any stored UpdatedAt, so an import stamped with it would overrule the
        # findings of every newer scan and archive what they reported.
        # ReportMetadata always sets generated_at, so this is reached only for
        # a hand-edited or foreign results file.
        raise error_type(
            f"{reporter}: the results' generated_at {value!r} is not an "
            "ISO 8601 timestamp, so the scan time that orders this import "
            f"against the findings already in Security Hub is unknown; {nothing}. "
            "Set metadata.generated_at in the results file to the "
            "time of the scan."
        )
    return (
        moment.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _str_or_none(value: int | None) -> str | None:
    return None if value is None else str(value)


def _truncate(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[: limit - 3] + "..."
