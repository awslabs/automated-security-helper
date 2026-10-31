# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

from typing import Any, Literal, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.models.flat_vulnerability import (
    extract_workspace_project,
)
from automated_security_helper.models.workspace import SkippedProject
from automated_security_helper.plugin_modules.ash_builtin.reporters.workspace_skipped_rows import (
    skipped_project_detail,
    skipped_projects,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.schemas.ocsf.ocsf_vulnerability_finding import (
    AffectedCode,
    VulnerabilityFinding,
    Vulnerability,
    # Cve,
    Metadata,
    Product,
    FindingInfo,
    ActivityId,
    SeverityId,
    StatusId,
)
from automated_security_helper.schemas.sarif_schema_model import Result, Suppression
from automated_security_helper.utils.error_text import error_text
from automated_security_helper.utils.get_ash_version import get_ash_version
import json
import re
from datetime import datetime, timezone
import uuid
from typing import Dict, Optional, List, Tuple
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.sarif_utils import (
    is_not_a_finding,
    result_message_text,
    result_rule_id,
    result_scanner_name,
    shared_finding_ids,
    suppressions_in_effect,
)
from automated_security_helper.utils.severity_ladder import result_severity
from automated_security_helper.utils.undecodable_text import recorded

#: The longest ``finding_info.title`` this reporter writes, ellipsis included. The
#: cap was applied to the message part alone, so a long rule id and file name
#: pushed a title past it, and the ellipsis was added after a full-width slice.
TITLE_MAX_LENGTH = 120

#: Marks a record built by the fallback path: a finding whose construction
#: failed, kept with what could still be read of it (the gate's severity, the
#: project). Same ``key:value`` shape as the other labels, so a SIEM can set it
#: apart from a finding the builder read whole. Such records were counted as
#: successes, so the failure rate never reflected them. The label marks every
#: fallback, the whole-record one and the two inner ones (a ``Vulnerability``
#: or a ``FindingInfo`` the builder could not read); the inner ones carried
#: no mark, so the rate and the shortfall record left them out.
DEGRADED_FINDING_LABEL = "ash_row_type:degraded_finding"

#: The description of a ``Vulnerability`` built by its fallback: the rule id is
#: kept, the rest of the finding could not be read.
_FALLBACK_VULNERABILITY_DESC = "Error processing vulnerability details"

#: Marks the one record that stands for findings this array does not carry:
#: results whose construction and fallback both failed, and findings whose
#: serialization failed. They were dropped with a log line each and the array
#: looked complete; the record says how many are missing, so a reader of the
#: file alone learns it is incomplete.
CONVERSION_SHORTFALL_LABEL = "ash_row_type:conversion_shortfall"

#: The fixed part of the shortfall record's identity. Its ``finding_info.uid``
#: is derived (:func:`_finding_uid`) from this and the scanned project's
#: configured name, so a SIEM deduplicates the record across runs of one named
#: project and keeps differently named projects' records apart. The uid was
#: this string itself for every scan, so a SIEM that deduplicates on the uid
#: merged unrelated scans' shortfall records into one, which a later clean run
#: of any of them could never close. The name is the only identity the report
#: model carries: scans that keep the default project name share one record,
#: so set ``project_name`` in each repository's configuration to keep their
#: records apart.
CONVERSION_SHORTFALL_UID = "ash-ocsf-conversion-shortfall"

#: Splits a location uri on either separator: a Windows scanner can write a
#: drive-letter or UNC uri with backslashes, and splitting on "/" alone made
#: the whole path the file name and the title's "in <file>" part.
_PATH_SEPARATORS = re.compile(r"[\\/]")


def _file_name(path: str) -> str:
    """The last path component of *path*, whichever separator it uses."""
    parts = [part for part in _PATH_SEPARATORS.split(path) if part]
    return parts[-1] if parts else path


def _rule_descriptor(
    rule_id: Optional[str], rules: Optional[Dict[str, Any]] = None
) -> Any:
    """The descriptor of the rule *rule_id* names, from *rules* (rule ids to their
    descriptors, :func:`_rule_descriptors`), or None.

    A message given by ``id`` alone is resolved against it: SARIF reads such a
    message through the rule's ``messageStrings`` (3.11.10). Without the rule
    the result was titled "R1 - default", the key of the string rather than the
    string.

    *rule_id* is the id the caller already read from the result, under its own
    guard (None when the result names none, or the read failed). It is not read
    from the result again here: that read can raise, and this lookup runs inside
    the message-text handler, so a result whose rule id cannot be read lost its
    description as well.
    """
    return rules.get(rule_id) if rules and rule_id else None


def _rule_descriptors(sarif: Any) -> Dict[str, Any]:
    """Each rule id to the first descriptor declaring it, over every run's
    driver and extensions: what a message given by ``id`` is resolved against."""
    rules: Dict[str, Any] = {}
    for run in getattr(sarif, "runs", None) or []:
        tool = getattr(run, "tool", None)
        components = [getattr(tool, "driver", None)]
        components.extend(getattr(tool, "extensions", None) or [])
        for component in components:
            for rule in getattr(component, "rules", None) or []:
                rule_id = getattr(rule, "id", None)
                if isinstance(rule_id, str) and rule_id and rule_id not in rules:
                    rules[rule_id] = rule
    return rules


def _finding_title(rule_part: str, location_info: str, message_text: str) -> str:
    """The title ``<rule><location> - <message>`` at most :data:`TITLE_MAX_LENGTH`
    characters, the ellipsis counted, the prefix cut too when it alone is past
    the cap."""
    prefix = f"{rule_part}{location_info} - "
    whole = prefix + message_text
    if len(whole) <= TITLE_MAX_LENGTH:
        return whole
    room = TITLE_MAX_LENGTH - len(prefix) - 3
    if room > 0:
        return prefix + message_text[:room] + "..."
    return whole[: TITLE_MAX_LENGTH - 3] + "..."


#: OCSF severity_id for each ASH severity (OCSF: 1 Informational, 2 Low,
#: 3 Medium, 4 High, 5 Critical).
_OCSF_SEVERITY_ID = {
    "CRITICAL": SeverityId.integer_5,
    "HIGH": SeverityId.integer_4,
    "MEDIUM": SeverityId.integer_3,
    "LOW": SeverityId.integer_2,
    "INFO": SeverityId.integer_1,
}


#: Prefix for the ``metadata.labels`` entry carrying workspace attribution.
#: ``key:value`` is OCSF's conventional shape for a label, and the prefix is what
#: lets a SIEM query for it without matching a project name by accident.
WORKSPACE_PROJECT_LABEL_PREFIX = "workspace_project:"

#: Marks a record that stands for a skipped project rather than for a finding.
#: Same ``key:value`` shape as the project label, so one SIEM query form covers
#: both; a fixed string rather than a prefix because there is nothing per-record to
#: carry -- the project is already on its own label.
SKIPPED_PROJECT_LABEL = "ash_row_type:workspace_skipped_project"

#: The free-form ``status`` accompanying ``status_id`` 99. OCSF defines 99 as "not
#: mapped -- see the ``status`` attribute, which contains a data source specific
#: value", so this string is what that lookup is meant to find.
SKIPPED_PROJECT_STATUS = "Skipped"

#: Prefix for a skipped project's ``finding_info.uid``. Deterministic, unlike a
#: real finding's fresh uuid4, so a re-run of the same workspace produces the same
#: identifier and a SIEM deduplicates rather than accumulating one record per run
#: for a project that keeps being skipped.
SKIPPED_PROJECT_UID_PREFIX = "ash-workspace-skipped-project:"

#: The ``activity_name`` for ``activity_id`` 1 of the OCSF vulnerability_finding
#: class, whose activities are Unknown (0), Create (1), Update (2), Close (3) and
#: Other (99). Every record this reporter emits is the creation of a finding.
#: The name was "Scan", which is not an activity of the class, beside the id 1.
ACTIVITY_NAME = "Create"

#: A CVE identifier at the head of a rule id, the only value OCSF's ``cve.uid``
#: is defined to hold. Grype names its rules ``<CVE id>-<package>``
#: (``CVE-2022-40897-setuptools``), so the identifier is read off the front and
#: the package suffix is left behind; a scanner's own rule id (``B602``), or an
#: id that only contains a CVE id further in, carries no cve.
_CVE_ID = re.compile(r"^(CVE-\d{4}-\d{4,})(?:-|$)", re.IGNORECASE)

#: The namespace every finding's ``finding_info.uid`` is derived under. A uid was
#: a fresh uuid4 on every run, so the same finding reached a SIEM under a new
#: identifier each scan: the SIEM accumulated duplicates and could never update or
#: close one. A uuid5 over the finding's identity is a UUID (what consumers and the
#: existing tests expect) and the same across runs for the same finding.
_FINDING_UID_NAMESPACE = uuid.uuid5(
    uuid.NAMESPACE_URL, "https://github.com/awslabs/automated-security-helper/ocsf"
)


def _finding_uid(key: str) -> str:
    """The deterministic ``finding_info.uid`` for an identity *key*."""
    return str(uuid.uuid5(_FINDING_UID_NAMESPACE, key))


#: How a record describes a result whose message has nothing to read. The whole
#: record and the degraded one read the message with this default, so a result
#: with no message keys one finding, not two, whichever record is built.
_NO_DESCRIPTION = "No description"

#: Joins the parts of an identity key; a part's own separator is escaped.
_IDENTITY_SEPARATOR = "|"


def _identity_part(value: Any) -> str:
    """*value* as one part of an identity key.

    The separator and the escape are escaped inside a part, so that the parts
    ``("a|b", "c")`` and ``("a", "b|c")`` give two keys; joined raw they gave one.
    """
    return (
        str(value or "")
        .replace("\\", "\\\\")
        .replace(_IDENTITY_SEPARATOR, "\\" + _IDENTITY_SEPARATOR)
    )


def _scan_identity(model: Any) -> str:
    """The configured name of the scanned project: the report metadata's, else
    the configuration's, else "". Every read is guarded; a model this cannot
    read still gets a shortfall record, one shared by every such scan.

    The name is all the report model records of what was scanned (it holds no
    source directory or repository address), and its default is the same for
    every repository, so scans that keep the default share this identity."""
    for holder in (
        getattr(model, "metadata", None),
        getattr(model, "ash_config", None),
    ):
        name = getattr(holder, "project_name", None)
        if isinstance(name, str) and name.strip():
            return name.strip()
    return ""


def _shortfall_uid(scan_identity: str) -> str:
    """The shortfall record's uid for the project *scan_identity* names."""
    return _finding_uid(f"{scan_identity}|{CONVERSION_SHORTFALL_UID}")


def _identity_key(result: Any, rule_id: str, message_text: Optional[str] = None) -> str:
    """A finding's identity from the result alone: scanner, workspace project,
    rule, message, file and lines, each part escaped (:func:`_identity_part`).

    The fallback for a result the run-level flattening did not give an id (a
    direct call of the finding builder, or a model that cannot be flattened).
    Every read is guarded, because this is called on the error paths too.

    The scanner and the project are in the key because two scanners can fire
    one rule id at one line (grype and trivy on a CVE), and two workspace
    projects can each hold ``src/index.js`` with the same finding in it; keyed
    on the rule, message, file and lines alone, two such findings shared a uid
    and a SIEM merged them into one. Two results identical in every part are
    told apart by the report (:func:`_fallback_identities`).
    """
    parts: List[str] = [_identity_part(result_scanner_name(result) or "")]
    try:
        parts.append(_identity_part(extract_workspace_project(result)))
    except Exception:  # noqa: BLE001 -- see the docstring
        parts.append("")
    parts.append(_identity_part(rule_id))
    try:
        text = message_text
        if text is None:
            # The reading every report shares (text, else markdown, else the
            # message string's id), so a message given in markdown or by id
            # alone is told apart from another at the same site; read as
            # ``text`` alone, every such message was the same empty part.
            text = result_message_text(result, default="")
        parts.append(_identity_part(text))
    except Exception:  # noqa: BLE001 -- see the docstring
        parts.append("")
    try:
        for location in getattr(result, "locations", None) or []:
            physical = getattr(location, "physicalLocation", None)
            loc = getattr(physical, "root", physical)
            artifact = getattr(loc, "artifactLocation", None)
            region = getattr(loc, "region", None)
            parts.append(_identity_part(getattr(artifact, "uri", None)))
            parts.append(_identity_part(getattr(region, "startLine", None)))
            parts.append(_identity_part(getattr(region, "endLine", None)))
    except Exception:  # noqa: BLE001 -- see the docstring
        pass
    return _IDENTITY_SEPARATOR.join(parts)


def _fallback_identities(
    results: List[Any], shared_ids: List[Optional[str]]
) -> List[Optional[str]]:
    """The identity each result's uid is derived from when it has no shared id,
    and None where it has one.

    The identity is the result's :func:`_identity_key`; the second and later
    results of the report that give the same key carry an occurrence number, so
    two identical results in one run are two findings with two uids, as they are
    in every other report (the flattened id's occurrence counter), instead of one
    finding a SIEM sees twice and merges.

    A result that states no finding (:func:`is_not_a_finding`) is left out of the
    array, so it has no identity and takes no number: counted, it shifted the
    occurrence number of every identical finding after it when a rule stopped
    evaluating, and the uids of those findings changed with it.
    """
    seen: Dict[str, int] = {}
    identities: List[Optional[str]] = []
    for result, shared_id in zip(results, shared_ids):
        if shared_id or is_not_a_finding(result):
            identities.append(None)
            continue
        key = _identity_key(result, result_rule_id(result) or "Unknown Rule")
        count = seen.get(key, 0)
        seen[key] = count + 1
        if count:
            key = _IDENTITY_SEPARATOR.join([key, "occurrence", str(count)])
        identities.append(key)
    return identities


def _metadata_with_labels(metadata: Metadata, *labels: str) -> Metadata:
    """*metadata* with *labels* appended, as a copy.

    Copied rather than mutated in place: one ``Metadata`` instance is shared across
    every record in the report, so appending to its ``labels`` would give every
    record every other record's labels -- each one individually plausible, and the
    whole report useless for routing.

    Why ``labels`` and not a declared ``metadata`` field
    ---------------------------------------------------
    The RFC asked for the project "in metadata", and OCSF's ``Metadata`` sets
    ``extra="forbid"``. Worse than forbidding, pydantic's ``model_copy(update=...)``
    *silently drops* a key the schema does not declare -- so the obvious
    implementation would have produced findings with no attribution at all and no
    error to show for it. ``labels`` is the schema's own slot for free-form
    annotation, is indexed by SIEMs, and needs no schema extension.
    """
    existing = metadata.labels
    merged = list(existing) if isinstance(existing, list) else []
    for label in labels:
        if label not in merged:
            merged.append(label)
    return metadata.model_copy(update={"labels": merged})


def _metadata_for_project(metadata: Metadata, result: Result) -> Metadata:
    """*metadata* with this finding's workspace project recorded in ``labels``.

    Returns the shared object unchanged for a single-directory scan, so that
    output is byte-identical and no needless copies are made.
    """
    project = extract_workspace_project(result)
    if not project:
        return metadata
    return _metadata_with_labels(metadata, f"{WORKSPACE_PROJECT_LABEL_PREFIX}{project}")


class OCSFReporterConfigOptions(ReporterOptionsBase):
    pass


class OCSFReporterConfig(ReporterPluginConfigBase):
    name: Literal["ocsf"] = "ocsf"
    extension: str = "ocsf.json"
    enabled: bool = True
    options: OCSFReporterConfigOptions = OCSFReporterConfigOptions()


@ash_reporter_plugin
class OcsfReporter(ReporterPluginBase[OCSFReporterConfig]):
    """Formats results as an array of Open Cybersecurity Schema Framework (OCSF) VulnerabilityFinding objects.

    Workspace mode: one merged artefact, with the project carried in each
    finding's ``metadata``.

    ``metadata`` rather than ``resources`` or the finding title, because OCSF's
    ``Metadata`` object is where provenance belongs and a SIEM ingesting these
    can index on it without parsing a string. Each finding gets its own copy: the
    array is flat, an event is routed individually, and a project stated once at
    the top of the file would be lost the moment a consumer split the array --
    which is the normal way a SIEM ingests one.

    A skipped project gets one record of its own, because it has no findings and
    would otherwise be absent from this array in the one way a reader cannot
    notice. It is marked ``status_id`` 99 -- OCSF's "not mapped, see ``status``" --
    with ``status`` ``Skipped``, severity 1 (Informational), an empty
    ``vulnerabilities`` array, and a ``metadata.labels`` entry naming it a project
    record. See ``workspace_skipped_rows`` for why 99 rather than 3 (Suppressed) or
    0 (Unknown), and for what makes the record filterable.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.MERGED

    def model_post_init(self, context):
        if self.config is None:
            self.config = OCSFReporterConfig()
        return super().model_post_init(context)

    def _create_vulnerability_from_result(
        self, result: Result, rules: Optional[Dict[str, Any]] = None
    ) -> Vulnerability:
        """The ``Vulnerability`` for a SARIF result, whole or built by the
        fallback; :meth:`_build_vulnerability` says which."""
        return self._build_vulnerability(result, rules)[0]

    def _build_vulnerability(
        self, result: Result, rules: Optional[Dict[str, Any]] = None
    ) -> Tuple[Vulnerability, bool]:
        """Extract vulnerability data from SARIF result.

        Args:
            result: SARIF result object
            rules: rule ids to descriptors (:func:`_rule_descriptors`), for a
                message given by ``id``

        Returns:
            The Vulnerability object with data extracted from the SARIF result,
            and whether it was built by the fallback path (True) rather than
            read whole (False). The flag is what lets the record carry
            :data:`DEGRADED_FINDING_LABEL`; a fallback that returned the object
            alone was counted as a finding read whole.
        """
        rule_id = "Unknown Rule"
        named_rule: Optional[str] = None
        try:
            # Safely extract rule ID first for logging context
            try:
                named_rule = result_rule_id(result)
                rule_id = named_rule or rule_id
            except Exception as e:
                ASH_LOGGER.debug(f"Error extracting rule ID: {str(e)}")

            ASH_LOGGER.debug(
                f"Creating vulnerability from SARIF result for rule: {rule_id}"
            )

            # Safely extract message text
            desc = ""
            try:
                desc = result_message_text(
                    result, _rule_descriptor(named_rule, rules), default=""
                )
                ASH_LOGGER.debug(
                    f"Extracted message text for {rule_id}: {len(desc)} characters"
                )
            except Exception as e:
                ASH_LOGGER.debug(
                    f"Error extracting message text for {rule_id}: {str(e)}"
                )
                desc = "No description available"

            # The gate's severity (issue_severity, else the level, error being
            # CRITICAL), not the SARIF level ("ERROR").
            severity = result_severity(result)

            # Create vulnerability object with required fields
            vuln_dict = {
                "desc": desc,
                "title": rule_id,
                "severity": severity,
            }

            # Add a CVE only when the rule id is one. OCSF defines ``cve.uid``
            # as the CVE identifier; a scanner rule id (a bandit or checkov
            # rule) published there told a SIEM that every finding was a known
            # CVE. The rule id is the vulnerability's ``title`` either way.
            try:
                cve_match = _CVE_ID.match(rule_id) if rule_id else None
                if cve_match:
                    vuln_dict["cve"] = {
                        "uid": cve_match.group(1).upper(),
                        "desc": desc,
                    }
            except Exception as e:
                ASH_LOGGER.debug(f"Error creating CVE information: {str(e)}")

            # Add location information if available
            affected_code = []
            location_count = 0
            try:
                if result.locations and len(result.locations) > 0:
                    location_count = len(result.locations)
                    ASH_LOGGER.debug(
                        f"Processing {location_count} locations for {rule_id}"
                    )

                    for i, location in enumerate(result.locations):
                        try:
                            if (
                                location.physicalLocation
                                and location.physicalLocation.root
                            ):
                                loc = location.physicalLocation.root

                                # Safely extract file path
                                file_path = None
                                try:
                                    if (
                                        loc.artifactLocation
                                        and loc.artifactLocation.uri
                                    ):
                                        file_path = loc.artifactLocation.uri
                                        ASH_LOGGER.debug(
                                            f"Extracted file path for {rule_id} location {i}: {file_path}"
                                        )
                                except Exception as e:
                                    ASH_LOGGER.debug(
                                        f"Error extracting file path for {rule_id} location {i}: {str(e)}"
                                    )
                                    continue

                                if file_path:
                                    try:
                                        file_name = _file_name(file_path)

                                        file_dict = {
                                            "name": file_name,
                                            "path": file_path,
                                            "type_id": 1,  # Regular file
                                        }

                                        code_dict = {"file": file_dict}

                                        # Safely extract region information
                                        try:
                                            if loc.region:
                                                if (
                                                    hasattr(loc.region, "startLine")
                                                    and loc.region.startLine
                                                ):
                                                    code_dict["start_line"] = (
                                                        loc.region.startLine
                                                    )
                                                    ASH_LOGGER.debug(
                                                        f"Extracted start line for {rule_id} location {i}: {loc.region.startLine}"
                                                    )
                                                if (
                                                    hasattr(loc.region, "endLine")
                                                    and loc.region.endLine
                                                ):
                                                    code_dict["end_line"] = (
                                                        loc.region.endLine
                                                    )
                                                    ASH_LOGGER.debug(
                                                        f"Extracted end line for {rule_id} location {i}: {loc.region.endLine}"
                                                    )
                                        except Exception as e:
                                            ASH_LOGGER.debug(
                                                f"Error extracting region info for {rule_id} location {i}: {str(e)}"
                                            )

                                        # Validated one entry at a time: the
                                        # whole Vulnerability was validated at
                                        # once, so one location with a value
                                        # the schema refuses discarded every
                                        # location, the CVE and the description
                                        # with it. This entry alone is skipped.
                                        affected_code.append(
                                            AffectedCode.model_validate(code_dict)
                                        )
                                        ASH_LOGGER.debug(
                                            f"Successfully processed location {i} for {rule_id}"
                                        )
                                    except Exception as e:
                                        ASH_LOGGER.debug(
                                            f"Error processing file information for {rule_id} location {i}: {str(e)}"
                                        )
                                        continue
                        except Exception as e:
                            ASH_LOGGER.debug(
                                f"Error processing {rule_id} location {i}: {str(e)}"
                            )
                            continue
                else:
                    ASH_LOGGER.debug(f"No locations found for {rule_id}")
            except Exception as e:
                ASH_LOGGER.debug(f"Error processing locations for {rule_id}: {str(e)}")

            ASH_LOGGER.debug(
                f"Created {len(affected_code)} affected code entries from {location_count} locations for {rule_id}"
            )

            if affected_code:
                vuln_dict["affected_code"] = affected_code

            vulnerability = Vulnerability(**vuln_dict)
            ASH_LOGGER.debug(f"Successfully created vulnerability object for {rule_id}")
            return vulnerability, False

        except Exception as e:
            ASH_LOGGER.error(
                f"Critical error creating vulnerability from result {rule_id}: {str(e)}"
            )
            # Return minimal vulnerability object as fallback
            fallback_vuln = Vulnerability(
                desc=_FALLBACK_VULNERABILITY_DESC,
                title=rule_id if rule_id != "Unknown Rule" else "Unknown Rule",
                severity="MEDIUM",
            )
            ASH_LOGGER.debug(f"Created fallback vulnerability object for {rule_id}")
            return fallback_vuln, True

    def _determine_status_from_suppressions(
        self, suppressions: Optional[List[Suppression]], rule_id: str = "Unknown"
    ) -> Tuple[Optional[StatusId], Optional[str], Optional[str]]:
        """Analyze suppressions and return appropriate status.

        Args:
            suppressions: List of SARIF suppressions or None
            rule_id: Rule ID for logging context

        Returns:
            Tuple of (status_id, status_detail) where:
            - status_id: StatusId enum value or None
            - status_detail: String with suppression details or None
            - status: String with suppression status correlating to the returned status_id

        Only a suppression in effect closes the finding. One ``rejected`` by the
        reviewer or still ``underReview`` has not taken effect (SARIF 3.35.4),
        and the exit code and the per-scanner counts read it that way
        (``sarif_utils.suppressions_in_effect``), so the record reads it the same
        way instead of reporting a finding the scan failed on as closed. Such a
        suppression is also left out of ``status_detail``, which explains why the
        finding is closed.
        """
        try:
            suppressions = suppressions_in_effect(suppressions)
        except Exception as e:  # noqa: BLE001 -- the record degrades, as below
            # A suppression list that cannot be read at all (len says there are
            # suppressions, iterating raises) is an unknown status, the same
            # answer the handler below gives when nothing in the list is readable.
            ASH_LOGGER.error(f"Error reading suppressions for {rule_id}: {str(e)}")
            return StatusId.integer_0, "Unknown suppression status", "Unknown"
        if not suppressions:
            # No suppression in effect - finding is active/open
            ASH_LOGGER.debug(
                f"No suppression in effect for {rule_id} - marking as active"
            )
            return StatusId.integer_1, None, "New"

        suppression_count = len(suppressions)
        ASH_LOGGER.debug(f"Processing {suppression_count} suppressions for {rule_id}")

        try:
            # Has suppressions - finding is suppressed/closed
            status_details = []
            processed_suppressions = 0
            failed_suppressions = 0

            for i, suppression in enumerate(suppressions):
                try:
                    detail_parts = []

                    # Safely extract kind
                    try:
                        if suppression.kind:
                            kind_value = str(suppression.kind).split(".")[-1]
                            detail_parts.append(f"kind: {kind_value}")
                            ASH_LOGGER.debug(
                                f"Extracted suppression kind for {rule_id} suppression {i}: {kind_value}"
                            )
                    except Exception as e:
                        ASH_LOGGER.debug(
                            f"Error extracting suppression kind for {rule_id} suppression {i}: {str(e)}"
                        )

                    # Safely extract state
                    try:
                        if suppression.state:
                            state_value = str(suppression.state).split(".")[-1]
                            detail_parts.append(f"state: {state_value}")
                            ASH_LOGGER.debug(
                                f"Extracted suppression state for {rule_id} suppression {i}: {state_value}"
                            )
                    except Exception as e:
                        ASH_LOGGER.debug(
                            f"Error extracting suppression state for {rule_id} suppression {i}: {str(e)}"
                        )

                    # Safely extract justification
                    try:
                        if (
                            suppression.justification
                            and suppression.justification.strip()
                        ):
                            justification = suppression.justification.strip()
                            detail_parts.append(f"justification: {justification}")
                            ASH_LOGGER.debug(
                                f"Extracted suppression justification for {rule_id} suppression {i}: {len(justification)} characters"
                            )
                    except Exception as e:
                        ASH_LOGGER.debug(
                            f"Error extracting suppression justification for {rule_id} suppression {i}: {str(e)}"
                        )

                    if detail_parts:
                        status_details.append("; ".join(detail_parts))
                        processed_suppressions += 1
                        ASH_LOGGER.debug(
                            f"Successfully processed suppression {i} for {rule_id}"
                        )
                    else:
                        # If no details could be extracted, add a generic entry
                        status_details.append(f"suppression_{i}")
                        processed_suppressions += 1
                        ASH_LOGGER.warning(
                            f"No details extracted for {rule_id} suppression {i}, using generic entry"
                        )

                except Exception as e:
                    failed_suppressions += 1
                    ASH_LOGGER.warning(
                        f"Error processing individual suppression {i} for {rule_id}: {str(e)}"
                    )
                    status_details.append(f"suppression_{i}_error")
                    continue

            # Log suppression processing statistics
            ASH_LOGGER.debug(
                f"Suppression processing for {rule_id}: {processed_suppressions} successful, {failed_suppressions} failed"
            )

            if failed_suppressions > 0:
                ASH_LOGGER.warning(
                    f"Failed to process {failed_suppressions}/{suppression_count} suppressions for {rule_id}"
                )

            status_detail = (
                " | ".join(status_details) if status_details else "Suppressed"
            )
            ASH_LOGGER.debug(
                f"Determined suppressed status for {rule_id} with detail: {status_detail[:100]}{'...' if len(status_detail) > 100 else ''}"
            )
            return StatusId.integer_3, status_detail, "Suppressed"

        except Exception as e:
            ASH_LOGGER.error(
                f"Critical error processing suppressions for {rule_id}: {str(e)}"
            )
            return StatusId.integer_0, "Unknown suppression status", "Unknown"

    def _create_vulnerability_finding(
        self,
        result: Result,
        metadata: Metadata,
        current_time_ms: int,
        shared_id: Optional[str] = None,
        identity: Optional[str] = None,
        rules: Optional[Dict[str, Any]] = None,
    ) -> VulnerabilityFinding:
        """Build individual VulnerabilityFinding object.

        Args:
            result: SARIF result object
            metadata: OCSF metadata object
            current_time_ms: Current timestamp in milliseconds
            shared_id: the finding's id in every other report
                (``sarif_utils.shared_finding_ids``); the uid is derived from it, else
                from *identity*, the result's own identity numbered within the
                report (:func:`_fallback_identities`), else from the result's
                own identity alone (:func:`_identity_key`)
            identity: see *shared_id*
            rules: rule ids to descriptors (:func:`_rule_descriptors`), for a
                message given by ``id``

        Returns:
            VulnerabilityFinding object for the individual result
        """
        # Extract rule ID early for logging context
        rule_id = "Unknown Rule"
        named_rule: Optional[str] = None
        try:
            named_rule = result_rule_id(result)
            rule_id = named_rule or rule_id
        except Exception:  # nosec B110 — graceful fallback when ruleId attribute missing
            pass

        ASH_LOGGER.debug(f"Creating VulnerabilityFinding for {rule_id}")

        try:
            # Create vulnerability from result (this method has its own error
            # handling). A vulnerability its fallback built makes the record
            # degraded: the label below marks it so report() counts it apart
            # from the findings read whole.
            ASH_LOGGER.debug(f"Creating vulnerability object for {rule_id}")
            vulnerability, degraded = self._build_vulnerability(result, rules)

            # Determine status from suppressions (this method has its own error handling)
            ASH_LOGGER.debug(f"Determining suppression status for {rule_id}")
            status_id, status_detail, status = self._determine_status_from_suppressions(
                getattr(result, "suppressions", None), rule_id
            )

            # severity_id from the gate's severity too, so a finding the scan
            # fails as critical reaches a SIEM as critical.
            severity_id = _OCSF_SEVERITY_ID[result_severity(result)]

            # Create unique finding info for this result
            ASH_LOGGER.debug(f"Creating finding info for {rule_id}")
            message_text = _NO_DESCRIPTION
            rule_part = rule_id  # Use already extracted rule_id

            try:
                # Safely extract message text
                message_text = result_message_text(
                    result, _rule_descriptor(named_rule, rules), default=message_text
                )
                ASH_LOGGER.debug(
                    f"Extracted message text for finding info {rule_id}: {len(message_text)} characters"
                )
            except Exception as e:
                ASH_LOGGER.debug(
                    f"Error extracting message text for finding info {rule_id}: {str(e)}"
                )

            # Create descriptive title with proper truncation
            try:
                # Extract location info for more descriptive titles
                location_info = ""
                try:
                    if result.locations and len(result.locations) > 0:
                        first_location = result.locations[0]
                        if (
                            first_location.physicalLocation
                            and first_location.physicalLocation.root
                            and first_location.physicalLocation.root.artifactLocation
                            and first_location.physicalLocation.root.artifactLocation.uri
                        ):
                            file_path = first_location.physicalLocation.root.artifactLocation.uri
                            file_name = _file_name(file_path)
                            location_info = f" in {file_name}"
                            ASH_LOGGER.debug(
                                f"Extracted location info for {rule_id} title: {location_info}"
                            )
                except Exception as e:
                    ASH_LOGGER.debug(
                        f"Error extracting location for {rule_id} title: {str(e)}"
                    )

                # Create title with rule, location, and message, at most
                # TITLE_MAX_LENGTH characters with the ellipsis counted.
                title = _finding_title(rule_part, location_info, message_text)
                if title.endswith("..."):
                    ASH_LOGGER.debug(
                        f"Truncated title for {rule_id} from {len(message_text)} to {len(title)} characters"
                    )

                ASH_LOGGER.debug(
                    f"Created title for {rule_id}: {title[:50]}{'...' if len(title) > 50 else ''}"
                )
            except Exception as e:
                ASH_LOGGER.debug(
                    f"Error creating title for {rule_id}, using fallback: {str(e)}"
                )
                title = f"{rule_part} - {message_text}"[:TITLE_MAX_LENGTH]

            # Create finding info with error handling
            ASH_LOGGER.debug(f"Creating FindingInfo object for {rule_id}")
            identity = (
                shared_id or identity or _identity_key(result, rule_id, message_text)
            )
            try:
                finding_uid = _finding_uid(identity)
                finding_info = FindingInfo(
                    uid=finding_uid,
                    title=title,
                    desc=message_text,
                )
                ASH_LOGGER.debug(
                    f"Created FindingInfo for {rule_id} with UID: {finding_uid}"
                )
            except Exception as e:
                ASH_LOGGER.warning(
                    f"Error creating FindingInfo for {rule_id}, using minimal version: {str(e)}"
                )
                # A finding whose title and description could not be built is
                # degraded too; without the mark the rate counted it whole.
                degraded = True
                fallback_uid = _finding_uid(f"{identity}|fallback-info")
                finding_info = FindingInfo(
                    uid=fallback_uid,
                    title="Error creating finding title",
                    desc="Error extracting finding description",
                )
                ASH_LOGGER.debug(
                    f"Created fallback FindingInfo for {rule_id} with UID: {fallback_uid}"
                )

            record_metadata = _metadata_for_project(metadata, result)
            if degraded:
                record_metadata = _metadata_with_labels(
                    record_metadata, DEGRADED_FINDING_LABEL
                )

            # Create OCSF vulnerability finding
            ASH_LOGGER.debug(f"Creating VulnerabilityFinding object for {rule_id}")
            vulnerability_finding_dict = {
                "activity_id": ActivityId.integer_1,  # Create
                "activity_name": ACTIVITY_NAME,
                "severity_id": severity_id,
                "type_uid": 200201,  # Vulnerability Finding type ID
                "class_uid": 2002,  # Vulnerability Finding class ID
                "category_uid": 2,  # Vulnerability Finding category ID
                "category_name": "Findings",
                "time": current_time_ms,
                "metadata": record_metadata,
                "finding_info": finding_info,
                "vulnerabilities": [vulnerability],
            }

            # Add status information if available
            if status_id is not None:
                vulnerability_finding_dict["status_id"] = status_id
                ASH_LOGGER.debug(f"Added status_id for {rule_id}: {status_id}")
            if status is not None:
                vulnerability_finding_dict["status"] = status
                ASH_LOGGER.debug(f"Added status for {rule_id}: {status}")
            if status_detail is not None:
                vulnerability_finding_dict["status_detail"] = status_detail
                ASH_LOGGER.debug(
                    f"Added status_detail for {rule_id}: {status_detail[:50]}{'...' if len(status_detail) > 50 else ''}"
                )

            vuln_finding = VulnerabilityFinding(**vulnerability_finding_dict)
            ASH_LOGGER.debug(f"Successfully created VulnerabilityFinding for {rule_id}")
            return vuln_finding

        except Exception as e:
            ASH_LOGGER.error(
                f"Critical error creating VulnerabilityFinding for {rule_id}: {str(e)}"
            )
            # Create minimal fallback finding. It keeps what can still be read
            # of the finding: the gate's severity and the workspace project,
            # each guarded on its own. A fallback that hardcoded LOW and the
            # shared metadata turned a CRITICAL finding of one project into a
            # LOW record of no project.
            try:
                ASH_LOGGER.debug(
                    f"Creating fallback VulnerabilityFinding for {rule_id}"
                )
                try:
                    fallback_severity = result_severity(result)
                    fallback_severity_id = _OCSF_SEVERITY_ID[fallback_severity]
                except Exception:  # noqa: BLE001 -- the fallback's own fallback
                    fallback_severity = "LOW"
                    fallback_severity_id = SeverityId.integer_2
                try:
                    fallback_metadata = _metadata_for_project(metadata, result)
                except Exception:  # noqa: BLE001 -- the fallback's own fallback
                    fallback_metadata = metadata
                # Marked, so report() counts it as degraded rather than as a
                # finding read whole, and a SIEM can tell the two apart.
                fallback_metadata = _metadata_with_labels(
                    fallback_metadata, DEGRADED_FINDING_LABEL
                )

                fallback_vulnerability = Vulnerability(
                    desc=_FALLBACK_VULNERABILITY_DESC,
                    title=rule_id if rule_id != "Unknown Rule" else "Unknown Rule",
                    severity=fallback_severity,
                )

                # The uid is the finding's own, the one a whole record would
                # carry: the degraded label above tells the two apart. A suffix
                # on the uid made a finding that degraded in one run and built
                # whole in the next two records in a SIEM for good, and every
                # record of it a Create. The message is read with the default
                # the whole record's key reads it with: left to the key's own
                # default (empty), a result with nothing to read gave the two
                # records two uids on a direct call.
                try:
                    fallback_message = result_message_text(
                        result, default=_NO_DESCRIPTION
                    )
                except Exception:  # noqa: BLE001 -- the fallback's own fallback
                    fallback_message = _NO_DESCRIPTION
                fallback_finding_info = FindingInfo(
                    uid=_finding_uid(
                        shared_id
                        or identity
                        or _identity_key(result, rule_id, fallback_message)
                    ),
                    title=f"Error processing finding {rule_id}",
                    desc="An error occurred while processing this security finding",
                )

                fallback_finding = VulnerabilityFinding(
                    activity_id=ActivityId.integer_1,
                    activity_name=ACTIVITY_NAME,
                    severity_id=fallback_severity_id,
                    status_id=StatusId.integer_0,  # Unknown
                    type_uid=200201,
                    class_uid=2002,
                    category_uid=2,
                    category_name="Findings",
                    time=current_time_ms,
                    metadata=fallback_metadata,
                    finding_info=fallback_finding_info,
                    vulnerabilities=[fallback_vulnerability],
                )
                ASH_LOGGER.debug(f"Created fallback VulnerabilityFinding for {rule_id}")
                return fallback_finding
            except Exception as fallback_error:
                ASH_LOGGER.error(
                    f"Failed to create fallback VulnerabilityFinding for {rule_id}: {str(fallback_error)}"
                )
                raise Exception(
                    f"Unable to create VulnerabilityFinding for {rule_id}: {str(e)}"
                )

    def _create_skipped_project_finding(
        self, entry: SkippedProject, metadata: Metadata, current_time_ms: int
    ) -> VulnerabilityFinding:
        """One record standing for a project that was never scanned.

        ``vulnerabilities`` is required by the class, so the record cannot omit it
        -- but an empty array is both the honest value and the filter: a consumer
        summing vulnerability counts across the array never sees this record.

        ``severity_id`` 1 is Informational, deliberately not 0 (Unknown). Unknown
        severity is a thing a scanner says about a finding it could not rank, and
        some pipelines escalate it; this is not a finding at all, and Informational
        is the bucket that neither escalates nor disappears.

        No ``try``/``except`` here, unlike the finding builder. That one wraps
        untrusted scanner output whose shape varies; every value here comes from a
        validated ``SkippedProject``, so a failure would be a bug in this code and
        should surface rather than be swallowed into a fallback record that says
        less than the real one.
        """
        return VulnerabilityFinding(
            activity_id=ActivityId.integer_1,
            activity_name=ACTIVITY_NAME,
            # Informational: the record reports a fact about the run, not a risk.
            severity_id=SeverityId.integer_1,
            # 99 is OCSF's "not mapped -- see `status`". See the module constants.
            status_id=StatusId.integer_99,
            status=SKIPPED_PROJECT_STATUS,
            status_detail=skipped_project_detail(entry),
            type_uid=200201,
            class_uid=2002,
            category_uid=2,
            category_name="Findings",
            time=current_time_ms,
            metadata=_metadata_with_labels(
                metadata,
                f"{WORKSPACE_PROJECT_LABEL_PREFIX}{entry.project}",
                SKIPPED_PROJECT_LABEL,
            ),
            finding_info=FindingInfo(
                uid=f"{SKIPPED_PROJECT_UID_PREFIX}{entry.project}",
                title=f"Project '{entry.project}' was not scanned",
                desc=skipped_project_detail(entry),
            ),
            vulnerabilities=[],
        )

    def _shortfall_record(
        self,
        missing: int,
        degraded: int,
        metadata: Metadata,
        current_time_ms: int,
        scan_identity: str = "",
    ) -> Optional[Dict[str, Any]]:
        """The shortfall record as the array carries it, or None when it could
        not be built or dumped.

        Guarded alone, apart from the findings array's guard: a record the model
        rejected used to raise into that guard, whose answer is the error
        envelope, so one bad note about missing findings cost every finding
        that was present. The findings are kept; the loss of the note is logged
        with the counts it would have carried. *scan_identity* is passed on to
        the builder (:func:`_scan_identity`).
        """
        try:
            return self._create_shortfall_finding(
                missing,
                degraded,
                metadata,
                current_time_ms,
                scan_identity=scan_identity,
            ).model_dump(by_alias=True, exclude_none=True, exclude_unset=True)
        except Exception as e:  # noqa: BLE001 -- the findings outrank the note
            ASH_LOGGER.error(
                f"The OCSF shortfall record could not be built ({e}); {missing} "
                f"absent and {degraded} degraded finding(s) are left unrecorded in "
                "the array, which is written with the findings it holds"
            )
            return None

    def _create_shortfall_finding(
        self,
        missing: int,
        degraded: int,
        metadata: Metadata,
        current_time_ms: int,
        scan_identity: str = "",
    ) -> VulnerabilityFinding:
        """One record standing for the findings this array does not carry whole.

        *missing* results were converted by neither the builder nor its fallback,
        or failed to serialize, and are absent; *degraded* records are present
        but built by the fallback (:data:`DEGRADED_FINDING_LABEL`).
        *scan_identity* is the scanned project's configured name
        (:func:`_scan_identity`), and the record's uid is derived from it, so
        a project's record is the same across its runs and distinct from that
        of a project with another name; scans that keep the default name share
        one record. Without this
        record the array was shorter than the scan's findings and nothing in the
        file said so; the log named each one, and nothing downstream reads the
        log. Shaped like a skipped-project record: ``status_id`` 99 with
        ``status`` naming it, severity Informational, an empty
        ``vulnerabilities`` array so no consumer counts it as a finding, and a
        label that makes it filterable.

        The title, the detail and the ``status`` name only the counts that are
        not zero. One sentence for both read "0 finding(s) could not be
        converted ... The array is incomplete" for an array that held every
        finding and had only degraded records, so a SIEM rule keyed on it
        alarmed on a complete array, and the title named the wrong problem.
        ``status`` is "Incomplete" only when findings are absent; an array
        that is whole but carries fallback records is "Degraded".
        """
        missing_text = (
            f"{missing} finding(s) of this scan could not be converted to OCSF and "
            "are absent from this array"
        )
        degraded_text = (
            f"{degraded} record(s) were built by the fallback path and carry less "
            "than the scan knows"
        )
        if missing and degraded:
            title = (
                f"{missing} finding(s) could not be converted to OCSF; "
                f"{degraded} record(s) built by the fallback path"
            )
            detail = f"{missing_text}; {degraded_text}."
        elif missing:
            title = f"{missing} finding(s) could not be converted to OCSF"
            detail = f"{missing_text}."
        else:
            title = f"{degraded} record(s) built by the fallback path"
            detail = f"{degraded_text}."
        detail += " The ASH log names each one."
        if missing:
            detail += " The array is incomplete."
        return VulnerabilityFinding(
            activity_id=ActivityId.integer_1,
            activity_name=ACTIVITY_NAME,
            severity_id=SeverityId.integer_1,
            status_id=StatusId.integer_99,
            status="Incomplete" if missing else "Degraded",
            status_detail=detail,
            type_uid=200201,
            class_uid=2002,
            category_uid=2,
            category_name="Findings",
            time=current_time_ms,
            metadata=_metadata_with_labels(metadata, CONVERSION_SHORTFALL_LABEL),
            finding_info=FindingInfo(
                uid=_shortfall_uid(scan_identity),
                title=title,
                desc=detail,
            ),
            vulnerabilities=[],
        )

    def _serialize_skipped_project_findings(
        self, findings: list[VulnerabilityFinding]
    ) -> list[dict[str, Any]]:
        """*findings* as dumped dicts, with the same options the real records use.

        Same ``by_alias``/``exclude_none``/``exclude_unset`` triple, so a project
        record and a finding record are shaped alike and a consumer needs one
        parser rather than two. ``vulnerabilities=[]`` survives ``exclude_unset``
        because it is passed explicitly, which is what keeps the required attribute
        present.
        """
        return [
            finding.model_dump(
                by_alias=True,
                exclude_none=True,
                exclude_unset=True,
            )
            for finding in findings
        ]

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model in Open Cybersecurity Schema Framework (OCSF) format.

        Returns an array of VulnerabilityFinding objects, one per SARIF result,
        plus one per skipped workspace project.
        """
        ASH_LOGGER.info("Starting OCSF report generation")

        # Get current timestamp in milliseconds since epoch
        current_time_ms = int(datetime.now(timezone.utc).timestamp() * 1000)
        ASH_LOGGER.debug(f"Report timestamp: {current_time_ms}")

        # Create base OCSF product metadata
        product = Product(
            name="Automated Security Helper",
            vendor_name="Amazon Web Services",
            version=get_ash_version(),
        )

        metadata = Metadata(
            product=product,
            version="1.1.0",  # OCSF schema version
            logged_time=current_time_ms,
        )
        ASH_LOGGER.debug(f"Created OCSF metadata with ASH version: {get_ash_version()}")

        # Built before the four no-findings early returns below, because those are
        # exactly the cases that lose the disclosure: a workspace whose scanned
        # projects all came back clean has no results, and returning a bare `[]`
        # there would make the artefact say nothing at all about a project the
        # operator asked for. Kept in its own list rather than appended to
        # `vulnerability_findings` so that every statistic and failure rate below
        # still counts real findings only -- merging here would inflate the success
        # rate with records that never went through the fragile builder.
        skipped_project_findings = [
            self._create_skipped_project_finding(entry, metadata, current_time_ms)
            for entry in skipped_projects(model)
        ]
        skipped_project_data = self._serialize_skipped_project_findings(
            skipped_project_findings
        )

        def _only_skipped_projects(reason: str) -> str:
            """The array when there are no findings at all.

            ``json.dumps([], indent=2)`` is ``"[]"``, so a scan with nothing to
            report and nothing skipped produces the exact string it always has --
            which matters, because a consumer may well be comparing against it.
            The log line says what the array holds: in workspace mode the same
            return carries the skipped-project records, and "returning empty
            array" was wrong there.
            """
            if skipped_project_data:
                ASH_LOGGER.info(
                    f"{reason} - the OCSF array carries "
                    f"{len(skipped_project_data)} skipped-project record(s) and "
                    "no findings"
                )
            else:
                ASH_LOGGER.info(f"{reason} - returning empty array")
            return json.dumps(skipped_project_data, indent=2, default=str)

        # Create array of individual VulnerabilityFinding objects
        vulnerability_findings = []
        total_results_count = 0
        failed_results_count = 0
        suppressed_findings_count = 0
        active_findings_count = 0
        degraded_findings_count = 0
        non_finding_count = 0

        # Check if we have SARIF data to process
        if not model.sarif:
            return _only_skipped_projects("No SARIF data found in model")

        if not model.sarif.runs:
            return _only_skipped_projects("No SARIF runs found in model")

        # Through the record form, as the GitLab SAST report reads them: a file
        # name decoded with surrogateescape holds a lone surrogate, which
        # json.dumps wrote as a lone \udcXX escape that strict JSON parsers
        # reject; in the record form it is text every parser reads.
        #
        # Guarded as the GitLab SAST reporter guards the same call: a model
        # whose SARIF cannot be enumerated raised out of report(), so no file
        # was written and nothing said why. The error response says it. The
        # exception text goes through error_text, because a pydantic error
        # quotes the input it refused, which can be a scanned file's text.
        try:
            recorded_sarif = recorded(model.sarif)
            all_results = recorded_sarif.get_all_results()
        except Exception as e:  # noqa: BLE001 -- see the comment above
            ASH_LOGGER.error(f"Failed to read SARIF results: {error_text(e)}")
            return self._create_error_response(
                f"ASH could not read the SARIF results: {error_text(e)}",
                current_time_ms,
                0,
                0,
            )

        if not all_results:
            return _only_skipped_projects("No SARIF results found in any run")

        total_results_count = len(all_results)
        ASH_LOGGER.info(
            f"Processing {total_results_count} SARIF results for OCSF report"
        )
        shared_ids = shared_finding_ids(model, all_results)
        identities = _fallback_identities(all_results, shared_ids)
        # The rules every run declares, read once, so a message given by id
        # is described by the string the rule names rather than by the key.
        rules = _rule_descriptors(recorded_sarif)

        for i, result in enumerate(all_results):
            rule_id = result_rule_id(result) or f"result_{i}"
            ASH_LOGGER.debug(
                f"Processing SARIF result {i + 1}/{total_results_count}: {rule_id}"
            )

            if is_not_a_finding(result):
                # Evaluated and passed, not applicable, or informational: not
                # a vulnerability finding, and neither a success nor a failure
                # of the conversion. Counted here and taken off the total after
                # the loop; decremented inside it, the total changed meaning
                # partway and the per-result line read "5/3".
                non_finding_count += 1
                ASH_LOGGER.debug(
                    f"Result {rule_id} states no problem (kind "
                    f"{getattr(getattr(result, 'kind', None), 'value', getattr(result, 'kind', None))}); "
                    "not an OCSF vulnerability finding"
                )
                continue

            try:
                # Create individual VulnerabilityFinding for this result
                finding = self._create_vulnerability_finding(
                    result,
                    metadata,
                    current_time_ms,
                    shared_id=shared_ids[i],
                    identity=identities[i],
                    rules=rules,
                )
                vulnerability_findings.append(finding)

                labels = getattr(getattr(finding, "metadata", None), "labels", None)
                if isinstance(labels, list) and DEGRADED_FINDING_LABEL in labels:
                    degraded_findings_count += 1

                # Track finding status for statistics
                if (
                    hasattr(finding, "status_id")
                    and finding.status_id == StatusId.integer_3
                ):
                    suppressed_findings_count += 1
                    ASH_LOGGER.debug(
                        f"Created suppressed vulnerability finding for {rule_id}"
                    )
                else:
                    active_findings_count += 1
                    ASH_LOGGER.debug(
                        f"Created active vulnerability finding for {rule_id}"
                    )

            except Exception as e:
                failed_results_count += 1
                ASH_LOGGER.error(
                    f"Error creating vulnerability finding for result {rule_id}: {str(e)}"
                )
                ASH_LOGGER.debug(
                    f"Failed result details - Rule ID: {rule_id}, Level: {getattr(result, 'level', None)}, Suppressions: {len(getattr(result, 'suppressions', []) or [])}"
                )
                continue

        processed_results_count = len(vulnerability_findings)
        # The results that are findings: what the rates below are over.
        finding_results_count = total_results_count - non_finding_count
        if non_finding_count:
            ASH_LOGGER.info(
                f"{non_finding_count} SARIF result(s) state no problem (kind pass, "
                "notApplicable or informational) and are not OCSF findings"
            )

        # Log comprehensive processing statistics. A degraded record is a
        # finding whose builder failed and whose fallback kept what it could;
        # it is counted apart from the findings read whole, and with the
        # failures in the rate, so the rate says what the array is worth.
        if finding_results_count > 0:
            whole_count = processed_results_count - degraded_findings_count
            success_rate = (whole_count / finding_results_count) * 100
            ASH_LOGGER.info(
                f"OCSF report processing complete: {whole_count}/{finding_results_count} "
                f"findings created whole, {degraded_findings_count} degraded, "
                f"{failed_results_count} failed ({success_rate:.1f}% success rate)"
            )
            ASH_LOGGER.info(
                f"Finding status breakdown: {active_findings_count} active, {suppressed_findings_count} suppressed"
            )

            if failed_results_count > 0:
                failure_rate = (failed_results_count / finding_results_count) * 100
                ASH_LOGGER.warning(
                    f"{failed_results_count} findings failed to process and were skipped ({failure_rate:.1f}% failure rate)"
                )
        else:
            ASH_LOGGER.debug("No SARIF results to process")

        # Handle case where all findings failed to process
        if finding_results_count > 0 and processed_results_count == 0:
            ASH_LOGGER.error(
                "All SARIF results failed to process - returning error response"
            )
            # processed_results_count, which is 0 here, not the total: the
            # response adds its two counts into a total, so passing the total
            # as the processed count doubled it and stated a 50% success rate
            # for a run in which every result failed.
            return self._create_error_response(
                "All findings failed to process",
                current_time_ms,
                processed_results_count,
                failed_results_count,
            )

        # If no findings were created from empty input, return empty array
        if not vulnerability_findings:
            return _only_skipped_projects(
                "No vulnerability findings created from SARIF results"
            )

        try:
            # Convert array of findings to JSON
            ASH_LOGGER.debug(
                f"Serializing {len(vulnerability_findings)} findings to JSON"
            )
            findings_data = []
            serialization_failures = 0

            for i, finding in enumerate(vulnerability_findings):
                finding_id = "Unknown"
                try:
                    if hasattr(finding, "finding_info") and hasattr(
                        finding.finding_info, "uid"
                    ):
                        finding_id = finding.finding_info.uid

                    ASH_LOGGER.debug(
                        f"Serializing finding {i + 1}/{len(vulnerability_findings)}: {finding_id}"
                    )
                    finding_data = finding.model_dump(
                        by_alias=True,
                        exclude_none=True,
                        exclude_unset=True,
                    )
                    findings_data.append(finding_data)
                    ASH_LOGGER.debug(f"Successfully serialized finding {finding_id}")
                except Exception as e:
                    serialization_failures += 1
                    ASH_LOGGER.error(
                        f"Error serializing individual finding {finding_id}: {str(e)}"
                    )
                    continue

            if serialization_failures > 0:
                serialization_failure_rate = (
                    serialization_failures / len(vulnerability_findings)
                ) * 100
                ASH_LOGGER.warning(
                    f"{serialization_failures} findings failed to serialize and were excluded from output ({serialization_failure_rate:.1f}% serialization failure rate)"
                )

            # If all findings failed to serialize, return error response
            if len(findings_data) == 0 and len(vulnerability_findings) > 0:
                ASH_LOGGER.error(
                    "All findings failed to serialize - returning error response"
                )
                # Zero processed: the response adds its two counts into a total,
                # so passing the processed count as both doubled the total and
                # stated a 50% success rate for a run in which nothing reached
                # the file. The failed count is every result the file lacks:
                # the ones whose record failed to serialize and the ones the
                # builder had already dropped. Counted from the serialization
                # failures alone, three results of which one failed to build
                # and two to serialize read "total 2, failed 2".
                return self._create_error_response(
                    "All findings failed to serialize",
                    current_time_ms,
                    0,
                    processed_results_count + failed_results_count,
                )

            # Appended AFTER the all-failed check, deliberately. The error response
            # is not a findings array -- it is a single-element envelope carrying
            # processing statistics -- so mixing project records into it would
            # produce a document neither shape describes. A skip lost there is
            # still in the payload and in the other five reporters, and a run where
            # every finding failed to serialise has a larger problem to report.
            findings_data.extend(skipped_project_data)

            # One record for what this array does not carry whole, so the file
            # says it is incomplete; see _create_shortfall_finding. Built under
            # its own guard: this try's except returns the error envelope, so a
            # shortfall record the model rejected discarded every finding it
            # stood beside.
            missing = failed_results_count + serialization_failures
            shortfall = None
            if missing or degraded_findings_count:
                shortfall = self._shortfall_record(
                    missing,
                    degraded_findings_count,
                    metadata,
                    current_time_ms,
                    scan_identity=_scan_identity(model),
                )
                if shortfall is not None:
                    findings_data.append(shortfall)

            final_json = json.dumps(findings_data, indent=2, default=str)
            # Counted apart from the findings rather than folded in, for the same
            # reason the records are marked in the output: a log line that called
            # them findings would be the first place the conflation appeared.
            shortfall_records = 1 if shortfall is not None else 0
            ASH_LOGGER.info(
                f"Successfully generated OCSF report with "
                f"{len(findings_data) - len(skipped_project_data) - shortfall_records} "
                f"findings, {len(skipped_project_data)} skipped-project records and "
                f"{shortfall_records} shortfall record ({len(final_json)} characters)"
            )
            return final_json

        except Exception as e:
            ASH_LOGGER.error(f"Failed to serialize OCSF findings array: {str(e)}")
            # Nothing reached the file, so nothing was processed: every result,
            # built or not, is a failure of this report. Passing the built
            # count as processed stated a success rate for an array that was
            # never written.
            return self._create_error_response(
                f"Failed to create OCSF report: {str(e)}",
                current_time_ms,
                0,
                processed_results_count + failed_results_count,
            )

    def _create_error_response(
        self,
        error_message: str,
        current_time_ms: int,
        processed_count: int,
        failed_count: int,
    ) -> str:
        """Create standardized error response with processing statistics.

        Args:
            error_message: Description of the error
            current_time_ms: Current timestamp in milliseconds
            processed_count: Number of successfully processed results
            failed_count: Number of failed results

        Returns:
            JSON string containing error response with statistics
        """
        ASH_LOGGER.debug(f"Creating error response: {error_message}")
        ASH_LOGGER.debug(
            f"Error response statistics - Processed: {processed_count}, Failed: {failed_count}"
        )

        try:
            total_count = processed_count + failed_count
            success_rate = (
                (processed_count / total_count) * 100 if total_count > 0 else 0
            )

            error_response = {
                "error": error_message,
                "metadata": {
                    "product": {
                        "name": "Automated Security Helper",
                        "vendor_name": "Amazon Web Services",
                        "version": get_ash_version(),
                    },
                    "version": "1.1.0",
                    "logged_time": current_time_ms,
                },
                "processing_statistics": {
                    "processed_results_count": processed_count,
                    "failed_results_count": failed_count,
                    "total_results_count": total_count,
                    "success_rate_percent": round(success_rate, 1),
                },
            }

            error_json = json.dumps([error_response], indent=2, default=str)
            ASH_LOGGER.debug(f"Created error response ({len(error_json)} characters)")
            return error_json

        except Exception as e:
            # Fallback to minimal error response if even error response creation fails
            ASH_LOGGER.error(f"Failed to create detailed error response: {str(e)}")
            fallback_response = json.dumps(
                [
                    {
                        "error": "Critical error in OCSF reporter - unable to create detailed error response"
                    }
                ],
                indent=2,
            )
            ASH_LOGGER.debug(
                f"Created fallback error response ({len(fallback_response)} characters)"
            )
            return fallback_response
