# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import itertools
import json
import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults
from automated_security_helper.base.options import ReporterOptionsBase
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
)
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.get_ash_version import get_ash_version

SPDX_VERSION = "SPDX-2.3"
DOCUMENT_SPDX_ID = "SPDXRef-DOCUMENT"
ROOT_PACKAGE_SPDX_ID = "SPDXRef-RootPackage"
NOASSERTION = "NOASSERTION"

# The namespace every ASH-generated document URI lives under. uuid5 over it plus
# the scan's identity gives a namespace that is unique per scan, as SPDX 2.3
# section 6.5 requires, and stable for one scan: re-running `ash report` on the
# same results reproduces the same document rather than a new one.
_NAMESPACE_BASE = "https://github.com/awslabs/automated-security-helper/spdx"
_NAMESPACE_UUID = uuid.uuid5(uuid.NAMESPACE_URL, _NAMESPACE_BASE)

# SPDX identifiers allow letters, digits, '.' and '-' after the "SPDXRef-" prefix.
_SPDX_ID_UNSAFE = re.compile(r"[^A-Za-z0-9.-]+")

# A ``LicenseRef-`` identifier inside a license expression. One qualified by an
# external document (``DocumentRef-x:LicenseRef-y``) is that document's to declare
# and is not matched (the lookbehind refuses the ':').
_LICENSE_REF_IN_EXPRESSION = re.compile(r"(?<![A-Za-z0-9.:-])LicenseRef-[A-Za-z0-9.-]+")

#: The CycloneDX 1.6 license acknowledgement that names a license as concluded by
#: the SBOM's author rather than declared by the component's author.
_CONCLUDED = "concluded"


class SPDXReporterConfigOptions(ReporterOptionsBase):
    pass


class SPDXReporterConfig(ReporterPluginConfigBase):
    name: Literal["spdx"] = "spdx"
    extension: str = "spdx.json"
    enabled: bool = False
    options: SPDXReporterConfigOptions = SPDXReporterConfigOptions()


def _spdx_created(value: Any) -> str:
    """``creationInfo.created`` in the ``YYYY-MM-DDThh:mm:ssZ`` form SPDX requires."""
    parsed = None
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        try:
            parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            parsed = None
    if parsed is None:
        parsed = datetime.now(timezone.utc)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


#: What the root package says when no SBOM scanner produced an inventory.
NO_SBOM_COMMENT = (
    "No SBOM scanner produced an inventory for this scan (the scanner was "
    "missing, skipped or failed), so the packages this document would CONTAIN "
    "are unknown. An empty package list here is not a statement that the "
    "project has no dependencies."
)


def _license_ref(name: str, extracted: Dict[str, Dict[str, str]]) -> str:
    """A ``LicenseRef-`` identifier for the free-text license *name*.

    Registered in *extracted*, the document's ``hasExtractedLicensingInfos``,
    so the reference resolves. Two names that sanitize to one identifier get
    distinct ones, because an identifier that stood for both would declare the
    second component under the first's license.
    """
    base = f"LicenseRef-{_SPDX_ID_UNSAFE.sub('-', name)}"[:120]
    ref = base
    counter = 2
    while ref in extracted and extracted[ref]["name"] != name:
        ref = f"{base}-{counter}"
        counter += 1
    extracted.setdefault(
        ref, {"licenseId": ref, "name": name, "extractedText": NOASSERTION}
    )
    return ref


def _declare_license_refs(term: str, extracted: Dict[str, Dict[str, str]]) -> str:
    """*term*, with each ``LicenseRef-`` identifier in it declared in *extracted*.

    An SBOM's ``id`` or ``expression`` can name a ``LicenseRef-`` term of its own
    (Syft writes one for a license text it could not match). SPDX requires every
    such identifier used in the document to be declared in
    ``hasExtractedLicensingInfos``; copied undeclared, as this once did, the
    document referred to a license it never defined and failed validation. The
    declaration says what is known: the identifier as its name, and NOASSERTION
    for the text the SBOM did not carry. A name-only license that was given the
    same identifier keeps its entry; the two then share one declaration, which
    is the SBOM's statement.
    """
    for ref in _LICENSE_REF_IN_EXPRESSION.findall(term):
        extracted.setdefault(
            ref, {"licenseId": ref, "name": ref, "extractedText": NOASSERTION}
        )
    return term


def _license_expressions(
    component: Dict[str, Any], extracted: Dict[str, Dict[str, str]]
) -> Tuple[str, str]:
    """The component's (declared, concluded) licenses as SPDX expressions.

    CycloneDX carries a license as an SPDX ``id``, a free-text ``name`` or an
    ``expression``. ``id`` and ``expression`` are SPDX expressions and are used
    as they are, with any ``LicenseRef-`` term they hold declared
    (:func:`_declare_license_refs`). A ``name`` is arbitrary text and cannot
    stand in an expression, so it becomes a ``LicenseRef-`` identifier declared
    in the document's ``hasExtractedLicensingInfos`` (*extracted*), the SPDX way
    to declare a license that has no listed identifier. Dropping name-only
    licenses, as this once did, declared a narrower license than the SBOM
    states: a component under "Apache-2.0" and a named commercial license read
    as Apache-2.0 alone. Several terms are joined with AND, the conservative
    reading of a list.

    CycloneDX 1.6 lets a license entry say whether the component's author
    ``declared`` it or the SBOM's author ``concluded`` it from the contents.
    SPDX keeps the two apart as ``licenseDeclared`` and ``licenseConcluded``, so
    a concluded entry goes to the second; written to the first, as every entry
    once was, the document attributed the SBOM author's conclusion to the
    component's author. Either expression is NOASSERTION when it has no term.
    """
    declared: List[str] = []
    concluded: List[str] = []
    for choice in component.get("licenses") or []:
        if not isinstance(choice, dict):
            continue
        license_obj = choice.get("license")
        acknowledgement = choice.get("acknowledgement")
        if acknowledgement is None and isinstance(license_obj, dict):
            acknowledgement = license_obj.get("acknowledgement")
        terms = concluded if acknowledgement == _CONCLUDED else declared
        expression = choice.get("expression")
        if isinstance(expression, str) and expression.strip():
            terms.append(_declare_license_refs(expression.strip(), extracted))
            continue
        if isinstance(license_obj, dict):
            license_id = license_obj.get("id")
            if isinstance(license_id, str) and license_id.strip():
                terms.append(_declare_license_refs(license_id.strip(), extracted))
                continue
            license_name = license_obj.get("name")
            if isinstance(license_name, str) and license_name.strip():
                terms.append(_license_ref(license_name.strip(), extracted))
    return _expression(declared), _expression(concluded)


def _expression(terms: List[str]) -> str:
    """*terms* joined with AND as one SPDX expression, or NOASSERTION."""
    if not terms:
        return NOASSERTION
    if len(terms) == 1:
        return terms[0]
    return " AND ".join(f"({term})" if " " in term else term for term in terms)


def _package_name(component: Dict[str, Any], index: int) -> str:
    """The component's name, qualified by its CycloneDX ``group`` when it has one.

    A CycloneDX ``group`` is the namespace a name is unique in: an npm scope
    (``@angular`` for ``core``), a Maven groupId (``org.apache.commons`` for
    ``commons-lang3``). Read from ``name`` alone, as this once was, two
    components from different groups became one indistinguishable SPDX package
    name, and the purl in ``externalRefs`` was the only thing telling them
    apart. The name is written ``<group>/<name>``, the form npm itself uses,
    unless the name already carries the group.
    """
    name = str(component.get("name") or f"component-{index}")
    group = component.get("group")
    if isinstance(group, str) and group.strip():
        group = group.strip()
        if not name.startswith(f"{group}/"):
            name = f"{group}/{name}"
    return name


def _exclusion_marks(component: Dict[str, Any]) -> List[str]:
    """The values of the component's client-exclusion marks, if any.

    The CycloneDX report marks a component a delivered client exclusion would
    have dropped with a property (``config.client_scanner_exclusions``). The
    SPDX document is built from the same SBOM and left the mark out, so the two
    inventories disagreed about those components.
    """
    from automated_security_helper.config.client_scanner_exclusions import (
        SBOM_PROPERTY,
    )

    marks: List[str] = []
    for prop in component.get("properties") or []:
        if isinstance(prop, dict) and prop.get("name") == SBOM_PROPERTY:
            value = prop.get("value")
            if value:
                marks.append(str(value))
    return marks


def _package(
    component: Dict[str, Any], index: int, extracted: Dict[str, Dict[str, str]]
) -> Dict[str, Any]:
    name = _package_name(component, index)
    declared, concluded = _license_expressions(component, extracted)
    package: Dict[str, Any] = {
        "SPDXID": f"SPDXRef-Package-{index}-{_SPDX_ID_UNSAFE.sub('-', name)}"[:200],
        "name": name,
        "downloadLocation": NOASSERTION,
        "filesAnalyzed": False,
        "licenseConcluded": concluded,
        "licenseDeclared": declared,
        "copyrightText": NOASSERTION,
    }
    marks = _exclusion_marks(component)
    if marks:
        package["comment"] = (
            "ASH: a delivered client exclusion would have dropped this component "
            f"({'; '.join(marks)}); the SBOM lists it, so this document does too, "
            "with the same mark the CycloneDX report carries."
        )
    version = component.get("version")
    if version:
        package["versionInfo"] = str(version)
    supplier = (component.get("supplier") or {}).get("name")
    if supplier:
        package["supplier"] = f"Organization: {supplier}"
    purl = component.get("purl")
    if purl:
        package["externalRefs"] = [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": str(purl),
            }
        ]
    return package


def build_spdx_document(model: "AshAggregatedResults") -> Dict[str, Any]:
    """An SPDX 2.3 JSON document for the scanned project.

    The packages come from the CycloneDX SBOM the scan already holds
    (``model.cyclonedx``, populated by the SBOM scanners), so the SPDX and
    CycloneDX reports describe the same components. A root package stands for
    the scanned project itself: the document DESCRIBES it, and it CONTAINS each
    component. With no SBOM the document has the root package only, which is a
    valid document that says nothing was inventoried.

    Fields ASH cannot know -- where a package was downloaded from, its concluded
    license, its copyright text -- are NOASSERTION, which is SPDX's way of saying
    the creator makes no claim, rather than invented values.
    """
    metadata = model.metadata
    project_name = str(getattr(metadata, "project_name", None) or "ASH")
    workspace_project = getattr(metadata, "workspace_project", None)
    if isinstance(workspace_project, str) and workspace_project:
        project_name = f"{project_name}/{workspace_project}"
    generated_at = getattr(metadata, "generated_at", None)
    report_id = getattr(metadata, "report_id", None)

    document_identity = "|".join(
        str(part) for part in (project_name, report_id, generated_at) if part
    )
    namespace = (
        f"{_NAMESPACE_BASE}/{_SPDX_ID_UNSAFE.sub('-', project_name)}-"
        f"{uuid.uuid5(_NAMESPACE_UUID, document_identity)}"
    )

    components: List[Dict[str, Any]] = []
    # Every SBOM a scanner writes has metadata or a serial number; the default
    # model, and its dump read back from a results file, have neither (the
    # cyclonedx reporter's test for the same case).
    no_sbom = True
    if model.cyclonedx is not None:
        # exclude_unset as in cyclonedx_reporter: only what the SBOM actually says.
        bom = model.cyclonedx.model_dump(
            by_alias=True, exclude_unset=True, exclude_none=True, mode="json"
        )
        components = [c for c in bom.get("components") or [] if isinstance(c, dict)]
        no_sbom = not (bom.get("metadata") or bom.get("serialNumber") or components)

    root_package: Dict[str, Any] = {
        "SPDXID": ROOT_PACKAGE_SPDX_ID,
        "name": project_name,
        "downloadLocation": NOASSERTION,
        "filesAnalyzed": False,
        "licenseConcluded": NOASSERTION,
        "licenseDeclared": NOASSERTION,
        "copyrightText": NOASSERTION,
        "primaryPackagePurpose": "SOURCE",
    }
    if no_sbom:
        # A document with the root package only is valid, and before this it
        # was byte-identical to the document of a project with no dependencies.
        root_package["comment"] = NO_SBOM_COMMENT

    packages: List[Dict[str, Any]] = [root_package]
    relationships: List[Dict[str, str]] = [
        {
            "spdxElementId": DOCUMENT_SPDX_ID,
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": ROOT_PACKAGE_SPDX_ID,
        }
    ]
    extracted: Dict[str, Dict[str, str]] = {}
    counter = itertools.count(1)

    def add(items: List[Dict[str, Any]], parent_spdx_id: str) -> None:
        # Depth first, so a component's nested ``components`` (CycloneDX's
        # assemblies, a bundled dependency's own dependencies) become packages
        # CONTAINED by their parent package. Reading the top level alone left
        # them out, so this document and the CycloneDX report listed different
        # inventories for one scan.
        for component in items:
            package = _package(component, next(counter), extracted)
            packages.append(package)
            relationships.append(
                {
                    "spdxElementId": parent_spdx_id,
                    "relationshipType": "CONTAINS",
                    "relatedSpdxElement": package["SPDXID"],
                }
            )
            nested = component.get("components")
            if isinstance(nested, list):
                add([c for c in nested if isinstance(c, dict)], package["SPDXID"])

    add(components, ROOT_PACKAGE_SPDX_ID)

    document: Dict[str, Any] = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": "CC0-1.0",
        "SPDXID": DOCUMENT_SPDX_ID,
        "name": f"{project_name} ASH SBOM",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": _spdx_created(generated_at),
            "creators": [f"Tool: automated-security-helper-{get_ash_version()}"],
        },
        "documentDescribes": [ROOT_PACKAGE_SPDX_ID],
        "packages": packages,
        "relationships": relationships,
    }
    if extracted:
        document["hasExtractedLicensingInfos"] = list(extracted.values())
    return document


@ash_reporter_plugin
class SpdxReporter(ReporterPluginBase[SPDXReporterConfig]):
    """Formats results as an SPDX 2.3 JSON document.

    This reporter used to be a stub that dumped the whole results model as YAML
    into ``ash.spdx.json``: a file that was neither SPDX nor JSON, which also
    made ``ash report --format spdx`` exit 1 when the CLI tried to print it as
    JSON. It now emits a real SPDX 2.3 document built from the scan's CycloneDX
    SBOM; see :func:`build_spdx_document`.

    Workspace mode: per project, on the same ground as ``cyclonedx_reporter`` --
    an SPDX document describes one package with one set of license and
    provenance conclusions, and N independently versioned deliverables are N
    documents. The unified workspace model carries no ``cyclonedx`` at all, so a
    workspace-level document would describe no packages while presenting itself
    as an inventory.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT

    def model_post_init(self, context):
        if self.config is None:
            self.config = SPDXReporterConfig()
        return super().model_post_init(context)

    def report(self, model: "AshAggregatedResults") -> str:
        """Format ASH model as SPDX 2.3 JSON."""
        return json.dumps(build_spdx_document(model), indent=2)
