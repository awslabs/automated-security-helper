# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""The scanner facets register: what each scanner's native output can map.

Every scanner class declares a :class:`ScannerFacets` as a class attribute
named :data:`SCANNER_FACETS_ATTR`, classifying each facet of
:data:`FACET_NAMES` as MAPPED (lands where the shared pipeline reads it),
MAPPABLE-BUT-DROPPED (the native output carries it; ASH discards it today -- a
roadmap record, not a promise), N/A (this scanner class cannot have it,
with the reason), or UNCONFIRMED (no real run of the tool has been read for
it, so it is a fixture owed, with the reason).

Why a declared descriptor and not a base-class hook or an inference from code:
a hook whose default returns ``None`` tests nothing -- a scanner that silently
never overrides it is indistinguishable from a scanner that cannot have the
facet -- and a register derived from the code it is supposed to check can
never fail. The distinction is DECLARED, and the registry totality test
(tests/unit/plugin_modules/test_scanner_facets_registry_totality.py) refuses
every registered scanner without a declaration of its own.

Why production code and not a tests-side table: ``ScannerPluginBase`` is a
public plugin API with out-of-tree members, which a tests-side table
could never enumerate; and the declaration has runtime consumers (generated
per-scanner docs rows; reporters that can say "this scanner cannot carry
resource ids" instead of implying absence is a gap).

Declaration rules, fail closed:

- Every facet name is a REQUIRED field of :class:`ScannerFacets`, so adding a
  facet to the vocabulary refuses every undeclared scanner at validation time:
  a new facet forces one conscious classification per scanner, never a silent
  default. The vocabulary meta-test pins ``model_fields`` to
  :data:`FACET_NAMES` so the tuple and the model cannot drift apart.
- A MAPPED or DROPPED cell names the native field verbatim; a DROPPED or N/A
  or UNCONFIRMED cell carries a one-line reason; a MAPPED ``resource_id`` additionally
  carries an example value from a real read (a committed fixture or a tool
  run). An UNREAD source is declared UNCONFIRMED with the reason (what was read
  instead, and the run that would settle it) -- the honest unconfirmed state is
  representable, never a guess, and never stretched into N/A, which the corpus
  gate reads as "a populated column is contamination".
- A value the ADAPTER writes where the tool wrote none (a constant line 1 or
  level, a path built from a package name) is classified by what a real read
  shows, not by who wrote it: MAPPED, with the cell opening "(no native <x>)"
  and naming the synthesis, when a committed capture or a tested adapter path
  shows the value on every result; UNCONFIRMED only when no read shows what
  the adapter writes. Where one adapter converts several native shapes (npm,
  yarn, pnpm), the cell states each path's source, or says which path lacks
  the value, rather than quoting the strongest path alone. An N/A cell whose
  reason says UNCONFIRMED is the documented form for "the tool might carry it
  and no read says"; the generated docs mark such a cell.
- ``resource_id`` values obey the resource value test: a value is a resource
  id only when it names an infrastructure/deployable resource (a terraform
  address, a CloudFormation logical id, a k8s object). Secret hashes, file
  paths, instructions, literals, in-file locators and package/image locators
  are NOT resource ids whatever field they sit in: the key binds
  resource-scoped suppressions (utils/package_identity.py
  ``ASH_RESOURCE_ID_KEY``), so a wrong value binds a suppression to a finding
  it was not written for. Missing only fails closed; wrong does damage.

The runtime pipeline keeps reading only the property-bag keys
(utils/package_identity.py ``extract_resource_identity``), exactly as before
this module existed: a third-party scanner that predates the register still
works, fail closed, and suppression semantics do not move.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, model_validator

#: The class attribute a scanner declares its register entry under. The
#: totality test reads it from ``vars(cls)`` -- the class's OWN dict -- so an
#: inherited declaration never satisfies it: a subclass (trivy-repo over the
#: shared trivy base, say) classifies its own output.
SCANNER_FACETS_ATTR = "facets"

#: The facet vocabulary, one name per thing a scanner's native output could
#: map into the shared pipeline. Each is a required field of
#: :class:`ScannerFacets`; the order here is the model's field order and the
#: generated docs' column order.
FACET_NAMES: tuple[str, ...] = (
    "rule_id",
    "severity",
    "file_path",
    "line_range",
    "column",
    "message",
    "resource_id",
    "resource_type",
    "package_name",
    "package_version",
    "package_path",
    "taxonomy_cve",
    "taxonomy_cwe",
    "fingerprints",
    "fix_available",
    "remediation_text",
    "snippet",
    "references",
    "tags",
    "extras",
)


class FacetState(str, Enum):
    """How one facet relates to one scanner's native output.

    A ``str`` mixin rather than ``enum.StrEnum`` because the project's floor
    is Python 3.10 and ``StrEnum`` arrived in 3.11 (the SARIF schema models
    record the same choice).
    """

    #: Lands where the shared pipeline reads it; conformance-tested.
    MAPPED = "mapped"
    #: The native output carries it; ASH discards it today. A roadmap record:
    #: mapping a DROPPED cell is its own later unit, decided per facet.
    DROPPED = "mappable-dropped"
    #: This scanner class cannot have it, with the reason. The corpus gate reads
    #: a populated column here as contamination, so the state is for a facet
    #: the tool's output cannot carry, never for one nobody has looked at.
    NA = "n/a"
    #: Nobody has read a real run of this tool's output for the facet, so the
    #: register can claim neither that it maps nor that it cannot exist. The
    #: corpus gate lists the cell as a fixture owed while its column is empty
    #: or has no corpus, and FAILS it once the column is populated (the cell
    #: is then settled or contaminated: redeclare it, or fix the adapter). The
    #: reference page says so. Reason required: what was read instead, and the
    #: run that would settle it.
    UNCONFIRMED = "unconfirmed"


class FacetDecl(BaseModel):
    """One facet's declaration: its state, and the evidence the state needs.

    The per-state requirements are validation, not etiquette: a MAPPED or
    DROPPED cell with no named native field, or a DROPPED, N/A or UNCONFIRMED
    cell with no reason, refuses to construct, so an unevidenced cell cannot
    enter the register at all.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    state: FacetState
    #: The native field carrying the value, verbatim, for MAPPED and DROPPED.
    native_field: Optional[str] = None
    #: One line, for NA, DROPPED and UNCONFIRMED: why the cell is what it is.
    reason: Optional[str] = None
    #: A value from a real read (fixture or tool run). Required for a MAPPED
    #: ``resource_id`` -- enforced by :class:`ScannerFacets`, which knows
    #: which facet this declaration sits under.
    example: Optional[str] = None

    @model_validator(mode="after")
    def _state_requirements(self) -> "FacetDecl":
        if (
            self.state in (FacetState.MAPPED, FacetState.DROPPED)
            and not (self.native_field or "").strip()
        ):
            raise ValueError(
                f"a {self.state.value} facet must name its native field "
                "verbatim; if the output was never read, declare unconfirmed "
                "with the reason instead"
            )
        if (
            self.state in (FacetState.NA, FacetState.DROPPED, FacetState.UNCONFIRMED)
            and not (self.reason or "").strip()
        ):
            raise ValueError(f"a {self.state.value} facet must carry a one-line reason")
        return self


class ScannerFacets(BaseModel):
    """A scanner's whole register row: one :class:`FacetDecl` per facet.

    Every facet in :data:`FACET_NAMES` is a required field and unknown fields
    are refused, so the model is total over the vocabulary by construction:
    a scanner cannot declare a subset, and a vocabulary change refuses every
    stale declaration instead of defaulting it.
    """

    model_config = ConfigDict(frozen=True, extra="forbid", hide_input_in_errors=True)

    rule_id: FacetDecl
    severity: FacetDecl
    file_path: FacetDecl
    line_range: FacetDecl
    column: FacetDecl
    message: FacetDecl
    resource_id: FacetDecl
    resource_type: FacetDecl
    package_name: FacetDecl
    package_version: FacetDecl
    package_path: FacetDecl
    taxonomy_cve: FacetDecl
    taxonomy_cwe: FacetDecl
    fingerprints: FacetDecl
    fix_available: FacetDecl
    remediation_text: FacetDecl
    snippet: FacetDecl
    references: FacetDecl
    tags: FacetDecl
    extras: FacetDecl

    @model_validator(mode="after")
    def _mapped_resource_id_carries_an_example(self) -> "ScannerFacets":
        """A mapped resource id proves itself with a value from a real read.

        The example is the declaration-level half of the "no assumed sources"
        rule: it cannot exist unless someone read a record. The fixture-level
        half (a conformance row over the recorded native output) is the test
        suite's.
        """
        if (
            self.resource_id.state is FacetState.MAPPED
            and not (self.resource_id.example or "").strip()
        ):
            raise ValueError(
                "a mapped resource_id requires an example value from a real "
                "read (a committed fixture or a tool run)"
            )
        return self
