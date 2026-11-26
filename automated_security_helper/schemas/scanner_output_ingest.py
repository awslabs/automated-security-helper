"""Read a scanner's report, repairing the parts ASH's model cannot hold.

Every scanner hands ASH a report written by another program: SARIF from most of
them, CycloneDX from syft. The models that read them are strict, and one value
they refuse, a region that starts on line 0, a link that is not a URL, a key the
spec does not define, used to cost the scanner its whole report: the model
raised, the scanner ended in ERROR, and every finding the tool had found in the
same run went with it.

This module reads a report through the model and, where the model refuses, drops
or rewrites the smallest part that is out of spec, notes what it changed, and
validates again. What it cannot repair it refuses, with the model's own error,
as the model would have on its own.

What may change. A part is repaired only when dropping or rewriting it cannot
change a finding's level, kind, suppression, rule reference, locations, message,
or the rule's id and default configuration: an unreadable region (the finding
stays, without its lines), a key the spec does not define, a link that is not a
URL, a date that does not parse, a number where the spec wants text (written as
its decimal text), a related location, a property. A value that would have to be
guessed to be kept (a ``level`` of ``info``, a missing ``message``, a suppression
of a kind the spec does not define, a bad notification the completeness gate
reads) is not repaired: the report is refused as before.

What the record holds. Each change is counted by kind and named by a pointer
built only from list indices and names the SARIF or CycloneDX schema defines; any
other key, which the tool chose (a property name, a fingerprint name), is written
``*``. The record holds no value from the report and no path, host or user name,
so it can go into a log line, a results file and a SARIF notification.

The input is never changed: a refused document is repaired on a copy.
"""

from __future__ import annotations

import contextlib
import copy
import functools
import json
import re
from typing import Any, Callable, Iterator, NamedTuple, Sequence

from pydantic import BaseModel, ValidationError

from automated_security_helper.schemas import (
    cyclonedx_bom_1_6_schema as _cyclonedx_module,
)
from automated_security_helper.schemas import sarif_schema_model as _sarif_module
from automated_security_helper.schemas.cyclonedx_bom_1_6_schema import CycloneDXReport
from automated_security_helper.schemas.sarif_schema_model import SarifReport

__all__ = [
    "IngestRecord",
    "ingest_cyclonedx",
    "ingest_sarif",
    "read_json_text_tolerant",
    "read_json_tolerant",
]

#: Rounds of "read the model's errors, repair, validate again" before the last
#: error is raised, and the most changes one document may take. A report that
#: needs more than this is not an out-of-spec element but a different format.
_MAX_ROUNDS = 8
_MAX_CHANGES = 10_000

#: Elements a record names; the rest are only counted.
_MAX_NAMED = 50

#: What a rule id may look like to be kept in a summary. Anything else (a path, a
#: URL, a sentence) is recorded as no rule id.
_RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

#: A scope label for a per-template or per-chunk reader: an ordinal, never a name.
_SCOPE_LABEL = re.compile(r"^[A-Za-z0-9 ._-]{1,40}$")

_BOM_BYTES = b"\xef\xbb\xbf"
_BOM_TEXT = _BOM_BYTES.decode("utf-8")

#: The lone surrogates ``surrogateescape`` makes of undecodable bytes, and any
#: surrogate at all. Built from code points so the source holds no escape that
#: an editor or a tool could turn into the character.
_ESCAPED_BYTE = re.compile(f"[{chr(0xDC80)}-{chr(0xDCFF)}]")
_ANY_SURROGATE = re.compile(f"[{chr(0xD800)}-{chr(0xDFFF)}]")

# --------------------------------------------------------------------------- #
# The record
# --------------------------------------------------------------------------- #

#: Words for the kinds of change, for a sentence. A code not listed here is
#: described by its pattern (see :func:`_phrase`); no phrase quotes the report.
_PHRASES = {
    "bom": "a byte-order mark before the document",
    "bytes_not_utf8": "bytes that are not valid UTF-8",
    "control_character": "a control character inside a string",
    "region_line_unreadable": "a region with no readable line",
    "region_field_unreadable": "a region field that is out of range",
    "fix_unreadable": "a fix with a region that cannot be read",
    "unknown_key": "a key the schema does not define",
    "number_as_text": "a number where the schema wants text",
    "tag_not_text": "a tag that is not text",
    "property_unreadable": "a property that cannot be read",
    "fingerprint_unreadable": "a fingerprint that cannot be read",
    "rule_field_unreadable": "a rule field that cannot be read",
    "tool_field_unreadable": "a tool field that cannot be read",
    "invocation_field_unreadable": "an invocation field that cannot be read",
    "run_field_unreadable": "a run field that cannot be read",
    "indexed_field_unreadable": "a field of a referenced artifact or location that "
    "cannot be read",
    "document_field_unreadable": "a document field that cannot be read",
    "metadata_field_unreadable": "a metadata field that cannot be read",
    "dependency_entry_unreadable": "a dependency entry that cannot be read",
    "result_unreadable:missing": "a required field missing",
    "result_unreadable:string_type": "a field of the wrong type",
    "result_unreadable:int_type": "a field of the wrong type",
    "result_unreadable:enum": "a value the schema does not allow",
    "result_unreadable:literal_error": "a value the schema does not allow",
    "result_unreadable:greater_than_equal": "a number out of range",
    "result_unreadable:less_than_equal": "a number out of range",
    "result_unreadable:url_parsing": "a link that is not a URL",
    "result_unreadable:datetime_from_date_parsing": "a date ASH cannot read",
    "result_unreadable:datetime_parsing": "a date ASH cannot read",
    "result_unreadable:string_unicode": "text that is not valid Unicode",
    "component_unreadable": "a component that cannot be read",
}


def _phrase(code: str) -> str:
    """The words for *code*: the table, then its pattern, then a plain default."""
    phrase = _PHRASES.get(code)
    if phrase is not None:
        return phrase
    if code.endswith("_entry_unreadable"):
        return "an entry that cannot be read"
    if code.endswith("_unreadable"):
        return "a field that cannot be read"
    return "a part that the schema does not allow"


@functools.lru_cache(maxsize=1)
def _known_names() -> frozenset[str]:
    """Every field name and alias of the SARIF and CycloneDX models.

    A pointer writes these as they are; any other key is the tool's own and is
    written ``*`` (property names, fingerprint names, hash algorithms, base ids).
    """
    names = {"$schema"}
    for module in (_sarif_module, _cyclonedx_module):
        for value in vars(module).values():
            if not (isinstance(value, type) and issubclass(value, BaseModel)):
                continue
            for name, field in value.model_fields.items():
                names.add(name)
                for alias in (field.alias, field.validation_alias):
                    if isinstance(alias, str):
                        names.add(alias)
    names.discard("root")
    return frozenset(names)


class IngestRecord:
    """What reading one target's report changed. Plain data: it pickles.

    ``results_read`` counts what the tool's document held (results, or components
    for an SBOM); ``repaired`` counts the parts dropped or rewritten with their
    finding kept; ``left_out`` counts whole results or components that were left
    out. Nothing here holds a value from the report (see the module docstring).
    """

    def __init__(self) -> None:
        self.results_read: int = 0
        self.repaired: int = 0
        self.left_out: int = 0
        self.format_name: str = "SARIF"
        self._counts: dict[tuple[str, str], int] = {}
        self._named: list[tuple[str, str, str, str | None]] = []
        self._not_listed: int = 0
        self._scope: str | None = None

    def __repr__(self) -> str:
        return (
            f"IngestRecord(results_read={self.results_read}, "
            f"repaired={self.repaired}, left_out={self.left_out})"
        )

    @property
    def is_empty(self) -> bool:
        """Whether the read changed nothing."""
        return not self._counts

    @contextlib.contextmanager
    def scoped(self, label: str) -> Iterator[None]:
        """Prefix the pointers noted inside the block with *label*.

        For a reader that makes one document per input (``template 3``, ``chunk
        2``): the label is the input's ordinal, never its name. A label that is
        not a short ordinal is replaced by ``input``.
        """
        previous = self._scope
        self._scope = label if _SCOPE_LABEL.fullmatch(label) else "input"
        try:
            yield
        finally:
            self._scope = previous

    def note(
        self,
        action: str,
        code: str,
        pointer: Sequence[str | int] = (),
        *,
        rule_id: object = None,
        count: int = 1,
    ) -> None:
        """Record *count* changes of one kind at one place.

        *action* is ``dropped``, ``rewritten`` or ``left_out``; *code* names the
        kind; *pointer* is the raw path of the element in the tool's own
        document. A rule id is kept only when it is a plain identifier.
        """
        if count < 1:
            return
        if action == "left_out":
            self.left_out += count
        else:
            self.repaired += count
        key = (action, code)
        self._counts[key] = self._counts.get(key, 0) + count
        if len(self._named) < _MAX_NAMED:
            self._named.append(
                (
                    action,
                    code,
                    self._pointer_text(pointer),
                    rule_id
                    if isinstance(rule_id, str) and _RULE_ID.fullmatch(rule_id)
                    else None,
                )
            )
        else:
            self._not_listed += 1

    def _pointer_text(self, pointer: Sequence[str | int]) -> str:
        known = _known_names()
        parts = [
            str(token) if isinstance(token, int) or token in known else "*"
            for token in pointer
        ]
        text = "/".join(parts) if parts else "(document)"
        return f"{self._scope}: {text}" if self._scope else text

    def summary(self) -> dict | None:
        """The record as plain JSON, or ``None`` when nothing was noted."""
        if not self._counts:
            return None
        return {
            "results_read": self.results_read,
            "repaired": self.repaired,
            "left_out": self.left_out,
            "changes": [
                {"action": action, "code": code, "count": count}
                for (action, code), count in sorted(self._counts.items())
            ],
            "elements": [
                {"action": action, "code": code, "pointer": pointer, "rule_id": rule}
                for action, code, pointer, rule in self._named
            ],
            "elements_not_listed": self._not_listed,
        }

    def sentence(self, source: str | None = None) -> str | None:
        """One line for a log or a reason: counts and kinds, no value, no path.

        *source* is the scanner's name; without it the line says "this scanner's".
        """
        if not self._counts:
            return None
        if source:
            whose = (
                f"{source}' report" if source.endswith("s") else f"{source}'s report"
            )
        else:
            whose = "this scanner's report"
        clauses = []
        if self.repaired:
            clauses.append(
                f"ASH repaired {self.repaired} "
                f"{'part' if self.repaired == 1 else 'parts'} of {whose} that "
                f"{self.format_name} does not allow ({self._kinds('repaired')})."
            )
        if self.left_out:
            clauses.append(
                f"ASH left out {self.left_out} of the {self.results_read} "
                f"{'result' if self.results_read == 1 else 'results'} its tool "
                f"reported, which it could not read ({self._kinds('left_out')})."
            )
        return " ".join(clauses)

    def _kinds(self, which: str) -> str:
        tally: dict[str, int] = {}
        for (action, code), count in self._counts.items():
            if (action == "left_out") == (which == "left_out"):
                phrase = _phrase(code)
                tally[phrase] = tally.get(phrase, 0) + count
        ordered = sorted(tally.items(), key=lambda item: (-item[1], item[0]))
        phrases = [phrase for phrase, _ in ordered[:3]]
        if len(ordered) > 3:
            phrases.append(f"and {len(ordered) - 3} more kinds")
        return ", ".join(phrases)

    def notifications(self) -> list[dict]:
        """The record as SARIF notifications, level ``warning``.

        A ``warning`` is not read by the unevaluated-rules gate, which fails a
        run only on ``error``; the repairs say so in the report without failing
        a scan that kept every finding.
        """
        sentence = self.sentence()
        if sentence is None:
            return []
        return [
            {
                "level": "warning",
                "message": {"text": sentence},
                "properties": {"ash_output_ingest": self.summary()},
            }
        ]


# --------------------------------------------------------------------------- #
# Reading the bytes
# --------------------------------------------------------------------------- #


def read_json_tolerant(data: bytes, record: IngestRecord) -> Any:
    """Parse a tool's JSON file, keeping what strict parsing would refuse.

    A leading byte-order mark is dropped; bytes that are not UTF-8 are read as
    the lone surrogates ASH already holds undecodable file names as; a raw
    control character inside a string is accepted. Each is noted. Any other
    error is raised as ``json.loads`` raises it, and an empty file is ``None``.
    """
    if data.startswith(_BOM_BYTES):
        data = data[len(_BOM_BYTES) :]
        record.note("rewritten", "bom")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="surrogateescape")
        record.note(
            "rewritten",
            "bytes_not_utf8",
            count=max(1, len(_ESCAPED_BYTE.findall(text))),
        )
    return read_json_text_tolerant(text, record)


def read_json_text_tolerant(text: str, record: IngestRecord) -> Any:
    """:func:`read_json_tolerant` for text a tool already gave as ``str``."""
    if text.startswith(_BOM_TEXT):
        text = text[len(_BOM_TEXT) :]
        record.note("rewritten", "bom")
    if not text.strip():
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        if not error.msg.startswith("Invalid control character"):
            raise
        first = error
    try:
        value = json.loads(text, strict=False)
    except json.JSONDecodeError:
        raise first from None
    record.note("rewritten", "control_character")
    return value


# --------------------------------------------------------------------------- #
# Reading the document through a model
# --------------------------------------------------------------------------- #


class _Change(NamedTuple):
    """One repair: ``drop`` the node at *path*, or ``set_text`` it to its text."""

    kind: str
    path: tuple
    code: str
    #: What it gives up, to choose the smaller repair when a union offers two:
    #: 0 a rewrite, 1 a field or map entry, 2 a list element.
    rank: int


class _Error(NamedTuple):
    """One model error placed on the raw document."""

    path: tuple
    #: Where the model's loc could not be followed: a required field that is
    #: missing, named last.
    tail: tuple
    #: ``(depth, member)`` for each union the loc passes through, outermost
    #: first; *depth* is how many resolved tokens precede the member.
    unions: tuple
    change: _Change | None


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _resolve(doc: Any, loc: Sequence[str | int]) -> tuple[tuple, tuple, tuple, Any]:
    """Follow the model's *loc* into the raw *doc*.

    A token that is a key of the current object, or an index of the current list,
    descends. A token that is neither and is not last is a union member or
    validator name pydantic put between two keys, and is skipped (remembered, so
    the members of one union can be told apart). A last token that is not found
    names a required field that is missing.
    """
    node = doc
    path: list[str | int] = []
    unions: list[tuple[int, str]] = []
    last = len(loc) - 1
    for position, token in enumerate(loc):
        if isinstance(node, dict) and isinstance(token, str) and token in node:
            node = node[token]
            path.append(token)
        elif (
            isinstance(node, list)
            and isinstance(token, int)
            and not isinstance(token, bool)
            and 0 <= token < len(node)
        ):
            node = node[token]
            path.append(token)
        elif position < last and isinstance(token, str):
            unions.append((len(path), token))
        else:
            return tuple(path), tuple(loc[position:]), tuple(unions), node
    return tuple(path), (), tuple(unions), node


def _get(doc: Any, path: Sequence[str | int]) -> Any:
    node = doc
    for token in path:
        node = node[token]
    return node


def _sort_key(path: tuple) -> tuple:
    return tuple((0, token) if isinstance(token, int) else (1, token) for token in path)


# --- the SARIF part table ---------------------------------------------------- #

_REGION_KEYS = ("region", "contextRegion")

_RESULT_FIELDS = frozenset(
    {
        "rank",
        "guid",
        "correlationGuid",
        "occurrenceCount",
        "baselineState",
        "hostedViewerUri",
        "provenance",
        "analysisTarget",
        "webRequest",
        "webResponse",
    }
)
_RESULT_LISTS = frozenset(
    {
        "relatedLocations",
        "codeFlows",
        "fixes",
        "stacks",
        "attachments",
        "graphs",
        "graphTraversals",
        "taxa",
        "workItemUris",
    }
)
_RULE_FIELDS = frozenset(
    {
        "helpUri",
        "help",
        "fullDescription",
        "shortDescription",
        "messageStrings",
        "name",
        "guid",
        "deprecatedIds",
        "deprecatedGuids",
        "deprecatedNames",
        "relationships",
        "properties",
    }
)
_RUN_FIELDS = frozenset(
    {
        "versionControlProvenance",
        "originalUriBaseIds",
        "automationDetails",
        "runAggregates",
        "baselineGuid",
        "conversion",
        "language",
        "newlineSequences",
        "columnKind",
        "redactionTokens",
        "defaultEncoding",
        "defaultSourceLanguage",
        "specialLocations",
        "webRequests",
        "webResponses",
        "externalPropertyFileReferences",
    }
)
#: Run fields that hold a map or a list, where one bad entry costs only itself.
_RUN_ELEMENT_FIELDS = frozenset(
    {
        "versionControlProvenance",
        "originalUriBaseIds",
        "runAggregates",
        "webRequests",
        "webResponses",
    }
)
#: Run lists other parts refer to by index: never an element, only a field in it.
_INDEXED_RUN_LISTS = frozenset(
    {
        "artifacts",
        "logicalLocations",
        "threadFlowLocations",
        "graphs",
        "addresses",
        "taxonomies",
        "policies",
        "translations",
    }
)
_INDEXED_FIELDS = frozenset(
    {
        "roles",
        "lastModifiedTimeUtc",
        "mimeType",
        "encoding",
        "sourceLanguage",
        "description",
        "length",
        "offset",
    }
)


def _drop(path: tuple, length: int, code: str, rank: int = 1) -> _Change:
    return _Change("drop", path[:length], code, rank)


def _bag_change(path: tuple, bag: int, code: str = "property_unreadable") -> _Change:
    """A repair for an error under the property bag at ``path[bag]``.

    The bag itself when it is the error, a tag that is not text, or the one
    property that cannot be read: what the tool put in a bag changes no finding.
    """
    rest = path[bag + 1 :]
    if not rest:
        return _drop(path, bag + 1, code)
    if rest[0] == "tags":
        if len(rest) == 1:
            return _drop(path, bag + 2, code)
        return _drop(path, bag + 3, "tag_not_text", 2)
    return _drop(path, bag + 2, code)


def _region_change(path: tuple) -> _Change | None:
    """An error inside a region: drop the region, or only the field."""
    for index in range(len(path) - 1, 0, -1):
        if path[index] in _REGION_KEYS and path[index - 1] == "physicalLocation":
            if index == len(path) - 1:
                return _drop(path, index + 1, "region_field_unreadable")
            if path[index + 1] == "startLine":
                return _drop(path, index + 1, "region_line_unreadable")
            return _drop(path, index + 2, "region_field_unreadable")
    return None


def _fix_change(path: tuple) -> _Change | None:
    """An error in a fix's ``deletedRegion``: the fix cannot be applied, so it goes."""
    if "deletedRegion" not in path or "fixes" not in path:
        return None
    start = path.index("fixes")
    if start + 1 < len(path) and isinstance(path[start + 1], int):
        return _drop(path, start + 2, "fix_unreadable", 2)
    return None


def _result_change(path: tuple) -> _Change | None:
    if len(path) < 5 or not isinstance(path[3], int):
        return None
    field = path[4]
    if field in _RESULT_FIELDS:
        return _drop(path, 5, f"{field}_unreadable")
    if field in _RESULT_LISTS:
        if len(path) >= 6 and isinstance(path[5], int):
            return _drop(path, 6, f"{field}_entry_unreadable", 2)
        return _drop(path, 5, f"{field}_unreadable")
    if field == "properties":
        return _bag_change(path, 4)
    if field in ("fingerprints", "partialFingerprints"):
        return _drop(path, 5 if len(path) == 5 else 6, "fingerprint_unreadable")
    return None


def _descriptor_change(path: tuple, element: int) -> _Change | None:
    """A rule or notification descriptor: the field goes; never the id or the
    default configuration."""
    rest = path[element + 1 :]
    if not rest or rest[0] not in _RULE_FIELDS:
        return None
    field = rest[0]
    if field == "properties":
        return _bag_change(path, element + 1, "rule_field_unreadable")
    if field == "relationships" and len(rest) >= 2:
        return _drop(path, element + 3, "rule_field_unreadable", 2)
    return _drop(path, element + 2, "rule_field_unreadable")


def _tool_change(path: tuple) -> _Change | None:
    if len(path) < 4:
        return None
    if path[3] == "driver":
        component = 4
    elif path[3] == "extensions" and len(path) >= 5 and isinstance(path[4], int):
        component = 5
    else:
        return None
    rest = path[component:]
    if not rest:
        return None
    field = rest[0]
    if field in ("rules", "notifications"):
        if len(rest) >= 2 and isinstance(rest[1], int):
            return _descriptor_change(path, component + 1)
        return None
    if field in ("name", "taxa"):
        return None
    if field == "properties":
        return _bag_change(path, component, "tool_field_unreadable")
    return _drop(path, component + 1, "tool_field_unreadable")


def _invocation_change(path: tuple) -> _Change | None:
    """The tool's own invocation: ASH reads only whether it succeeded and what it
    reported; every other field may go."""
    if len(path) < 5 or not isinstance(path[3], int):
        return None
    field = path[4]
    if field in ("executionSuccessful", "toolExecutionNotifications"):
        return None
    if field == "properties":
        return _bag_change(path, 4, "invocation_field_unreadable")
    return _drop(path, 5, "invocation_field_unreadable")


def _run_change(path: tuple) -> _Change | None:
    field = path[2]
    if field == "properties":
        return _bag_change(path, 2, "run_field_unreadable")
    if field in _RUN_ELEMENT_FIELDS and len(path) >= 4:
        return _drop(
            path, 4, "run_field_unreadable", 2 if isinstance(path[3], int) else 1
        )
    if field in _RUN_FIELDS:
        return _drop(path, 3, "run_field_unreadable")
    if field in _INDEXED_RUN_LISTS and len(path) >= 5 and isinstance(path[3], int):
        sub = path[4]
        if sub == "properties":
            return _bag_change(path, 4, "indexed_field_unreadable")
        if sub == "hashes" and len(path) >= 6:
            return _drop(path, 6, "indexed_field_unreadable")
        if sub in _INDEXED_FIELDS or sub == "hashes":
            return _drop(path, 5, "indexed_field_unreadable")
    return None


def _classify_sarif(path: tuple, tail: tuple, etype: str, value: Any) -> _Change | None:
    """The repair for one error at *path* in a SARIF document, or ``None``."""
    if etype == "string_type" and not tail and _is_number(value):
        return _Change("set_text", path, "number_as_text", 0)
    if etype == "extra_forbidden" and path and not tail:
        return _drop(path, len(path), "unknown_key")
    change = _region_change(path) or _fix_change(path)
    if change is not None:
        return change
    if len(path) < 3 or path[0] != "runs" or not isinstance(path[1], int):
        return None
    section = path[2]
    if section == "results":
        return _result_change(path)
    if section == "tool":
        return _tool_change(path)
    if section == "invocations":
        return _invocation_change(path)
    return _run_change(path)


# --- the CycloneDX part table ------------------------------------------------ #

_CDX_COMPONENT_FIELDS = frozenset(
    {
        "description",
        "publisher",
        "supplier",
        "author",
        "authors",
        "externalReferences",
        "hashes",
        "properties",
        "cpe",
        "purl",
        "licenses",
    }
)
#: What a CycloneDX document must keep for ASH to read it at all.
_CDX_KEPT_FIELDS = frozenset({"bomFormat", "specVersion", "version", "components"})


def _classify_cyclonedx(
    path: tuple, tail: tuple, etype: str, value: Any
) -> _Change | None:
    """The repair for one error at *path* in a CycloneDX document, or ``None``."""
    if etype == "string_type" and not tail and _is_number(value):
        return _Change("set_text", path, "number_as_text", 0)
    if etype == "extra_forbidden" and path and not tail:
        return _drop(path, len(path), "unknown_key")
    for index in range(len(path) - 2, -1, -1):
        if path[index] == "components" and isinstance(path[index + 1], int):
            rest = path[index + 2 :]
            if not rest or rest[0] not in _CDX_COMPONENT_FIELDS:
                return None
            field = rest[0]
            if len(rest) >= 2 and isinstance(rest[1], int):
                return _drop(path, index + 4, f"{field}_entry_unreadable", 2)
            return _drop(path, index + 3, f"{field}_unreadable")
    if not path:
        return None
    if path[0] == "dependencies":
        if len(path) >= 2 and isinstance(path[1], int):
            return _drop(path, 2, "dependency_entry_unreadable", 2)
        return None
    if path[0] == "metadata":
        return _drop(path, min(len(path), 2), "metadata_field_unreadable")
    if path[0] not in _CDX_KEPT_FIELDS and path[0] != "dependencies":
        return _drop(path, 1, "document_field_unreadable")
    return None


# --- choosing and applying repairs ------------------------------------------- #

Classifier = Callable[[tuple, tuple, str, Any], "_Change | None"]


def _place(doc: Any, error: ValidationError, classify: Classifier) -> list[_Error]:
    """Every error of *error*, placed on the raw *doc* and classified."""
    placed = []
    for item in error.errors(
        include_input=False, include_url=False, include_context=False
    ):
        path, tail, unions, value = _resolve(doc, item["loc"])
        etype = item["type"]
        if etype == "string_unicode" and isinstance(value, dict) and not tail:
            # The model names the bag, not the key it could not hold.
            for key, entry in value.items():
                if isinstance(key, str) and _ANY_SURROGATE.search(key):
                    where = path + (key,)
                    placed.append(
                        _Error(where, (), unions, classify(where, (), etype, entry))
                    )
            continue
        placed.append(_Error(path, tail, unions, classify(path, tail, etype, value)))
    return placed


def _cost(changes: list[_Change]) -> tuple[int, int]:
    return (max((change.rank for change in changes), default=0), len(changes))


def _choose(errors: list[_Error], level: int, strict: bool) -> list[_Change] | None:
    """The changes that answer *errors*, choosing one member of each union.

    A union (a physical location is one of two shapes, a message one of two)
    validates when any member does, and the model reports every member's errors.
    One member whose errors can all be repaired is enough, and the member that
    gives up least is chosen. With *strict* a group that cannot be answered
    makes the whole answer ``None``; without it that group is left as it is, so
    the model reports it again and the rest is still repaired.
    """
    changes: list[_Change] = []
    groups: dict[tuple, dict[str, list[_Error]]] = {}
    for error in errors:
        if len(error.unions) > level:
            depth, member = error.unions[level]
            groups.setdefault((error.path[:depth], depth), {}).setdefault(
                member, []
            ).append(error)
        elif error.change is not None:
            changes.append(error.change)
        elif strict:
            return None
    for members in groups.values():
        best: list[_Change] | None = None
        for member_errors in members.values():
            answer = _choose(member_errors, level + 1, strict=True)
            if answer is not None and (best is None or _cost(answer) < _cost(best)):
                best = answer
        if best is not None:
            changes.extend(best)
        elif strict:
            return None
    return changes


def _minimal(changes: list[_Change]) -> list[_Change]:
    """*changes* without duplicates and without any under a node that is dropped."""
    dropped = {change.path for change in changes if change.kind == "drop"}
    kept: dict[tuple[str, tuple], _Change] = {}
    for change in changes:
        if not change.path:
            continue
        if any(change.path[:size] in dropped for size in range(len(change.path))):
            continue
        if change.kind == "set_text" and change.path in dropped:
            continue
        kept.setdefault((change.kind, change.path), change)
    return sorted(kept.values(), key=lambda change: _sort_key(change.path))


def _original(path: tuple, removed: dict[tuple, list[int]]) -> tuple:
    """*path* as it was in the tool's own document, before earlier rounds took
    elements out of lists."""
    original: list[str | int] = []
    for token in path:
        if isinstance(token, int):
            for gone in sorted(removed.get(tuple(original), ())):
                if gone <= token:
                    token += 1
        original.append(token)
    return tuple(original)


def _rule_id_of(doc: Any, path: tuple) -> object:
    """The rule id of the result *path* is inside, when it names one."""
    if len(path) >= 4 and path[0] == "runs" and path[2] == "results":
        try:
            return _get(doc, path[:4]).get("ruleId")
        except (KeyError, IndexError, TypeError, AttributeError):
            return None
    return None


def _apply(
    doc: Any,
    changes: list[_Change],
    removed: dict[tuple, list[int]],
    record: IngestRecord,
) -> None:
    """Note and make *changes* on *doc*.

    The notes use the tool's own coordinates (``removed`` is what earlier rounds
    took out of lists), and the edits go from the last path to the first so a
    list index a later edit names has not moved.
    """
    noted = [
        (
            change,
            _original(change.path, removed),
            _rule_id_of(doc, change.path),
        )
        for change in changes
    ]
    for change, original, rule_id in noted:
        record.note(
            "dropped" if change.kind == "drop" else "rewritten",
            change.code,
            original,
            rule_id=rule_id,
        )
    for change in sorted(changes, key=lambda item: _sort_key(item.path), reverse=True):
        parent = _get(doc, change.path[:-1])
        key = change.path[-1]
        if change.kind == "drop":
            del parent[key]
        else:
            parent[key] = str(parent[key])
    for change, original, _ in noted:
        if change.kind == "drop" and isinstance(change.path[-1], int):
            removed.setdefault(original[:-1], []).append(original[-1])


def _ingest(
    raw: Any,
    record: IngestRecord,
    *,
    model: type[BaseModel],
    classify: Classifier,
    format_name: str,
    count_results: Callable[[Any], int],
) -> Any:
    record.format_name = format_name
    try:
        report = model.model_validate(raw)
    except ValidationError as error:
        last = error
    else:
        record.results_read += count_results(raw)
        return report
    try:
        doc = copy.deepcopy(raw)
    except RecursionError:
        # Too deeply nested to copy, so too deeply nested to repair.
        raise last from None
    removed: dict[tuple, list[int]] = {}
    spent = 0
    for _ in range(_MAX_ROUNDS):
        changes = _minimal(_choose(_place(doc, last, classify), 0, strict=False) or [])
        changes = changes[: _MAX_CHANGES - spent]
        if not changes:
            break
        spent += len(changes)
        try:
            _apply(doc, changes, removed, record)
        except (KeyError, IndexError, TypeError, ValueError):
            break
        try:
            report = model.model_validate(doc)
        except ValidationError as error:
            last = error
            continue
        record.results_read += count_results(raw)
        return report
    raise last


def _sarif_result_count(raw: Any) -> int:
    if not isinstance(raw, dict) or not isinstance(raw.get("runs"), list):
        return 0
    return sum(
        len(run["results"])
        for run in raw["runs"]
        if isinstance(run, dict) and isinstance(run.get("results"), list)
    )


def _cyclonedx_component_count(raw: Any) -> int:
    if isinstance(raw, dict) and isinstance(raw.get("components"), list):
        return len(raw["components"])
    return 0


def ingest_sarif(raw: Any, record: IngestRecord) -> SarifReport:
    """*raw*, a tool's SARIF as parsed JSON, as a ``SarifReport``.

    A valid document costs what ``SarifReport.model_validate`` costs, and the
    record stays empty. A document the model refuses is repaired on a copy, part
    by part, as the module docstring describes, and each repair is noted; a
    document that still cannot be read raises the model's own last
    ``ValidationError``, naming only the errors that remain. *raw* is not
    changed.
    """
    return _ingest(
        raw,
        record,
        model=SarifReport,
        classify=_classify_sarif,
        format_name="SARIF",
        count_results=_sarif_result_count,
    )


def ingest_cyclonedx(raw: Any, record: IngestRecord) -> CycloneDXReport:
    """:func:`ingest_sarif` for a CycloneDX document, with its own part table."""
    return _ingest(
        raw,
        record,
        model=CycloneDXReport,
        classify=_classify_cyclonedx,
        format_name="CycloneDX",
        count_results=_cyclonedx_component_count,
    )
