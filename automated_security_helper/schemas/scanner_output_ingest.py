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
URL, a date that does not parse, an integer where the spec wants text (written as
its decimal text), a related location, a property. A number with a fraction or an
exponent is not rewritten as text: reading it as a float lost the digits the tool
wrote (``1.10`` reads as ``1.1``), and a rule id or a version must not change.

What is not repaired. A value that would have to be guessed to be kept (a
``level`` of ``info``, a missing ``message``, a suppression of a kind the spec
does not define) and a part ASH reads or resolves through (a notification, a
configuration override, the ``uri`` or ``uriBaseId`` of a base id a location is
resolved against, a CycloneDX vulnerability) are not repaired: the report is
refused as before.

What the record holds. Each change is counted by kind and named by a pointer
built only from list indices, names the SARIF or CycloneDX schema defines and the
field names of the tool reports the converters read (``_TOOL_FIELDS``, a fixed
list); any other key, which the tool chose (a property name, a fingerprint name, a
package name), is written ``*``. The record holds no value from the report and no
path, host or user name, so it can go into a log line, a results file and a SARIF
notification. A read that is refused leaves the changes its attempt made to the
copy it discarded: a reader that goes on after a refusal rolls the record back
(``checkpoint`` and ``rollback``), and none says what was repaired of a report it
did not read.

Converters. A scanner that builds its SARIF from the tool's own JSON (npm audit,
GuardDog, detect-secrets, actionlint, cdk-nag) repairs the one field it cannot
convert where it converts, and notes it on the same record with a pointer into
the tool's JSON: :meth:`IngestRecord.text_or` and :meth:`IngestRecord.url_or_none`
are the two repairs they share. A record made in another process (cdk-nag's
worker) crosses as its :meth:`~IngestRecord.summary` and is read back with
:meth:`~IngestRecord.from_summary` and added with :meth:`~IngestRecord.absorb`.

The input is never changed: a refused document is repaired on a copy.
"""

from __future__ import annotations

import contextlib
import copy
import functools
import json
import re
from typing import Any, Callable, Iterator, NamedTuple, Sequence, TypeVar

from pydantic import AnyUrl, BaseModel, TypeAdapter, ValidationError

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

#: The longest pointer a record read back from JSON keeps. A pointer is a handful
#: of names and indices, so a longer one is not a pointer this module wrote.
_MAX_POINTER = 400

#: What a rule id may look like to be kept in a summary. Anything else (a path, a
#: URL, a sentence) is recorded as no rule id.
_RULE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

#: A scope label for a per-template or per-chunk reader: a lowercase word and an
#: ordinal, ``template 3`` or ``batch 2.1``. Never a name: a file name would fit
#: any looser pattern.
_SCOPE_LABEL = re.compile(r"^[a-z]+ [0-9]{1,6}(\.[0-9]{1,6})?$")

#: The field names of the tool reports the converters read, which a pointer may
#: write as they are when the SARIF and CycloneDX models do not define them (npm
#: audit's ``via``, GuardDog's ``risks`` and its ``threat_*`` fields, detect-secrets'
#: ``line_number``, actionlint's ``errors``, cdk-nag's ``pluginReports``). Names
#: the code reads, never a key the tool chose.
_TOOL_FIELDS = frozenset(
    {
        "via",
        "risks",
        "threat_description",
        "threat_code",
        "threat_location",
        "file_path",
        "mitre_tactics",
        "code",
        "match",
        "line_number",
        "errors",
        "pluginReports",
        "violations",
        "ruleName",
    }
)

#: What a link must be for a SARIF link field to take it: the model's own type, so
#: a link this accepts is one the model accepts.
_LINK = TypeAdapter(AnyUrl)

#: What :meth:`IngestRecord.text_or` falls back to: text for a caller that has a
#: text to put in its place, ``None`` for one that leaves the field out. Its
#: answer is text or the fallback's own type.
_Fallback = TypeVar("_Fallback")

#: A record's kinds of change, as ``summary`` writes them.
_ACTIONS = frozenset({"dropped", "rewritten", "left_out"})
_CODE = re.compile(r"^[a-z][a-z0-9_:]{0,95}$")

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
    "text_as_number": "a number written as text",
    "title_not_text": "a title that is not text",
    "field_not_text": "a field that is not text",
    "text_not_unicode": "text that is not valid Unicode",
    "url_not_absolute": "a link that is not an absolute URL",
    "side_report_unreadable": "a side report that cannot be read",
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


def _scope_label(label: str) -> str:
    """*label* when it is a scope label (a word and an ordinal), else ``input``."""
    return label if _SCOPE_LABEL.fullmatch(label) else "input"


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
    return frozenset(names) | _TOOL_FIELDS


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

    def checkpoint(self) -> dict[str, Any]:
        """The record as it is now, for :meth:`rollback`."""
        return copy.deepcopy(self.__dict__)

    def rollback(self, checkpoint: dict[str, Any]) -> None:
        """Forget what was noted since *checkpoint*, which this record gave.

        For a reader that makes one document per input and goes on when one is
        refused: the repairs made on a document that was then left unread
        changed nothing the report keeps, so they are not counted.
        """
        self.__dict__.clear()
        self.__dict__.update(copy.deepcopy(checkpoint))

    @contextlib.contextmanager
    def scoped(self, label: str) -> Iterator[None]:
        """Prefix the pointers noted inside the block with *label*.

        For a reader that makes one document per input (``template 3``, ``chunk
        2``): the label is a word and the input's ordinal, never its name. A
        label of any other form is replaced by ``input``.
        """
        previous = self._scope
        self._scope = _scope_label(label)
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

    def summary(self) -> dict[str, Any] | None:
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

    def notifications(self, source: str | None = None) -> list[dict[str, Any]]:
        """The record as SARIF notifications, level ``warning``.

        A ``warning`` is not read by the unevaluated-rules gate, which fails a
        run only on ``error``; the repairs say so in the report without failing
        a scan that kept every finding. *source* is the scanner's name, as for
        ``sentence``.
        """
        sentence = self.sentence(source)
        if sentence is None:
            return []
        return [
            {
                "level": "warning",
                "message": {"text": sentence},
                "properties": {"ash_output_ingest": self.summary()},
            }
        ]

    def text_or(
        self,
        value: object,
        fallback: _Fallback,
        pointer: Sequence[str | int] = (),
        *,
        code: str = "field_not_text",
        rule_id: object = None,
        integers: bool = False,
    ) -> str | _Fallback:
        """*value* when it is text, else *fallback*, the change noted as rewritten.

        For a converter that reads a field of the tool's JSON its SARIF wants as
        text. With *integers*, an integer is written as its decimal text and noted
        as ``number_as_text``; a number with a fraction is not (reading it as a
        float lost the digits the tool wrote). Anything else, ``None`` included,
        is replaced by *fallback* and noted under *code*. A caller for which an
        absent or empty value is no repair filters it out before asking.
        """
        if isinstance(value, str):
            return value
        if integers and isinstance(value, int) and not isinstance(value, bool):
            self.note("rewritten", "number_as_text", pointer, rule_id=rule_id)
            return str(value)
        self.note("rewritten", code, pointer, rule_id=rule_id)
        return fallback

    def url_or_none(
        self,
        value: object,
        pointer: Sequence[str | int] = (),
        *,
        code: str = "url_not_absolute",
        rule_id: object = None,
    ) -> str | None:
        """*value* when it is a link the SARIF models take, else ``None``.

        A value that is not such a link (``N/A``, a relative path, a number) is
        left out and noted as dropped under *code*; a link field is not part of
        what a finding says. An absent link (``None`` or an empty string) is not a
        repair and is not noted.
        """
        if value is None or value == "":
            return None
        if isinstance(value, str):
            try:
                _LINK.validate_python(value)
            except ValueError:
                pass
            else:
                return value
        self.note("dropped", code, pointer, rule_id=rule_id)
        return None

    def absorb(self, other: IngestRecord, scope: str | None = None) -> None:
        """Add what *other* recorded to this record; *other* is not changed.

        For a reader whose parts ran apart from it, cdk-nag's worker process
        answering one template at a time: the counts add, and the elements *other*
        named are named here too, under *scope* (``template 2``, a word and an
        ordinal) when one is given, up to the most a record names.
        """
        prefix = _scope_label(scope) if scope is not None else None
        self.results_read += other.results_read
        self.repaired += other.repaired
        self.left_out += other.left_out
        for key, count in other._counts.items():
            self._counts[key] = self._counts.get(key, 0) + count
        for action, code, pointer, rule in other._named:
            if len(self._named) < _MAX_NAMED:
                shown = f"{prefix}: {pointer}" if prefix else pointer
                self._named.append((action, code, shown, rule))
            else:
                self._not_listed += 1
        self._not_listed += other._not_listed

    @classmethod
    def from_summary(cls, summary: object) -> IngestRecord:
        """The record a :meth:`summary` described, read back from JSON.

        For a record that crossed a process boundary. A summary that is not of the
        shape ``summary`` writes, or a part of one that is not, is not read: the
        result holds the parts that are, and the counts it reports are the ones
        those parts add up to.
        """
        record = cls()
        if not isinstance(summary, dict):
            return record
        read = summary.get("results_read")
        if type(read) is int and read >= 0:
            record.results_read = read
        changes = summary.get("changes")
        for change in changes if isinstance(changes, list) else []:
            if not isinstance(change, dict):
                continue
            action, code = change.get("action"), change.get("code")
            count = change.get("count")
            if not (
                isinstance(action, str)
                and action in _ACTIONS
                and isinstance(code, str)
                and _CODE.fullmatch(code)
                and type(count) is int
                and count >= 1
            ):
                continue
            key = (action, code)
            record._counts[key] = record._counts.get(key, 0) + count
            if action == "left_out":
                record.left_out += count
            else:
                record.repaired += count
        elements = summary.get("elements")
        for element in elements if isinstance(elements, list) else []:
            if not isinstance(element, dict):
                continue
            action, code = element.get("action"), element.get("code")
            pointer, rule = element.get("pointer"), element.get("rule_id")
            if not (
                isinstance(action, str)
                and action in _ACTIONS
                and isinstance(code, str)
                and _CODE.fullmatch(code)
                and isinstance(pointer, str)
                and pointer.isprintable()
                and len(pointer) <= _MAX_POINTER
                and (
                    rule is None or (isinstance(rule, str) and _RULE_ID.fullmatch(rule))
                )
            ):
                continue
            if len(record._named) < _MAX_NAMED:
                record._named.append((action, code, pointer, rule))
            else:
                record._not_listed += 1
        unlisted = summary.get("elements_not_listed")
        if type(unlisted) is int and unlisted >= 0:
            record._not_listed += unlisted
        return record


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
        if not data.strip():
            # A mark and nothing after it is an empty file: nothing was read, so
            # nothing was repaired.
            return None
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
        if text.strip():
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


#: Where a node sits in a raw document: the keys and list indices down to it.
_Path = tuple[str | int, ...]

#: ``(depth, member)`` for each union a model loc passes through, outermost first.
_Unions = tuple[tuple[int, str], ...]


class _Change(NamedTuple):
    """One repair: ``drop`` the node at *path*, or ``set_text`` it to its text."""

    kind: str
    path: _Path
    code: str
    #: What it gives up, to choose the smaller repair when a union offers two:
    #: 0 a rewrite, 1 a field or map entry, 2 a list element.
    rank: int


class _Error(NamedTuple):
    """One model error placed on the raw document."""

    path: _Path
    #: Where the model's loc could not be followed: a required field that is
    #: missing, named last.
    tail: _Path
    #: ``(depth, member)`` for each union the loc passes through, outermost
    #: first; *depth* is how many resolved tokens precede the member.
    unions: _Unions
    change: _Change | None


def _is_integer(value: object) -> bool:
    """A JSON integer, which is the only number that can be written back as the
    text it was. A number with a fraction or an exponent was read as a float, and
    the digits the tool wrote are gone (``1.10`` is ``1.1``), so it is not one."""
    return isinstance(value, int) and not isinstance(value, bool)


def _resolve(doc: Any, loc: Sequence[str | int]) -> tuple[_Path, _Path, _Unions, Any]:
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


def _sort_key(path: _Path) -> tuple[tuple[int, str | int], ...]:
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
#: ``originalUriBaseIds`` is not one: a location's ``uriBaseId`` is resolved through
#: it (``_base_id_change``).
_RUN_ELEMENT_FIELDS = frozenset(
    {
        "versionControlProvenance",
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


def _drop(path: _Path, length: int, code: str, rank: int = 1) -> _Change:
    return _Change("drop", path[:length], code, rank)


def _bag_change(path: _Path, bag: int, code: str = "property_unreadable") -> _Change:
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


def _region_change(path: _Path) -> _Change | None:
    """An error inside a region: drop the region, or only the field."""
    for index in range(len(path) - 1, 0, -1):
        if path[index] in _REGION_KEYS and path[index - 1] == "physicalLocation":
            if index == len(path) - 1:
                return _drop(path, index + 1, "region_field_unreadable")
            if path[index + 1] == "startLine":
                return _drop(path, index + 1, "region_line_unreadable")
            return _drop(path, index + 2, "region_field_unreadable")
    return None


def _fix_change(path: _Path) -> _Change | None:
    """An error in a fix's ``deletedRegion``: the fix cannot be applied, so it goes."""
    if "deletedRegion" not in path or "fixes" not in path:
        return None
    start = path.index("fixes")
    if start + 1 < len(path) and isinstance(path[start + 1], int):
        return _drop(path, start + 2, "fix_unreadable", 2)
    return None


def _result_change(path: _Path) -> _Change | None:
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


def _descriptor_change(path: _Path, element: int) -> _Change | None:
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


def _tool_change(path: _Path) -> _Change | None:
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


#: Invocation fields ASH reads, or that change what another part means. The
#: completeness gate reads the execution notifications, the staleness check and
#: bandit's reader read the configuration notifications, and a configuration
#: override sets the level a rule or a notification reports at. One bad entry in
#: any of them is not repaired: dropping the list would lose what the tool said
#: it could not do, or how it was set up.
_INVOCATION_KEPT_FIELDS = frozenset(
    {
        "executionSuccessful",
        "toolExecutionNotifications",
        "toolConfigurationNotifications",
        "ruleConfigurationOverrides",
        "notificationConfigurationOverrides",
    }
)


def _invocation_change(path: _Path) -> _Change | None:
    """The tool's own invocation: ASH reads whether it succeeded and what it
    reported (``_INVOCATION_KEPT_FIELDS``); every other field may go."""
    if len(path) < 5 or not isinstance(path[3], int):
        return None
    field = path[4]
    if field in _INVOCATION_KEPT_FIELDS:
        return None
    if field == "properties":
        return _bag_change(path, 4, "invocation_field_unreadable")
    return _drop(path, 5, "invocation_field_unreadable")


def _base_id_change(path: _Path) -> _Change | None:
    """An error under ``originalUriBaseIds``, the table a location's ``uriBaseId``
    is resolved through (dedupe keys, suppression scopes, the GitHub code scanning
    report). An entry is never dropped, and neither is its ``uri`` or its own
    ``uriBaseId``: without them a location points somewhere else. Only a field
    that describes the entry may go."""
    if len(path) < 5:
        return None
    field = path[4]
    if field in ("uri", "uriBaseId"):
        return None
    if field == "properties":
        return _bag_change(path, 4, "run_field_unreadable")
    return _drop(path, 5, "run_field_unreadable")


def _run_change(path: _Path) -> _Change | None:
    field = path[2]
    if field == "originalUriBaseIds":
        return _base_id_change(path)
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


def _classify_sarif(path: _Path, tail: _Path, etype: str, value: Any) -> _Change | None:
    """The repair for one error at *path* in a SARIF document, or ``None``."""
    if etype == "string_type" and not tail and _is_integer(value):
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
#: Top-level fields a bad entry is not repaired in. A vulnerability is a finding,
#: and a refused SBOM says so where a dropped one would read as one with none.
_CDX_REFUSED_FIELDS = frozenset({"vulnerabilities"})


def _component_change(path: _Path, start: int) -> _Change | None:
    """An error under a component whose own place is ``path[:start]``: a field that
    describes it may go, and never its type, name or ``bom-ref``."""
    rest = path[start:]
    if not rest or rest[0] not in _CDX_COMPONENT_FIELDS:
        return None
    field = rest[0]
    if len(rest) >= 2 and isinstance(rest[1], int):
        return _drop(path, start + 2, f"{field}_entry_unreadable", 2)
    return _drop(path, start + 1, f"{field}_unreadable")


def _classify_cyclonedx(
    path: _Path, tail: _Path, etype: str, value: Any
) -> _Change | None:
    """The repair for one error at *path* in a CycloneDX document, or ``None``."""
    if etype == "string_type" and not tail and _is_integer(value):
        return _Change("set_text", path, "number_as_text", 0)
    if etype == "extra_forbidden" and path and not tail:
        return _drop(path, len(path), "unknown_key")
    for index in range(len(path) - 2, -1, -1):
        if path[index] == "components" and isinstance(path[index + 1], int):
            return _component_change(path, index + 2)
    if not path:
        return None
    first = path[0]
    if first == "dependencies":
        if len(path) >= 2 and isinstance(path[1], int):
            return _drop(path, 2, "dependency_entry_unreadable", 2)
        return None
    if first == "metadata":
        if len(path) >= 2 and path[1] == "component":
            # The component the BOM describes follows the component rules.
            return _component_change(path, 2)
        if len(path) >= 3 and isinstance(path[2], int):
            return _drop(path, 3, "metadata_entry_unreadable", 2)
        return _drop(path, min(len(path), 2), "metadata_field_unreadable")
    if first in _CDX_KEPT_FIELDS or first in _CDX_REFUSED_FIELDS:
        return None
    if len(path) >= 2 and isinstance(path[1], int):
        # One bad entry of a list (a service, a composition, an annotation) costs
        # that entry, not the list.
        return _drop(path, 2, "document_entry_unreadable", 2)
    return _drop(path, 1, "document_field_unreadable")


# --- choosing and applying repairs ------------------------------------------- #

Classifier = Callable[[_Path, _Path, str, Any], "_Change | None"]


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
    groups: dict[tuple[_Path, int], dict[str, list[_Error]]] = {}
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
    kept: dict[tuple[str, _Path], _Change] = {}
    for change in changes:
        if not change.path:
            continue
        if any(change.path[:size] in dropped for size in range(len(change.path))):
            continue
        if change.kind == "set_text" and change.path in dropped:
            continue
        kept.setdefault((change.kind, change.path), change)
    return sorted(kept.values(), key=lambda change: _sort_key(change.path))


def _original(path: _Path, removed: dict[_Path, list[int]]) -> _Path:
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


def _rule_id_of(doc: Any, path: _Path) -> object:
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
    removed: dict[_Path, list[int]],
    record: IngestRecord,
) -> None:
    """Make *changes* on *doc* and note them.

    The notes use the tool's own coordinates (``removed`` is what earlier rounds
    took out of lists), and the edits go from the last path to the first so a
    list index a later edit names has not moved. A change is noted once every
    edit is made: an edit that raises leaves the record naming nothing of this
    round, which the caller then refuses.
    """
    noted = [
        (
            change,
            _original(change.path, removed),
            _rule_id_of(doc, change.path),
        )
        for change in changes
    ]
    for change in sorted(changes, key=lambda item: _sort_key(item.path), reverse=True):
        parent = _get(doc, change.path[:-1])
        key = change.path[-1]
        if change.kind == "drop":
            del parent[key]
        else:
            number = parent[key]
            if not _is_integer(number):
                raise TypeError("only an integer is written as text")
            parent[key] = str(number)
    for change, original, rule_id in noted:
        record.note(
            "dropped" if change.kind == "drop" else "rewritten",
            change.code,
            original,
            rule_id=rule_id,
        )
    for change, original, _ in noted:
        if change.kind == "drop" and isinstance(change.path[-1], int):
            gone = original[-1]
            if isinstance(gone, int):
                removed.setdefault(original[:-1], []).append(gone)


def _ingest(
    raw: Any,
    record: IngestRecord,
    *,
    model: type[BaseModel],
    classify: Classifier,
    format_name: str,
    count_results: Callable[[Any], int],
    names_the_format: Callable[[Any], bool],
) -> Any:
    """:func:`_read_and_repair`, which leaves *record* as it found it on a refusal.

    The repairs a refused document went through changed nothing the report keeps,
    so they are not counted.
    """
    checkpoint = record.checkpoint()
    try:
        return _read_and_repair(
            raw,
            record,
            model=model,
            classify=classify,
            format_name=format_name,
            count_results=count_results,
            names_the_format=names_the_format,
        )
    except Exception:
        record.rollback(checkpoint)
        raise


def _read_and_repair(
    raw: Any,
    record: IngestRecord,
    *,
    model: type[BaseModel],
    classify: Classifier,
    format_name: str,
    count_results: Callable[[Any], int],
    names_the_format: Callable[[Any], bool],
) -> Any:
    record.format_name = format_name
    try:
        report = model.model_validate(raw)
    except ValidationError as error:
        last = error
    else:
        record.results_read += count_results(raw)
        return report
    if not names_the_format(raw):
        # Both models make every key optional, so a JSON object that is not this
        # format at all (a tool's error object, say) holds only keys the model
        # does not define. Dropping them all would leave an empty report, which a
        # reader takes for a scan that found nothing.
        raise last
    try:
        doc = copy.deepcopy(raw)
    except RecursionError:
        # Too deeply nested to copy, so too deeply nested to repair.
        raise last from None
    removed: dict[_Path, list[int]] = {}
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


def _is_a_sarif_log(raw: Any) -> bool:
    """A SARIF log carries ``runs`` or ``version``; the spec requires both."""
    return isinstance(raw, dict) and ("runs" in raw or "version" in raw)


def _is_a_cyclonedx_bom(raw: Any) -> bool:
    """A CycloneDX BOM carries ``bomFormat`` or ``specVersion``; the spec requires both."""
    return isinstance(raw, dict) and ("bomFormat" in raw or "specVersion" in raw)


def ingest_sarif(raw: Any, record: IngestRecord) -> SarifReport:
    """*raw*, a tool's SARIF as parsed JSON, as a ``SarifReport``.

    A valid document costs what ``SarifReport.model_validate`` costs, and the
    record stays empty. A document the model refuses is repaired on a copy, part
    by part, as the module docstring describes, and each repair is noted; a
    document that still cannot be read raises the model's own last
    ``ValidationError``, naming only the errors that remain. A JSON object that
    carries neither ``runs`` nor ``version`` is not a SARIF log and is refused as
    it is. *raw* is not changed.
    """
    return _ingest(
        raw,
        record,
        model=SarifReport,
        classify=_classify_sarif,
        format_name="SARIF",
        count_results=_sarif_result_count,
        names_the_format=_is_a_sarif_log,
    )


def ingest_cyclonedx(raw: Any, record: IngestRecord) -> CycloneDXReport:
    """:func:`ingest_sarif` for a CycloneDX document, with its own part table.

    A JSON object that carries neither ``bomFormat`` nor ``specVersion`` is not a
    BOM and is refused as it is.
    """
    return _ingest(
        raw,
        record,
        model=CycloneDXReport,
        classify=_classify_cyclonedx,
        format_name="CycloneDX",
        count_results=_cyclonedx_component_count,
        names_the_format=_is_a_cyclonedx_bom,
    )
