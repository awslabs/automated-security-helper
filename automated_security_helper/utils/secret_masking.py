"""Utility functions for masking secrets in security findings."""

import html
import json
import math
import re
from enum import Enum
from typing import (
    AbstractSet,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
    get_args,
    get_origin,
)
from urllib.parse import quote, quote_plus, unquote

from pydantic import AnyUrl, BaseModel, ConfigDict


def mask_secret_in_text(text: str, rule_id: str | None = None) -> str:
    """
    Mask secrets in text based on the rule ID and content patterns.

    Args:
        text: The text that may contain secrets
        rule_id: The rule ID that triggered the finding (e.g., 'B105')

    Returns:
        The text with secrets masked
    """
    if not text or not rule_id:
        return text

    # Handle Bandit B105/B106/B107 (hardcoded password) findings
    if rule_id in ("B105", "B106", "B107"):
        return _mask_bandit_password_secret(text)

    return text


def _mask_bandit_password_secret(text: str) -> str:
    """
    Mask secrets in Bandit B105/B106/B107 findings.

    These findings typically have messages like:
    "Possible hardcoded password: 'actual_secret_value'"

    Args:
        text: The finding description text

    Returns:
        The text with the secret value masked
    """
    # bandit writes the raw value between quotes at the end of its message, so
    # the value runs to the last quote, not the first; see _quoted_values.
    return _mask_spans(text, _quoted_values(text, _HARDCODED_PASSWORD_LABEL))


_mask_bandit_b105_secret = _mask_bandit_password_secret


def _visible_lengths(length: int) -> Tuple[int, int]:
    """How many leading and trailing characters ``_mask_secret_value`` leaves visible."""
    # For very short secrets (< 4 chars), mask completely
    if length < 4:
        return 0, 0
    # For secrets of length 4-7, show only the first character
    if length <= 7:
        return 1, 0
    # For secrets of length 8-12, show first and last character
    if length <= 12:
        return 1, 1
    # For long secrets, show first 2 and last 1 character
    return 2, 1


def _mask_secret_value(secret: str) -> str:
    """
    Mask a secret value while preserving some structure for analysis.
    At least 75% of characters are masked for any secret of length >= 4.

    Args:
        secret: The secret value to mask

    Returns:
        The masked secret value
    """
    if not secret:
        return secret

    length = len(secret)
    shown_prefix, shown_suffix = _visible_lengths(length)
    return (
        secret[:shown_prefix]
        + "*" * (length - shown_prefix - shown_suffix)
        + secret[length - shown_suffix :]
    )


#: What the docstring below means by "already shows in every masked message", since
#: it is written into the generated schema (schemas/AshAggregatedResults.json) and
#: stays as it is: a shape holds no more than the masked form of its value shows,
#: the characters ``_mask_secret_value`` leaves visible and the length. A value
#: quoted in a message leaves that form in the masked message; a value read from
#: a finding's region alone, whose lines are masked whole, leaves it nowhere, and
#: its shape then tells those visible characters and the length on its own. Only
#: a value of at least ``MIN_PROPAGATED_VALUE_LENGTH`` characters that
#: ``_looks_like_a_secret`` has a shape at all, so no short value's shape can be
#: reversed by trying values.
class SecretValueShape(BaseModel):
    """What the masked form of a value shows: its visible prefix and suffix and its length.

    Recorded with the results (``AshAggregatedResults.secret_value_shapes``) so that
    a union of result sets built in another process -- ``ash merge`` of shard
    results -- can mask a value that no shard holds any more. It holds only what
    ``_mask_secret_value`` already shows in every masked message, never a digest:
    a digest of a short value can be reversed by trying values.
    """

    # Read from a results file, whose values an error does not quote.
    model_config = ConfigDict(frozen=True, hide_input_in_errors=True)

    prefix: str
    suffix: str
    length: int
    #: Whether the value holds whitespace, which decides whether a token of this
    #: shape may span it.
    spans_whitespace: bool = False


def secret_value_shape(value: str) -> SecretValueShape:
    """The shape of ``value``'s masked form."""
    shown_prefix, shown_suffix = _visible_lengths(len(value))
    return SecretValueShape(
        prefix=value[:shown_prefix],
        suffix=value[len(value) - shown_suffix :],
        length=len(value),
        spans_whitespace=any(character.isspace() for character in value),
    )


def _shape_key(shape: SecretValueShape) -> Tuple[int, str, str, bool]:
    return (shape.length, shape.prefix, shape.suffix, shape.spans_whitespace)


def shapes_of_secret_values(values: Iterable[str]) -> List[SecretValueShape]:
    """The shapes of the values that are masked wherever they occur, in a stable order."""
    return sorted(
        {secret_value_shape(value) for value in values if _propagates(value)},
        key=_shape_key,
    )


# ---------------------------------------------------------------------------
# Masking across a scan's results
# ---------------------------------------------------------------------------
#
# The functions above mask a finding's own message. The value a secret finding
# reports also travels in snippets -- ``region.snippet`` and
# ``contextRegion.snippet`` of its own result and of any other result whose
# region or context encloses the same line -- and in every output that
# serializes a whole result (``raw_data`` of the flat model, GitLab SAST's
# ``details``, YAML, the Bedrock summary's raw JSON). A non-secret finding's
# contextRegion can enclose a secret on a neighboring line, and a value one
# finding exposed can be reused on a line no secret finding reports, so a mask
# keyed on rule ID cannot cover them. ``mask_secrets_in_results`` therefore works
# on all results of a scan at once:
#
# * by location: every snippet line in a file and line range a secret finding
#   reports is replaced with ``MASKED_LINE`` (indentation and line end kept), a
#   private key's range runs to its END line, and a secret finding's own
#   snippets are masked whole;
# * by value: every value a secret finding exposes -- quoted in its message
#   (bandit B105-B107's ``Possible hardcoded password: '<value>'``, ferret-scan's
#   ``Matched text: '<value>'``) or matched by its own region (semgrep's and
#   opengrep's columns) -- is masked in its own message (a quoted value at its
#   quotes; a matched value wherever the message repeats it, unless it is an
#   ordinary word, which the message's label may be made of), in every finding
#   that shows the line it was found on, and, when it looks like a secret
#   (``_propagates``), with ``_mask_secret_value`` wherever it occurs as a whole
#   token in the text findings report. Rule metadata, tags and identifiers are
#   left alone (``_METADATA_FIELDS``, ``_SKIPPED_FIELDS``).
#
# A secret finding is one from a secrets scanner (``utils/scanner_tool_types.py``),
# one tagged ``secret``, ``secrets`` or a hard-coded credential CWE (798, 259,
# 321), one of the rules listed in ``_SECRET_RULE_IDS`` / ``_SECRET_RULE_PREFIXES``
# or with a ``secrets`` segment in its id (``generic.secrets.*``), one whose rule
# metadata carries such a tag, or one whose message quotes a value as above.
#
# The masking is idempotent: a masked line no longer matches anything, and a
# masked value no longer equals the value. Lines that are not at a secret
# location and hold none of the values are left as they were.

#: What a snippet line at a secret finding's location is replaced with.
MASKED_LINE = "[masked: a secret finding reports this line]"

#: Rules of scanners that are not secrets scanners whose findings report a secret.
_SECRET_RULE_IDS = frozenset({"B105", "B106", "B107"})
#: checkov's secrets framework.
_SECRET_RULE_PREFIXES = ("CKV_SECRET_",)
_SECRET_TAGS = frozenset({"secret", "secrets"})
#: The hard-coded credential CWEs, in every spelling scanners tag them with:
#: semgrep and opengrep write "CWE-798: Use of Hard-coded Credentials", bandit
#: "external/cwe/cwe-259". 798 is credentials, 259 a password, 321 a key.
_SECRET_CWE = re.compile(r"(?i)(?:^|[^0-9a-z])cwe-(?:798|259|321)(?![0-9])")
#: A ``secrets`` segment in a rule id: semgrep's and opengrep's
#: ``generic.secrets.*`` rules, which the default p/ci ruleset holds.
_SECRET_RULE_ID = re.compile(r"(?i)(?:^|\.)secrets?\.")


#: The CWEs of a detected credential or key, as opposed to a hard-coded password
#: check (CWE-259), which a linter raises on a name such as ``password`` whatever
#: the value is.
_DETECTION_CWE = re.compile(r"(?i)(?:^|[^0-9a-z])cwe-(?:798|321)(?![0-9])")


def _is_secret_tag(tag: Any) -> bool:
    return isinstance(tag, str) and (
        tag.lower() in _SECRET_TAGS or bool(_SECRET_CWE.search(tag))
    )


def _is_detection_tag(tag: Any) -> bool:
    return isinstance(tag, str) and (
        tag.lower() in _SECRET_TAGS or bool(_DETECTION_CWE.search(tag))
    )


#: How bandit's B105-B107 and ferret-scan's messages introduce the value they quote.
_HARDCODED_PASSWORD_LABEL = "Possible hardcoded password:"
_MATCHED_TEXT_LABEL = "Matched text:"


def _value_patterns(label: str) -> Tuple[re.Pattern[str], re.Pattern[str]]:
    """(the quoted value ending the message, the first quoted value after ``label``).

    The value is written raw, so it can hold its own quote character, and it
    ends the message: the first pattern takes everything to the last matching
    quote at the end. The second, to the first matching quote, is for a message
    that goes on after the value, which neither tool writes; it fails closed
    by still masking what it can. Both span line breaks, since a value can
    hold one.
    """
    escaped = re.escape(label)
    return (
        re.compile(escaped + r"""\s*(["'])(.*)\1\s*\Z""", re.DOTALL),
        re.compile(escaped + r"""\s*(["'])((?:(?!\1).)*)\1""", re.DOTALL),
    )


_VALUE_PATTERNS: Dict[str, Tuple[re.Pattern[str], re.Pattern[str]]] = {
    label: _value_patterns(label)
    for label in (_HARDCODED_PASSWORD_LABEL, _MATCHED_TEXT_LABEL)
}


def _quoted_values(text: str, label: Optional[str] = None) -> List[Tuple[int, int]]:
    """The (start, end) of each value a message quotes, for one label or all."""
    spans: List[Tuple[int, int]] = []
    for name, (ending, first) in _VALUE_PATTERNS.items():
        if label is not None and name != label:
            continue
        match = ending.search(text)
        if match is not None:
            spans.append(match.span(2))
        else:
            spans.extend(found.span(2) for found in first.finditer(text))
    return sorted(set(spans))


def _mask_spans(text: str, spans: Iterable[Tuple[int, int]]) -> str:
    """``text`` with each (start, end) span masked; spans are replaced last to first."""
    for start, end in sorted(set(spans), reverse=True):
        text = text[:start] + _mask_secret_value(text[start:end]) + text[end:]
    return text


#: A value is masked wherever it occurs, not only in its own finding, only when it
#: looks like a secret (``_looks_like_a_secret``). A hard-coded password check
#: quotes ordinary words as often as credentials (``password``, ``secret``,
#: ``access_token``), and masking those everywhere rewrote other findings'
#: messages, and so their IDs, and SBOM entries. Every value is still masked in
#: its own finding's message and lines.
MIN_PROPAGATED_VALUE_LENGTH = 8
#: The longest value whose shape is recorded and matched. A shape's length goes
#: into a ``{N}`` quantifier; a stored results file could name any length, and a
#: length past what ``re`` accepts made every later load fail to compile the
#: pattern, while a very long one made matching slow. Values themselves are
#: masked whatever their length.
MAX_PROPAGATED_VALUE_LENGTH = 4096
#: A value shorter than this is masked in its own finding only: a one-character
#: value names nothing, and masked in every finding that overlaps its line it
#: rewrote every occurrence of that character.
MIN_LOCAL_VALUE_LENGTH = 2
#: Shannon entropy per character below which a value is too repetitive to tell
#: from ordinary text (``aaaaaaaa1``, ``86400000``).
MIN_PROPAGATED_VALUE_ENTROPY = 2.5
#: Letters alone, as one word or several joined by whitespace, dots, hyphens or
#: underscores: words, identifiers and prose.
_WORD_LIKE = re.compile(r"[A-Za-z]+(?:[\s._-]+[A-Za-z]+)*")
#: The label and quote punctuation at either end of a value: the colon, equals
#: sign, quotes, brackets, hyphens, dots, commas and spaces around a word
#: (``password:``, ``--password``, ``'secret'``) make it no less a word. The
#: characters that end real passwords (``!``, ``@``, ``#``, ``$``, ``%``, ``^``,
#: ``&``, ``*``, ``+``, ``~``) are not trimmed: ``Password!`` is a value, not the
#: word.
_LABEL_EDGE = r"""[\s'"`:=,;.()\[\]{}<>-]+"""
_EDGE_NON_WORD = re.compile(f"^{_LABEL_EDGE}|{_LABEL_EDGE}$")
#: Template placeholders: ``${NAME}``, ``{name}``, ``%(name)s``, ``<value>``, and
#: a bare ``$NAME`` as shells and templates name a variable: upper case with
#: digits and underscores, or letters and underscores alone. A value such as
#: ``$uperSecret99``, letters of both cases with digits, is not a reference.
_PLACEHOLDER = re.compile(
    r"\$\{\w+\}|\$(?:[A-Z_][A-Z0-9_]*|[A-Za-z_]+)|\{\w*\}|%\(\w+\)[a-z]|<[^<>]*>"
)

#: Fields that name things rather than hold text a finding reports: identifiers,
#: and ASH's own bookkeeping on a result (``scanner_name`` and
#: ``scanner_version``, which decide the result's tool type). The fingerprint and
#: GUID fields are not among them: they are masked like any other text, because
#: masking is the side that fails closed and a hash-shaped field can hold a value
#: a scanner matched.
_SKIPPED_FIELDS = frozenset(
    {
        "uri",
        "uriBaseId",
        "ruleId",
        "guid",
        "correlationGuid",
        "baselineState",
        "scanner_name",
        "scanner_version",
    }
)
#: Enum-valued SARIF fields: ``Result.level`` and ``Result.kind``,
#: ``Suppression.kind`` and ``Suppression.state``, ``Run.columnKind``,
#: ``ThreadFlowLocation.importance`` and ``Artifact.roles``. A model field of one
#: of these names is skipped when the model declares it as an enum
#: (``_is_skipped_field``), so a model's free-text ``kind`` fields stay masked.
#: A value or shape that matched an enum (``warning``, ``inSource``) rewrote a
#: result's severity and wrote a value the model refuses on the next load.
_ENUM_FIELDS = frozenset(
    {"level", "kind", "state", "columnKind", "importance", "roles"}
)
#: The same, for a report already reduced to plain JSON (``_is_skipped_key``),
#: which carries no declarations: these names are enum-valued wherever SARIF uses
#: them. ``kind`` and ``state`` are not among them: ``Address.kind``,
#: ``LogicalLocation.kind`` and ``Exception.kind`` are free text, and
#: ``threadFlowLocation.state`` is a free-text map that can hold a secret; a
#: result's and a suppression's ``kind``, and a suppression's ``state``, are told
#: by the key their dict sits under instead (``_ENUM_KIND_PARENTS``).
_ENUM_KEYS = frozenset({"level", "columnKind", "importance", "roles"})
#: The plain-JSON keys under which a dict's ``kind`` is a SARIF enum: a run's or
#: an external property set's ``results`` (``Result.kind``) and a result's
#: ``suppressions`` (``Suppression.kind``).
_ENUM_KIND_PARENTS = frozenset({"results", "suppressions"})
#: Fields under which nothing is masked by value: a tool's rule metadata,
#: taxonomies and policies, a result's rule reference and every ``tags`` list.
#: They describe or classify findings; a finding tagged ``secret`` whose tag was
#: masked stopped being a secret finding on the next pass.
_METADATA_FIELDS = frozenset(
    {
        "tool",
        "driver",
        "extensions",
        "taxonomies",
        "translations",
        "policies",
        "rule",
        "tags",
    }
)


def _is_skipped(name: str) -> bool:
    """Whether nothing under a model field of this name is masked by value."""
    return name in _SKIPPED_FIELDS or name in _METADATA_FIELDS


def _is_enum_annotated(model: Any, name: str) -> bool:
    """Whether ``name`` is a field of ``model``'s class declared as an enum or literal.

    The SARIF models are configured with ``use_enum_values``, so such a field
    holds the plain string of its member at runtime and ``_mask_tree``'s
    ``Enum`` type check never sees it; its declaration is what tells it from a
    free-text field of the same name. The model instance is given, not its
    class: the class is read here, by name, from the value.
    """
    field = getattr(type(model), "model_fields", {}).get(name)
    if field is None:
        return False
    pending = [field.annotation]
    while pending:
        annotation = pending.pop()
        origin = get_origin(annotation)
        if origin is Literal:
            return True
        if origin is not None:
            pending.extend(get_args(annotation))
            continue
        if isinstance(annotation, type) and issubclass(annotation, Enum):
            return True
    return False


def _is_skipped_field(model: Any, name: str) -> bool:
    """Whether nothing under this field of a model is masked by value.

    An enum-valued field (``_ENUM_FIELDS``) counts only when the model declares
    it so, which keeps a free-text field that shares a name with one
    (``Address.kind``, ``LogicalLocation.kind``, ``Exception.kind``) masked.
    ``model`` is the instance; its class is read by :func:`_is_enum_annotated`.
    """
    return _is_skipped(name) or (
        name in _ENUM_FIELDS and _is_enum_annotated(model, name)
    )


def _is_skipped_key(key: str, parent: Optional[str] = None) -> bool:
    """Whether nothing under a plain-JSON key of this name is masked by value.

    A report reduced to plain data carries no declarations, so its enum-valued
    fields are known by name (``_ENUM_KEYS``), and a result's or suppression's
    ``kind`` and a suppression's ``state`` by the key their dict sits under
    (``parent``); a ``kind`` under any other key is free text and is masked.
    """
    return (
        _is_skipped(key)
        or key in _ENUM_KEYS
        or (key == "kind" and parent in _ENUM_KIND_PARENTS)
        or (key == "state" and parent == "suppressions")
    )


#: The pattern the SARIF models declare on every GUID field.
_GUID_PATTERN = (
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}"
    r"-[0-9a-fA-F]{12}$"
)
#: A GUID that is plainly no GUID of anything: all zeros but the version and
#: variant digits the pattern requires.
_SYNTHETIC_GUID = "-".join(("0" * 8, "0" * 4, "4" + "0" * 3, "8" + "0" * 3, "0" * 12))
#: One value for each distinct pattern the SARIF models declare on a string: the
#: GUID, ``dottedQuadFileVersion``, a language tag and a MIME type. A field whose
#: text was masked to something its pattern refuses takes the first of these the
#: pattern accepts, which keeps the report loadable without keeping the value.
_SYNTHETIC_PATTERN_VALUES = (_SYNTHETIC_GUID, "0.0.0.0", "en", "x/x")
#: The GUID fields of a report already reduced to plain JSON, which carries no
#: declarations (``deprecatedGuids`` holds a list of GUID strings). ``guid`` and
#: ``correlationGuid`` are skipped outright (``_SKIPPED_FIELDS``).
_GUID_KEYS = frozenset(
    {
        "baselineGuid",
        "runGuid",
        "firstDetectionRunGuid",
        "lastDetectionRunGuid",
        "deprecatedGuids",
    }
)


def _field_pattern(model: Any, name: str) -> Optional[str]:
    """The pattern ``model``'s class declares on its string field ``name``, or None."""
    field = getattr(type(model), "model_fields", {}).get(name)
    for item in getattr(field, "metadata", None) or ():
        pattern = getattr(item, "pattern", None)
        if isinstance(pattern, str):
            return pattern
    return None


def _keep_the_pattern(pattern: str, original: str, masked: str) -> str:
    """``masked``, or a synthetic value the pattern accepts when masking left a
    field that matched its pattern with text that does not.

    The models do not validate on assignment, so a masked GUID was written
    without complaint and then refused when the report was read again (``ash
    merge``, the findings browser). The mask has already removed the value; the
    replacement is a fixed value that carries none of it.
    """
    if masked == original or re.search(pattern, masked):
        return masked
    if not re.search(pattern, original):
        return masked
    for candidate in _SYNTHETIC_PATTERN_VALUES:
        if re.search(pattern, candidate):
            return candidate
    return masked


def _keep_the_key_pattern(key: Optional[str], original: Any, masked: Any) -> Any:
    """``_keep_the_pattern`` for a plain-JSON key that names a GUID field."""
    if key in _GUID_KEYS and isinstance(original, str) and isinstance(masked, str):
        return _keep_the_pattern(_GUID_PATTERN, original, masked)
    return masked


_WORD_CHARACTER = re.compile(r"\w")

#: The line breaks scanners number lines by: universal newlines.
_LINE_BREAK = re.compile(r"\r\n|\n|\r")
#: What makes a snippet's line numbers untrustworthy: a character
#: ``str.splitlines`` also breaks at (vertical tab, form feed, the information
#: separators, NEL, U+2028, U+2029), which scanners do not count as a line
#: break, or a lone carriage return, which some count and some do not.
_UNCOUNTED_LINE_BREAK = re.compile(
    r"[\v\f\x1c\x1d\x1e\x85\N{LINE SEPARATOR}\N{PARAGRAPH SEPARATOR}]|\r(?!\n)"
)


def _split_lines(text: str, keepends: bool = False) -> List[str]:
    """``text`` split at ``\\r\\n``, ``\\n`` and ``\\r`` only, like ``str.splitlines``
    otherwise: no empty last line for a trailing break.
    """
    lines = []
    start = 0
    for match in _LINE_BREAK.finditer(text):
        lines.append(text[start : match.end() if keepends else match.start()])
        start = match.end()
    if start < len(text):
        lines.append(text[start:])
    return lines


def _text_of(message: Any) -> Optional[str]:
    root = getattr(message, "root", message)
    if isinstance(root, dict):
        text = root.get("text")
    else:
        text = getattr(root, "text", None)
    return text if isinstance(text, str) else None


#: The ``file`` scheme in each of its forms before an absolute path:
#: ``file:///path``, ``file://localhost/path`` and ``file:/path``.
_FILE_SCHEME = re.compile(r"(?i)\Afile:(?://(?:localhost)?)?(?=/)")
#: Two or more slashes, and a ``.`` segment between slashes.
_REPEATED_SLASHES = re.compile(r"/{2,}")
_DOT_SEGMENTS = re.compile(r"/(?:\./)+")


def _normalized_uri(uri: Any) -> Optional[str]:
    """``uri`` as a plain relative or absolute path, for comparing two names of a file.

    Backslashes become slashes; the ``file`` scheme, leading ``./``, interior
    ``.`` segments and repeated slashes are removed; and percent-encoding is decoded:
    SARIF URIs are URI references, so ``my%20app/settings.py`` and
    ``my app/settings.py`` name one file. Decoding runs until nothing changes, so
    a name one tool wrote raw with a literal ``%2B`` and another wrote encoded
    as ``%252B`` meet at the same text; naming one file twice over is the safe
    side (``_same_file``).
    """
    if not isinstance(uri, str) or not uri:
        return None
    text = uri.replace("\\", "/")
    while True:
        decoded = unquote(text)
        if decoded == text:
            break
        text = decoded
    text = _FILE_SCHEME.sub("", text)
    text = _REPEATED_SLASHES.sub("/", text)
    text = _DOT_SEGMENTS.sub("/", text)
    while text.startswith("./"):
        text = text[2:]
    return text or None


def _stack_locations(stack: Any) -> List[Any]:
    return [
        getattr(frame, "location", None)
        for frame in getattr(stack, "frames", None) or []
    ]


def _locations_of(result: Any, related: bool = False) -> List[Any]:
    """``result``'s locations; with ``related``, also its related locations, the
    steps of its code flows (and their stacks) and the frames of its stacks.

    Every one of them names a place in the code the result is about, so a
    secret line any of them shows is masked, and a value exposed at that line
    is masked in the result that shows it.
    """
    locations = list(getattr(result, "locations", None) or [])
    if related:
        locations.extend(getattr(result, "relatedLocations", None) or [])
        for flow in getattr(result, "codeFlows", None) or []:
            for thread in getattr(flow, "threadFlows", None) or []:
                for step in getattr(thread, "locations", None) or []:
                    locations.append(getattr(step, "location", None))
                    locations.extend(_stack_locations(getattr(step, "stack", None)))
        for stack in getattr(result, "stacks", None) or []:
            locations.extend(_stack_locations(stack))
    return [location for location in locations if location is not None]


def _physical_of(location: Any) -> Any:
    """The physical location of a SARIF ``Location``, unwrapped, or None."""
    physical = getattr(location, "physicalLocation", None)
    return getattr(physical, "root", physical)


def _physical_locations_of(result: Any, related: bool = False) -> Iterable[Any]:
    """``result``'s physical locations, and its related locations' with ``related``."""
    for location in _locations_of(result, related):
        physical = _physical_of(location)
        if physical is not None:
            yield physical


def _uri_of(physical: Any, index: Optional["_SecretIndex"] = None) -> Any:
    """The uri of a node's ``artifactLocation``: its own, or, given the index of
    the report it belongs to, the one its artifact index resolved to
    (``_resolve_artifact_uris``, ``_SecretIndex.resolved_uris``)."""
    location = getattr(physical, "artifactLocation", None)
    uri = getattr(location, "uri", None)
    if uri is None and location is not None and index is not None:
        resolved = index.resolved_uris.get(id(location))
        if resolved is not None and resolved[0] is location:
            return resolved[1]
    return uri


def _resolve_artifact_uris(sarif_report: Any, index: "_SecretIndex") -> None:
    """Record the URI of every artifact location that names its file by index only.

    SARIF lets a location name its artifact through ``artifactLocation.index``
    into the run's ``artifacts`` array with no ``uri`` of its own. The maskings
    below read the URI (``_uri_of``), so such a location was neither indexed as
    a secret location nor placed for masking. The URI (and ``uriBaseId``) the
    artifact carries is recorded for the location in ``index.resolved_uris`` and
    read from there, not written onto the location: the results are read, never
    changed, by the masker that only reads them (``source_snippet_masker``), and
    a location is left as the scanner wrote it. The map lives on the index of
    the one report, never in module state: maskings run on several threads at
    once (one per orchestrator), and a shared map one of them cleared emptied
    another's entries.
    """
    for container in list(getattr(sarif_report, "runs", None) or []) + list(
        _external_properties_of(sarif_report)
    ):
        artifacts = list(getattr(container, "artifacts", None) or [])
        if not artifacts:
            continue
        _resolve_artifact_uris_in(container, artifacts, set(), index.resolved_uris)


def _resolve_artifact_uris_in(
    node: Any,
    artifacts: List[Any],
    seen: Set[int],
    resolved: Dict[int, Tuple[Any, str, Any]],
) -> None:
    if isinstance(node, (str, Enum)) or id(node) in seen:
        return
    if isinstance(node, BaseModel):
        seen.add(id(node))
        fields = type(node).model_fields
        if "uri" in fields and "uriBaseId" in fields and "index" in fields:
            index = getattr(node, "index", None)
            if (
                getattr(node, "uri", None) is None
                and isinstance(index, int)
                and 0 <= index < len(artifacts)
            ):
                location = getattr(artifacts[index], "location", None)
                uri = getattr(location, "uri", None)
                if isinstance(uri, str) and uri:
                    base = getattr(node, "uriBaseId", None)
                    if base is None:
                        base = getattr(location, "uriBaseId", None)
                    resolved[id(node)] = (node, uri, base)
            return
        for name in fields:
            _resolve_artifact_uris_in(
                getattr(node, name, None), artifacts, seen, resolved
            )
        return
    if isinstance(node, list):
        seen.add(id(node))
        for item in node:
            _resolve_artifact_uris_in(item, artifacts, seen, resolved)
    elif isinstance(node, dict):
        seen.add(id(node))
        for item in node.values():
            _resolve_artifact_uris_in(item, artifacts, seen, resolved)


def _external_properties_of(sarif_report: Any) -> List[Any]:
    """The ``inlineExternalProperties`` of a SARIF log: results, artifacts and
    tool components a log carries outside its runs."""
    return list(getattr(sarif_report, "inlineExternalProperties", None) or [])


def _has_runs(sarif_report: Any) -> bool:
    """Whether a SARIF log holds anything to index: runs, or external property sets."""
    return sarif_report is not None and bool(
        getattr(sarif_report, "runs", None) or _external_properties_of(sarif_report)
    )


def _all_results(sarif_report: Any) -> List[Any]:
    """Every result of a SARIF log: each run's, and each external property set's."""
    results = list(sarif_report.get_all_results() or [])
    for external in _external_properties_of(sarif_report):
        results.extend(getattr(external, "results", None) or [])
    return results


def _artifacts_of(sarif_report: Any) -> Iterable[Any]:
    for run in getattr(sarif_report, "runs", None) or []:
        yield from getattr(run, "artifacts", None) or []
    for external in _external_properties_of(sarif_report):
        yield from getattr(external, "artifacts", None) or []


def _rules_of(sarif_report: Any) -> Iterable[Any]:
    components: List[Any] = []
    for run in getattr(sarif_report, "runs", None) or []:
        tool = getattr(run, "tool", None)
        components.append(getattr(tool, "driver", None))
        components.extend(getattr(tool, "extensions", None) or [])
    for external in _external_properties_of(sarif_report):
        components.append(getattr(external, "driver", None))
        components.extend(getattr(external, "extensions", None) or [])
    for component in components:
        yield from getattr(component, "rules", None) or []


def _rule_ids_tagged(sarif_report: Any, is_tag) -> Set[str]:
    found: Set[str] = set()
    for rule in _rules_of(sarif_report):
        tags = getattr(getattr(rule, "properties", None), "tags", None) or []
        if any(is_tag(tag) for tag in tags) and getattr(rule, "id", None):
            found.add(rule.id)
    return found


#: What the rules about a credential written into infrastructure code say,
#: since neither tool tags them. checkov's checks: "Ensure no hard coded AWS
#: access key and secret key exists in provider" (CKV_AWS_41), "... hard-coded
#: secrets exist in lambda environment" (CKV_AWS_45), "... in EC2 user data"
#: (CKV_AWS_46), "... in Parameter Store values" (CKV_AWS_384), "no sensitive
#: credentials are exposed in VM custom_data" (CKV_AZURE_45), "SecureString
#: parameter should not have hardcoded default values" (CKV_AZURE_131), and the
#: providers' "no hard coded ... token/key/password" checks. cfn-nag's
#: PasswordBaseRule rules: "<Resource> <Property> password must not be a
#: plaintext string ..." (F23, F31, F34-F37, F41, F44-F71 and others, written
#: with a CFN_NAG_ prefix in its SARIF). "master username must not be a
#: plaintext string" (F24) is not about a credential.
#:
#: A text describes one when it holds both a "hard-coded" and a credential word,
#: in either order, or one of the fixed phrases. Each is its own search, since
#: one pattern joining the two words with ``.*`` backtracked over the whole
#: text for every credential word in it.
_HARD_CODED = re.compile(r"(?i)\bhard[- ]?coded\b")
_CREDENTIAL_WORD = re.compile(
    r"(?i)\b(?:secrets?|credentials?|passwords?|keys?|tokens?|securestring)\b"
)
_IAC_CREDENTIAL = re.compile(
    r"(?i)(?:passw|secret|token|key|credential)\w*\s+must not be a plaintext"
    r"|\bsensitive credentials\b"
    r"|\bcredentials in the template\b"
)


def _describes_a_credential_in_code(text: Any) -> bool:
    """Whether a text describes a credential written into code.

    The description counts for a finding of any scanner type. A code scanner
    (semgrep, opengrep) writes the value its rule matched into its message, so
    "describes a credential without quoting it" is not a property of a scanner's
    type, and reading it only for infrastructure scanners left such a finding's
    value unmasked. Masking a file from the finding's line to its end for a
    description that names no credential is the side that fails closed.
    """
    if not isinstance(text, str):
        return False
    if _HARD_CODED.search(text) and _CREDENTIAL_WORD.search(text):
        return True
    return bool(_IAC_CREDENTIAL.search(text))


def _has_columns(region: Any) -> bool:
    """Whether a region reports a column: a span of its line, not a whole resource.

    cfn-nag, cdk-nag and checkov report lines alone; bandit and semgrep report
    the column their match starts at. A start column of 1 with no end column is
    a placeholder, not a span: npm-audit writes ``startColumn=1`` on every
    finding it places at line 1 of a package file, naming no match.
    """
    if isinstance(getattr(region, "endColumn", None), int):
        return True
    start = getattr(region, "startColumn", None)
    return isinstance(start, int) and start != 1


def _rule_ids_described(sarif_report: Any) -> Set[str]:
    """IDs of rules whose name or description is about a credential in code.

    Read from the rules of every run, whatever scanner wrote it
    (``_describes_a_credential_in_code``).
    """
    found: Set[str] = set()
    containers = list(getattr(sarif_report, "runs", None) or []) + list(
        _external_properties_of(sarif_report)
    )
    for container in containers:
        components: List[Any] = [
            getattr(getattr(container, "tool", None), "driver", None),
            getattr(container, "driver", None),
        ]
        components.extend(
            getattr(getattr(container, "tool", None), "extensions", None) or []
        )
        components.extend(getattr(container, "extensions", None) or [])
        for component in components:
            for rule in getattr(component, "rules", None) or []:
                texts = [getattr(rule, "name", None)]
                for field in ("shortDescription", "fullDescription"):
                    texts.append(_text_of(getattr(rule, field, None)))
                if any(
                    _describes_a_credential_in_code(text) for text in texts
                ) and getattr(rule, "id", None):
                    found.add(rule.id)
    return found


def _rule_id_of(result: Any) -> str:
    """The id of ``result``'s rule: ``ruleId``, or the ``id`` of its ``rule``
    reference when a tool names the rule that way only."""
    rule_id = getattr(result, "ruleId", None)
    if isinstance(rule_id, str) and rule_id:
        return rule_id
    reference = getattr(result, "rule", None)
    reference = getattr(reference, "root", reference)
    if isinstance(reference, dict):
        rule_id = reference.get("id")
    else:
        rule_id = getattr(reference, "id", None)
    return rule_id if isinstance(rule_id, str) else ""


def secret_detection_rule_ids(sarif_report: Any) -> Set[str]:
    """IDs of rules whose metadata marks them as detecting a credential or key.

    Tagged ``secret``/``secrets``, CWE-798 or CWE-321; see ``is_secret_detection``.
    """
    return _rule_ids_tagged(sarif_report, _is_detection_tag)


def is_secret_detection(
    result: Any, detection_rule_ids: AbstractSet[str] = frozenset()
) -> bool:
    """Whether ``result`` comes from a rule that detects a credential or key.

    The narrower question the Bedrock summary reporter asks: a secrets scanner's
    finding, one from a ``secrets`` rule (``generic.secrets.*``, ``CKV_SECRET_*``),
    or one whose tags, or its rule's, carry ``secret``, ``secrets``, CWE-798 or
    CWE-321. A hard-coded password check (bandit B105-B107, CWE-259) is a secret
    finding for masking (``is_secret_finding``) but not a detection.
    """
    from automated_security_helper.utils.scanner_tool_types import (
        SECRETS_TOOL_TYPE,
        result_tags,
        result_tool_types,
    )

    rule_id = _rule_id_of(result)
    if rule_id in detection_rule_ids:
        return True
    if rule_id.startswith(_SECRET_RULE_PREFIXES) or _SECRET_RULE_ID.search(rule_id):
        return True
    if any(_is_detection_tag(tag) for tag in result_tags(result)):
        return True
    return SECRETS_TOOL_TYPE in result_tool_types(result)


def secret_rule_ids(sarif_report: Any) -> Set[str]:
    """IDs of rules a tool's rule metadata marks as secret rules.

    A rule is a secret rule when its tags include ``secret``/``secrets`` (trivy's)
    or a hard-coded credential CWE (``_SECRET_CWE``: semgrep's and opengrep's
    ``generic.secrets.*`` rules, whose results carry no tags of their own), or
    when its name or description is about a credential written into
    infrastructure code (``_IAC_CREDENTIAL``: checkov's and cfn-nag's).
    """
    return _rule_ids_tagged(sarif_report, _is_secret_tag) | _rule_ids_described(
        sarif_report
    )


#: Tool types whose findings describe a dependency, not the scanned code: a
#: vulnerability advisory (``SCA``: npm-audit, grype, trivy) or an inventory entry
#: (``SBOM``: syft), as ``utils/scanner_names.SCANNER_TOOL_TYPES`` declares them.
#: An advisory titled "Hardcoded credentials in configuration" describes the
#: dependency's weakness class, not a value in the scanned files, so such a
#: finding is not a secret finding by its text and never a resource-level one:
#: read as one, placed at line 1 of package.json with no column span, it masked
#: every line of the file.
_DEPENDENCY_TOOL_TYPES = frozenset({"SCA", "SBOM"})


def _is_dependency_finding(tool_types: AbstractSet[str]) -> bool:
    """Whether the tool types of a finding mark it as a dependency advisory or
    inventory entry (``_DEPENDENCY_TOOL_TYPES``)."""
    return any(tool_type in _DEPENDENCY_TOOL_TYPES for tool_type in tool_types)


def is_secret_finding(
    result: Any, secret_rule_ids: AbstractSet[str] = frozenset()
) -> bool:
    """Whether ``result`` reports a secret; see the module notes above."""
    from automated_security_helper.utils.scanner_tool_types import (
        SECRETS_TOOL_TYPE,
        result_tags,
        result_tool_types,
    )

    rule_id = _rule_id_of(result)
    if rule_id in secret_rule_ids or _is_secret_rule_id(rule_id):
        return True
    if any(_is_secret_tag(tag) for tag in result_tags(result)):
        return True
    tool_types = result_tool_types(result)
    if SECRETS_TOOL_TYPE in tool_types:
        return True
    if _is_dependency_finding(tool_types):
        # An advisory's text describes the dependency's weakness, not a value
        # or credential written into the scanned files.
        return False
    text = _text_of(getattr(result, "message", None)) or ""
    return _text_reports_a_secret(text)


def _is_secret_rule_id(rule_id: Any) -> bool:
    """Whether a rule id alone marks a secret finding (see the module notes)."""
    return isinstance(rule_id, str) and (
        rule_id in _SECRET_RULE_IDS
        or rule_id.startswith(_SECRET_RULE_PREFIXES)
        or bool(_SECRET_RULE_ID.search(rule_id))
    )


def _text_reports_a_secret(text: Any) -> bool:
    """Whether a message quotes a value or describes a credential in code."""
    return isinstance(text, str) and (
        bool(_quoted_values(text)) or _describes_a_credential_in_code(text)
    )


def _same_file(first: str, second: str) -> bool:
    """Whether two normalized URIs name one file: equal, or one a suffix of the other.

    A finding written relative to another directory still matches. That can match
    two different files of one name; masking both is the safe side.
    """
    return (
        first == second or first.endswith("/" + second) or second.endswith("/" + first)
    )


#: Where a reported range runs to when where it ends is unknown.
_TO_END_OF_FILE = 2**62

#: Properties a masking writes on a key finding to record where its range ran,
#: per primary location in the order of the finding's ``locations``: to the END
#: line some other finding's snippet showed (``masked_block_end``, a list with
#: that line's number at the location's position and null where the location
#: recorded no END line) or, with no END line in any snippet, to the end of the
#: file (``masked_to_end_of_file``, the list of the positions that ran to it). A
#: single number, or ``true``, is the record of an earlier version and applies to
#: every location. The next masking (every reload, a merge, the findings
#: browser) takes the recorded range: by then the END line and every line of the
#: block read as masked lines, so the snippets cannot place the block again, and
#: the finding's own region is left as the scanner wrote it, because the file
#: and lines are the finding's identity across scans. One record per location:
#: one per finding applied the widest location's end to every location, so a
#: second masking hid more lines than the first.
MASKED_BLOCK_END_PROPERTY = "masked_block_end"
MASKED_TO_END_OF_FILE_PROPERTY = "masked_to_end_of_file"


def _recorded_block_end(result: Any, position: int) -> Optional[int]:
    """The END line an earlier masking recorded for the key finding's location at
    ``position`` (its index among the finding's ``locations``), if any."""
    properties = getattr(result, "properties", None)
    recorded = _extra_of(properties).get(MASKED_BLOCK_END_PROPERTY)
    if isinstance(recorded, list):
        recorded = recorded[position] if 0 <= position < len(recorded) else None
    if isinstance(recorded, bool) or not isinstance(recorded, int):
        return None
    return recorded if recorded > 0 else None


def _masked_to_end_of_file(result: Any, position: int) -> bool:
    """Whether an earlier masking recorded the finding's location at ``position``
    as running to the file's end."""
    properties = getattr(result, "properties", None)
    recorded = _extra_of(properties).get(MASKED_TO_END_OF_FILE_PROPERTY)
    if isinstance(recorded, list):
        return position in recorded
    return bool(recorded)


def _mark_masked_range(
    result: Any, ends: List[Optional[int]], to_end_of_file: List[int]
) -> None:
    """Record on ``result`` where each primary location's range ran: to the END
    line at its position in ``ends``, or to the file's end for the positions in
    ``to_end_of_file``."""
    properties = getattr(result, "properties", None)
    if properties is None:
        from automated_security_helper.schemas.sarif_schema_model import PropertyBag

        properties = PropertyBag()
        result.properties = properties
    extra = getattr(properties, "__pydantic_extra__", None)
    if not isinstance(extra, dict):
        return
    if any(isinstance(end, int) for end in ends):
        extra[MASKED_BLOCK_END_PROPERTY] = list(ends)
    else:
        extra.pop(MASKED_BLOCK_END_PROPERTY, None)
    if to_end_of_file:
        extra[MASKED_TO_END_OF_FILE_PROPERTY] = list(to_end_of_file)
    else:
        extra.pop(MASKED_TO_END_OF_FILE_PROPERTY, None)


#: A private-key finding's rule, message or tag.
_PRIVATE_KEY = re.compile(r"(?i)private[\s_-]*key")
_PEM_BEGIN = "-----BEGIN"
_PEM_END = "-----END"


def _outside_quoted_values(text: str) -> str:
    """``text`` without the values it quotes (``_quoted_values``).

    What a finding is about is read from the rest of its message: a quoted value
    that merely mentions a private key is the evidence, not the kind of finding.
    """
    pieces = []
    position = 0
    for start, end in _quoted_values(text):
        pieces.append(text[position:start])
        position = max(position, end)
    pieces.append(text[position:])
    return "".join(pieces)


def _is_private_key_finding(result: Any) -> bool:
    from automated_security_helper.utils.scanner_tool_types import result_tags

    texts = [
        _rule_id_of(result),
        _outside_quoted_values(_text_of(getattr(result, "message", None)) or ""),
    ]
    texts.extend(tag for tag in result_tags(result) if isinstance(tag, str))
    return any(_PRIVATE_KEY.search(text) for text in texts)


def _basename(uri: str) -> str:
    return uri.rsplit("/", 1)[-1]


class _KnownLines:
    """The text of every line any snippet of a report places: uri -> line -> text.

    Looked up by file (``matching``): two URIs name one file when they are equal
    or one is a suffix of the other at a path separator (``_same_file``), which
    means they share a last segment, so the candidates are found by basename
    instead of a scan of every file for every lookup.
    """

    def __init__(self) -> None:
        self.lines: Dict[str, Dict[int, str]] = {}
        self._by_basename: Dict[str, List[str]] = {}

    def record(self, uri: Any, first_line: Any, text: Any) -> None:
        normalized = _normalized_uri(uri)
        if normalized is None or not isinstance(first_line, int):
            return
        if not isinstance(text, str) or _UNCOUNTED_LINE_BREAK.search(text):
            return
        if normalized not in self.lines:
            self.lines[normalized] = {}
            self._by_basename.setdefault(_basename(normalized), []).append(normalized)
        lines = self.lines[normalized]
        for offset, line in enumerate(_split_lines(text)):
            lines.setdefault(first_line + offset, line)

    def matching(self, uri: str) -> Iterable[Dict[int, str]]:
        """The lines of every known file ``uri`` may name."""
        for candidate in self._by_basename.get(_basename(uri), []):
            if _same_file(candidate, uri):
                yield self.lines[candidate]


def _known_lines(sarif_report: Any, index: "_SecretIndex") -> _KnownLines:
    """The text of every line any snippet of the report places."""
    known = _KnownLines()
    for result in _all_results(sarif_report):
        for physical in _physical_locations_of(result, related=True):
            uri = _uri_of(physical, index)
            for name in ("region", "contextRegion"):
                region = getattr(physical, name, None)
                known.record(
                    uri,
                    getattr(region, "startLine", None),
                    getattr(getattr(region, "snippet", None), "text", None),
                )
    for artifact in _artifacts_of(sarif_report):
        known.record(
            getattr(getattr(artifact, "location", None), "uri", None),
            1,
            getattr(getattr(artifact, "contents", None), "text", None),
        )
    return known


def _block_end(known: _KnownLines, uri: str, start: int) -> Optional[int]:
    """The line a PEM block starting at ``start`` ends on in ``uri``, if known.

    Each file ``uri`` may name (``_same_file``: equal, or one a suffix of the
    other) gives the first line at or after ``start`` known to end a block; the
    last of those is taken. Two spellings of one file agree on it, and a
    different file of the same name with an earlier END line can then not cut
    the range short.
    """
    ends: List[int] = []
    for lines in known.matching(uri):
        own = [
            number
            for number, text in lines.items()
            if number >= start and _PEM_END in text
        ]
        if own:
            ends.append(min(own))
    return max(ends) if ends else None


def _starts_a_block(known: _KnownLines, uri: str, line: int) -> bool:
    return any(_PEM_BEGIN in (lines.get(line) or "") for lines in known.matching(uri))


class _LineRanges:
    """A set of line numbers kept as inclusive (start, end) ranges.

    One entry per secret finding rather than per line, so a region a stored
    results file says ends at line 3,000,000 costs one pair, not three million
    integers.
    """

    def __init__(self, ranges: Iterable[Tuple[int, int]] = ()) -> None:
        self.ranges: List[Tuple[int, int]] = list(ranges)

    def add(self, start: int, end: int) -> None:
        self.ranges.append((start, max(start, end)))

    def __contains__(self, line: object) -> bool:
        return isinstance(line, int) and any(
            start <= line <= end for start, end in self.ranges
        )

    def overlaps(self, start: int, end: int) -> bool:
        return any(first <= end and start <= last for first, last in self.ranges)

    def __or__(self, other: "_LineRanges") -> "_LineRanges":
        return _LineRanges(self.ranges + other.ranges)

    def __bool__(self) -> bool:
        return bool(self.ranges)


class _SecretIndex:
    """The locations and values the secret findings of one scan report."""

    def __init__(self) -> None:
        #: normalized uri -> reported lines, or None for the whole file.
        self.lines: Dict[str, Optional[_LineRanges]] = {}
        self._by_basename: Dict[str, List[str]] = {}
        self.values: Set[str] = set()
        self.shapes: Set[SecretValueShape] = set()
        #: The secret findings themselves, whose own snippets are masked whole.
        self.secret_results: List[Any] = []
        #: (uri, first line, last line, values) of each secret finding's location:
        #: every finding that overlaps it has these values masked, whatever they
        #: look like. The lines are None when the location gives none. Looked up
        #: by the file's basename (``local_values_for``), as the locations are.
        self.local_values: List[Tuple[str, Optional[int], Optional[int], Set[str]]] = []
        self._local_by_basename: Dict[str, List[int]] = {}
        #: id(secret finding) -> every value it exposed, whatever it looks like.
        self.values_of: Dict[int, Set[str]] = {}
        #: (key finding, the END line each primary location's range ran to in the
        #: order of the finding's locations with None where a location recorded
        #: none, the positions whose range ran to the end of the file) for the
        #: masking to record on the finding (``_mask_report``), so the next
        #: masking takes the same range per location instead of reading it off
        #: snippet text, and the finding's own region is left as written.
        self.end_marks: List[Tuple[Any, List[Optional[int]], List[int]]] = []
        #: id(artifact location) -> (the location, its artifact's uri, its
        #: uriBaseId), for a location of this report that names its file by index
        #: into the run's artifacts and carries no uri of its own
        #: (``_resolve_artifact_uris``). ``_uri_of`` reads it in place of the
        #: location's own uri, so the location is left as written. The location
        #: is kept with its entry so its id is not reused while the map holds it.
        self.resolved_uris: Dict[int, Tuple[Any, str, Any]] = {}
        self._pattern: Optional[re.Pattern[str]] = None

    def add_values(self, values: Iterable[str]) -> None:
        """Add the values that are masked wherever they occur (``_propagates``)."""
        for value in values:
            if isinstance(value, str) and _propagates(value):
                self.values.add(value)
                self._pattern = None

    def add_shapes(self, shapes: Iterable[Any]) -> None:
        """Add shapes of values whose tokens are masked wherever they occur.

        A shape read from a results file is checked against what
        ``_mask_secret_value`` would have shown for its length, and against the
        lengths a shape can have (``MIN_PROPAGATED_VALUE_LENGTH`` to
        ``MAX_PROPAGATED_VALUE_LENGTH``); one that does not match was not written
        by ASH and is ignored.
        """
        for shape in shapes:
            if isinstance(shape, dict):
                try:
                    shape = SecretValueShape.model_validate(shape)
                except ValueError:
                    continue
            if not isinstance(shape, SecretValueShape):
                continue
            if (
                not MIN_PROPAGATED_VALUE_LENGTH
                <= shape.length
                <= MAX_PROPAGATED_VALUE_LENGTH
                or (len(shape.prefix), len(shape.suffix))
                != _visible_lengths(shape.length)
            ):
                continue
            self.shapes.add(shape)
            self._pattern = None

    def add_local_values(
        self, uri: str, start: Optional[int], end: Optional[int], values: Set[str]
    ) -> None:
        """Record the values a secret finding exposed at a location of ``uri``."""
        self._local_by_basename.setdefault(_basename(uri), []).append(
            len(self.local_values)
        )
        self.local_values.append((uri, start, end, values))

    def local_values_for(
        self, uri: str
    ) -> Iterable[Tuple[str, Optional[int], Optional[int], Set[str]]]:
        """The recorded locations in a file the normalized ``uri`` may name."""
        for position in self._local_by_basename.get(_basename(uri), []):
            entry = self.local_values[position]
            if _same_file(entry[0], uri):
                yield entry

    def add_location(self, uri: str, start: Optional[int], end: Optional[int]) -> None:
        if uri not in self.lines:
            self.lines[uri] = _LineRanges()
            self._by_basename.setdefault(_basename(uri), []).append(uri)
        current = self.lines[uri]
        if current is None:
            return
        if not isinstance(start, int):
            self.lines[uri] = None
            return
        last = end if isinstance(end, int) and end >= start else start
        current.add(start, last)

    def lines_for(self, uri: Any) -> Optional[Tuple[bool, _LineRanges]]:
        """(whole file, lines) a secret finding reports in ``uri``, or None.

        Two URIs name the same file when they are equal or one ends with the other
        at a path separator, so a finding written relative to another directory
        still matches. That can match two different files of one name; masking
        both is the safe side.
        """
        normalized = _normalized_uri(uri)
        if normalized is None:
            return None
        whole = False
        lines = _LineRanges()
        matched = False
        for candidate in self._by_basename.get(_basename(normalized), []):
            if not _same_file(candidate, normalized):
                continue
            matched = True
            reported = self.lines[candidate]
            if reported is None:
                whole = True
            else:
                lines |= reported
        return (whole, lines) if matched else None

    def mask_values(self, text: str) -> str:
        """``text`` with each value, and each token of a recorded shape, masked.

        A token of a shape is masked only when it could be a value the shape
        stands for (``_mask_token``): every shape is of a value that
        ``_propagates``, so a token that is letters alone, a placeholder or too
        repetitive (``_looks_like_a_secret``) is an ordinary word, not that
        value, and is kept. The hidden characters of a shape match ``password``
        and ``provided`` as readily as the credential, and masking them rewrote
        every message that held such a word, bandit's own label among them.

        The longest alternative is tried first, values and shapes together: a
        value that is the punctuation-delimited head of a longer shape token
        (``abc!1234`` in ``abc!1234$efgh5678``) masked its own part and left the
        rest of the token readable, since the shape could no longer match it.
        """
        if not self.values and not self.shapes:
            return text
        if self._pattern is None:
            alternatives: List[Tuple[int, int, str]] = [
                (len(value), 1, _token_pattern(re.escape(value), value[0], value[-1]))
                for value in self.values
            ]
            alternatives.extend(
                (shape.length, 0, _shape_pattern(shape)) for shape in self.shapes
            )
            alternatives.sort(reverse=True)
            self._pattern = re.compile(
                "|".join(pattern for _, _, pattern in alternatives)
            )
        return self._pattern.sub(self._mask_token, text)

    def _mask_token(self, match: "re.Match[str]") -> str:
        """The masked form of a matched value, or the token itself for a shape
        token that is not a value (see ``mask_values``)."""
        token = match.group(0)
        if token in self.values or _looks_like_a_secret(token):
            return _mask_secret_value(token)
        return token


def _token_pattern(body: str, first: Optional[str], last: Optional[str]) -> str:
    """``body`` as a whole token: not preceded or followed by a word character.

    A boundary is asserted only on a side whose own character is a word character
    (or unknown), so a value that starts or ends with punctuation still matches
    next to a word.
    """
    left = r"(?<!\w)" if first is None or _WORD_CHARACTER.match(first) else ""
    right = r"(?!\w)" if last is None or _WORD_CHARACTER.match(last) else ""
    return left + body + right


def _shape_pattern(shape: SecretValueShape) -> str:
    """A token of ``shape``: its prefix, the right number of characters, its suffix.

    The hidden characters may be any non-whitespace character, or any character
    but a line break for a value that held whitespace. Every token of the shape
    that could be a propagating value is masked, including ones that are not the
    value (``_mask_token`` keeps the ordinary words): over-masking is the accepted
    cost of masking a value no result set holds any more.
    """
    hidden = shape.length - len(shape.prefix) - len(shape.suffix)
    character = r"[^\r\n]" if shape.spans_whitespace else r"\S"
    return _token_pattern(
        re.escape(shape.prefix)
        + character
        + "{"
        + str(hidden)
        + "}"
        + re.escape(shape.suffix),
        shape.prefix[:1] or None,
        shape.suffix[-1:] or None,
    )


def _propagates(value: str) -> bool:
    """Whether ``value`` is masked wherever it occurs, not only in its own finding.

    A value a scanner already masked (``_is_masked_form``) hides what it was, so
    only its length counts; it is kept for its shape when no line holds the
    value to read back.
    """
    if "\n" in value or len(value) < MIN_PROPAGATED_VALUE_LENGTH:
        return False
    return _is_masked_form(value) or _looks_like_a_secret(value)


def _looks_like_a_secret(value: str) -> bool:
    """Not letters alone, not a placeholder, and not repetitive (see the constants).

    The punctuation and spaces at either end do not count: ``password:``,
    ``--password`` and ``'secret'`` are the words inside them, and masked
    everywhere they rewrote bandit's own label, which then no longer marked the
    finding as a secret finding on the next pass.
    """
    core = _EDGE_NON_WORD.sub("", value)
    if not core or _WORD_LIKE.fullmatch(core) or _PLACEHOLDER.fullmatch(value):
        return False
    return _entropy(value) >= MIN_PROPAGATED_VALUE_ENTROPY


def _entropy(value: str) -> float:
    """Shannon entropy of ``value``'s characters, in bits per character."""
    counts: Dict[str, int] = {}
    for character in value:
        counts[character] = counts.get(character, 0) + 1
    total = len(value)
    return -sum(count / total * math.log2(count / total) for count in counts.values())


def _mask_message_values(text: str) -> str:
    """``text`` with each value a message quotes masked (``_quoted_values``)."""
    return _mask_spans(text, _quoted_values(text))


def _region_last_line(region: Any, start: int) -> int:
    """The last line a region starting at ``start`` covers: its ``endLine`` when
    it has one at or after ``start``, else the last line of its snippet, else
    ``start``. A region with no ``endLine`` whose snippet has several lines
    covers them all; counted as one line it missed the later ones.

    The snippet's lines are counted both by the breaks scanners count and by every
    break ``str.splitlines`` knows (form feed, vertical tab, NEL, U+2028), and the
    larger count is taken: a snippet with a break only some scanners count covers
    at least that many lines, and the smaller count left the lines after the first
    unmasked."""
    end = getattr(region, "endLine", None)
    text = getattr(getattr(region, "snippet", None), "text", None)
    last = start
    if isinstance(text, str):
        last = start + max(len(_split_lines(text)), len(text.splitlines()), 1) - 1
    if isinstance(end, int) and end > last:
        last = end
    return last


def _snippet_cannot_be_placed(region: Any) -> bool:
    """Whether a region's snippet holds a break only some scanners count, so its
    lines cannot be matched to the file's lines."""
    text = getattr(getattr(region, "snippet", None), "text", None)
    return isinstance(text, str) and bool(_UNCOUNTED_LINE_BREAK.search(text))


def _index_secrets(sarif_report: Any) -> _SecretIndex:
    from automated_security_helper.utils.scanner_tool_types import result_tool_types

    index = _SecretIndex()
    _resolve_artifact_uris(sarif_report, index)
    rule_ids = secret_rule_ids(sarif_report)
    described = _rule_ids_described(sarif_report)
    known: Optional[_KnownLines] = None
    for result in _all_results(sarif_report):
        if not is_secret_finding(result, rule_ids):
            continue
        index.secret_results.append(result)
        private_key = _is_private_key_finding(result)
        text = _text_of(getattr(result, "message", None)) or ""
        quoted = _quoted_values(text)
        # cfn-nag reports a credential rule at its resource's first line only; the
        # property holding the value is somewhere after it. A finding that quotes
        # its value (bandit's "Possible hardcoded password: '...'") names the
        # line itself and is not one of these; nor is a dependency advisory,
        # whose text describes the dependency and whose location is the
        # manifest's first line (_DEPENDENCY_TOOL_TYPES).
        resource_only = (
            not quoted
            and not _is_dependency_finding(result_tool_types(result))
            and (
                _rule_id_of(result) in described
                or _describes_a_credential_in_code(text)
            )
        )
        exposed: List[str] = []
        for value_start, value_end in quoted:
            exposed.extend(_exposed_values(text[value_start:value_end], result))
        if not quoted:
            exposed.extend(_matched_values(result))
        # Every value is masked wherever it looks like a secret; and, whatever it
        # looks like, in every finding that overlaps where this one reports it.
        index.add_values(exposed)
        local = {
            value
            for value in exposed
            if len(value) >= MIN_LOCAL_VALUE_LENGTH and "\n" not in value
        }
        index.values_of[id(result)] = local
        primary = _locations_of(result)
        # The range a masking records on a finding (_mark_masked_range) is one
        # per primary location: the END line that location's range ran to, or
        # that it ran to the end of its file. One record per finding, with the
        # widest location's end, made the next masking take that end at every
        # location and hide more lines than the first did.
        marked = False
        ends: List[Optional[int]] = [None] * len(primary)
        to_end_of_file: List[int] = []
        # A related location of a secret finding (a credential literal reported
        # where it is used) is a secret location too: indexed as is, with no
        # key or resource range of its own.
        for position, location in enumerate(_locations_of(result, related=True)):
            physical = _physical_of(location)
            if physical is None:
                continue
            is_primary = position < len(primary)
            uri = _normalized_uri(_uri_of(physical, index))
            if uri is None:
                continue
            region = getattr(physical, "region", None)
            start = getattr(region, "startLine", None)
            end = getattr(region, "endLine", None)
            if isinstance(start, int):
                end = _region_last_line(region, start)
            if isinstance(start, int) and is_primary:
                # A key reported on its BEGIN line (detect-secrets does) runs to
                # its END line, which only some other finding's snippet may show.
                # With no END line known, every later line is masked.
                if known is None:
                    known = _known_lines(sarif_report, index)
                # A finding whose range an earlier masking recorded is a key
                # block on every later masking too, though its BEGIN line now
                # reads as a masked line.
                recorded = _recorded_block_end(result, position)
                if (
                    private_key
                    or _starts_a_block(known, uri, start)
                    or recorded is not None
                    or _masked_to_end_of_file(result, position)
                ):
                    # The END line some snippet shows now, else the one an
                    # earlier masking recorded (its line reads as masked by
                    # now), else the end of the file: a producer's own endLine
                    # says nothing about where the key ends. The finding records
                    # the range taken (_mask_report); its region is left as the
                    # scanner wrote it.
                    block_end = _block_end(known, uri, start)
                    if block_end is None and recorded is not None:
                        block_end = max(recorded, start)
                    if block_end is not None:
                        # The scanner's own range stands where it reaches
                        # further: the first END line at or after the start
                        # ends the first block, not a range that spans more.
                        end = max(block_end, end)
                    else:
                        end = _TO_END_OF_FILE
                    marked = True
                    if block_end is None:
                        to_end_of_file.append(position)
                    else:
                        ends[position] = block_end
                elif (
                    resource_only
                    and not _has_columns(region)
                    and (end <= start or _snippet_cannot_be_placed(region))
                ):
                    # cdk-nag writes endLine == startLine for the resource's
                    # first line; a one-line region says nothing about where
                    # the resource ends. A snippet with a break some scanners
                    # do not count cannot be placed line by line, so the lines
                    # it spans (_region_last_line) say nothing about the
                    # resource either. A finding that reports a column (bandit,
                    # semgrep) points at a span of its line, not at a resource,
                    # whatever its message says about hard-coded credentials.
                    end = _TO_END_OF_FILE
            index.add_location(uri, start, end)
            if local:
                index.add_local_values(
                    uri,
                    start if isinstance(start, int) else None,
                    end
                    if isinstance(end, int) and isinstance(start, int) and end >= start
                    else start,
                    local,
                )
        if marked:
            index.end_marks.append((result, ends, to_end_of_file))
    return index


def _line_spans(physical: Any) -> List[Tuple[Optional[int], Optional[int]]]:
    """The (first, last) lines a physical location's region and context cover.

    A region or context with a first line covers through its ``endLine`` or the
    last line of its snippet, whichever is further (``_region_last_line``).
    ``(None, None)`` for one with a snippet but no first line, which cannot be
    placed.
    """
    spans: List[Tuple[Optional[int], Optional[int]]] = []
    for name in ("region", "contextRegion"):
        region = getattr(physical, name, None)
        if region is None:
            continue
        start = getattr(region, "startLine", None)
        if isinstance(start, int):
            spans.append((start, _region_last_line(region, start)))
        elif getattr(region, "snippet", None) is not None:
            spans.append((None, None))
    return spans


def _overlaps_a_secret(result: Any, index: _SecretIndex) -> bool:
    """Whether a location of ``result`` lies on a line a secret finding reports."""
    for physical in _physical_locations_of(result, related=True):
        placed = index.lines_for(_uri_of(physical, index))
        if placed is None:
            continue
        whole, lines = placed
        if whole:
            return True
        for first, last in _line_spans(physical):
            if first is None or lines.overlaps(
                first, last if last is not None else first
            ):
                return True
    return False


def _overlapping_values(result: Any, index: _SecretIndex) -> Set[str]:
    """The values of the secret findings whose location ``result`` overlaps."""
    found: Set[str] = set()
    if not index.local_values:
        return found
    for physical in _physical_locations_of(result, related=True):
        uri = _normalized_uri(_uri_of(physical, index))
        if uri is None:
            continue
        for first, last in _line_spans(physical):
            found |= _values_at(uri, first, last, index)
    return found


def _values_at(
    uri: str, first: Optional[int], last: Optional[int], index: _SecretIndex
) -> Set[str]:
    """The values of the secret findings whose location lines ``first``-``last``
    of the normalized ``uri`` overlap; a span with no line overlaps every one."""
    found: Set[str] = set()
    for _, start, end, values in index.local_values_for(uri):
        # A span with no line cannot be placed, so it overlaps. Each pair is None
        # together (_line_spans, _index_secrets), so the end checks only say so
        # to the type checker.
        if (
            first is None
            or last is None
            or start is None
            or end is None
            or (first <= end and start <= last)
        ):
            found |= values
    return found


def _matched_values(result: Any) -> List[str]:
    """What a secret finding's own region matched, for one that quotes no value.

    semgrep and opengrep report a match by columns on its line: the key itself,
    or an assignment holding it, whose string literals are then the values. Only
    a single-line region with both columns is read, and only where the snippet
    can be placed on the line: a snippet too short to hold the columns (the
    matched text alone, say) is not, and one the contextRegion shows to start
    after the line's first column is read at the matching offset
    (``_snippet_column_offset``), since the columns are the file line's.
    """
    values: List[str] = []
    for physical in _physical_locations_of(result):
        region = getattr(physical, "region", None)
        start_line = getattr(region, "startLine", None)
        end_line = getattr(region, "endLine", None) or start_line
        start = getattr(region, "startColumn", None)
        end = getattr(region, "endColumn", None)
        text = getattr(getattr(region, "snippet", None), "text", None)
        if not (
            isinstance(text, str)
            and isinstance(start, int)
            and isinstance(end, int)
            and start_line == end_line
            and 1 <= start < end
        ):
            continue
        lines = _split_lines(text)
        # A line already masked holds no value: the columns were the original
        # line's, and read from ``MASKED_LINE`` they gave a piece of it, which
        # masking the results again then masked inside the masked line.
        if not lines or lines[0].strip() == MASKED_LINE:
            continue
        offset = _snippet_column_offset(physical, start_line, lines[0])
        if offset is None:
            continue
        first, last = start - 1 - offset, end - 1 - offset
        # The columns are the file line's. A snippet that does not reach the
        # region's end does not start at column 1, and slicing it at these
        # columns would read a fragment of the match.
        if first < 0 or last > len(lines[0]):
            continue
        match = lines[0][first:last].strip()
        literals = _string_literals(match)
        values.extend(literals or [match])
    return values


def _snippet_column_offset(
    physical: Any, line_number: Any, snippet_line: str
) -> Optional[int]:
    """How many columns of the file's line precede the region snippet's first line.

    Read from the contextRegion when it places that line: 0 when its text is the
    snippet's line, the difference in length when the snippet is its tail, and
    None when the two disagree otherwise, since the snippet then cannot be placed
    on the line and the columns would read a fragment. A contextRegion that does
    not place the line gives 0: the snippet is taken to start at column 1, as
    semgrep's and opengrep's do.
    """
    context = getattr(physical, "contextRegion", None)
    context_start = getattr(context, "startLine", None)
    text = getattr(getattr(context, "snippet", None), "text", None)
    if (
        not isinstance(context_start, int)
        or not isinstance(line_number, int)
        or not isinstance(text, str)
        or _UNCOUNTED_LINE_BREAK.search(text)
    ):
        return 0
    context_lines = _split_lines(text)
    position = line_number - context_start
    if not 0 <= position < len(context_lines):
        return 0
    full_line = context_lines[position]
    if full_line == snippet_line:
        return 0
    if full_line.endswith(snippet_line):
        return len(full_line) - len(snippet_line)
    return None


_QUOTES = frozenset("\"'")


def _string_literals(line: str) -> List[str]:
    """The body of every quoted string literal in a line of source, in order.

    A literal runs from a quote to the next quote of its kind that an odd run of
    backslashes does not escape; what it holds is kept as written. An unterminated
    quote starts no literal, and the scan goes on from the character after it, so
    a literal of the other kind inside it is still found. One pass over the line:
    a pattern tried again from every quote took time quadratic in the length of
    a line of escaped quotes with no closing one.
    """
    literals: List[str] = []
    unescaped: Dict[str, List[int]] = {quote: [] for quote in _QUOTES}
    backslashes = 0
    for position, character in enumerate(line):
        if character == "\\":
            backslashes += 1
            continue
        if character in _QUOTES and backslashes % 2 == 0:
            unescaped[character].append(position)
        backslashes = 0
    pending = dict.fromkeys(_QUOTES, 0)
    position = 0
    length = len(line)
    while position < length:
        character = line[position]
        if character not in _QUOTES:
            position += 1
            continue
        closers = unescaped[character]
        cursor = pending[character]
        while cursor < len(closers) and closers[cursor] <= position:
            cursor += 1
        pending[character] = cursor
        if cursor < len(closers):
            closing = closers[cursor]
            literals.append(line[position + 1 : closing])
            position = closing + 1
        else:
            position += 1
    return literals


def _exposed_values(quoted: str, result: Any) -> List[str]:
    """The value a message quotes; if the scanner already masked it, read from the finding's line.

    A scanner can mask the value in its own message before the results are
    merged (``BanditScanner._post_process_sarif`` does), leaving the shape
    ``_mask_secret_value`` writes. The value is then the string literal in the
    lines the finding itself reports whose mask is exactly that shape. Those lines
    are masked by location anyway; the value is recovered so that its reuse on a
    line no secret finding reports is masked too.

    Only the exact shape counts as already masked (``_is_masked_form``): a raw
    value can hold a ``*`` too, and is returned as it is, without the whitespace
    around it. When no line holds a value whose mask is the quoted one, the
    masked form itself is returned: masking it again changes nothing, and it
    still carries the value's shape. It is not returned beside a value read back,
    whose own test decides whether it is masked elsewhere (``_propagates``): the
    masked form of ``password`` would otherwise mask every eight-letter word that
    starts with p and ends with d. ``quoted`` is the text between the quotes as
    written: a value with spaces around it masks to a form with those spaces, and
    read back it has to match that form.
    """
    stripped = quoted.strip()
    if not stripped:
        return []
    forms = {form for form in (quoted, stripped) if _is_masked_form(form)}
    if not forms:
        return [stripped]
    found = []
    for line in _own_snippet_lines(result):
        for candidate in _string_literals(line):
            if candidate not in forms and _mask_secret_value(candidate) in forms:
                found.append(candidate)
    return found or [stripped]


def _is_masked_form(text: str) -> bool:
    """Whether ``text`` has the shape ``_mask_secret_value`` writes for its length.

    The hidden characters are all asterisks and the visible ones are not: a value
    of asterisks alone (the ``********`` of a placeholder password) is a value,
    not a masked form. Taken as one it was propagated as a shape with no token
    boundary, which masked every run of eight characters from ``*`` to ``*``,
    Markdown's ``**Note**`` among them.
    """
    shown_prefix, shown_suffix = _visible_lengths(len(text))
    hidden = text[shown_prefix : len(text) - shown_suffix]
    visible = text[:shown_prefix] + text[len(text) - shown_suffix :]
    if not hidden or set(hidden) != {"*"}:
        return False
    return not visible or set(visible) != {"*"}


def _own_snippet_lines(result: Any) -> List[str]:
    """The snippet lines at ``result``'s own region, from its region and contextRegion."""
    lines: List[str] = []
    for physical in _physical_locations_of(result):
        region = getattr(physical, "region", None)
        start = getattr(region, "startLine", None)
        end_line = getattr(region, "endLine", None)
        text = getattr(getattr(region, "snippet", None), "text", None)
        if isinstance(text, str):
            lines.extend(_split_lines(text))
        context = getattr(physical, "contextRegion", None)
        context_start = getattr(context, "startLine", None)
        context_text = getattr(getattr(context, "snippet", None), "text", None)
        if not isinstance(context_text, str):
            continue
        context_lines = _split_lines(context_text)
        if (
            not isinstance(start, int)
            or not isinstance(context_start, int)
            or _UNCOUNTED_LINE_BREAK.search(context_text)
        ):
            # The region's lines cannot be placed in the context, so every line is
            # a candidate; a candidate must still mask to exactly the quoted shape.
            lines.extend(context_lines)
            continue
        # A region with no end line ends where it starts.
        end = end_line if isinstance(end_line, int) and end_line else start
        for offset, line in enumerate(context_lines):
            if start <= context_start + offset <= end:
                lines.append(line)
    return lines


def _mask_lines(
    text: str, first_line: Optional[int], whole: bool, lines: _LineRanges
) -> str:
    """``text`` with each line at a reported line number replaced by ``MASKED_LINE``.

    Lines are counted the way scanners count them (``_split_lines``). A snippet
    that cannot be placed -- its first line number is unknown, or it holds a
    character only some line counts break at (``_UNCOUNTED_LINE_BREAK``) -- is in
    a file with secret findings, so every line of it is replaced.
    """
    if _UNCOUNTED_LINE_BREAK.search(text):
        whole = True
    out = []
    for offset, line in enumerate(_split_lines(text, keepends=True)):
        number = first_line + offset if isinstance(first_line, int) else None
        if whole or number is None or number in lines:
            body = line.rstrip("\r\n")
            ending = line[len(body) :]
            if body.strip() and body.strip() != MASKED_LINE:
                indent = body[: len(body) - len(body.lstrip())]
                line = indent + MASKED_LINE + ending
        out.append(line)
    return "".join(out)


def _mask_snippet(
    content: Any,
    first_line: Optional[int],
    last_line: Optional[int],
    placed: Tuple[bool, _LineRanges],
) -> None:
    """Mask one ``ArtifactContent`` in place by the reported lines in its file.

    The text and its plain rendering are masked line by line. The Markdown
    rendering is not numbered like the text (a code fence puts the first line of
    code on its second line), so it is masked whole when the content reaches a
    reported line, as the base64 form is dropped then.
    """
    whole, lines = placed
    if content is None:
        return
    text = getattr(content, "text", None)
    if isinstance(text, str):
        masked = _mask_lines(text, first_line, whole, lines)
        if masked != text:
            content.text = masked
    if isinstance(first_line, int):
        last = max(first_line, last_line or 0)
        if isinstance(text, str):
            last = max(last, first_line + len(_split_lines(text)) - 1)
        reached = whole or lines.overlaps(first_line, last)
    else:
        reached = True
    rendered = getattr(content, "rendered", None)
    if rendered is not None:
        plain = getattr(rendered, "text", None)
        if isinstance(plain, str):
            masked = _mask_lines(plain, first_line, whole, lines)
            if masked != plain:
                rendered.text = masked
        markdown = getattr(rendered, "markdown", None)
        if isinstance(markdown, str) and reached:
            masked = _mask_text_whole(markdown)
            if masked != markdown:
                rendered.markdown = masked
    # Base64 content cannot be masked line by line, so it is dropped when its
    # lines reach a reported line, or cannot be placed.
    if getattr(content, "binary", None) is not None and reached:
        content.binary = None


def _mask_region(region: Any, placed: Tuple[bool, _LineRanges]) -> None:
    if region is None:
        return
    _mask_snippet(
        getattr(region, "snippet", None),
        getattr(region, "startLine", None),
        getattr(region, "endLine", None),
        placed,
    )


#: Properties under which a result carries source text outside its regions'
#: snippets: a ``snippet`` a tool writes into the result's properties (the flat
#: model reads it as the finding's code) and cdk-nag's ``cfn_resource``, the
#: resource the finding is about with every property value. A fix's
#: ``insertedContent`` and ``deletedRegion`` and a fenced code block in the
#: message carry source text too. For a secret finding they are its excerpt of
#: the secret and are masked whole, like its snippets: masked by value alone
#: they kept a credential whose finding quotes no value.
_SOURCE_FIELDS = frozenset({"snippet", "cfn_resource"})


def _mask_text_whole(text: str) -> str:
    """Every non-blank line of ``text`` replaced with ``MASKED_LINE``."""
    return _mask_lines(text, None, True, _LineRanges())


def _mask_source_whole(node: Any, seen: Set[int]) -> Any:
    """Mask every leaf of ``node`` in place; returns a leaf node's replacement.

    ``node`` is a secret finding's own excerpt of the secret (a ``cfn_resource``
    with every property value, a ``snippet``), so nothing in it is an identifier
    worth keeping: every string, under whatever key, and every number (a port, a
    PIN) is replaced. Only an enum member, which a model refuses any other value
    for, is left alone.
    """
    if isinstance(node, Enum):
        return node
    if isinstance(node, str):
        return _mask_text_whole(node)
    if isinstance(node, (int, float)) and not isinstance(node, bool):
        return MASKED_LINE
    if id(node) in seen:
        return node
    if isinstance(node, BaseModel):
        seen.add(id(node))
        names = list(type(node).model_fields)
        names.extend((node.__pydantic_extra__ or {}).keys())
        for name in names:
            if _is_enum_annotated(node, name):
                continue
            value = getattr(node, name, None)
            if value is None:
                continue
            masked = _mask_source_whole(value, seen)
            if masked is not value and not isinstance(value, (BaseModel, list, dict)):
                setattr(node, name, masked)
        return node
    if isinstance(node, list):
        seen.add(id(node))
        for position, item in enumerate(node):
            masked = _mask_source_whole(item, seen)
            if masked is not item and not isinstance(item, (BaseModel, list, dict)):
                node[position] = masked
        return node
    if isinstance(node, dict):
        seen.add(id(node))
        for key in list(node):
            item = node[key]
            masked = _mask_source_whole(item, seen)
            if masked is not item and not isinstance(item, (BaseModel, list, dict)):
                node[key] = masked
        return node
    return node


#: Markdown code fences, backticks and tildes.
_CODE_FENCES = ("```", "~~~")


def _mask_fenced_code(text: str) -> str:
    """``text`` with every line inside a code fence masked.

    The flat model reads the first fenced block of a message as the finding's
    code (``_extract_snippet_from_message`` splits on the backtick fence wherever
    it stands) and the HTML and text reports print it, so a secret finding's
    fenced block is its snippet by another name. The text after an opening fence
    with no closing one (a message cut short) is masked to the end: it is code
    the reports print as a block too.
    """
    for fence in _CODE_FENCES:
        if fence not in text:
            continue
        parts = text.split(fence)
        for position in range(1, len(parts), 2):
            parts[position] = _mask_text_whole(parts[position])
        text = fence.join(parts)
    return text


def _extra_of(node: Any) -> Dict[str, Any]:
    return getattr(node, "__pydantic_extra__", None) or {}


def _set_extra(node: Any, name: str, value: Any) -> None:
    extra = getattr(node, "__pydantic_extra__", None)
    if isinstance(extra, dict):
        extra[name] = value


def _replacements_of(result: Any) -> Iterable[Tuple[Any, Any]]:
    """(artifact change, replacement) of every fix a result proposes."""
    for fix in getattr(result, "fixes", None) or []:
        for change in getattr(fix, "artifactChanges", None) or []:
            for replacement in getattr(change, "replacements", None) or []:
                yield change, replacement


def _annotation_regions(result: Any) -> Iterable[Any]:
    """The annotation regions of every location of ``result``, and the regions
    of every attachment it carries: source text outside its snippets."""
    for location in _locations_of(result, related=True):
        yield from getattr(location, "annotations", None) or []
    for attachment in getattr(result, "attachments", None) or []:
        yield from getattr(attachment, "regions", None) or []


def _mask_own_source_text(result: Any, index: _SecretIndex) -> None:
    """Mask whole the source text a secret finding carries outside its snippets.

    Its ``properties`` named in ``_SOURCE_FIELDS``, the inserted content and
    deleted region of every fix it proposes, the annotation regions of its
    locations and the regions of its attachments, and a fenced code block in its
    message. Its message's text and markdown are masked at the values they quote
    and at every value the finding exposed that is not an ordinary word
    (``_WORD_LIKE``): a value its region matched and its message repeats is
    masked there too, while the words of a label such as "Possible hardcoded
    password:" are left, since they are what recognizes the finding. Its message
    arguments are masked at every value the finding exposed, whatever it looks
    like.
    """
    whole_file = (True, _LineRanges())
    properties = getattr(result, "properties", None)
    if properties is not None:
        for name in _SOURCE_FIELDS:
            value = _extra_of(properties).get(name)
            if value is None:
                continue
            masked = _mask_source_whole(value, set())
            if masked is not value and not isinstance(value, (list, dict)):
                _set_extra(properties, name, masked)
    for _, replacement in _replacements_of(result):
        _mask_region(getattr(replacement, "deletedRegion", None), whole_file)
        _mask_snippet(
            getattr(replacement, "insertedContent", None), None, None, whole_file
        )
    for region in _annotation_regions(result):
        _mask_region(region, whole_file)
    message = getattr(result, "message", None)
    root: Any = getattr(message, "root", message)
    if root is None:
        return
    own = _SecretIndex()
    own.values = set(index.values_of.get(id(result), ()))
    in_text = _SecretIndex()
    in_text.values = {
        value
        for value in own.values
        if not _WORD_LIKE.fullmatch(_EDGE_NON_WORD.sub("", value))
    }
    for name in ("text", "markdown"):
        text = getattr(root, name, None)
        if isinstance(text, str):
            masked = _mask_fenced_code(in_text.mask_values(_mask_message_values(text)))
            if masked != text:
                setattr(root, name, masked)
    arguments = getattr(root, "arguments", None)
    if isinstance(arguments, list):
        for position, argument in enumerate(arguments):
            if isinstance(argument, str):
                masked = own.mask_values(_mask_message_values(argument))
                if masked != argument:
                    arguments[position] = masked


def _changed(item: Any, masked: Any) -> bool:
    """Whether a parent holding ``item`` has to store ``masked`` in its place: a
    string masked to another, or a URL masked to a new object."""
    if isinstance(item, str):
        return masked != item
    return isinstance(item, AnyUrl) and masked is not item


def _mask_url(node: AnyUrl, index: _SecretIndex) -> Any:
    """``node`` with the values in it masked: the same URL when nothing changed,
    else a URL of the masked text, or that text when it is no URL any more.

    A pydantic URL (``versionControlProvenance.repositoryUri``,
    ``hostedViewerUri``) is neither a str nor a model, and a credential written
    into it (``https://user:token@host/repo``) was kept.

    ``str(node)`` is the URL as pydantic writes it, with the userinfo and the path
    percent-encoded, so a value with ``@``, ``:``, ``/``, ``#``, ``?``, ``%`` or a
    character outside ASCII is in it in its encoded spelling; the values are
    masked in each spelling reports use (``mask_secret_values_in_text``) as well
    as plain.
    """
    text = str(node)
    masked = mask_secret_values_in_text(index.mask_values(text), index.values)
    if masked == text:
        return node
    try:
        return type(node)(masked)
    except (ValueError, TypeError):
        return masked


def _rename_masked_key(mapping: Dict[Any, Any], key: str, index: _SecretIndex) -> None:
    """Replace ``key`` of ``mapping`` by its masked text, keeping its value.

    The raw key is always removed. When the masked text is already a key of the
    mapping (two keys masked to the same text, or a key that already reads like
    the masked form), the value is stored under the masked text with a number
    after it, so no value is lost and no raw key is kept.
    """
    masked_key = index.mask_values(key)
    if masked_key == key:
        return
    value = mapping.pop(key)
    target = masked_key
    number = 2
    while target in mapping:
        target = f"{masked_key}#{number}"
        number += 1
    mapping[target] = value


def _mask_tree(
    node: Any,
    index: _SecretIndex,
    seen: Set[int],
    parent: Optional[str] = None,
    skipped_keys: Tuple[str, ...] = (),
) -> Any:
    """Mask ``node`` in place; returns the replacement for a string or URL node.

    ``skipped_keys`` names keys of a plain dict ``node`` under which nothing is
    masked and whose names are kept, beyond ``_is_skipped_key``; it applies to
    that dict alone, not to the dicts under it.
    """
    if isinstance(node, Enum):
        # An enum member (Result.level, Suppression.kind) is a str as well, and
        # masking it wrote a value the model refuses (_ENUM_FIELDS).
        return node
    if isinstance(node, str):
        return index.mask_values(node)
    if isinstance(node, AnyUrl):
        return _mask_url(node, index)
    if id(node) in seen:
        return node
    if isinstance(node, BaseModel):
        seen.add(id(node))
        fields = type(node).model_fields
        if "artifactLocation" in fields and "contextRegion" in fields:
            placed = index.lines_for(_uri_of(node, index))
            if placed is not None:
                _mask_region(getattr(node, "region", None), placed)
                _mask_region(getattr(node, "contextRegion", None), placed)
        elif "physicalLocation" in fields and "annotations" in fields:
            # A location's annotations are regions of its physical location's
            # file, placed by their own lines.
            placed = index.lines_for(_uri_of(_physical_of(node), index))
            if placed is not None:
                for region in getattr(node, "annotations", None) or []:
                    _mask_region(region, placed)
        elif "artifactLocation" in fields and "regions" in fields:
            # An attachment: regions of interest in the file it names.
            placed = index.lines_for(_uri_of(node, index))
            if placed is not None:
                for region in getattr(node, "regions", None) or []:
                    _mask_region(region, placed)
        elif "artifactLocation" in fields and "replacements" in fields:
            # A fix's change to one file: its deleted regions are placed by
            # their lines; what it inserts at a reported line is masked whole.
            placed = index.lines_for(_uri_of(node, index))
            if placed is not None:
                whole, lines = placed
                for replacement in getattr(node, "replacements", None) or []:
                    deleted = getattr(replacement, "deletedRegion", None)
                    _mask_region(deleted, placed)
                    first = getattr(deleted, "startLine", None)
                    last = getattr(deleted, "endLine", None)
                    if (
                        whole
                        or not isinstance(first, int)
                        or lines.overlaps(
                            first, last if isinstance(last, int) else first
                        )
                    ):
                        _mask_snippet(
                            getattr(replacement, "insertedContent", None),
                            None,
                            None,
                            (True, _LineRanges()),
                        )
        elif "ruleId" in fields and "locations" in fields:
            # A result's properties.snippet is its first location's code, numbered
            # from that location's first line when it spans no more lines than
            # the region does. A snippet with more lines than the region (context
            # lines above it) cannot be placed: the secret line could be any of
            # them, so it is masked whole when any line it could cover is one a
            # secret finding reports.
            properties = getattr(node, "properties", None)
            snippet = _extra_of(properties).get("snippet")
            physical = next(iter(_physical_locations_of(node)), None)
            if isinstance(snippet, str) and physical is not None:
                placed = index.lines_for(_uri_of(physical, index))
                if placed is not None:
                    whole, lines = placed
                    region = getattr(physical, "region", None)
                    first = getattr(region, "startLine", None)
                    last = getattr(region, "endLine", None)
                    count = len(_split_lines(snippet))
                    span = (
                        max(last, first) - first + 1
                        if isinstance(first, int) and isinstance(last, int)
                        else 1
                    )
                    if (
                        not whole
                        and isinstance(first, int)
                        and count > span
                        and lines.overlaps(first - (count - span), first + count - 1)
                    ):
                        masked = _mask_text_whole(snippet)
                    else:
                        masked = _mask_lines(snippet, first, whole, lines)
                    if masked != snippet:
                        _set_extra(properties, "snippet", masked)
            # A fenced code block in the message of a finding that overlaps a
            # secret finding's lines is that finding's excerpt of the same
            # lines, with no line numbers to place it by: masked whole, as its
            # properties.snippet and fixes are at those lines.
            if _overlaps_a_secret(node, index):
                message = getattr(node, "message", None)
                root: Any = getattr(message, "root", message)
                for name in ("text", "markdown"):
                    text = getattr(root, name, None) if root is not None else None
                    if isinstance(text, str):
                        masked = _mask_fenced_code(text)
                        if masked != text:
                            setattr(root, name, masked)
        elif ("tool" in fields or "driver" in fields) and "results" in fields:
            # A run (or an external property set): its tool components are rule
            # metadata and are skipped (_METADATA_FIELDS), but the scanner
            # details ASH writes on them carry the tool's invocation (command
            # line, arguments), which is text a value can be in.
            tool = getattr(node, "tool", None)
            components = [getattr(tool, "driver", None)]
            components.extend(getattr(tool, "extensions", None) or [])
            components.append(getattr(node, "driver", None))
            components.extend(getattr(node, "extensions", None) or [])
            for component in components:
                properties = getattr(component, "properties", None)
                details = _extra_of(properties).get("scanner_details")
                if details is None:
                    continue
                masked = _mask_tree(details, index, seen)
                if isinstance(details, str) and masked != details:
                    _set_extra(properties, "scanner_details", masked)
        elif "contents" in fields and "location" in fields:
            # An artifact whose contents a tool embedded: line 1 is the file's first.
            placed = index.lines_for(
                getattr(getattr(node, "location", None), "uri", None)
            )
            if placed is not None:
                # The contents run to the file's last line, wherever that is:
                # base64 contents are dropped when any line of the file is
                # reported, not only line 1.
                _mask_snippet(
                    getattr(node, "contents", None), 1, _TO_END_OF_FILE, placed
                )
        names = list(fields)
        names.extend((node.__pydantic_extra__ or {}).keys())
        for name in names:
            if _is_skipped_field(node, name):
                continue
            value = getattr(node, name, None)
            if value is None:
                continue
            masked = _mask_tree(value, index, seen)
            if _changed(value, masked):
                if isinstance(value, str):
                    # A string field that declares a pattern (every GUID field)
                    # has to match it after masking too.
                    pattern = _field_pattern(node, name)
                    if pattern is not None:
                        masked = _keep_the_pattern(pattern, value, masked)
                setattr(node, name, masked)
        # The names of a model's extra fields are text a value can be in too
        # (a map keyed by the values it holds), as a dict's keys are.
        extra = getattr(node, "__pydantic_extra__", None)
        if isinstance(extra, dict):
            for key in list(extra):
                if isinstance(key, str) and not _is_skipped_field(node, key):
                    _rename_masked_key(extra, key, index)
        return node
    if isinstance(node, list):
        for position, item in enumerate(node):
            masked = _keep_the_key_pattern(
                parent, item, _mask_tree(item, index, seen, parent)
            )
            if _changed(item, masked):
                node[position] = masked
        return node
    if isinstance(node, dict):
        for key in list(node):
            if isinstance(key, str) and (
                key in skipped_keys or _is_skipped_key(key, parent)
            ):
                continue
            item = node[key]
            masked = _mask_tree(
                item, index, seen, key if isinstance(key, str) else None
            )
            masked = _keep_the_key_pattern(
                key if isinstance(key, str) else None, item, masked
            )
            if _changed(item, masked):
                node[key] = masked
            # A value used as a key (a map keyed by the values it holds) is text
            # of the tree as much as any other string.
            if isinstance(key, str):
                _rename_masked_key(node, key, index)
        return node
    return node


def _mask_report(
    sarif_report: Any,
    values: Iterable[str] = (),
    shapes: Iterable[Any] = (),
) -> _SecretIndex:
    """Mask a SARIF report in place; returns the index it masked by.

    ``values`` and ``shapes`` are masked as well as what the report's own secret
    findings expose; every value's shape joins the index's shapes.
    """
    has_runs = _has_runs(sarif_report)
    # Indexed before the messages are masked, which removes the values from them.
    index = _index_secrets(sarif_report) if has_runs else _SecretIndex()
    index.add_values(values)
    index.add_shapes(shapes)
    index.add_shapes(secret_value_shape(value) for value in index.values)
    if not has_runs:
        return index
    # A key block's range, its END line found in another finding's snippet or the
    # end of the file, is recorded on the key finding: the next masking (every
    # reload, ash merge, the findings browser) reads those lines as MASKED_LINE
    # and could not place the block again. The finding's own region is left as
    # the scanner wrote it: the file and lines are its identity across scans.
    for result, ends, to_end_of_file in index.end_marks:
        _mark_masked_range(result, ends, to_end_of_file)
    for result in _all_results(sarif_report):
        message = getattr(result, "message", None)
        root: Any = getattr(message, "root", message)
        if root is None:
            continue
        for name in ("text", "markdown"):
            text = getattr(root, name, None)
            if isinstance(text, str):
                masked = _mask_message_values(text)
                if masked != text:
                    setattr(root, name, masked)
    # A secret finding's own snippets are its excerpt of the secret, so they are
    # masked whole rather than by line number: a tool's context can be numbered
    # one off (ferret-scan's is), and the line arithmetic would keep the secret.
    # So is the source text it carries elsewhere (_mask_own_source_text).
    whole_file = (True, _LineRanges())
    for result in index.secret_results:
        for physical in _physical_locations_of(result, related=True):
            _mask_region(getattr(physical, "region", None), whole_file)
            _mask_region(getattr(physical, "contextRegion", None), whole_file)
        _mask_own_source_text(result, index)
    # A value that does not look like a secret is not masked everywhere, but it is
    # masked in every finding whose region or context overlaps the secret
    # finding's location: what that finding reports is the same line. This pass
    # runs before the one by value and shape: that one can mask a token inside
    # such a value and leave the rest of it, which no longer matches here.
    if index.local_values:
        secret_ids = {id(result) for result in index.secret_results}
        for result in _all_results(sarif_report):
            values = _overlapping_values(result, index)
            if not values:
                continue
            local_index = _SecretIndex()
            local_index.values = set(values)
            if id(result) not in secret_ids:
                _mask_tree(result, local_index, set())
                continue
            # A secret finding's own message is masked at its quoted value
            # (_mask_message_values); masking the words of its label, as in
            # "Possible hardcoded password:" for the value "password", would
            # change what recognizes it.
            for name in list(type(result).model_fields) + list(
                (result.__pydantic_extra__ or {}).keys()
            ):
                if name == "message" or _is_skipped_field(result, name):
                    continue
                value = getattr(result, name, None)
                if value is None:
                    continue
                masked = _mask_tree(value, local_index, set())
                if _changed(value, masked):
                    setattr(result, name, masked)
    if index.lines or index.values or index.shapes:
        seen: Set[int] = set()
        for run in getattr(sarif_report, "runs", None) or []:
            _mask_tree(run, index, seen)
        for external in _external_properties_of(sarif_report):
            _mask_tree(external, index, seen)
    return index


def mask_secrets_in_sarif_report(sarif_report: Any) -> Any:
    """Mask, in place, every secret a SARIF report's findings expose; returns it."""
    _mask_report(sarif_report)
    return sarif_report


def exposed_secret_values(results: Any) -> Set[str]:
    """The raw values the maskings of ``results`` found, in this process.

    Kept on the model in a private attribute, which is never serialized, so that
    a union of result sets built in the same process -- a workspace's projects --
    can mask each one with the values the others exposed.
    """
    try:
        recorded = getattr(results, "_secret_values")
    except AttributeError:
        return set()
    return set(recorded or ())


def _record(results: Any, index: _SecretIndex) -> None:
    """Keep the index's values on ``results`` (privately) and its shapes (serialized)."""
    try:
        results._secret_values = set(index.values)
    except (AttributeError, TypeError, ValueError):
        pass
    fields = getattr(type(results), "model_fields", None) or {}
    if "secret_value_shapes" in fields:
        shapes = sorted(index.shapes, key=_shape_key)
        if list(getattr(results, "secret_value_shapes", None) or []) != shapes:
            results.secret_value_shapes = shapes


def mask_secrets_in_results(
    results: Any,
    values: Iterable[str] = (),
    shapes: Iterable[Any] = (),
) -> Any:
    """Mask, in place, every secret value the findings of an aggregated result set expose.

    Covers the SARIF report (its runs and its inline external properties), the
    entries of ``additional_reports`` (``_mask_additional_reports``) and the
    CycloneDX SBOM. Called once a scan's results are merged, before
    ``ash_aggregated_results.json`` is saved and before any reporter runs, and on
    every load of a stored results file.

    Also masks ``values`` (raw values other result sets exposed) and every token
    of ``shapes`` and of the shapes ``results`` already records
    (``secret_value_shapes``). What this masking found is recorded on
    ``results`` for the next one: the raw values privately
    (``exposed_secret_values``), their shapes in ``secret_value_shapes``.
    Returns ``results``.
    """
    known_values = set(values) | exposed_secret_values(results)
    known_shapes = list(shapes) + list(
        getattr(results, "secret_value_shapes", None) or []
    )
    index = _mask_report(getattr(results, "sarif", None), known_values, known_shapes)
    additional = getattr(results, "additional_reports", None)
    if isinstance(additional, dict):
        _mask_additional_reports(additional, index)
    # The SBOM is written to the results file and to the CycloneDX, SPDX and
    # GitLab SBOM reports as it is; a value a finding exposed can be in it.
    cyclonedx = getattr(results, "cyclonedx", None)
    if cyclonedx is not None and (index.values or index.shapes):
        _mask_tree(cyclonedx, index, set())
    _record(results, index)
    return results


def _mask_additional_reports(additional: Dict[str, Any], index: _SecretIndex) -> None:
    """Mask a scan's ``additional_reports`` in place.

    Every value and shape the index holds is masked throughout. The entries the
    flat model reads as findings (the dicts in a scanner's list, with
    ``file_path``, ``line_start`` and a ``snippet`` the reports print) are also
    masked the way the SARIF results are: an entry that is itself a secret
    finding has its snippet masked whole and its quoted values masked; any other
    entry has its snippet masked at the lines secret findings report in its file,
    and the values of the secret findings it overlaps masked whatever they look
    like.
    """
    if index.values or index.shapes:
        _mask_tree(additional, index, set())
    for scanner_name, entries in additional.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if isinstance(entry, dict):
                _mask_additional_entry(entry, scanner_name, index)


def _additional_entry_is_secret(entry: Dict[str, Any], scanner_name: Any) -> bool:
    from automated_security_helper.utils.scanner_tool_types import (
        SECRETS_TOOL_TYPE,
        scanner_tool_type,
    )

    tool_type = scanner_tool_type(scanner_name)
    if tool_type == SECRETS_TOOL_TYPE:
        return True
    if _is_secret_rule_id(entry.get("rule_id")):
        return True
    tags = entry.get("tags")
    if isinstance(tags, list) and any(_is_secret_tag(tag) for tag in tags):
        return True
    if tool_type in _DEPENDENCY_TOOL_TYPES:
        # A dependency advisory's text describes the dependency, not a value in
        # the scanned files (_DEPENDENCY_TOOL_TYPES).
        return False
    return any(_text_reports_a_secret(entry.get(name)) for name in _ENTRY_TEXTS)


#: The text fields of an additional-report entry the flat model shows.
_ENTRY_TEXTS = ("description", "title")
#: The fields of an additional-report entry that place it: its rule, and the file
#: and lines the flat model reads it at. They are not text the entry reports, so
#: a secret value they happen to equal (a file named by a value) is left in them;
#: rewriting ``file_path`` lost the entry's place. The entry's ``id`` is not among
#: them: a hash-shaped field can hold a value a scanner matched, and masking it
#: is the side that fails closed (the reasoning of ``_SKIPPED_FIELDS``).
_ENTRY_IDENTIFIERS = ("rule_id", "file_path", "line_start", "line_end")


def _mask_additional_entry(
    entry: Dict[str, Any], scanner_name: Any, index: _SecretIndex
) -> None:
    snippet = entry.get("snippet")
    if _additional_entry_is_secret(entry, scanner_name):
        for name in _ENTRY_TEXTS:
            text = entry.get(name)
            if isinstance(text, str):
                entry[name] = _mask_message_values(text)
        if isinstance(snippet, str):
            entry["snippet"] = _mask_text_whole(snippet)
        return
    uri = _normalized_uri(entry.get("file_path"))
    if uri is None:
        return
    first = entry.get("line_start")
    first = first if isinstance(first, int) else None
    last = entry.get("line_end")
    last = (
        last if isinstance(last, int) and first is not None and last >= first else first
    )
    placed = index.lines_for(uri)
    if placed is not None and isinstance(snippet, str):
        whole, lines = placed
        entry["snippet"] = _mask_lines(snippet, first, whole, lines)
    values = _values_at(uri, first, last, index)
    if values:
        local = _SecretIndex()
        local.values = set(values)
        _mask_tree(entry, local, set(), skipped_keys=_ENTRY_IDENTIFIERS)


def source_snippet_masker(results: Any) -> Callable[[Any, Optional[int], str], str]:
    """A function that masks lines read from a source file as ``results``' snippets are.

    For a reader that shows a finding's file from disk when the results hold no
    snippet for it (the findings browser): the lines at a location a secret
    finding of ``results`` reports, and every value and shape the masking of
    ``results`` found, are masked. ``results`` is read, never changed. The
    function takes the file's URI as the finding names it, the line number of
    the text's first line, and the text.
    """
    sarif_report = getattr(results, "sarif", None)
    has_runs = _has_runs(sarif_report)
    index = _index_secrets(sarif_report) if has_runs else _SecretIndex()
    index.add_values(exposed_secret_values(results))
    index.add_shapes(getattr(results, "secret_value_shapes", None) or [])
    index.add_shapes(secret_value_shape(value) for value in index.values)

    def mask(uri: Any, first_line: Optional[int], text: str) -> str:
        placed = index.lines_for(uri)
        if placed is not None:
            whole, lines = placed
            text = _mask_lines(text, first_line, whole, lines)
        text = index.mask_values(text)
        # The values a secret finding exposed, whatever they look like, are
        # masked in text that shows the lines it reports, as in every finding
        # that overlaps them (_overlapping_values): a short value reused next
        # to its line was shown from disk.
        normalized = _normalized_uri(uri)
        if normalized is not None and index.local_values:
            last = (
                first_line + max(len(_split_lines(text)) - 1, 0)
                if isinstance(first_line, int)
                else None
            )
            values = _values_at(normalized, first_line, last, index)
            if values:
                local = _SecretIndex()
                local.values = set(values)
                text = local.mask_values(text)
        return text

    return mask


def mask_secret_values_in_tree(
    tree: Any, values: Iterable[str], shapes: Iterable[Any] = ()
) -> Any:
    """Mask, in place, ``values`` and tokens of ``shapes`` in every string of ``tree``.

    For results already reduced to plain JSON data (a workspace's spooled SARIF
    runs). Identifiers (``_SKIPPED_FIELDS``) are left alone. Returns ``tree``.
    """
    index = _SecretIndex()
    index.add_values(values)
    index.add_shapes(shapes)
    index.add_shapes(secret_value_shape(value) for value in index.values)
    if index.values or index.shapes:
        _mask_tree(tree, index, set())
    return tree


def _yaml_double_quoted(value: str) -> str:
    """``value`` as the YAML report writes it inside double quotes: the report's
    own dumper (``utils/report_yaml``) escapes the quote, the backslash, the
    control characters and, since it allows no unicode, every character outside
    ASCII, in upper-case hex (``\\xE9``, ``\\u20AC``, and the eight-digit ``\\U``
    form past the basic plane)."""
    from automated_security_helper.utils.report_yaml import report_yaml

    written = report_yaml(value, default_style='"', width=2**31 - 1).strip()
    if len(written) >= 2 and written[0] == written[-1] == '"':
        return written[1:-1]
    return value


def _shown(value: str) -> str:
    """``value`` as the HTML and text reports show it (``terminal_text``): control
    and format characters, and a backslash before text that reads as an escape,
    written as escapes."""
    from automated_security_helper.utils.terminal_text import shown_not_obeyed

    return str(shown_not_obeyed(value))


#: ElementTree's escaping of an attribute value: ``&``, ``<``, ``>`` and ``"``,
#: and the layout characters as character references; the single quote stays.
_XML_ATTRIBUTE_ESCAPES = (
    ("&", "&amp;"),
    ("<", "&lt;"),
    (">", "&gt;"),
    ('"', "&quot;"),
    ("\r", "&#13;"),
    ("\n", "&#10;"),
    ("\t", "&#09;"),
)


def _xml_attribute(value: str) -> str:
    for character, reference in _XML_ATTRIBUTE_ESCAPES:
        value = value.replace(character, reference)
    return value


#: How a value is written into the text formats reports use: as is, inside a JSON
#: string, HTML or XML text and attributes, doubled quotes (CSV, YAML), a
#: backslash-escaped single quote (shell and script strings), percent-encoded
#: (URLs, with a space as ``%20`` or ``+``), inside a YAML double-quoted scalar,
#: as the reports show it, and as the JUnit report's XML attributes carry it.
_TEXT_ENCODINGS: Tuple[Callable[[str], str], ...] = (
    lambda value: value,
    lambda value: json.dumps(value)[1:-1],
    # pydantic's JSON: non-ASCII characters as they are, only the control and
    # quote characters escaped.
    lambda value: json.dumps(value, ensure_ascii=False)[1:-1],
    # A JSON document inside a JSON string (GitLab SAST's raw_data).
    lambda value: json.dumps(json.dumps(value)[1:-1])[1:-1],
    lambda value: html.escape(value, quote=True),
    lambda value: html.escape(value, quote=False),
    lambda value: value.replace('"', '""'),
    lambda value: value.replace("'", "''"),
    lambda value: value.replace("\\", "\\\\").replace("'", "\\'"),
    lambda value: quote(value, safe=""),
    lambda value: quote_plus(value, safe=""),
    # The Markdown reporter: HTML-escaped, then every Markdown character
    # backslash-escaped (markdown_reporter._text).
    lambda value: _MARKDOWN_CHARACTER.sub(r"\\\1", html.escape(value, quote=False)),
    # The YAML report's double-quoted scalar (report_yaml), with its upper-case
    # escapes of every character outside ASCII.
    _yaml_double_quoted,
    # The HTML report writes snippets and descriptions as the console shows them
    # (terminal_text.shown_not_obeyed), then HTML-escaped; the text report as
    # shown alone.
    _shown,
    lambda value: html.escape(_shown(value), quote=False),
    # An XML attribute as ElementTree writes it (the JUnit report): the double
    # quote and the layout characters escaped, the single quote not.
    _xml_attribute,
)

#: The characters the Markdown reporter backslash-escapes in a value.
_MARKDOWN_CHARACTER = re.compile(r"([\\`*_\[\]{}#|~])")

#: In a JSON or YAML string the character before a value can be the letter of
#: an escape (``\n``, ``\t``, ``\r``, ``\b``, ``\f``, ``\uXXXX``); a token
#: boundary that read it as part of a word kept the value.
_AFTER_AN_ESCAPE = r"(?<=\\[ntrbf])|(?<=\\u[0-9a-fA-F]{4})"


def _text_token_pattern(form: str) -> str:
    """``form`` as a whole token in rendered text (see ``_token_pattern``), where a
    word character before it may be the tail of an escape sequence."""
    left = (
        r"(?:(?<!\w)|" + _AFTER_AN_ESCAPE + ")"
        if _WORD_CHARACTER.match(form[0])
        else ""
    )
    right = r"(?!\w)" if _WORD_CHARACTER.match(form[-1]) else ""
    return left + re.escape(form) + right


def mask_secret_values_in_text(text: str, values: Iterable[str]) -> str:
    """``text`` with each of ``values`` masked in each of ``_TEXT_ENCODINGS``.

    For a rendered report that cannot be re-rendered from masked results: each
    value is matched as a whole token in each of ``_TEXT_ENCODINGS`` and replaced
    by its masked form in the same encoding. A form not listed there is not
    masked.
    """
    replacements: Dict[str, str] = {}
    for value in values:
        if not isinstance(value, str) or not _propagates(value):
            continue
        masked = _mask_secret_value(value)
        for encode in _TEXT_ENCODINGS:
            replacements.setdefault(encode(value), encode(masked))
    if not replacements:
        return text
    pattern = re.compile(
        "|".join(
            _text_token_pattern(form)
            for form in sorted(replacements, key=len, reverse=True)
        )
    )
    return pattern.sub(lambda match: replacements[match.group(0)], text)


def mask_secret_shapes_in_text(text: str, shapes: Iterable[Any]) -> str:
    """``text`` with each token of ``shapes`` masked, as the tree masker masks them.

    The counterpart of ``mask_secret_values_in_text`` for a process that holds
    only what a results file records: the ``secret_value_shapes`` written for an
    ``ash merge`` of shard results, not the values. ``shapes`` are
    ``SecretValueShape`` objects or their serialized dicts, read as
    ``_SecretIndex.add_shapes`` reads them: a shape ASH did not write is
    ignored. A token of a shape is masked only when it could be a value the
    shape stands for; an ordinary word of the shape is kept (``_mask_token``).

    A shape is matched in the plain spelling of a value only: an encoding that
    changes a value's length (a JSON escape) leaves no token of the shape to
    find, unlike the values masker, which spells each value in every encoding.
    """
    index = _SecretIndex()
    index.add_shapes(shapes)
    if not index.shapes:
        return text
    return index.mask_values(text)
