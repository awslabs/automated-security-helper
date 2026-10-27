"""Utility functions for masking secrets in security findings."""

import html
import json
import math
import re
from typing import (
    AbstractSet,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Optional,
    Set,
    Tuple,
)
from urllib.parse import unquote

from pydantic import BaseModel, ConfigDict


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
#   opengrep's columns) -- is masked in its own message, and, when it looks like
#   a secret (``_propagates``), with ``_mask_secret_value`` wherever it occurs as
#   a whole token in the text findings report. Rule metadata, tags and
#   identifiers are left alone (``_METADATA_FIELDS``, ``_SKIPPED_FIELDS``).
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
    by still masking what it can.
    """
    escaped = re.escape(label)
    return (
        re.compile(escaped + r"""\s*(["'])(.*)\1\s*\Z""", re.DOTALL),
        re.compile(escaped + r"""\s*(["'])((?:(?!\1).)*)\1"""),
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
#: Shannon entropy per character below which a value is too repetitive to tell
#: from ordinary text (``aaaaaaaa1``, ``86400000``).
MIN_PROPAGATED_VALUE_ENTROPY = 2.5
#: Letters alone, as one word or several joined by whitespace, dots, hyphens or
#: underscores: words, identifiers and prose.
_WORD_LIKE = re.compile(r"[A-Za-z]+(?:[\s._-]+[A-Za-z]+)*")
#: Template placeholders: ``${NAME}``, ``$NAME``, ``{name}``, ``%(name)s``,
#: ``<value>``.
_PLACEHOLDER = re.compile(r"\$\{?\w+\}?|\{\w*\}|%\(\w+\)[a-z]|<[^<>]*>")

#: Fields that name things rather than hold text a finding reports.
_SKIPPED_FIELDS = frozenset(
    {"uri", "uriBaseId", "ruleId", "guid", "correlationGuid", "baselineState"}
)
#: Fields under which nothing is masked by value: a tool's rule metadata,
#: taxonomies and policies, a result's rule reference and every ``tags`` list.
#: They describe or classify findings; a finding tagged ``secret`` whose tag was
#: masked stopped being a secret finding on the next pass.
_METADATA_FIELDS = frozenset(
    {"tool", "taxonomies", "translations", "policies", "rule", "tags"}
)

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


def _normalized_uri(uri: Any) -> Optional[str]:
    """``uri`` as a plain relative or absolute path, for comparing two names of a file.

    Backslashes become slashes, ``file://`` and leading ``./`` go, and
    percent-encoding is decoded: SARIF URIs are URI references, so
    ``my%20app/settings.py`` and ``my app/settings.py`` name one file.
    """
    if not isinstance(uri, str) or not uri:
        return None
    text = unquote(uri.replace("\\", "/"))
    text = text.removeprefix("file://")
    while text.startswith("./"):
        text = text[2:]
    return text or None


def _physical_locations_of(result: Any, related: bool = False) -> Iterable[Any]:
    """``result``'s physical locations, and its related locations' with ``related``."""
    locations = list(getattr(result, "locations", None) or [])
    if related:
        locations.extend(getattr(result, "relatedLocations", None) or [])
    for location in locations:
        physical = getattr(location, "physicalLocation", None)
        physical = getattr(physical, "root", physical)
        if physical is not None:
            yield physical


def _rules_of(sarif_report: Any) -> Iterable[Any]:
    for run in getattr(sarif_report, "runs", None) or []:
        tool = getattr(run, "tool", None)
        components = [getattr(tool, "driver", None)]
        components.extend(getattr(tool, "extensions", None) or [])
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
_IAC_CREDENTIAL = re.compile(
    r"(?i)\bhard[- ]?coded\b.*\b(?:secrets?|credentials?|passwords?|keys?|tokens?)\b"
    r"|\b(?:secrets?|credentials?|passwords?|keys?|tokens?|securestring)\b.*"
    r"\bhard[- ]?coded\b"
    r"|(?:passw|secret|token|key|credential)\w*\s+must not be a plaintext"
    r"|\bsensitive credentials\b"
    r"|\bcredentials in the template\b",
    re.DOTALL,
)


def _describes_a_credential_in_code(text: Any) -> bool:
    return isinstance(text, str) and bool(_IAC_CREDENTIAL.search(text))


def _rule_ids_described(sarif_report: Any) -> Set[str]:
    """IDs of rules whose name or description is about a credential in code."""
    found: Set[str] = set()
    for rule in _rules_of(sarif_report):
        texts = [getattr(rule, "name", None)]
        for field in ("shortDescription", "fullDescription"):
            texts.append(_text_of(getattr(rule, field, None)))
        if any(_describes_a_credential_in_code(text) for text in texts) and getattr(
            rule, "id", None
        ):
            found.add(rule.id)
    return found


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

    rule_id = getattr(result, "ruleId", None) or ""
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


def is_secret_finding(
    result: Any, secret_rule_ids: AbstractSet[str] = frozenset()
) -> bool:
    """Whether ``result`` reports a secret; see the module notes above."""
    from automated_security_helper.utils.scanner_tool_types import (
        SECRETS_TOOL_TYPE,
        result_tags,
        result_tool_types,
    )

    rule_id = getattr(result, "ruleId", None) or ""
    if rule_id in _SECRET_RULE_IDS or rule_id in secret_rule_ids:
        return True
    if rule_id.startswith(_SECRET_RULE_PREFIXES) or _SECRET_RULE_ID.search(rule_id):
        return True
    if any(_is_secret_tag(tag) for tag in result_tags(result)):
        return True
    if SECRETS_TOOL_TYPE in result_tool_types(result):
        return True
    text = _text_of(getattr(result, "message", None)) or ""
    return bool(_quoted_values(text)) or _describes_a_credential_in_code(text)


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

#: A private-key finding's rule, message or tag.
_PRIVATE_KEY = re.compile(r"(?i)private[\s_-]*key")
_PEM_BEGIN = "-----BEGIN"
_PEM_END = "-----END"


def _is_private_key_finding(result: Any) -> bool:
    from automated_security_helper.utils.scanner_tool_types import result_tags

    texts = [
        getattr(result, "ruleId", None) or "",
        _text_of(getattr(result, "message", None)) or "",
    ]
    texts.extend(tag for tag in result_tags(result) if isinstance(tag, str))
    return any(_PRIVATE_KEY.search(text) for text in texts)


def _known_lines(sarif_report: Any) -> Dict[str, Dict[int, str]]:
    """The text of every line any snippet of the report places: uri -> line -> text."""
    known: Dict[str, Dict[int, str]] = {}

    def record(uri: Any, first_line: Any, text: Any) -> None:
        normalized = _normalized_uri(uri)
        if normalized is None or not isinstance(first_line, int):
            return
        if not isinstance(text, str) or _UNCOUNTED_LINE_BREAK.search(text):
            return
        lines = known.setdefault(normalized, {})
        for offset, line in enumerate(_split_lines(text)):
            lines.setdefault(first_line + offset, line)

    for result in sarif_report.get_all_results() or []:
        for physical in _physical_locations_of(result, related=True):
            uri = getattr(getattr(physical, "artifactLocation", None), "uri", None)
            for name in ("region", "contextRegion"):
                region = getattr(physical, name, None)
                record(
                    uri,
                    getattr(region, "startLine", None),
                    getattr(getattr(region, "snippet", None), "text", None),
                )
    for run in getattr(sarif_report, "runs", None) or []:
        for artifact in getattr(run, "artifacts", None) or []:
            record(
                getattr(getattr(artifact, "location", None), "uri", None),
                1,
                getattr(getattr(artifact, "contents", None), "text", None),
            )
    return known


def _block_end(known: Dict[str, Dict[int, str]], uri: str, start: int) -> Optional[int]:
    """The first line at or after ``start`` known to end a PEM block in ``uri``."""
    ends = [
        number
        for candidate, lines in known.items()
        if _same_file(candidate, uri)
        for number, text in lines.items()
        if number >= start and _PEM_END in text
    ]
    return min(ends) if ends else None


def _starts_a_block(known: Dict[str, Dict[int, str]], uri: str, line: int) -> bool:
    return any(
        _PEM_BEGIN in (lines.get(line) or "")
        for candidate, lines in known.items()
        if _same_file(candidate, uri)
    )


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
        #: look like. The lines are None when the location gives none.
        self.local_values: List[Tuple[str, Optional[int], Optional[int], Set[str]]] = []
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
        ``_mask_secret_value`` would have shown for its length; one that does not
        match was not written by ASH and is ignored.
        """
        for shape in shapes:
            if isinstance(shape, dict):
                try:
                    shape = SecretValueShape.model_validate(shape)
                except ValueError:
                    continue
            if not isinstance(shape, SecretValueShape):
                continue
            if shape.length < MIN_PROPAGATED_VALUE_LENGTH or (
                len(shape.prefix),
                len(shape.suffix),
            ) != _visible_lengths(shape.length):
                continue
            self.shapes.add(shape)
            self._pattern = None

    def add_location(self, uri: str, start: Optional[int], end: Optional[int]) -> None:
        if uri not in self.lines:
            self.lines[uri] = _LineRanges()
            self._by_basename.setdefault(uri.rsplit("/", 1)[-1], []).append(uri)
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
        for candidate in self._by_basename.get(normalized.rsplit("/", 1)[-1], []):
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
        """``text`` with each value, and each token of a recorded shape, masked."""
        if not self.values and not self.shapes:
            return text
        if self._pattern is None:
            alternatives = [
                _token_pattern(re.escape(value), value[0], value[-1])
                for value in sorted(self.values, key=len, reverse=True)
            ]
            alternatives.extend(
                _shape_pattern(shape)
                for shape in sorted(self.shapes, key=_shape_key, reverse=True)
            )
            self._pattern = re.compile("|".join(alternatives))
        return self._pattern.sub(lambda match: _mask_secret_value(match.group(0)), text)


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
    but a line break for a value that held whitespace. Every token of the shape is
    masked, including ones that are not the value: over-masking is the accepted
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
    """Not letters alone, not a placeholder, and not repetitive (see the constants)."""
    if _WORD_LIKE.fullmatch(value) or _PLACEHOLDER.fullmatch(value):
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


def _index_secrets(sarif_report: Any) -> _SecretIndex:
    index = _SecretIndex()
    rule_ids = secret_rule_ids(sarif_report)
    described = _rule_ids_described(sarif_report)
    known: Optional[Dict[str, Dict[int, str]]] = None
    for result in sarif_report.get_all_results() or []:
        if not is_secret_finding(result, rule_ids):
            continue
        index.secret_results.append(result)
        private_key = _is_private_key_finding(result)
        # cfn-nag reports a credential rule at its resource's first line only; the
        # property holding the value is somewhere after it.
        resource_only = getattr(
            result, "ruleId", None
        ) in described or _describes_a_credential_in_code(
            _text_of(getattr(result, "message", None))
        )
        text = _text_of(getattr(result, "message", None)) or ""
        quoted = _quoted_values(text)
        exposed: List[str] = []
        for value_start, value_end in quoted:
            exposed.extend(_exposed_values(text[value_start:value_end].strip(), result))
        if not quoted:
            exposed.extend(_matched_values(result))
        # Every value is masked wherever it looks like a secret; and, whatever it
        # looks like, in every finding that overlaps where this one reports it.
        index.add_values(exposed)
        local = {value for value in exposed if value and "\n" not in value}
        for physical in _physical_locations_of(result):
            uri = _normalized_uri(
                getattr(getattr(physical, "artifactLocation", None), "uri", None)
            )
            if uri is None:
                continue
            region = getattr(physical, "region", None)
            start = getattr(region, "startLine", None)
            end = getattr(region, "endLine", None)
            if isinstance(start, int):
                # A key reported on its BEGIN line (detect-secrets does) runs to
                # its END line, which only some other finding's snippet may show.
                # With no END line known, every later line is masked.
                if known is None:
                    known = _known_lines(sarif_report)
                if private_key or _starts_a_block(known, uri, start):
                    block_end = _block_end(known, uri, start)
                    end = block_end if block_end is not None else _TO_END_OF_FILE
                elif resource_only and not isinstance(end, int):
                    end = _TO_END_OF_FILE
            index.add_location(uri, start, end)
            if local:
                index.local_values.append(
                    (
                        uri,
                        start if isinstance(start, int) else None,
                        end
                        if isinstance(end, int)
                        and isinstance(start, int)
                        and end >= start
                        else start,
                        local,
                    )
                )
    return index


def _line_spans(physical: Any) -> List[Tuple[Optional[int], Optional[int]]]:
    """The (first, last) lines a physical location's region and context cover.

    ``(None, None)`` for a region or context with a snippet but no first line,
    which cannot be placed.
    """
    spans: List[Tuple[Optional[int], Optional[int]]] = []
    region = getattr(physical, "region", None)
    if region is not None:
        start = getattr(region, "startLine", None)
        end = getattr(region, "endLine", None)
        if isinstance(start, int):
            spans.append(
                (start, end if isinstance(end, int) and end >= start else start)
            )
        elif getattr(region, "snippet", None) is not None:
            spans.append((None, None))
    context = getattr(physical, "contextRegion", None)
    if context is not None:
        start = getattr(context, "startLine", None)
        end = getattr(context, "endLine", None)
        text = getattr(getattr(context, "snippet", None), "text", None)
        if isinstance(start, int):
            last = (
                start + max(len(_split_lines(text)) - 1, 0)
                if isinstance(text, str)
                else start
            )
            if isinstance(end, int) and end > last:
                last = end
            spans.append((start, last))
        elif isinstance(text, str):
            spans.append((None, None))
    return spans


def _overlapping_values(result: Any, index: _SecretIndex) -> Set[str]:
    """The values of the secret findings whose location ``result`` overlaps."""
    found: Set[str] = set()
    if not index.local_values:
        return found
    for physical in _physical_locations_of(result, related=True):
        uri = _normalized_uri(
            getattr(getattr(physical, "artifactLocation", None), "uri", None)
        )
        if uri is None:
            continue
        for first, last in _line_spans(physical):
            for secret_uri, start, end, values in index.local_values:
                if not _same_file(secret_uri, uri):
                    continue
                # A span with no line cannot be placed, so it overlaps. Each pair
                # is None together (_line_spans, _index_secrets), so the end
                # checks only say so to the type checker.
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
    a single-line region with both columns and a snippet starting at the line's
    first column is read.
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
        match = lines[0][start - 1 : end - 1].strip()
        literals = [found.group(2) for found in _STRING_LITERAL.finditer(match)]
        values.extend(literals or [match])
    return values


#: A quoted string literal in a line of source. The two alternatives inside it
#: are disjoint (an escape, or one character that is neither the quote nor a
#: backslash), so the search is linear: with ``(?!\1).`` a backslash matched
#: either one, and an unterminated quote followed by n backslashes took a
#: Fibonacci(n) number of paths.
_STRING_LITERAL = re.compile(r"""(["'])((?:\\.|(?!\1)[^\\])*)\1""")


def _exposed_values(quoted: str, result: Any) -> List[str]:
    """The value a message quotes; if the scanner already masked it, read from the finding's line.

    A scanner can mask the value in its own message before the results are
    merged (``BanditScanner._post_process_sarif`` does), leaving the shape
    ``_mask_secret_value`` writes. The value is then the string literal in the
    lines the finding itself reports whose mask is exactly that shape. Those lines
    are masked by location anyway; the value is recovered so that its reuse on a
    line no secret finding reports is masked too.

    Only the exact shape counts as already masked (``_is_masked_form``): a raw
    value can hold a ``*`` too, and is returned as it is. When no line holds a
    value whose mask is the quoted one, the masked form itself is returned: masking
    it again changes nothing, and it still carries the value's shape. It is not
    returned beside a value read back, whose own test decides whether it is
    masked elsewhere (``_propagates``): the masked form of ``password`` would
    otherwise mask every eight-letter word that starts with p and ends with d.
    """
    if not quoted:
        return []
    if not _is_masked_form(quoted):
        return [quoted]
    found = []
    for line in _own_snippet_lines(result):
        for match in _STRING_LITERAL.finditer(line):
            candidate = match.group(2)
            if candidate != quoted and _mask_secret_value(candidate) == quoted:
                found.append(candidate)
    return found or [quoted]


def _is_masked_form(text: str) -> bool:
    """Whether ``text`` has the shape ``_mask_secret_value`` writes for its length."""
    shown_prefix, shown_suffix = _visible_lengths(len(text))
    hidden = text[shown_prefix : len(text) - shown_suffix]
    return bool(hidden) and set(hidden) == {"*"}


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
    """Mask one ``ArtifactContent`` in place by the reported lines in its file."""
    whole, lines = placed
    if content is None:
        return
    text = getattr(content, "text", None)
    if isinstance(text, str):
        masked = _mask_lines(text, first_line, whole, lines)
        if masked != text:
            content.text = masked
    rendered = getattr(content, "rendered", None)
    for name in ("text", "markdown"):
        value = getattr(rendered, name, None) if rendered is not None else None
        if isinstance(value, str):
            masked = _mask_lines(value, first_line, whole, lines)
            if masked != value:
                setattr(rendered, name, masked)
    # Base64 content cannot be masked line by line, so it is dropped when its
    # lines reach a reported line, or cannot be placed.
    if getattr(content, "binary", None) is not None:
        if (
            whole
            or not isinstance(first_line, int)
            or lines.overlaps(first_line, max(first_line, last_line or 0))
        ):
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


def _mask_tree(node: Any, index: _SecretIndex, seen: Set[int]) -> Any:
    """Mask ``node`` in place; returns the replacement for a string node."""
    if isinstance(node, str):
        return index.mask_values(node)
    if id(node) in seen:
        return node
    if isinstance(node, BaseModel):
        seen.add(id(node))
        fields = type(node).model_fields
        if "artifactLocation" in fields and "contextRegion" in fields:
            placed = index.lines_for(
                getattr(getattr(node, "artifactLocation", None), "uri", None)
            )
            if placed is not None:
                _mask_region(getattr(node, "region", None), placed)
                _mask_region(getattr(node, "contextRegion", None), placed)
        elif "contents" in fields and "location" in fields:
            # An artifact whose contents a tool embedded: line 1 is the file's first.
            placed = index.lines_for(
                getattr(getattr(node, "location", None), "uri", None)
            )
            if placed is not None:
                _mask_snippet(getattr(node, "contents", None), 1, None, placed)
        names = list(fields)
        names.extend((node.__pydantic_extra__ or {}).keys())
        for name in names:
            if name in _SKIPPED_FIELDS or name in _METADATA_FIELDS:
                continue
            value = getattr(node, name, None)
            if value is None:
                continue
            masked = _mask_tree(value, index, seen)
            if isinstance(value, str) and masked != value:
                setattr(node, name, masked)
        return node
    if isinstance(node, list):
        for position, item in enumerate(node):
            masked = _mask_tree(item, index, seen)
            if isinstance(item, str) and masked != item:
                node[position] = masked
        return node
    if isinstance(node, dict):
        for key in list(node):
            if key in _SKIPPED_FIELDS or key in _METADATA_FIELDS:
                continue
            item = node[key]
            masked = _mask_tree(item, index, seen)
            if isinstance(item, str) and masked != item:
                node[key] = masked
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
    has_runs = sarif_report is not None and bool(getattr(sarif_report, "runs", None))
    # Indexed before the messages are masked, which removes the values from them.
    index = _index_secrets(sarif_report) if has_runs else _SecretIndex()
    index.add_values(values)
    index.add_shapes(shapes)
    index.add_shapes(secret_value_shape(value) for value in index.values)
    if not has_runs:
        return index
    for result in sarif_report.get_all_results() or []:
        message = getattr(result, "message", None)
        root: Any = getattr(message, "root", message)
        text = getattr(root, "text", None)
        # A root with a text is never None; the check says so to the type checker.
        if root is not None and isinstance(text, str):
            masked = _mask_message_values(text)
            if masked != text:
                root.text = masked
    # A secret finding's own snippets are its excerpt of the secret, so they are
    # masked whole rather than by line number: a tool's context can be numbered
    # one off (ferret-scan's is), and the line arithmetic would keep the secret.
    whole_file = (True, _LineRanges())
    for result in index.secret_results:
        for physical in _physical_locations_of(result, related=True):
            _mask_region(getattr(physical, "region", None), whole_file)
            _mask_region(getattr(physical, "contextRegion", None), whole_file)
    if index.lines or index.values or index.shapes:
        seen: Set[int] = set()
        for run in sarif_report.runs:
            _mask_tree(run, index, seen)
    # A value that does not look like a secret is not masked everywhere, but it is
    # masked in every finding whose region or context overlaps the secret
    # finding's location: what that finding reports is the same line.
    if index.local_values:
        secret_ids = {id(result) for result in index.secret_results}
        for result in sarif_report.get_all_results() or []:
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
                if name == "message" or name in _SKIPPED_FIELDS:
                    continue
                if name in _METADATA_FIELDS:
                    continue
                value = getattr(result, name, None)
                if value is None:
                    continue
                masked = _mask_tree(value, local_index, set())
                if isinstance(value, str) and masked != value:
                    setattr(result, name, masked)
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

    Covers the SARIF report and the values in ``additional_reports``. Called once
    a scan's results are merged, before ``ash_aggregated_results.json`` is saved
    and before any reporter runs, and on every load of a stored results file.

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
    if (index.values or index.shapes) and isinstance(additional, dict):
        _mask_tree(additional, index, set())
    _record(results, index)
    return results


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
    has_runs = sarif_report is not None and bool(getattr(sarif_report, "runs", None))
    index = _index_secrets(sarif_report) if has_runs else _SecretIndex()
    index.add_values(exposed_secret_values(results))
    index.add_shapes(getattr(results, "secret_value_shapes", None) or [])
    index.add_shapes(secret_value_shape(value) for value in index.values)

    def mask(uri: Any, first_line: Optional[int], text: str) -> str:
        placed = index.lines_for(uri)
        if placed is not None:
            whole, lines = placed
            text = _mask_lines(text, first_line, whole, lines)
        return index.mask_values(text)

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


#: How a value is written into the text formats reports use: as is, inside a JSON
#: string, HTML or XML text and attributes, and doubled quotes (CSV, YAML).
_TEXT_ENCODINGS: Tuple[Callable[[str], str], ...] = (
    lambda value: value,
    lambda value: json.dumps(value)[1:-1],
    lambda value: html.escape(value, quote=True),
    lambda value: html.escape(value, quote=False),
    lambda value: value.replace('"', '""'),
    lambda value: value.replace("'", "''"),
)


def mask_secret_values_in_text(text: str, values: Iterable[str]) -> str:
    """``text`` with each of ``values`` masked in every form a report writes it.

    For a rendered report that cannot be re-rendered from masked results: each
    value is matched as a whole token in each of ``_TEXT_ENCODINGS`` and replaced
    by its masked form in the same encoding.
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
            _token_pattern(re.escape(form), form[0], form[-1])
            for form in sorted(replacements, key=len, reverse=True)
        )
    )
    return pattern.sub(lambda match: replacements[match.group(0)], text)
