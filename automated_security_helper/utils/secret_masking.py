"""Utility functions for masking secrets in security findings."""

import re
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from pydantic import BaseModel


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
    # Pattern to match Bandit password messages with quoted secrets.
    # Uses a non-greedy match that handles escaped quotes and stops at
    # the matching closing delimiter (single or double quote).
    pattern = r"""(Possible hardcoded password:\s*)(["'])((?:(?!\2).)*)\2"""

    def mask_replacement(match):
        prefix = match.group(1)  # "Possible hardcoded password: "
        quote = match.group(2)  # The quote character (' or ")
        secret = match.group(3)  # The actual secret

        masked_secret = _mask_secret_value(secret)
        return f"{prefix}{quote}{masked_secret}{quote}"

    return re.sub(pattern, mask_replacement, text)


_mask_bandit_b105_secret = _mask_bandit_password_secret


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

    # For very short secrets (< 4 chars), mask completely
    if length < 4:
        return "*" * length

    # For secrets of length 4-7, show only the first character
    if length <= 7:
        return secret[0] + "*" * (length - 1)

    # For secrets of length 8-12, show first and last character
    if length <= 12:
        return secret[0] + "*" * (length - 2) + secret[-1]

    # For long secrets, show first 2 and last 1 character
    return secret[:2] + "*" * (length - 3) + secret[-1]


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
#   reports is replaced with ``MASKED_LINE`` (indentation and line end kept);
# * by value: every value a secret finding's message exposes (bandit B105-B107's
#   ``Possible hardcoded password: '<value>'``, ferret-scan's
#   ``Matched text: '<value>'``) is masked with ``_mask_secret_value`` wherever it
#   occurs as a whole token in any string of any result.
#
# A secret finding is one from a secrets scanner (``utils/scanner_tool_types.py``),
# one tagged ``secret`` or ``secrets``, one of the rules listed in
# ``_SECRET_RULE_IDS`` / ``_SECRET_RULE_PREFIXES``, one whose rule metadata is
# tagged secret, or one whose message quotes a value as above.
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

#: Messages that quote the value a finding matched.
_VALUE_IN_MESSAGE = (
    re.compile(r"""Possible hardcoded password:\s*(["'])((?:(?!\1).)*)\1"""),
    re.compile(r"""Matched text:\s*(["'])((?:(?!\1).)*)\1"""),
)

#: Values shorter than this are masked in their own finding's message only, not
#: wherever they occur: replacing a two- or three-character token across every
#: snippet would change unrelated code.
MIN_PROPAGATED_VALUE_LENGTH = 4

#: Fields that name things rather than hold text a finding reports.
_SKIPPED_FIELDS = frozenset(
    {"uri", "uriBaseId", "ruleId", "guid", "correlationGuid", "baselineState"}
)

_WORD_CHARACTER = re.compile(r"\w")


def _text_of(message: Any) -> Optional[str]:
    root = getattr(message, "root", message)
    if isinstance(root, dict):
        text = root.get("text")
    else:
        text = getattr(root, "text", None)
    return text if isinstance(text, str) else None


def _normalized_uri(uri: Any) -> Optional[str]:
    if not isinstance(uri, str) or not uri:
        return None
    text = uri.replace("\\", "/")
    text = text.removeprefix("file://")
    while text.startswith("./"):
        text = text[2:]
    return text or None


def _physical_locations_of(result: Any) -> Iterable[Any]:
    for location in getattr(result, "locations", None) or []:
        physical = getattr(location, "physicalLocation", None)
        physical = getattr(physical, "root", physical)
        if physical is not None:
            yield physical


def _secret_rule_ids_from_metadata(sarif_report: Any) -> Set[str]:
    """IDs of rules a tool's rule metadata tags as secret rules (trivy's, for one)."""
    found: Set[str] = set()
    for run in getattr(sarif_report, "runs", None) or []:
        tool = getattr(run, "tool", None)
        components = [getattr(tool, "driver", None)]
        components.extend(getattr(tool, "extensions", None) or [])
        for component in components:
            for rule in getattr(component, "rules", None) or []:
                tags = getattr(getattr(rule, "properties", None), "tags", None) or []
                if any(
                    isinstance(tag, str) and tag.lower() in _SECRET_TAGS for tag in tags
                ):
                    if getattr(rule, "id", None):
                        found.add(rule.id)
    return found


def is_secret_finding(result: Any, secret_rule_ids: Set[str] = frozenset()) -> bool:
    """Whether ``result`` reports a secret; see the module notes above."""
    from automated_security_helper.utils.scanner_tool_types import (
        SECRETS_TOOL_TYPE,
        result_tags,
        result_tool_types,
    )

    rule_id = getattr(result, "ruleId", None) or ""
    if rule_id in _SECRET_RULE_IDS or rule_id in secret_rule_ids:
        return True
    if rule_id.startswith(_SECRET_RULE_PREFIXES):
        return True
    if any(tag.lower() in _SECRET_TAGS for tag in result_tags(result)):
        return True
    if SECRETS_TOOL_TYPE in result_tool_types(result):
        return True
    text = _text_of(getattr(result, "message", None)) or ""
    return any(pattern.search(text) for pattern in _VALUE_IN_MESSAGE)


class _SecretIndex:
    """The locations and values the secret findings of one scan report."""

    def __init__(self) -> None:
        #: normalized uri -> reported lines, or None for the whole file.
        self.lines: Dict[str, Optional[Set[int]]] = {}
        self._by_basename: Dict[str, List[str]] = {}
        self.values: Set[str] = set()
        self._pattern: Optional[re.Pattern] = None

    def add_location(self, uri: str, start: Optional[int], end: Optional[int]) -> None:
        if uri not in self.lines:
            self.lines[uri] = set()
            self._by_basename.setdefault(uri.rsplit("/", 1)[-1], []).append(uri)
        current = self.lines[uri]
        if current is None:
            return
        if start is None:
            self.lines[uri] = None
            return
        last = end if isinstance(end, int) and end >= start else start
        current.update(range(start, last + 1))

    def lines_for(self, uri: Any) -> Optional[Tuple[bool, Set[int]]]:
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
        lines: Set[int] = set()
        matched = False
        for candidate in self._by_basename.get(normalized.rsplit("/", 1)[-1], []):
            if not (
                candidate == normalized
                or candidate.endswith("/" + normalized)
                or normalized.endswith("/" + candidate)
            ):
                continue
            matched = True
            reported = self.lines[candidate]
            if reported is None:
                whole = True
            else:
                lines |= reported
        return (whole, lines) if matched else None

    def mask_values(self, text: str) -> str:
        if not self.values:
            return text
        if self._pattern is None:
            alternatives = []
            for value in sorted(self.values, key=len, reverse=True):
                left = r"(?<!\w)" if _WORD_CHARACTER.match(value[0]) else ""
                right = r"(?!\w)" if _WORD_CHARACTER.match(value[-1]) else ""
                alternatives.append(left + re.escape(value) + right)
            self._pattern = re.compile("|".join(alternatives))
        return self._pattern.sub(lambda match: _mask_secret_value(match.group(0)), text)


def _mask_message_values(text: str) -> str:
    """``text`` with each value a message pattern quotes masked."""

    def replace(match: "re.Match[str]") -> str:
        start, end = match.span(2)
        whole_start = match.start(0)
        segment = match.group(0)
        return (
            segment[: start - whole_start]
            + _mask_secret_value(match.group(2))
            + segment[end - whole_start :]
        )

    for pattern in _VALUE_IN_MESSAGE:
        text = pattern.sub(replace, text)
    return text


def _index_secrets(sarif_report: Any) -> _SecretIndex:
    index = _SecretIndex()
    secret_rule_ids = _secret_rule_ids_from_metadata(sarif_report)
    for result in sarif_report.get_all_results() or []:
        if not is_secret_finding(result, secret_rule_ids):
            continue
        for physical in _physical_locations_of(result):
            uri = _normalized_uri(
                getattr(getattr(physical, "artifactLocation", None), "uri", None)
            )
            if uri is None:
                continue
            region = getattr(physical, "region", None)
            index.add_location(
                uri,
                getattr(region, "startLine", None),
                getattr(region, "endLine", None),
            )
        text = _text_of(getattr(result, "message", None)) or ""
        for pattern in _VALUE_IN_MESSAGE:
            for match in pattern.finditer(text):
                for value in _exposed_values(match.group(2).strip(), result):
                    if len(value) >= MIN_PROPAGATED_VALUE_LENGTH and "\n" not in value:
                        index.values.add(value)
    return index


#: A quoted string literal in a line of source.
_STRING_LITERAL = re.compile(r"""(["'])((?:\\.|(?!\1).)*)\1""")


def _exposed_values(quoted: str, result: Any) -> List[str]:
    """The value a message quotes; if the scanner already masked it, read from the finding's line.

    A scanner can mask the value in its own message before the results are
    merged (``BanditScanner._post_process_sarif`` does), leaving the shape
    ``_mask_secret_value`` writes. The value is then the string literal in the
    lines the finding itself reports whose mask is exactly that shape. Those lines
    are masked by location anyway; the value is recovered so that its reuse on a
    line no secret finding reports is masked too.
    """
    if not quoted or "*" not in quoted:
        return [quoted] if quoted else []
    found = []
    for line in _own_snippet_lines(result):
        for match in _STRING_LITERAL.finditer(line):
            candidate = match.group(2)
            if candidate != quoted and _mask_secret_value(candidate) == quoted:
                found.append(candidate)
    return found


def _own_snippet_lines(result: Any) -> List[str]:
    """The snippet lines at ``result``'s own region, from its region and contextRegion."""
    lines: List[str] = []
    for physical in _physical_locations_of(result):
        region = getattr(physical, "region", None)
        start = getattr(region, "startLine", None)
        end = getattr(region, "endLine", None) or start
        text = getattr(getattr(region, "snippet", None), "text", None)
        if isinstance(text, str):
            lines.extend(text.splitlines())
        context = getattr(physical, "contextRegion", None)
        context_start = getattr(context, "startLine", None)
        context_text = getattr(getattr(context, "snippet", None), "text", None)
        if not (
            isinstance(context_text, str)
            and isinstance(start, int)
            and isinstance(context_start, int)
        ):
            continue
        for offset, line in enumerate(context_text.splitlines()):
            if start <= context_start + offset <= end:
                lines.append(line)
    return lines


def _mask_lines(
    text: str, first_line: Optional[int], whole: bool, lines: Set[int]
) -> str:
    """``text`` with each line at a reported line number replaced by ``MASKED_LINE``.

    A snippet whose first line number is unknown cannot be placed, so in a file
    with secret findings every line of it is replaced.
    """
    out = []
    for offset, line in enumerate(text.splitlines(keepends=True)):
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
    placed: Tuple[bool, Set[int]],
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
            or lines & set(range(first_line, max(first_line, last_line or 0) + 1))
        ):
            content.binary = None


def _mask_region(region: Any, placed: Tuple[bool, Set[int]]) -> None:
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
            if name in _SKIPPED_FIELDS:
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
            if key in _SKIPPED_FIELDS:
                continue
            item = node[key]
            masked = _mask_tree(item, index, seen)
            if isinstance(item, str) and masked != item:
                node[key] = masked
        return node
    return node


def _mask_report(sarif_report: Any) -> Optional[_SecretIndex]:
    """Mask a SARIF report in place; returns the index it masked by."""
    if sarif_report is None or not getattr(sarif_report, "runs", None):
        return None
    # Indexed before the messages are masked, which removes the values from them.
    index = _index_secrets(sarif_report)
    for result in sarif_report.get_all_results() or []:
        message = getattr(result, "message", None)
        root = getattr(message, "root", message)
        text = getattr(root, "text", None)
        if isinstance(text, str):
            masked = _mask_message_values(text)
            if masked != text:
                root.text = masked
    if index.lines or index.values:
        seen: Set[int] = set()
        for run in sarif_report.runs:
            _mask_tree(run, index, seen)
    return index


def mask_secrets_in_sarif_report(sarif_report: Any) -> Any:
    """Mask, in place, every secret a SARIF report's findings expose; returns it."""
    _mask_report(sarif_report)
    return sarif_report


def mask_secrets_in_results(results: Any) -> Any:
    """Mask, in place, every secret value the findings of an aggregated result set expose.

    Covers the SARIF report and the values in ``additional_reports``. Called once
    a scan's results are merged, before ``ash_aggregated_results.json`` is saved
    and before any reporter runs, and on every load of a stored results file.
    Returns ``results``.
    """
    index = _mask_report(getattr(results, "sarif", None))
    additional = getattr(results, "additional_reports", None)
    if index is not None and index.values and isinstance(additional, dict):
        _mask_tree(additional, index, set())
    return results
