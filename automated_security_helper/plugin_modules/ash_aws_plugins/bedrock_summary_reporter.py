# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
import hashlib
import logging
import html
import math
import os
import re
import string
from collections import Counter, defaultdict
from copy import deepcopy
from pathlib import Path
from types import SimpleNamespace
from typing import (
    Annotated,
    Any,
    Callable,
    ClassVar,
    Dict,
    Iterable,
    List,
    Literal,
    Optional,
    Set,
    Tuple,
    TYPE_CHECKING,
)

import boto3
import botocore.exceptions
from markdown_it import MarkdownIt
from pydantic import Field, model_validator

from automated_security_helper.base.options import (
    ReporterOptionsBase,
    _warn_once,
    report_file_name,
)
from automated_security_helper.base.reporter_plugin import (
    ReporterPluginBase,
    ReporterPluginConfigBase,
    ReporterWorkspaceBehaviour,
    write_report_file,
)
from automated_security_helper.core.enums import ScannerStatus
from automated_security_helper.plugins.decorators import ash_reporter_plugin
from automated_security_helper.utils.error_text import error_text, text_without_values
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.scanner_tool_types import (
    SECRETS_TOOL_TYPE,
    normalize_tool_type,
    result_tool_types,
)
from automated_security_helper.utils.secret_masking import (
    is_secret_detection,
    secret_detection_rule_ids,
)
from automated_security_helper.utils.numeric_text import purely_numeric
from automated_security_helper.utils.redacted_model import value_tuple
from automated_security_helper.utils.sarif_utils import _resolve_result_severity
from automated_security_helper.utils.severity_ladder import (
    effective_sarif_level,
    result_severity,
    severity_fails_threshold,
)
from automated_security_helper.utils.ui_theme import FOOTER_CREDIT
from automated_security_helper.plugin_modules.ash_builtin.reporters.report_content_emitter import (
    ReportContentEmitter,
)
from automated_security_helper.plugin_modules.ash_builtin.reporters.markdown_reporter import (
    _cell,
    _code_block,
    _text,
    coverage_markdown,
    outcome_markdown,
)
from automated_security_helper.utils.command_safe_stream import json_commands_broken
from automated_security_helper.utils.terminal_text import (
    shown_not_obeyed,
    shown_on_one_line,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.aws_utils import (
    AWS_REGION_PATTERN,
    MAX_RETRIES,
    MAX_RETRY_DELAY_SECONDS,
    UNEXPECTED_LISTING_ERROR,
    ListingsOnce,
    candidate_spellings,
    check_is_legacy,
    check_is_spelling_specific,
    check_is_transient,
    check_listing_client_side,
    check_listing_failure,
    check_model_id,
    check_retry_delays,
    control_plane_client_config,
    get_fallback_model,
    report_missing_setting,
    reporter_client_config,
    validate_bedrock_model,
)
from automated_security_helper.plugin_modules.ash_aws_plugins.bedrock_pipeline import (
    BedrockModelClient,
    BedrockPromptBuilder,
    CallOutcome,
)

if TYPE_CHECKING:
    from automated_security_helper.models.asharp_model import AshAggregatedResults


#: The three variables this reporter's options read as defaults at import time:
#: ASH_BEDROCK_MODEL_ID (model_id), ASH_BEDROCK_TEMPERATURE (temperature) and
#: ASH_BEDROCK_MAX_TOKENS (max_tokens). Their import-time values
#: join the redaction values whether or not the loaded config's environment
#: values also record them, except a numeric knob's purely numeric value
#: (``_ASH_BEDROCK_NUMERIC_KNOBS``).
#:
#: The boundary: a value an option read from the environment is a
#: recorded environment value and is redacted wherever a line would repeat it,
#: which is the same rule the config's ``${VAR}`` values follow
#: (``AshConfig._environment_values``). The one exception is by name: the
#: purely numeric value of ASH_BEDROCK_TEMPERATURE or ASH_BEDROCK_MAX_TOKENS,
#: read at import or by the config itself (``_config_read_knob_values``), is no
#: needle; the two sources combine in ``_redaction_values``. The standard AWS_*
#: identifiers (AWS_REGION, AWS_DEFAULT_REGION, AWS_PROFILE) are deliberately
#: left as written. The options below do read them as defaults (``aws_region``,
#: ``aws_profile``), but what they hold are the names the AWS SDK routes by - a
#: region, a profile - identifiers in every line that names them, not values
#: to hide.
#: An operator who needs the hidden model id has it in the environment and the
#: config; the written reports and ash.log are the surfaces that travel.
_ASH_BEDROCK_DEFAULT_VARS = (
    "ASH_BEDROCK_MODEL_ID",
    "ASH_BEDROCK_TEMPERATURE",
    "ASH_BEDROCK_MAX_TOKENS",
)


#: The numeric knobs among ``_ASH_BEDROCK_DEFAULT_VARS``: a purely numeric
#: value of one of these is no redaction needle. Chosen by name, not by the
#: value's shape, so a numeric value read from any other variable -- a model
#: id that happens to be all digits -- stays redacted.
_ASH_BEDROCK_NUMERIC_KNOBS = frozenset(
    {"ASH_BEDROCK_TEMPERATURE", "ASH_BEDROCK_MAX_TOKENS"}
)

#: The CommonMark parser the generated sections are written for: it tells an
#: answer's code from its text, and checks what the written answer renders as.
_COMMONMARK = MarkdownIt("commonmark")

#: The characters a backslash outside code makes literal, a backtick among them.
_ASCII_PUNCTUATION = frozenset(string.punctuation)

#: A "<" that starts a line inside a code span, after any indentation or
#: block-quote markers: the line could open an HTML block before the span is read.
_SPAN_LINE_START_TAG = re.compile(r"(\n[ \t>]*)<")
#: A pipe no backslash escapes: the character a GitHub viewer splits a table
#: row at. Inside a code span the backslash is literal to CommonMark, but the
#: GFM table extension reads "\|" as a pipe kept inside its column, spans included.
_UNESCAPED_PIPE = re.compile(r"(?<!\\)\|")
#: A GFM table's delimiter row: columns of one or more hyphens, each with an
#: optional colon at either end, separated by pipes, with the pipe at either end
#: optional. Leading whitespace is admitted whatever its width: the row is read
#: from a paragraph's content, whose lines a viewer has already stripped.
_TABLE_DELIMITER_ROW = re.compile(r"^\s*\|?\s*:?-+:?\s*(?:\|\s*:?-+:?\s*)*\|?\s*$")

#: A line put after an answer while closing its fences: report text follows every
#: answer, so text here shows whether the answer left a fence open.
_AFTER_ANSWER = "ash-report-continues"

#: An "&" or "<" with the backslashes before it: an odd number of them escapes
#: the character, which CommonMark then renders as that character, so writing
#: an entity after the backslash would render the entity's text instead.
_HTML_CHARACTER = re.compile(r"(\\*)([&<])")


def _html_as_text(text: str) -> str:
    """*text* with each "&" and "<" written as an entity, so it renders as text.

    A "&" or "<" the answer escaped with a backslash is left as written: it is
    text already, and "\\&lt;" would render as the four characters "&lt;"."""

    def entity(match: "re.Match[str]") -> str:
        backslashes, character = match.group(1), match.group(2)
        if len(backslashes) % 2 == 1:
            return match.group(0)
        return backslashes + ("&amp;" if character == "&" else "&lt;")

    return _HTML_CHARACTER.sub(entity, text)


def _closing_backticks(source: str, start: int, run: int) -> Optional[int]:
    """Where the next string of exactly *run* backticks at or after *start* begins."""
    position, length = start, len(source)
    while position < length:
        if source[position] != "`":
            position += 1
            continue
        end = position
        while end < length and source[end] == "`":
            end += 1
        if end - position == run:
            return position
        position = end
    return None


def _code_span_ranges(source: str) -> List[Tuple[int, int]]:
    """The (start, end) of each code span's content in *source*, one block's
    inline text, paired as CommonMark pairs them: a backtick string opens a span
    only when a later string of the same length closes it, and outside a span a
    backslash makes the punctuation after it literal, a backtick included."""
    spans: List[Tuple[int, int]] = []
    index, length = 0, len(source)
    while index < length:
        char = source[index]
        if char == "\\":
            following = source[index + 1 : index + 2]
            index += 2 if following and following in _ASCII_PUNCTUATION else 1
            continue
        if char != "`":
            index += 1
            continue
        end = index
        while end < length and source[end] == "`":
            end += 1
        close = _closing_backticks(source, end, end - index)
        if close is None:
            index = end
            continue
        spans.append((end, close))
        index = close + (end - index)
    return spans


def _cell_count(line: str) -> int:
    """How many columns a GitHub viewer reads *line* as: the segments between
    its unescaped pipes, the optional pipe at either end not counting. The pipes
    inside code spans count too, as the viewer splits before it reads spans."""
    text = line.strip().removeprefix("|")
    if text.endswith("|") and not text.endswith("\\|"):
        text = text[:-1]
    return len(_UNESCAPED_PIPE.split(text))


def _table_row_lines(lines: List[str]) -> List[bool]:
    """Which of *lines*, one block's text as a viewer reads it, a GitHub viewer
    reads as table rows, by the GFM table rule: a table exists only where a
    delimiter row (``|---|``-shaped columns of hyphens, an optional colon at
    either end of each) follows a header row with the same column count, and
    it then runs to the end of the block (the lines are one block, so there is
    no blank line to end it sooner). The header, the delimiter and every later
    line of the block are its rows. A lone line holding a pipe is prose: the
    viewer never splits it, so its spans are whole and a pipe inside one of
    them is just code. The viewer splits a row at the pipes inside spans too,
    so they count toward a column count. *lines* are the block's content lines,
    not its raw lines: a table inside a block quote or a list item is a table
    to the viewer, which reads the rows with the "> " and "- " markers already
    stripped, and a raw line still carrying them is read as prose here."""
    rows = [False] * len(lines)
    for index in range(len(lines) - 1):
        if rows[index]:
            continue
        delimiter = lines[index + 1]
        if not _TABLE_DELIMITER_ROW.match(delimiter) or "|" not in delimiter:
            continue
        if _cell_count(lines[index]) != _cell_count(delimiter):
            continue
        for row in range(index, len(lines)):
            rows[row] = True
        break
    return rows


def _inline_as_written(source: str, content: Optional[str] = None) -> str:
    """One block's inline text with HTML outside its code spans written as text
    and each span as the model wrote it, but for a "<" starting a line inside a
    span, which stays text (_SPAN_LINE_START_TAG), and for a span that holds a
    pipe on a row of a GFM table (_table_row_lines): the report is read by GitHub
    Markdown viewers, which split a table row into columns at every pipe before
    reading the spans, so a span that crosses a column boundary ends there and the
    HTML after the pipe is outside any span. There the span's pipes are written
    as "\\|", which GFM keeps inside the column and inside the span, and its "<" as
    text, so the HTML stays inert in a viewer that does not read the escape. The
    same goes for a span that holds a line break and touches a table row on any
    of its lines, however it starts: the viewer cuts it at the row's end. A span
    holding a pipe, or a line break, away from every table row is code to every
    viewer and is left as written, as is a span on one row with no pipe:
    entities are not decoded inside a code span, so a "&lt;" written
    there would show as the entity. The cost is confined to table rows.

    *source* is the block's raw lines, container markers included, so the result
    splits back into the answer's lines. *content* is the same block as the
    parser reads it, one line per raw line with the block-quote and list-item
    markers stripped; the table rule reads it, because a viewer finds a table
    inside a block quote or a list item too, and a raw ``> |---|`` is no
    delimiter row. Given no *content*, or one whose line count disagrees with
    the raw lines, every line holding a pipe is treated as a table row: the
    side that rewrites a span it could have left alone, never the other."""
    spans = _code_span_ranges(source)
    lines = source.split("\n")
    classified = lines if content is None else content.split("\n")
    if content is None or len(classified) != len(lines):
        table_rows = ["|" in line for line in lines]
    else:
        table_rows = _table_row_lines(classified)
    pieces = []
    position = 0
    for start, end in spans:
        pieces.append(_html_as_text(source[position:start]))
        span = source[start:end]
        # Every line the span touches, not only the one it starts on: the viewer
        # splits each table row into columns before it reads spans, so a span that
        # starts above a table, or on one row and ends on another, is cut at the
        # row's end and its HTML is outside any span.
        first_line = source.count("\n", 0, start)
        last_line = source.count("\n", 0, end)
        on_table_row = any(table_rows[first_line : last_line + 1])
        if ("|" in span or first_line != last_line) and on_table_row:
            pieces.append(_UNESCAPED_PIPE.sub(r"\\|", span).replace("<", "&lt;"))
        else:
            pieces.append(_SPAN_LINE_START_TAG.sub(r"\1&lt;", span))
        position = end
    pieces.append(_html_as_text(source[position:]))
    return "".join(pieces)


def _renders_html(text: str) -> bool:
    """Whether a CommonMark viewer would render any HTML from *text*."""
    for token in _COMMONMARK.parse(text):
        if token.type in ("html_block", "html_inline"):
            return True
        if any(child.type == "html_inline" for child in token.children or []):
            return True
    return False


def _fences_closed(text: str) -> str:
    """*text* with a closing line after any fence it leaves open, so the report
    text after an answer renders as the report and not as the answer's code.

    Only a fence outside any list or block quote can run on: the blank line the
    report puts after each answer ends a block quote, and the report's next line,
    at the left margin, ends a list item and any fence inside it.

    An open fence is the one whose lines reach the marker line, read from the
    token's line map; a closed fence whose content happens to hold the marker's
    text is not open, and used to be taken for one, which appended fences the
    answer did not need and left one open over the rest of the report.
    """
    for _ in range(3):
        # The marker's 0-based line: the answer's lines, a blank line, then it.
        marker_line = text.count("\n") + 2
        tokens = _COMMONMARK.parse(f"{text}\n\n{_AFTER_ANSWER}\n")
        open_fence = next(
            (
                token
                for token in tokens
                if token.type == "fence"
                and token.level == 0
                and token.map is not None
                and token.map[0] <= marker_line < token.map[1]
            ),
            None,
        )
        if open_fence is None:
            return text
        text = f"{text}\n{open_fence.markup}"
    return text


def _markdown_as_written(shown: str) -> str:
    """A model answer, its controls shown already, as the report writes it: HTML
    outside code written as text, the answer's code as the model wrote it, and a
    fence the answer leaves open closed.

    Code is what CommonMark keeps as written: fenced blocks of any length,
    indented blocks, and code spans. HTML in code renders as text already, and
    an entity written there would show as the entity, so code is left alone.
    Which lines are code comes from parsing the answer with every "&" and "<"
    written as text, which has the same block structure as the written answer.
    If the written answer would still render any HTML, the whole answer is
    written as text instead.

    Costs, both in raw Markdown only: a "<" or "&" outside code reads as "&lt;"
    or "&amp;" (a viewer shows it as written), and a "<" that starts a line
    inside a code span reads as "&lt;", because there it could open an HTML
    block. The answer's Markdown structure (headings, emphasis, links, tables)
    stays live by design. The split between code and text is code to maintain.
    """
    lines = shown.split("\n")
    written = [_html_as_text(line) for line in lines]
    for token in _COMMONMARK.parse("\n".join(written)):
        if token.map is None:
            continue
        start, end = token.map
        if token.type in ("fence", "code_block"):
            written[start:end] = lines[start:end]
        elif token.type == "inline":
            # The raw lines are rewritten; the token's content, the same lines with
            # their block-quote and list-item markers stripped, is what the table
            # rule reads, as a viewer finds tables inside those containers too.
            written[start:end] = _inline_as_written(
                "\n".join(lines[start:end]), content=token.content
            ).split("\n")
    result = "\n".join(written)
    if _renders_html(result):
        result = _html_as_text(shown)
    return _fences_closed(result)


def _purely_numeric(value: str) -> bool:
    """The shared bare-number boundary with one leading sign allowed on top.

    The core is one definition (utils.numeric_text, a leaf module): a change
    to it moves the knob exclusion here and the validator's derived-spelling
    rule together. A knob's number identifies nothing signed or not ("-1",
    "+0.5"), so this site strips one leading sign before the shared test.
    Imported at the top, not from the config package: this module runs the
    predicate while it is being imported (_ASH_BEDROCK_DEFAULT_VALUES), and
    the config package imports the plugin modules at start-up, so a config
    import here would close that cycle at load time."""
    unsigned = value[1:] if value[:1] in "+-" else value
    return purely_numeric(unsigned)


def _read_ash_bedrock_defaults() -> Tuple[str, ...]:
    """The values of ``_ASH_BEDROCK_DEFAULT_VARS`` the environment holds now.

    AWS_REGION, AWS_DEFAULT_REGION and AWS_PROFILE are deliberately not read:
    an identifier is left as written. The numeric knobs' numbers
    (``_ASH_BEDROCK_NUMERIC_KNOBS``: ASH_BEDROCK_TEMPERATURE and
    ASH_BEDROCK_MAX_TOKENS, when purely numeric) are excluded too: the knob's
    number identifies nothing, and replacing it corrupts what legitimately
    prints that number -- redact_values matches a four-character needle like
    "4000" as a whole word, which mangled a line printing that count, and a
    date inside a model id. ASH_BEDROCK_MODEL_ID joins whatever its shape.
    """
    return tuple(
        value
        for name in _ASH_BEDROCK_DEFAULT_VARS
        if (value := os.environ.get(name))
        and not (name in _ASH_BEDROCK_NUMERIC_KNOBS and _purely_numeric(value))
    )


def _config_read_knob_values(config: Any, values: Iterable[str]) -> frozenset:
    """The values among ``values`` (the config's environment values) that the
    config read only through a numeric knob: the import snapshot's exclusion,
    applied to what the config itself recorded.

    A value is left out only when each of its occurrences in ``values`` is
    accounted for by a reference (``AshConfig._environment_references``) to
    one of ``_ASH_BEDROCK_NUMERIC_KNOBS`` that read it, it is purely numeric,
    and no other reference read it. A value also read through any other
    variable, or recorded with no reference saying where from (one a trusted
    config contributed), stays a needle, so the rule can only err toward
    redacting.
    """
    # Imported here: the config package imports the plugin modules at start-up.
    from automated_security_helper.config.environment_record import referenced_name

    references = getattr(config, "_environment_references", None) or ()
    from_knobs: Counter = Counter()
    from_others = set()
    for reference in references:
        value = getattr(reference, "value", None)
        written = getattr(reference, "written", None)
        if not isinstance(value, str) or not isinstance(written, str):
            continue
        if referenced_name(written) in _ASH_BEDROCK_NUMERIC_KNOBS and _purely_numeric(
            value
        ):
            from_knobs[value] += 1
        else:
            from_others.add(value)
    recorded = Counter(values)
    excluded = {
        value
        for value, read in from_knobs.items()
        if value not in from_others and recorded[value] <= read
    }
    if excluded:
        # The derived needles move with the exclusion: environment_record_read
        # adds the spellings a typing model prints for the knob's value, and
        # leaving those in would redact "1e+06" while deliberately showing
        # 1000000. A spelling another reference also read stays. Imported at
        # call time, from the report path, never at module load.
        from automated_security_helper.config.config_validator import _typed_spellings

        for value in tuple(excluded):
            excluded.update(
                spelling
                for spelling in _typed_spellings(value)
                if spelling in recorded and spelling not in from_others
            )
    return frozenset(excluded)


def _error_reason(error: Optional[str]) -> str:
    """The reason an "*Error ...*" text gives: its wrapping asterisks and a
    leading "Error: " taken off."""
    if not error:
        return ""
    reason = error.strip()
    if len(reason) > 1 and reason.startswith("*") and reason.endswith("*"):
        reason = reason[1:-1]
    reason = reason.removeprefix("Error: ")
    return reason.strip()


def _shim_outcome(text: str) -> CallOutcome:
    """A text-returning call as an outcome, for the backward-compatible shims,
    whose ``_try_model_call`` answers text: an "*Error ...*" text failed.
    The report path reads ``BedrockModelClient.call``'s own outcome instead."""
    failed = text.startswith("*Error")
    return CallOutcome(text, ok=not failed, model_specific=failed)


def _exhaustion_text(
    primary: str,
    called: List[str],
    unavailable: List[str],
    primary_error: Optional[str],
    run_model: Optional[str] = None,
    run_model_error: Optional[str] = None,
    not_checked: Optional[List[str]] = None,
    listing_refused: Optional[Dict[str, List[str]]] = None,
    listing_client_side: Optional[Iterable[str]] = None,
    profile_listing_refused: Optional[Dict[str, List[str]]] = None,
    profile_listing_client_side: Optional[Iterable[str]] = None,
) -> str:
    """The fallback walk's "nothing answered" text: the configured model, the
    models called (and failed) apart from the ones not available to call and
    the ones whose check the control plane gave no answer to (``not_checked``:
    the walk does not know whether they are available), why the configured
    model failed when that is known, and, for a walk resumed after the run's
    model failed in turn, why that one failed.

    ``listing_refused`` maps how the model listing failed (the error code the
    control plane answered with, the class name of a botocore error, or
    ``UNEXPECTED_LISTING_ERROR``) to the models that listing left unchecked.
    Each is a group of its own, naming the code or class, so an operator whose
    listing was denied is not told the region does not list the model.
    ``listing_client_side`` names the keys of ``listing_refused`` that are class
    names of errors botocore raised before any service answered: nothing
    refused those listings, so their groups say the listing failed, as they do
    for ``UNEXPECTED_LISTING_ERROR``.

    ``profile_listing_refused`` and ``profile_listing_client_side`` are the same
    for the models left unchecked by a failed inference profile listing alone
    (the foundation-model listing answered): their groups say "profile
    listing", so a refused ``ListInferenceProfiles`` is not read as a refused
    ``ListFoundationModels``."""
    groups = []
    if called:
        groups.append("called: " + ", ".join(called))
    if unavailable:
        groups.append("unavailable: " + ", ".join(unavailable))
    if not_checked:
        groups.append("not checked: " + ", ".join(not_checked))
    for kind, refused, client_side_keys in (
        ("", listing_refused, listing_client_side),
        ("profile ", profile_listing_refused, profile_listing_client_side),
    ):
        client_side = set(client_side_keys or ())
        for failure, models in (refused or {}).items():
            unanswered = failure == UNEXPECTED_LISTING_ERROR or failure in client_side
            what = "failed" if unanswered else "refused"
            groups.append(
                f"not checked, {kind}listing {what} ({failure}): " + ", ".join(models)
            )
    text = (
        f"*Error: No suitable fallback model found for {primary} ({'; '.join(groups)})"
    )
    reason = _error_reason(primary_error)
    if reason:
        text += f". The configured model's error: {reason}"
    run_reason = _error_reason(run_model_error)
    if run_model and run_reason:
        # rstrip: the configured model's reason can end its own sentence.
        text = (
            text.rstrip(".")
            + f". The run's fallback model {run_model} then failed: {run_reason}"
        )
    return text + "*"


#: Snapshotted at import. The options read their defaults when they are built
#: (default factories), so a value set after this module loaded is what an
#: option holds; ``_redaction_values`` reads the environment again at report
#: time and redacts both readings, this one and the current one.
_ASH_BEDROCK_DEFAULT_VALUES: Tuple[str, ...] = _read_ash_bedrock_defaults()


def _number_or_default(
    raw: Optional[str],
    default: str,
    parse: Callable[[str], Any],
    name: str,
    *,
    low: Optional[float] = None,
    high: Optional[float] = None,
) -> Any:
    """``parse`` of ``raw``, the value the environment's ``name`` holds, or of
    ``default`` when it is unset, empty, not a number ``parse`` reads, a
    float that is not finite ("nan", "inf": ``float`` reads them, Converse
    refuses them), or a number below ``low`` or above ``high`` when the caller
    names a bound (Converse's own ranges: a temperature of 0 to 1, at least one
    token; a value outside is refused by every candidate alike).

    The options model is built for every scan, the reporter enabled or not, so
    a value ``parse`` refuses used to make every scan fail with the model's
    error. The default is taken instead and the variable named at WARNING,
    with no value: the value is a configured one.

    The caller reads the variable itself (``os.environ.get(name, default)`` in
    the field's default factory): the environment-variable reference is
    generated from the reads a default factory makes, so the read has to be
    written there, not inside this helper."""
    if raw is None or raw.strip() == "":
        return parse(default)
    try:
        value = parse(raw.strip())
    except ValueError:
        ASH_LOGGER.warning(
            f"{name} is set but is not a number; using the default {default}"
        )
        return parse(default)
    if isinstance(value, float) and not math.isfinite(value):
        ASH_LOGGER.warning(
            f"{name} is set but is not a finite number; using the default {default}"
        )
        return parse(default)
    if (low is not None and value < low) or (high is not None and value > high):
        bounds = (
            f"at least {low}"
            if high is None
            else f"{low} to {high}"
            if low is not None
            else f"at most {high}"
        )
        ASH_LOGGER.warning(
            f"{name} is set but is outside the range Converse takes ({bounds}); "
            f"using the default {default}"
        )
        return parse(default)
    return value


#: How many times a model call is retried when the operator sets no
#: ``max_retries``. The control-plane client has its own default
#: (``CONTROL_PLANE_RETRIES``: three attempts, which is two retries).
DEFAULT_MODEL_CALL_RETRIES = 3

#: The Converse refusals that are about the model, not the prompt: the caller
#: is not permitted to invoke it, or Converse does not know it. A fallback
#: candidate refused with one of these is skipped by the run's later sections
#: as an unlisted one is; every other failure (a validation error of this
#: prompt, a throttle, a timeout) is tried again on the next section.
_REFUSED_FOR_THE_RUN = frozenset({"AccessDeniedException", "ResourceNotFoundException"})

#: The line under a generated section's title: the text came from a model.
GENERATED_HEADER = (
    "Generated with Amazon Bedrock. Verify suggestions against the source findings."
)

#: The same line for a run that called no model (no findings matched the
#: analysis filters): the companion files are written so a configured file
#: exists and the previous run's does not linger, and they say what they hold.
NOTHING_SENT_HEADER = (
    "No findings matched the analysis filters; nothing was sent to Amazon Bedrock."
)

#: The same line for ONE companion file whose section had nothing to analyze
#: while the run's other sections were generated (a secrets-only scan: the
#: executive summary is sent, the technical analysis has no finding to send).
NOT_SENT_SECTION_HEADER = (
    "No findings matched this section's analysis filters; nothing was sent to "
    "Amazon Bedrock for it."
)


class BedrockSummaryReporterConfigOptions(ReporterOptionsBase):
    # The environment defaults are read when the options are built, not when this
    # module is imported, so a config built later sees the run's environment.
    aws_region: Annotated[
        str | None,
        Field(
            default_factory=lambda: os.environ.get(
                "AWS_REGION", os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
            ),
            # Every region name AWS publishes: the two-letter areas plus mx and
            # the eusc, us-isof and eu-isoe partitions, with an optional
            # country segment (eusc-de-east-1). A value refused here is refused
            # as a configuration error (exit 3), so the pattern errs wide. One
            # pattern for the three AWS reporters (aws_utils).
            pattern=AWS_REGION_PATTERN,
            description="AWS region to use for Bedrock. If not specified, the default region will be used. If specified, the region will be used for all Bedrock requests.",
        ),
    ]
    aws_profile: Annotated[
        str | None,
        Field(
            default_factory=lambda: os.environ.get("AWS_PROFILE", None),
            description="AWS profile to use for Bedrock. If not specified, the default profile will be used.",
        ),
    ]
    model_id: Annotated[
        str,
        Field(
            default_factory=lambda: os.environ.get(
                "ASH_BEDROCK_MODEL_ID", "us.anthropic.claude-3-7-sonnet-20250219-v1:0"
            ),
            description="Bedrock model ID to use for generating summaries.",
        ),
    ]
    # The ranges are Converse's own (InferenceConfiguration: temperature "Minimum
    # value of 0. Maximum value of 1."; maxTokens "Minimum value of 1."), read
    # from https://docs.aws.amazon.com/bedrock/latest/APIReference/API_runtime_InferenceConfiguration.html.
    # A value outside them is copied to every fallback candidate and refused
    # by each with a ValidationException, so the walk exhausts for nothing. A
    # config-file value outside the range is a configuration error, like a
    # finding count below one; an environment value outside it takes the
    # default with a WARNING, like a non-numeric one (the options are built for
    # every scan, the reporter enabled or not). ``allow_inf_nan=False`` refuses
    # a config-file ``.nan`` or ``.inf``, which the range check alone admits.
    temperature: Annotated[
        float,
        Field(
            default_factory=lambda: _number_or_default(
                os.environ.get("ASH_BEDROCK_TEMPERATURE", "0.5"),
                "0.5",
                float,
                "ASH_BEDROCK_TEMPERATURE",
                low=0,
                high=1,
            ),
            ge=0,
            le=1,
            allow_inf_nan=False,
            description="Temperature parameter for the Bedrock model, 0 to 1 (Converse's range). Higher values make output more random.",
        ),
    ]
    max_tokens: Annotated[
        int,
        Field(
            default_factory=lambda: _number_or_default(
                os.environ.get("ASH_BEDROCK_MAX_TOKENS", "4000"),
                "4000",
                int,
                "ASH_BEDROCK_MAX_TOKENS",
                low=1,
            ),
            ge=1,
            description="Maximum number of tokens to generate in the response, at least 1 (Converse's range).",
        ),
    ]
    top_p: Annotated[
        float,
        Field(
            description="Top-p parameter for the Bedrock model. Controls diversity of generated text.",
        ),
    ] = 0.9
    # At least one: zero made the batch split's range() step zero and raise,
    # and a negative count sliced the findings from the end instead of
    # limiting them. A value a config file sets below one is refused as a
    # configuration error (exit 3), as every option validator's refusal is
    # (``aws_region``'s pattern says the same of itself); only the environment
    # defaults are read tolerantly, because they are read for every scan
    # whether or not this reporter runs, and these two have none.
    max_findings_to_analyze: Annotated[
        int,
        Field(
            ge=1,
            description=(
                "Maximum number of findings to include in the analysis. At least 1; "
                "a smaller value is refused as a configuration error."
            ),
        ),
    ] = 10
    max_findings_per_severity: Annotated[
        int,
        Field(
            ge=1,
            description=(
                "Maximum number of findings to include per severity level when "
                "grouping by severity. At least 1; a smaller value is refused as a "
                "configuration error."
            ),
        ),
    ] = 5
    group_by_severity: Annotated[
        bool,
        Field(
            description="Whether to group findings by severity level in the report.",
        ),
    ] = True
    add_section_headers: Annotated[
        bool,
        Field(
            description="Whether to add section headers to the report for better organization.",
        ),
    ] = True
    add_table_of_contents: Annotated[
        bool,
        Field(
            description="Whether to add a table of contents to the report.",
        ),
    ] = True
    enable_caching: Annotated[
        bool,
        Field(
            description="Whether to cache Bedrock responses to avoid duplicate API calls.",
        ),
    ] = True
    output_markdown: Annotated[
        bool,
        Field(
            description="Whether to output the report as a markdown file.",
        ),
    ] = True
    output_file: Annotated[
        str,
        Field(
            description="Filename for the main output markdown report, a file name in the reports directory.",
        ),
        report_file_name("reporters.bedrock-summary-reporter.options.output_file"),
    ] = "ash.bedrock.summary.md"
    # Retry configuration
    max_retries: Annotated[
        int | None,
        Field(
            le=MAX_RETRIES,
            description=(
                "Maximum number of retries for Bedrock API calls. Unset, a model "
                "call is retried 3 times and a model listing makes 3 attempts."
            ),
        ),
    ] = None
    base_delay: Annotated[
        float,
        Field(
            le=MAX_RETRY_DELAY_SECONDS,
            description="Base delay in seconds between retries (will be increased exponentially).",
        ),
    ] = 1.0
    max_delay: Annotated[
        float,
        Field(
            le=MAX_RETRY_DELAY_SECONDS,
            description="Maximum delay in seconds between retries.",
        ),
    ] = 60.0

    @model_validator(mode="after")
    def _retry_delays_are_bounded(self):
        return check_retry_delays(self)

    enable_fallback_models: Annotated[
        bool,
        Field(
            description="Whether to try fallback models if the primary model fails.",
        ),
    ] = True
    # Output additional files with specific content
    output_executive_file: Annotated[
        str,
        Field(
            description="Filename for the executive summary markdown report, a file name in the reports directory.",
        ),
        report_file_name(
            "reporters.bedrock-summary-reporter.options.output_executive_file"
        ),
    ] = "bedrock-executive.md"
    output_technical_file: Annotated[
        str,
        Field(
            description="Filename for the technical analysis markdown report, a file name in the reports directory.",
        ),
        report_file_name(
            "reporters.bedrock-summary-reporter.options.output_technical_file"
        ),
    ] = "bedrock-technical.md"

    #: The options that each name a file this reporter writes in the reports
    #: directory, in declaration order: when two name the same file, the earlier
    #: keeps its name.
    _FILE_NAME_OPTIONS: ClassVar[Tuple[str, ...]] = (
        "output_file",
        "output_executive_file",
        "output_technical_file",
    )

    @model_validator(mode="after")
    def _file_options_name_distinct_files(self):
        """Two of the file options naming one file would have the later report
        overwrite the earlier (``_write_markdown_files`` writes them in turn) with
        no line saying so, and the pre-write checks would count one file twice.
        The later option, in declaration order, is replaced by its default with
        one warning naming both keys, as ``report_file_name`` replaces a value
        that is no file name. The keys are named, never the values, which can be
        read from the environment. A default that names the same file as an
        earlier option (``output_file: bedrock-executive.md`` with
        ``output_executive_file`` left at its default) cannot be repaired without
        guessing which report the operator meant, so that config is refused.

        Names are compared as written: two spellings that one file system folds
        to one file (a case-insensitive one) are not read as the same file here.
        """
        prefix = "reporters.bedrock-summary-reporter.options."
        taken: Dict[str, str] = {}
        for option in self._FILE_NAME_OPTIONS:
            name = getattr(self, option)
            earlier = taken.get(name)
            if earlier is None:
                taken[name] = option
                continue
            default = type(self).model_fields[option].default
            if default in taken:
                raise ValueError(
                    f"{prefix}{option} and {prefix}{earlier} name the same file in "
                    f"the reports directory, and the default of {prefix}{option} is "
                    "taken too; give each report its own file name"
                )
            _warn_once(
                f"{prefix}{option}",
                str(name),
                f"Ignoring {prefix}{option}: it names the same file as "
                f"{prefix}{earlier}, so the later report would overwrite the "
                "earlier one. Using the default instead.",
            )
            setattr(self, option, default)
            taken[default] = option
        return self

    include_code_snippets: Annotated[
        bool,
        Field(
            description="Whether to include code snippets in the report.",
        ),
    ] = False
    # Summary style: executive, technical, or detailed
    summary_style: Annotated[
        Literal["executive", "technical", "detailed"],
        Field(
            description="Style of summary to generate: executive (high-level), technical (detailed), or detailed (comprehensive).",
        ),
    ] = "executive"
    # Custom prompt to guide the AI analysis
    custom_prompt: Annotated[
        str | None,
        Field(
            description="Custom prompt to prepend to all Bedrock requests for more tailored analysis.",
        ),
    ] = None
    # List of scanner types to exclude from detailed analysis
    exclude_scanner_types: Annotated[
        List[str],
        Field(
            description=(
                "Scanner tool types whose findings are counted but not sent to the "
                "model (e.g., 'SECRETS'). A finding's type is its scanner's tool "
                "type, looked up from the scanner's name, or a tool_type:: tag on "
                "the finding; 'SECRET' and 'SECRETS' both name the secrets type. A "
                "finding whose type cannot be determined is sent without its code "
                "snippets."
            ),
        ),
    ] = ["SECRET"]
    # Include only actionable findings (not suppressed, above severity threshold)
    actionable_only: Annotated[
        bool,
        Field(
            description="Whether to include only actionable findings (not suppressed, above severity threshold).",
        ),
    ] = True
    # Sections to include or exclude
    include_sections: Annotated[
        List[str],
        Field(
            description="List of sections to include in the report.",
        ),
    ] = [
        "executive_summary",
        "risk_assessment",
        "technical_analysis",
        "remediation_guide",
        "compliance_impact",
    ]
    exclude_sections: Annotated[
        List[str],
        Field(
            description="List of sections to exclude from the report.",
        ),
    ] = []
    # Industry-specific analysis
    industry_context: Annotated[
        str | None,
        Field(
            description="Industry context to provide to the model for more relevant analysis.",
        ),
    ] = None
    compliance_frameworks: Annotated[
        List[str],
        Field(
            description="List of compliance frameworks to consider in the analysis.",
        ),
    ] = []
    custom_context: Annotated[
        str | None,
        Field(
            description="Custom context information to provide to the model.",
        ),
    ] = None
    # Performance optimization
    summarize_findings: Annotated[
        bool,
        Field(
            description="Whether to summarize findings to reduce token usage.",
        ),
    ] = False
    batch_processing: Annotated[
        bool,
        Field(
            description="Whether to process findings in batches for better performance with large datasets.",
        ),
    ] = False


#: Keys of a SARIF result that hold source code: snippets of a region or context
#: region, and the content a fix would insert.
_CODE_KEYS = frozenset({"snippet", "insertedContent"})


def _without_snippets(value: Any) -> Any:
    """A copy of a SARIF result dict (or part of one) without any code it holds."""
    if isinstance(value, dict):
        return {
            key: _without_snippets(item)
            for key, item in value.items()
            if key not in _CODE_KEYS
        }
    if isinstance(value, list):
        return [_without_snippets(item) for item in value]
    return value


class BedrockSummaryReporterConfig(ReporterPluginConfigBase):
    name: Literal["bedrock-summary-reporter"] = "bedrock-summary-reporter"
    extension: str = "bedrock.summary.md"
    # Off by default: this reporter sends findings to an AWS service with the
    # operator's credentials, so only the operator's config turns it on.
    enabled: bool = False
    # A factory, so the environment defaults are read when the config is built.
    options: BedrockSummaryReporterConfigOptions = Field(
        default_factory=BedrockSummaryReporterConfigOptions
    )


@ash_reporter_plugin
class BedrockSummaryReporter(ReporterPluginBase[BedrockSummaryReporterConfig]):
    """Generates a summary of security findings using Amazon Bedrock.

    Workspace mode: per project.

    A useful remediation summary is specific to one codebase -- its language, its
    frameworks, its conventions. Handing a model N projects' findings at once
    produces advice that is either generic across all of them or silently focused
    on whichever project dominates the prompt, and there is no way for a reader to
    tell which happened. Per project, each summary is grounded in one codebase,
    exactly as ``ash --source-dir P`` would produce it.

    Cost is a secondary argument in the same direction: this reporter makes a paid
    inference call, and a workspace-level invocation would add an N+1st call whose
    output is worse than the N it duplicates.
    """

    workspace_behaviour = ReporterWorkspaceBehaviour.PER_PROJECT
    # Sends findings to AWS with the host's credentials.
    sends_off_host = True
    destination_options = (
        "aws_region",
        "aws_profile",
        "model_id",
        "output_file",
        "output_executive_file",
        "output_technical_file",
        # What is sent to the model with the findings, which findings and how
        # many, whether another model may receive them, and which of the calls
        # that send them are made.
        "include_code_snippets",
        "custom_prompt",
        "exclude_scanner_types",
        "actionable_only",
        "max_findings_to_analyze",
        "max_findings_per_severity",
        "summarize_findings",
        "batch_processing",
        "industry_context",
        "compliance_frameworks",
        "custom_context",
        "enable_fallback_models",
        "add_section_headers",
        "output_markdown",
        "include_sections",
        "exclude_sections",
        "group_by_severity",
        # How long it keeps calling Bedrock with the operator's credentials.
        "max_retries",
        "base_delay",
        "max_delay",
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cache = {}
        # The prompt digest each cached answer was generated for, by cache
        # key: an answer is served again only for the prompt it answered.
        self._cache_prompts: Dict[str, str] = {}
        self._secret_findings_exist = False
        # One report run's state (reset by report()): the control-plane client
        # the fallback walk validates candidates with, built once, the
        # fallback model that answered, which the run's later calls go to first,
        # the configured model's error, kept for an exhaustion after it, and
        # the candidates a walk found the listing does not name, which a later
        # section's walk takes as unavailable without asking again. Only that
        # listing fact is kept: a candidate that was called and failed is
        # called again with the next section's prompt, and a candidate the
        # control plane left unchecked is checked again.
        self._control_client: Any = None
        self._run_model: Optional[str] = None
        # The chain member ``_run_model`` was called for: the listing may spell
        # a member another way than the chain does (a region's geography, a
        # different case), and a walk resumed after the run's model failed
        # continues from the chain, not from the listing's spelling.
        self._run_model_member: Optional[str] = None
        self._configured_error: Optional[str] = None
        self._unavailable_models: set[str] = set()
        # The configured model and, as the listing spells it, the id the run's
        # calls go to, when validate_plugin_dependencies matched it
        # case-insensitively (Converse knows the listing's spelling). Kept as a
        # pair across report(), which the check precedes, so the listed
        # spelling is used only while the configured id is still the one it
        # was computed for.
        self._listed_spelling: Optional[Tuple[str, str]] = None

    def _session(self) -> Any:
        """The boto3 session every client of this reporter is built from: the
        configured profile and region, the ones validate_plugin_dependencies
        checked."""
        session_params: Dict[str, Any] = {}
        if self.config.options.aws_profile:
            session_params["profile_name"] = self.config.options.aws_profile
        if self.config.options.aws_region:
            session_params["region_name"] = self.config.options.aws_region
        return boto3.Session(**session_params)

    def _control_plane(self) -> Any:
        """The run's control-plane ("bedrock") client, from ``_session``,
        built the first time the walk needs one."""
        if self._control_client is None:
            self._control_client = self._session().client(
                "bedrock",
                config=control_plane_client_config(self.config.options.max_retries),
            )
        return self._control_client

    def model_post_init(self, context):
        if self.config is None:
            self.config = BedrockSummaryReporterConfig()
        return super().model_post_init(context)

    def companion_file_names(self) -> Tuple[str, ...]:
        """The markdown files ``_write_markdown_files`` writes, with ``output_markdown`` on."""
        config = self.config
        if isinstance(config, dict):
            config = BedrockSummaryReporterConfig.model_validate(config)
        opts = config.options
        if not opts.output_markdown:
            return ()
        included = set(opts.include_sections) - set(opts.exclude_sections)
        names = [opts.output_file]
        if "executive_summary" in included:
            names.append(opts.output_executive_file)
        if "technical_analysis" in included:
            names.append(opts.output_technical_file)
        return tuple(names)

    def _redaction_values(self) -> Tuple[str, ...]:
        """The values this reporter's lines are redacted with.

        The scan config's environment values (``PluginBase._environment_values``)
        plus the ASH_BEDROCK_MODEL_ID, ASH_BEDROCK_TEMPERATURE and
        ASH_BEDROCK_MAX_TOKENS defaults as the environment held them when this
        module loaded (``_ASH_BEDROCK_DEFAULT_VALUES``) and as it holds them now:
        the options read their defaults when they are built, so a model id set
        after the import is what the option holds, and the snapshot alone missed
        it. A numeric knob's number is no needle in any of them: the readings
        leave it out by name, and so does this for a value the config read
        through one (``_config_read_knob_values``).
        """
        values = value_tuple(self._environment_values())
        knob_values = _config_read_knob_values(
            getattr(getattr(self, "context", None), "config", None), values
        )
        current = tuple(
            value
            for value in _read_ash_bedrock_defaults()
            if value not in _ASH_BEDROCK_DEFAULT_VALUES
        )
        return (
            tuple(value for value in values if value not in knob_values)
            + _ASH_BEDROCK_DEFAULT_VALUES
            + current
        )

    def validate_plugin_dependencies(self) -> bool:
        """Validate reporter configuration and requirements."""
        self.dependencies_satisfied = False

        # A configured option can come from the environment (``${VAR}``, or the
        # ASH_BEDROCK_MODEL_ID, ASH_BEDROCK_TEMPERATURE and ASH_BEDROCK_MAX_TOKENS
        # defaults), these lines are appended to the reporter's
        # errors, which the report output persists, and ash.log is a sink; each
        # line that interpolates an option or an error's text is redacted with
        # the reporter's redaction values.
        values = self._redaction_values()

        # The region defaults to us-east-1, so it is unset only when a config sets
        # it to null.
        if self.config.options.aws_region is None:
            report_missing_setting(
                self.config.name, "aws_region", ("AWS_REGION", "AWS_DEFAULT_REGION")
            )
            return self.dependencies_satisfied

        try:
            # Create AWS session
            session = self._session()

            # Verify AWS credentials
            sts_client = session.client("sts")
            caller_id = sts_client.get_caller_identity()
            if "Account" not in caller_id:
                self._plugin_log(
                    "Invalid AWS credentials. Unable to get caller identity.",
                    level=logging.WARNING,
                    target_type="source",
                    append_to_stream="stderr",
                )
                return self.dependencies_satisfied

            # Check if Bedrock is available
            bedrock_client = session.client(
                "bedrock",
                config=control_plane_client_config(self.config.options.max_retries),
            )

            # Check if we can list models. ListFoundationModels is unpaginated and
            # declares only the four by* filters, so there is no page size to ask
            # for; the response is discarded either way, since this call is here to
            # prove the API is reachable and permitted. byOutputModality narrows it
            # to the only models this reporter can use.
            try:
                bedrock_client.list_foundation_models(byOutputModality="TEXT")
            except (
                botocore.exceptions.ClientError,
                botocore.exceptions.BotoCoreError,
            ) as e:
                # BotoCoreError is the client-side half of the contract: a parameter
                # the operation does not declare, an endpoint that will not resolve.
                # It is not a ClientError and carries no ``response``, so it has to
                # be described differently -- and if it is not caught here it reaches
                # the outermost handler below, which reports it as Bedrock access
                # failing in general and sends a reader after credentials instead of
                # after the call that actually failed.
                if isinstance(e, botocore.exceptions.ClientError):
                    error = e.response.get("Error", {})
                    detail = f"{error.get('Code')}: {error.get('Message')}"
                else:
                    detail = f"{type(e).__name__}: {e}"
                self._plugin_log(
                    text_without_values(
                        f"Error accessing Bedrock service: {detail}", values
                    ),
                    level=logging.WARNING,
                    target_type="source",
                    append_to_stream="stderr",
                )
                return self.dependencies_satisfied

            # Validate the configured model. One listing serves it and every
            # fallback candidate (ListingsOnce), as in the run's walk: wrapping
            # only the fallback walk asked the control plane for every page
            # again, possibly while it was already throttling, and logged a
            # failed profile listing a second time at WARNING, because the walk's
            # first call through a fresh wrapper raised the original error.
            model_id = self.config.options.model_id
            label = self._model_label(model_id)
            bedrock_client = ListingsOnce(bedrock_client)
            check = validate_bedrock_model(
                bedrock_client, model_id, values=values, label=label
            )
            is_valid, error_message = check
            # The listing's spelling of a model matched case-insensitively is
            # the one the run calls; the configured spelling is not known to
            # Converse. Kept with the configured id it was computed for.
            listed = check_model_id(check) if is_valid else None
            self._listed_spelling = (model_id, listed) if listed else None

            if not is_valid:
                self._plugin_log(
                    text_without_values(
                        f"Configured model '{label}' is not valid: {error_message}",
                        values,
                    ),
                    level=logging.WARNING,
                    target_type="source",
                    append_to_stream="stderr",
                )

                # Check if fallback models are available. The run walks the
                # whole chain (_walk_fallbacks), so the check walks it too:
                # checking the first fallback alone disabled the reporter when
                # only a later one was usable. The listing the configured
                # model's check made serves every candidate (the wrapper above).
                if self.config.options.enable_fallback_models:
                    visited = {model_id}
                    fallback_model = get_fallback_model(model_id)
                    while fallback_model and fallback_model not in visited:
                        visited.add(fallback_model)
                        # Each candidate under every spelling this region may
                        # list, as the run's walk checks it, against the one
                        # listing the configured model's check made.
                        check, spelling = self._check_candidate(
                            bedrock_client, fallback_model, values
                        )
                        if check[0] and check_is_legacy(check):
                            # Listed, but marked LEGACY: Bedrock may refuse it
                            # to an account that has not used it recently, so
                            # it does not make the dependency check pass. The
                            # run still tries it, after the models before it.
                            self._plugin_log(
                                text_without_values(
                                    f"Fallback model '{spelling}' is listed as "
                                    "Legacy, which Bedrock may refuse to an "
                                    "account that has not used it recently; it "
                                    "is not counted as available",
                                    values,
                                ),
                                level=logging.INFO,
                                target_type="source",
                                append_to_stream="stderr",
                            )
                        elif check[0]:
                            self._plugin_log(
                                text_without_values(
                                    f"Fallback model '{spelling}' is available; "
                                    "the run falls back to it if the configured model "
                                    "still fails",
                                    values,
                                ),
                                level=logging.INFO,
                                target_type="source",
                                append_to_stream="stderr",
                            )
                            # We can proceed with the fallback model
                            self.dependencies_satisfied = True
                            break
                        fallback_model = get_fallback_model(fallback_model)
            else:
                # Primary model is valid
                self.dependencies_satisfied = True

        except botocore.exceptions.ClientError as e:
            error_code = e.response.get("Error", {}).get("Code")
            error_message = e.response.get("Error", {}).get("Message")
            self._plugin_log(
                text_without_values(
                    f"AWS API error when validating Bedrock access: {error_code}: {error_message}",
                    values,
                ),
                level=logging.WARNING,
                target_type="source",
                append_to_stream="stderr",
            )
        except Exception as e:
            self._plugin_log(
                "Error when validating Bedrock access: "
                f"{type(e).__name__}: {error_text(e, values)}",
                level=logging.WARNING,
                target_type="source",
                append_to_stream="stderr",
            )

        return self.dependencies_satisfied

    def report(self, model: "AshAggregatedResults") -> str:
        """Generate a summary report of findings using Amazon Bedrock."""
        if isinstance(self.config, dict):
            self.config = BedrockSummaryReporterConfig.model_validate(self.config)

        # A new run: no control-plane client yet, and the configured model first.
        self._control_client = None
        self._run_model = None
        self._run_model_member = None
        self._configured_error = None
        self._unavailable_models = set()
        # The answer cache is keyed by fixed section names, so a second report()
        # on one instance read the first run's answers for another model's
        # findings; the cache is one run's.
        self._cache = {}
        self._cache_prompts = {}
        self._secret_findings_exist = False

        all_findings, secret_findings, indexed_findings = self._extract_findings(model)
        outcome = self._scan_outcome(model)
        if not all_findings and not secret_findings:
            summary = (
                outcome
                + "\n\nNo findings matched the analysis filters. Review scanner coverage and the complete scan reports.\n\n"
                + FOOTER_CREDIT
            )
            # The files are written for this run too: ``ash report`` does not
            # clear the reports directory, so without them a run with no
            # findings left the previous run's summary, executive and technical
            # files in place, and a configured output_file never existed for a
            # clean scan.
            if self.config.options.output_markdown:
                nothing = self._nothing_to_analyze()
                # No model was called, so the companion files say so instead
                # of claiming generated output.
                self._write_files(
                    model,
                    summary,
                    nothing,
                    nothing,
                    exec_header=NOTHING_SENT_HEADER,
                    tech_header=NOTHING_SENT_HEADER,
                )
            return summary

        # The model client repeats a failed call itself (BedrockModelClient), so
        # this client makes one attempt per call.
        bedrock_runtime = self._session().client(
            "bedrock-runtime", config=reporter_client_config()
        )

        if self.config.options.add_section_headers:
            ASH_LOGGER.info("Generating structured report with section headers")
            summary = self._run_structured_report(
                bedrock_runtime, model, all_findings, secret_findings, indexed_findings
            )
        else:
            ASH_LOGGER.info("Generating simple summary report")
            # The whole list: legacy_summary counts the total from it and
            # itself carries at most max_findings_to_analyze of them, so slicing
            # here made the prompt's total read as the limit.
            summary = self._run_simple_report(
                bedrock_runtime, model, all_findings, secret_findings
            )

        summary = (
            outcome
            + "\n\n## Generated analysis\n\n"
            + GENERATED_HEADER
            + "\n\n"
            + summary.removeprefix("# Security scan summary report\n\n")
            + f"\n\n{FOOTER_CREDIT}\n"
        )
        if self.config.options.output_markdown:
            self._write_markdown_files(
                bedrock_runtime, model, all_findings, secret_findings, summary
            )

        return summary

    @staticmethod
    def _scanners_used(model: "AshAggregatedResults") -> List[str]:
        """The scanners that ran, for the prompts' "Scanners used" line.

        ``scanner_results`` keys every scanner the run knew of, the ones it
        excluded, skipped or found missing included, so the prompt used to name
        scanners that scanned nothing. A row the run left out (``excluded``), or
        whose status says it did not run (SKIPPED, MISSING, ERROR), is not used;
        a row that says nothing readable about itself is kept.
        """
        used = []
        for name, info in (model.scanner_results or {}).items():
            if getattr(info, "excluded", None) is True:
                continue
            status = getattr(info, "status", None)
            if isinstance(status, ScannerStatus) and status in (
                ScannerStatus.SKIPPED,
                ScannerStatus.MISSING,
                ScannerStatus.ERROR,
            ):
                continue
            used.append(name)
        return used

    @staticmethod
    def _scan_outcome(model: "AshAggregatedResults") -> str:
        emitter = ReportContentEmitter(model, human_presentation=True)
        summary = emitter.get_scan_summary()
        project = model.metadata.project_name or "Unknown"
        return "\n\n".join(
            part
            for part in (
                "# ASH security scan analysis",
                outcome_markdown(summary).strip(),
                f"Project: {_text(shown_on_one_line(str(project)))}",
                coverage_markdown(summary).strip(),
            )
            if part
        )

    # ------------------------------------------------------------------
    # Finding extraction
    # ------------------------------------------------------------------

    def _extract_findings(
        self, model: "AshAggregatedResults"
    ) -> "tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]":
        all_findings: List[Dict[str, Any]] = []
        secret_findings: List[Dict[str, Any]] = []
        indexed_findings: List[Dict[str, Any]] = []

        if not (model.sarif and model.sarif.runs):
            return all_findings, secret_findings, indexed_findings

        sarif_results = model.sarif.get_all_results()
        if not sarif_results:
            return all_findings, secret_findings, indexed_findings
        detection_rule_ids = secret_detection_rule_ids(model.sarif)

        thresholds: Dict[str, str] = {}
        for i, result in enumerate(sarif_results):
            finding_dict = result.model_dump(
                by_alias=True, exclude_defaults=True, exclude_unset=True, mode="json"
            )
            # A finding from a scanner of unknown type might be a secret finding the
            # exclusion cannot recognize, so its code is not sent or written.
            if not result_tool_types(finding_dict):
                finding_dict = _without_snippets(finding_dict)
            # Explicit: exclude_defaults drops a level equal to the model's
            # default, and the readers below took a missing level as "none".
            finding_dict["level"] = effective_sarif_level(result)
            finding_dict["index"] = i + 1
            finding_dict["severity"] = _resolve_result_severity(result).upper()
            indexed = self._make_indexed_finding(i + 1, finding_dict)
            indexed_findings.append(indexed)

            excluded_types = self._excluded_tool_types(finding_dict)
            is_secret = SECRETS_TOOL_TYPE in excluded_types or (
                self._excludes_secrets()
                and is_secret_detection(result, detection_rule_ids)
            )
            is_actionable = self._is_actionable(
                finding_dict,
                threshold=self._scanner_threshold(model, finding_dict, thresholds),
                result=result,
            )
            # Why the finding details list a finding the analysis left out, so
            # a reader can tell a suppressed or below-threshold finding from an
            # analyzed one; None for a finding the analysis took.
            indexed["left_out"] = self._left_out_reason(
                finding_dict, is_actionable, excluded_types, is_secret
            )

            if is_secret:
                if is_actionable:
                    secret_findings.append(finding_dict)
                    self._secret_findings_exist = True
            elif excluded_types:
                # A type exclude_scanner_types names that is not the secrets
                # type (IAC, say): counted in the scan outcome, not sent to the
                # model, and not reported as a potential secret either.
                continue
            elif is_actionable:
                all_findings.append(finding_dict)

        return all_findings, secret_findings, indexed_findings

    @staticmethod
    def _left_out_reason(
        finding_dict: Dict[str, Any],
        is_actionable: bool,
        excluded_types: set,
        is_secret: bool,
    ) -> Optional[str]:
        """Why the analysis left ``finding_dict`` out, or None when it took it."""
        if not is_actionable:
            if finding_dict.get("suppressions"):
                return "suppressed"
            return "below threshold"
        if excluded_types and not is_secret:
            return "excluded"
        return None

    def _make_indexed_finding(
        self, index: int, finding_dict: Dict[str, Any]
    ) -> Dict[str, Any]:
        locations = []
        for loc in finding_dict.get("locations", []):
            phys = loc.get("physicalLocation", {})
            if not phys:
                continue
            entry: Dict[str, Any] = {}
            artifact = phys.get("artifactLocation", {})
            if artifact.get("uri"):
                entry["file"] = artifact["uri"]
            region = phys.get("region", {})
            if "startLine" in region:
                entry["startLine"] = region["startLine"]
            if "endLine" in region:
                entry["endLine"] = region["endLine"]
            locations.append(entry)

        msg = finding_dict.get("message", {})
        return {
            "index": index,
            "rule_id": finding_dict.get("ruleId")
            or (finding_dict.get("rule") or {}).get("id")
            or "Unknown",
            "level": finding_dict.get("level", "none"),
            "severity": self._finding_severity(finding_dict),
            "message": (
                msg.get("text", "No description available")
                if isinstance(msg, dict)
                else "No description available"
            ),
            "locations": locations,
        }

    @staticmethod
    def _finding_severity(finding: Dict[str, Any]) -> str:
        properties = dict(finding.get("properties") or {})
        if finding.get("severity"):
            properties["issue_severity"] = str(finding["severity"])
        return _resolve_result_severity(
            SimpleNamespace(properties=properties, level=finding.get("level"))
        ).upper()

    def _excluded_tool_types(self, finding_dict: Dict[str, Any]) -> set:
        """The finding's scanner types among the ones ``exclude_scanner_types``
        names.

        The type comes from the scanner, looked up by the ``scanner_name`` the
        engine writes on every result, and from ``tool_type::`` tags
        (utils/scanner_tool_types.py). No scanner writes a ``scanner_type``
        property. Only the secrets type among them makes a finding a secret
        finding; any other excluded type keeps the finding out of the prompts.
        """
        excluded = {
            normalize_tool_type(name)
            for name in self.config.options.exclude_scanner_types
        }
        excluded.discard(None)
        return result_tool_types(finding_dict) & excluded

    def _is_secret_scanner(self, finding_dict: Dict[str, Any]) -> bool:
        """Whether the finding's scanner type is the secrets type and
        ``exclude_scanner_types`` names it."""
        return SECRETS_TOOL_TYPE in self._excluded_tool_types(finding_dict)

    def _excludes_secrets(self) -> bool:
        """Whether ``exclude_scanner_types`` names the secrets type.

        Then a finding from any rule that detects a credential or key is counted,
        not sent: semgrep's and opengrep's ``generic.secrets.*`` findings come from
        SAST scanners, so only the finding's rule says what it is
        (utils/secret_masking.is_secret_detection). A hard-coded password check
        such as bandit's B105 is sent, its value masked like every other.
        """
        return SECRETS_TOOL_TYPE in {
            normalize_tool_type(name)
            for name in self.config.options.exclude_scanner_types
        }

    def _is_actionable(
        self,
        finding_dict: Dict[str, Any],
        threshold: Optional[str] = None,
        result: Any = None,
    ) -> bool:
        """Whether ``actionable_only`` keeps this finding: the single-directory gate's.

        In workspace mode the verdict uses one ``gate_threshold`` per project
        (which a workspace ceiling can tighten) and can leave out policy-added
        scanners; this uses each scanner's threshold, so the two can differ there.

        Not suppressed, and its severity (``result_severity``, which reads
        ``issue_severity`` first) fails *threshold*, the threshold of the scanner
        that reported it. A ``properties.below_threshold`` flag alone would not
        do: nothing in ASH sets it, so every unsuppressed finding would be sent,
        LOW and INFO ones included. The severity is
        read from *result* when given, because *finding_dict* is dumped with
        ``exclude_defaults`` and so drops a level equal to the field default.
        With no *threshold* only suppression is checked; ``_scanner_threshold``
        always resolves one.
        """
        if not self.config.options.actionable_only:
            return True
        if finding_dict.get("suppressions"):
            return False
        if (finding_dict.get("properties") or {}).get("below_threshold"):
            return False
        if threshold is None:
            return True
        return severity_fails_threshold(
            result_severity(result if result is not None else finding_dict),
            threshold,
        )

    @staticmethod
    def _scanner_threshold(
        model: "AshAggregatedResults",
        finding_dict: Dict[str, Any],
        memo: Dict[str, str],
    ) -> str:
        """The severity threshold of the scanner that reported *finding_dict*.

        Resolved as the exit-code gate resolves it: the scanner's own
        ``options.severity_threshold``, else the global one, which is never
        unset. A finding with no scanner name gets the global threshold.
        """
        from automated_security_helper.core.scanner_statistics_calculator import (
            ScannerStatisticsCalculator,
        )

        name = (finding_dict.get("properties") or {}).get("scanner_name")
        key = name if isinstance(name, str) else ""
        if key not in memo:
            memo[key] = ScannerStatisticsCalculator.get_scanner_threshold_info(
                model, key
            )[0]
        return memo[key]

    # ------------------------------------------------------------------
    # Report runners
    # ------------------------------------------------------------------

    def _run_simple_report(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
    ) -> str:
        opts = self.config.options
        builder = BedrockPromptBuilder()
        client = self._make_model_client(bedrock_runtime)
        prepared = builder.prepare_prompt(
            builder.legacy_summary(
                findings,
                secret_findings,
                self._scanners_used(model),
                opts.max_findings_to_analyze,
            ),
            custom_prompt=opts.custom_prompt,
            industry_context=opts.industry_context,
            compliance_frameworks=opts.compliance_frameworks,
            custom_context=opts.custom_context,
        )
        return self._model_answer(
            client,
            prepared,
            "You are a security expert specializing in code security analysis. "
            "Your task is to analyze security findings from the Automated Security Helper (ASH) tool "
            "and provide a concise, actionable summary report.",
            cache_key="simple_summary",
        )

    def _run_structured_report(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
        indexed_findings: List[Dict[str, Any]],
    ) -> str:
        opts = self.config.options
        builder = BedrockPromptBuilder()
        client = self._make_model_client(bedrock_runtime)

        # The finding details show every finding as it was found: the
        # summarized list below is for the prompts, and the Evidence section
        # used to read it, so all but the first instance of each rule lost their
        # Raw JSON and that one showed the synthesized record.
        raw_findings = findings
        if opts.summarize_findings:
            ASH_LOGGER.info("Summarizing findings to reduce token usage")
            findings = self._summarize_findings(findings)

        report = "# Security scan summary report\n\n"
        report += self._build_toc(findings)

        included = set(opts.include_sections) - set(opts.exclude_sections)

        def _section_call(prompt: str, system: str, cache_key: str) -> str:
            if not prompt:
                # Nothing to analyze: the section says so itself. A builder's
                # empty answer is never sent to the model as a prompt.
                return self._nothing_to_analyze(included)
            prepared = builder.prepare_prompt(
                prompt,
                custom_prompt=opts.custom_prompt,
                industry_context=opts.industry_context,
                compliance_frameworks=opts.compliance_frameworks,
                custom_context=opts.custom_context,
            )
            return self._model_answer(client, prepared, system, cache_key=cache_key)

        if "executive_summary" in included:
            ASH_LOGGER.info("Generating executive summary")
            report += "## Executive summary\n\n"
            report += (
                _section_call(
                    builder.executive_summary(
                        findings, secret_findings, self._scanners_used(model)
                    ),
                    "You are a security expert providing a concise executive summary of security scan results.",
                    "executive_summary",
                )
                + "\n\n"
            )

        if "technical_analysis" in included:
            report += "## Findings by severity\n\n"
            if opts.group_by_severity:
                report += self._render_by_severity(findings, builder, client, opts)
            else:
                report += (
                    self._render_flat_findings(
                        bedrock_runtime,
                        model,
                        findings,
                        builder,
                        client,
                        opts,
                        included,
                    )
                    + "\n\n"
                )

        if self._secret_findings_exist and "secret_findings" in included:
            report += "## Secret findings\n\n"
            report += (
                _section_call(
                    builder.secret_advice(secret_findings),
                    "You are a security expert providing advice on handling secrets found in code.",
                    "secret_advice",
                )
                + "\n\n"
            )

        if "remediation_guide" in included:
            ASH_LOGGER.info("Generating recommendations")
            report += "## Recommendations\n\n"
            report += (
                _section_call(
                    builder.recommendations(findings, opts.max_findings_to_analyze),
                    "You are a security expert providing actionable recommendations based on security scan findings.",
                    "recommendations",
                )
                + "\n\n"
            )

        if "risk_assessment" in included:
            ASH_LOGGER.info("Generating risk assessment")
            report += "## Risk assessment\n\n"
            report += (
                _section_call(
                    builder.risk_assessment(
                        findings,
                        opts.compliance_frameworks,
                        opts.max_findings_to_analyze,
                    ),
                    "You are a security expert providing risk assessment based on security scan findings.",
                    "risk_assessment",
                )
                + "\n\n"
            )

        if "compliance_impact" in included and opts.compliance_frameworks:
            ASH_LOGGER.info("Generating compliance impact analysis")
            report += "## Compliance impact\n\n"
            report += (
                _section_call(
                    builder.compliance_impact(
                        findings,
                        opts.compliance_frameworks,
                        opts.industry_context,
                        opts.max_findings_to_analyze,
                    ),
                    "You are a compliance expert analyzing security findings against regulatory frameworks.",
                    "compliance_impact",
                )
                + "\n\n"
            )

        if "detailed_findings" not in opts.exclude_sections:
            report += self._render_finding_details(
                raw_findings, secret_findings, indexed_findings
            )

        return report

    def _nothing_to_analyze(self, included: Optional[Set[str]] = None) -> str:
        """What a section says when its builder had nothing to analyze: fixed
        report text, not a model's reply to a placeholder prompt. Names the
        secret findings when the run has them AND the report being written
        holds their section (``included`` is the main report's section set and
        names ``secret_findings``), so a secrets-only scan's risk and technical
        sections point at where its findings are. A section the operator left
        out, or the separate technical-analysis file, has no secrets section to
        point at, so the sentence is not written there."""
        text = "No actionable findings to analyze for this section."
        if (
            self._secret_findings_exist
            and included is not None
            and "secret_findings" in included
        ):
            text += " The secret findings are reported in their own section."
        return text

    def _render_by_severity(
        self,
        findings: List[Dict[str, Any]],
        builder: BedrockPromptBuilder,
        client: BedrockModelClient,
        opts: Any,
    ) -> str:
        severity_groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in findings:
            severity_groups[self._finding_severity(f).lower()].append(f)

        out = ""
        for severity in ("critical", "high", "medium", "low", "info"):
            if severity not in severity_groups:
                continue
            limited = severity_groups[severity][: opts.max_findings_per_severity]
            ASH_LOGGER.info(f"Analyzing {len(limited)} {severity} level findings")
            out += f"### {severity.capitalize()} findings\n\n"
            prompt = builder.prepare_prompt(
                builder.severity_analysis(limited, severity),
                custom_prompt=opts.custom_prompt,
                industry_context=opts.industry_context,
                compliance_frameworks=opts.compliance_frameworks,
                custom_context=opts.custom_context,
            )
            out += (
                self._model_answer(
                    client,
                    prompt,
                    f"You are a security expert analyzing {severity} level findings from a security scan.",
                    cache_key=f"severity_{severity}",
                )
                + "\n\n"
            )
        return out

    def _render_flat_findings(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        builder: BedrockPromptBuilder,
        client: BedrockModelClient,
        opts: Any,
        included: Optional[Set[str]] = None,
    ) -> str:
        if opts.batch_processing and len(findings) > opts.max_findings_to_analyze:
            return self._process_findings_by_batch(bedrock_runtime, model, findings)
        # The most severe findings first, so the cut keeps the worst.
        summary_prompt = builder.findings_summary(
            builder.most_severe_first(findings)[: opts.max_findings_to_analyze]
        )
        if not summary_prompt:
            return self._nothing_to_analyze(included)
        prompt = builder.prepare_prompt(
            summary_prompt,
            custom_prompt=opts.custom_prompt,
            industry_context=opts.industry_context,
            compliance_frameworks=opts.compliance_frameworks,
            custom_context=opts.custom_context,
        )
        return self._model_answer(
            client,
            prompt,
            "You are a security expert summarizing findings from a security scan.",
            cache_key="findings_flat",
        )

    def _render_finding_details(
        self,
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
        indexed_findings: List[Dict[str, Any]],
    ) -> str:
        import json

        report = "## Finding details\n\n"
        report += "### Finding index\n\n"
        report += "| Index | Rule ID | Severity | File | Line range | Description |\n"
        report += "|-------|---------|----------|------|------------|-------------|\n"

        for finding in indexed_findings:
            index = finding.get("index", "")
            rule_id = finding.get("rule_id", "Unknown")
            severity = self._finding_severity(finding)
            # A finding the analysis left out says why beside its severity, so
            # the table is not read as the analyzed set.
            left_out = finding.get("left_out")
            if left_out:
                severity = f"{severity} ({left_out})"
            file_path = "Unknown"
            line_range = "Unknown"
            if finding.get("locations"):
                loc = finding["locations"][0]
                file_path = loc.get("file", "Unknown")
                start = loc.get("startLine", "?")
                end = loc.get("endLine", start)
                line_range = f"{start}-{end}" if start != end else str(start)
            message = finding.get("message", "No description available")
            if len(message) > 50:
                message = message[:47] + "..."
            report += (
                "| "
                + " | ".join(
                    _cell(shown_on_one_line(str(value)))
                    for value in (
                        index,
                        rule_id,
                        severity,
                        file_path,
                        line_range,
                        message,
                    )
                )
                + " |\n"
            )

        report += "\n\n### Evidence\n\n"
        raw_by_index = {f.get("index"): f for f in findings + secret_findings}
        # A secret finding's code is never written, with include_code_snippets
        # on or off: its snippet is the credential the finding is about. The
        # same rule already keeps the code of a finding that only might be a
        # secret out of the prompts and the report.
        secret_indexes = {f.get("index") for f in secret_findings}

        for finding in indexed_findings:
            index = finding.get("index", "")
            rule_id = finding.get("rule_id", "Unknown")
            severity = self._finding_severity(finding)
            report += (
                "<details>\n"
                f"<summary>{html.escape(str(shown_on_one_line(str(index))))}. "
                f"{html.escape(str(shown_on_one_line(str(severity))))} · "
                f"{html.escape(str(shown_on_one_line(str(rule_id))))}</summary>\n\n"
                f"#### Finding {index}: {_text(shown_on_one_line(str(rule_id)))} "
                f"({_text(shown_on_one_line(str(severity)))})\n\n"
            )

            if finding.get("locations"):
                loc = finding["locations"][0]
                file_path = loc.get("file", "Unknown")
                start = loc.get("startLine", "?")
                end = loc.get("endLine", start)
                report += (
                    f"Location: {_text(shown_on_one_line(str(file_path)))} "
                    f"(lines {_text(shown_on_one_line(str(start)))}-{_text(shown_on_one_line(str(end)))})\n\n"
                )

            report += f"{_text(shown_not_obeyed(str(finding.get('message', 'No description available'))))}\n\n"

            original = raw_by_index.get(index)
            with_code = (
                self.config.options.include_code_snippets
                and index not in secret_indexes
            )
            if with_code and original:
                for loc in original.get("locations", []):
                    phys = loc.get("physicalLocation", {})
                    snippet_text = phys.get("region", {}).get("snippet", {}).get("text")
                    if snippet_text:
                        report += (
                            "Code snippet:\n"
                            + _code_block(str(shown_not_obeyed(str(snippet_text))))
                            + "\n\n"
                        )

            if original:
                if not with_code:
                    original = _without_snippets(original)
                report += "<details>\n<summary>Raw JSON</summary>\n\n"
                # Still JSON: each "##name[" form's first "#" is written as
                # JSON's own escape, which parses to the same text.
                report += _code_block(
                    json_commands_broken(json.dumps(original, indent=2)), "json"
                )
                report += "\n</details>\n\n"

            report += "</details>\n\n"
        return report

    # ------------------------------------------------------------------
    # TOC builder
    # ------------------------------------------------------------------

    def _build_toc(self, findings: List[Dict[str, Any]]) -> str:
        opts = self.config.options
        if not opts.add_table_of_contents:
            return ""

        included = set(opts.include_sections) - set(opts.exclude_sections)
        items = []
        n = 1

        if "executive_summary" in included:
            items.append(f"{n}. [Executive summary](#executive-summary)")
            n += 1
        if "technical_analysis" in included:
            items.append(f"{n}. [Findings by severity](#findings-by-severity)")
            if opts.group_by_severity:
                for sev in ("critical", "high", "medium", "low", "info"):
                    if any(self._finding_severity(f).lower() == sev for f in findings):
                        items.append(
                            f"   - [{sev.capitalize()} findings](#{sev.lower()}-findings)"
                        )
            n += 1
        if self._secret_findings_exist and "secret_findings" in included:
            items.append(f"{n}. [Secret findings](#secret-findings)")
            n += 1
        if "remediation_guide" in included:
            items.append(f"{n}. [Recommendations](#recommendations)")
            n += 1
        if "risk_assessment" in included:
            items.append(f"{n}. [Risk assessment](#risk-assessment)")
            n += 1
        if "compliance_impact" in included and opts.compliance_frameworks:
            items.append(f"{n}. [Compliance impact](#compliance-impact)")
            n += 1
        if "detailed_findings" not in opts.exclude_sections:
            items.append(f"{n}. [Finding details](#finding-details)")

        return "## Contents\n\n" + "\n".join(items) + "\n\n"

    # ------------------------------------------------------------------
    # Client factory
    # ------------------------------------------------------------------

    def _model_label(self, model_id: str) -> str:
        """How the logs and the error text name ``model_id``: the configured ID
        as the config file wrote it when the file read it from the environment
        (config/environment_record.py), else the ID itself. A fallback model's
        ID is ASH's own."""
        if model_id != self.config.options.model_id:
            return model_id
        from automated_security_helper.config.environment_record import (
            record_environment_references,
        )

        ash_config = getattr(self.context, "config", None)
        shown = record_environment_references(
            {"model_id": model_id},
            getattr(ash_config, "_environment_references", ()) or (),
            at=("reporters", "bedrock-summary-reporter", "options"),
        )["model_id"]
        return str(shown)

    def _model_call_retries(self) -> int:
        """The retries of a model call: the ``max_retries`` option, or
        ``DEFAULT_MODEL_CALL_RETRIES`` when the operator set none."""
        retries = self.config.options.max_retries
        return DEFAULT_MODEL_CALL_RETRIES if retries is None else retries

    def _model_id_to_call(self) -> str:
        """The id the run's calls go to: the listing's spelling when the
        dependency check matched the configured id case-insensitively and the
        configured id is still the one that check was made for, else the
        configured id. Read with a default: a reporter built by
        ``model_construct`` (the retry-config tests) has not run ``__init__``,
        so the attribute may not exist."""
        configured = self.config.options.model_id
        listed = getattr(self, "_listed_spelling", None)
        if listed is not None and listed[0] == configured:
            return listed[1]
        return configured

    def _make_model_client(self, bedrock_runtime: Any) -> BedrockModelClient:
        opts = self.config.options
        return BedrockModelClient(
            bedrock_runtime=bedrock_runtime,
            model_id=self._model_id_to_call(),
            temperature=opts.temperature,
            max_tokens=opts.max_tokens,
            top_p=opts.top_p,
            max_retries=self._model_call_retries(),
            base_delay=opts.base_delay,
            max_delay=opts.max_delay,
            model_label=self._model_label(opts.model_id),
            values=self._redaction_values(),
        )

    def _model_answer(
        self,
        client: BedrockModelClient,
        prompt: str,
        system_prompt: str,
        cache_key: Optional[str] = None,
    ) -> str:
        """A model answer as the report shows it: the one way report text
        comes from the model.

        The answer comes from ``_outcome_with_fallback``, cached under
        *cache_key* when one is given, and is shown here, once, after the
        cache: a cached answer is stored as the model gave it and shown each
        time it is placed. Only an answer is cached: a failure's "*Error ...*"
        text is not kept, so the next placement under the key asks again. A
        cached answer is served only for the prompt it answered: the key names
        a section, and two placements under one key (the report's executive
        summary and the executive file) share the answer while their prompts
        are the same and generate anew when they differ. A model response can
        repeat the scanned
        repository's text verbatim, so the generated-analysis sections carry
        repository text one hop removed. The answer is shown with its layout
        kept: control characters become visible escapes, a line that would
        start a workflow command is broken, HTML outside its code is text, its
        code reads as written, and a fence it leaves open is closed, while the
        response's own Markdown formatting stays as written
        (``_markdown_as_written``).
        """

        answered = {"ok": True}

        def _answer() -> str:
            outcome = self._outcome_with_fallback(client, prompt, system_prompt)
            answered["ok"] = outcome.ok
            return outcome.text

        if cache_key is None:
            text = _answer()
        else:
            digest = hashlib.sha256(
                f"{system_prompt}\x00{prompt}".encode("utf-8")
            ).hexdigest()
            prompts = getattr(self, "_cache_prompts", None)
            if prompts is not None and prompts.get(cache_key) != digest:
                # The key's cached answer, if any, answered another prompt.
                self._cache.pop(cache_key, None)
                prompts[cache_key] = digest
            text = self._get_cached_or_generate(cache_key, _answer)
            if not answered["ok"]:
                # A failure is shown but not kept: the next placement under
                # this key asks the model again.
                self._cache.pop(cache_key, None)
        shown = str(shown_not_obeyed(str(text)))
        # HTML outside the answer's code is written as text, its code as the
        # model wrote it, and a fence it leaves open is closed; the costs are
        # named on _markdown_as_written.
        return _markdown_as_written(shown)

    def _call_with_fallback(
        self, client: BedrockModelClient, prompt: str, system_prompt: str
    ) -> str:
        """The text of ``_outcome_with_fallback``: an answer, or the "*Error
        ...*" text of a failure. A caller that has to tell the two apart (the
        batch synthesis) reads the outcome's ``ok`` instead of its text."""
        return self._outcome_with_fallback(client, prompt, system_prompt).text

    def _outcome_with_fallback(
        self, client: BedrockModelClient, prompt: str, system_prompt: str
    ) -> CallOutcome:
        """The report path's model call: the configured model first, then the
        fallback chain when the call errors and ``enable_fallback_models`` is
        on. The answer comes back as the model gave it; report text takes it
        through ``_model_answer``, which shows it once.

        This is the walk ``validate_plugin_dependencies`` promises: it answers
        True for a run whose configured model is invalid but whose fallback is
        available, so the run itself has to reach that fallback, rather than
        write the configured model's "*Error ...*" string into every section
        of the report.

        Whether a call answered is the outcome's ``ok``, never its text. Only a
        failure another model can answer (``CallOutcome.model_specific``) is
        walked: one of the credentials, the connection or the service comes
        back as it is. A fallback that answered is the run's model from then
        on, so each later call goes to it first instead of failing on the
        configured model and walking again. A model-specific failure stands
        for the rest of the run, so if the run's model fails in turn the walk
        resumes after it, without calling the configured model again
        (``_configured_error`` keeps why that one failed). A walk that found
        nothing is not kept as such: what it keeps is which candidates the
        listing does not name and which Converse refused as not permitted or
        not found (``_unavailable_models``), so a later section does not ask
        about them again, while a candidate that failed on one prompt (a
        validation error, a throttle, a timeout) is called again with the next
        one, and one the control plane left unchecked is checked again.
        """
        opts = self.config.options

        def call(model: str) -> CallOutcome:
            return client.with_model(model).call(prompt, system_prompt)

        run_model = self._run_model
        if run_model is not None and opts.enable_fallback_models:
            kept = call(run_model)
            if kept.ok or not kept.model_specific:
                return kept
            run_member = getattr(self, "_run_model_member", None)
            self._run_model = None
            self._run_model_member = None
            return self._walk_outcome(
                self._control_plane(),
                opts.model_id,
                call,
                primary_error=self._configured_error,
                resume_after=run_model,
                resume_error=kept.text,
                resume_member=run_member,
            )
        outcome = client.call(prompt, system_prompt)
        if outcome.ok or not opts.enable_fallback_models or not outcome.model_specific:
            return outcome
        self._configured_error = outcome.text
        return self._walk_outcome(
            self._control_plane(),
            opts.model_id,
            call,
            primary_error=outcome.text,
        )

    def _walk_fallbacks(
        self,
        bedrock_client: Any,
        primary: str,
        call_model: Callable[[str], CallOutcome],
        primary_error: Optional[str] = None,
        primary_called: bool = True,
        keep_as_run_model: bool = True,
        resume_after: Optional[str] = None,
        resume_error: Optional[str] = None,
        primary_check: Optional[Any] = None,
    ) -> str:
        """The text of ``_walk_outcome``: the answer of the first candidate that
        answered, or the failure text (the real error of a failure no other
        model can answer, else the exhaustion text)."""
        return self._walk_outcome(
            bedrock_client,
            primary,
            call_model,
            primary_error=primary_error,
            primary_called=primary_called,
            keep_as_run_model=keep_as_run_model,
            resume_after=resume_after,
            resume_error=resume_error,
            primary_check=primary_check,
        ).text

    def _check_candidate(
        self, bedrock_client: Any, model: str, values: Iterable[str]
    ) -> Tuple[Any, str]:
        """Check one chain candidate against the listing under each spelling
        the calling region may list (``candidate_spellings``: the chain's own
        area, the region's geography, ``us.``), in that order, and answer the
        first check that is True or that the listing itself decided (a
        throttled or refused listing of the models answers the same for every
        spelling). A failed inference profile listing does not: it may have
        been read in part, so a spelling that is not on the pages that were
        read says nothing about the next one (``check_is_spelling_specific``),
        and the remaining spellings are tried. Returns the check and the
        spelling it is about, so a candidate the listing names under another
        spelling is called by that one. Every spelling is read from the one
        cached listing (``ListingsOnce``), so the extra spellings cost no
        control-plane call. A reporter built without ``__init__`` and without
        a region checks the chain's own spelling and ``us.`` only."""
        region = getattr(getattr(self, "config", None), "options", None)
        region = getattr(region, "aws_region", None)
        check: Any = None
        spelling = model
        for spelling in candidate_spellings(model, region):
            check = validate_bedrock_model(bedrock_client, spelling, values=values)
            if check[0]:
                break
            if check_is_spelling_specific(check):
                continue
            if check_is_transient(check) or check_listing_failure(check) is not None:
                break
        return check, spelling

    def _walk_outcome(
        self,
        bedrock_client: Any,
        primary: str,
        call_model: Callable[[str], CallOutcome],
        primary_error: Optional[str] = None,
        primary_called: bool = True,
        keep_as_run_model: bool = True,
        resume_after: Optional[str] = None,
        resume_error: Optional[str] = None,
        primary_check: Optional[Any] = None,
        resume_member: Optional[str] = None,
    ) -> CallOutcome:
        """Walk the fallback chain from *primary*: the one walk the report
        path (``_outcome_with_fallback``) and the shims (``_try_fallback_models``)
        share, so the two cannot drift.

        ``get_fallback_model`` falls through to its default model for a
        chain's last member, and the default's own chain walks back around, so
        the walk keeps every model it has visited and ends on a repeat rather
        than recursing without bound. Each candidate is validated before it is
        called; one that fails validation, or whose call fails, is walked past.
        A candidate whose validation the control plane gave no usable answer to
        (``check_is_transient``: a throttled listing, a failed check) is
        counted as not checked, which is not the same as not available. A
        candidate whose check failed because the listing was refused for a
        reason a later try does not pass (a denied call, an expired
        credential) is also not checked, and the exhaustion text names the
        error code of the refusal in a group of its own. The
        walk asks the control plane for each listing once (``ListingsOnce``),
        so a throttled control plane is asked once per walk, not once per
        candidate. The first that answers is the report run's model
        (``_run_model``) when ``keep_as_run_model`` says so; the shims' walks
        answer their own call only.

        Exhaustion names the model the operator configured, keeps why it
        failed (``primary_error``), and separates the models that were called
        and failed from the ones that were not available to call (*primary*
        itself is called unless ``primary_called`` says otherwise) and from the
        ones that were not checked. Every line here is redacted with the
        reporter's values.

        ``resume_after`` is the run's model when it failed in turn: the walk
        goes on from the model after it, with it and *primary* counted as
        called, and exhaustion keeps its error (``resume_error``) too.

        ``primary_check`` is the answer ``validate_bedrock_model`` gave for
        *primary* when it was not called because that check failed (the
        shim's). It is sorted as a candidate's is, so a listing the control
        plane refused or did not answer leaves *primary* in the same group as
        the fallbacks it left unchecked; without it *primary* is unavailable.
        A client already wrapped in ``ListingsOnce`` (the shim's, which made
        that check through it) is used as it is, so the listing is not asked
        again.
        """
        values = self._redaction_values()
        # Every candidate is checked against one listing: the walk asks the
        # control plane for each listing once, however long the chain is.
        if not isinstance(bedrock_client, ListingsOnce):
            bedrock_client = ListingsOnce(bedrock_client)
        called: List[str] = [primary] if primary_called else []
        unavailable: List[str] = []
        not_checked: List[str] = []
        listing_refused: Dict[str, List[str]] = {}
        listing_client_side: set[str] = set()
        profile_refused: Dict[str, List[str]] = {}
        profile_client_side: set[str] = set()

        def leave_unchecked(model: str, check: Any) -> None:
            """Sort a model whose check was False into its exhaustion group."""
            if check_is_transient(check):
                # The control plane gave no usable answer: the model was not
                # checked, which is not the same as not available. The kind is
                # the check's own data, never its text.
                not_checked.append(model)
                return
            refused_with = check_listing_failure(check)
            if refused_with is None:
                unavailable.append(model)
            else:
                # The control plane refused the listing, so the model was not
                # checked either: it is not "unavailable", which sends the
                # operator to model availability when the fault is access.
                # The code names the group; a failure of the inference profile
                # listing alone is a group of its own, so it is not read as a
                # refusal of the foundation-model listing.
                if check_is_spelling_specific(check):
                    profile_refused.setdefault(refused_with, []).append(model)
                    if check_listing_client_side(check):
                        profile_client_side.add(refused_with)
                else:
                    listing_refused.setdefault(refused_with, []).append(model)
                    if check_listing_client_side(check):
                        listing_client_side.add(refused_with)

        if not primary_called:
            if primary_check is None:
                unavailable.append(primary)
            else:
                leave_unchecked(primary, primary_check)
        if resume_after is not None and resume_after not in called:
            called.append(resume_after)
        visited = set(called) | {primary}
        if resume_member is not None:
            visited.add(resume_member)
        # The candidates an earlier walk of this run found the listing does
        # not name, or Converse refused as not permitted or not found: facts
        # about the model that do not change within a run, so a later section
        # takes them as unavailable without asking again. The shims' walks
        # (keep_as_run_model False) neither read nor write it.
        known_unavailable = (
            getattr(self, "_unavailable_models", None) if keep_as_run_model else None
        )
        # The chain continues from the member the run's model was called for;
        # the id it was called by is the listing's spelling, which the chain may
        # not hold.
        model: Optional[str] = get_fallback_model(
            primary if resume_after is None else (resume_member or resume_after)
        )
        while model and model not in visited:
            visited.add(model)
            if known_unavailable is not None and model in known_unavailable:
                unavailable.append(model)
                model = get_fallback_model(model)
                continue
            ASH_LOGGER.info(
                text_without_values(f"Trying fallback model: {model}", values)
            )
            check, spelling = self._check_candidate(bedrock_client, model, values)
            if not check[0]:
                leave_unchecked(model, check)
            else:
                # A candidate the listing matched case-insensitively is called
                # by the listing's spelling, the one Converse knows.
                called_id = check_model_id(check) or spelling
                called.append(called_id)
                outcome = call_model(called_id)
                if outcome.ok:
                    ASH_LOGGER.info(
                        text_without_values(
                            f"Fallback model {called_id} succeeded", values
                        )
                    )
                    if keep_as_run_model:
                        self._run_model = called_id
                        self._run_model_member = model
                    return outcome
                if not outcome.model_specific:
                    # No connection, no credentials, the service down: every
                    # later candidate fails the same way, so the walk ends here
                    # with the real error, not the generic exhaustion text
                    # after calling the rest of the chain for nothing.
                    return outcome
                if (
                    known_unavailable is not None
                    and outcome.code in _REFUSED_FOR_THE_RUN
                ):
                    # Not permitted, or not found by Converse: a refusal about
                    # the model, the same on every prompt, so the run's later
                    # sections skip it as they skip an unlisted one. A throttle,
                    # a timeout or a refusal of this prompt is not kept: the
                    # next section's call may pass.
                    known_unavailable.add(model)
            model = get_fallback_model(model)
        exhausted = CallOutcome(
            text_without_values(
                _exhaustion_text(
                    primary,
                    called,
                    unavailable,
                    primary_error,
                    run_model=resume_after,
                    run_model_error=resume_error,
                    not_checked=not_checked,
                    listing_refused=listing_refused,
                    listing_client_side=listing_client_side,
                    profile_listing_refused=profile_refused,
                    profile_listing_client_side=profile_client_side,
                ),
                values,
            ),
            ok=False,
            model_specific=True,
        )
        if known_unavailable is not None:
            # What the run's later sections take as settled: the listing's
            # answer, and the candidates Converse refused as not permitted or
            # not found (kept above). A candidate whose call failed on this
            # prompt (a validation error, a throttle, a timeout) may answer the
            # next section's prompt, and a candidate the control plane left
            # unchecked (a throttled or refused listing) is checked again.
            known_unavailable.update(unavailable)
        return exhausted

    # ------------------------------------------------------------------
    # Markdown file writer
    # ------------------------------------------------------------------

    def _write_markdown_files(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        all_findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
        summary: str,
    ) -> None:
        opts = self.config.options
        included = set(opts.include_sections) - set(opts.exclude_sections)
        builder = BedrockPromptBuilder()
        client = self._make_model_client(bedrock_runtime)

        exec_content: Optional[str] = None
        if "executive_summary" in included:
            prompt = builder.prepare_prompt(
                builder.executive_summary(
                    all_findings, secret_findings, self._scanners_used(model)
                ),
                custom_prompt=opts.custom_prompt,
                industry_context=opts.industry_context,
                compliance_frameworks=opts.compliance_frameworks,
                custom_context=opts.custom_context,
            )
            # The same key as the structured report's executive summary: the
            # two prompts are the same (the builder reads counts, which a
            # summarized list keeps), so under enable_caching the answer is
            # generated once and the file and the report carry one copy. Under
            # a key of its own the prompt was sent twice and the copies differed.
            exec_content = self._model_answer(
                client,
                prompt,
                "You are a security expert providing a concise executive summary of security scan results.",
                cache_key="executive_summary",
            )

        tech_content: Optional[str] = None
        tech_header = GENERATED_HEADER
        if "technical_analysis" in included:
            analysis_prompt = builder.technical_analysis(
                all_findings,
                opts.max_findings_to_analyze,
                opts.include_code_snippets,
            )
            if analysis_prompt:
                tech_prompt = builder.prepare_prompt(
                    analysis_prompt,
                    custom_prompt=opts.custom_prompt,
                    industry_context=opts.industry_context,
                    compliance_frameworks=opts.compliance_frameworks,
                    custom_context=opts.custom_context,
                )
                tech_content = self._model_answer(
                    client,
                    tech_prompt,
                    "You are a security expert providing detailed technical analysis of security findings.",
                    cache_key="technical_summary_only",
                )
            else:
                # A secrets-only scan: the section has nothing to send, so its
                # file carries fixed text and says so instead of claiming
                # generated output (the executive file, which was sent, keeps
                # the generated-output notice).
                tech_content = self._nothing_to_analyze()
                tech_header = NOT_SENT_SECTION_HEADER

        self._write_files(
            model, summary, exec_content, tech_content, tech_header=tech_header
        )

    def _write_files(
        self,
        model: "AshAggregatedResults",
        summary: str,
        exec_content: Optional[str],
        tech_content: Optional[str],
        *,
        exec_header: str = GENERATED_HEADER,
        tech_header: str = GENERATED_HEADER,
    ) -> None:
        """Write the summary file and, for each included section with content,
        its companion file. Shared by the run with findings and the run with
        none, so a clean scan writes its files too. *exec_header* and
        *tech_header* are the line under each companion file's title: the
        generated-output notice by default, and for a file whose text no model
        produced (a run that called no model; a section with nothing to send)
        a line that says so, per file, since one file may be generated while
        the other is not."""
        opts = self.config.options
        included = set(opts.include_sections) - set(opts.exclude_sections)

        # The configured file names can come from the environment (``${VAR}``),
        # and ash.log is a sink, so each "written to" line is redacted with the
        # reporter's redaction values. The files themselves keep their names.
        values = self._redaction_values()

        reports_dir = Path(self.context.output_dir) / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        self._write_companion(
            reports_dir, opts.output_file, summary, "Bedrock summary", values
        )

        if "executive_summary" in included and exec_content is not None:
            self._write_companion(
                reports_dir,
                opts.output_executive_file,
                self._scan_outcome(model)
                + "\n\n## Executive summary\n\n"
                + exec_header
                + "\n\n"
                + exec_content
                + f"\n\n{FOOTER_CREDIT}\n",
                "Executive summary",
                values,
            )

        if "technical_analysis" in included and tech_content is not None:
            self._write_companion(
                reports_dir,
                opts.output_technical_file,
                self._scan_outcome(model)
                + "\n\n## Technical analysis\n\n"
                + tech_header
                + "\n\n"
                + tech_content
                + f"\n\n{FOOTER_CREDIT}\n",
                "Technical analysis",
                values,
            )

    @staticmethod
    def _write_companion(
        reports_dir: Path,
        filename: str,
        content: str,
        label: str,
        values: Tuple[str, ...],
    ) -> None:
        """Write *content* as the file *filename* under *reports_dir* and log
        the write as "*label* written to <path>".

        The line names the path the file has, ``reports_dir / filename``,
        which is where ``write_report_file`` writes when it writes at all (it
        answers None, having logged why, for a name that is not a file in the
        directory or a write the file system refused). The write's result is
        not what the line is built from: the report text, which quotes values
        the reporter has shown already (the model's answer, the project name),
        goes into the file and nowhere near the line, so the line shows the path
        once and nothing twice, and the shown-once check, which follows what a
        logged value is bound from, reads it that way."""
        if write_report_file(reports_dir, filename, content) is None:
            return
        ASH_LOGGER.info(
            text_without_values(f"{label} written to {reports_dir / filename}", values)
        )

    # ------------------------------------------------------------------
    # Caching
    # ------------------------------------------------------------------

    def _get_cached_or_generate(self, key: str, generator_func):  # type: ignore[type-arg]
        """Get a cached result or generate and cache it."""
        if not self.config.options.enable_caching:
            return generator_func()
        if key in self._cache:
            ASH_LOGGER.debug(f"Using cached result for {key}")
            return self._cache[key]
        result = generator_func()
        self._cache[key] = result
        return result

    # ------------------------------------------------------------------
    # Findings utilities (tested directly by existing test suite)
    # ------------------------------------------------------------------

    def _summarize_findings(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Summarize findings to reduce token usage.

        Grouped by rule AND severity: grouping by rule alone gave every instance
        the first one's severity, so a CRITICAL instance of a rule whose first
        instance was LOW was analyzed as LOW and the Critical section could
        vanish. A summary carries every instance's location, in SARIF shape, so
        the prompts list them instead of the first instance's alone, and
        ``original_count`` so the builders count every instance.
        """
        if not self.config.options.summarize_findings or not findings:
            return findings

        grouped: Dict[Tuple[str, str], List[Dict[str, Any]]] = defaultdict(list)
        for finding in findings:
            rule_id = (
                finding.get("ruleId")
                or (finding.get("rule") or {}).get("id")
                or "unknown"
            )
            grouped[(rule_id, self._finding_severity(finding))].append(finding)

        summarized = []
        for _group, rule_findings in grouped.items():
            if len(rule_findings) == 1:
                summarized.append(rule_findings[0])
                continue
            base = deepcopy(rule_findings[0])
            seen_uris: List[str] = []
            locations: List[Dict[str, Any]] = []
            for f in rule_findings:
                for loc in f.get("locations", []):
                    uri = (
                        loc.get("physicalLocation", {})
                        .get("artifactLocation", {})
                        .get("uri")
                    )
                    if uri and uri not in seen_uris:
                        seen_uris.append(uri)
                        locations.append(
                            {"physicalLocation": {"artifactLocation": {"uri": uri}}}
                        )
            if locations:
                base["locations"] = locations
            if "message" in base and isinstance(base["message"], dict):
                base["message"]["text"] = (
                    f"Found {len(rule_findings)} instances of this issue"
                )
            if "properties" not in base:
                base["properties"] = {}
            base["properties"]["summarized"] = True
            base["properties"]["original_count"] = len(rule_findings)
            summarized.append(base)
        return summarized

    def _process_findings_by_batch(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
    ) -> str:
        """Process findings in batches to optimize token usage."""
        opts = self.config.options
        builder = BedrockPromptBuilder()
        client = self._make_model_client(bedrock_runtime)

        if not opts.batch_processing or len(findings) <= opts.max_findings_to_analyze:
            prompt = builder.prepare_prompt(
                builder.findings_summary(
                    builder.most_severe_first(findings)[: opts.max_findings_to_analyze]
                ),
                custom_prompt=opts.custom_prompt,
                industry_context=opts.industry_context,
                compliance_frameworks=opts.compliance_frameworks,
                custom_context=opts.custom_context,
            )
            return self._model_answer(
                client,
                prompt,
                "You are a security expert summarizing findings from a security scan.",
            )

        batch_size = opts.max_findings_to_analyze
        batches = [
            findings[i : i + batch_size] for i in range(0, len(findings), batch_size)
        ]
        answered: List[Tuple[int, str]] = []
        failed: List[Tuple[int, str]] = []
        for i, batch in enumerate(batches):
            ASH_LOGGER.info(f"Processing batch {i + 1} of {len(batches)}")
            prompt = builder.prepare_prompt(
                builder.findings_summary(batch),
                custom_prompt=opts.custom_prompt,
                industry_context=opts.industry_context,
                compliance_frameworks=opts.compliance_frameworks,
                custom_context=opts.custom_context,
            )
            # Each batch's answer is prompt input for the synthesis below, not
            # report text, so it is kept as the model gave it. Whether a batch
            # answered is the outcome's ``ok``, never its text: a failed batch's
            # "*Error ...*" text used to be fed to the synthesis as that batch's
            # summary, and the report showed no failure.
            outcome = self._outcome_with_fallback(
                client,
                prompt,
                "You are a security expert summarizing findings from a security scan.",
            )
            (answered if outcome.ok else failed).append((i, outcome.text))

        if not answered:
            # Every batch failed: the first failure is the section's text, shown
            # as any model text is.
            return _markdown_as_written(str(shown_not_obeyed(str(failed[0][1]))))

        formatted = [f"BATCH {i + 1}:\n{s}" for i, s in answered]
        # Prepared as every other prompt is: the synthesis is the section's
        # final text, and it used to go without the custom prompt, the context
        # and the writing rules each batch was sent with.
        combined = builder.prepare_prompt(
            "Synthesize the following batch summaries into a cohesive overall summary:\n\n"
            + "\n".join(formatted)
            + "\n\nProvide a unified summary that captures the key insights from all batches.\n",
            custom_prompt=opts.custom_prompt,
            industry_context=opts.industry_context,
            compliance_frameworks=opts.compliance_frameworks,
            custom_context=opts.custom_context,
        )
        synthesis = self._model_answer(
            client,
            combined,
            "You are a security expert synthesizing multiple security scan batch summaries.",
        )
        if failed:
            # The report says which batches the synthesis does not cover, and
            # why, in the failure's own (redacted) words.
            notes = "\n".join(
                f"- Batch {i + 1} of {len(batches)} was not summarized: "
                + _markdown_as_written(str(shown_not_obeyed(str(_error_reason(text)))))
                for i, text in failed
            )
            synthesis += (
                f"\n\n{len(failed)} of {len(batches)} batches could not be "
                f"summarized and are not covered above:\n{notes}"
            )
        return synthesis

    # ------------------------------------------------------------------
    # Backward-compat shims (existing tests call these methods directly)
    # ------------------------------------------------------------------

    def _call_bedrock(
        self, bedrock_runtime: Any, user_message: str, system_prompt: str
    ) -> str:
        """Thin shim retained for backward compatibility with existing tests.

        It keeps none of a report run's state: its control-plane client is
        built for this call, from the profile and region the options hold
        now, and a fallback its walk reaches answers this call only.
        """
        opts = self.config.options
        builder = BedrockPromptBuilder()
        client = self._make_model_client(bedrock_runtime)

        # The listing is asked once for this call: the check of the configured
        # model and the fallback walk read the same answer.
        bedrock_client = ListingsOnce(
            self._session().client(
                "bedrock", config=control_plane_client_config(opts.max_retries)
            )
        )
        label = self._model_label(opts.model_id)
        primary_check = validate_bedrock_model(
            bedrock_client,
            opts.model_id,
            values=self._redaction_values(),
            label=label,
        )
        is_valid, error_message = primary_check
        if not is_valid:
            if opts.enable_fallback_models:
                prepared = self._prepare_prompt(user_message)
                return self._try_fallback_models(
                    bedrock_runtime,
                    bedrock_client,
                    opts.model_id,
                    [{"role": "user", "content": [{"text": prepared}]}],
                    [{"text": system_prompt}],
                    {
                        "temperature": opts.temperature,
                        "maxTokens": opts.max_tokens,
                        "topP": opts.top_p,
                    },
                    primary_error=error_message,
                    primary_called=False,
                    primary_check=primary_check,
                )
            return text_without_values(
                f"*Error: Primary model {label} validation failed: {error_message}*",
                self._redaction_values(),
            )

        prepared = builder.prepare_prompt(
            user_message,
            custom_prompt=opts.custom_prompt,
            industry_context=opts.industry_context,
            compliance_frameworks=opts.compliance_frameworks,
            custom_context=opts.custom_context,
        )
        outcome = client.call(prepared, system_prompt)
        if not outcome.ok and outcome.model_specific and opts.enable_fallback_models:
            return self._try_fallback_models(
                bedrock_runtime,
                bedrock_client,
                opts.model_id,
                [{"role": "user", "content": [{"text": prepared}]}],
                [{"text": system_prompt}],
                {
                    "temperature": opts.temperature,
                    "maxTokens": opts.max_tokens,
                    "topP": opts.top_p,
                },
                primary_error=outcome.text,
            )
        return outcome.text

    def _try_fallback_models(
        self,
        bedrock_runtime: Any,
        bedrock_client: Any,
        failed_model_id: str,
        messages: List[Dict],
        system: List[Dict],
        inference_config: Dict,
        primary_error: Optional[str] = None,
        primary_called: bool = True,
        primary_check: Optional[Any] = None,
    ) -> str:
        """Try fallback models when the primary model fails.

        The walk itself is ``_walk_fallbacks``, shared with the report path
        (``_call_with_fallback``); here each candidate is called through
        ``_try_model_call`` with the shim's raw converse arguments.
        ``_try_model_call`` answers text, as this shim always has, so a
        candidate's call failed when that text is an "*Error ...*" string.
        ``primary_error``, ``primary_called`` and ``primary_check`` say how the
        configured model failed, for the exhaustion text.
        """
        return self._walk_fallbacks(
            bedrock_client,
            failed_model_id,
            lambda model: _shim_outcome(
                self._try_model_call(
                    bedrock_runtime, model, messages, system, inference_config
                )
            ),
            primary_error=primary_error,
            primary_called=primary_called,
            keep_as_run_model=False,
            primary_check=primary_check,
        )

    def _prepare_prompt(self, user_message: str) -> str:
        """Prepare the prompt with custom context and industry information."""
        opts = self.config.options
        return BedrockPromptBuilder().prepare_prompt(
            user_message,
            custom_prompt=opts.custom_prompt,
            industry_context=opts.industry_context,
            compliance_frameworks=opts.compliance_frameworks,
            custom_context=opts.custom_context,
        )

    def _invoke_bedrock_model(self, bedrock_runtime: Any, **converse_args) -> dict:  # type: ignore[type-arg]
        """Invoke the Bedrock model."""
        return bedrock_runtime.converse(**converse_args)

    def _try_model_call(
        self,
        bedrock_runtime: Any,
        model_id: str,
        messages: List[Dict],
        system: List[Dict],
        inference_config: Dict,
    ) -> str:
        """Try to call a specific model with error handling."""
        opts = self.config.options
        client = BedrockModelClient(
            bedrock_runtime=bedrock_runtime,
            model_id=model_id,
            temperature=inference_config.get("temperature", opts.temperature),
            max_tokens=inference_config.get("maxTokens", opts.max_tokens),
            top_p=inference_config.get("topP", opts.top_p),
            max_retries=self._model_call_retries(),
            base_delay=opts.base_delay,
            max_delay=opts.max_delay,
            model_label=self._model_label(model_id),
            values=self._redaction_values(),
        )
        prompt_text = ""
        if messages and messages[0].get("content"):
            first = messages[0]["content"]
            if first and isinstance(first[0], dict):
                prompt_text = first[0].get("text", "")
        system_text = ""
        if system and isinstance(system[0], dict):
            system_text = system[0].get("text", "")
        return client.try_call(prompt_text, system_text)

    def _generate_executive_summary(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
    ) -> str:
        """Generate an executive summary of the scan results.

        The builder's prompt goes to ``_call_bedrock`` as it is: that shim
        prepares it (the custom prompt, the context, the writing rules), and
        preparing it here as well sent all three twice."""
        builder = BedrockPromptBuilder()
        return self._call_bedrock(
            bedrock_runtime,
            builder.executive_summary(
                findings, secret_findings, self._scanners_used(model)
            ),
            "You are a security expert providing a concise executive summary of security scan results.",
        )

    def _generate_summary(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
    ) -> str:
        """Generate a summary of findings using Amazon Bedrock (legacy method)."""
        return self._run_simple_report(
            bedrock_runtime, model, findings, secret_findings
        )

    def _generate_technical_analysis(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
    ) -> str:
        """Generate a detailed technical analysis of findings.

        The builder's prompt goes to ``_call_bedrock`` unprepared, as in
        ``_generate_executive_summary``."""
        opts = self.config.options
        builder = BedrockPromptBuilder()
        return self._call_bedrock(
            bedrock_runtime,
            builder.technical_analysis(
                findings, opts.max_findings_to_analyze, opts.include_code_snippets
            ),
            "You are a security expert providing detailed technical analysis of security findings.",
        )

    def _generate_report_with_headers(
        self,
        bedrock_runtime: Any,
        model: "AshAggregatedResults",
        findings: List[Dict[str, Any]],
        secret_findings: List[Dict[str, Any]],
        indexed_findings: List[Dict[str, Any]],
    ) -> str:
        """Thin alias retained for backward compatibility."""
        return self._run_structured_report(
            bedrock_runtime, model, findings, secret_findings, indexed_findings
        )
