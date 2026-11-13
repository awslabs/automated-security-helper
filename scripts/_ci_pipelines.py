# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""CI pipelines: fragments merged into the pipeline they extend, and the runner census.

Loaded by path from scripts/docs_checks.py, the way the MCP contract reader is,
and nowhere else: docs_checks re-exports every name here, so callers keep one
import surface. The merge rules, the YAML 1.1/1.2 reading comparisons and the
hand-ported Psych scalar reading live here, apart from the page checks, because
they pin upstream behavior (Psych v5.3.1, GitLab's loader, PyYAML) and have to
be audited against those sources on their own.

docs_checks passes its page model helpers and marker constants through
``bind()`` after loading; the functions here use them under their original
names, so this module holds the moved code as it was.
"""

from __future__ import annotations

import functools
import math
import re
from dataclasses import dataclass
from typing import Any, Iterable

# -- Bound by docs_checks through bind(): its page model helpers and marker
# -- constants, under the names the code below has always used. The defaults
# -- exist so the module imports on its own; nothing works until bind() runs.
ci_marker: Any = None
extended_block: Any = None
groovy_sh_scripts: Any = None
parse_config_text: Any = None
split_shell: Any = None
find_invocations: Any = None
invocations_in_script: Any = None
_dicts_with_key: Any = None
_calls_scan_workflow: Any = None
_strings_under_keys: Any = None
CI_MERGE_KINDS: Any = None
CI_RUNNERS: Any = None
CI_RUNNER_NONE: Any = None
JENKINSFILE_KIND: Any = None
OTHER_CONFIG_KINDS: Any = None
_SHELL_KEYWORDS: Any = None


def bind(**helpers: Any) -> None:
    """Receive docs_checks' page model helpers and marker constants.

    They land in this module's globals under the names the functions below
    already use, so markers and shell commands are read exactly as the rest of
    the checks read them, and the moved code stays as it was in docs_checks.
    """
    globals().update(helpers)


# The CI pages hold whole pipelines and fragments of them: a second job to add under
# jobs:, steps that replace the install and scan steps of the job above, the rules: a
# merge request pipeline adds. The Docs CI Runners workflow runs each block with its
# CI system's own runner (CI_RUNNERS). A fragment, marked extends=<path>, runs merged
# into the block an earlier marker saved at <path>; the config check performs the same
# merge (check_config_blocks), so a fragment that no longer fits the pipeline it
# changes fails the lint before any runner starts. The rules, by kind:
#
# - gitlab-ci: as GitLab merges an included file into the including one, with the
#   fragment as the including file. Hashes merge at any depth and the fragment's value
#   wins; anything that is not a hash on both sides (arrays such as script and rules,
#   scalars) is the fragment's. https://docs.gitlab.com/ci/yaml/includes/
# - github-actions, a mapping of job ids: its jobs are added, and a job with the same
#   id is replaced whole.
# - github-actions, a list of steps: a named step replaces the step of the saved job
#   with the same name; an unnamed one replaces the step that uses the same action,
#   whatever its ref. A step with no counterpart goes right before the next step of the
#   fragment that replaces one, or right after the last replaced step. The steps must
#   match in exactly one job, and replace its steps in the job's order: in any other
#   order no merged job has the new steps where the page shows them.
#
# The merged pipeline is written back as YAML, from what PyYAML read, so it carries
# PyYAML's YAML 1.1 reading of every value that is not a string. Where YAML 1.2 reads
# such a plain value differently (no is false in 1.1 and the string "no" in 1.2, 0755
# is 493 and 755, 1:30 is 90 and a string), a runner reading YAML 1.2 would run a
# pipeline the page does not show, so the merge refuses the value and names its line;
# quoting it gives it one reading. A gitlab-ci pipeline is held to GitLab's reading as
# well. GitLab loads it with Ruby's Psych (_psych_reading), which reads yEs as true,
# nUll as null, 1,000 as 1000 and :x as a symbol, and leaves 0o17 and 1e3 strings;
# gitlab-ci-local, which runs the page's pipeline, is not a Psych reader, so a run
# would test a value GitLab never sees. The merge refuses a plain value Psych reads
# otherwise than YAML 1.2 or PyYAML there too, and the config check refuses it in
# every gitlab-ci block, merged or not (_gitlab_block_reading_problem). The refusal
# names the reader that differs: gitlab-ci-local reads plain values by YAML 1.2's core
# schema, plus timestamps and merge keys (js-yaml), so where GitLab reads a value as
# YAML 1.2 does (1__0, a string to both) the one that differs is PyYAML, which these
# checks read the pipeline with, and a block marked runner=none, which no runner runs,
# gets no word about a run.
#
# A string is written back in the page's form. One the page writes plain stays plain,
# so every reader reads it as it reads the page's. One the page quotes stays quoted,
# whatever a reader makes of its plain form: readers differ there (0o17 is 15 to YAML
# 1.2, yEs true to Psych, and 0o1_7, a string to both, 15 to go-yaml, which act reads a
# workflow with; act gets the 15 where it decodes a value untyped, as a job's with:,
# and the text in env:, which it decodes into strings). The one exception is a
# workflow's top-level on: key, which PyYAML reads as true and GitHub as the trigger
# key: it is written back as the bare on: the page writes, and a true: key stays the
# boolean key GitHub reads too. A pipeline is one YAML document; one of several is
# refused too.


class CiComposeError(ValueError):
    """A fragment that cannot be merged into the pipeline it extends."""


#: How YAML 1.2's core schema resolves a plain scalar
#: (https://yaml.org/spec/1.2.2/#1023-core-schema); anything else is a string.
_YAML12_NULL = re.compile(r"^(?:~|null|Null|NULL|)$")
_YAML12_BOOL = re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$")
_YAML12_INT = re.compile(r"^(?:[-+]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)$")
_YAML12_FLOAT = re.compile(
    r"^(?:[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?"
    r"|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))$"
)
_YAML_TAG = "tag:yaml.org,2002:"


def _float_value(value: float) -> Any:
    """A float as the readings compare it: an infinity or a NaN by its YAML name (.inf,
    -.inf, .nan), since a NaN equals nothing, itself included."""
    if value != value:
        return ".nan"
    if math.isinf(value):
        return ".inf" if value > 0 else "-.inf"
    return value


def _yaml12_reading(text: str) -> tuple[str, Any]:
    """(type, value) of a plain scalar as YAML 1.2's core schema reads it."""
    if _YAML12_NULL.match(text):
        return "null", None
    if _YAML12_BOOL.match(text):
        return "bool", text.lower() == "true"
    if _YAML12_INT.match(text):
        if text.startswith(("0o", "0x")):
            return "int", int(text[2:], 8 if text[1] == "o" else 16)
        return "int", int(text, 10)
    if _YAML12_FLOAT.match(text):
        lowered = text.lower()
        if lowered.endswith(("inf", "nan")):
            return "float", _float_value(float(lowered.replace(".", "")))
        return "float", float(text)
    return "str", text


def _yaml11_reading(text: str, tag: str) -> tuple[str, Any]:
    """(type, value) of a plain scalar as PyYAML, a YAML 1.1 reader, resolved it.
    Raises ValueError for a value PyYAML resolves and cannot build (0x_ as an int)."""
    import yaml

    kind = tag.removeprefix(_YAML_TAG)
    if kind in ("int", "float"):
        value = yaml.safe_load(text)  # digits, signs, _, :, . and e only
        return kind, _float_value(value) if kind == "float" else value
    if kind == "bool":
        return kind, text.lower() in ("yes", "true", "on")
    if kind == "null":
        return kind, None
    return kind, text


# GitLab reads a pipeline with YAML.safe_load (lib/gitlab/config/loader/yaml.rb in
# gitlab-org/gitlab, read at commit 80e0a21742e0), which permits Symbol and no other
# Ruby class, and turns each untagged plain scalar into a value with Psych's
# ScalarScanner#tokenize. _psych_reading is a port of tokenize from Psych v5.3.1 (tag
# commit 8345af9ffbac), the version GitLab's Gemfile.lock pins at that commit:
# https://github.com/ruby/psych/blob/v5.3.1/lib/psych/scalar_scanner.rb, lines 8-25
# and 38-111. The one change: INTEGER_LEGACY is v5.0.1's (lines 22-25 there), which
# also takes 0x, 0b or 0 followed by nothing but _ and ,: v5.0.1 reads those as numbers
# or refuses the file, and v5.3.1 as strings, so a value either version reads as other
# than a string is caught. Ruby's \d and \s are ASCII; the patterns are compiled so
# that Python's are too, and anchored as Ruby's ^ and $ are, at each line.
_PSYCH_TIME = re.compile(
    r"^-?\d{4}-\d{1,2}-\d{1,2}(?:[Tt]|\s+)\d{1,2}:\d\d:\d\d(?:\.\d*)?"
    r"(?:\s*(?:Z|[-+]\d{1,2}:?(?:\d\d)?))?$",
    re.ASCII | re.MULTILINE,
)
_PSYCH_DATE = re.compile(
    r"^\d{4}-(?:1[012]|0\d|\d)-(?:[12]\d|3[01]|0\d|\d)$", re.ASCII | re.MULTILINE
)
_PSYCH_FLOAT = re.compile(
    r"^(?:[-+]?(?:[0-9][0-9_,]*)?\.[0-9]*(?:[eE][-+][0-9]+)?)$", re.MULTILINE
)
_PSYCH_INTEGER = re.compile(
    r"^(?:[-+]?0b[0-1_,]+|[-+]?0[0-7_,]+|[-+]?(?:0|[1-9](?:[0-9]|,[0-9]|_[0-9])*)"
    r"|[-+]?0x[0-9a-fA-F_,]+)$",
    re.MULTILINE,
)
_PSYCH_SEXAGESIMAL_INT = re.compile(
    r"^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9]){1,2}$", re.MULTILINE
)
_PSYCH_SEXAGESIMAL_FLOAT = re.compile(
    r"^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9]){1,2}\.[0-9_]*$", re.MULTILINE
)
#: tokenize's first test, ^[^\d.:-]?[[:alpha:]_\s!@#$%\^&*(){}<>|/\\~;=]+ : at most one
#: character that is not a digit, ., : or -, then a letter ([^\W\d_], Ruby's
#: [[:alpha:]]) or one of the others.
_PSYCH_WORD = re.compile(
    r"^[^0-9.:-]?(?:[^\W\d_]|[_ \t\n\v\f\r!@#$%^&*(){}<>|/\\~;=])", re.MULTILINE
)


def _psych_search(pattern: str, text: str) -> bool:
    """Ruby's string.match?(/pattern/i): ^ and $ at each line, case ignored."""
    return re.search(pattern, text, re.IGNORECASE | re.MULTILINE) is not None


def _ruby_to_i(part: str) -> int:
    """Ruby's String#to_i: the leading digits, a _ between two of them allowed, with
    their sign; 0 when there are none."""
    match = re.match(r"([-+]?)([0-9]+(?:_[0-9]+)*)", part)
    if match is None:
        return 0
    value = int(match.group(2).replace("_", ""))
    return -value if match.group(1) == "-" else value


def _ruby_to_f(part: str) -> float:
    """Ruby's String#to_f, for the digits and the point a sexagesimal part has."""
    match = re.match(r"[-+]?[0-9]+(?:_[0-9]+)*(?:\.[0-9]+(?:_[0-9]+)*)?", part)
    return float(match.group(0).replace("_", "")) if match else 0.0


def _ruby_integer(digits: str) -> int:
    """Ruby's Integer() of what tokenize's integer pattern matched, its _ and , deleted:
    0b and 0x set the base, as a leading 0 sets octal. Raises ValueError where Ruby
    raises ArgumentError: 0b or 0x with no digit after it."""
    sign = -1 if digits.startswith("-") else 1
    body = digits[1:] if digits[:1] in ("-", "+") else digits
    if body[:2] in ("0b", "0x"):
        return sign * int(body[2:], 2 if body[1] == "b" else 16)
    if len(body) > 1 and body[0] == "0":
        return sign * int(body[1:], 8)
    return sign * int(body, 10)


def _psych_reading(text: str) -> tuple[str, Any]:
    """(type, value) of a plain scalar as GitLab reads it: the port of Psych's
    ScalarScanner#tokenize described above, branch by branch.

    A timestamp or a date is a Time or Date to Psych, classes GitLab's loader does not
    permit, so GitLab refuses the file; "error" is a value Ruby's Float() or Integer()
    refuses (.e+5, 0x_), which GitLab reports as invalid YAML.
    """
    if text == "":
        return "null", None
    if "\n" in text or _PSYCH_WORD.search(text):
        if len(text) > 5 or _psych_search(r"^[^ytonf~]", text):
            return "str", text
        if text == "~" or _psych_search(r"^null$", text):
            return "null", None
        if _psych_search(r"^(?:yes|true|on)$", text):
            return "bool", True
        if _psych_search(r"^(?:no|false|off)$", text):
            return "bool", False
        return "str", text
    if _PSYCH_TIME.search(text):
        return "timestamp", text
    if _PSYCH_DATE.search(text):
        return "date", text
    if _psych_search(r"^\+?\.inf$", text):
        return "float", ".inf"
    if _psych_search(r"^-\.inf$", text):
        return "float", "-.inf"
    if _psych_search(r"^\.nan$", text):
        return "float", ".nan"
    if re.search(r"^:.", text, re.MULTILINE):
        quoted = re.search(r"^:([\"'])(.*)\1", text, re.MULTILINE)
        name = quoted.group(2).removeprefix(":") if quoted else text[1:]
        return "symbol", name
    if _PSYCH_SEXAGESIMAL_INT.search(text):
        total = 0
        for index, part in enumerate(text.split(":")):
            total += _ruby_to_i(part) * 60 ** abs(index - 2)
        return "int", total
    if _PSYCH_SEXAGESIMAL_FLOAT.search(text):
        total = 0.0
        for index, part in enumerate(text.split(":")):
            total += _ruby_to_f(part) * 60 ** abs(index - 2)
        return "float", _float_value(total)
    if _PSYCH_FLOAT.search(text):
        if re.fullmatch(r"[-+]?\.", text):
            return "str", text
        number = re.sub(r"\.([Ee]|$)", r"\1", text.replace(",", "").replace("_", ""))
        try:
            return "float", _float_value(float(number))
        except ValueError:
            return "error", text
    if _PSYCH_INTEGER.search(text):
        try:
            return "int", _ruby_integer(text.replace(",", "").replace("_", ""))
        except ValueError:
            return "error", text
    return "str", text


def _reading_text(kind: str, value: Any) -> str:
    if kind == "bool":
        return f"the boolean {'true' if value else 'false'}"
    if kind in ("int", "float"):
        return f"the number {value}"
    if kind == "null":
        return "null"
    if kind == "str":
        return "a string"
    if kind == "symbol":
        return f"the symbol :{value}"
    if kind == "error":
        return "invalid YAML"
    return f"a {kind}"


def _trigger_key_node(root: Any) -> Any:
    """The top-level plain on: key of a composed GitHub workflow, or None: the trigger
    key, which PyYAML would read as true."""
    import yaml

    if not isinstance(root, yaml.MappingNode):
        return None
    return next(
        (
            key
            for key, _value in root.value
            if isinstance(key, yaml.ScalarNode)
            and key.style is None
            and key.value == "on"
        ),
        None,
    )


def _yaml_reading_problem(
    root: Any,
    what: str,
    first_line: int,
    exempt_on: bool,
    psych: bool = False,
    written_back: bool = True,
    runs: bool = True,
) -> str | None:
    """The first plain scalar of a composed YAML document that the merge cannot carry
    as the page shows it, as a message naming the value and its line, or None.

    That is a value PyYAML (YAML 1.1) reads as something other than a string, and
    YAML 1.2 reads differently: the merged pipeline carries PyYAML's reading, written
    back in its own form (no as false, 0755 as 493). With ``psych``, for a gitlab-ci
    pipeline, it is also a value GitLab (_psych_reading) reads otherwise than YAML 1.2
    or PyYAML (yEs, 1,000, 0o17), named by _gitlab_reading_message. A string PyYAML
    reads, and that passes, is written back as the page writes it (_dump_pipeline).

    With ``written_back`` False and ``psych``, for a gitlab-ci block run as the page
    writes it, which nothing writes back, only GitLab's reading is checked. That
    refuses every value the YAML 1.1 rule above refuses too, since GitLab's reading
    cannot match both of two readings that differ, and names the reading GitLab
    gives it. With ``runs`` False, for a block no runner runs (runner=none), the
    message says nothing of a run.

    With ``exempt_on``, the document's top-level on: key is exempt: a saved GitHub
    workflow's trigger key (_trigger_key_node), which compose_ci_pipeline writes back
    as on:. A merge key (<<) is left alone: the CI systems' readers take it. A quoted,
    block or !!str scalar is a string to every reader.
    """
    import yaml

    exempt = _trigger_key_node(root) if exempt_on else None
    stack = [root]
    seen: set[int] = set()
    while stack:
        node = stack.pop()
        if node is None or id(node) in seen:
            continue
        seen.add(id(node))  # an alias is the same node object as its anchor
        if isinstance(node, yaml.MappingNode):
            for key, value in reversed(node.value):
                stack += [value, key]
            continue
        if isinstance(node, yaml.SequenceNode):
            stack += reversed(node.value)
            continue
        if not isinstance(node, yaml.ScalarNode) or node.style is not None:
            continue  # quoted and block scalars are strings to both
        if node is exempt or node.tag in (_YAML_TAG + "merge", _YAML_TAG + "value"):
            continue
        if node.tag == _YAML_TAG + "str" and getattr(node, "explicit_tag", False):
            continue
        text = node.value
        line = first_line + node.start_mark.line
        try:
            old = _yaml11_reading(text, node.tag)
        except ValueError:
            return (
                f"{what} has the plain value {text!r} at line {line}, which PyYAML "
                f"resolves as type {node.tag.removeprefix(_YAML_TAG)} and cannot build; "
                "quote the value, or write the one you mean, to give it one reading"
            )
        new = _yaml12_reading(text)
        if written_back and old[0] != "str" and old != new:
            return (
                f"{what} has the plain value {text!r} at line {line}, which YAML 1.1 "
                f"reads as {_reading_text(*old)} and YAML 1.2 as {_reading_text(*new)}; "
                "CI systems differ in which they read, so quote the value, or write "
                "the one you mean, to give it one reading"
            )
        if not psych:
            continue
        ruby = _psych_reading(text)
        if ruby != new or ruby != old:
            return _gitlab_reading_message(what, text, line, ruby, new, old, runs)
    return None


def _gitlab_reading_message(
    what: str,
    text: str,
    line: int,
    ruby: tuple[str, Any],
    new: tuple[str, Any],
    old: tuple[str, Any],
    runs: bool,
) -> str:
    """The refusal of a plain value GitLab reads as ``ruby``, YAML 1.2 as ``new`` and
    PyYAML as ``old``, naming the reader that differs from GitLab.

    gitlab-ci-local reads plain values by YAML 1.2's core schema, plus timestamps and
    merge keys (js-yaml). GitLab refuses a timestamp and these checks pass merge keys
    over, so where GitLab's reading is YAML 1.2's (1__0, a string to both, which PyYAML
    reads as 10) a local run tests the value GitLab reads, and the reader that differs
    is PyYAML. Anywhere else a local run tests another value, which the message says
    unless no runner runs the block (``runs`` False).
    """
    start = f"{what} has the plain value {text!r} at line {line}, which "
    end = "quote the value, or write the one you mean, to give it one reading"
    if ruby == new:
        return (
            f"{start}GitLab (Psych) and YAML 1.2 read as {_reading_text(*ruby)} and "
            f"PyYAML, which these checks read the pipeline with, as "
            f"{_reading_text(*old)}; {end}"
        )
    readings = (
        f"{start}GitLab (Psych) reads as {_reading_text(*ruby)}, YAML 1.2 as "
        f"{_reading_text(*new)} and PyYAML as {_reading_text(*old)}"
    )
    if not runs:
        return f"{readings}; {end}"
    return f"{readings}; a local run would not test the value GitLab reads, so {end}"


#: The tag _load_pipeline gives a workflow's top-level plain on: key, so that it is
#: read as the trigger key rather than true.
_TRIGGER_KEY_TAG = "tag:docs-checks.invalid,2026:trigger-key"


class _TriggerKey(str):
    """A workflow's on: key, written back as the bare ``on:`` the page writes."""

    __slots__ = ()


class _PlainStr(str):
    """A string the page writes plain, written back plain (_dump_pipeline)."""

    __slots__ = ()


@functools.lru_cache(maxsize=1)
def _pipeline_loader() -> type:
    """PyYAML's safe loader, reading a string the page writes plain (untagged, unquoted)
    as a _PlainStr and a node tagged _TRIGGER_KEY_TAG as the trigger key. It notes on
    each scalar node whether the page gives its tag (!!str 0o17)."""
    import yaml

    class PipelineLoader(yaml.SafeLoader):
        def compose_scalar_node(self, anchor: Any) -> Any:
            explicit = self.peek_event().tag not in (None, "!")
            node = super().compose_scalar_node(anchor)
            node.explicit_tag = explicit
            return node

    def string(loader: Any, node: Any) -> str:
        value = loader.construct_scalar(node)
        if node.style is None and not getattr(node, "explicit_tag", False):
            return _PlainStr(value)
        return value

    PipelineLoader.add_constructor(_YAML_TAG + "str", string)
    PipelineLoader.add_constructor(
        _TRIGGER_KEY_TAG, lambda _loader, _node: _TriggerKey("on")
    )
    return PipelineLoader


def _load_pipeline(
    text: str,
    what: str,
    first_line: int = 1,
    exempt_on: bool = False,
    psych: bool = False,
) -> Any:
    """A pipeline's text, read as one YAML document. Raises CiComposeError when it does
    not parse, holds more than one document, or has a plain value the merge cannot
    carry as the page shows it (_yaml_reading_problem; ``psych`` for a gitlab-ci
    pipeline). ``first_line`` is the page line of the text's first line, for the
    messages.

    A string the page writes plain comes back as a _PlainStr; with ``exempt_on``, the
    top-level plain on: key comes back as the trigger key, a _TriggerKey, not true.
    """
    import yaml

    loader = _pipeline_loader()(text)
    try:
        documents = []
        while loader.check_node():
            documents.append(loader.get_node())
        if len(documents) > 1:
            raise CiComposeError(
                f"{what} holds {len(documents)} YAML documents, separated by ---; a "
                "fragment and the pipeline it extends are one document each"
            )
        if not documents:
            return None
        root = documents[0]
        problem = _yaml_reading_problem(root, what, first_line, exempt_on, psych)
        if problem:
            raise CiComposeError(problem)
        trigger = _trigger_key_node(root) if exempt_on else None
        if trigger is not None:
            trigger.tag = _TRIGGER_KEY_TAG
        return loader.construct_document(root)
    except CiComposeError:
        raise
    except (yaml.YAMLError, ValueError) as exc:
        # ValueError: a value PyYAML resolves and cannot build, in a tagged scalar
        # (!!int 1,000) that the reading check passes.
        first = str(exc).strip().splitlines()[0] if str(exc).strip() else "invalid"
        raise CiComposeError(f"{what} does not parse as yaml: {first}") from exc
    finally:
        loader.dispose()


def _gitlab_block_reading_problem(block: Any) -> str | None:
    """A plain value of a gitlab-ci block that GitLab reads otherwise than YAML 1.2 or
    PyYAML, as a message naming the value and its page line, or None.

    The merge holds the pipelines it merges to GitLab's reading; this holds every
    gitlab-ci block to it, merged or not. gitlab-ci-local reads the pipeline it runs
    with js-yaml, not Psych, so a block it runs as the page writes it (one that
    extends nothing, or a saved block, which runs on its own as well) would test such
    a value as GitLab never reads it. A fragment is checked as the merge checks it,
    so the config check names its value even when the merge is not attempted. Every
    document of the block is checked: GitLab reads a spec: header and the pipeline
    after it. A block that does not parse is parse_config_text's to report. A block
    marked runner=none, which no runner runs, is held to GitLab's reading too, and its
    message says nothing of a run.
    """
    import yaml

    marker = ci_marker(block)
    fragment = marker is not None and marker.extends is not None
    runs = marker is None or marker.runner != CI_RUNNER_NONE
    loader = _pipeline_loader()(block.body)
    try:
        while loader.check_node():
            problem = _yaml_reading_problem(
                loader.get_node(),
                "the fragment" if fragment else "the pipeline",
                block.body_line,
                exempt_on=False,
                psych=True,
                written_back=fragment,
                runs=runs,
            )
            if problem:
                return problem
    except yaml.YAMLError:
        return None
    finally:
        loader.dispose()
    return None


def _saved_workflow_reading_problem(block: Any) -> str | None:
    """A plain value of a saved github-actions block that the merge cannot carry as
    the page shows it (_yaml_reading_problem), or None.

    The merge reads the saved workflow whenever a fragment extends it, so such a
    value is the saved block's own problem: this reports it once, at the saved
    fence, and _fragment_merge_problems then skips every fragment that extends the
    block, instead of each fragment repeating the same message. The top-level plain
    on: key is exempt, as the merge exempts it (_load_pipeline exempt_on). A
    workflow nothing extends is held to the same rule: its save-as says a fragment
    may extend it. A block that is not saved is left to the merge, which reports a
    fragment's own values at the fragment's fence, and a block that does not parse
    is parse_config_text's to report.
    """
    import yaml

    marker = ci_marker(block)
    if marker is None or marker.save_as is None or marker.extends is not None:
        return None
    loader = _pipeline_loader()(block.body)
    try:
        while loader.check_node():
            problem = _yaml_reading_problem(
                loader.get_node(),
                f"the saved config kind={marker.kind} pipeline",
                block.body_line,
                exempt_on=True,
            )
            if problem:
                return problem
    except yaml.YAMLError:
        return None
    finally:
        loader.dispose()
    return None


def _parse_workflow(text: str) -> tuple[Any, str | None]:
    """parse_config_text for a GitHub workflow, with each document's top-level plain
    on: key read as the key "on", as GitHub reads it, rather than true. PyYAML reads a
    true:, True: or On: key as true too; GitHub reads none of them as on:."""
    loader = _pipeline_loader()(text)
    try:
        documents = []
        while loader.check_node():
            node = loader.get_node()
            trigger = _trigger_key_node(node)
            if trigger is not None:
                trigger.tag = _TRIGGER_KEY_TAG
            documents.append(loader.construct_document(node))
        return (documents[0] if len(documents) == 1 else documents), None
    except Exception as exc:  # every parser's error is the finding, as there
        first = (
            str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
        )
        return None, f"does not parse as yaml: {first}"
    finally:
        loader.dispose()


def _workflow_on(document: Any) -> Any:
    """The value of a GitHub workflow's on: key, from the workflow as _parse_workflow
    reads it: the top-level on:, plain or quoted, which GitHub reads as the trigger
    key. PyYAML reads a true:, True: or On: key as true, as it reads a plain on:;
    GitHub reads none of them as on:, so none of them is read here."""
    return document.get("on") if isinstance(document, dict) else None


def _type_name(value: Any) -> str:
    """What a parsed YAML value is, for a message: "a mapping", "a list", "empty"."""
    if value is None:
        return "empty"
    # isinstance, not type(): a string the page writes plain is a _PlainStr.
    for kind, name in ((dict, "a mapping"), (list, "a list"), (str, "a string")):
        if isinstance(value, kind):
            return name
    return f"a {type(value).__name__}"


def _gitlab_include_merge(including: Any, included: Any) -> Any:
    """``included`` merged into ``including`` as GitLab merges an included file: the
    including file's value wins, and two hashes are merged key by key, at any depth."""
    import copy

    if not (isinstance(including, dict) and isinstance(included, dict)):
        return copy.deepcopy(including)
    merged = copy.deepcopy(included)
    for key, value in including.items():
        merged[key] = _gitlab_include_merge(value, merged.get(key))
    return merged


def _step_label(step: dict, number: int) -> str:
    if "name" in step:
        return f"step {step['name']!r}"
    if "uses" in step:
        return f"the unnamed step that uses {step['uses']}"
    return f"step {number} of the fragment"


def _step_matches(fragment_step: dict, saved_step: Any) -> bool:
    """Whether a fragment step replaces a saved step: by name when the fragment step
    has one, else by the action it uses, ignoring the @ref."""
    if not isinstance(saved_step, dict):
        return False
    if "name" in fragment_step:
        return "name" in saved_step and saved_step["name"] == fragment_step["name"]
    if "uses" in fragment_step and "uses" in saved_step:
        action = str(fragment_step["uses"]).split("@", 1)[0].strip()
        return str(saved_step["uses"]).split("@", 1)[0].strip() == action
    return False


def _merge_github_steps(workflow: dict, fragment: list) -> dict:
    import copy

    for number, step in enumerate(fragment, start=1):
        if not isinstance(step, dict):
            raise CiComposeError(
                f"step {number} of the fragment is {_type_name(step)}, not a step's "
                "mapping"
            )
    jobs = workflow["jobs"]
    #: job id, as YAML read it (a number stays a number) -> the saved step indices
    #: each fragment step replaces.
    matched: dict[Any, list[list[int]]] = {}
    for job_id, job in jobs.items():
        steps = job.get("steps") if isinstance(job, dict) else None
        if not isinstance(steps, list):
            continue
        per_step = [
            [index for index, saved in enumerate(steps) if _step_matches(step, saved)]
            for step in fragment
        ]
        if any(per_step):
            matched[job_id] = per_step
    if not matched:
        raise CiComposeError(
            "no step of the fragment replaces a step of the saved workflow (a named "
            "step replaces the step with the same name, an unnamed one the step that "
            "uses the same action), so nothing says where its steps go"
        )
    if len(matched) > 1:
        raise CiComposeError(
            "the fragment's steps match steps in more than one job "
            f"({', '.join(sorted(str(job_id) for job_id in matched))}), so which job "
            "it changes is ambiguous; name the steps as they are named in the job it "
            "changes"
        )
    ((job_id, per_step),) = matched.items()
    saved_steps = jobs[job_id]["steps"]
    replaced: dict[int, dict] = {}
    before: dict[int, list[dict]] = {}
    pending: list[dict] = []
    last = -1
    last_label = ""
    for number, (step, indices) in enumerate(zip(fragment, per_step), start=1):
        if not indices:
            pending.append(step)
            continue
        if len(indices) > 1:
            raise CiComposeError(
                f"{_step_label(step, number)} matches {len(indices)} steps of job "
                f"{job_id}, so which one it replaces is ambiguous"
            )
        (index,) = indices
        if index in replaced:
            raise CiComposeError(
                f"two steps of the fragment replace step {index + 1} of job {job_id}"
            )
        if index < last:
            # Out of order, the steps between have no place that is the page's.
            raise CiComposeError(
                f"{_step_label(step, number)} replaces step {index + 1} of job "
                f"{job_id}, which comes before step {last + 1}, the one {last_label} "
                "replaces; a fragment's steps replace the job's in the job's order, "
                "so list them in that order"
            )
        replaced[index] = step
        before[index], pending = pending, []
        last, last_label = index, _step_label(step, number)
    merged_steps: list[Any] = []
    for index, saved in enumerate(saved_steps):
        if index not in replaced:
            merged_steps.append(copy.deepcopy(saved))
            continue
        merged_steps += copy.deepcopy(before[index])
        merged_steps.append(copy.deepcopy(replaced[index]))
        if index == last:
            merged_steps += copy.deepcopy(pending)
    merged = copy.deepcopy(workflow)
    merged["jobs"][job_id]["steps"] = merged_steps
    return merged


def _merge_github_workflow(workflow: Any, fragment: Any) -> dict:
    import copy

    if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
        raise CiComposeError(
            "the saved workflow has no jobs: mapping for the fragment to change"
        )
    if isinstance(fragment, list):
        merged = _merge_github_steps(workflow, fragment)
    elif isinstance(fragment, dict):
        merged = copy.deepcopy(workflow)
        for job_id, job in fragment.items():
            merged["jobs"][job_id] = copy.deepcopy(job)
    else:
        raise CiComposeError(
            "a github-actions fragment is a mapping of jobs or a list of steps; this "
            f"one is {_type_name(fragment)}"
        )
    for job_id, job in merged["jobs"].items():
        if not isinstance(job, dict):
            raise CiComposeError(
                f"job {job_id} is {_type_name(job)}, not a job's mapping, so the "
                "merged workflow no longer parses as a GitHub Actions workflow"
            )
        if "runs-on" not in job and "uses" not in job:
            # A jobs fragment written as a whole workflow (jobs: around its jobs) ends
            # here, as a job named jobs.
            raise CiComposeError(
                f"job {job_id} has neither runs-on: nor uses:, so the merged workflow "
                "no longer parses as a GitHub Actions workflow; a jobs fragment holds "
                "the jobs themselves, as they go under jobs:"
            )
    return merged


def _dump_pipeline(document: Any) -> str:
    import yaml

    class Dumper(yaml.SafeDumper):
        pass

    def trigger_key(dumper: Any, _value: str) -> Any:
        # Tagged as the boolean PyYAML reads it as, so the emitter writes it plain;
        # GitHub, a YAML 1.2 reader, reads the plain on as the string "on".
        return dumper.represent_scalar("tag:yaml.org,2002:bool", "on")

    def string(dumper: Any, value: str) -> Any:
        # A script keeps its lines, as a literal block, rather than one quoted line
        # of \n escapes. A string the page writes plain is written plain, so every
        # reader reads it as it reads the page's. Any other one, which the page
        # quotes, tags !!str or writes as a block, is quoted: readers differ in which
        # plain forms they read as strings (YAML 1.2 reads 0o17 as 15, GitLab yEs as
        # true, go-yaml 0o1_7 as 15), and quoted it is a string to each of them. The
        # emitter quotes a value the style chosen cannot hold, in double quotes where
        # single quotes cannot hold it either.
        if "\n" in value:
            style = "|"
        elif isinstance(value, _PlainStr):
            style = None
        else:
            style = "'"
        return dumper.represent_scalar("tag:yaml.org,2002:str", value, style=style)

    Dumper.add_representer(_TriggerKey, trigger_key)
    Dumper.add_representer(_PlainStr, string)
    Dumper.add_representer(str, string)
    return yaml.dump(
        document, Dumper=Dumper, sort_keys=False, allow_unicode=True, width=1 << 16
    )


def compose_ci_pipeline(
    kind: str,
    saved: str,
    fragment: str,
    *,
    saved_first_line: int = 1,
    fragment_first_line: int = 1,
) -> str:
    """The text of the pipeline a fragment of ``kind`` makes of the ``saved`` pipeline it
    extends, by the rules above. Raises CiComposeError when the two do not merge.

    The ``*_first_line`` arguments are the page lines the two texts start on, so a
    message names a value's line on the page; by default, its line in the text.
    """
    if kind not in CI_MERGE_KINDS:
        raise CiComposeError(
            f"config kind={kind} has no merge rule, so it takes no extends="
        )
    base = _load_pipeline(
        saved,
        f"the saved config kind={kind} pipeline",
        saved_first_line,
        exempt_on=kind == "github-actions",
        psych=kind == "gitlab-ci",
    )
    part = _load_pipeline(
        fragment, "the fragment", fragment_first_line, psych=kind == "gitlab-ci"
    )
    if kind == "gitlab-ci":
        if not isinstance(part, dict):
            raise CiComposeError(
                "a gitlab-ci fragment is a mapping, merged as GitLab merges an included "
                f"file; this one is {_type_name(part)}"
            )
        if not isinstance(base, dict):
            raise CiComposeError(
                f"the saved gitlab-ci pipeline is {_type_name(base)}, not a mapping"
            )
        return _dump_pipeline(_gitlab_include_merge(part, base))
    # The saved workflow's plain on: key was read as the trigger key (_load_pipeline)
    # and is written back as on:; a true: key is a boolean key to GitHub too, and stays
    # one.
    return _dump_pipeline(_merge_github_workflow(base, part))


def ci_pipeline_text(page: Any, block: Any) -> str:
    """The pipeline a CI block runs as: its own body, or for a fragment (extends=) the
    pipeline the block it extends saved (extended_block), with the fragment merged in.
    Raises CiComposeError for a fragment that names nothing above it to extend, or one
    that does not merge."""
    marker = ci_marker(block)
    if marker is None or marker.extends is None:
        return block.body
    saved = extended_block(page, block)
    if saved is None:
        raise CiComposeError(
            f"extends={marker.extends} names no earlier block on this page saved with "
            f"save-as={marker.extends}"
        )
    return compose_ci_pipeline(
        marker.kind,
        saved.body,
        block.body,
        saved_first_line=saved.body_line,
        fragment_first_line=block.body_line,
    )


@dataclass(frozen=True)
class CiCensusEntry:
    """One CI block, as the census sees it."""

    #: The page, repo-relative (Page.rel).
    page: str
    #: The block's fence line.
    line: int
    kind: str
    #: The fence line of the block it extends, or None for a whole pipeline.
    composed_from: int | None
    #: The event its runner emulates, or None for a kind that takes none.
    event: str | None
    #: Whether its scan keeps only the findings in changed files.
    changed_files: bool
    #: The marker's reason, for a runner=none block.
    reason: str | None


@dataclass
class CiRunnerCensus:
    """Which CI blocks each leg of the Docs CI Runners workflow runs, and which none does.

    Every CI block is in exactly one of the three: run by the leg (or, for a
    Jenkinsfile, the two legs) of its kind, marked runner=none, or of a kind with no
    local runner.
    """

    #: (runner, page) -> the page's blocks that runner runs, in page order.
    legs: dict[tuple[str, str], list[CiCensusEntry]]
    #: Blocks marked runner=none, in page order.
    runner_none: list[CiCensusEntry]
    #: Blocks of a kind with no local runner (not in CI_RUNNERS), in page order.
    static_only: list[CiCensusEntry]


def _triggers(document: Any) -> set[str]:
    """The events a GitHub workflow's on: names (a string, a list or a mapping), from
    the workflow as _parse_workflow reads it."""
    on = _workflow_on(document)
    if isinstance(on, str):
        return {on}
    if isinstance(on, (list, dict)):
        return {str(event) for event in on}
    return set()


def _pipeline_scripts(kind: str, text: str) -> tuple[Any, list[str]]:
    """A pipeline's parsed document (None for a Jenkinsfile, or one that does not parse)
    and its shell scripts, read as the CLI check reads them (block_invocations)."""
    if kind == JENKINSFILE_KIND:
        return None, [script for _line, script in groovy_sh_scripts(text)]
    if kind == "github-actions":
        document, error = _parse_workflow(text)
    else:
        document, error = parse_config_text(text, "yaml")
    if error is not None:
        return None, []
    return document, list(_strings_under_keys(document, OTHER_CONFIG_KINDS[kind]))


def _scans_changed_files(document: Any, scripts: list[str]) -> bool:
    """An ash command with --changed-files-only (a mention of the option in any other
    command, such as an echo, does not count), one taking "$@" after the script's own
    set -- put --changed-files-only in the positional parameters, or a call of the
    scan workflow with its changed-files-only input true.

    The positionals are followed in script order: a set -- behind a leading
    reserved word (``then set -- ...``) or a case pattern counts, a set --
    passing "$@" back (``set -- "$@" --base-ref ...``) carries the old
    positionals forward with whatever they hold, a later plain set -- resets
    them only outside every if and case (an else or elif arm's reset is the
    then arm's sibling, not its undoing), and an ash command before any set --
    never had them."""
    for script in scripts:
        positional = False
        depth = 0
        for command in split_shell(script):
            words = list(command.words)
            while words and (
                words[0] in _SHELL_KEYWORDS
                or words[0] in ("case", "esac")
                or words[0].endswith(")")
            ):
                if words[0] in ("if", "case"):
                    depth += 1
                elif words[0] in ("fi", "esac"):
                    depth = max(depth - 1, 0)
                words.pop(0)
            if words[:2] == ["set", "--"]:
                if "--changed-files-only" in words:
                    positional = True
                elif "$@" in words[2:]:
                    # The old positionals, and the flag they may hold, are
                    # carried forward: at runtime this set appends to them.
                    pass
                elif depth == 0:
                    positional = False
                continue
            found = find_invocations(words)
            for inner in command.substitutions:
                found += invocations_in_script(inner)
            for invocation in found:
                if "--changed-files-only" in invocation.args or (
                    positional and "$@" in invocation.args
                ):
                    return True
    for job in _dicts_with_key(document, "uses"):
        given = job.get("with")
        if not _calls_scan_workflow(str(job.get("uses"))) or not isinstance(
            given, dict
        ):
            continue
        value = given.get("changed-files-only")
        if value is True or str(value).strip().lower() == "true":
            return True
    return False


def ci_runner_census(pages: Iterable[Any]) -> CiRunnerCensus:
    """Every CI block of the pages, by the runner leg that runs it (CI_RUNNERS).

    A block's event is its marker's event=, else for a GitHub workflow pull_request
    when its (merged) on: has it and push when not, and for a GitLab pipeline push;
    other kinds have none. Whether it scans changed files only is read from the
    (merged) pipeline, never from the marker, so it cannot drift from the page. A
    .md.template page is left out: its rendered page has the same blocks, and that
    is the page that runs.
    """
    legs: dict[tuple[str, str], list[CiCensusEntry]] = {}
    runner_none: list[CiCensusEntry] = []
    static_only: list[CiCensusEntry] = []
    for page in pages:
        if page.path.name.endswith(".md.template"):
            continue
        for block in page.blocks:
            marker = ci_marker(block)
            if marker is None:
                continue
            saved = extended_block(page, block)
            try:
                text = ci_pipeline_text(page, block)
            except CiComposeError:
                text = block.body  # the config check reports the fragment
            document, scripts = _pipeline_scripts(marker.kind, text)
            event = marker.event
            if event is None and marker.kind == "github-actions":
                event = (
                    "pull_request" if "pull_request" in _triggers(document) else "push"
                )
            elif event is None and marker.kind == "gitlab-ci":
                event = "push"
            entry = CiCensusEntry(
                page=page.rel,
                line=block.fence_line,
                kind=marker.kind,
                composed_from=saved.fence_line if saved is not None else None,
                event=event,
                changed_files=_scans_changed_files(document, scripts),
                reason=marker.reason,
            )
            if marker.kind not in CI_RUNNERS:
                static_only.append(entry)
            elif marker.runner == CI_RUNNER_NONE:
                runner_none.append(entry)
            else:
                for runner in CI_RUNNERS[marker.kind]:
                    legs.setdefault((runner, page.rel), []).append(entry)
    return CiRunnerCensus(legs=legs, runner_none=runner_none, static_only=static_only)
