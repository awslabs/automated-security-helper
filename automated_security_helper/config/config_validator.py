# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Configuration validation utilities for ASH."""

import bisect
import copy
import functools
import json
import math
import os
import re
import shlex
import typing
from collections import deque
from dataclasses import dataclass, field
from datetime import date, datetime
from pathlib import Path
from typing import (
    Any,
    Callable,
    Collection,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Pattern,
    Sequence,
    Set,
    Tuple,
)

import yaml
from pydantic_core import core_schema as _core_schema

from automated_security_helper.config.ash_config import (
    ENV_REFERENCE_PATTERN,
    _PluginConfigSegment,
    env_reference_left_as_written,
    env_reference_value,
    plugin_key_lookup_names,
    read_env_reference,
    resolve_env_references,
)
from automated_security_helper.config.environment_record import (
    ENVIRONMENT_VALUE_SHOWN,
    EnvironmentReference,
    environment_references,
    with_environment_values_shown,
)
from automated_security_helper.config.plugin_section_names import (
    fold_known_plugin_sections,
    folded_section_name,
)
from automated_security_helper.config.config_sources import (
    EXTENDS_KEY,
    PATCH_KEY,
    FileIdentity,
    _resolve_dict_key,
    describe_config_path,
    is_config_parse_error,
    is_json_file,
    identity_to_hold,
    is_toml_file,
    parse_config_text,
    parse_config_text_literally,
    read_config_file,
    read_config_file_as_written,
    read_config_file_literally,
    read_config_text,
    refuse_unless_a_file,
    unparsed_config_reason,
)
from automated_security_helper.core.exceptions import (
    ASHConfigEnvNotResolvedError,
    ASHConfigInputNotPermittedError,
    ASHConfigSourceError,
    ASHConfigUnparsedError,
)
from automated_security_helper.utils.numeric_text import (
    MIN_ANYWHERE_LENGTH,
    MIN_REDACTED_LENGTH,
    bounded_number_pattern,
    number_bounded_form,
    purely_numeric,
)
from automated_security_helper.utils.path_matching import directory_spelling
from automated_security_helper.utils.redacted_model import value_tuple
from automated_security_helper.utils.unknown_keys import (
    INTERNAL_SECTION_FIELDS,
    internal_field_message,
    internal_fields_named,
)


#: What ``directory_path_advice`` says of the path. ``ash config validate``
#: prints it as a warning: a scan accepts the config, and the path matches nothing.
DIRECTORY_PATH_PROBLEM = "points to a directory but matches no file in it"


def directory_path_advice(path_pattern: str, *, ignore_path: bool) -> str:
    """The warning for a path that names an existing directory and no file in it.

    Shared by ``ash config validate`` and ``ash config lint``, and spelled as
    ``path_matching.directory_spelling`` spells it, as the warning after the scan
    does: ``<dir>/`` for an ignore path, ``<dir>/**/*`` for a suppression path.
    """
    spelling = directory_spelling(path_pattern, ignore_path=ignore_path)
    action = (
        "to ignore every file inside the directory"
        if ignore_path
        else "to suppress the findings in every file inside the directory"
    )
    return f"Path '{path_pattern}' {DIRECTORY_PATH_PROBLEM}. Use '{spelling}' {action}."


#: What ``path_pattern_advice`` says of a pattern that starts with ``./``.
DOT_PREFIX_PROBLEM = "starts with './' and matches no path"

#: What ``path_pattern_advice`` says of a pattern that leads to a path in the
#: scanned tree only by case.
CASE_ONLY_PROBLEM = "only by case; patterns match case-sensitively"

#: Patterns that name no path: ASH matches a pattern against paths relative to
#: the scan root, and none of those is empty or ``.``.
_PATTERNS_THAT_NAME_NO_PATH = ("", ".", "./", ".\\")


def _without_dot_prefix(pattern: str) -> str:
    while pattern.startswith("./"):
        pattern = pattern[2:]
    return pattern


def _match_spelling(pattern: str) -> str:
    """``pattern`` as the matcher reads it: each backslash a separator
    (``path_matching._match_form``), so ``.\\src`` is ``./src`` and ``src\\lib``
    is ``src/lib``. The checks below read this spelling, and the advice spells
    its replacement with ``/``; a message still names the pattern as written."""
    return pattern.replace("\\", "/")


def _with_tree_spelling(pattern: str, project_root: Path) -> str:
    """``pattern`` with its leading names respelled as the tree spells them
    (``_case_only_spelling``) and the rest kept, or ``pattern`` itself when the
    tree holds the names as written, or not at all."""
    spelled = _case_only_spelling(pattern, project_root)
    if spelled is None:
        return pattern
    parts = pattern.split("/")
    index = 0
    while index < len(parts) and not any(
        character in parts[index] for character in _GLOB_CHARACTERS
    ):
        index += 1
    tail = parts[index:]
    if not tail:
        return spelled
    return "/".join([spelled.rstrip("/"), *tail])


#: Directories a walk for one pattern's directory reads before it gives up:
#: a tree larger than this is not read whole for one warning.
_DIRECTORY_WALK_LIMIT = 20000


def _names_a_directory_below(name: str, project_root: Path) -> bool:
    """Whether a directory named ``name`` is anywhere below the root, found
    by a walk that follows no link and stops at _DIRECTORY_WALK_LIMIT
    directories. For a ``**/<name>`` pattern, which names a path exactly: a
    file of that name, never the files inside a directory of that name."""
    seen = 0
    try:
        for _parent, directories, _files in os.walk(project_root, followlinks=False):
            if name in directories:
                return True
            seen += len(directories)
            if seen > _DIRECTORY_WALK_LIMIT:
                return False
    except (OSError, ValueError):
        return False
    return False


def _case_only_spelling(pattern: str, project_root: Path) -> Optional[str]:
    """The tree's spelling of ``pattern``'s leading names, when the tree holds them
    only in another case; None when it holds them as written, or not at all.

    The leading names are the components before the first one with a glob
    character. Each is looked up in its directory's listing, so the answer is
    the same on a filesystem that ignores case. A name two entries match in
    another case (``Tests`` and ``TESTS``) is not guessed at.
    """
    if pattern.startswith("/"):
        return None
    names: List[str] = []
    for part in pattern.split("/"):
        if any(character in part for character in _GLOB_CHARACTERS):
            break
        if part in ("", "."):
            continue
        if part == "..":
            return None
        names.append(part)
    current = project_root
    spelled: List[str] = []
    differs = False
    for name in names:
        try:
            entries = os.listdir(current)
        except OSError:
            return None
        if name not in entries:
            matches = [
                entry for entry in entries if entry.casefold() == name.casefold()
            ]
            if len(matches) != 1:
                return None
            name, differs = matches[0], True
        spelled.append(name)
        current = current / name
    if not differs:
        return None
    return "/".join(spelled) + ("/" if _names_a_directory(current) else "")


def _names_a_directory(path: Path) -> bool:
    """Whether ``path`` is a directory, with a stat that raises read as "not
    one": a parent that cannot be searched (EACCES), a name past the system's
    length (ENAMETOOLONG) or a NUL in the pattern (ValueError). The advice for
    one pattern must not abort every structural warning of the check, and the
    catch-all that would report the exception prints the pattern's value."""
    try:
        return path.is_dir()
    except (OSError, ValueError):
        return False


def path_pattern_advice(
    path_pattern: str,
    project_root: Path,
    *,
    ignore_path: bool,
    shown_pattern: Optional[str] = None,
) -> Optional[str]:
    """The warning for an ignore or suppression path that matches nothing, with
    what to write instead, or None for a path that is fine.

    Shared by ``ash config validate`` and ``ash config lint``. ASH matches a
    pattern against paths relative to the scan root (``project_root``), which
    never start with ``./``, and case-sensitively, so in this order:

    - an empty pattern, ``.``, ``./`` or ``.\\`` names no path; the advice is to
      name the paths;
    - a pattern that starts with ``./`` matches no path; the advice is the pattern
      without it, with a directory spelled as ``directory_path_advice`` spells it;
    - a pattern whose leading names the tree holds only in another case is named
      with the tree's spelling;
    - a path that names an existing directory and no file in it gets
      ``directory_path_advice``.

    The message names the pattern as ``shown_pattern``, with any part read from
    the environment shown as such, and then quotes neither the pattern nor the
    tree's spelling of it; None names it as it is.
    """
    shown = path_pattern if shown_pattern is None else shown_pattern
    read_from_environment = shown != path_pattern
    # Read as the matcher reads it, a backslash a separator: a pattern spelled
    # '.\\src' or 'src\\lib' got no warning here while it matched nothing.
    form = _match_spelling(path_pattern)
    shown_form = form if not read_from_environment else _match_spelling(shown)
    # './/x' strips to '/x', which joined to the root is the host's '/x' and,
    # advised, an absolute pattern: the slashes the prefix leaves come off too.
    rest = _without_dot_prefix(form).lstrip("/")
    # A '.' or '..' component names no path under the root: a path relative to
    # the scan root holds neither, so './.', './..', '../x' and 'dir/.' match
    # nothing, and so would a directory spelling made of them ('dir/./').
    components = rest.split("/")
    if (
        path_pattern in _PATTERNS_THAT_NAME_NO_PATH
        or (form.startswith("./") and not rest)
        or _DOT_COMPONENTS & set(components)
    ):
        target = "to ignore" if ignore_path else "whose findings to suppress"
        example = "build/" if ignore_path else "tests/**/*"
        return (
            f"Path '{shown}' matches no path. Name the paths {target} instead, "
            f"such as '{example}'."
        )

    if form.startswith("./"):
        if not shown_form.startswith("./"):
            return f"Path '{shown}' {DOT_PREFIX_PROBLEM}. Remove the leading './'."
        # The slash the operator typed, read before the respelling: the tree's
        # spelling of a directory ends in one too, and that one is not theirs.
        typed_as_directory = rest.endswith("/")
        if read_from_environment:
            shown_rest = _without_dot_prefix(shown_form).lstrip("/")
        else:
            # The tree's spelling of the names: './Tests/' was advised as
            # 'Tests/' where the tree spells it 'tests', a pattern that
            # matches nothing either.
            rest = _with_tree_spelling(rest, project_root)
            shown_rest = rest
        # Asked of the tree's spelling: './Tests' names the directory 'tests'
        # on a case-sensitive filesystem only once respelled.
        names_directory = (
            not any(character in rest for character in _GLOB_CHARACTERS)
            and not (ignore_path and typed_as_directory)
            and _names_a_directory(project_root / rest.rstrip("/"))
        )
        if names_directory:
            spelling = directory_spelling(shown_rest, ignore_path=ignore_path)
            action = (
                "to ignore every file inside the directory"
                if ignore_path
                else "to suppress the findings in every file inside the directory"
            )
        else:
            spelling = shown_rest
            action = "to ignore it" if ignore_path else "to suppress its findings"
        return f"Path '{shown}' {DOT_PREFIX_PROBLEM}. Use '{spelling}' {action}."

    spelled = _case_only_spelling(form, project_root)
    if spelled is not None:
        if read_from_environment:
            return (
                f"Path '{shown}' matches a path in the scanned tree "
                f"{CASE_ONLY_PROBLEM}."
            )
        return f"Path '{shown}' matches '{spelled}' {CASE_ONLY_PROBLEM}."

    # An ignore path ending in / names the directory and what is in it.
    if ignore_path and form.endswith("/"):
        return None
    clean_path = form.rstrip("/")
    # A glob in the last component matches files.
    from pathlib import PurePosixPath

    basename = PurePosixPath(clean_path).name
    if any(character in basename for character in _GLOB_CHARACTERS):
        return None
    if "**" in form:
        # '**' matches any run of directories, and the last component then
        # names a path exactly: '**/node_modules' is a file of that name, and
        # the files inside a directory of that name do not match. Advised only
        # for a directory the tree holds somewhere, by a bounded walk.
        if basename != "**" and _names_a_directory_below(basename, project_root):
            return directory_path_advice(shown, ignore_path=ignore_path)
        return None
    if _names_a_directory(project_root / clean_path):
        return directory_path_advice(shown, ignore_path=ignore_path)
    return None


#: What a message ``path_pattern_advice`` returns says after the path it names.
_PATH_ADVICE_PROBLEMS = (
    "matches no path. Name the paths ",
    f"{DOT_PREFIX_PROBLEM}. ",
    f"{CASE_ONLY_PROBLEM}.",
    f"{DIRECTORY_PATH_PROBLEM}. ",
)


def is_path_pattern_advice(message: str) -> bool:
    """Whether ``message`` is one ``path_pattern_advice`` returns.

    ``validate_config_file`` lists that advice with its errors, and ``ash config
    validate`` prints it as a warning; ``ash config lint`` reports it as one.
    """
    return message.startswith("Path '") and any(
        f" {problem}" in message for problem in _PATH_ADVICE_PROBLEMS
    )


class ConfigValidationError(Exception):
    """Raised when configuration validation fails."""


@dataclass
class ConfigCheck:
    """What ``ConfigValidator.check_config_file`` found in one config file.

    ``errors`` are the problems that make a scan refuse the config, with exit
    3, before any scanner runs: a file that does not parse, an ``extends``
    chain that does not resolve, a value the AshConfig model refuses, or a
    ``--config-overrides`` entry that cannot be applied. ``warnings`` are the
    problems a scan tolerates: it runs, but ignores or overrides something the
    file says, or the file carries fields only ASH itself should write.
    """

    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    # The files the config was built from, lowest precedence first: the file
    # alone, or its `extends` chain once that resolved. Empty when the file
    # itself could not be read.
    chain: List[Path] = field(default_factory=list)
    # The file does not parse (YAML, JSON, or not UTF-8). A scan refuses it with
    # exit 3, and so does this check: none of the file applies. The parser's
    # message keeps its own lines when it is printed.
    ignored_by_scan: bool = False
    # The file could not be read at all (OSError), one of the ignored_by_scan
    # cases: a printer says read rather than parse, because the syntax was
    # never seen.
    could_not_read: bool = False
    # Values the config read from the environment, for a message that names no
    # field (redact()): a refusal's free text, such as a parser's or an
    # override's. A message about a field quotes it by its place instead
    # (``references``).
    environment_values: List[str] = field(default_factory=list)
    # What the checked file and its chain read from the environment, each at
    # its place (config/environment_record.py): the file's own, as it wrote
    # them, then the chain's, at the place each holds in the merged config. A
    # message quotes ``with_environment_values_shown`` of the data, so a value
    # read from the environment is ``<value>`` in it whatever its length.
    references: List[EnvironmentReference] = field(default_factory=list)
    # The checked file's own references alone, at the place it writes each: for
    # a message about the file's own entries (the linter's).
    file_references: List[EnvironmentReference] = field(default_factory=list)
    # The files of ``chain`` reached through a value read from the environment
    # (ResolvedConfigDocument.environment_paths), named ``<value>``.
    environment_paths: FrozenSet[Path] = frozenset()
    # The merged configuration the checks read, and the same with each value
    # read from the environment shown as ``<value>`` (None when the file did
    # not parse).
    resolved_data: Any = None
    shown_resolved: Any = None
    # The file's own contents as read_config_file returned them, for a caller
    # that reports more about the same file (validate's note on plugin options):
    # reading it again would log each !ENV warning again. None when the file
    # could not be read.
    config_data: Any = None
    # The errors in ``errors`` that are the scan's refusal of the file ASH_CONFIG
    # names, when that is not the file checked: a scan starts from it, so its
    # refusal is one of this check's too, but it is not about the checked file.
    ash_config_errors: List[str] = field(default_factory=list)
    # Each warning in ``warnings`` about an ignore or suppression path, in
    # order, with that path as the merged config holds it, before any value read
    # from the environment is shown. Two paths read from the environment are each
    # ``<value>``, so their warnings can read the same; ``ash config lint`` tells
    # them apart by this (LintIssue.pattern). Never shown.
    path_patterns: List[Tuple[str, str]] = field(default_factory=list, repr=False)
    # What the check read of the chain, held for a judgment of the same files
    # that reads nothing a second time (the MCP runtime-override policy): each
    # file's document as it was parsed, before its ``extends`` and ``patch``
    # were applied (``ResolvedConfigDocument.documents``); the paths each file
    # was reached by (``ResolvedConfigDocument.names``); and each file's text
    # (``texts``), for a judgment that reads the text and not the parse (a read
    # of the environment). All by resolved path, and empty when the chain did
    # not resolve: a refused chain has nothing to judge, and the check's errors
    # say why. Never shown.
    documents: Dict[Path, Any] = field(default_factory=dict, repr=False, compare=False)
    document_names: Dict[Path, Tuple[Path, ...]] = field(
        default_factory=dict, repr=False, compare=False
    )
    texts: Dict[Path, str] = field(default_factory=dict, repr=False, compare=False)

    @property
    def scan_accepts(self) -> bool:
        return not self.errors

    def redact(self, text: str) -> str:
        return redact_values(text, self.environment_values)

    def shown_path(self, path: Path) -> str:
        """How a message names ``path``, a file of ``chain``: ``<value>`` when
        the environment chose it, else as ``describe_config_path`` does."""
        if Path(path) in self.environment_paths:
            return ENVIRONMENT_VALUE_SHOWN
        return describe_config_path(Path(path))


# What a check prints in place of a value: one the file holds, or one it read
# from the environment. Messages are printed to CI logs and, through the MCP
# validate_config tool, sent to a client, so no value is repeated, whatever
# its source.
REDACTED = "<value>"


# How free text hides a value, by the length of the form a message prints it in
# (redact_values), in any case. A form shorter than MIN_REDACTED_LENGTH is
# replaced only where the text quotes it whole ('x', "x" or `x`), the way a
# repr-printed input or an override's text shows it. One of MIN_REDACTED_LENGTH
# up to MIN_ANYWHERE_LENGTH characters, all letters, digits and "_", is replaced
# as a whole word, so the "true" in "untrue" stays. By default "_" bounds a
# word like any other non-alphanumeric character, so the value in
# "<value>_findings" is hidden; only the test-report backstop's entry point
# (_redact_for_test_reports) treats "_" as a word character, keeping the
# "runner" in "test_uv_tool_runner" readable there (a CI host's USER). The
# edge of another value's match still bounds
# a word. One of MIN_ANYWHERE_LENGTH or more, or
# of MIN_REDACTED_LENGTH or more holding any other character ("/src"), is
# replaced anywhere, inside a longer word too (a short finite number of this
# band is bounded instead: hidden inside words, never inside a longer number;
# see number_bounded_form), and so is a piece of it, of
# MIN_ANYWHERE_LENGTH or more, where it touches the "..." or "…" a message cuts
# it at. Replacing every whole-word "a" or "on" (a one-letter project name, a
# short tag), or a common word inside longer ones, cut words out of every message
# ("<value> scan ignores it"). See the CHANGELOG. The two lengths live in
# utils.numeric_text with the shared number predicates (every surface that
# redacts a numeric value reads one boundary) and are re-exported here.


class ModuleFormNeedle(str):
    """A needle derived from a masked module path, not an environment value
    itself (plugins.loader._masked_module_forms builds these).

    The text is the form, so every str-typed carrier -- value_tuple, the
    values an error carries, a tuple a model stores -- transports it
    unchanged, and a consumer that sees only the str treats it exactly as
    the plain literal it replaces. The two extras REFINE what the literal
    already does; stripped back to str by a transform that rebuilds
    strings, behavior degrades to the literal's, never past it:

    - ``frame_exempt``: inside a traceback frame line of ASH's or the
      import machinery's own files -- after the quoted path, through the
      source line printed under it (_ash_frame_regions) -- the form keeps
      the frame's text readable. A masked segment spelled like the
      machinery's own vocabulary ("import_module", "exec_module") otherwise
      blanks frame text that is the same for every failing load, and the
      blanking itself tells a reader what the segment is called. The
      quoted path is never exempt: a plugin under ASH's opt-in root puts
      the masked leaf inside an automated_security_helper path. The
      exemption is dropped for a form a PLAIN value also yields
      (_replace_values subtracts those), so an environment value never
      loses redaction to it.
    - ``pattern``: a compiled alternative-spelling pattern matched in
      addition to the literal forms. The distribution needle carries one:
      PEP 503 treats every run of "-", "_" and "." as one separator, so
      the canonical literal alone left every other separator spelling
      readable ("Segtop.Ash_Plugins" beside the needle
      "segtop-ash-plugins").
    - ``whole_component``: the form is matched only as a whole component,
      with no ASCII letter, digit or "_" beside either end of it. A form
      derived from a masked module name (a dotted parent, an inner segment, a
      path or file spelling) is hidden where a text names it, and a longer
      module name that merely holds it ("<parent>_extras") stays readable;
      ".", "/", "\\" and quotes bound a component. The entry's own name does
      not rest on this flag: a load and a registry read also pass it as a
      plain value (plugins.loader.masked_module_scope), which hides it inside
      a longer name too. The bound holds for every length: the
      anywhere band, the four- to seven-character band, a form past
      _LONG_FORM_LENGTH, and the separator variants a ``pattern`` carries
      (the loader builds those with whole_component_regex). A form shorter
      than MIN_REDACTED_LENGTH keeps its quoted-only treatment. A form a
      PLAIN value also yields keeps the strict treatment
      (_replace_values subtracts those), so an environment value never
      loses redaction to it.
    """

    # Built by plain construction plus slot assignment (make_module_form_needle
    # below), never a custom constructor: the shown-text sweep allows the
    # terminal escaper alone to touch low-level string construction, and a
    # needle is redaction INPUT, not display output, so it has no business
    # near that machinery. The consumers read the slots with getattr and a
    # default, so an instance that somehow misses an assignment behaves as
    # the plain literal.

    frame_exempt: bool
    pattern: Optional[Pattern[str]]
    whole_component: bool
    __slots__ = ("frame_exempt", "pattern", "whole_component")

    def __getnewargs__(self) -> Tuple[str]:
        # Pickle and deepcopy rebuild from the text, and the slot attributes
        # ride along in the state dict. Without this, copying a tuple that
        # carries a needle raises instead of copying.
        return (str(self),)


def make_module_form_needle(
    form: str,
    *,
    frame_exempt: bool = False,
    pattern: Optional[Pattern[str]] = None,
    whole_component: bool = False,
) -> ModuleFormNeedle:
    """A :class:`ModuleFormNeedle` with its three slots set.

    Plain construction, then assignment: see the note in the class body for
    why the class defines no constructor of its own.
    """
    needle = ModuleFormNeedle(form)
    needle.frame_exempt = frame_exempt
    needle.pattern = pattern
    needle.whole_component = whole_component
    return needle


class CaseInsensitiveNeedle(str):
    """A value matched ignoring case inside a redact_values call whose other
    values are matched as written (``whole_words`` without ``ignore_case``).

    The text is the value, so every str-typed holder transports it unchanged
    and a consumer that sees only the str treats it as the plain value. The one
    extra REFINES the literal treatment: ``ignore_case`` widens the match of
    this value's forms to any case, where the call's own flags would match
    them as written. Stripped back to str by a transform that rebuilds strings,
    behavior degrades to the literal's, never past it.

    Built for ``redact_refused_input``: the inputs a validator's own message
    quotes are matched ignoring case (a validator upper-cases its input), the
    inputs pydantic's own messages quote only as written (such a message lists
    the values a field accepts, which an ignore-case match would take out).
    Before this needle the two sets were replaced in two passes, and two
    overlapping values, one in each set, left part of a value behind, the
    defect ``redact_values`` closes for ONE pass ("foo/bar" and "bar/baz-long"
    in "foo/bar/baz-long"). With the needle both sets go through one pass.

    A module-form needle (ModuleFormNeedle) is never case-insensitive, and this
    needle carries none of its slots: a value that needs both treatments has
    no caller today, and _replace_values reads each needle's own slots alone.
    """

    # Plain construction plus slot assignment (make_case_insensitive_needle
    # below), never a custom constructor, for the reason ModuleFormNeedle gives.
    ignore_case: bool
    __slots__ = ("ignore_case",)

    def __getnewargs__(self) -> Tuple[str]:
        # Pickle and deepcopy rebuild from the text; the slot rides along in
        # the state dict.
        return (str(self),)


def make_case_insensitive_needle(value: str) -> CaseInsensitiveNeedle:
    """A :class:`CaseInsensitiveNeedle` for *value*, matched ignoring case."""
    needle = CaseInsensitiveNeedle(value)
    needle.ignore_case = True
    return needle


#: The look-arounds that keep a form to whole components: no ASCII letter,
#: digit or "_" beside it. ASCII on purpose: a module name is an identifier,
#: and a neighbor outside that set (".", "/", "\\", a quote, a space, a
#: non-ASCII letter) ends the name, so the form beside it is hidden. The class
#: turns the case-insensitive flag off (``(?-i:...)``): the patterns are
#: compiled with it, and under it the class would also match the characters
#: that fold onto an ASCII letter (the Kelvin sign, the long s, the dotless i
#: and the dotted capital I), which are not ASCII and do not glue a name.
_COMPONENT_BEFORE = r"(?<!(?-i:[A-Za-z0-9_]))"
_COMPONENT_AFTER = r"(?!(?-i:[A-Za-z0-9_]))"


def whole_component_regex(body: str) -> Pattern[str]:
    """*body* as a case-insensitive pattern matched only as a whole component.

    For the separator variants a :class:`ModuleFormNeedle` carries, so a
    variant is bounded as its literal forms are (``whole_component``).
    """
    return re.compile(f"{_COMPONENT_BEFORE}{body}{_COMPONENT_AFTER}", re.IGNORECASE)


def _is_component_character(character: str) -> bool:
    """Whether *character* is inside a module name's component: an ASCII
    letter, an ASCII digit or "_"."""
    return character.isascii() and (character.isalnum() or character == "_")


def _component_pattern(form: str) -> str:
    """The pattern text of *form* matched only as a whole component.

    A bound is added at an end of the form that is a component character, as
    ``_replace_values`` bounds a whole word: a form starting with "/" is
    matched after any character.
    """
    before = _COMPONENT_BEFORE if _is_component_character(form[0]) else ""
    after = _COMPONENT_AFTER if _is_component_character(form[-1]) else ""
    return f"{before}{re.escape(form)}{after}"


def _printed_forms(value: str) -> set:
    """The ways a message can print ``value``.

    As it is, as repr() prints it inside its quotes (a validator writes
    ``{v!r}``, which escapes a backslash and a non-printable character), as
    ``unicode_escape`` writes it, and as JSON escapes it. As a URL prints it
    too: a library that formats a request URL into its error (an SDK naming
    the endpoint it called) percent-encodes the value in a path segment, in a
    path, or in a query, so a model id's ":" prints as "%3A". A value with no
    character a URL encodes adds no form. As a joined command line prints it
    too: the command records join their arguments with ``shlex.join``, which
    respells a piece the shell would re-split or misread as several quoted
    segments, so a value whose space-separated pieces stand as arguments is
    matched in that quoted spelling as well; one no piece of which needs
    quoting adds no form. A value ending in "/" is matched
    without the slashes, which covers it with them too and leaves them
    printed: the directory-path warning suggests
    `<path without its trailing "/">/**`, and matching the value with its
    slash took the slash of `/**` into the marker ("Use '<value>**'").
    A value holding "\\r\\n" or "\\r" also matches with those rewritten to
    "\\n": a child read in text mode comes back through universal newlines,
    which respell the value that way before any sink sees the text.
    """
    from urllib.parse import quote, quote_plus

    without_slashes = value.rstrip("/")
    if without_slashes != value and len(without_slashes) >= MIN_REDACTED_LENGTH:
        return _printed_forms(without_slashes)
    quoted = repr(value)
    body = quoted[1:-1]
    if quoted[0] == "'":
        # repr escapes the quote it chose; the quote-free body below carries
        # only the backslash and non-printable escaping, so each quote kind
        # can be escaped once, never twice.
        body = body.replace("\\'", "'")
    forms = {
        value,
        body,
        # The value as repr prints it inside a LONGER string: a text that
        # holds both quote kinds is single-quoted with the single quote
        # escaped (attribute {text!r} shows a value's "'" as "\'"). repr
        # never escapes a double quote -- it picks single quotes instead --
        # and JSON's escaped double quote is the json.dumps form below.
        body.replace("'", "\\'"),
        value.encode("unicode_escape").decode("ascii"),
        json.dumps(value)[1:-1],
        # JSON with ensure_ascii=False: a writer that keeps non-ASCII raw (an
        # HTTP body echoed into an error, say) still escapes the double quote
        # and the backslash, a combination the default json.dumps form (which
        # escapes non-ASCII as \uXXXX) and the repr body (which never escapes
        # a double quote) do not spell. For a pure-ASCII value the two JSON
        # forms are the same string, and the set keeps one.
        json.dumps(value, ensure_ascii=False)[1:-1],
    }
    respelled = shlex.join(value.split(" "))
    if respelled != value:
        # As a joined command line prints it: the command records join their
        # arguments with shlex.join, which respells an argument the shell
        # would re-split or misread (one holding a quote, say) as several
        # quoted segments. A value whose space-separated pieces stand as
        # arguments appears in that line only in this spelling, so it has to
        # match in it too. A value no piece of which needs quoting respells
        # to itself and adds no form.
        forms.add(respelled)
    try:
        forms |= {quote(value, safe=""), quote(value, safe="/"), quote_plus(value)}
    except UnicodeEncodeError:
        # A lone surrogate (a name that is not UTF-8) has no URL spelling:
        # quote() encodes UTF-8 strictly, as a library that formats the value
        # into a URL does, so no message prints one. The forms above still
        # match the value.
        pass
    newline_normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    if newline_normalized != value:
        # A child read in text mode comes back through universal newlines,
        # which rewrite the value's "\r\n" and "\r" to "\n" before any sink
        # sees the text, so the rewritten spelling has to match too, with
        # its own escaped and URL forms. It holds no CR, so this ends here;
        # the consumer's per-form length bands gate a shortened spelling.
        forms |= _printed_forms(newline_normalized)
    # Imported here, as error_text defers its own config imports: the config
    # package loads before utils may import it back at module level.
    from automated_security_helper.utils.error_text import ESCAPE_CODES

    escape_stripped = ESCAPE_CODES.sub("", value)
    if escape_stripped and escape_stripped != value:
        # The shown layers strip every complete CSI or OSC sequence from a
        # tool's text before matching, so a value that itself holds such a
        # code appears there in its stripped spelling; without that form the
        # strip re-splits the match it exists to protect. One strip can
        # leave a code behind when one sequence's bytes interleave another,
        # but the shown layers strip their text the same single way, so the
        # one-strip spelling is the one they can show, and this ends here.
        # A value made only of codes strips to the empty string, whose
        # printed forms are the quoted empty strings every message may
        # legitimately hold, so an empty stripped spelling adds nothing.
        forms |= _printed_forms(escape_stripped)
    return forms


def printed_forms(value: str) -> set:
    """The public name importers use for a value's printable spellings: the
    read-edge trim (plugin_base.trimmed_at_read_edge) matches the SAME set the
    sinks here match, or a cut inside a printed spelling leaves a piece the
    trim does not see and the sinks cannot match. A def, not an alias bound at
    import time, so a caller and a test that replaces ``_printed_forms`` see
    the same function the sinks run."""
    return _printed_forms(value)


# What redact_values and environment_record.environment_marker put in, and so
# never match inside: REDACTED, and `<from ${VAR}>`.
_MARKER_PATTERN = re.compile(re.escape(REDACTED) + r"|<from [^<>]*>")

#: REDACTED alone, for a caller whose text holds no environment marker of
#: ASH's: there a value shaped `<from X>` is the text's own, and is hidden.
REDACTED_MARKERS = re.compile(re.escape(REDACTED))


#: The words a float prints for a non-finite number, signed forms included.
#: "-inf" is MIN_REDACTED_LENGTH characters with a non-word character, the
#: shape otherwise replaced anywhere -- which eats "--info" and
#: "non-inference". The word identifies nothing inside another word, so these
#: forms are matched as whole words instead: standing alone or quoted they
#: still redact (tests/unit/base's non-finite cells), and a word character
#: FOLLOWING the match keeps the text ("--info", "non-inference"). The
#: leading "-" bounds itself, so text running into it from the left
#: ("non-inf bound", "range 0-inf") is still replaced.
_NON_FINITE_FORMS = frozenset({"inf", "-inf", "+inf", "nan", "-nan", "+nan"})


# The shared number-boundary predicate (utils.numeric_text): a short numeric
# print is matched only at a number boundary. The non-finite words never
# reach the anywhere band here (_NON_FINITE_FORMS routes them to whole-word).
_number_bounded_form = number_bounded_form


def _is_anywhere_form(form: str) -> bool:
    """Whether a printed form is replaced anywhere, inside a longer word too:
    MIN_ANYWHERE_LENGTH characters or more, or MIN_REDACTED_LENGTH or more
    holding a character other than a letter, a digit or "_". A short finite
    number of the band is still an anywhere form, but bounded: hidden inside
    words and never inside a longer number (number_bounded_form). A
    non-finite float's word (_NON_FINITE_FORMS) is never one: it is matched
    as a whole word, whatever its punctuation."""
    if form.casefold() in _NON_FINITE_FORMS:
        return False
    return len(form) >= MIN_ANYWHERE_LENGTH or (
        len(form) >= MIN_REDACTED_LENGTH and re.search(r"\W", form) is not None
    )


def _folded(text: str) -> str:
    """*text* lower-cased one character at a time, keeping its length, so an
    index into it is an index into *text*. A character whose lower case is longer
    (U+0130) is kept as it is. An ASCII text is lowered in one call: no ASCII
    character has a longer lower case, or one that depends on its neighbors as a
    final sigma's does, so that is the text the fold one at a time gives."""
    if text.isascii():
        return text.lower()
    return "".join(c if len(c.lower()) != 1 else c.lower() for c in text)


def _is_word_character(character: str) -> bool:
    return re.match(r"\w", character) is not None


def _bounds_report(character: str) -> bool:
    """Whether *character*, beside a match's end, bounds a word UNDER THE
    TEST-REPORT RULE (``_redact_for_test_reports``, the entry point only the
    test-report backstop uses -- never the product default): anything that is
    not a word character. "_" is a word character here, as it is to Python's own word
    boundary and to the match's own end character (``_is_word_character``),
    so a value glued to a word by "_" (``test_uv_tool_runner`` under
    ``USER=runner``) is not a whole word and stays printed in a test report.
    Under that rule the whole-word fixed point uses this predicate for every
    candidate's neighbor (``_whole_word_spans``), looking past a "_" neighbor
    -- and a whole run of them, which bounds only against the text's edge or
    a covered character -- where what lies past is covered, is the text's
    edge, or (for a single "_") bounds a word itself; a "_" of the run that
    another match covers closes the side as the covered character would
    (``needed``). The DEFAULT rule, and a long cut piece's own far side
    under either rule, use ``_bounds_strict``."""
    return not _is_word_character(character)


def _bounds_strict(character: str) -> bool:
    """Whether *character* bounds a word under the DEFAULT rule, and a long
    cut piece's far side under either rule: anything that is not a letter or
    a digit, "_" included. So by default a value glued into a longer name by
    "_" (``<value>_findings``) IS a whole word and is hidden -- the product's
    fail-closed band. A cut piece is MIN_ANYWHERE_LENGTH characters or more
    of a long value's own print beside a marker, so one glued to a word by
    "_" (``ASH_<the value's first 12 characters>...``) is a real cut of the
    value, not a word that happens to match -- the common-word mangling this
    rule accepts lives in the four- to seven-character bands, whose far sides
    go through ``_bounds_report`` only under the test-report rule. A piece
    this says is not bounded has an alphanumeric neighbor, which the report
    rule does not bound either, so the fixed point never re-judges a piece's
    "_" neighbor the other way."""
    return not character.isalnum()


def _z_array(joined: str) -> List[int]:
    """The Z-array of *joined*: at each index, the length of the longest common
    prefix of *joined* and its suffix there, in time linear in the length."""
    length = len(joined)
    z = [0] * length
    if length:
        z[0] = length
    left = right = 0
    for i in range(1, length):
        if i < right:
            z[i] = min(right - i, z[i - left])
        while i + z[i] < length and joined[z[i]] == joined[i + z[i]]:
            z[i] += 1
        if i + z[i] > right:
            left, right = i, i + z[i]
    return z


def _match_lengths(folded_text: str, folded_form: str, forward: bool) -> List[int]:
    """How many characters of *folded_form*'s start match *folded_text* at each
    index (``forward``), or of its end match up to each index (so the entry at
    ``i`` is the longest ``m`` with ``folded_text[i - m:i] == folded_form[-m:]``,
    and the list is one longer than the text). One Z-function over
    form + "\\0" + text, so a value of any length costs time linear in the
    text's and the form's lengths, not a search at every index."""
    if forward:
        z = _z_array(folded_form + "\0" + folded_text)
        offset = len(folded_form) + 1
        bound = len(folded_form)
        return [min(z[offset + i], bound) for i in range(len(folded_text))]
    z = _z_array(folded_form[::-1] + "\0" + folded_text[::-1])
    offset = len(folded_form) + 1
    bound = len(folded_form)
    length = len(folded_text)
    return [min(z[offset + length - i], bound) if i else 0 for i in range(length + 1)]


#: A form longer than this is found by _long_form_spans rather than in the one
#: pattern. The pattern tries each form at every position, and ignoring case re
#: compares a form a character at a time, so a long form over a long run of its
#: own letters cost time in the square of the run (100000 characters, 8 s).
_LONG_FORM_LENGTH = 64


def _case_key(character: str) -> str:
    """A key that two characters re matches to each other ignoring case always
    share: the first character of the lower case, of its upper case, and of
    that one's lower case. "ſ" and "s" share "s", the Kelvin sign and "k" share
    "k", "İ" and "i" share "i". Characters that share a key need not match."""
    lower = character.lower()[:1]
    upper = lower.upper()[:1]
    return upper.lower()[:1]


def _case_classes(characters: Set[str], flags: int) -> Dict[int, str]:
    """A str.translate table that maps each of *characters* to one member of the
    characters re matches it to under *flags*, so two strings of the same
    length compare equal after it exactly where a pattern of one matches the
    other. Empty when *flags* does not ignore case. re itself decides each
    match, and only characters that share a key (_case_key) are compared."""
    table: Dict[int, str] = {}
    if not flags & re.IGNORECASE:
        return table
    classes: Dict[str, List[str]] = {}
    for character in sorted(characters):
        members = classes.setdefault(_case_key(character), [])
        for member in members:
            if re.fullmatch(re.escape(member), character, flags):
                table[ord(character)] = member
                break
        else:
            members.append(character)
    return table


def _long_form_spans(
    text: str,
    long_forms: List[str],
    flags: int,
    whole_words: bool,
    component: bool = False,
) -> List[Tuple[int, int]]:
    """Each place one of *long_forms* occurs in *text*, as the pattern of it
    finds them under *flags*, overlapping places included; with
    *whole_words*, only where no word character is beside an end of the form
    that is one; with *component*, only where no ASCII letter, digit or "_"
    is beside an end of the form that is one (``_component_pattern``). Each
    form costs time linear in the text, with the text and
    the form mapped to their case classes (_case_classes): a form whose places
    can be closer than half its length apart, one that repeats a part shorter
    than that (_repeats_closely), takes the match lengths at every position;
    any other is searched for from each place it occurs to the next, and its
    places, at least half its length apart, cost the search no more than
    twice the text."""
    spans: List[Tuple[int, int]] = []
    if not long_forms:
        return spans
    inside = _is_component_character if component else _is_word_character
    table = _case_classes(set(text).union(*long_forms), flags)
    keyed_text = text.translate(table)
    for form in long_forms:
        keyed_form = form.translate(table)
        first = keyed_text.find(keyed_form)
        if first == -1:
            continue
        length = len(form)
        if _repeats_closely(keyed_form):
            offset = length + 1
            z = _z_array(keyed_form + "\0" + keyed_text)
            places: Iterable[int] = (
                at
                for at in range(first, len(text) - length + 1)
                if z[offset + at] >= length
            )
        else:
            places = _places(keyed_text, keyed_form, first)
        bounded = whole_words or component
        word_first = bounded and inside(form[0])
        word_last = bounded and inside(form[-1])
        for at in places:
            end = at + length
            if word_first and at > 0 and inside(text[at - 1]):
                continue
            if word_last and end < len(text) and inside(text[end]):
                continue
            spans.append((at, end))
    return spans


def _repeats_closely(form: str) -> bool:
    """Whether *form* is its own shorter part repeated, at a period under half
    its length, so two of its places in a text can overlap by more than half."""
    z = _z_array(form)
    return any(z[period] >= len(form) - period for period in range(1, len(form) // 2))


def _places(text: str, form: str, first: int) -> Iterable[int]:
    """Every index of *form* in *text* from *first*, overlapping ones included."""
    at = first
    while at != -1:
        yield at
        at = text.find(form, at + 1)


def _cut_pieces(
    text: str, folded_text: str, form: str, cut_starts: List[int], cut_ends: List[int]
) -> List[Tuple[int, int, bool, bool]]:
    """Every piece of *form* that touches a marker, as
    ``(start, end, far_ok, head)``: a start of the form, MIN_ANYWHERE_LENGTH
    characters or more, ending where a "..." or "…" begins (``head``), or an
    end of it, as long, beginning where one ends. ``far_ok`` says the piece's
    far side is already a word boundary: the text's edge, or, where the form's
    own character there is a letter, a digit or "_", a neighbor that bounds a
    piece (``_bounds_strict``, where "_" still bounds: a piece this long
    beside "_" is a real cut of the value, not a word that happens to
    match). The pieces are found with string comparisons rather than a
    pattern, so no limit of the regex parser applies to how long the value is.

    *cut_starts* and *cut_ends* are the sorted positions where a marker starts
    and ends. The match lengths of a direction are computed only when the
    form's start (or end) occurs in the text at all, so a value the text never
    prints costs two searches, not two passes over the text."""
    pieces: List[Tuple[int, int, bool, bool]] = []
    if len(form) <= MIN_ANYWHERE_LENGTH or not cut_starts:
        return pieces
    folded_form = _folded(form)
    head = folded_form[:MIN_ANYWHERE_LENGTH]
    tail = folded_form[-MIN_ANYWHERE_LENGTH:]
    word_first = _is_word_character(form[0])
    word_last = _is_word_character(form[-1])
    at = folded_text.find(head)
    if at != -1:
        forward = _match_lengths(folded_text, folded_form, True)
    while at != -1:
        matched = forward[at]
        # The last marker that starts inside the matched start, at its piece's end.
        index = bisect.bisect_right(cut_starts, at + matched) - 1
        if index >= 0 and cut_starts[index] >= at + MIN_ANYWHERE_LENGTH:
            far_ok = not word_first or at == 0 or _bounds_strict(text[at - 1])
            pieces.append((at, cut_starts[index], far_ok, True))
        at = folded_text.find(head, at + 1)
    at = folded_text.find(tail)
    if at != -1:
        backward = _match_lengths(folded_text, folded_form, False)
    while at != -1:
        end = at + MIN_ANYWHERE_LENGTH
        matched = backward[end]
        # The first marker that ends inside the matched end, at its piece's start.
        index = bisect.bisect_left(cut_ends, end - matched)
        if index < len(cut_ends) and cut_ends[index] <= end - MIN_ANYWHERE_LENGTH:
            far_ok = not word_last or end == len(text) or _bounds_strict(text[end])
            pieces.append((cut_ends[index], end, far_ok, False))
        at = folded_text.find(tail, at + 1)
    return pieces


#: Listed characters up to which _cut_windows builds its prefilter set. The set
#: costs 81-121 bytes a listed character, depending on the characters
#: (measured at the cap), so this bounds it at 20-30 MiB. Past it, each window
#: is searched for in the values.
_PREFILTER_LISTED_CHARACTERS = 1 << 18

#: Distinct windows a message pays one direct search for before _cut_windows
#: builds the prefilter set. One search is one C-level find in the joined
#: forms, well under a millisecond; the set is tens of milliseconds and
#: 20-30 MiB at the cap, so it pays only with hundreds of distinct windows,
#: the many-windows shape rather than a message that lists two truncated
#: inputs. 32 is not that break-even point: it bounds the searches a
#: many-windows message spends before the set is built, a few milliseconds at
#: most, while a message with a window or two never builds it. The set is a
#: necessary condition only, so where the gate puts the build changes no
#: window's answer.
_PREFILTER_AFTER_SEARCHES = 32


def _window_prefilter(folded_forms: List[Tuple[str, str]]) -> Optional[Set[str]]:
    """Every MIN_ANYWHERE_LENGTH-character run of the folded forms, which a
    window a form holds has to start with, or None when the forms hold more than
    _PREFILTER_LISTED_CHARACTERS characters. The set is only a necessary
    condition, so leaving it out changes no window's answer, only its cost."""
    listed = sum(len(folded_form) for _, folded_form in folded_forms)
    if listed > _PREFILTER_LISTED_CHARACTERS:
        return None
    return {
        folded_form[i : i + MIN_ANYWHERE_LENGTH]
        for _, folded_form in folded_forms
        for i in range(len(folded_form) - MIN_ANYWHERE_LENGTH + 1)
    }


def _cut_windows(
    folded_text: str,
    folded_forms: List[Tuple[str, str]],
    cut_starts: List[int],
    cut_ends: List[int],
) -> List[Tuple[int, int, str]]:
    """Every part of a form a message prints with both of its ends cut, as
    ``(start, end, form)``: the text from where a "..." or "…" ends to where the
    next one begins, MIN_ANYWHERE_LENGTH characters or more, when a form holds
    it. Both its sides are a marker's own character, which bounds a word, so it
    is hidden wherever it is, as a cut piece bounded on its far side is.
    *folded_forms* pairs each form, longest first, with its folded copy, and the
    first form that holds the window labels it.

    A window a form holds starts with MIN_ANYWHERE_LENGTH characters the form
    holds, so a set of every such run of the forms (_window_prefilter) answers
    most windows in one lookup. The set is built once, and only after the
    message's distinct windows have cost _PREFILTER_AFTER_SEARCHES direct
    searches: a normal message with a window or two is cheaper answered by the
    searches alone than by building the set. It is built only while the forms
    hold at most _PREFILTER_LISTED_CHARACTERS characters; past that every
    window goes to the search, as it would if the set let it by. A window that
    passes costs one search of the forms joined around a separator none of
    them holds, rather than a scan of every form: the first place a window
    occurs lies inside the first form that holds it, since a window without
    the separator cannot reach across one. A window holding the
    separator is in no form and is left without a search. In the odd case of a
    form holding the separator, such a window scans the forms one by one, as
    before. Each distinct window is answered once (*held*)."""
    windows: List[Tuple[int, int, str]] = []
    if not folded_forms:
        return windows
    separator = "\0"
    joined = None
    if all(separator not in folded_form for _, folded_form in folded_forms):
        joined = separator.join(folded_form for _, folded_form in folded_forms)
        form_starts = []
        offset = 0
        for _, folded_form in folded_forms:
            form_starts.append(offset)
            offset += len(folded_form) + 1
    starts_held: Optional[Set[str]] = None
    prefilter_looked_at = False
    searched = 0
    held: Dict[str, Optional[str]] = {}
    for after_marker in cut_ends:
        index = bisect.bisect_left(cut_starts, after_marker)
        if index == len(cut_starts):
            continue
        next_marker = cut_starts[index]
        if next_marker - after_marker < MIN_ANYWHERE_LENGTH:
            continue
        window = folded_text[after_marker:next_marker]
        if window in held:
            form = held[window]
        else:
            if not prefilter_looked_at and searched >= _PREFILTER_AFTER_SEARCHES:
                starts_held = _window_prefilter(folded_forms)
                prefilter_looked_at = True
            if (
                starts_held is not None
                and window[:MIN_ANYWHERE_LENGTH] not in starts_held
            ):
                form = None
            else:
                searched += 1
                if joined is not None:
                    at = -1 if separator in window else joined.find(window)
                    form = (
                        None
                        if at == -1
                        else folded_forms[bisect.bisect_right(form_starts, at) - 1][0]
                    )
                else:
                    form = next(
                        (f for f, folded in folded_forms if window in folded), None
                    )
            held[window] = form
        if form is not None:
            windows.append((after_marker, next_marker, form))
    return windows


def _short_cut_pieces(
    folded_text: str,
    folded_forms: List[Tuple[str, str]],
    cut_starts: List[int],
    cut_ends: List[int],
) -> List[Tuple[int, int, str]]:
    """Every piece of MIN_REDACTED_LENGTH up to MIN_ANYWHERE_LENGTH characters
    a cut leaves of a form, as ``(start, end, form)``: a start of the form
    ending where a "..." or "…" begins, or an end of it beginning where one
    ends. A message that cuts two values printed back to back can leave as
    little as that of one beside the other. Alone such a piece could be any
    word, so it is hidden only in a run of MIN_ANYWHERE_LENGTH characters or
    more (_whole_word_spans). *folded_forms* pairs each form, longest first,
    with its folded copy, and the first form a piece starts or ends labels it.
    Each marker costs a lookup per length, whatever the forms."""
    lengths = range(MIN_REDACTED_LENGTH, MIN_ANYWHERE_LENGTH)
    starts: Dict[str, str] = {}
    ends: Dict[str, str] = {}
    for form, folded_form in folded_forms:
        for length in lengths:
            if len(folded_form) > length:
                starts.setdefault(folded_form[:length], form)
                ends.setdefault(folded_form[-length:], form)
    pieces: List[Tuple[int, int, str]] = []
    for marker in cut_starts:
        for length in lengths:
            if length <= marker:
                started = starts.get(folded_text[marker - length : marker])
                if started is not None:
                    pieces.append((marker - length, marker, started))
    for marker in cut_ends:
        for length in lengths:
            if marker + length <= len(folded_text):
                ended = ends.get(folded_text[marker : marker + length])
                if ended is not None:
                    pieces.append((marker, marker + length, ended))
    return pieces


def _edge_index(spans: Iterable[Tuple[int, int]]) -> Tuple[List[int], List[int]]:
    """*spans* as sorted starts with a running maximum of their ends, for the
    stabbing checks below."""
    ordered = sorted(spans)
    starts = [start for start, _ in ordered]
    reach: List[int] = []
    for _, end in ordered:
        reach.append(max(reach[-1], end) if reach else end)
    return starts, reach


def _edge_covers(edges: Tuple[List[int], List[int]], before: int, point: int) -> bool:
    """Whether a span of *edges* starting before *before* reaches *point*."""
    starts, reach = edges
    index = bisect.bisect_left(starts, before) - 1
    return index >= 0 and reach[index] >= point


class _StandingReach:
    """The candidates in order of their start, with a max-tree of their ends: it
    answers which standing candidate covers a character, and a candidate that
    falls leaves it. Of those starting at one place the longest comes first,
    so the one found, the last that covers the character, is the shortest:
    tail pieces of a value all start where a marker ends, and each then leans
    on the next longer one rather than all on the longest, which falls first
    and would send every one of them to look again."""

    def __init__(self, candidates: List[Tuple[int, int, str]]) -> None:
        # The leaf order: by start, the longest first among those starting at
        # one place (the class docstring says why).
        self._build(
            candidates,
            sorted(
                range(len(candidates)),
                key=lambda i: (candidates[i][0], -candidates[i][1]),
            ),
        )

    def _build(self, candidates: List[Tuple[int, int, str]], order: List[int]) -> None:
        """The tree over *candidates* with *order* as its leaf order.

        Split from ``__init__`` for callers that need another leaf order: a
        tree rebuilt with another order goes through the same layout, so a
        layout change cannot leave such a rebuild on an outdated one."""
        self.order = order
        self.starts = [candidates[i][0] for i in self.order]
        self.slot = [0] * len(candidates)
        for position, i in enumerate(self.order):
            self.slot[i] = position
        self.size = 1
        while self.size < len(candidates):
            self.size *= 2
        self.reach = [-1] * (2 * self.size)
        for position, i in enumerate(self.order):
            self.reach[self.size + position] = candidates[i][1]
        for node in range(self.size - 1, 0, -1):
            self.reach[node] = max(self.reach[2 * node], self.reach[2 * node + 1])

    def fall(self, i: int) -> None:
        reach = self.reach
        node = self.size + self.slot[i]
        reach[node] = -1
        node //= 2
        while node:
            highest = max(reach[2 * node], reach[2 * node + 1])
            if reach[node] == highest:
                break
            reach[node] = highest
            node //= 2

    def covering(self, point: int) -> int:
        """The standing candidate that covers the character at *point* (starts
        at or before it and ends after it) and starts last, the shortest of
        those starting there, or -1."""
        reach = self.reach
        last = bisect.bisect_right(self.starts, point) - 1
        if last < 0:
            return -1
        node = self.size + last
        if reach[node] > point:
            return self.order[last]
        # Up from that leaf; each left sibling on the way holds the candidates
        # that start just before the ones already looked at.
        while node > 1:
            if node & 1 and reach[node - 1] > point:
                node -= 1
                while node < self.size:
                    right = 2 * node + 1
                    node = right if reach[right] > point else right - 1
                return self.order[node - self.size]
            node //= 2
        return -1


def _whole_word_spans(
    text: str,
    candidates: List[Tuple[int, int, str]],
    fixed: List[Tuple[int, int, str]],
    short: Sequence[int] = (),
    *,
    underscore_joins_words: bool = False,
) -> List[Tuple[int, int, str]]:
    """The candidates that stand as whole words: matches of four- to
    seven-character forms anywhere, and the cut pieces whose far side runs into
    a word (_cut_pieces, _short_cut_pieces). An end of a candidate whose
    character is a letter, a digit or "_" needs, beside it, the text's edge, a
    character that bounds a word, or another match that covers that character.

    By default "_" bounds a word like any other non-alphanumeric character
    (the strict rule, ``_bounds_strict``), so a value glued into a longer
    name by "_" is a whole word and hides. With *underscore_joins_words* (the
    test-report rule; only that backstop passes it) "_" is part of the word,
    as in Python's own word boundary, so the value in ``ASH_x_logs`` is not
    whole and stays -- unless what lies past the "_" is the text's edge,
    bounds a word itself, or is covered, as ``needed`` reads it; a run of two
    or more "_" bounds only against the text's edge or a covered character,
    so two values joined by "__" hide together while ``__main__`` stays
    whole. The covering match is a
    fixed match (an anywhere or quoted form, or a cut piece already bounded),
    or another candidate that stands too. A cut piece's marker side ends beside
    the marker's own character, which bounds a word, so only its far side can
    fail. The candidates that stand are the largest set that holds every one of
    them up, so two values run together ("qz4brk5c"), a value and a cut piece,
    and two cut pieces run together all stand by each other.

    Each edge that needs holding up records one witness: among the positions
    ``needed`` accepts for that edge (the character past a run of "_", or any
    uncovered "_" of the run as the alternatives), the standing candidate covering
    one of them that starts last, found through ``_StandingReach`` in time
    logarithmic in the candidates. A candidate is looked at again only when
    its witness falls, so a chain of matches falls in time bounded by the
    matches rather than by their square, however long the cut pieces in it
    are.

    The candidates *short* indexes, cut pieces under MIN_ANYWHERE_LENGTH
    characters, also need a run of MIN_ANYWHERE_LENGTH characters or more: the
    standing and fixed matches that overlap or touch them, as they are replaced
    together. Those in a shorter run fall, and the matches leaning on them are
    looked at again. A witness touches what leans on it, so those falls stay
    inside the short run, and a second look finds nothing more to drop."""
    if not candidates:
        return []
    count = len(candidates)
    # Fixed spans by start, with a running maximum of their ends: a span
    # reaching a point starts at or before it, so the maximum end over the
    # starts up to the point answers "does any fixed span reach it".
    fixed_edges = _edge_index((start, end) for start, end, _ in fixed)

    bounds = _bounds_report if underscore_joins_words else _bounds_strict

    def joins(character: str) -> bool:
        """Whether the candidate's own edge character can be part of a longer
        word: the complement of the active boundary rule, so a value ending
        in "_" is self-bounded under the strict rule."""
        return not bounds(character)

    def needed(start: int, end: int, left: bool) -> Tuple[int, ...]:
        """The positions beside an end of which another candidate has to cover
        ONE, or an empty tuple when nothing needs to. Under the strict rule
        every non-alphanumeric
        neighbor bounds, "_" included. Under the test-report rule a neighbor
        "_" is looked past: it bounds the word where what lies past it is the
        text's edge, a character that bounds a word itself (space,
        punctuation -- the "_" then glues the value to nothing), or a
        character another match covers, so two values joined by "_" hold each
        other up, while a word character past it keeps the word rule and a CI
        path's ``test_uv_tool_<word>`` stays whole. A run of two or more "_"
        bounds only against the text's edge or a covered character, so
        ``__main__`` stays whole and values joined by "__" hide together.
        A "_" a fixed match covers is marker text, not a joiner: the walk
        stops there and the side closes, as the covered character itself
        would close it. A "_" a STANDING CANDIDATE covers is marker text the
        same way once that candidate hides, so every uncovered "_" the walk
        visited is an alternative witness beside the character past the run:
        a side holds when another match covers any of them, which is how the
        oracle reads it through its mask, where a covered "_" anywhere in
        the run leaves the value's side against masked text.

        Returns the acceptable witness positions, any one of which another
        candidate has to cover, or an empty tuple when nothing needs to."""

        def covered(index: int) -> bool:
            return _edge_covers(fixed_edges, index + 1, index + 1)

        if left:
            if not joins(text[start]) or start == 0:
                return ()
            at = start - 1
            alternatives: Tuple[int, ...] = ()
            if underscore_joins_words and text[at] == "_" and not covered(at):
                underscore_at = at
                run_start = at
                while (
                    run_start > 0
                    and text[run_start - 1] == "_"
                    and not covered(run_start - 1)
                ):
                    run_start -= 1
                if run_start == 0:
                    return ()
                single = run_start == at
                at = run_start - 1
                if single and _bounds_report(text[at]):
                    return ()
                # Every uncovered "_" the walk visited, nearest the value
                # first: a standing candidate covering ANY of them is marker
                # text inside the run, which closes the side, as the oracle's
                # mask reads it.
                alternatives = tuple(range(underscore_at, run_start - 1, -1))
            elif bounds(text[at]):
                return ()
            # A fixed span covering the witness: o_start <= at < o_end.
            if _edge_covers(fixed_edges, at + 1, at + 1):
                return ()
            return (*alternatives, at)
        if not joins(text[end - 1]) or end == len(text):
            return ()
        at = end
        alternatives = ()
        if underscore_joins_words and text[at] == "_" and not covered(at):
            underscore_at = at
            run_end = at
            while (
                run_end + 1 < len(text)
                and text[run_end + 1] == "_"
                and not covered(run_end + 1)
            ):
                run_end += 1
            if run_end + 1 == len(text):
                return ()
            single = run_end == at
            at = run_end + 1
            if single and _bounds_report(text[at]):
                return ()
            # The mirror of the left side: every uncovered "_" of the run,
            # nearest the value first.
            alternatives = tuple(range(underscore_at, run_end + 1))
        elif bounds(text[at]):
            return ()
        if _edge_covers(fixed_edges, at + 1, at + 1):
            return ()
        return (*alternatives, at)

    needs = [
        (needed(start, end, True), needed(start, end, False))
        for start, end, _ in candidates
    ]
    standing = [True] * count
    reach = _StandingReach(candidates)
    witness = [[-1, -1] for _ in range(count)]
    leaning: List[List[Tuple[int, int]]] = [[] for _ in range(count)]
    fallen: deque = deque()

    def held(i: int, side: int) -> bool:
        points = needs[i][side]
        if not points:
            return True
        # A candidate never covers the character beside its own end. Any one
        # of the acceptable positions held by a standing candidate holds the
        # side (any uncovered "_" of the run or the character past it).
        for point in points:
            other = reach.covering(point)
            if other >= 0:
                witness[i][side] = other
                leaning[other].append((i, side))
                return True
        return False

    def fall(i: int) -> None:
        standing[i] = False
        reach.fall(i)
        fallen.append(i)

    def settle() -> None:
        while fallen:
            gone = fallen.popleft()
            for i, side in leaning[gone]:
                if standing[i] and witness[i][side] == gone and not held(i, side):
                    fall(i)
            leaning[gone] = []

    def in_short_runs() -> List[int]:
        """The standing short candidates whose run is under
        MIN_ANYWHERE_LENGTH characters."""
        spans = sorted(
            [(start, end, -1) for start, end, _ in fixed]
            + [(start, end, i) for i, (start, end, _) in enumerate(candidates)]
        )
        dropped: List[int] = []
        run_start, run_end = -1, -1
        members: List[int] = []
        # The last entry, past the text, closes the last run.
        for start, end, i in spans + [(len(text) + 1, len(text) + 1, -1)]:
            if i >= 0 and not standing[i]:
                continue
            if start > run_end:
                if run_end - run_start < MIN_ANYWHERE_LENGTH:
                    dropped.extend(m for m in members if is_short[m])
                run_start, run_end, members = start, end, []
            run_end = max(run_end, end)
            if i >= 0:
                members.append(i)
        return dropped

    for i in range(count):
        if not (held(i, 0) and held(i, 1)):
            fall(i)
    settle()
    is_short = [False] * count
    for i in short:
        is_short[i] = True
    while short:
        dropped = in_short_runs()
        if not dropped:
            break
        for i in dropped:
            fall(i)
        settle()
    return [candidate for i, candidate in enumerate(candidates) if standing[i]]


#: A traceback frame line, anchored at its line's start: frame-shaped text in
#: the middle of a line earns no exemption.
_FRAME_LINE = re.compile(r"(?m)^[ \t]*File \"(?P<path>[^\"\n]*)\", line \d+, in \S")


_PATH_SEPARATORS = re.compile(r"[\\/]+")


def _is_machinery_path(path: str) -> bool:
    """Whether a frame's quoted *path* is importlib's or ASH's own.

    The match is exact: a ``<frozen importlib.`` pseudo-path, or a path with an
    ``importlib`` or ``automated_security_helper`` component. A component that
    merely contains one of those words (``importlib_metadata``, a directory
    named for it) is not the machinery.
    """
    if path.startswith("<frozen importlib."):
        return True
    components = _PATH_SEPARATORS.split(path)
    return "importlib" in components or "automated_security_helper" in components


def _ash_frame_regions(
    text: str,
    needle_forms: Iterable[str] = (),
    needle_patterns: Iterable[Pattern[str]] = (),
) -> List[Tuple[int, int]]:
    """The spans where a frame-exempt needle keeps *text* readable.

    One region per traceback frame line of ASH's or the import machinery's
    own files: from after the quoted path (the path itself is never exempt;
    an opt-in plugin's path holds the masked leaf) through the end of the
    line, and through the source line printed under it. The following line
    joins only when it is indented and not itself a frame line, so a
    third-party frame printed directly under an ASH frame, or the exception
    message line that ends a traceback at column zero, is never sheltered.

    A frame whose quoted path holds any of the needle forms (case-folded) or
    matches a needle pattern has no region, whichever module owns it.
    """
    folded_forms = [form for form in (f.casefold() for f in needle_forms) if form]
    patterns = list(needle_patterns)
    regions: List[Tuple[int, int]] = []
    for match in _FRAME_LINE.finditer(text):
        path = match.group("path")
        if not _is_machinery_path(path):
            continue
        folded_path = path.casefold()
        if any(form in folded_path for form in folded_forms) or any(
            pattern.search(path) for pattern in patterns
        ):
            continue
        start = match.end("path")
        end = text.find("\n", match.end())
        if end == -1:
            regions.append((start, len(text)))
            continue
        if (
            end + 1 < len(text)
            and text[end + 1] in " \t"
            and not _FRAME_LINE.match(text, end + 1)
        ):
            following = text.find("\n", end + 1)
            end = len(text) if following == -1 else following
        regions.append((start, end))
    return regions


def _replace_values(
    text: str,
    labelled: Iterable[Tuple[str, str]],
    render: Callable[[List[str]], str],
    ignore_case: bool = False,
    min_length: int = MIN_REDACTED_LENGTH,
    markers: Pattern[str] = _MARKER_PATTERN,
    whole_words: bool = False,
    *,
    underscore_joins_words: bool = False,
) -> str:
    """``text`` with every occurrence of each value replaced.

    ``labelled`` pairs each value with a label; a run of matches is replaced by
    ``render`` of their labels, the longest match's first. The rules are
    redact_values'.
    """
    forms: Dict[str, str] = {}
    # The forms matched inside a longer word too, and those matched only where
    # the text quotes them whole; the rest are matched as whole words. The band
    # is the form's, as the message prints it: "build/" is matched as "build",
    # five word characters, so "rebuild" keeps its "build".
    anywhere: Set[str] = set()
    quoted_only: Set[str] = set()
    # Module-form needles (ModuleFormNeedle) refine the literal treatment:
    # their forms are exempt inside ASH's and importlib's own frame lines,
    # and a needle can carry a variant pattern matched beside its literal.
    # Read with getattr so a plain str, or a needle a transform stripped
    # back to str, takes the literal treatment exactly as before.
    frame_exempt_sources: Set[str] = set()
    plain_sources: Set[str] = set()
    # Likewise a needle marked whole_component is matched only as a whole
    # component (no ASCII letter, digit or "_" beside it), whatever its
    # length, and a form any other value also yields is matched the strict way.
    component_sources: Set[str] = set()
    other_sources: Set[str] = set()
    # The forms of a value marked ignore_case (CaseInsensitiveNeedle): matched
    # in any case even when the call's own flags match as written. A form
    # such a value shares with a plain value is matched the wider way, as the
    # two passes the needle replaces (redact_refused_input) matched it.
    insensitive_sources: Set[str] = set()
    variant_patterns: List[Tuple[Pattern[str], str, bool]] = []
    for value, label in labelled:
        if not value or (whole_words and len(value) < min_length):
            continue
        value_exempt = bool(getattr(value, "frame_exempt", False))
        value_component = bool(getattr(value, "whole_component", False))
        value_insensitive = bool(getattr(value, "ignore_case", False))
        variant = getattr(value, "pattern", None)
        if variant is not None:
            variant_patterns.append((variant, label, value_exempt))
        for form in _printed_forms(value):
            forms.setdefault(form, label)
            (frame_exempt_sources if value_exempt else plain_sources).add(
                form.casefold()
            )
            (component_sources if value_component else other_sources).add(
                form.casefold()
            )
            if value_insensitive:
                insensitive_sources.add(form.casefold())
            if whole_words:
                continue
            if _is_anywhere_form(form):
                anywhere.add(form)
            elif len(form) < min_length:
                quoted_only.add(form)
    # A form two values share is matched the wider way.
    quoted_only -= anywhere
    # A form a plain value also yields keeps the strict treatment: only
    # module-form needles are ever frame-exempt, never environment values.
    frame_exempt_folded = frame_exempt_sources - plain_sources
    component_folded = component_sources - other_sources
    if not forms:
        return text
    # The component forms: matched where no ASCII letter, digit or "_" is beside
    # them, in one pattern for the forms up to _LONG_FORM_LENGTH and by
    # _long_form_spans past it. One shorter than min_length stays quoted-only,
    # and with whole_words every form is already matched whole.
    component_forms: Set[str] = (
        set()
        if whole_words
        else {
            form
            for form in forms
            if form.casefold() in component_folded and form not in quoted_only
        }
    )
    # A match found ignoring case is labelled as the form it matches, by its
    # case-folded text; one whose folding differs (a character that matches
    # only under re's own case rules) takes the first form's label.
    folded_forms: Dict[str, str] = {}
    for form, label in forms.items():
        folded_forms.setdefault(form.casefold(), label)
    first_label = next(iter(forms.values()))

    def label_of(matched: str) -> str:
        if matched in forms:
            return forms[matched]
        return folded_forms.get(matched.casefold(), first_label)

    flags = re.IGNORECASE if ignore_case or not whole_words else 0
    # The case-insensitive needles' forms, when the call's flags match as
    # written: their patterns run under the flags plus IGNORECASE. Under flags
    # that already ignore case every form is matched that way, and the set is
    # left empty so no form takes a second pattern.
    insensitive_flags = flags | re.IGNORECASE
    insensitive_folded: Set[str] = (
        set() if flags & re.IGNORECASE else insensitive_sources
    )
    marked = [m.span() for m in markers.finditer(text)]

    def unmarked(start: int, end: int) -> bool:
        return not any(m_start <= start and end <= m_end for m_start, m_end in marked)

    # Where a frame-exempt needle keeps the text: computed only when such a
    # needle is in play, so a plain value's call never pays for it.
    exempt_regions: List[Tuple[int, int]] = []
    if frame_exempt_folded or any(exempt for _, _, exempt in variant_patterns):
        exempt_regions = _ash_frame_regions(
            text,
            frame_exempt_sources,
            [variant for variant, _, exempt in variant_patterns if exempt],
        )

    def frame_exempt_span(start: int, end: int) -> bool:
        return any(
            r_start <= start and end <= r_end for r_start, r_end in exempt_regions
        )

    # The four- to seven-character forms of a value read from the environment:
    # matched anywhere, then kept where they stand as whole words
    # (_whole_word_spans). With whole_words every form is matched in the
    # pattern, as a whole word between characters that are not letters, digits
    # or "_".
    banded = (
        []
        if whole_words
        else sorted(
            (
                f
                for f in forms
                if f not in anywhere
                and f not in quoted_only
                and f not in component_forms
            ),
            key=len,
            reverse=True,
        )
    )
    # Frame-exempt forms are matched by their own pattern over the whole
    # text, never folded into the plain alternation: the lookahead takes one
    # longest match per position, so an exempt form sharing a position with
    # a shorter plain form would otherwise shadow the plain match and then
    # drop it with the exemption.
    # The case-insensitive needles' forms are matched by their own pattern
    # too, under flags that ignore case; a frame-exempt or component form
    # keeps its own treatment (no needle carries both).
    alternatives = []
    exempt_alternatives: List[str] = []
    insensitive_alternatives: List[str] = []
    long_forms: List[str] = []
    exempt_long_forms: List[str] = []
    insensitive_long_forms: List[str] = []
    component_long_forms: List[str] = []
    exempt_component_long_forms: List[str] = []
    for form in sorted(forms, key=len, reverse=True):
        form_exempt = form.casefold() in frame_exempt_folded
        form_insensitive = not form_exempt and form.casefold() in insensitive_folded
        if len(form) > _LONG_FORM_LENGTH and form not in quoted_only:
            if form in component_forms:
                (
                    exempt_component_long_forms if form_exempt else component_long_forms
                ).append(form)
            elif form_exempt:
                exempt_long_forms.append(form)
            elif form_insensitive:
                insensitive_long_forms.append(form)
            else:
                long_forms.append(form)
            continue
        if form_exempt:
            target = exempt_alternatives
        elif form_insensitive and form not in component_forms:
            target = insensitive_alternatives
        else:
            target = alternatives
        if form in component_forms:
            target.append(_component_pattern(form))
            continue
        if form in anywhere:
            if _number_bounded_form(form):
                # A short numeric print ("-1.5", "1e+20") stops being that
                # number only when a digit, or a dot attached to a digit,
                # runs into it from either side: "requests-1.5.4" and
                # "delta -1.55s" keep their text, while the print standing
                # alone, quoted, before a lone dot ("limit -1.5."), glued
                # into a word ("x1.50y") or ending the number ("-1.5s") is
                # hidden.
                target.append(bounded_number_pattern(form))
            else:
                target.append(re.escape(form))
            continue
        if form in quoted_only:
            # Between two of the same quote, ', " or `, which stay; the closing
            # one may be escaped, as a JSON string writes \"x\".
            escaped = re.escape(form)
            target.extend(
                f"(?<={quote})(?:{escaped})(?=\\\\?{quote})"
                for quote in ("'", '"', "`")
            )
            continue
        if form in banded:
            continue
        before = r"(?<!\w)" if re.match(r"\w", form[0]) else ""
        after = r"(?!\w)" if re.match(r"\w", form[-1]) else ""
        target.append(f"{before}{re.escape(form)}{after}")
    # One pass over the text. The lookahead finds a match at every position,
    # so matches that overlap one another are found too; at one position the
    # longest form matches, and a shorter one there is inside it anyway. A value
    # read from the environment is matched in any case: a message can print it
    # upper-cased, and it is the value all the same. A form longer than
    # _LONG_FORM_LENGTH is found apart, in time linear in the text, with the
    # same rules (_long_form_spans).
    spans: List[Tuple[int, int, str]] = []
    if alternatives:
        pattern = re.compile(f"(?=({'|'.join(alternatives)}))", flags)
        for match in pattern.finditer(text):
            start, end = match.span(1)
            if unmarked(start, end):
                spans.append((start, end, label_of(match.group(1))))
    # The case-insensitive needles' forms, with the same rules, in any case.
    if insensitive_alternatives:
        pattern = re.compile(
            f"(?=({'|'.join(insensitive_alternatives)}))", insensitive_flags
        )
        for match in pattern.finditer(text):
            start, end = match.span(1)
            if unmarked(start, end):
                spans.append((start, end, label_of(match.group(1))))
    # The frame-exempt forms, with the same rules, except inside ASH's and
    # the import machinery's own frame lines, where they keep the text.
    if exempt_alternatives:
        pattern = re.compile(f"(?=({'|'.join(exempt_alternatives)}))", flags)
        for match in pattern.finditer(text):
            start, end = match.span(1)
            if unmarked(start, end) and not frame_exempt_span(start, end):
                spans.append((start, end, label_of(match.group(1))))
    # A needle's variant pattern (the distribution needle's separator
    # spellings): bounded by its own construction, so matched as it stands.
    for variant, variant_label, variant_exempt in variant_patterns:
        for match in variant.finditer(text):
            start, end = match.span()
            if not unmarked(start, end):
                continue
            if variant_exempt and frame_exempt_span(start, end):
                continue
            spans.append((start, end, variant_label))
    for start, end in _long_form_spans(text, exempt_long_forms, flags, whole_words):
        if unmarked(start, end) and not frame_exempt_span(start, end):
            spans.append((start, end, label_of(text[start:end])))
    for start, end in _long_form_spans(text, long_forms, flags, whole_words):
        if unmarked(start, end):
            spans.append((start, end, label_of(text[start:end])))
    for start, end in _long_form_spans(
        text, insensitive_long_forms, insensitive_flags, whole_words
    ):
        if unmarked(start, end):
            spans.append((start, end, label_of(text[start:end])))
    # The component forms past that length: found the same way, between
    # characters that are not ASCII letters, digits or "_".
    for start, end in _long_form_spans(
        text, exempt_component_long_forms, flags, whole_words, component=True
    ):
        if unmarked(start, end) and not frame_exempt_span(start, end):
            spans.append((start, end, label_of(text[start:end])))
    for start, end in _long_form_spans(
        text, component_long_forms, flags, whole_words, component=True
    ):
        if unmarked(start, end):
            spans.append((start, end, label_of(text[start:end])))
    # The four- to seven-character forms, matched anywhere and kept where they
    # stand as whole words (_whole_word_spans below).
    candidates: List[Tuple[int, int, str]] = []
    for form in banded:
        banded_exempt = form.casefold() in frame_exempt_folded
        for match in re.finditer(f"(?=({re.escape(form)}))", text, flags):
            start, end = match.span(1)
            if banded_exempt and frame_exempt_span(start, end):
                continue
            if unmarked(start, end):
                candidates.append((start, end, label_of(match.group(1))))
    # The pieces of a long value a message cuts at "..." or "…", found apart
    # from the pattern, so a full form starting at the same place is found too,
    # and found once per form. A piece whose far side is already a word
    # boundary is hidden as it is. One whose far side runs into a word joins
    # the fixed point with the banded matches, so a piece run into a value, or
    # into another piece, is hidden with it; one inside a span already hidden
    # changes nothing and is left out. A part cut at both ends, between two
    # markers, that a form holds is hidden too (_cut_windows). A piece of four
    # to seven characters joins the fixed point too, and stands only in a run of
    # eight characters or more (_short_cut_pieces).
    short: Sequence[int] = ()
    if anywhere:
        cut_starts = sorted(m.start() for m in re.finditer(r"(?=\.\.\.)|…", text))
        cut_ends = sorted(
            [m.start() + 3 for m in re.finditer(r"(?=\.\.\.)", text)]
            + [m.end() for m in re.finditer("…", text)]
        )
        folded_text = _folded(text)
        ordered_anywhere = sorted(anywhere, key=len, reverse=True)
        form_pieces = {
            form: _cut_pieces(text, folded_text, form, cut_starts, cut_ends)
            for form in ordered_anywhere
        }
        for form in ordered_anywhere:
            for start, end, far_ok, _ in form_pieces[form]:
                if far_ok and unmarked(start, end):
                    spans.append((start, end, forms[form]))
        folded_anywhere = [(form, _folded(form)) for form in ordered_anywhere]
        for start, end, form in _cut_windows(
            folded_text, folded_anywhere, cut_starts, cut_ends
        ):
            if unmarked(start, end):
                spans.append((start, end, forms[form]))
        hidden = _edge_index((start, end) for start, end, _ in spans)
        for form in ordered_anywhere:
            for start, end, far_ok, _ in form_pieces[form]:
                if (
                    not far_ok
                    and unmarked(start, end)
                    # Inside a span already hidden: o_start <= start, o_end >= end.
                    and not _edge_covers(hidden, start + 1, end)
                ):
                    candidates.append((start, end, forms[form]))
        first_short = len(candidates)
        for start, end, form in _short_cut_pieces(
            folded_text, folded_anywhere, cut_starts, cut_ends
        ):
            if unmarked(start, end) and not _edge_covers(hidden, start + 1, end):
                candidates.append((start, end, forms[form]))
        short = range(first_short, len(candidates))
    if candidates:
        spans.extend(
            _whole_word_spans(
                text,
                candidates,
                list(spans),
                short,
                underscore_joins_words=underscore_joins_words,
            )
        )
    if not spans:
        return text
    spans.sort()
    # Each run of overlapping or touching matches: its start, its end, and the
    # matches in it.
    merged: List[Tuple[int, int, List[Tuple[int, int, str]]]] = []
    for span in spans:
        if merged and span[0] <= merged[-1][1]:
            run_start, run_end, members = merged[-1]
            members.append(span)
            merged[-1] = (run_start, max(run_end, span[1]), members)
        else:
            merged.append((span[0], span[1], [span]))
    pieces, last = [], 0
    for start, end, members in merged:
        longest_first = sorted(members, key=lambda m: m[0] - m[1])
        pieces += [text[last:start], render([label for _, _, label in longest_first])]
        last = end
    pieces.append(text[last:])
    return "".join(pieces)


def location_text(loc: Iterable[Any], names: Optional[Iterable[str]] = None) -> str:
    """A pydantic error location as messages print it: ``a.b[0].c``.

    Empty for the top level. With ``names``, a part that is not one of them is
    printed as ``<key>``: a mapping key on the path is the file's data, not a
    field name.
    """
    shown_names = None if names is None else set(names)
    location = ""
    for part in loc:
        if isinstance(part, int):
            location += f"[{part}]"
            continue
        shown = str(part) if shown_names is None or part in shown_names else "<key>"
        location += f".{shown}" if location else shown
    return location


#: What ``_paired_items`` pairs an entry with when the copy does not line up:
#: everything under it is shown as read from the environment.
_ALL_SHOWN = object()


def _paired_items(
    mapping: Dict[Any, Any], shown: Any
) -> List[Tuple[Any, Any, str, Any]]:
    """Each key and value of ``mapping``, with the key and value ``shown`` holds at
    the same position: ``shown`` is ``mapping`` as
    ``environment_record.with_environment_values_shown`` returns it, a key or
    value read from the environment shown as ``<value>``.

    Positions are paired, not keys, since two keys read from the environment
    are both ``<value>`` in the copy. A copy that does not line up with
    ``mapping`` shows every key, and everything under it, as read from the
    environment.
    """
    if isinstance(shown, dict) and len(shown) == len(mapping):
        return [
            (key, value, str(shown_key), shown_value)
            for (key, value), (shown_key, shown_value) in zip(
                mapping.items(), shown.items()
            )
        ]
    return [
        (key, value, ENVIRONMENT_VALUE_SHOWN, _ALL_SHOWN)
        for key, value in mapping.items()
    ]


def _shown_at(
    location: Sequence[Any], data: Any, shown: Any
) -> Tuple[List[Any], Any, Any]:
    """Each step of ``location``, a pydantic error's path into ``data``, as the
    copy ``shown`` names it, and the node of ``data`` and of ``shown`` the path
    ends at.

    A key of ``data`` is named as ``shown`` holds it at the same position
    (``_paired_items``), so a key read from the environment is ``<value>``. A
    step that is not a key of ``data`` (one pydantic adds, such as a union
    member's name) is named as it is and passed over, as are the steps after
    the path leaves ``data``.
    """
    steps: List[Any] = []
    node, shown_node = data, shown
    for step in location:
        if isinstance(node, dict) and step in node:
            index = list(node).index(step)
            _key, node, shown_step, shown_node = _paired_items(node, shown_node)[index]
            steps.append(shown_step)
            continue
        if isinstance(node, list) and isinstance(step, int) and 0 <= step < len(node):
            steps.append(step)
            aligned = isinstance(shown_node, list) and len(shown_node) == len(node)
            node = node[step]
            shown_node = shown_node[step] if aligned else _ALL_SHOWN
            continue
        steps.append(step)
    return steps, node, shown_node


def shown_location_text(location: Iterable[Any], data: Any, shown: Any) -> str:
    """``location_text`` of ``location``, a path into ``data``, with each key the
    config read from the environment named as ``shown`` (``data`` as
    ``with_environment_values_shown`` returns it) holds it: ``<value>``."""
    steps, _node, _shown_node = _shown_at(list(location), data, shown)
    return location_text(steps)


def _strings_read_from_the_environment(item: Any, shown: Any) -> List[str]:
    """Every key and string of ``item`` its copy ``shown`` does not hold as it
    is: the ones the config read from the environment."""
    if shown is _ALL_SHOWN:
        if isinstance(item, str):
            return [item]
        shown = None
    if isinstance(item, dict):
        found: List[str] = []
        for key, value, shown_key, shown_value in _paired_items(item, shown):
            if isinstance(key, str) and shown_key != key:
                found.append(key)
            found += _strings_read_from_the_environment(value, shown_value)
        return found
    if isinstance(item, (list, tuple)):
        aligned = isinstance(shown, (list, tuple)) and len(shown) == len(item)
        return [
            text
            for index, value in enumerate(item)
            for text in _strings_read_from_the_environment(
                value, shown[index] if aligned else _ALL_SHOWN
            )
        ]
    if isinstance(item, str) and shown != item:
        return [item]
    return []


def redact_values(
    text: str,
    values: Iterable[str],
    ignore_case: bool = False,
    min_length: int = MIN_REDACTED_LENGTH,
    markers: Pattern[str] = _MARKER_PATTERN,
    whole_words: bool = False,
) -> str:
    """``text`` with every occurrence of each value replaced by REDACTED.

    A value is matched in any case: a message can print it in another one (a
    validator upper-cases its input). With ``whole_words``, only with
    ``ignore_case``: for a message a validator wrote (redact_refused_input).

    Each value is matched in each form a message prints it in (_printed_forms),
    by the band of that form (MIN_REDACTED_LENGTH), so "build/", printed as
    "build", is a five-character word:

    - shorter than ``min_length``: only where the text quotes it whole, between
      two ', ", or `, which stay; the closing one may be escaped (\\"x\\"). Unquoted
      it is left;
    - from ``min_length`` up to MIN_ANYWHERE_LENGTH characters, and not one of
      the next band: as a whole word, not inside a longer one ("untrue" keeps
      its "true"); a quoted one is whole too. "_" bounds a word like any other
      character that is not a letter or a digit, so a value glued into a
      longer name by "_" ("<value>_findings", "ASH_<value>_logs") is hidden.
      (The test-report backstop's own entry point,
      ``_redact_for_test_reports``, makes "_" a word character instead, as in
      Python's own word boundary, so a CI path or module name holding a
      common host value stays whole; its look-past and double-"_" rules are
      ``_whole_word_spans``'. This function has no opt-in for that rule.)
      The edge of another value's match the value touches or overlaps bounds
      a word too, so a value run into another one ("qz4brk5c"), or beside a
      hidden longer one, is hidden with it; one whose far side runs into an
      uncovered letter or digit (in test reports, one "_" before an uncovered
      word character, or a run of two or more "_" that reaches neither the
      text's edge nor a covered character) is shown even beside a
      hidden one (_whole_word_spans). Run into
      letters or digits ("qz4b1", "xqz4b") it is shown;
    - MIN_ANYWHERE_LENGTH characters or more, or MIN_REDACTED_LENGTH or more
      holding a character other than a letter, a digit or "_": anywhere, inside
      a longer word too. A piece of one longer than MIN_ANYWHERE_LENGTH, of
      MIN_ANYWHERE_LENGTH characters or more, is replaced where a message cuts
      the value: its start where "..." or "…" begins, its end where one ends,
      each as a whole word on its other side (_cut_pieces). A piece whose
      other side runs into another value's match, or into another such piece,
      is hidden with it, as two values run together are (_whole_word_spans).
      A piece of MIN_REDACTED_LENGTH up to MIN_ANYWHERE_LENGTH characters is
      hidden only that way, in a run of MIN_ANYWHERE_LENGTH characters or more,
      as a message that cuts two values printed back to back leaves it
      (_short_cut_pieces); alone it could be any word, and is left.
      A part cut at both ends, between two markers, of MIN_ANYWHERE_LENGTH
      characters or more, is replaced when a value holds it (_cut_windows).
      A piece at the end of the text with no marker is a word like any other,
      and is left.

    Whole applies only at an end of the form that is a word character: a value
    starting with "/" is replaced after any character.

    A form of a masked module name (a ``ModuleFormNeedle`` marked
    ``whole_component``, which ``plugins.loader._masked_module_forms`` builds)
    is replaced in none of those ways but one, whatever its length: where no
    ASCII letter, digit or "_" is beside either end of it. A longer module name
    that holds such a form ("<parent>_extras") keeps its text, and ".", "/",
    "\\" and quotes end a component. The masked entry's own name is passed as a
    plain value beside its forms, so it is replaced as any value is, inside a
    longer module name too. A form shorter than ``min_length`` is still
    replaced only between quotes, and a form that a plain value also yields is
    replaced as that value is.

    ``whole_words`` replaces every value of ``min_length`` or more only whole,
    and leaves a shorter one, quoted or not, so a value ("LOWX") does not take a
    piece out of a longer word ("'LOWXY'" stays readable): for the inputs a
    model error quotes (redact_refused_input) and a results file's or a shard's
    values, which are not the environment's and are matched against pydantic's
    and a validator's own wording, its quoted choices included.

    Every match of every form is found in the original text, overlapping
    matches included, and each run of overlapping or touching matches is
    replaced by one REDACTED. Replacing values one after another, or taking
    the first of two overlapping matches, left part of a value behind: with
    "foo/bar" and "bar/baz-long" in "foo/bar/baz-long", "<value>/baz-long".
    A REDACTED already in the text is left as it is, so redacting a message
    twice (a model error, then the check's own pass) changes nothing more:
    with the value "value", "<value>" became "<<value>>".

    ``min_length`` 1 replaces a short value as a whole word too, for a caller
    that knows by its place that the value was read from the environment
    (format_model_error).

    ``markers`` is what is left as it is, a REDACTED and, by default, a
    `<from ${VAR}>` an environment record wrote. A caller whose text holds no
    such record passes REDACTED_MARKERS, so a value shaped like one is hidden.
    """
    return _replace_values(
        text,
        # One string given as values is one value (redacted_model.value_tuple).
        ((value, REDACTED) for value in value_tuple(values)),
        lambda _labels: REDACTED,
        ignore_case=ignore_case,
        min_length=min_length,
        markers=markers,
        whole_words=whole_words,
    )


def _redact_for_test_reports(
    text: str,
    values: Iterable[str],
    ignore_case: bool = False,
    min_length: int = MIN_REDACTED_LENGTH,
    markers: Pattern[str] = _MARKER_PATTERN,
    whole_words: bool = False,
) -> str:
    """``redact_values`` under the test-report word rule, for the backstop.

    The one entry point that reads "_" as a word character (as in Python's
    own word boundary): the test-report backstop sweeps the WHOLE environment
    over report text, where a common host value (USER=runner) glued into a CI
    path or module name must not mangle it. Private on purpose -- a product
    message never carries this rule: ``redact_values`` has no opt-in for it,
    the test suite's source scan keeps product modules other than this file
    from importing this entry point or passing the private keyword directly,
    and an AST check over this file allows the name only as this definition,
    and the private keyword only inside this definition and inside
    ``_replace_values``, whose forwarding to ``_whole_word_spans`` must pass
    the enclosing parameter itself. Any other keyword site whatever its
    value, a forwarding value of its own, a parameter of the keyword's name
    defaulting to anything but ``False``, any string constant equal to this
    entry point's name (a ``globals()`` or ``getattr`` lookup, pieces the
    parser joins included), and any string constant in the whole product
    package equal to the keyword's name (every ``**`` mapping shape,
    however the mapping is built) are red in that check; only a name
    assembled at runtime stays outside it, as it stays outside any source
    scan. The look-past, run
    and covered-"_" rules are ``_whole_word_spans``'; everything else is
    ``redact_values``' documented behavior. Memory grows quadratically with
    the length of a "_" run when an all-"_" value of four to seven characters
    is in the environment, since every uncovered "_" of the run is kept as a
    witness for each side; this path is the test-report rule's only, and no
    bound is placed on it.
    """
    return _replace_values(
        text,
        ((value, REDACTED) for value in value_tuple(values)),
        lambda _labels: REDACTED,
        ignore_case=ignore_case,
        min_length=min_length,
        markers=markers,
        whole_words=whole_words,
        underscore_joins_words=True,
    )


def _string_leaves(value: Any) -> List[str]:
    """Every string value in a value, at any depth: what a validator might quote.

    Mapping keys are not included. A key is a name, and the location of the
    error already prints the keys on its path. A check that names the key it
    refuses and lists the accepted ones, which are often keys of the same
    entry, turned "Unknown key 'ruleId' ... Accepted keys: path, reason, ..."
    into "Unknown key '<value>' ... Accepted keys: <value>, <value>, ...", and
    pydantic's own text loses words to keys such as "valid". A key read from
    the environment is still replaced, by the checks (ConfigCheck.redact) and
    the scan, which redact every value and key the file's references resolved
    to.

    The walk is iterative, on its own stack: the input is the refused value at
    whatever depth it was written, and this walk runs while that refusal is
    being described, where a RecursionError would replace the one-line refusal
    with a crash. The leaves keep the file's own order (depth-first, left to
    right), so the longest-match replacement downstream sees them as written.
    Each container is visited once, by identity: YAML aliases survive the load
    as shared containers, so one container can be reachable along many paths,
    and re-visiting it costs the walk once per path -- exponential for an
    alias-amplified document. The same visit set would end a cyclic structure,
    though the loader fails on one before any refusal is described.
    """
    leaves: List[str] = []
    stack: List[Any] = [value]
    visited: Set[int] = set()
    while stack:
        current = stack.pop()
        if isinstance(current, str):
            leaves.append(current)
        elif isinstance(current, (dict, list, tuple)):
            if id(current) in visited:
                continue
            visited.add(id(current))
            if isinstance(current, dict):
                stack.extend(reversed(list(current.values())))
            else:
                stack.extend(reversed(current))
    return leaves


@functools.lru_cache(maxsize=1)
def _schema_names() -> frozenset:
    """Every name the configuration schema defines, from AshConfig down.

    Each model's field names and aliases (a declared plugin's key, such as
    `bandit` or `cdk-nag`, is a field of its segment) and the models' class
    names. A message names these as the path of what it refuses, and an input
    value equal to one (a section's `name: bandit`) is not something to hide.
    """
    from pydantic import BaseModel

    from automated_security_helper.config.ash_config import AshConfig

    names: set = set()
    seen: set = set()

    def models_in(annotation: Any) -> List[type[BaseModel]]:
        found: List[type[BaseModel]] = []
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            found.append(annotation)
        for argument in typing.get_args(annotation):
            found += models_in(argument)
        return found

    def walk(model: type[BaseModel]) -> None:
        if model in seen:
            return
        seen.add(model)
        names.add(model.__name__)
        for field_name, info in model.model_fields.items():
            names.add(field_name)
            if info.alias:
                names.add(info.alias)
            for nested in models_in(info.annotation):
                walk(nested)

    walk(AshConfig)
    return frozenset(names)


def _input_leaves(value: Any) -> List[str]:
    """The strings of an error's input that a message must not show: every
    string in it but a name the schema defines (_schema_names)."""
    names = _schema_names()
    return [leaf for leaf in _string_leaves(value) if leaf not in names]


#: pydantic's own error types. Their messages never quote the input, and some
#: list the values a field accepts ("Input should be 'LOW' or 'HIGH'"), so they
#: are matched only as written. A validator's own message (value_error,
#: assertion_error, or an error type pydantic does not define) can quote its
#: input in any form.
_PYDANTIC_ERROR_TYPES = frozenset(typing.get_args(_core_schema.ErrorType))


def _validator_wrote(error: Mapping[str, Any]) -> bool:
    kind = error.get("type")
    return kind in ("value_error", "assertion_error") or (
        kind not in _PYDANTIC_ERROR_TYPES
    )


#: A changed form of an input is looked for only for an input this long or
#: longer, compared as letters and digits alone: a shorter one would match
#: ordinary words of the message. What is looked for is the whole input, in
#: order. So a message is shown as the validator wrote it, past every
#: replacement, when it quotes only part of the input (its first twelve
#: characters, or all but its ends), the input reversed, or a shorter input
#: in a form no replacement reaches (its separators taken out).
MIN_CHANGED_LENGTH = 8

#: A validator's message in place of one that repeats its input in a form no
#: replacement reaches (separators taken out, spaced out, ...).
CHANGED_INPUT_WITHHELD = (
    "the value is not valid (the check's message is not shown: it repeats "
    "the value in another form)"
)


def _letters_and_digits(text: str) -> str:
    return "".join(ch for ch in text.casefold() if ch.isalnum())


def shows_a_changed_input(text: str, inputs: Iterable[str]) -> bool:
    """Whether ``text`` still holds one of ``inputs`` once both are compared as
    their letters and digits alone, case-folded: a validator wrote it back
    changed. The markers redaction put in are not part of the text compared,
    and neither is a run of letters that crosses one: the text on each side of
    a marker is compared on its own, since letters either side of a hidden
    value spliced together read as the value in a changed form, and an
    unrelated message was withheld. Only a whole input of MIN_CHANGED_LENGTH
    or more is looked for; see there for what that misses."""
    names = {_letters_and_digits(name) for name in _schema_names()}
    compared = [_letters_and_digits(piece) for piece in _MARKER_PATTERN.split(text)]
    for value in inputs:
        letters = _letters_and_digits(value)
        if (
            len(letters) >= MIN_CHANGED_LENGTH
            and letters not in names
            and any(letters in piece for piece in compared)
        ):
            return True
    return False


def redact_refused_input(
    text: str, errors: Iterable[Mapping[str, Any]]
) -> Tuple[str, bool]:
    """``text``, which quotes the pydantic ``errors`` (``e.errors()``) in some
    form, with each refused input replaced by REDACTED, and whether a changed
    form of an input is still in it.

    Every error's input is replaced in each form a message prints it in. The
    input of an error a validator wrote is replaced ignoring case as well, and
    only that input is looked for in a changed form: the message is the
    validator's, and pydantic's own messages never quote the input.

    Both sets go through ONE redact_values pass, the validator-written inputs
    as case-insensitive needles (CaseInsensitiveNeedle): two passes replaced
    the exact inputs first and the written ones over the result, so an input
    of each set that overlapped the other left part of a value behind, the
    shape the one-pass merge in redact_values exists to close.
    """
    errors = list(errors)
    exact: List[str] = []
    written: List[str] = []
    for error in errors:
        leaves = _input_leaves(error.get("input"))
        (written if _validator_wrote(error) else exact).extend(leaves)
    # Whole words: an input is the file's text, matched against the message's
    # own wording.
    needles: List[str] = [
        *exact,
        *(make_case_insensitive_needle(leaf) for leaf in written),
    ]
    text = redact_values(text, needles, whole_words=True)
    return text, shows_a_changed_input(text, written)


def _without_env_tag(written: str) -> str:
    """``written`` without the explicit ``!ENV `` tag read_config_file_as_written
    keeps (config_sources)."""
    return written.removeprefix("!ENV ")


def _reference_variable_is_set(written: str) -> bool:
    """Whether the variable a reference names is set, so its value came from
    the environment.

    For ``${VAR:default}`` with ``VAR`` unset the value is the default, the
    file's own text: not read from the environment, so neither redacted nor
    recorded as the reference. A variable set to an empty or blank value gave
    nothing either (environment_record._value_read reads it so): what the
    string then holds is the text after the reference, the file's own, which
    is not listed for redaction. A string with no reference at its start,
    which resolution does not read, counts as set: what differs there is not
    a default.
    """
    reference = ENV_REFERENCE_PATTERN.match(_without_env_tag(written))
    if reference is None:
        return True
    value = os.environ.get(reference.group(1))
    return value is not None and bool(value.strip())


def _has_reference_key(key: Any) -> bool:
    """Whether ``key``, a mapping key as its file wrote it, holds a reference."""
    return isinstance(key, str) and "${" in key


def _quietly_resolved(text: str) -> Optional[str]:
    """``text``, a scalar holding a ``${VAR}`` or ``${VAR:default}`` reference
    at its start, as the loader resolves it (``resolve_env_references``), with
    nothing logged and nothing raised.

    The loader's resolver logs a warning for a default taken, a name a file may
    not read, a credential-shaped name and the shell's ``:-`` form, and raises
    for a variable unset with no default. Building the record runs after the
    load, over the same text, and its contract is that nothing is read from
    the environment that the load did not read and no ``!ENV`` warning is
    logged again (environment_record_read), so the rule is applied here
    without its reporting: a name the loader does not read, and a composite
    the loader leaves as written, come back as written; a variable unset with
    no default comes back None (the load raised there); the rest resolves as
    the loader did. The rule is the loader's own functions (read_env_reference,
    env_reference_left_as_written, env_reference_value), not a copy of them:
    a copy kept here once fell behind the loader's composite check, so the two
    read ``${A}/${B}`` differently and a stripped key could pair by position.
    The pairing tests still read both against the same shapes."""
    reference = read_env_reference(text)
    if reference is None:
        return text
    if env_reference_left_as_written(reference) is not None:
        return text.strip()
    value, _used_default = env_reference_value(reference)
    if value is None:
        return None
    full_value = value + reference.rest
    return None if full_value.strip() == "" else full_value.strip()


def _resolved_reference_key(written_key: str, resolved: Dict[Any, Any]) -> Any:
    """The key of ``resolved`` that ``written_key``, a mapping key written as a
    reference, came to, or None when none of them can be told.

    The loader keeps a key as written where it resolves no key at all (a JSON
    or TOML file) or where the key is a quoted scalar (the implicit ``!ENV``
    resolver reads plain scalars only), so a written key that is itself a key
    of ``resolved`` came to itself. Otherwise the key is resolved by the
    loader's own rule, read quietly (_quietly_resolved), and looked up by the
    merge's spelling rule (_record_key without its plugin-section fold: ``-``
    for ``_``, the twin environment_record_read folds a plugin section's
    canonical spelling by too; a key resolving to another plugin's name is
    not this mapping's entry). A key that still names no key of ``resolved``
    (the variable unset, or set to a name the mapping does not hold) is None,
    and _paired_keys pairs it by position."""
    text = _without_env_tag(written_key)
    if text in resolved:
        return text
    key = _quietly_resolved(text)
    if key is None:
        return None
    if key in resolved:
        return key
    found = _record_key(resolved, key)
    return found if found in resolved else None


def _paired_keys(
    written: Dict[Any, Any], resolved: Dict[Any, Any]
) -> Tuple[List[Tuple[Any, Any]], List[Tuple[Any, Any, Any, bool]]]:
    """How the entries of ``written``, a mapping as its file wrote it, pair with
    the entries of ``resolved``, the same mapping as the loader read it.

    A key written without a reference pairs with the same key. A key written
    as a reference pairs with the key it resolves to (_resolved_reference_key),
    never by position: a reference that resolves onto another key of its
    mapping merges the two entries, and pairing the referenced keys with the
    leftover resolved keys in order compared every later entry with the wrong
    one and the merged entry's value with nothing, so that value was neither
    redacted nor recorded as its reference. The loader keeps the last entry
    written under a name, so of a plain key and the referenced keys that come
    to one name, the one written last holds the value there: only that entry's
    value is paired (``kept``). Returns the plain entries whose value is kept,
    as ``(key, value)``, and every referenced entry as ``(written key, written
    value, resolved key, kept)``.

    A referenced key whose resolved key cannot be told (_resolved_reference_key
    is None: the variable is set to a name the mapping does not hold, or
    unset) is paired by position with the keys of ``resolved`` no other entry
    claims, in writing order, as every referenced key once was. Dropping such
    an entry instead left the value under it neither redacted nor recorded, so
    the results file and an off-host payload carried it in clear; one that
    still finds no partner is left out.
    """
    order = {key: index for index, key in enumerate(written)}
    plain_keys = [key for key in written if not _has_reference_key(key)]
    referenced_keys = [key for key in written if _has_reference_key(key)]
    names = {key: _resolved_reference_key(key, resolved) for key in referenced_keys}
    claimed = set(plain_keys) | {name for name in names.values() if name is not None}
    unclaimed = [key for key in resolved if key not in claimed]
    for key in referenced_keys:
        if names[key] is None and unclaimed:
            names[key] = unclaimed.pop(0)
    kept: Dict[Any, int] = {key: order[key] for key in plain_keys}
    for key in referenced_keys:
        name = names[key]
        if name is not None:
            kept[name] = max(kept.get(name, -1), order[key])
    plain = [(key, written[key]) for key in plain_keys if kept[key] == order[key]]
    referenced = [
        (key, written[key], names[key], kept[names[key]] == order[key])
        for key in referenced_keys
        if names[key] is not None
    ]
    return plain, referenced


def _interpolated_pairs(literal: Any, resolved: Any) -> List[Tuple[str, str]]:
    """The strings in ``resolved`` that came from the environment, each with the
    text the file writes for it.

    ``literal`` is the same file read without interpolation
    (``read_config_file_literally``, or ``read_config_file_as_written``); a
    string that differs there and holds a ``${`` reference to a variable that
    is set was read from the environment. A default the reference fell back to
    is the file's own text, and is not paired. Keys are compared too, because a
    plain YAML key is interpolated like any other scalar.

    Mapping entries are paired by key, not position: an interpolated key that
    resolves to another key of the mapping merges the two, and pairing by
    position would then compare every later value with the wrong one. A key
    written without a reference pairs with the same key; a key holding a
    reference pairs with the key it resolves to, and only one whose resolved
    key cannot be told pairs, in order, with the resolved keys no other entry
    claims (_paired_keys).
    """
    found: List[Tuple[str, str]] = []
    if isinstance(literal, dict) and isinstance(resolved, dict):
        plain, referenced = _paired_keys(literal, resolved)
        for key, literal_value in plain:
            if key in resolved:
                found += _interpolated_pairs(literal_value, resolved[key])
        for literal_key, literal_value, key, kept in referenced:
            found += _interpolated_pairs(literal_key, key)
            if kept:
                found += _interpolated_pairs(literal_value, resolved[key])
    elif isinstance(literal, list) and isinstance(resolved, list):
        for literal_item, item in zip(literal, resolved):
            found += _interpolated_pairs(literal_item, item)
    elif (
        isinstance(literal, str)
        and "${" in literal
        and isinstance(resolved, str)
        and resolved != literal
        # A value resolution left as its own text read nothing: with an
        # explicit tag, the two readings differ by the tag alone (a composite
        # or embedded reference, which is not resolved), and listing the text
        # would put the file's own text in the redaction list. The run then
        # agrees with the load's record (environment_record._reference).
        and resolved != _without_env_tag(literal)
        and _reference_variable_is_set(literal)
    ):
        found.append((resolved, literal))
        # `${VAR...}rest`: the part the reference resolved to, too. What a
        # check prints can be the string rewritten after `rest` (a base path
        # normalized, "x/./base.yaml" to "x/base.yaml"), which the whole value
        # no longer matches.
        reference = read_env_reference(_without_env_tag(literal))
        if reference:
            part = _environment_part(resolved, reference.rest)
            if part != resolved:
                found.append((part, reference.text))
    return found


def describe_validation_error(error: Any, values: Iterable[str] = ()) -> str:
    """A pydantic ValidationError as ASH prints it: one line per field, no input.

    pydantic's own text quotes every input (``input_value='...'``), and the
    config's inputs can be values read from the environment, so neither the
    scan nor a config command prints it. ``values`` are the values and keys the
    config read from the environment (ResolvedConfigDocument.environment_values,
    AshConfig._environment_values): an error's location names a key, which no
    input redaction reaches, so they are redacted from the whole text. The
    location alone is redacted with ``min_length`` 1 as well: a key shorter
    than the free-text band is unquoted there (``'a.<key>.b'``), so the band
    left it in print, while by its place it is known to be one.
    """
    messages = []
    for item in error.errors():
        text = ConfigValidator.format_model_error(item)
        location = ConfigValidator.model_error_location(text)
        if location is not None:
            prefix = ConfigValidator.MODEL_ERROR_PREFIX
            hidden = redact_values(location, values, min_length=1)
            text = f"{prefix}{hidden}{text[len(prefix) + len(location) :]}"
        messages.append(text)
    return redact_values("; ".join(messages), values)


class EnvironmentRewrite(typing.NamedTuple):
    """One way a record of the configuration differs from the configuration
    (environment_record_read, record_of_config).

    ``kind`` "value": the string at ``path`` is ``resolved``, and the record
    keeps ``written``, the file's text, in its place. ``kind`` "key": the
    mapping at ``path`` has the key ``resolved``, and the record names it
    ``written``. ``environment_part`` is the part of ``resolved`` the
    variable's value gave, and ``reference`` the text the file wrote for that
    part: where the record's string is not ``resolved`` as a whole (a value
    the model normalized), only that part is replaced. A path is a tuple of
    the file's keys and list indices.
    """

    kind: str
    path: Tuple[Any, ...]
    resolved: str
    written: str
    environment_part: str
    reference: str


def _rewrite_for(
    kind: str, path: Tuple[Any, ...], written: str, resolved: str
) -> EnvironmentRewrite:
    text = _without_env_tag(written)
    reference = read_env_reference(text)
    if reference is None:
        return EnvironmentRewrite(kind, path, resolved, written, resolved, written)
    part = _environment_part(resolved, reference.rest)
    return EnvironmentRewrite(kind, path, resolved, written, part, reference.text)


def _environment_part(resolved: str, rest: str) -> str:
    """The part of ``resolved`` the variable gave, for a reference the file
    follows with ``rest`` (``${VAR}rest`` or ``${VAR} rest``).

    The loader keeps what follows the reference as written up to the value's
    end, which it strips, so the part ends where ``rest`` begins in
    ``resolved``: the tail is matched as written, then without its trailing
    blanks (a quoted ``"${VAR} tail "``), then stripped (a value a model
    normalized), and one found no way leaves the whole value as the part.
    Stripping the tail first folded the blank between the reference and the
    rest into the part, so the record's reference text and the redaction
    needle each carried a trailing blank the value never had."""
    for tail in (rest, rest.rstrip(), rest.strip()):
        if tail and resolved.endswith(tail):
            return resolved[: len(resolved) - len(tail)]
    return resolved


def _written_rewrites(
    written: Any, resolved: Any, path: Tuple[Any, ...] = ()
) -> List[EnvironmentRewrite]:
    """Where ``resolved`` holds a value or a key read from the environment, and
    the text ``written`` (read_config_file_as_written) has there.

    The same pairing as _interpolated_pairs, so a default a reference fell
    back to is not one. A value under a key read from the environment is found
    at the resolved key: the key's own rewrite renames it afterwards
    (record_of_config). That rename is emitted only for the entry whose value
    the loader kept: a referenced key a later plain key overwrote, or one of
    two references to one name, renamed the surviving entry after the
    overwritten one, so the record named the wrong variable for the value it
    shows (its key text is still paired for redaction).
    """
    found: List[EnvironmentRewrite] = []
    if isinstance(written, dict) and isinstance(resolved, dict):
        plain, referenced = _paired_keys(written, resolved)
        for key, written_value in plain:
            if key in resolved:
                found += _written_rewrites(written_value, resolved[key], (*path, key))
        for written_key, written_value, key, kept in referenced:
            if kept and _interpolated_pairs(written_key, key):
                found.append(_rewrite_for("key", path, written_key, key))
            if kept:
                found += _written_rewrites(written_value, resolved[key], (*path, key))
    elif isinstance(written, list) and isinstance(resolved, list):
        for index, (written_item, item) in enumerate(zip(written, resolved)):
            found += _written_rewrites(written_item, item, (*path, index))
    elif _interpolated_pairs(written, resolved):
        found.append(_rewrite_for("value", path, written, resolved))
    return found


#: An append (``-``) in a patch pointer, kept in a rewrite's path until the
#: configuration is built and the index is known (placed_at_appends).
_APPENDED = "-"


def _placed_rewrites(
    rewrites: List[EnvironmentRewrite], data: Any
) -> List[EnvironmentRewrite]:
    """``rewrites``, one file's (``data``), each at the path it has once the file
    merges, as config_sources._placed_references places the file's references.

    A value a ``patch`` operation's ``value`` reads from the environment lands
    at the operation's ``path``, so its rewrite is moved there: left under
    ``patch``, it would name no place in the record, and the value would be
    written and sent as it was read. A list index in the pointer is kept as the
    index, and
    an append (``-``) as ``-`` until the configuration is built
    (placed_at_appends). One under ``extends`` names a base, not part of the
    configuration, and any other one under ``patch`` sets no value: both are
    left out.
    """
    placed: List[EnvironmentRewrite] = []
    ops = data.get(PATCH_KEY) if isinstance(data, dict) else None
    for rewrite in rewrites:
        head = rewrite.path[:1]
        if head == (EXTENDS_KEY,):
            continue
        if head != (PATCH_KEY,):
            placed.append(rewrite)
            continue
        index = rewrite.path[1] if len(rewrite.path) > 2 else None
        if (
            rewrite.kind != "value"
            or not isinstance(ops, list)
            or not isinstance(index, int)
            or not 0 <= index < len(ops)
            or rewrite.path[2] != "value"
            or not isinstance(ops[index], dict)
            or not isinstance(ops[index].get("path"), str)
        ):
            continue
        segments: List[Any] = []
        for segment in ops[index]["path"].split("/")[1:]:
            segment = segment.replace("~1", "/").replace("~0", "~")
            # ASCII digits only: str.isdigit admits a superscript or another
            # script's digit, which int() refuses with a ValueError that
            # escaped the record's read.
            segments.append(
                int(segment) if segment.isascii() and segment.isdigit() else segment
            )
        placed.append(rewrite._replace(path=(*segments, *rewrite.path[3:])))
    return placed


def placed_at_appends(
    config: Any, rewrites: List[EnvironmentRewrite]
) -> List[EnvironmentRewrite]:
    """``rewrites`` with each patch append (``-``) in a path given the index the
    value has in ``config``: the last entry of that list that holds it, as the
    operation appended it. A rewrite whose list holds the value nowhere (a later
    file or an override replaced it) names no place and is left out. A ``-``
    whose container is a mapping is that mapping's own key, not an append, and
    the rewrite is kept as it is."""
    if not any(_APPENDED in rewrite.path for rewrite in rewrites):
        return rewrites
    dumped = config.model_dump(mode="json", by_alias=True)
    found: List[EnvironmentRewrite] = []
    for rewrite in rewrites:
        if _APPENDED not in rewrite.path:
            found.append(rewrite)
            continue
        at = rewrite.path.index(_APPENDED)
        listed = recorded_value_at(config, dumped, rewrite.path[:at])
        if isinstance(listed, dict):
            found.append(rewrite)
            continue
        if not isinstance(listed, list):
            continue
        for index in reversed(range(len(listed))):
            path = (*rewrite.path[:at], index, *rewrite.path[at + 1 :])
            leaf = recorded_value_at(config, dumped, path)
            if leaf == rewrite.resolved or (
                isinstance(leaf, str)
                and rewrite.environment_part
                and rewrite.environment_part in leaf
            ):
                found.append(rewrite._replace(path=path))
                break
    return found


def _value_folded_into(written: Any, merged: Any) -> bool:
    """Whether ``merged``, a value of the resolved chain, holds ``written``, a
    file's value for the same setting, the way ``config_sources.deep_merge``
    folds it.

    The merge joins two mappings key by key under its spelling rule
    (``_resolve_dict_key``: a key and its ``-``/``_`` twin are one key, which
    is every alias a field declares), the file's values winning, so the merged
    mapping holds every key the file wrote with its value folded the same way,
    and a base's other keys beside them. Compared for equality, a merged mapping
    that holds a base's keys too never matched the file's, and a respelled
    mapping-valued field (``global-settings``) the chain did fold was said to be
    ignored. Any other value (a scalar, a list) the merge replaces whole, so it
    is held only when equal. An empty mapping as the file's whole value sets
    nothing, so nothing of it is applied: it is not held, and the warning for it
    says to write the declared spelling, not that the chain applies its value.
    An empty mapping nested inside a value the file does set (``mcp: {}`` under
    ``global-settings``) is a part of a value the chain applies: the merge
    places it where the file wrote it, so it is held wherever the merged value
    there is a mapping. Read as "nothing of it is applied" at every level, that
    one nested ``{}`` said the whole value was ignored.
    """
    if isinstance(written, dict) and not written:
        return False
    return _value_held_as_merged(written, merged)


def _value_held_as_merged(written: Any, merged: Any) -> bool:
    """``_value_folded_into`` below its top level: a mapping is held when each
    of its keys is, under the merge's spelling rule, an empty mapping included;
    any other value is held when equal."""
    if isinstance(written, dict) and isinstance(merged, dict):
        for key, value in written.items():
            target = _resolve_dict_key(merged, key) if isinstance(key, str) else key
            if target not in merged or not _value_held_as_merged(value, merged[target]):
                return False
        return True
    return written == merged


_MISSING_IN_RECORD = object()


def _record_key(
    record: Dict[Any, Any], segment: Any, plugin_sections: bool = False
) -> Any:
    """The key of the mapping ``record`` that a rewrite's path segment names: a
    string by the merge's spelling rule (_resolve_dict_key); an index by itself,
    or, where the mapping keys the digits as text ("123"), by that text.

    A patch pointer's segment of digits is typed as an index when the rewrite
    is placed (_placed_rewrites), before anything says whether a list or a
    mapping holds it. Looked up as an index alone, a rewrite into a mapping
    keyed by a numeric string found no place, and the record kept the value
    read from the environment.

    With ``plugin_sections``, ``record`` is the dump of a plugin section
    container (the ``scanners``, ``reporters`` or ``converters`` segment), and
    a string segment the merge's spelling rule does not find is looked up as a
    plugin section too, by the rule the merge joins plugin sections with
    (``deep_merge`` under a ``_PluginConfigSegment`` model: the first key whose
    ``ash_config.plugin_key_lookup_names`` overlap the segment's): the extends
    merge joins two spellings of an undeclared plugin section (``s3`` and
    ``S3Reporter``) under the child's spelling, while a base's reference keeps
    the base's spelling in its path, so the record found no place for the
    rewrite and kept the value read from the environment. Applied at every
    depth, the lookup matched a plain mapping's ``Owner`` to a path's ``owner``
    and could pair a referenced key with another entry; the merge folds plugin
    names only directly under a plugin segment, so this does too."""
    if isinstance(segment, str):
        key = _resolve_dict_key(record, segment)
        if key in record or not plugin_sections:
            return key
        names = plugin_key_lookup_names(segment)
        for other in record:
            if isinstance(other, str) and plugin_key_lookup_names(other) & names:
                return other
        return key
    if segment not in record and str(segment) in record:
        return str(segment)
    return segment


def _record_child(model: Any, record: Any, segment: Any) -> Tuple[Any, Any]:
    """The key ``segment`` (a key the file wrote) has in ``record``, the dump of
    ``model``, and the part of ``model`` under it.

    A model's field is dumped under its name or its alias, and a file may write
    either. A mapping's key is the file's own, but spelled as the merged
    configuration spells it: ``extends`` folds a child's ``cloudwatch_logs``
    into the base's ``cloudwatch-logs`` (config_sources._resolve_dict_key, the
    rule merging uses), so the file's spelling is looked up by that rule. A
    list's index is the file's own.
    """
    from pydantic import BaseModel

    if isinstance(record, dict):
        if isinstance(model, BaseModel):
            for name, field in type(model).model_fields.items():
                if segment in (name, field.alias):
                    for key in (segment, name, field.alias):
                        if key is not None and key in record:
                            return key, getattr(model, name, None)
            extra = model.model_extra or {}
            key = _record_key(
                record, segment, plugin_sections=isinstance(model, _PluginConfigSegment)
            )
            if key in record:
                return key, extra.get(key)
        else:
            key = _record_key(record, segment)
            if key in record:
                child = model.get(key) if isinstance(model, dict) else None
                return key, child
    elif isinstance(record, list) and isinstance(segment, int):
        if 0 <= segment < len(record):
            # The model's list can be shorter than the record's: a patch that
            # added entries (runtime_patch._as_written).
            child = (
                model[segment]
                if isinstance(model, list) and segment < len(model)
                else None
            )
            return segment, child
    return _MISSING_IN_RECORD, None


def dumped_path(
    config: Any, dumped: Any, path: Tuple[Any, ...]
) -> Optional[Tuple[Any, ...]]:
    """``path``, a rewrite's path in its file's keys, in the keys of
    ``dumped``, a dump of ``config`` (a field's name or alias as the dump has
    it, a mapping key as the merged configuration spells it), or None where
    the dump has no such place. For following a rewrite through a JSON patch,
    whose pointers name the dump's keys."""
    model, node = config, dumped
    keys = []
    for segment in path:
        key, model = _record_child(model, node, segment)
        if key is _MISSING_IN_RECORD:
            return None
        keys.append(key)
        node = node[key]
    return tuple(keys)


def dumped_place(
    config: Any, dumped: Any, path: Tuple[Any, ...]
) -> Optional[Tuple[Tuple[Any, ...], Any]]:
    """``dumped_path`` of ``path``, with the part of ``config`` there: a model,
    a mapping, a list or a value. None where the dump has no such place."""
    model, node = config, dumped
    keys = []
    for segment in path:
        key, model = _record_child(model, node, segment)
        if key is _MISSING_IN_RECORD:
            return None
        keys.append(key)
        node = node[key]
    return tuple(keys), model


def _record_container(config: Any, record: Any, path: Tuple[Any, ...]) -> Any:
    """The part of ``record`` at ``path``, with the model under it, or missing."""
    model, node = config, record
    for segment in path:
        key, model = _record_child(model, node, segment)
        if key is _MISSING_IN_RECORD:
            return _MISSING_IN_RECORD, None
        node = node[key]
    return node, model


def recorded_value_at(config: Any, record: Any, path: Tuple[Any, ...]) -> Any:
    """What ``record``, a dump or the record of ``config``, holds at ``path``, a
    rewrite's path in its file's keys, or None where it holds nothing."""
    if not path:
        return None
    container, model = _record_container(config, record, path[:-1])
    if container is _MISSING_IN_RECORD:
        return None
    key, _ = _record_child(model, container, path[-1])
    return None if key is _MISSING_IN_RECORD else container[key]


def reads_back_as(
    config: Any, dumped: Any, path: Tuple[Any, ...], text: str, current: Any
) -> bool:
    """Whether the model reads ``text`` at ``path`` (a rewrite's path in its
    file's keys) as ``current``: ``dumped``, a dump of ``config``, with ``text``
    there, validated, holds ``current`` there. For a value the model made
    something other than a string of (a list of formats from one string), so the
    reference that read ``text`` is written only where it loads back as what the
    configuration holds. A copy of ``dumped`` is validated."""
    from pydantic import ValidationError

    keys = dumped_path(config, dumped, path)
    if not keys:
        return False
    trial = copy.deepcopy(dumped)
    node = trial
    for key in keys[:-1]:
        node = node[key]
    node[keys[-1]] = text
    try:
        rebuilt: Any = (
            type(config).model_validate(trial).model_dump(mode="json", by_alias=True)
        )
    except (ValidationError, ValueError, TypeError):
        return False
    for key in keys:
        try:
            rebuilt = rebuilt[key]
        except (KeyError, IndexError, TypeError):
            return False
    return bool(rebuilt == current)


def _resolves_back_to(written: str, current: str) -> bool:
    """Whether the loader reads ``written`` from the environment as ``current``,
    by the loader's own rule (resolve_env_references)."""
    try:
        return resolve_env_references(written) == current
    except ASHConfigSourceError:
        # A variable that is no longer set: the string is not read back.
        return False


@functools.lru_cache(maxsize=None)
def _lax_number_field(kind: type) -> Any:
    """A lax field of ``kind``, as a plugin's options model declares a number."""
    from pydantic import TypeAdapter

    return TypeAdapter(kind)


def _typed_by_field(kind: type, text: str) -> Any:
    """``text`` as a lax ``kind`` field types it, or None when it refuses it."""
    from pydantic import ValidationError

    try:
        return _lax_number_field(kind).validate_python(text)
    except ValidationError:
        return None


def typed_from(current: Any, text: Any) -> bool:
    """Whether ``current`` is the number a lax model typed from ``text``, a value
    read from the environment ("067" read as 67). Never for a bool. Public:
    ``utils.error_text.timeout_limit_token`` asks it too.

    The text is typed the way the field holding ``current`` types it. An int
    field holds the text's exact value ("067", "67.0", and digits past 2**53
    whether or not the text carries decimal zeros, which no float keeps) and
    refuses an exponent text or one ending in a point ("1e3", "67."), so no
    int reads as typed from those, and an int that only the text's nearest float
    equals is not typed from it (2**53 from "9007199254740993"). A float field
    holds the nearest float. A NaN typed from "nan" is typed from it, though it
    equals nothing."""
    if isinstance(current, bool) or not isinstance(current, (int, float)):
        return False
    if not isinstance(text, str):
        return False
    typed = _typed_by_field(int if isinstance(current, int) else float, text)
    if typed is None:
        return False
    if isinstance(current, float) and math.isnan(current):
        return math.isnan(typed)
    return bool(typed == current)


def record_of_config(
    config: Any, dumped: Any, mark: Optional[Callable[[str], Any]] = None
) -> Any:
    """``dumped``, a dump of ``config``, as the record of ``config``: each value
    and key its files read from the environment as the file wrote it, never the
    value.

    For what ASH writes or sends from a configuration: the ``ash_config`` of a
    results file (AshAggregatedResults), and the results a reporter sends off
    the host (to_simple_dict). The rewrites are the config's own
    (``_written_references``, environment_record_read), each at the path where
    its file wrote the reference: a string elsewhere equal to the value is left
    as it is. Where the string at that path is not the resolved value as a
    whole, only the part the variable gave is replaced. Without ``mark``, a
    number there that a model typed from the value ("067" read as 67) is
    replaced as the value is: a scanner's dump of its own config
    (ScannerPluginBase._config_as_written). A config loaded any
    other way (AshConfig.from_file, a results file) has no rewrites, and its
    dump is returned as it is.

    ``mark``, for a file written to be loaded again (config_writer), is applied
    to each string a rewrite puts in the record, value or key, and to nothing
    else, so a string that only looks like a reference stays text. With it, a
    string that holds the value with other text (one the model changed) is
    written as the reference only when the loader resolves that back to the
    same string (resolve_env_references), and then with an explicit ``!ENV``
    tag, which the loader resolves however the string is quoted. Any other such
    string is left as the configuration holds it, which the writer refuses to
    write as text (config_writer): a reference made of it would read as other
    text, or another variable. A client's patch is not one: a runtime patch
    drops the rewrite of a value an op wrote over (runtime_patch).
    """
    rewrites = list(getattr(config, "_written_references", None) or [])
    if not rewrites or not isinstance(dumped, dict):
        return dumped
    marked = mark if mark is not None else (lambda text: text)
    record = copy.deepcopy(dumped)
    for rewrite in rewrites:
        if rewrite.kind != "value" or not rewrite.path:
            continue
        container, model = _record_container(config, record, rewrite.path[:-1])
        if container is _MISSING_IN_RECORD:
            continue
        key, _ = _record_child(model, container, rewrite.path[-1])
        if key is _MISSING_IN_RECORD:
            continue
        current = container[key]
        if current == rewrite.resolved or (
            # A dump of a section a plugin's model typed: the number it read
            # from the variable's text. Not for a file written to be loaded
            # again, whose reference has to read back as the same value.
            mark is None and typed_from(current, rewrite.resolved)
        ):
            container[key] = marked(rewrite.written)
        elif (
            isinstance(current, str)
            and rewrite.environment_part
            and rewrite.environment_part in current
        ):
            # The one place the variable's part has in the string: at its
            # start, where the reference stands in the file's text, else the
            # first place it is found. Replacing every occurrence turned a
            # short value's other occurrences into references the file never
            # wrote, and garbled the record.
            part = rewrite.environment_part
            # Counted on the string as the configuration holds it, never on
            # the replaced text: a value that is a substring of its own
            # reference's spelling ("AB" under ${TAB}) is found again inside
            # the reference once written, and read as a second occurrence.
            repeated = current.count(part) > 1
            if repeated:
                # A record never holds the value: where it occurs again, every
                # occurrence is hidden, as the whole-string replace hid them,
                # since a value shown is the worse side.
                replaced = current.replace(part, rewrite.reference)
            elif current.startswith(part):
                replaced = rewrite.reference + current[len(part) :]
            else:
                replaced = current.replace(part, rewrite.reference, 1)
            if mark is None:
                container[key] = replaced
            elif not repeated and _resolves_back_to(replaced, current):
                # One reference, and nothing of the value left as text: a
                # string that holds the value again is left as the
                # configuration holds it, which the writer refuses to write.
                # Tagged: the loader reads a tagged string from the environment
                # however the emitter quotes it, and an untagged one only when
                # it is written plain.
                container[key] = mark("!ENV " + replaced)
        elif (
            mark is not None
            and current is not None
            and not isinstance(current, str)
            and rewrite.environment_part == rewrite.resolved
            and reads_back_as(config, dumped, rewrite.path, rewrite.resolved, current)
        ):
            # A value the model made something else of, a list from one string
            # (output_formats: ${VAR}): the reference, which loads back as it.
            container[key] = mark(rewrite.written)
    # Keys last, deepest first: a value's path holds the key as it was read.
    keys = [rewrite for rewrite in rewrites if rewrite.kind == "key"]
    for rewrite in sorted(keys, key=lambda item: len(item.path), reverse=True):
        container, _ = _record_container(config, record, rewrite.path)
        if not isinstance(container, dict) or rewrite.resolved not in container:
            continue
        written_key = marked(rewrite.written)
        if written_key != rewrite.resolved and written_key in container:
            # The mapping already holds an entry under the written key: the
            # rename would overwrite it, and the record would lose that
            # entry. The resolved key stays.
            continue
        renamed = {
            (written_key if key == rewrite.resolved else key): value
            for key, value in container.items()
        }
        container.clear()
        container.update(renamed)
    return record


def record_of_metadata(config: Any, dumped: Any) -> Any:
    """``dumped``, a dump of results metadata, with what it takes from
    ``config`` recorded as ``record_of_config`` records ``config``'s own fields.

    The metadata names the project as ``config.project_name`` and lists the
    scanners as the keys of ``config.scanners``, so where the configuration's
    files read one of them from the environment the metadata held the value.
    Each is recorded at the configuration's own place, through the same
    record: ``project_name`` as the field, each ``expected_scanners`` entry as a
    key of ``scanners``. A copy; a dump that is not a mapping, or a config with
    nothing to record, is returned as it is.
    """
    if config is None or not isinstance(dumped, dict):
        return dumped
    places: Dict[str, Any] = {}
    if "project_name" in dumped:
        places["project_name"] = dumped["project_name"]
    names = dumped.get("expected_scanners")
    if isinstance(names, list):
        places["scanners"] = {name: {} for name in names if isinstance(name, str)}
    record = record_of_config(config, places)
    if record is places:
        return dumped
    recorded = dict(dumped)
    if "project_name" in places:
        recorded["project_name"] = record.get("project_name")
    if isinstance(names, list) and isinstance(record.get("scanners"), dict):
        # Renaming keeps each key's position.
        renamed = dict(zip(places["scanners"], record["scanners"]))
        recorded["expected_scanners"] = [
            renamed.get(name, name) if isinstance(name, str) else name for name in names
        ]
    return recorded


# The shared bare-number boundary (utils.numeric_text): _typed_spellings
# drops a derived print it describes, and the Bedrock reporter's numeric-knob
# exclusion layers one leading sign on top of the same core, so the two
# redaction surfaces move together. It lives in a leaf module because both
# sides call it at module load.
_purely_numeric = purely_numeric

#: An integer rendering: the only long derived form distinctive enough to be
#: an anywhere needle. A float or exponent rendering that long is a generic
#: number whose anywhere match eats longer numbers ("100000.0" inside
#: "1100000.05").
_INTEGER_RENDERING = re.compile(r"[+-]?\d+")


def _typed_spellings(value: str) -> List[str]:
    """The spellings a model that types *value* as a number prints, other than
    *value*, kept only where redacting them cannot corrupt ordinary text.

    A plugin module's section is typed by the plugin's own model after the
    load, and laxly: "067", "+67" and "67.0" all load as 67, so a line prints
    67, which the variable's text no longer matches. The candidates are the
    integer's text when the number is whole, the ``:g`` form the quoted limit
    token uses, and the float's own text. Which finite spellings are kept: an
    INTEGER rendering of MIN_ANYWHERE_LENGTH or more is distinctive enough to
    identify the value (an account id's typed digits) and joins; a float or
    exponent rendering that long is a generic number whose anywhere match
    eats longer numbers ("100000.0" inside "1100000.05ms") and does not join
    by length. Any other spelling joins only when the value itself is
    MIN_REDACTED_LENGTH or longer --
    hidden beyond its quoted form, so a plugin's own exception naming the
    typed float ("-67.0", "1e+20") must not print a spelling of it -- and
    the spelling is not a bare unsigned number (_purely_numeric: "67.0",
    "1000" corrupt line numbers and versions, and the records that print a
    typed limit redact the quoted token from the limit they hold;
    tests/unit/base's failure-line cells pin both sides). A short value's
    prints keep the drop its own band gives it: "-10" is only
    quoted-redacted, so "-10.0" identifies nothing a line hides. A non-finite
    number's own
    spellings (inf, -inf, nan) always join, as a float option types
    "Infinity", "+nan" or "1e999" and a line prints the word, which no record
    redacts for itself (the non-finite cells in the same file pin that); they
    are words, not the generic numbers the length rule exists to drop. The
    value as written is the caller's needle whatever its shape, never this
    function's to drop. Empty for a value that is not a number.
    """
    text = value.strip()
    try:
        number = float(text)
    except ValueError:
        return []
    # A non-finite number flows through the same path as a finite one:
    # int(text) refuses its text, the int-typed fallbacks add nothing
    # (is_integer() is False for inf and nan), and the tail's {number:g} and
    # str(number) are the float's own spellings.
    spellings: List[str] = []
    try:
        # int() itself for a whole-number text, so a long one keeps its digits.
        spellings.append(str(int(text)))
    except ValueError:
        # A whole number int() refuses but an int field types exactly: one
        # written with decimal zeros, whose digits past 2**53 the float below
        # does not keep ("12345678901234567891.0" is 12345678901234567891).
        whole = _typed_by_field(int, text)
        if whole is not None:
            spellings.append(str(whole))
        elif number.is_integer():
            # Only when no int field types the text exactly: past 2**53 the
            # nearest float's digits are a number the variable did not give
            # (_typed_from), and no model prints them for this value.
            spellings.append(str(int(number)))
    spellings += [f"{number:g}", str(number)]
    if not math.isfinite(number):
        # inf, -inf and nan join whatever their length: the length rule drops
        # generic-looking numbers, and these are the words a line prints for
        # the typed value. redact_values bounds the short ones to their
        # quoted form as it does every short value.
        return [spelling for spelling in dict.fromkeys(spellings) if spelling != value]
    return [
        spelling
        for spelling in dict.fromkeys(spellings)
        if spelling != value
        and (
            (
                len(spelling) >= MIN_ANYWHERE_LENGTH
                and _INTEGER_RENDERING.fullmatch(spelling) is not None
            )
            or (len(text) >= MIN_REDACTED_LENGTH and not _purely_numeric(spelling))
        )
    ]


def environment_record_read(
    chain: Iterable[Path],
    reads: Dict[Path, Any],
    texts: Optional[Dict[Path, str]] = None,
    places: Optional[Dict[Tuple[Any, ...], List[Tuple[Any, ...]]]] = None,
) -> Tuple[List[str], List[EnvironmentRewrite]]:
    """The values and keys the files of a resolved chain read from the
    environment, and how to record each value as the file wrote it, for a chain
    whose files were read already.

    ``reads`` holds what ``read_config_file`` returned for each file, by its
    resolved path, as a reader that keeps what it reads records it, and
    ``texts`` the text that was parsed from. Each file is parsed once more
    from that text, as written (parse_config_text_literally, keeping ``!ENV``
    tags), with nothing read from the environment and no ``!ENV`` warning
    logged: both views are of one read, so a file changed since cannot make
    them disagree. A file with no text here is read again as written, and one
    ``reads`` lacks is read both ways.

    Returns the values and keys the chain read from the environment, for
    redacting what is printed (with, for a value that reads as a number, the
    spellings a model that types it prints, under _typed_spellings' own
    rule), and the rewrites that turn the configuration
    into its record (AshAggregatedResults.ash_config in a results file), which
    keeps each reference exactly as the file wrote it and never the value. Each
    rewrite is at the place its value has in the configuration. ``places`` is
    the load's (ResolvedConfigDocument.reference_places): where each reference
    a file wrote ended up once every ``patch`` of the chain applied, an insert
    in front of it or a remove before it included, none for one an operation
    wrote over. A rewrite it does not know is placed by its file alone
    (_placed_rewrites): a patch operation's at the operation's path, with an
    append's index left for placed_at_appends to fill in. That placing missed
    an operation after the one that put the value, and gave two equal appends
    one index, so the record named another entry and kept the value.
    """
    values: List[str] = []
    rewrites: List[EnvironmentRewrite] = []
    texts = texts or {}
    for path in dict.fromkeys(chain):
        key = Path(path).resolve()
        resolved = reads.get(key, _READ_THE_FILE)
        try:
            if resolved is _READ_THE_FILE:
                resolved = read_config_file(path)
            if key in texts:
                written = parse_config_text_literally(
                    path, texts[key], keep_env_tags=True
                )
            else:
                written = read_config_file_as_written(path)
            # Folded as the load folded the document (plugin_section_names),
            # so a rewrite under a respelled known-plugin section carries the
            # place the record and the dump use. Copies: the caller's
            # ``reads`` cache keeps the file as parsed.
            resolved = fold_known_plugin_sections(resolved)
            written = fold_known_plugin_sections(written)
        except (ASHConfigSourceError, yaml.YAMLError, OSError, ValueError):
            # Read once already for the load; one that cannot be read again
            # holds nothing to redact or rewrite.
            continue
        for value, _ in _interpolated_pairs(written, resolved):
            values.append(value)
            # The value as written always joins -- an all-digits value can be
            # an account id, which is exactly what the needles exist to hide.
            # The derived spellings a typing model prints join by
            # _typed_spellings' own rule: a bare unsigned number ("10.0",
            # "1000") never joins, because hiding it corrupts text that
            # legitimately contains it ("10.0" inside "10.0.0.5" or
            # "110.05s"); a short signed or exponent print of a value that is
            # itself redacted ("-67.0", "1e+20") joins, so a plugin's own
            # words cannot print a spelling of a hidden value; and a long
            # typed form (the 11 digits an int field prints for
            # "012345678901") stays a needle.
            values += _typed_spellings(value)
        # At the place each value has in the configuration: where the load
        # followed it to, or else where its file puts it.
        for rewrite in _written_rewrites(written, resolved):
            place = ((key, tuple(rewrite.path)), rewrite.kind == "key", rewrite.written)
            if places is not None and place in places:
                rewrites += [rewrite._replace(path=at) for at in places[place]]
            else:
                rewrites += _placed_rewrites([rewrite], resolved)
    return values, rewrites


def environment_record_of_references(
    references: Iterable[Any],
) -> Tuple[List[str], List[EnvironmentRewrite]]:
    """What ``environment_record_read`` gives for the files of a chain, for
    ``references`` that were read some other way.

    For the references a profile copy a client patched was filled with
    (environment_record.fill_environment_references): that copy holds each
    reference as text, so reading its file pairs nothing, and the references
    are the operator's copy's, each at the path the fill read it at. Each gives
    the rewrite the same reference gives when its own file is read, and its
    resolved string and the part the variable gave join the values, with the
    spellings a typing model prints (``_typed_spellings``), as
    ``environment_record_read`` adds them. A key's reference is at the path of
    its mapping, as a file's rewrite for a key is.
    """
    values: List[str] = []
    rewrites: List[EnvironmentRewrite] = []
    for reference in references:
        rewrite = _rewrite_for(
            "key" if reference.key else "value",
            tuple(reference.path),
            reference.written,
            reference.resolved,
        )
        rewrites.append(rewrite)
        for value in dict.fromkeys((rewrite.resolved, rewrite.environment_part)):
            if value:
                values.append(value)
                values += _typed_spellings(value)
    return values, rewrites


#: Written as \xNN when a results file's error is printed: every C0 control
#: (newline and tab included), DEL and C1. A key holding ESC sequences reached the
#: terminal, and one holding a newline put a line starting "::error" on the
#: console, which GitHub Actions reads as a workflow command.
_RESULTS_TEXT_CONTROLS = re.compile(r"[\x00-\x1f\x7f-\x9f]")

#: Printed in a location in place of a mapping key that is not a field name.
_REDACTED_KEY = "<key>"


def describe_results_error(error: BaseException) -> str:
    """Why a results file could not be read, without repeating any of it.

    A results file holds finding data: snippets, paths, and keys a scanner or a
    configuration chose. pydantic's own text for a ValidationError quotes each
    input as ``input_value='...'``, an error's location names every mapping key
    on its path, and ASH's validators quote the value they refuse. So each error
    is given as format_model_error gives it, ``Invalid value at '<loc>':
    <message>``, where:

    - a location part is printed only when it is a field name, alias or model
      name of the results schema, an index as ``[n]``, and ``<key>`` otherwise;
    - every string of the input, and the same string stripped, is replaced in the
      message by REDACTED, except for invalid JSON, whose message gives a line and
      column and no input (metadata.generated_at is parsed after .strip(), and its
      error quotes what was parsed);
    - control characters are written as ``\\xNN``.

    A file that is not UTF-8 is described by the offset of the first bad byte;
    the decoder's own text prints the byte. ash merge describes an unreadable
    shard the same way (cli/merge.py's _describe_unreadable_shard).
    """
    from pydantic import ValidationError

    if isinstance(error, UnicodeDecodeError):
        text = f"not UTF-8 at byte offset {error.start}"
    elif isinstance(error, ValidationError):
        names = _results_schema_names()
        problems = []
        for item in error.errors(include_url=False):
            location = ""
            for part in item["loc"]:
                if isinstance(part, int):
                    location += f"[{part}]"
                else:
                    shown = part if part in names else _REDACTED_KEY
                    location += f".{shown}" if location else shown
            message = str(item["msg"])
            if item["type"] != "json_invalid":
                leaves = _string_leaves(item.get("input"))
                message = redact_values(
                    message,
                    leaves + [leaf.strip() for leaf in leaves],
                    whole_words=True,
                )
            problems.append(
                f"{ConfigValidator.MODEL_ERROR_PREFIX}{location or '(top level)'}': "
                f"{message}"
            )
        text = "; ".join(problems)
    else:
        text = str(error)
    return _RESULTS_TEXT_CONTROLS.sub(lambda m: "\\x%02x" % ord(m.group()), text)


@functools.lru_cache(maxsize=1)
def _results_schema_names() -> frozenset:
    """Every field name, alias and model name reachable from AshAggregatedResults.

    The location of a pydantic error mixes these with the keys of mappings the
    file chose (a scanner's name in scanner_results, a key the schema forbids),
    which are data. Measured: 1077 names over 300 models, in about 3 ms.
    """
    from pydantic import BaseModel

    from automated_security_helper.models.asharp_model import AshAggregatedResults

    names: set = set()
    seen: set = set()

    def visit(annotation: Any) -> None:
        if isinstance(annotation, type) and issubclass(annotation, BaseModel):
            if annotation in seen:
                return
            seen.add(annotation)
            names.add(annotation.__name__)
            for name, info in annotation.model_fields.items():
                names.add(name)
                if info.alias:
                    names.add(info.alias)
                if isinstance(info.validation_alias, str):
                    names.add(info.validation_alias)
                visit(info.annotation)
            return
        for argument in typing.get_args(annotation):
            visit(argument)

    visit(AshAggregatedResults)
    return frozenset(names)


# check_config_file's default for config_data: read the file itself.
_READ_THE_FILE: Any = object()
#: An option the trusted base does not set (``_ignored_reporter_destinations``):
#: distinct from ``None``, which a base can write as a value.
_MISSING_OPTION: Any = object()


@functools.lru_cache(maxsize=None)
def _built_in_section_classes(segment_name: str) -> Dict[str, type]:
    """Each built-in plugin's config class in a segment, by the keys the model reads.

    The field name and its alias (``cdk_nag`` and ``cdk-nag``): the spellings the
    segment model validates against the plugin's own config class.
    """
    # Imported here: ash_config imports the config package, and this module is
    # imported by the linter at CLI start-up.
    from pydantic import BaseModel

    from automated_security_helper.config.ash_config import (
        ConverterConfigSegment,
        ReporterConfigSegment,
        ScannerConfigSegment,
    )

    segments: Dict[str, type[BaseModel]] = {
        "scanners": ScannerConfigSegment,
        "reporters": ReporterConfigSegment,
        "converters": ConverterConfigSegment,
    }
    segment_cls = segments[segment_name]
    classes: Dict[str, type] = {}
    for field_name, info in segment_cls.model_fields.items():
        config_class = next(
            (
                candidate
                for candidate in typing.get_args(info.annotation) or (info.annotation,)
                if isinstance(candidate, type) and issubclass(candidate, BaseModel)
            ),
            None,
        )
        if config_class is None:
            continue
        for spelling in (field_name, info.alias):
            if spelling:
                classes[spelling] = config_class
    return classes


# A path that starts at a filesystem root: "/x", or a drive, "C:/x", once
# backslashes are read as separators, as the matcher reads them.
_ABSOLUTE_PATH_PATTERN = re.compile(r"^(?:/|[A-Za-z]:/)")

#: What follows "Path '<pattern>' " in absolute_path_warning, which the linter
#: reads back to fold the validator's copy of the warning into its own.
ABSOLUTE_PATH_MESSAGE = "is absolute, so it matches nothing"

_DRIVE_PATH_PATTERN = re.compile(r"^[A-Za-z]:/")
_GLOB_CHARACTERS = frozenset("*?[")


#: Path components that do not name an entry below the one before them.
_DOT_COMPONENTS = frozenset({".", ".."})


def _names_something_under(relative: str, project_root: Path) -> bool:
    """Whether the part of ``relative`` before its first glob exists in the root.

    False for a part that is "." or "..": ".." leaves the root, so what it names
    is not under it.
    """
    literal = []
    for part in relative.split("/"):
        if part in _DOT_COMPONENTS:
            return False
        if not part or _GLOB_CHARACTERS & set(part):
            break
        literal.append(part)
    if not literal:
        return False
    try:
        return Path(project_root, *literal).exists()
    except (OSError, ValueError):
        return False


def _is_directory_under(relative: str, project_root: Path) -> bool:
    """Whether ``relative``, with no glob in it, is a directory in the root."""
    if not relative or _GLOB_CHARACTERS & set(relative):
        return False
    try:
        return Path(project_root, relative).is_dir()
    except (OSError, ValueError):
        return False


_REPEATED_SLASHES = re.compile(r"/{2,}")


def _relative_through_links(form: str, project_root: Path) -> str:
    """The rest of the absolute ``form`` under the root when its literal part
    (before any glob) reaches the root through a symbolic link: the pattern
    spelled through a linked path to the scanned tree, where the root is
    resolved (``source_dir.resolve()``). Empty when it does not."""
    literal: List[str] = []
    tail: List[str] = []
    for part in form.split("/"):
        if tail or (part and _GLOB_CHARACTERS & set(part)):
            tail.append(part)
        else:
            literal.append(part)
    if len(literal) < 2 or _DOT_COMPONENTS & set(literal):
        return ""
    try:
        real = Path(os.path.realpath("/".join(literal))).as_posix()
    except (OSError, ValueError):
        return ""
    root = project_root.as_posix().rstrip("/") + "/"
    if not real.startswith(root):
        return ""
    return "/".join([real[len(root) :], *tail]) if tail else real[len(root) :]


def absolute_path_warning(
    path_pattern: Any,
    project_root: Path,
    *,
    ignore_path: bool = True,
    shown_pattern: Optional[str] = None,
) -> Optional[str]:
    """The warning for an ignore or suppression ``path`` that is absolute, or None.

    The matcher compares ``path`` with file paths relative to the scan root
    (utils/path_matching.py), so an absolute pattern matches nothing anywhere,
    and the files it names are scanned. ``ash config lint`` and ``ash config
    validate`` both report it, with the spelling that matches when there is
    one:

    * a pattern under ``project_root``: the rest of it after the root, compared
      case-insensitively only for a Windows path, a drive (``C:/...``) or a
      root on a UNC share (``//server/share/repo``), as Windows does;
    * ``/x``: ``x``, when what ``x`` names before any glob exists under the root
      (``/vendor/**`` for the root's ``vendor``);
    * otherwise, a drive or a UNC share (``//server/share``) outside the root,
      ``/x`` that names nothing under it, or a rest that holds a "." or ".."
      component (``..`` leaves the root): none, only "write it relative".

    A remainder that ends in ``/``, or that has no glob and is a directory in
    the root, names a directory, and is spelled as
    ``path_matching.directory_spelling`` spells it: ``dir/`` for an ignore path
    (``ignore_path``), ``dir/**/*`` for a suppression path, whose ``dir/**``
    would also match a file named ``dir``. ``dir`` alone matches only a file of
    that name.

    The message names the path as ``shown_pattern`` (None: as it is), the path
    with each part the config read from the environment shown as ``<value>``.
    Such a path gets no spelling, only "write it relative": the spelling is a
    piece of the path, which ``<value>`` does not hide.
    """
    if not isinstance(path_pattern, str):
        return None
    if shown_pattern is None:
        shown_pattern = path_pattern
    read_from_environment = shown_pattern != path_pattern
    form = path_pattern.replace("\\", "/")
    if not _ABSOLUTE_PATH_PATTERN.match(form):
        return None
    root = project_root.as_posix().rstrip("/") + "/"
    drive = _DRIVE_PATH_PATTERN.match(form) is not None
    windows = drive or root.startswith("//")
    under_root = (
        form.lower().startswith(root.lower()) if windows else form.startswith(root)
    )
    if read_from_environment:
        relative = ""
    elif under_root:
        # The rest after the root, with the slashes a doubled separator leaves
        # ('/root//build') taken out: left in, the rest was '/build', which
        # joined to the root is the host's '/build', and the advice another
        # absolute pattern.
        relative = _REPEATED_SLASHES.sub("/", form[len(root) :]).lstrip("/")
    elif drive or form.startswith("//"):
        # A drive, or a UNC share, outside the root.
        relative = ""
    elif _names_something_under(form.lstrip("/"), project_root):
        relative = form.lstrip("/")
    else:
        relative = _relative_through_links(form, project_root)
    if _DOT_COMPONENTS & set(relative.split("/")):
        relative = ""
    if relative and windows:
        # The root was compared as Windows compares it; the matcher compares
        # case-sensitively, so the rest is spelled as the tree spells it.
        relative = _with_tree_spelling(relative, project_root)
    if relative.endswith("/") or _is_directory_under(relative, project_root):
        relative = directory_spelling(relative, ignore_path=ignore_path)
    advice = (
        f"Use '{relative}' for the path under the scan root."
        if relative
        else "Write it relative to the scan root."
    )
    return (
        f"Path '{shown_pattern}' {ABSOLUTE_PATH_MESSAGE}: ignore and suppression "
        f"paths are matched relative to the scan root. {advice}"
    )


class _AshConfigCheck(typing.NamedTuple):
    """What ConfigValidator._ash_config_check found for the file ASH_CONFIG
    names: the scan's refusals of it, the configuration it loads to (None when
    refused, unset, or the checked file itself), whether it is the checked
    file, and whether a file of its chain is inside the scanned trees, as its
    one load found."""

    errors: List[str]
    loaded: Any
    is_the_checked_file: bool
    in_tree: bool


class ConfigValidator:
    """Validates ASH configuration files for common issues."""

    # Fields that should NOT appear in user configs (internal-only). The model
    # refuses those a section does not declare (utils/unknown_keys.py).
    INTERNAL_SCANNER_FIELDS = set(INTERNAL_SECTION_FIELDS["scanners"])

    INTERNAL_REPORTER_FIELDS = set(INTERNAL_SECTION_FIELDS["reporters"])

    INTERNAL_CONVERTER_FIELDS = set(INTERNAL_SECTION_FIELDS["converters"])

    # Top-level fields that should NOT appear in user configs
    INVALID_TOP_LEVEL_FIELDS = {
        "build",
    }

    # Top-level fields a config is expected to set. The model gives each a
    # default, so a scan accepts a config without them, and a missing one is a
    # warning (MISSING_PROJECT_NAME_MESSAGE), not an error.
    REQUIRED_TOP_LEVEL_FIELDS = {
        "project_name",
    }

    # Valid top-level fields
    VALID_TOP_LEVEL_FIELDS = {
        "project_name",
        "fail_on_findings",
        "fail_on_incomplete_scanners",
        "content_db_staleness",
        "content_db_staleness_overrides",
        "honor_ignore_files",
        "content_db_staleness_offline_image_default",
        "sandbox",
        "ash_plugin_modules",
        "external_reports_to_include",
        "global_settings",
        "scanners",
        "reporters",
        "output_formats",
        "converters",
        # The alias, and the field name, which a scan reads as the alias.
        "mcp-resource-management",
        "mcp_resource_management",
        # Workspace-mode execution settings. Valid at the top level rather than
        # internal-only, because an operator scanning a multi-project workspace
        # sets max_parallel_projects and project_timeout by hand.
        "workspace",
        # Loader directives (#289), resolved before the config is validated.
        EXTENDS_KEY,
        PATCH_KEY,
        # A JSON config's schema reference, which editors read; a scan ignores it.
        "$schema",
    }

    # Prefix of every error about a config's `extends` chain or `patch`, which
    # ConfigLinter maps to its own category.
    EXTENDS_ERROR_PREFIX = "Config extends error: "

    # Prefix of the error for an `extends` base that `permit_base` refused. Its
    # own prefix so a caller can tell a refusal from a broken chain.
    NOT_PERMITTED_ERROR_PREFIX = "Config input not permitted: "

    # Prefix of the error for a file an MCP client delivered that reads from the
    # environment (ASHConfigEnvNotResolvedError), the file checked or a base.
    ENV_NOT_RESOLVED_ERROR_PREFIX = "Config reads the environment: "

    # Prefix of every error for a value the AshConfig model refuses. What follows
    # it, up to "': ", is the field's dotted path.
    MODEL_ERROR_PREFIX = "Invalid value at '"

    # Prefix of the error for a config file whose text does not parse, by its
    # format: the category mcp_validate_config types the error by, never the
    # message's words, the parser's class name or the path.
    PARSE_ERROR_PREFIXES = {
        "TOML": "TOML parsing error: ",
        "YAML": "YAML parsing error: ",
        "JSON": "JSON parsing error: ",
    }

    # The project_name warning. project_name has a default, so a scan accepts a
    # config without it; the check stays because reports are labeled with it.
    MISSING_PROJECT_NAME_MESSAGE = (
        "Top-level field 'project_name' is not set, so reports name the project "
        "'ash-scan' (or the ASH_PROJECT_NAME environment variable)"
    )

    LEGACY_MISSING_PROJECT_NAME_MESSAGE = (
        "Missing required top-level field: 'project_name'"
    )

    @classmethod
    def check_config_file(
        cls,
        config_path: Path,
        source_dir: Optional[Path] = None,
        permit_base: Optional[Callable[[Path], bool]] = None,
        config_overrides: Optional[List[str]] = None,
        config_data: Any = _READ_THE_FILE,
        check_ash_config: bool = True,
        config_text: Optional[str] = None,
        untrusted_config: bool = False,
        additional_plugin_modules: Sequence[str] = (),
        expect: Optional[FileIdentity] = None,
        refuse_env: Optional[Callable[[Path], bool]] = None,
    ) -> "ConfigCheck":
        """Check a config file the way a scan loads it, and lint its structure.

        ``expect`` is ``identity_to_hold(config_path)`` as the caller took it when
        it checked the path: every read here is held to that file, so one
        swapped in after the check is refused ("Could not read the config file")
        and not checked. That covers the reads after the first too: a name that
        a symbolic link repointed since reaches another file, which the loader
        and the plugin-module check would otherwise read while the structural
        checks describe the first. Without it the identity is taken when this
        check starts. An ``extends`` base is held to the identity taken when the
        chain walk vetted it.

        ``refuse_env`` is which files of the chain may not read the environment,
        as ``config_sources.resolve_config_document`` takes it; None refuses the
        files an MCP client delivered. It is applied in the one read each file
        gets here, the named file's first and then each base's: a file it
        refuses whose text reads the environment is refused before any of its
        references is resolved, in one sentence whether or not the variable is
        set, and every base of a refused file is refused with it.

        ``untrusted_config`` True judges the file as a scan judges one a client
        supplied (``resolve_config(untrusted_config=True)``): the whole chain
        counts as in-tree for the plugin-module check, so a not-installed entry
        is dropped there rather than refused.

        ``check_ash_config`` False leaves out the check of the file ASH_CONFIG
        names (``ash_config_errors`` stays empty), for a caller that holds that
        file's refusal already: the check loads the file, and logs it, again.

        The file is read with ``read_config_file`` (so ``!ENV`` references
        resolve, and a ``pyproject.toml`` yields its ``[tool.ash]`` table), then
        loaded by ``load_config_file``, the function every scan loads a config
        file with: its ``extends`` chain and ``patch``, then the AshConfig model
        with strict types and ``config_overrides``. Every file goes through it,
        one without ``extends`` too, so a refusal the loader makes is one the
        check makes, in the scan's words. Anything that fails is in ``errors``:
        a scan refuses that config with exit 3 before any scanner runs, a file
        that does not parse (``ignored_by_scan``) included.

        No message repeats a value of the config (see ``format_model_error``) or
        one it read from the environment (``environment_values``).

        The structural checks (internal-only fields, unknown or internal
        top-level keys, duplicate keys, a missing project_name, directory paths
        without ``**``) look for things a scan tolerates, so they are
        ``warnings``. They read the file's own keys, since that is the file a fix
        would edit; project_name and the path patterns are read from the merged
        result, because a base may supply them.

        Args:
            config_path: Path to the configuration file.
            source_dir: The directory a scan would scan, as ``--source-dir``: it
                bounds where ``extends`` bases may be, and ignore_path patterns are
                resolved against it. If None, inferred from config_path location,
                as ``resolve_config`` does for a config path with no source dir.
            permit_base: Optional check every ``extends`` base must also pass;
                see ``config/config_sources.py``.
            config_overrides: ``key.path=value`` overrides, applied as
                ``--config-overrides`` applies them to a scan.
            config_data: The file's contents as ``read_config_file`` returned
                them, for a caller that has read the file already (the linter).
                Reading it again would log each ``!ENV`` warning again, so the
                check reads each file of an ``extends`` chain once.
            config_text: The text ``config_data`` was parsed from
                (read_config_text), with it. The values the messages are
                redacted with, and the structural checks, come from that one
                text: a file changed since cannot give values the check never
                read. Without it the file's text is read here.
        """
        result = ConfigCheck()
        config_path = Path(config_path)
        # A caller's str source_dir: the path checks call .resolve() on it,
        # and an AttributeError there escaped the structural checks' guard.
        if source_dir is not None:
            source_dir = Path(source_dir)
        is_toml = is_toml_file(config_path)
        if expect is None:
            # Every read below opens the file this one names, whichever name
            # leads where by then.
            expect = identity_to_hold(config_path)

        try:
            if config_data is _READ_THE_FILE:
                config_text = read_config_text(config_path, expect=expect)
                config_data = parse_config_text(
                    config_path, config_text, refuse_env=refuse_env
                )
            elif config_text is None:
                # The caller read it already, without its text: read once here
                # for the checks below. (refuse_unless_a_file inside: a FIFO's
                # open waits for a writer.)
                config_text = read_config_text(config_path, expect=expect)
            else:
                refuse_unless_a_file(config_path)
        except ASHConfigEnvNotResolvedError as e:
            # A file an MCP client delivered that reads from the environment,
            # refused before it was read with it, as a scan refuses it.
            result.errors.append(f"{cls.ENV_NOT_RESOLVED_ERROR_PREFIX}{e}")
            return result
        except ASHConfigSourceError as e:
            # TOML that does not parse, or a pyproject.toml without [tool.ash]: a
            # scan refuses these. A parse refusal carries its format's category
            # prefix, the classifier's contract (mcp_validate_config types by
            # prefix, never by words of the message or the path). The prefix
            # is the format of the file that was parsed: a TOML file's decode
            # and parse refusals, and a file of any format nested past the
            # recursion limit (parse_config_text), all arrive as one
            # ASHConfigUnparsedError.
            if isinstance(e, ASHConfigUnparsedError):
                if is_toml:
                    parse_format = "TOML"
                elif is_json_file(config_path):
                    parse_format = "JSON"
                else:
                    parse_format = "YAML"
                result.errors.append(f"{cls.PARSE_ERROR_PREFIXES[parse_format]}{e}")
                # A parse refusal, like its YAML and JSON twins below: since
                # the shared formatter every format's parse refusal is one
                # ASHConfigUnparsedError through one sentence, so the verdict
                # built from this check says the file does not parse for TOML
                # too. The subtree's non-parse refusals keep the
                # generic verdict.
                result.ignored_by_scan = True
            else:
                result.errors.append(f"TOML error: {e}" if is_toml else str(e))
            return result
        except yaml.YAMLError as e:
            # The parser's own words can quote the file (unparsed_config_reason).
            result.errors.append(
                cls.PARSE_ERROR_PREFIXES["YAML"]
                + unparsed_config_reason(config_path, e)
            )
            result.ignored_by_scan = True
            return result
        except json.JSONDecodeError as e:
            result.errors.append(
                cls.PARSE_ERROR_PREFIXES["JSON"]
                + unparsed_config_reason(config_path, e)
            )
            result.ignored_by_scan = True
            return result
        except UnicodeDecodeError as e:
            # The decoder's message gives the bad byte's value; the formatter
            # gives its offset and nothing from the file. The format's category
            # prefix is the classifier's contract (mcp_validate_config types by
            # prefix, never by words of the message or the path), and a
            # TOML file's decode failure arrives above as ASHConfigSourceError.
            kind = "JSON" if is_json_file(config_path) else "YAML"
            result.errors.append(
                cls.PARSE_ERROR_PREFIXES[kind] + unparsed_config_reason(config_path, e)
            )
            result.ignored_by_scan = True
            return result
        except OSError as e:
            result.errors.append(f"Could not read the config file: {e}")
            result.ignored_by_scan = True
            # A read failure, not a parse: a header built from this check says
            # read, so a reader is not sent to fix syntax the check never saw.
            # (A file that is not UTF-8 was read; its decode failure arrives
            # in the arms above, never here.)
            result.could_not_read = True
            return result
        except ValueError as e:
            # A constructor's ValueError (!!int, !!float) quotes the file; the
            # shared refusal gives its type and nothing from it, under
            # the format's category prefix, the classifier's contract.
            # Of ASH's own refusals, only the ASHConfigSourceError subtree is
            # handled above; the rest, and pydantic's ValidationError, are
            # excluded ValueErrors and stay theirs to show.
            if not is_config_parse_error(e):
                raise
            kind = "JSON" if is_json_file(config_path) else "YAML"
            result.errors.append(
                cls.PARSE_ERROR_PREFIXES[kind] + unparsed_config_reason(config_path, e)
            )
            result.ignored_by_scan = True
            return result

        # The path the name resolves to, taken straight after the first read: the
        # file that read opened, unless the name was repointed in the instants
        # between its open and this line (a window this does not close). The
        # caches below are keyed by it, so a later read of a name repointed
        # since misses them and is held to the first read's identity, where a
        # key taken after the steps that follow (the repository settings among
        # them) would be the other file's path and would serve this file's data
        # for it, unread and unchecked.
        root_key = config_path.resolve()
        result.config_data = config_data
        result.environment_values = cls.environment_values_of(
            config_path, config_data, config_text
        )
        # The file's own references, at the place it writes each, from the same
        # text; the chain's follow once it resolves.
        result.file_references = cls.file_references_of(
            config_path, config_data, config_text
        )
        result.references = list(result.file_references)

        # Imported here: resolve_config imports the config package, and this
        # module is imported by the linter at CLI start-up.
        from automated_security_helper.config.operator_only_options import (
            repository_settings_for_root,
        )
        from automated_security_helper.config.operator_paths import (
            the_operators_files,
        )
        from automated_security_helper.config.resolve_config import (
            ConfigFileRefused,
            load_config_file,
        )
        from automated_security_helper.config.sandbox_grants import (
            working_directory,
        )

        # As resolve_config reads the file for a scan of source_dir (of the
        # working directory without one): what a file inside the scanned tree
        # writes for an option only the operator sets is left out before the
        # model validates the document, and the check says the scan ignores it.
        # With neither (the working directory deleted while the process runs),
        # the check confines fail-closed, every checkout file treated as the
        # repository's, so it still warns about what such a scan ignores.
        repository = repository_settings_for_root(
            Path(source_dir) if source_dir is not None else working_directory(),
            every_file=untrusted_config,
        )

        # The loader reads the root again; hand it, and the environment check
        # below, what was read already, so no file is parsed twice.
        reads: Dict[Path, Any] = {root_key: config_data}
        # Each file's text, for its as-written view (environment_values_of).
        texts: Dict[Path, str] = {root_key: config_text}

        def read_once(path: Path, expect: Optional[FileIdentity] = None) -> Any:
            key = Path(path).resolve()
            if key not in reads:
                # ``expect`` is the identity the chain walk vetted for a base
                # (a caller's reader that takes it is handed it); a read
                # nothing vetted gets the file's identity now (the identity no
                # file has when the path leads nowhere), as resolve_config's
                # reader does.
                if expect is None:
                    expect = identity_to_hold(path)
                texts[key] = read_config_text(path, expect=expect)
                reads[key] = parse_config_text(path, texts[key])
            return reads[key]

        document = None
        built = None
        chain_resolved = True
        refused: Optional[ConfigFileRefused] = None
        try:
            document, built = load_config_file(
                config_path,
                source_dir=source_dir,
                permit_base=permit_base,
                config_overrides=config_overrides,
                reader=read_once,
                texts=texts,
                confine=repository.confine,
                repository_file=repository.is_repository_file,
                refuse_env=refuse_env,
                # As the scan reads the chain (resolve_config): an operator
                # file's relative tool paths are taken from its own directory,
                # so the documents checked here hold what the scan holds.
                anchor_relative_paths=(
                    None if untrusted_config else the_operators_files(repository.trees)
                ),
                expect=expect,
            )
        except ConfigFileRefused as refusal:
            document = refusal.document
            refused = refusal
        except ASHConfigSourceError as e:
            # Named by place in config_sources: a base the environment chose,
            # and every base below it, is <value>.
            result.errors.append(cls._chain_error(e))
            chain_resolved = False
        except OSError as e:
            # The loader read the root again and it is not the file this check
            # read first (a link repointed since: ESTALE), or it cannot be read
            # now. What the structural checks below would say describes a file
            # the loader never saw, so nothing more is checked.
            result.errors.append(f"Could not read the config file: {e}")
            result.ignored_by_scan = True
            result.could_not_read = True
            return result

        resolved_data = config_data
        result.chain = [config_path]
        if document is not None:
            # A `patch` can leave a document that is not a mapping. The model
            # reports that as a scan does; the structural checks below read
            # the file's own keys and skip what needs a mapping.
            resolved_data = document.data
            result.chain = list(document.chain)
            result.references += document.environment_references
            result.environment_paths = frozenset(document.environment_paths)
            # Held for a judgment of the same files that reads none a second
            # time: the chain's documents and names, and the text of each file
            # of the chain (not of every file a check along the way read).
            result.documents = document.documents
            result.document_names = document.names
            result.texts = {
                path: texts[path] for path in document.documents if path in texts
            }
            for base in result.chain[:-1]:
                result.environment_values += cls.environment_values_of(
                    base,
                    reads.get(Path(base).resolve(), _READ_THE_FILE),
                    texts.get(Path(base).resolve()),
                )
        # The copies the messages quote: each value and key a file read from
        # the environment is `<value>` at its own place, while every check
        # reads the values themselves.
        shown_config = with_environment_values_shown(config_data, result.references)
        shown_resolved = with_environment_values_shown(resolved_data, result.references)
        result.resolved_data = resolved_data
        result.shown_resolved = shown_resolved
        refused_fields: List[Tuple[str, str, str]] = []
        if refused is not None:
            # The model names each internal-only field it refuses, read from
            # the messages with each key as it is; the structural checks below
            # warn only about the ones it accepts. Read from the model's own
            # messages, before any redaction: a section value equal to a word
            # of the refusal sentence was replaced in the formatted message,
            # and the field was then both an error and a tolerated warning.
            refused_fields = cls._internal_fields_refused(
                cls._unredacted_refusal_messages(refused), config_data
            )
            result.errors.extend(
                cls._refusal_messages(refused, data=resolved_data, shown=shown_resolved)
            )
        # Free text from another file, which names no field of this one: what
        # the chain read from the environment is redacted from it.
        ash_config = (
            cls._ash_config_check(config_path, repository.trees)
            if check_ash_config
            else _AshConfigCheck([], None, False, False)
        )
        ash_config_errors = [result.redact(e) for e in ash_config.errors]
        result.errors.extend(ash_config_errors)

        # An ash_plugin_modules entry a scan's plugin loader refuses before it
        # imports anything (plugins/loader.refuse_plugin_modules_outside_namespace):
        # exit 3, so an error here, in the loader's words. Checked only on a
        # resolved document the model accepts, since a refused one never reaches
        # the loader in a scan either; and only while the ASH_CONFIG check runs
        # and finds nothing, since a scan refuses that file before any module
        # import, the resolution here would load a refused file a second time,
        # and a caller that turned the ASH_CONFIG check off holds a refusal of
        # its own already (its report prints that refusal, not this check's).
        if (
            refused is None
            and chain_resolved
            and check_ash_config
            and not ash_config_errors
            and isinstance(resolved_data, dict)
            # Nothing to judge, no resolution: the built config holds the
            # overridden list before confinement, and confinement only removes
            # entries, so an empty list here is empty in a scan too. The
            # caller's additional entries count: they reach a scan beside its
            # config.
            and (
                getattr(built, "ash_plugin_modules", None) or additional_plugin_modules
            )
        ):
            module_errors, module_check_failure = cls._plugin_module_refusal(
                config_path,
                source_dir,
                config_overrides,
                permit_base,
                untrusted_config,
                reads,
                texts,
                additional_plugin_modules,
                expect,
            )
            result.errors.extend(result.redact(m) for m in module_errors)
            if module_check_failure is not None:
                result.warnings.append(module_check_failure)

        # The checks that read the merged result read it as the scan builds
        # it: with --config-overrides applied. A missing project_name an
        # override supplies is not missing, and the ignore and suppression
        # paths an override replaced or added are the scan's, not the file's.
        checked_data = cls._with_override_lists(resolved_data, built, config_overrides)
        shown_checked = (
            shown_resolved
            if checked_data is resolved_data
            else with_environment_values_shown(checked_data, result.references)
        )
        # A file that is not a mapping has no keys to check; the model's
        # refusal above says so, in the words a scan uses.
        if isinstance(config_data, dict):
            try:
                result.warnings.extend(
                    cls._structure_warnings(
                        config_path,
                        config_data,
                        checked_data,
                        chain_resolved,
                        is_toml,
                        source_dir,
                        reported_as_errors=refused_fields,
                        override_keys=cls._override_keys(config_overrides),
                        layers=[
                            (path, reads.get(Path(path).resolve()))
                            for path in result.chain
                        ],
                        shown_config=shown_config,
                        shown_resolved=shown_checked,
                        environment_paths=result.environment_paths,
                        raw_content=config_text,
                        path_patterns=result.path_patterns,
                    )
                )
            except (OSError, ValueError) as e:
                # A path check that trips over an unusual value (a NUL byte, a
                # name too long for the filesystem) must not hide the verdict.
                # Free text: what the chain read is redacted from it.
                result.warnings.append(
                    result.redact(f"Unexpected error during validation: {str(e)}")
                )
        # Each operator-only option the repository's files wrote that a scan
        # warns it ignores: one no override and no file outside the tree keeps,
        # whose value is not the trusted base's, the base a scan of source_dir
        # uses (ASH_CONFIG's file outside the tree, or the defaults). A file
        # that writes the base's own value (`ash config init` writes the
        # defaults) warns nothing. Never the value; a key the chain read from
        # the environment is redacted like any free text.
        ignored_places = cls._ignored_operator_only(
            built, repository, config_overrides, ash_config
        )
        # The off-host reporters' destination and retry options, and their
        # ``enabled``, which a scan, ``ash report`` and ``ash merge`` take from
        # the trusted base and --config-overrides when a repository file writes
        # them (config/reporter_trust.py REPORTER_DESTINATION_OPTIONS): the same
        # warning, from the checked file's own document, so a config check says
        # what a scan's log says. The operator-only table above names two of
        # them too; each place is warned once.
        for place in cls._ignored_reporter_destinations(
            config_data, config_path, root_key, repository, config_overrides, ash_config
        ):
            if place not in ignored_places:
                ignored_places.append(place)
        for place in ignored_places:
            result.warnings.append(
                result.redact(
                    f"{place} is set in a config file inside the scanned tree, "
                    "and a scan ignores that value: only --config-overrides or a "
                    "config file outside the tree set it."
                )
            )
        result.ash_config_errors = ash_config_errors
        return result

    @classmethod
    def file_references_of(
        cls,
        config_path: Path,
        resolved: Any = _READ_THE_FILE,
        text: Optional[str] = None,
    ) -> List[EnvironmentReference]:
        """What ``config_path`` read from the environment, each at the place the
        file writes it (config/environment_record.py); ``resolved`` is the file
        as read_config_file read it.

        ``text``, the text ``resolved`` was parsed from, gives the as-written
        view too, so both are of one read (environment_references_of); without
        it the file is read again.
        """
        try:
            if resolved is _READ_THE_FILE:
                resolved = read_config_file(config_path)
            written = (
                parse_config_text_literally(config_path, text, keep_env_tags=True)
                if text is not None
                else read_config_file_as_written(config_path)
            )
        except (ASHConfigSourceError, yaml.YAMLError, OSError, ValueError):
            # The file was read once already for the check; one that cannot be
            # read again holds nothing this check will quote.
            return []
        return environment_references(written, resolved)

    @classmethod
    def _ignored_operator_only(
        cls,
        built: Any,
        repository: Any,
        config_overrides: Optional[List[str]],
        ash_config: "_AshConfigCheck",
    ) -> List[str]:
        """The operator-only options a scan of *repository*'s trees warns it
        ignores (operator_only_options.ignored_operator_only_options), judged
        against the trusted base that scan uses (resolve_config's
        trusted_base_config): the file ASH_CONFIG names, as *ash_config* loaded
        it, when no file of its chain is inside the trees; otherwise the
        defaults. The defaults stand in, too, for a file the check refused or
        did not load. A file the model refuses (*built* None) is judged by what
        its files wrote, without the overrides."""
        from automated_security_helper.config.ash_config import AshConfig
        from automated_security_helper.config.operator_only_options import (
            ignored_operator_only_options,
        )

        trusted = AshConfig()
        if ash_config.loaded is not None and not ash_config.in_tree:
            trusted = ash_config.loaded
        # When ASH_CONFIG names the checked file itself and none of its chain
        # is inside the trees, nothing was recorded as the repository's, so
        # both readers below answer [] whatever the trusted base holds: the
        # defaults stand without a case for it.
        if built is None:
            return repository.ignored_against(trusted)
        return ignored_operator_only_options(
            built, trusted, config_overrides, repository
        )

    @classmethod
    def _ignored_reporter_destinations(
        cls,
        config_data: Any,
        config_path: Path,
        real_path: Path,
        repository: Any,
        config_overrides: Optional[List[str]],
        ash_config: "_AshConfigCheck",
    ) -> List[str]:
        """The off-host reporters' destination options, retry options and
        ``enabled`` the checked file writes that a scan, ``ash report`` and
        ``ash merge`` ignore when the file is the repository's.

        Those commands take them from the trusted base with the overrides
        replayed onto it (reporter_trust.confine_reporter_destinations, the
        table REPORTER_DESTINATION_OPTIONS and REPORTER_ENABLED_DEFAULTS) and log
        what a repository file wrote for them; the config check said nothing,
        because the operator-only table above names only two of these options.
        Judged from the checked file's own document, as read (a reference the
        file reads from the environment is compared as written, and the place
        it names is redacted by the caller like any free text): the file is the
        repository's by the check's own membership (``is_repository_file``, the
        judgment the operator-only confinement uses); a reporter's section is
        matched by its reduced name, an option under any mix of ``-`` and ``_``
        in its name, as the merge reads them; a value the trusted base already
        gives the option changes nothing and is not named, and neither is a
        value an override writes the same, which is the operator's choice. A
        base this file extends is not read: its writes are its own file's.
        """
        from automated_security_helper.config.ash_config import (
            AshConfig,
            reduced_plugin_name,
        )
        from automated_security_helper.config.reporter_trust import (
            REPORTER_DESTINATION_OPTIONS,
            REPORTER_ENABLED_DEFAULTS,
        )

        if not isinstance(config_data, dict):
            return []
        reporters = config_data.get("reporters")
        if not isinstance(reporters, dict):
            return []
        if not repository.is_repository_file(real_path, config_path):
            return []
        trusted = AshConfig()
        if ash_config.loaded is not None and not ash_config.in_tree:
            trusted = ash_config.loaded

        def folded(name: str) -> str:
            return name.replace("-", "_")

        def as_mapping(value: Any) -> Dict[str, Any]:
            if value is None:
                return {}
            if isinstance(value, dict):
                return value
            dump = getattr(value, "model_dump", None)
            if callable(dump):
                try:
                    dumped = dump(by_alias=True)
                except (TypeError, ValueError):
                    return {}
                return dumped if isinstance(dumped, dict) else {}
            return {}

        def folded_value(mapping: Dict[str, Any], name: str) -> Any:
            for key, value in mapping.items():
                if isinstance(key, str) and folded(key) == folded(name):
                    return value
            return _MISSING_OPTION

        def override_writes(segments: Sequence[str], value: Any) -> bool:
            # An override of the place, or of a section above it, writes it; one
            # that writes the value the file wrote is no reason to warn (the
            # value stands), one that writes another is the operator's choice
            # and the file's value is not kept, which the warning is about.
            # Overrides apply in order, so when more than one names the place
            # the LAST one is the value a scan sees, and it decides here.
            decision: Optional[bool] = None
            for override in config_overrides or []:
                key_path, _, text = override.partition("=")
                parts = key_path.removesuffix("+").strip().split(".")
                if not parts or len(parts) > len(segments):
                    continue
                if any(
                    not (
                        folded(part) == folded(want)
                        or (
                            index == 1
                            and reduced_plugin_name(part) == reduced_plugin_name(want)
                        )
                    )
                    for index, (part, want) in enumerate(zip(parts, segments))
                ):
                    continue
                if len(parts) < len(segments):
                    decision = True
                    continue
                try:
                    written = yaml.safe_load(text)
                except yaml.YAMLError:
                    written = text
                decision = written == value
            return bool(decision)

        places: List[str] = []
        for key, section in reporters.items():
            if not isinstance(key, str) or not isinstance(section, dict):
                continue
            plugin = next(
                (
                    name
                    for name in REPORTER_DESTINATION_OPTIONS
                    if reduced_plugin_name(name) == reduced_plugin_name(key)
                ),
                None,
            )
            if plugin is None:
                continue
            trusted_section = as_mapping(trusted.get_plugin_config("reporter", plugin))
            trusted_options = as_mapping(trusted_section.get("options"))
            if "enabled" in section:
                trusted_enabled = trusted_section.get(
                    "enabled", REPORTER_ENABLED_DEFAULTS.get(plugin)
                )
                if section["enabled"] != trusted_enabled and not override_writes(
                    ("reporters", key, "enabled"), section["enabled"]
                ):
                    places.append(f"reporters.{key}.enabled")
            options = section.get("options")
            if not isinstance(options, dict):
                continue
            names = {folded(name) for name in REPORTER_DESTINATION_OPTIONS[plugin]}
            for option, value in options.items():
                if not isinstance(option, str) or folded(option) not in names:
                    continue
                kept = folded_value(trusted_options, option)
                if kept is not _MISSING_OPTION and kept == value:
                    continue
                if override_writes(("reporters", key, "options", option), value):
                    continue
                places.append(f"reporters.{key}.options.{option}")
        return places

    @classmethod
    def _ash_config_check(
        cls,
        config_path: Path,
        trees: Sequence[Path] = (),
    ) -> "_AshConfigCheck":
        """The scan's refusal of the file ASH_CONFIG names, when that is another
        file, and the configuration it loads to.

        A scan starts from the configuration ASH_CONFIG names
        (``get_default_config``), with ``--config`` naming a different file too,
        and refuses the run when that file is refused. So the check loads it
        with the same function and reports the refusal in the scan's words; a
        check of the named file alone called it valid. When ASH_CONFIG names the
        checked file itself, there is nothing more to load. *trees* are the
        scanned trees the check judges files by: what a file of that chain
        inside them, or inside any other checkout, writes for an operator-only
        option is left out as a scan leaves it out, so a value the option
        refuses refuses nothing. The file
        is loaded once: the check's trusted base is the configuration loaded
        here (_ignored_operator_only).
        """
        # Imported here, like resolve_config above.
        from automated_security_helper.config.default_config import (
            get_default_config,
        )
        from automated_security_helper.core.exceptions import (
            ASHConfigValidationError,
        )

        named = os.environ.get("ASH_CONFIG")
        # A name that does not exist is refused by get_default_config, as a scan
        # refuses it: it is not left unchecked.
        if not named:
            return _AshConfigCheck([], None, False, False)
        try:
            if Path(named).resolve() == Path(config_path).resolve():
                return _AshConfigCheck([], None, True, False)
        except (OSError, RuntimeError):
            if Path(named) == Path(config_path):
                return _AshConfigCheck([], None, True, False)
        # The scan's own constructor, so this check agrees with the loader on
        # which files count as a repository's and another checkout's refused
        # value is not this file's error.
        from automated_security_helper.config.operator_only_options import (
            scan_repository_settings,
        )

        settings = scan_repository_settings(list(trees))
        try:
            loaded = get_default_config(
                settings.confine, repository_file=settings.is_repository_file
            )
        except ASHConfigValidationError as e:
            return _AshConfigCheck([str(e)], None, False, False)
        except (OSError, ValueError) as e:
            # A scan stops on these too; say which file it could not use.
            where = describe_config_path(Path(named))
            return _AshConfigCheck(
                [f"Could not use the file ASH_CONFIG names ({where}): {e}"],
                None,
                False,
                False,
            )
        return _AshConfigCheck([], loaded, False, bool(settings.repository_files))

    @classmethod
    def environment_values_of(
        cls,
        config_path: Path,
        resolved: Any = _READ_THE_FILE,
        text: Optional[str] = None,
    ) -> List[str]:
        """The values ``config_path`` reads from the environment."""
        return [
            value
            for value, _ in cls.environment_references_of(config_path, resolved, text)
        ]

    @classmethod
    def environment_references_of(
        cls,
        config_path: Path,
        resolved: Any = _READ_THE_FILE,
        text: Optional[str] = None,
    ) -> List[Tuple[str, str]]:
        """environment_values_of, each value with the text the file writes for it.

        ``text``, the text ``resolved`` was parsed from, gives the literal view
        too, so both are of one read; without it the file is read again.
        """
        try:
            if resolved is _READ_THE_FILE:
                resolved = read_config_file(config_path)
            literal = (
                parse_config_text_literally(config_path, text)
                if text is not None
                else read_config_file_literally(config_path)
            )
        except (ASHConfigSourceError, yaml.YAMLError, OSError, ValueError):
            # The file was read once already for the check; one that cannot be
            # read again holds nothing this check will quote.
            return []
        return _interpolated_pairs(literal, resolved)

    @classmethod
    def _chain_error(cls, error: ASHConfigSourceError) -> str:
        """Why the `extends` chain does not resolve, after the prefix ConfigLinter
        and the MCP tool sort errors by.

        The error's message reads nothing from the environment, and is the one
        a scan prints: config_sources.resolve_config_document builds it, and
        load_config_file raises it as it is.
        """
        if isinstance(error, ASHConfigInputNotPermittedError):
            prefix = cls.NOT_PERMITTED_ERROR_PREFIX
        elif isinstance(error, ASHConfigEnvNotResolvedError):
            prefix = cls.ENV_NOT_RESOLVED_ERROR_PREFIX
        else:
            prefix = cls.EXTENDS_ERROR_PREFIX
        return f"{prefix}{error}"

    #: The global_settings lists an override can replace or add to, which the
    #: path checks then read from the configuration the scan builds.
    _OVERRIDDEN_LISTS = ("ignore_paths", "suppressions")

    #: The byte order mark a text may start with, which is not part of its
    #: first key.
    _BYTE_ORDER_MARK = chr(0xFEFF)

    @staticmethod
    def _override_keys(config_overrides: Optional[Sequence[str]]) -> FrozenSet[str]:
        """The dotted key of each ``--config-overrides`` entry, as written
        (``+`` for an append dropped, '-' read as '_'), for the checks that
        ask whether an override supplies a field."""
        keys = set()
        for override in config_overrides or ():
            key = str(override).partition("=")[0].removesuffix("+").strip()
            if key:
                keys.add(key.replace("-", "_"))
        return frozenset(keys)

    @classmethod
    def _with_override_lists(
        cls, resolved_data: Any, built: Any, config_overrides: Optional[Sequence[str]]
    ) -> Any:
        """``resolved_data`` with its ``global_settings`` ignore and suppression
        lists taken from ``built``, the configuration the scan builds with the
        overrides applied, when an override names one of them; else as it is.
        The path checks then describe the scan's lists, not the lists an
        override replaced or added to."""
        if built is None or not isinstance(resolved_data, dict):
            return resolved_data
        keys = cls._override_keys(config_overrides)
        touched = [
            name
            for name in cls._OVERRIDDEN_LISTS
            if any(
                key == f"global_settings.{name}"
                or key.startswith(f"global_settings.{name}.")
                for key in keys
            )
        ]
        if not touched:
            return resolved_data
        try:
            dumped = built.model_dump(mode="json", by_alias=True)
        except (TypeError, ValueError):
            return resolved_data
        built_settings = dumped.get("global_settings")
        if not isinstance(built_settings, dict):
            return resolved_data
        settings = resolved_data.get("global_settings")
        checked = dict(resolved_data)
        checked["global_settings"] = (
            dict(settings) if isinstance(settings, dict) else {}
        )
        for name in touched:
            checked["global_settings"][name] = copy.deepcopy(built_settings.get(name))
        return checked

    @classmethod
    def _unredacted_refusal_messages(cls, refusal: Any) -> List[str]:
        """The refusal's messages with the model's own text, before any
        redaction, for reading which fields it refused (internal_fields_refused):
        never shown. A refusal with no model error has one message, its own."""
        if refusal.validation_error is None:
            return [str(refusal)]
        return [
            f"{cls.MODEL_ERROR_PREFIX}{location_text(error.get('loc', ())) or '(top level)'}"
            f"': {error.get('msg', '')}"
            for error in refusal.validation_error.errors()
        ]

    @classmethod
    def _refusal_messages(
        cls, refusal: Any, data: Any = None, shown: Any = None
    ) -> List[str]:
        """Why the AshConfig model refused the file, one message per field.

        ``refusal`` is load_config_file's ConfigFileRefused. A refusal after the
        overrides says so; an override that could not be applied at all has no
        field to name, and its own message is given. With ``shown``, each field
        is named by its place (format_model_error).
        """
        suffix = " (after --config-overrides)" if refusal.after_overrides else ""
        if refusal.validation_error is not None:
            return [
                cls.format_model_error(error, suffix, data=data, shown=shown)
                for error in refusal.validation_error.errors()
            ]
        return [str(refusal)]

    @classmethod
    def format_model_error(
        cls,
        error: dict,
        suffix: str = "",
        data: Any = None,
        shown: Any = None,
    ) -> str:
        """``Invalid value at 'a.b[0].c': <message>`` for one pydantic error.

        No input value appears in it. pydantic keeps the input apart from its
        own messages, but ASH's validators quote what they refuse ("Use
        YYYY-MM-DD: <value>"), so every string of the input is replaced in the
        message by REDACTED (redact_refused_input). A validator can quote its
        input changed: upper-cased, which is replaced too, or in a form no
        replacement reaches (its separators taken out), and then its message is
        not shown (CHANGED_INPUT_WITHHELD). The value may have come from the
        environment, and the message is printed to CI logs and sent to MCP
        clients.

        With ``shown``, ``data`` (the document the model refused) as
        ``environment_record.with_environment_values_shown`` returns it, each
        key of the location the config read from the environment is named
        ``<value>`` by its place, and every key and string under the location
        read from the environment is replaced in the message whatever its
        length: by its place, it is known to be one.
        """
        loc = error.get("loc", ())
        if shown is None:
            location = location_text(loc)
        else:
            location = shown_location_text(loc, data, shown)
        location = location or "(top level)"
        value = error.get("input")
        # Not a value equal to a name the schema defines (_input_leaves): a
        # validator that names the path ("scanners.bandit.severity_threshold")
        # lost "bandit" to a section's `name: bandit`.
        message, changed = redact_refused_input(str(error.get("msg", "")), [error])
        if changed:
            message = CHANGED_INPUT_WITHHELD
        elif shown is not None:
            _steps, node, shown_node = _shown_at(list(loc), data, shown)
            message = redact_values(
                message,
                _strings_read_from_the_environment(node, shown_node),
                min_length=1,
            )
        hint = ""
        if error.get("type") == "string_type" and isinstance(value, (date, datetime)):
            hint = " (an unquoted date is read as a date, not text; put it in quotes)"
        return f"{cls.MODEL_ERROR_PREFIX}{location}': {message}{hint}{suffix}"

    @classmethod
    def model_error_location(cls, message: str) -> Optional[str]:
        """The dotted field path of a model error message, or None for other messages."""
        if not message.startswith(cls.MODEL_ERROR_PREFIX):
            return None
        rest = message[len(cls.MODEL_ERROR_PREFIX) :]
        end = rest.find("': ")
        return rest[:end] if end >= 0 else None

    @classmethod
    def _declared_spelling_of(cls, field_name: Any) -> Optional[str]:
        """The declared top-level field that ``field_name`` respells with '-'
        for '_' or the reverse, or None when it is no such respelling."""
        if not isinstance(field_name, str):
            return None
        wanted = field_name.replace("-", "_")
        for declared in sorted(cls.VALID_TOP_LEVEL_FIELDS):
            if declared != field_name and declared.replace("-", "_") == wanted:
                return declared
        return None

    @classmethod
    def _both_spellings_warnings(cls, config_data: dict) -> List[str]:
        """A top-level key written both as its alias and as its field name.

        A scan accepts both spellings and reads the alias, so the other one has
        no effect.
        """
        from automated_security_helper.config.ash_config import AshConfig

        warnings = []
        for name, info in AshConfig.model_fields.items():
            alias = info.alias
            if alias and alias != name and alias in config_data and name in config_data:
                warnings.append(
                    f"Top-level field '{alias}' is set twice, as '{alias}' and "
                    f"'{name}'; a scan reads '{alias}' and ignores '{name}'"
                )
        return warnings

    @classmethod
    def _internal_fields(cls, config_data: dict) -> List[Tuple[str, str, str]]:
        """``(segment, section, field)`` for each internal-only field the file sets."""
        return [found for found, _shown in cls._internal_fields_shown(config_data)]

    @classmethod
    def _internal_fields_shown(
        cls, config_data: dict, shown: Any = None
    ) -> List[Tuple[Tuple[str, str, str], Tuple[str, str, str]]]:
        """``_internal_fields``, each with the same names as ``shown`` (the copy
        ``with_environment_values_shown`` returns) holds them: a section key
        the file read from the environment is ``<value>``."""
        if shown is None:
            shown = config_data
        found: List[Tuple[Tuple[str, str, str], Tuple[str, str, str]]] = []
        for segment_name, internal in (
            ("scanners", cls.INTERNAL_SCANNER_FIELDS),
            ("reporters", cls.INTERNAL_REPORTER_FIELDS),
            ("converters", cls.INTERNAL_CONVERTER_FIELDS),
        ):
            segment = config_data.get(segment_name)
            if not isinstance(segment, dict):
                continue
            shown_segment = shown.get(segment_name) if isinstance(shown, dict) else None
            for (
                section_name,
                section,
                shown_section_name,
                shown_section,
            ) in _paired_items(segment, shown_segment):
                if not isinstance(section, dict):
                    continue
                for field_name, _value, shown_field, _shown in _paired_items(
                    section, shown_section
                ):
                    if field_name in internal:
                        found.append(
                            (
                                (segment_name, section_name, field_name),
                                (segment_name, shown_section_name, shown_field),
                            )
                        )
        return found

    @classmethod
    def _internal_field_message(
        cls, segment_name: str, section_name: str, field_name: str
    ) -> str:
        return internal_field_message(segment_name, section_name, field_name)

    @classmethod
    def section_key_in_file(cls, config_data: Any, segment: str, section: str) -> str:
        """The key ``config_data`` writes the section ``segment.section`` under.

        The model names a built-in plugin's section by its own spelling
        (``cdk-nag``) wherever the file used the other one (``cdk_nag``).
        """
        file_segment = (
            config_data.get(segment) if isinstance(config_data, dict) else None
        )
        if (
            not isinstance(file_segment, dict)
            or section in file_segment
            or segment not in INTERNAL_SECTION_FIELDS
        ):
            return section
        classes = _built_in_section_classes(segment)
        wanted = classes.get(section)
        for key in file_segment:
            if wanted is not None and classes.get(key) is wanted:
                return key
        # The loader folds a case or separator spelling of a known plugin's
        # section onto the declared one (plugin_section_names), so the file
        # may spell it 'Bandit' or 'CDK_NAG': found by the same fold.
        folded = folded_section_name(section)
        for key in file_segment:
            if isinstance(key, str) and folded_section_name(key) == folded:
                return key
        return section

    @classmethod
    def internal_fields_refused(
        cls, message: str, config_data: Any
    ) -> List[Tuple[str, str, str]]:
        """``(segment, section, field)`` for each internal-only field a model error
        refuses that ``config_data``, the checked file, itself holds: the fields
        ``ash config lint --fix`` can remove from it.

        The section is spelled as the file spells it, so a fix finds it there.
        """
        location = cls.model_error_location(message)
        named = internal_fields_named(message)
        if location is None or not named:
            return []
        segment, _, section = location.partition(".")
        if segment not in INTERNAL_SECTION_FIELDS:
            return []
        section = cls.section_key_in_file(config_data, segment, section)
        # Only a field the file's own section holds: one an `extends` base sets
        # is refused too, but the fix belongs in the base, not in this file.
        file_segment = (
            config_data.get(segment) if isinstance(config_data, dict) else None
        )
        file_section = (
            file_segment.get(section) if isinstance(file_segment, dict) else None
        )
        if not isinstance(file_section, dict):
            return []
        return [
            (segment, section, field_name)
            for _kind, _named, field_name in named
            if field_name in file_section
        ]

    @classmethod
    def _internal_fields_refused(
        cls, errors: Iterable[str], config_data: Any
    ) -> List[Tuple[str, str, str]]:
        return [
            refused
            for error in errors
            for refused in cls.internal_fields_refused(error, config_data)
        ]

    @classmethod
    def _structure_warnings(
        cls,
        config_path: Path,
        config_data: dict,
        resolved_data: Any,
        chain_resolved: bool,
        is_toml: bool,
        source_dir: Optional[Path],
        reported_as_errors: Iterable[Tuple[str, str, str]] = (),
        layers: Sequence[Tuple[Path, Any]] = (),
        shown_config: Any = None,
        shown_resolved: Any = None,
        environment_paths: Collection[Path] = frozenset(),
        raw_content: Optional[str] = None,
        path_patterns: Optional[List[Tuple[str, str]]] = None,
        override_keys: Collection[str] = frozenset(),
    ) -> List[str]:
        """The structural checks: problems a scan tolerates. ``raw_content`` is
        the file's text, as check_config_file read it; read here without it.
        ``path_patterns`` gets each path warning with its path as the config
        holds it (``ConfigCheck.path_patterns``). ``override_keys`` are the
        keys ``--config-overrides`` set (``_override_keys``): a project_name
        one supplies is not missing.

        ``reported_as_errors`` are internal-only fields a scan refuses, which
        check_config_file reports as errors instead. A message names a key or
        value as ``shown_config`` (``config_data`` as
        ``environment_record.with_environment_values_shown`` returns it) or
        ``shown_resolved`` (the same of ``resolved_data``) holds it, so one the
        config read from the environment is ``<value>``; None names each as
        it is. ``environment_paths`` are the files of the chain the
        environment chose, which a message names ``<value>``.
        """
        reported_as_errors = set(reported_as_errors)
        warnings: List[str] = []
        if shown_config is None:
            shown_config = config_data

        if not isinstance(resolved_data, dict):
            # The model check reports it; there is nothing to read here.
            resolved_data = {}
            shown_resolved = {}
            chain_resolved = False
        if shown_resolved is None:
            shown_resolved = resolved_data

        if (
            chain_resolved
            and "project_name" not in resolved_data
            and "project_name" not in override_keys
        ):
            warnings.append(cls.MISSING_PROJECT_NAME_MESSAGE)

        # Check for invalid top-level fields
        for field_name, _value, shown_field, _shown in _paired_items(
            config_data, shown_config
        ):
            if field_name in cls.INVALID_TOP_LEVEL_FIELDS:
                warnings.append(
                    f"Top-level field '{shown_field}' is an internal field and should not be in user configs"
                )
            elif field_name not in cls.VALID_TOP_LEVEL_FIELDS:
                declared = cls._declared_spelling_of(field_name)
                if declared is None:
                    warnings.append(
                        f"Unknown top-level field '{shown_field}' - a scan ignores it"
                    )
                elif (
                    declared not in config_data
                    and isinstance(resolved_data, dict)
                    and declared in resolved_data
                    and _value_folded_into(
                        config_data.get(field_name), resolved_data.get(declared)
                    )
                ):
                    # A '-'/'_' respelling of a declared field that the chain
                    # applied: this file does not set the declared spelling, a
                    # base does, and the extends merge or the operator overlay
                    # folded this file's value onto it (config_sources.deep_merge,
                    # Spellings), so "a scan ignores it" was wrong here. Read as
                    # the merge folds (_value_folded_into): a mapping the merge
                    # joined holds the base's keys too and never equals this
                    # file's. The message keeps the unknown-field prefix
                    # `ash config lint` files it under.
                    warnings.append(
                        f"Unknown top-level field '{shown_field}' - a scan ignores "
                        f"it on its own, but this chain folds it onto '{declared}' "
                        f"and applies its value. Write '{declared}'."
                    )
                else:
                    # A file alone, a base, or a file that also sets the
                    # declared spelling: the respelled key is ignored as any
                    # unknown field, and the declared spelling is the fix.
                    warnings.append(
                        f"Unknown top-level field '{shown_field}' - a scan ignores "
                        f"it; write '{declared}'."
                    )
        warnings.extend(cls._both_spellings_warnings(config_data))

        # Check for duplicate field definitions (YAML allows this but causes
        # issues). TOML rejects a duplicate key when it parses, and its
        # `key = value` lines would not be recognized here anyway.
        if is_toml:
            raw_content = ""
        elif raw_content is None:
            raw_content = config_path.read_text(encoding="utf-8")
        for field_name in cls._duplicate_top_level_fields(config_path, raw_content):
            warnings.append(
                f"Duplicate top-level field '{field_name}' found at multiple locations"
            )

        # Internal-only fields in scanner, reporter and converter sections. The
        # ones a scan refuses are errors, reported by check_config_file.
        for internal, shown in cls._internal_fields_shown(config_data, shown_config):
            if internal not in reported_as_errors:
                warnings.append(cls._internal_field_message(*shown))

        # Validate ignore_paths and suppression paths for directory-without-glob issues
        warnings.extend(
            cls._check_path_patterns(
                config_path,
                resolved_data,
                source_dir,
                layers,
                shown=shown_resolved,
                environment_paths=environment_paths,
                path_patterns=path_patterns,
            )
        )
        return warnings

    @classmethod
    def _duplicate_top_level_fields(
        cls, config_path: Path, raw_content: str
    ) -> List[str]:
        """The declared top-level fields ``raw_content`` writes more than once,
        each once, in the order of their first repeat.

        A YAML file is read line by line: a line with no leading blank and a
        ``:`` names a top-level key, written bare or in quotes (the quotes come
        off: a quoted spelling matched no declared field and was never
        counted), and a byte order mark before the first key is not part of it.
        A JSON file's keys are indented inside its braces, so its lines never
        matched; its root object's keys are read from the text instead, every
        pair kept (the parser keeps the last). A text that does not parse
        counts nothing: the parse refusal is the check's answer.
        """
        found: List[str] = []
        seen: Set[str] = set()

        def count(field_name: str) -> None:
            if field_name in cls.VALID_TOP_LEVEL_FIELDS:
                if field_name in seen and field_name not in found:
                    found.append(field_name)
                seen.add(field_name)

        if is_json_file(config_path):
            pairs: List[List[Tuple[str, Any]]] = []

            def keep(items: List[Tuple[str, Any]]) -> Dict[str, Any]:
                pairs.append(items)
                return dict(items)

            try:
                json.loads(
                    raw_content.lstrip(cls._BYTE_ORDER_MARK), object_pairs_hook=keep
                )
            except (ValueError, RecursionError):
                return []
            # The hook is called innermost first, so the root object's pairs
            # are the last ones kept.
            for key, _value in pairs[-1] if pairs else []:
                if isinstance(key, str):
                    count(key)
            return found

        for line in raw_content.lstrip(cls._BYTE_ORDER_MARK).split("\n"):
            stripped = line.strip()
            # Only consider lines with no leading whitespace (true top-level fields)
            if (
                stripped
                and not stripped.startswith("#")
                and ":" in stripped
                and not line[0].isspace()
            ):
                count(stripped.split(":")[0].strip().strip("'\""))
        return found

    @classmethod
    def validate_config_file(
        cls,
        config_path: Path,
        source_dir: Optional[Path] = None,
        permit_base: Optional[Callable[[Path], bool]] = None,
        refuse_env: Optional[Callable[[Path], bool]] = None,
    ) -> Tuple[bool, List[str]]:
        """Validate a configuration file and return every problem found.

        Valid when a scan accepts the file, as ``ash config validate`` says:
        when ``check_config_file`` finds no error. The list holds those errors
        followed by the warnings (things a scan accepts but that are probably
        mistakes), so a valid file can still come with entries. The MCP
        validate_config tool reports both.

        Args:
            config_path: Path to the configuration file
            source_dir: Path to the source directory (for resolving ignore_path patterns).
                        If None, inferred from config_path location.
            permit_base: Optional check every ``extends`` base must also pass;
                see ``config/config_sources.py``.
            refuse_env: Which files of the chain may not use ``!ENV``, as
                ``config_sources.resolve_config_document`` takes it. None refuses
                the files an MCP client delivered.

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        check = cls.check_config_file(
            config_path,
            source_dir=source_dir,
            permit_base=permit_base,
            refuse_env=refuse_env,
        )
        # The MCP validate_config tool types its errors from these strings and
        # reports this one as "missing_required_field", so it keeps the wording
        # it had before project_name became a warning.
        warnings = [
            cls.LEGACY_MISSING_PROJECT_NAME_MESSAGE
            if warning == cls.MISSING_PROJECT_NAME_MESSAGE
            else warning
            for warning in check.warnings
        ]
        return not check.errors, check.errors + warnings

    #: Prefix of the error for ``ash_plugin_modules`` names a scan refuses.
    PLUGIN_MODULES_ERROR_PREFIX = "Invalid ash_plugin_modules: "

    @classmethod
    def _plugin_modules_refusal(cls, config_data: dict) -> Optional[str]:
        """The scan's refusal of the config's ``ash_plugin_modules``, or None.

        Entries are split on commas and stripped the way a scan reads them, then
        given to ``plugins.loader.refuse_plugin_modules_outside_namespace``, which
        imports nothing. Whether an accepted name imports is not checked here.
        """
        from automated_security_helper.config.plugin_module_trust import (
            split_plugin_modules,
        )
        from automated_security_helper.plugins.loader import (
            PluginModuleError,
            refuse_plugin_modules_outside_namespace,
        )

        entries = config_data.get("ash_plugin_modules")
        if isinstance(entries, str):
            entries = [entries]
        if not isinstance(entries, (list, tuple)):
            return None
        try:
            refuse_plugin_modules_outside_namespace(split_plugin_modules(entries))
        except PluginModuleError as e:
            return f"{cls.PLUGIN_MODULES_ERROR_PREFIX}{e}"
        return None

    @classmethod
    def _plugin_module_refusal(
        cls,
        config_path: Path,
        source_dir: Optional[Path],
        config_overrides: Optional[List[str]],
        permit_base: Optional[Callable[[Path], bool]],
        untrusted_config: bool,
        reads: Dict[Path, Any],
        texts: Dict[Path, str],
        additional_plugin_modules: Sequence[str] = (),
        expect: Optional[FileIdentity] = None,
    ) -> Tuple[List[str], Optional[str]]:
        """The refusal a scan's plugin loader gives ``ash_plugin_modules``, if
        any, and the check's own failure, if the modules could not be judged.

        ``expect`` is the identity the check holds ``config_path`` to: the
        resolution here reads the root as that file, so a link repointed since
        the check read it is refused (its error is the first element) and not
        judged in its place.

        The first element is the file's errors; the second, when not None, is
        a warning for the caller saying the check could not run (its own
        machinery failed, named by type alone), so a fail-open is never
        silent.

        The list judged is the one a scan would import: ``resolve_config``
        resolves the file with the overrides applied and the trust confinement
        done (the trusted base, ASH_CONFIG's included; in-tree judgment by the
        names that reached each file of the chain; the untrusted path for a
        client-supplied config), rather than this check re-implementing any of
        it, plus the caller's ``additional_plugin_modules`` -- the scan inputs
        that reach a scan beside its config, which the CLI's config commands
        pass (``ASH_PLUGIN_MODULES``). An entry read from the environment of a
        config FILE is named by its placeholder, never by the variable's value
        (``config_module_names``); an additional entry is the operator's own
        text and is named as it is.
        """
        from automated_security_helper.config.plugin_module_trust import (
            config_module_names,
            split_plugin_modules,
        )
        from automated_security_helper.config.resolve_config import resolve_config
        from automated_security_helper.plugins.loader import (
            PluginModuleImportError,
            PluginModuleNamespaceError,
            refuse_plugin_modules_outside_namespace,
            refuse_unfindable_plugin_imports,
        )

        try:
            # With the check's own read cache, so no file of the chain is
            # parsed (or its !ENV warnings logged) a second time.
            resolved = resolve_config(
                config_path=str(config_path),
                source_dir=source_dir,
                config_overrides=list(config_overrides or []),
                permit_base=permit_base,
                untrusted_config=untrusted_config,
                fallback_to_default=False,
                reads=reads,
                texts=texts,
                expect=expect,
            )
        except (ASHConfigSourceError, yaml.YAMLError, OSError, ValueError) as e:
            # ValueError includes ASHConfigValidationError. The caller runs
            # this check only when its own loader reported nothing on the
            # chain, so a refusal here is the verdict rather than a repeat:
            # swallowing it would call the file valid while the scan refuses
            # it. The caller redacts it.
            from automated_security_helper.utils.error_text import error_text

            return ([error_text(e)], None)
        except Exception as e:
            # With fallback_to_default=False the resolution re-raises anything
            # else raw, and its trust confinement ran on no checker path before
            # this call existed. Such a failure is the check's own, not the
            # file's: validate, lint, get's error printer and the MCP tool all
            # call this check and must keep answering about the file. Not
            # silently, though: the caller gets a warning naming the type (and
            # nothing of the error's text), so a fail-open is visible.
            from automated_security_helper.utils.log import ASH_LOGGER

            ASH_LOGGER.debug(
                "the module check's own resolution failed with "
                f"{type(e).__name__}; the check adds nothing"
            )
            return (
                [],
                (
                    "the plugin-module check could not run (its own resolution "
                    f"failed with {type(e).__name__}), so ash_plugin_modules "
                    "was not judged"
                ),
            )
        if resolved is None:
            return ([], None)
        try:
            # The caller's entries first, then the config's, the order
            # ScanExecutionEngine combines the scan's own inputs in.
            environment_entries = set(split_plugin_modules(additional_plugin_modules))
            config_entries = set(
                split_plugin_modules(
                    getattr(resolved, "ash_plugin_modules", None) or []
                )
            )
            modules = split_plugin_modules(
                [
                    *additional_plugin_modules,
                    *(getattr(resolved, "ash_plugin_modules", None) or []),
                ]
            )
            names = config_module_names(resolved)
            refuse_plugin_modules_outside_namespace(modules, shown=names)
            # The import refusal's locatable half: a kept name no installed
            # package provides scan-refuses with exit 3, so the check says so
            # too, importing nothing (the found-but-breaks-on-import half can
            # only be caught by importing, which stays the scan's).
            refuse_unfindable_plugin_imports(modules, shown=names)
        except PluginModuleNamespaceError as e:
            # In the check's own closing words: str(e) carries the scan's,
            # which say nothing was scanned and name options no check has
            # (--ash-plugin-modules, ASH_PLUGIN_MODULES). The entry can come
            # from --config-overrides as well as the file, as the import
            # closing says. The MCP validate_config tool types the refusal by
            # its opening, the field's name (cli/mcp_tools.py).
            closing = (
                "Nothing was imported. Rename the package or name the "
                "packages inside it, or remove the entry from the "
                "config file or --config-overrides"
            )
            return (
                [
                    e.shown_with(
                        cls.with_environment_remedy(
                            closing, e, environment_entries - config_entries
                        )
                    )
                ],
                None,
            )
        except PluginModuleImportError as e:
            # The import class closes in the check's own words too.
            closing = (
                "Nothing was imported. Install what the module needs, "
                "or remove the entry from the config file or "
                "--config-overrides"
            )
            return (
                [
                    e.shown_with(
                        cls.with_environment_remedy(
                            closing, e, environment_entries - config_entries
                        )
                    )
                ],
                None,
            )
        return ([], None)

    @staticmethod
    def with_environment_remedy(
        closing: str, error: Exception, environment_only: set
    ) -> str:
        """*closing* with the one remedy an environment-only entry has.

        A refused entry that only ``ASH_PLUGIN_MODULES`` contributed is not
        fixed by editing a config file or an override the operator never
        used, so the closing names the variable -- and only then, since for a
        file's or an override's entry the variable holds nothing to unset."""
        if any(entry in environment_only for entry in getattr(error, "entries", ())):
            return f"{closing}, or unset it in ASH_PLUGIN_MODULES."
        return f"{closing}."

    @classmethod
    def _check_path_patterns(
        cls,
        config_path: Path,
        config_data: dict,
        source_dir: Optional[Path] = None,
        layers: Sequence[Tuple[Path, Any]] = (),
        shown: Any = None,
        environment_paths: Collection[Path] = frozenset(),
        path_patterns: Optional[List[Tuple[str, str]]] = None,
    ) -> List[str]:
        """Check ignore_paths and suppression paths for directory-without-glob issues.

        Returns a list of warning messages for paths that point to existing
        directories and so match no file inside them, each with the spelling that
        does (``directory_path_advice``). Only warns when the path actually exists
        as a directory in the repo.

        ``config_data`` is the merged config. ``layers`` are the files of its
        ``extends`` chain with what each holds itself, in merge order; a warning
        about a path an ``extends`` base holds names that base, the file to edit,
        ``<value>`` when the environment chose it (``environment_paths``).
        A message names each path as ``shown`` (``config_data`` as
        ``environment_record.with_environment_values_shown`` returns it) holds
        it; None names it as it is. A path with any part read from the
        environment gets no spelling of itself (absolute_path_warning).
        ``path_patterns``, when given, gets each warning with its path as
        ``config_data`` holds it (``ConfigCheck.path_patterns``).
        """
        warnings: List[str] = []
        if shown is None:
            shown = config_data

        # Determine the project root for resolving relative paths
        if source_dir is not None:
            project_root = source_dir.resolve()
        else:
            config_parent = config_path.resolve().parent
            if config_parent.name == ".ash":
                project_root = config_parent.parent
            else:
                project_root = config_parent

        global_settings = config_data.get("global_settings", {})
        if not isinstance(global_settings, dict):
            return warnings
        shown_settings = (
            shown.get("global_settings") if isinstance(shown, dict) else None
        )

        # Check ignore_paths, then suppression paths
        for list_key in ("ignore_paths", "suppressions"):
            entries = global_settings.get(list_key, [])
            if not isinstance(entries, list):
                continue
            shown_entries = (
                shown_settings.get(list_key)
                if isinstance(shown_settings, dict)
                else None
            )
            if not (
                isinstance(shown_entries, list) and len(shown_entries) == len(entries)
            ):
                # Not the copy of this list: name every path as read from the
                # environment.
                shown_entries = [None] * len(entries)
            for entry, shown_entry in zip(entries, shown_entries):
                # An empty path is checked too; a missing one is the model's.
                if not isinstance(entry, dict) or not isinstance(
                    entry.get("path"), str
                ):
                    continue
                path_pattern = entry["path"]
                shown_pattern = (
                    shown_entry.get("path", ENVIRONMENT_VALUE_SHOWN)
                    if isinstance(shown_entry, dict)
                    else ENVIRONMENT_VALUE_SHOWN
                )
                warning = cls._check_single_path(
                    path_pattern,
                    project_root,
                    ignore_path=list_key == "ignore_paths",
                    shown_pattern=shown_pattern,
                )
                if warning:
                    warning += cls._base_holding(
                        list_key,
                        path_pattern,
                        layers,
                        config_path,
                        environment_paths,
                    )
                    warnings.append(warning)
                    if path_patterns is not None:
                        path_patterns.append((warning, path_pattern))

        return warnings

    @staticmethod
    def _base_holding(
        list_key: str,
        path_pattern: str,
        layers: Sequence[Tuple[Path, Any]],
        config_path: Path,
        environment_paths: Collection[Path] = frozenset(),
    ) -> str:
        """`` It is in <base>.``, naming the base that holds ``path_pattern``.

        The last file of the chain whose own ``global_settings.<list_key>`` has
        an entry with that path, as merging reads it. Empty when that file is the
        checked one, whose entries ``ash config lint`` locates itself, or when
        no layer holds it. A base the environment chose (``environment_paths``)
        is named ``<value>``.
        """
        for path, data in reversed(layers):
            settings = data.get("global_settings") if isinstance(data, dict) else None
            entries = settings.get(list_key) if isinstance(settings, dict) else None
            if not isinstance(entries, list) or not any(
                isinstance(entry, dict) and entry.get("path") == path_pattern
                for entry in entries
            ):
                continue
            try:
                if Path(path).resolve() == Path(config_path).resolve():
                    return ""
            except (OSError, RuntimeError):
                if Path(path) == Path(config_path):
                    return ""
            if Path(path) in environment_paths:
                return f" It is in {ENVIRONMENT_VALUE_SHOWN}."
            return f" It is in {describe_config_path(Path(path))}."
        return ""

    @classmethod
    def _check_single_path(
        cls,
        path_pattern: str,
        project_root: Path,
        *,
        ignore_path: bool,
        shown_pattern: Optional[str] = None,
    ) -> Optional[str]:
        """The warning for a path pattern that matches nothing, or None if the
        path is fine (``path_pattern_advice``, shared with ``ash config lint``),
        after ``absolute_path_warning`` for an absolute one.

        An ignore path ending in ``/`` names the directory and matches what is in
        it, so it is fine; a suppression path ending in ``/`` is literal and is
        not. The message names the path as ``shown_pattern``, with any part read
        from the environment shown as ``<value>``; None names it as it is.
        """
        # A path that is not a string is a model error, reported as one.
        if not isinstance(path_pattern, str):
            return None
        if shown_pattern is None:
            shown_pattern = path_pattern

        # Checked first: joined to the root, an absolute path is itself, so the
        # directory check would advise a spelling of it under itself.
        absolute = absolute_path_warning(
            path_pattern,
            project_root,
            ignore_path=ignore_path,
            shown_pattern=shown_pattern,
        )
        if absolute:
            return absolute

        return path_pattern_advice(
            path_pattern,
            project_root,
            ignore_path=ignore_path,
            shown_pattern=shown_pattern,
        )

    @classmethod
    def validate_and_raise(cls, config_path: Path) -> None:
        """Validate a configuration file and raise an exception if invalid.

        Args:
            config_path: Path to the configuration file

        Raises:
            ConfigValidationError: If the configuration is invalid. The message
                numbers the errors alone: a warning is a problem a scan
                tolerates, not one of the failures (validate_config_file lists
                both, warnings after errors, for ``ash config validate``).
        """
        check = cls.check_config_file(config_path)
        is_valid, errors = check.scan_accepts, check.errors

        if not is_valid:
            error_msg = f"Configuration validation failed for {config_path}:\n"
            for i, error in enumerate(errors, 1):
                error_msg += f"  {i}. {error}\n"
            error_msg += "\nPlease fix these issues and try again."
            error_msg += "\nTip: Run 'ash config validate' for detailed validation."
            raise ConfigValidationError(error_msg)
