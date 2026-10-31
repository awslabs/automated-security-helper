# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""actionlint: a linter for GitHub Actions workflow files.

What ASH runs
-------------
actionlint (https://github.com/rhysd/actionlint, MIT) is one statically linked Go
binary. ASH installs a pinned release asset (``utils/tool_downloads.py``), finds the
workflow files itself, and runs::

    actionlint -no-color -shellcheck= -pyflakes= -config-file <file>
               -format <template> -- <workflow> [<workflow> ...]

with the scan target as the working directory.

A builtin scanner, enabled by default; ``scanners.actionlint.enabled: false`` turns
it off.

Decisions, and why
------------------
1. Workflow files are passed explicitly. Run with no file arguments, actionlint looks
   for the nearest ``.github/workflows`` from its working directory and ignores ASH's
   ignore rules. ASH instead takes every ``*.yml``/``*.yaml`` file whose parent
   directory is ``.github/workflows`` from the scan set, which applies ``.gitignore``
   and ``.ignore`` files and leaves ASH's own output directory out (keeping the
   files git tracks there; the scan set does that in every ``honor_ignore_files``
   mode, and the scanner adds no second filter of its own), then drops
   ``global_settings.ignore_paths`` matches and anything under a
   ``KNOWN_IGNORE_PATHS`` directory (``node_modules``, ``.venv``, ``venv``). The
   zizmor scanner selects its inputs by the same rules, so the two audit the same
   workflows. The scan root's own name counts, so a source directory that is
   ``.github`` or ``.github/workflows`` has its workflows linted.
   A workflow that is a symlink resolving outside the scan root is skipped with a
   warning, because actionlint follows it and copies its lines into the report, and
   so is one that resolves to no file (a missing target, or a loop), on which
   actionlint exits 3 and lints nothing. A workflow with a ``uses: ./...``
   reference that resolves outside the scanned tree is skipped with a warning too:
   actionlint reads the action metadata or reusable workflow a local reference
   names, from its project root, and quotes it (the action's name, its input names)
   in findings. See ``_reference_outside_the_tree``.
   ``--`` ends the flags, so a path that begins with ``-`` is read as a file. A
   scan root with no workflow files does not run actionlint at all and reports
   SKIPPED ("evaluated nothing"), not PASSED.

2. shellcheck and pyflakes are OFF by default. actionlint runs ``shellcheck`` on
   every ``run:`` script and ``pyflakes`` on ``shell: python`` steps when it finds
   them on PATH, and silently skips them when it does not. That makes the result set
   depend on what happens to be installed on the host. ASH passes ``-shellcheck=``
   and ``-pyflakes=`` (the documented way to disable them) unless
   ``options.shellcheck`` / ``options.pyflakes`` is set. When one is set and cannot
   be found or is not executable, the scanner reports MISSING instead of running
   without it, so an enabled integration is never skipped quietly either.

   Both options name the program actionlint pipes each ``run:`` script to, and
   ASH's config usually comes from the scanned repository (``.ash/.ash.yaml``), so
   ``shellcheck: sh`` there would execute the repository's scripts. From a config
   inside a git checkout or the scanned directory, each option accepts only its own
   name (``shellcheck``, ``pyflakes``), looked up on PATH and ASH's bin directory.
   The operator, through ``--config-overrides`` or a config file outside every git
   checkout and the scanned directory (``utils/config_trust.py``), may name another program or a path, absolute or
   relative to the source directory, checked by ``config_trust.operator_path``.
   Whoever sets it, a program that resolves inside the scanned tree is
   refused, and so is a path in the tree that a symbolic link there leads out of
   it, whether the operator wrote it or a name was found at it through a PATH
   entry inside the tree, since the link would choose the program. A refused value
   is logged and the integration stays off.

   Names are looked up only in PATH's absolute entries and ASH's bin directory, and
   actionlint is handed the absolute path ASH checked; actionlint itself is started
   by its absolute path too. A relative PATH entry (``.``, ``bin``) is relative to
   the working directory, which is ASH's when it looks and the scan target when the
   program runs, so it could name a file the repository committed. With every
   program it starts given by absolute path, nothing actionlint runs depends on
   its working directory, which stays the scan target so workflow paths in the
   findings are relative to it.

3. The config file is always explicit, and it is never the scanned repository's.
   actionlint discovers ``.github/actionlint.yaml`` by walking up to the nearest
   ``.git`` directory, and a config's ``paths`` section can ``ignore`` findings,
   which actionlint drops before ASH sees them: they are neither reported nor
   counted as suppressed. So ASH passes ``-config-file`` every time: an empty config
   it writes outside the scanned tree for this run, unless the operator set
   ``options.config_file`` (``--config-overrides`` or a config file outside every
   git checkout and the scanned directory, ``utils/config_trust.py``). A
   ``config_file`` set by a config inside a git checkout or the scanned directory
   is ignored with a warning, and a ``.github/actionlint.yaml`` or
   ``.github/actionlint.yml`` in the tree is ignored with a note; findings are tuned
   with ASH suppressions, which are reported and counted. The flag keeps the
   tree's config out of the rules, not out of actionlint's hands: 1.7.12 parses a
   repository's own config while it looks for the project root (the nearest
   ancestor holding ``.github/workflows`` and ``.git``), before the file the flag
   names is consulted, and exits 3 on one it cannot read. So when the tree's
   config does not parse, the workflows are linted from a copy made outside the
   tree for this run (``config_to_avoid``, the exit-3 retry in ``scan``,
   ``_stage_workflows``), with a
   warning: the findings and their paths are the same, and the copy has no
   project root, so local ``uses: ./...`` references are not resolved on that run.
   An operator's file that
   does not exist is an error, not a silent fallback, and one whose ``paths``
   section has ``ignore`` patterns is logged with the patterns. The operator's file
   may be inside the scanned tree, but one there that resolves outside the tree
   through a symbolic link is an error too, and actionlint is not run: actionlint
   quotes the start of a value it cannot parse, ASH logs a config's ``ignore``
   patterns, and the tree decides what that path leads to.

4. Output is JSON, converted to SARIF here. actionlint 1.7.12 has no built-in SARIF
   writer; its documentation points at a Go template in its test data. ASH asks for
   ``{{json .}}`` instead, wrapped with ``getVersion``, and builds the SARIF in
   Python. JSON encoding is done by actionlint's own ``json`` template function, so
   escaping is not hand-written, and the severity mapping below needs per-finding
   logic a static template cannot express.

5. Exit codes are read, not assumed. actionlint exits 0 when clean, 1 when it found
   problems, 2 for a bad command line and 3 for a fatal error (for example an
   unreadable file). 0 and 1 are success. Anything else, a timeout, output that is not
   the expected JSON, or exit 1 with no findings raises ``ScannerError``, so a broken
   run is ERROR and never an empty PASSED. Each target (the source tree, then the
   converted files) is judged by its own run's exit code; the base class would
   otherwise carry the worst code from one target into the next.

Severity mapping
----------------
actionlint gives every finding the same weight; its upstream SARIF template marks all
of them ``error``. ASH maps by rule kind (``kind`` becomes the SARIF ``ruleId``) so the
severity gate separates workflow defects that expose the run from lint:

* HIGH (SARIF ``error``): an ``expression`` finding whose message says the input is
  "potentially untrusted" -- script injection, a ``${{ github.event.* }}`` value that
  whoever triggers the workflow sets, interpolated into a ``run:`` script -- and
  ``credentials`` (a password hard-coded in a ``container:``/``services:`` block).
* MEDIUM (SARIF ``warning``): ``if-cond`` (an ``if:`` that is always true because of
  text around ``${{ }}``, so a guard silently does nothing), ``permissions``
  (an invalid ``permissions:`` block), and a ``deprecated-commands`` finding for
  ``set-env`` or ``add-path``, which GitHub disabled because they let a step's
  output inject environment variables and PATH entries into later steps.
* LOW (SARIF ``note``): everything else, which is a correctness problem in the
  workflow rather than an exposure -- syntax, other expression type errors, unknown
  runner labels, undefined ``needs:``, bad globs, the ``set-output``/``save-state``
  deprecations, and shellcheck/pyflakes output when enabled. A kind this table does not name is also LOW, and is logged once, so a
  newer actionlint adding a kind does not change the gate silently.

With ASH's default threshold (MEDIUM) a workflow with only lint findings passes and one
with script injection fails.

A ``credentials`` finding's snippet is the hard-coded password, so it is left out of
the SARIF; the location still points at the line. The result and its rule are tagged
``secret`` and CWE-798, so ASH's secret masking treats the finding as a secret
finding and masks that line wherever another scanner's snippet shows it.

A binary whose reported version differs from the pin (a nix or PATH install) runs,
with a warning, since the kinds and messages the mapping keys on may differ.

Overlap with zizmor
-------------------
zizmor also audits workflows, including template injection. If ASH's zizmor scanner
is enabled too, the two are independent: neither reads the other's output or
configuration, and an injection is reported once by each.

Suppressions
------------
Findings go through ASH's normal suppression pass, so rule (``ruleId`` is the
actionlint kind), path and line suppressions apply. Suppressing ``expression`` also
suppresses its script-injection findings, because actionlint reports both under that
kind; a line-scoped suppression is the narrow form. Package- and symbol-scoped
suppressions do not apply: a workflow file has no package identity and no
function/class symbols.
"""

from __future__ import annotations

import codecs
import json
import logging
import os
import re
import time
from pathlib import Path, PurePosixPath
from typing import (
    Iterable,
    Annotated,
    Any,
    ClassVar,
    Dict,
    List,
    Literal,
    Optional,
    Sequence,
    Set,
    Tuple,
)

import yaml
from pydantic import Field, PrivateAttr, model_validator

from automated_security_helper.base.options import ScannerOptionsBase
from automated_security_helper.base.plugin_base import worse_exit_code
from automated_security_helper.base.scanner_plugin import (
    ScannerPluginBase,
    ScannerPluginConfigBase,
)
from automated_security_helper.core.constants import KNOWN_IGNORE_PATHS
from automated_security_helper.core.enums import OfflineStrategy, ScannerToolType
from automated_security_helper.core.exceptions import ScannerError
from automated_security_helper.models.core import (
    IgnorePathWithReason,
    ignore_paths_that_skip_scanning,
)
from automated_security_helper.plugins.decorators import ash_scanner_plugin
from automated_security_helper.schemas.sarif_schema_model import SarifReport
from automated_security_helper.utils.download_utils import (
    pinned_tool_install_commands,
)
from automated_security_helper.config.confinement_remedy import SET_BY_THE_OPERATOR
from automated_security_helper.config.path_trust import in_scanned_tree
from automated_security_helper.config.tool_config_trust import (
    empty_tool_config,
    empty_tool_directory,
)
from automated_security_helper.utils.error_text import text_without_values
from automated_security_helper.utils.config_trust import (
    INSIDE_THE_TREE,
    LEADS_OUT_OF_THE_TREE,
    NOT_THE_OPERATORS,
    leaves_the_tree_through_a_link,
    operator_path,
    refusal_warning,
    scan_root,
    set_by_operator,
)
from automated_security_helper.utils.get_scan_set import honors_ignore_files, scan_set
from automated_security_helper.utils.log import ASH_LOGGER
from automated_security_helper.utils.path_probe import probe_path
from automated_security_helper.utils.sandbox.fs_guard import open_for_write
from automated_security_helper.utils.scan_targets import scan_targets
from automated_security_helper.utils.sandbox.policy import SandboxRequirements
from automated_security_helper.utils.subprocess_utils import (
    COULD_NOT_STOP_ENDING,
    WAS_KILLED_ENDING,
    find_executable,
)
from automated_security_helper.utils.suppression_matcher import (
    active_ignore_paths,
    ignore_path_matches,
)
from automated_security_helper.utils.tool_downloads import TOOL_VERSIONS

#: The version the severity mapping below was written against.
PINNED_VERSION = TOOL_VERSIONS["actionlint"]

#: The checks reference for the pinned release, used as every rule's helpUri.
ACTIONLINT_CHECKS_URL = (
    "https://github.com/rhysd/actionlint/blob/v1.7.12/docs/checks.md"
)

#: The ``actionlint -format`` template. ``{{json .}}`` is the error list as a JSON array, encoded
#: by actionlint; ``getVersion`` is the running binary's version. Passed as one argv
#: element, never through a shell.
ACTIONLINT_FORMAT = '{"version":{{getVersion | json}},"errors":{{json .}}}'

#: The substring in both of actionlint's untrusted-input messages, from
#: ``expr_insecure.go`` at v1.7.12: ``%q is potentially untrusted. avoid using it
#: directly in inline scripts...`` and ``object filter extracts potentially untrusted
#: properties %s...``.
UNTRUSTED_INPUT_MARKER = "potentially untrusted"

#: Those two messages by their shape, anchored at the start: the quoted input
#: (``%q``, Go-escaped) followed by the first sentence, which ends in a period
#: or, in a message cut short, with the text, or the object-filter wording. Other
#: ``expression`` messages quote workflow-authored text (a property name, a
#: format string), which can hold the marker's words without being this finding,
#: so the marker alone is not what raises a finding to HIGH.
_UNTRUSTED_INPUT_MESSAGE = re.compile(
    r'^(?:"(?:[^"\\]|\\.)*" '
    + re.escape(f"is {UNTRUSTED_INPUT_MARKER}")
    + r"(?:\.|$)"
    + r"|"
    + re.escape(f"object filter extracts {UNTRUSTED_INPUT_MARKER} properties ")
    + r")"
)

#: The two deprecated workflow commands GitHub disabled for injection, as actionlint
#: quotes them in its message (``workflow command %q was deprecated``).
INJECTABLE_DEPRECATED_COMMANDS = ('"set-env"', '"add-path"')

#: Severity for each actionlint rule kind, as listed by ``allKinds`` in v1.7.12.
#: ``expression`` and ``deprecated-commands`` are LOW here and raised per finding by
#: :func:`severity_for`.
KIND_SEVERITY: Dict[str, str] = {
    "action": "LOW",
    "credentials": "HIGH",
    "deprecated-commands": "LOW",
    "env-var": "LOW",
    "events": "LOW",
    "expression": "LOW",
    "glob": "LOW",
    "id": "LOW",
    "if-cond": "MEDIUM",
    "job-needs": "LOW",
    "matrix": "LOW",
    "permissions": "MEDIUM",
    "pyflakes": "LOW",
    "runner-label": "LOW",
    "shell-name": "LOW",
    "shellcheck": "LOW",
    "syntax-check": "LOW",
    "workflow-call": "LOW",
}

#: Severity for a kind KIND_SEVERITY does not list.
UNKNOWN_KIND_SEVERITY = "LOW"

_SEVERITY_TO_LEVEL: Dict[str, str] = {
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}

#: Tags on a ``credentials`` result and its rule. The finding reports a password
#: written into the workflow, so it is marked the way ASH recognizes a secret
#: finding (``utils/secret_masking.py``: a ``secret`` tag or CWE-798), and the
#: line it points at is masked wherever another scanner's snippet shows it.
CREDENTIALS_TAGS: Tuple[str, ...] = (
    "secret",
    "CWE-798: Use of Hard-coded Credentials",
)

#: actionlint's own config names. ASH does not read them from the scanned tree
#: (decision 3); it names them in the note it logs when one is present.
_DEFAULT_CONFIG_CANDIDATES = (".github/actionlint.yaml", ".github/actionlint.yml")

_WORKFLOW_SUFFIXES = (".yml", ".yaml")

#: The reason ``nothing_to_scan_reason`` gives when no tree holds a workflow file
#: actionlint would lint.
NO_WORKFLOW_FILE = (
    "no GitHub Actions workflow file (.github/workflows/*.yml or *.yaml) for "
    "actionlint to lint in the scanned files"
)

#: Directory names whose workflows are not linted: vendored dependencies and
#: virtualenvs, which the repository does not own. zizmor skips the same ones.
_KNOWN_IGNORED_DIRS = frozenset(item.strip("/") for item in KNOWN_IGNORE_PATHS)


def severity_for(kind: str, message: str) -> str:
    """The ASH severity for one actionlint finding."""
    if kind == "expression" and _UNTRUSTED_INPUT_MESSAGE.match(message):
        return "HIGH"
    if kind == "deprecated-commands" and any(
        command in message for command in INJECTABLE_DEPRECATED_COMMANDS
    ):
        return "MEDIUM"
    return KIND_SEVERITY.get(kind, UNKNOWN_KIND_SEVERITY)


def is_workflow_file(relative_path: str, scan_root: Optional[Path] = None) -> bool:
    """Whether *relative_path* is a workflow file GitHub would load.

    GitHub reads ``*.yml``/``*.yaml`` directly inside ``.github/workflows`` and not
    in its subdirectories. Applied at any depth, so a nested project's workflows are
    linted too. The suffix is matched as spelled, as actionlint, zizmor and GitHub
    read it, so ``ci.YAML`` is not a workflow and the two scanners select the same
    files (``is_zizmor_input``).

    ``scan_root`` is the directory *relative_path* is relative to. Its own name and
    its parent's count, so a scan root that is itself a ``.github`` or
    ``.github/workflows`` directory has its workflows recognized.

    Split as the running platform splits a path: on Windows a backslash
    separates, on POSIX it is a character of the name, so a root-level file
    named ``.github\\workflows\\x.yml`` is not a workflow there, and one named
    ``.github/workflows/a\\b.yml`` is.
    """
    parts: Tuple[str, ...] = Path(relative_path).parts
    if scan_root is not None:
        parts = (scan_root.parent.name, scan_root.name, *parts)
    return (
        len(parts) >= 3
        and parts[-3] == ".github"
        and parts[-2] == "workflows"
        and parts[-1].endswith(_WORKFLOW_SUFFIXES)
    )


#: A ``uses`` key, in block or flow style, up to where its value starts: the key
#: may be quoted and is matched whatever its case, as actionlint reads workflow
#: keys; the value may start on the line after the key, and may carry a tag or
#: an anchor (``!!str ./x``, ``&a ./x``). The value itself is ``_USES_VALUE``,
#: matched at the key's end. The two are read apart because a quoted value may
#: run across lines and ``finditer`` never overlaps: as one pattern, a ``uses: "``
#: in a comment, a ``name:`` string or a ``run:`` script opened a quoted value
#: that ran to the next ``"`` and hid every ``uses`` key in between, a real
#: ``./../..`` reference included. Backs up the YAML walk in
#: ``local_uses_references``, which is why the value reads more than one line:
#: the walk is gone for a document PyYAML cannot compose, and that document can
#: still spell a reference actionlint's parser reads.
_USES_KEY = re.compile(
    r"""(?:^|[\s{,])["']?uses["']?[ \t]*:[ \t]*(?:\r?\n[ \t]+)?(?:[!&]\S*[ \t]+)*""",
    re.MULTILINE | re.IGNORECASE,
)
#: The value at a ``_USES_KEY`` match's end: double-quoted (group 1, with its
#: escapes still encoded; an escaped line break is part of it), single-quoted
#: (group 2, with ``''`` for a quote; it may span lines) or plain (group 3, cut
#: at the first space, quote, comma, closing bracket or ``#``, which is where a
#: plain value ends inside ``{...}``/``[...]``; ``_uses_values_of`` reads the rest
#: of the line for block style). No match for a value of another shape (a
#: remote action, an expression), which the key is then not a reference to.
_USES_VALUE = re.compile(
    r"""(?:"((?:[^"\\]|\\[\s\S])*)"|'((?:[^']|'')*)'|(\./[^\s"',}\]#]*))"""
)
#: Where a plain value ends in block context: a comment, which needs a blank in
#: front of its ``#``, or the end of the line. Spaces, commas and brackets are
#: part of the value there (``uses: ./my dir/act`` is ``./my dir/act``).
_PLAIN_VALUE_COMMENT = re.compile(r"[ \t]#")
_FLOW_OPENERS = frozenset("{[")


#: Byte-order marks go-yaml, actionlint's parser, decodes a workflow by. UTF-8
#: without a mark is its default, as here.
_BYTE_ORDER_MARKS: Tuple[Tuple[bytes, str], ...] = (
    (codecs.BOM_UTF16_LE, "utf-16-le"),
    (codecs.BOM_UTF16_BE, "utf-16-be"),
    (codecs.BOM_UTF8, "utf-8"),
)


def decode_workflow(data: bytes) -> str:
    """*data* as text, decoded as actionlint's YAML parser decodes it.

    go-yaml reads a UTF-16 workflow by its byte-order mark, so one written that
    way is parsed, and its local references followed, like any other. Decoding it
    as UTF-8 found no reference in it and let it be linted unchecked. Bytes that
    do not decode are replaced; a replaced character is part of no path.
    """
    for mark, encoding in _BYTE_ORDER_MARKS:
        if data.startswith(mark):
            return data[len(mark) :].decode(encoding, errors="replace")
    return data.decode("utf-8", errors="replace")


def _decoded_scalar(quoted: str, fallback: str) -> Optional[str]:
    """*quoted*, a YAML flow scalar with its quotes, as the text it denotes.

    Escapes are decoded and line breaks folded as YAML does. The *fallback* (the
    raw text, a superset reading) is returned when PyYAML raises a YAMLError on
    it: a quoting PyYAML cannot read, actionlint's parser might. None is returned
    on an escape outside Unicode (``\\UFFFFFFFF``), which PyYAML's scanner hands
    to ``chr()`` as is: a ValueError past ``0x10FFFF``, an OverflowError past
    the C int (``\\UFFFFFFFF`` itself, on every supported Python). actionlint's
    parser rejects that escape too, so no file is read through the value.
    """
    try:
        decoded = yaml.safe_load(quoted)
    except yaml.YAMLError:
        return fallback
    except (ValueError, OverflowError):
        return None
    return decoded if isinstance(decoded, str) else fallback


#: Where a plain value ends in flow context: a comma, a closing bracket or
#: brace, or a comment. Spaces are part of the value there too (``{uses: ./my
#: dir/act}`` is ``./my dir/act`` in YAML), which is why the cut at the first
#: space is only one of the candidates.
_FLOW_VALUE_END = re.compile(r"[,\]}]|[ \t]#")


def _uses_values_of(match: "re.Match[str]", text: str, key_start: int) -> Set[str]:
    """The values a ``_USES_VALUE`` match could name, YAML quoting decoded.

    A plain value is read two ways, because the line scan has no parser to say
    where the value ends: the match itself, cut at the first space, quote,
    comma, closing bracket or ``#`` (the cut that lets the scan proceed to the
    next key on the same flow line), and the value read to where its context
    ends it. In block context that is a comment or the end of the line (``uses:
    ./my dir/act`` names a directory with a space in it); in flow context a
    comma, a closing bracket or brace, or a comment, with spaces kept (``{uses:
    ./my dir/act}`` names the same directory, where the cut at the space alone
    named ``./my``, and a reference out of the tree spelled that way was read
    as naming nothing and the workflow linted). The flow reading is always a
    candidate. The block reading is added unless the text between the start of
    the KEY's line and the value (*key_start* is the key match's start) holds a
    flow opener, on the key's line or, for a value on the next line, on the line
    the key shares with it: there the value is in flow context for certain. A
    flow collection opened on an EARLIER line cannot be seen from the key's
    line, which is why the flow reading is kept in block context too: without
    it ``uses: ./../outside dir/action, with: {}}`` inside such a collection
    read as the whole rest of the line and as the first word, never as the real
    value, where actionlint would resolve it. Every reading is a candidate:
    this is a superset of what actionlint resolves, and a candidate that names
    nothing is judged to be inside the tree. A quoted value whose escape no
    YAML parser accepts yields nothing (``_decoded_scalar``).
    """
    double_quoted, single_quoted, plain = match.groups()
    if double_quoted is not None:
        value = _decoded_scalar(f'"{double_quoted}"', double_quoted)
        return set() if value is None else {value}
    if single_quoted is not None:
        value = _decoded_scalar(f"'{single_quoted}'", single_quoted.replace("''", "'"))
        return set() if value is None else {value}
    candidates = {plain}
    start = match.start(3)
    line_end = text.find("\n", start)
    rest = text[start : len(text) if line_end == -1 else line_end]
    # The key's line starts after the newline before the key match. When the key
    # opens a line, that newline is the match's own first character (the
    # separator the key pattern takes), so the search includes it; without this
    # a key at column 0 was read against the line above it.
    key_line_start = text.rfind("\n", 0, key_start + 1) + 1
    candidates.add(_FLOW_VALUE_END.split(rest, 1)[0].rstrip())
    if not _FLOW_OPENERS.intersection(text[key_line_start:start]):
        candidates.add(_PLAIN_VALUE_COMMENT.split(rest, 1)[0].rstrip())
    return candidates


def local_uses_references(text: str) -> Set[str]:
    """The ``uses:`` values in a workflow that name a local action or workflow.

    actionlint reads what a ``uses: ./...`` names (an action's ``action.yml``, a
    reusable workflow) to check inputs, and quotes what it read in its findings.
    Every mapping key named ``uses`` counts, wherever it sits and whatever its
    case, so this is a superset of what actionlint resolves. Taken from PyYAML's
    node graph (aliases and merge keys included, each node visited once; the
    documents before one PyYAML cannot compose are still walked) and from a line
    scan, so a file PyYAML reads differently from actionlint's parser, or cannot
    read, is still covered. A value holding an expression is left out: actionlint
    does not resolve it.
    """
    found: Set[str] = set()
    # Each key on its own, its value matched at the key's end: a quoted value
    # that runs across lines then hides no later key (see _USES_KEY).
    for key in _USES_KEY.finditer(text):
        value = _USES_VALUE.match(text, key.end())
        if value is not None:
            found.update(_uses_values_of(value, text, key.start()))
    stack: List[Any] = []
    try:
        # compose_all is a generator: the documents it composed before failing
        # on a later one are kept, not thrown away with the error.
        for node in yaml.compose_all(text, Loader=yaml.SafeLoader):
            if node is not None:
                stack.append(node)
    except (yaml.YAMLError, RecursionError, ValueError, OverflowError):
        # ValueError and OverflowError: an escape outside Unicode in a quoted
        # scalar; PyYAML's scanner lets chr() raise them (OverflowError past
        # the C int, as for \UFFFFFFFF) instead of wrapping them as a YAMLError.
        pass
    visited: Set[int] = set()
    while stack:
        node = stack.pop()
        if id(node) in visited:
            continue
        visited.add(id(node))
        if isinstance(node, yaml.MappingNode):
            for key, value in node.value:
                if (
                    isinstance(key, yaml.ScalarNode)
                    and str(key.value).lower() == "uses"
                    and isinstance(value, yaml.ScalarNode)
                ):
                    found.add(str(value.value))
                stack.extend((key, value))
        elif isinstance(node, yaml.SequenceNode):
            stack.extend(node.value)
    return {spec for spec in found if spec.startswith("./") and "${{" not in spec}


def find_absolute_executable(name: str) -> Optional[str]:
    """``name`` as an absolute path, through ASH's own lookup (``find_executable``).

    A relative PATH entry (``.``, ``bin``) names a directory relative to the
    working directory: ASH's when it looks, the scan target when the program runs,
    since actionlint runs from the target and starts shellcheck and pyflakes from
    there. ``find_executable`` reads only PATH's anchored entries and ASH's bin
    directories, never the working directory (on Windows ``shutil.which`` would
    look there first), and while a scan is in progress it passes over a copy
    inside the scanned tree, unless the operator allowed in-tree tools, and goes
    on to the next candidate. So a repository's own copy earlier on PATH neither
    passes the dependency check only to be refused at spawn, nor hides a usable
    copy later on PATH or in ASH's bin directory. None when ``name`` is found
    nowhere ASH looks.
    """
    found = find_executable(name)
    if found is None or not os.path.isabs(found):
        return None
    return Path(found).absolute().as_posix()


class IgnorePatternsUnlisted(Exception):
    """ASH could not list the ``paths.<glob>.ignore`` patterns of an actionlint
    config; the text says why (a YAML alias, a syntax error, an unreadable file,
    a value PyYAML's constructor rejects, nesting too deep for it). actionlint
    reads the file by its own parser and still drops the findings those patterns
    match, so the caller warns that ASH cannot say which."""


def _yaml_problem(exc: yaml.YAMLError) -> str:
    """A YAML error's own problem text with its line, or its str()."""
    problem = getattr(exc, "problem", None) or str(exc)
    mark = getattr(exc, "problem_mark", None)
    line = getattr(mark, "line", None)
    if isinstance(line, int):
        return f"{problem} (line {line + 1})"
    return str(problem)


def _scalar_text(node: Any) -> Optional[str]:
    """A YAML scalar node as go-yaml decodes it into a Go string: its source
    text (``False`` stays ``False``, ``0x1F`` stays ``0x1F``, ``yes`` stays
    ``yes``), with a null as the empty string. None for a node that is not a
    scalar. Reading the constructed Python value instead (``str(31)``,
    ``"true"``) listed patterns actionlint never compiles."""
    if not isinstance(node, yaml.ScalarNode):
        return None
    if node.tag == "tag:yaml.org,2002:null":
        return ""
    return str(node.value)


def _ignore_pattern_texts(text: str) -> set[str]:
    """The ``paths.<glob>.ignore`` scalar entries of the config *text*, each as
    actionlint reads it into a string (``_scalar_text``). An entry that is not
    a scalar is left out: actionlint refuses such a config itself. Composed, not
    constructed, so the entries keep their spelling; *text* has already been
    loaded by ``config_ignore_patterns``, which refused what cannot be read."""
    found: set[str] = set()
    root = yaml.compose(text, Loader=yaml.SafeLoader)
    if not isinstance(root, yaml.MappingNode):
        return found
    for key, paths in root.value:
        if _scalar_text(key) != "paths" or not isinstance(paths, yaml.MappingNode):
            continue
        for _glob, section in paths.value:
            if not isinstance(section, yaml.MappingNode):
                continue
            for name, ignore in section.value:
                if _scalar_text(name) != "ignore" or not isinstance(
                    ignore, yaml.SequenceNode
                ):
                    continue
                for item in ignore.value:
                    entry = _scalar_text(item)
                    if entry is not None:
                        found.add(entry)
    return found


def config_ignore_patterns(config_path: Path) -> List[str]:
    """The ``paths.<glob>.ignore`` patterns in an actionlint config, sorted.

    Read by its byte-order mark (``decode_workflow``), as actionlint's go-yaml
    reads it, so a UTF-16 config is listed like any other, and with
    ``load_config_yaml``, which refuses YAML aliases as every YAML config ASH
    reads does. actionlint reads aliases, dates PyYAML's constructor rejects and
    nesting deeper than PyYAML's recursion allows, so a config it accepts can
    still ignore findings ASH cannot list. Every such case, and a file that
    cannot be read, raises ``IgnorePatternsUnlisted`` naming the cause, for the
    caller to warn with; nothing is reported as "no patterns" that was not read
    as such. actionlint owns the judgment of its own config, and reports a
    malformed one itself with exit 3.

    Each pattern is listed with the spelling actionlint compiles: go-yaml decodes
    an ignore entry into a string as its source text, and a null as the empty
    string, which matches every message and drops every finding, the one entry
    the log line most needs to show.
    """
    # Imported here: config/ash_config.py imports this module.
    from automated_security_helper.config.ash_config import load_config_yaml

    try:
        text = decode_workflow(config_path.read_bytes())
        document = load_config_yaml(text)
        paths = document.get("paths") if isinstance(document, dict) else None
        # The second read of the text (the composed node tree the pattern
        # texts come from) is held to the same report as the first: a refusal
        # there is the caller's to warn with, never an exception out of here.
        patterns = _ignore_pattern_texts(text) if isinstance(paths, dict) else set()
    except yaml.YAMLError as exc:
        raise IgnorePatternsUnlisted(_yaml_problem(exc)) from exc
    except (OSError, ValueError, RecursionError) as exc:
        raise IgnorePatternsUnlisted(str(exc) or exc.__class__.__name__) from exc
    return sorted(patterns)


def _is_project_root(directory: Path) -> bool:
    """Whether actionlint's project search ends at *directory*: it holds a
    ``.github/workflows`` directory and a ``.git`` (a directory, or the file a
    submodule or a linked worktree carries). Stat only; nothing is opened."""
    return probe_path(directory / ".github" / "workflows", "is_dir") and probe_path(
        directory / ".git", "exists"
    )


def project_roots(target: Path, workflows: Iterable[str]) -> List[Path]:
    """The project roots actionlint 1.7.12 finds for *workflows* (paths relative to
    *target*), each once, in the order the workflows name them.

    For each workflow actionlint walks up from the workflow's directory, through
    and above the scanned tree, to the nearest directory holding both
    ``.github/workflows`` and ``.git``, and reads THAT directory's
    ``.github/actionlint.yaml`` (then ``.yml``) before the ``-config-file`` it is
    given; a file it cannot read or parse ends the run with exit 3 before any
    workflow is linted. A workflow under no such directory has no project, and
    actionlint reads no repository config for it. The scanned tree's own root is
    one such directory only when it carries both markers, and a nested project
    (``sub/.git`` beside ``sub/.github/workflows``) is another, with its own
    config.
    """
    base = Path(target).absolute()
    roots: List[Path] = []
    for rel in workflows:
        start = (base / rel).parent
        for directory in (start, *start.parents):
            if _is_project_root(directory):
                if directory not in roots:
                    roots.append(directory)
                break
    return roots


def config_to_avoid(
    target: Path, roots: Iterable[Path]
) -> Optional[Tuple[Path, str, str]]:
    """``(root, name, shape)`` for the first repository actionlint config, among
    *roots*, that actionlint would read and ASH must keep it from reading: a
    link (the file itself, or a directory on the way to it), anything but a
    regular file, or a file outside the scanned tree.

    actionlint picks the first of ``.github/actionlint.yaml`` and ``.yml`` that
    ``os.Stat`` finds at a project root (a dangling link is passed over) and reads
    it with ``os.ReadFile``, which follows a link and blocks on a FIFO. The run
    stays in the tree only when every root's candidate is absent or is a plain
    regular file inside the scanned tree, reached through no link; actionlint then
    reads that file itself, and a file it refuses is caught by its exit code (the
    batch is run again from a copy outside the tree). Nothing here opens a file: a
    candidate of any other shape is judged by its stat alone, and the run is moved
    to the copy before actionlint, or ASH, could read through it.

    The file is judged by where it really is. A link on the last component is
    seen by ``is_symlink``; a link on a directory before it (``.github`` itself)
    leaves the last component an ordinary file as far as that test goes, so the
    real path is compared with the root's real path joined to the name, and any
    difference is a link on the way. The scanned tree is the target's real path
    for the same reason: a name that merely sits under the target is not a file
    inside it.
    """
    tree = Path(os.path.realpath(target))
    for root in roots:
        real_root = Path(os.path.realpath(root))
        for name in _DEFAULT_CONFIG_CANDIDATES:
            path = root / name
            if not probe_path(path, "exists"):
                continue
            if probe_path(path, "is_symlink"):
                return root, name, "a link"
            if not probe_path(path, "is_file"):
                return root, name, "not a regular file"
            real = Path(os.path.realpath(path))
            if real != real_root / name:
                return root, name, "reached through a link"
            if not real.is_relative_to(tree):
                return root, name, "outside the scanned tree"
            break
    return None


def config_present(roots: Iterable[Path]) -> bool:
    """Whether any project root among *roots* holds a repository actionlint config
    actionlint would read (by stat, as its own search finds it)."""
    return any(
        probe_path(root / name, "exists")
        for root in roots
        for name in _DEFAULT_CONFIG_CANDIDATES
    )


def project_root_above(path: Path) -> Optional[Path]:
    """The nearest ancestor of *path* (not *path* itself) actionlint would take as a
    project root, or None."""
    for directory in Path(path).absolute().parents:
        if _is_project_root(directory):
            return directory
    return None


def _credential_lines(errors: Any) -> Set[Tuple[Any, Any]]:
    """The ``(filepath, line)`` of every ``credentials`` finding in *errors*.

    The password is the text of that line, and actionlint quotes the line in
    the snippet of every finding on it, not only the credentials finding's.
    """
    if not isinstance(errors, list):
        return set()
    return {
        (error.get("filepath"), error.get("line"))
        for error in errors
        if isinstance(error, dict) and error.get("kind") == "credentials"
    }


def redact_credentials(payload: Any) -> Any:
    """A copy of *payload* with the snippet of every finding on a line a
    ``credentials`` finding points at removed.

    That snippet holds the hard-coded password, whichever finding quotes the
    line, and the payload is written into the output directory.
    """
    if not isinstance(payload, dict) or not isinstance(payload.get("errors"), list):
        return payload
    lines = _credential_lines(payload["errors"])
    errors = []
    for error in payload["errors"]:
        if isinstance(error, dict):
            where = (error.get("filepath"), error.get("line"))
            if where in lines:
                error = {k: v for k, v in error.items() if k != "snippet"}
        errors.append(error)
    return {**payload, "errors": errors}


#: Characters of workflow paths one actionlint invocation is given. Windows
#: caps a command line at 32,767 characters and the fixed arguments (the
#: executable, the format template, the config path) take a few hundred, so a
#: tree with more workflows than fit is linted in several runs, each judged by
#: its own exit code.
_WORKFLOW_ARGV_BUDGET = 24_000


def workflow_batches(
    workflows: Sequence[str], budget: Optional[int] = None
) -> List[List[str]]:
    """*workflows* in order, split so that each batch's paths (with a separator
    each) fit *budget* characters; a path longer than the budget is a batch of
    its own. Empty for no workflows."""
    if budget is None:
        budget = _WORKFLOW_ARGV_BUDGET
    batches: List[List[str]] = []
    current: List[str] = []
    used = 0
    for workflow in workflows:
        cost = len(workflow) + 1
        if current and used + cost > budget:
            batches.append(current)
            current, used = [], 0
        current.append(workflow)
        used += cost
    if current:
        batches.append(current)
    return batches


def _joined_sarif(sarif_dicts: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """One SARIF dict from the per-batch dicts ``build_sarif`` returned: the
    first one's driver, every batch's results in order, and the rules of every
    batch, each once, sorted by id."""
    if len(sarif_dicts) == 1:
        return sarif_dicts[0]
    joined = json.loads(json.dumps(sarif_dicts[0]))
    run = joined["runs"][0]
    rules: Dict[str, Dict[str, Any]] = {
        rule["id"]: rule for rule in run["tool"]["driver"]["rules"]
    }
    for part in sarif_dicts[1:]:
        part_run = part["runs"][0]
        run["results"].extend(part_run["results"])
        for rule in part_run["tool"]["driver"]["rules"]:
            rules.setdefault(rule["id"], rule)
    run["tool"]["driver"]["rules"] = [rules[name] for name in sorted(rules)]
    return joined


#: What a shell-style split reads as one plain word, whole: letters, digits and
#: ``_ . / : @ % + = , -``. A path of anything else (whitespace, a quote, a
#: backslash, ``; & | < > ( ) $ * ? [ ] ~ #``, a backtick) is quoted by
#: ``_command_word``, since each of those either ends the word early, opens a
#: quote or a group, or fails the parse.
_PLAIN_WORD = re.compile(r"[A-Za-z0-9_./:@%+=,-]+\Z")


def _command_word(path: str) -> str:
    """*path* as the one word of an ``-shellcheck=``/``-pyflakes=`` value.

    actionlint reads the value as a command line, the program and its
    arguments split on whitespace with shell-style quoting. A path holding a
    space would be split into a program that does not exist and an argument;
    one holding a quote, a semicolon, an ampersand or a parenthesis would end
    the word early or fail the parse. Either way the integration is dropped with
    nothing in the findings to show for it (actionlint says so only in verbose
    mode), which is what decision 2 and this function exist to prevent. So a
    path made of anything but the characters of ``_PLAIN_WORD`` is
    double-quoted, with the quote and the backslash escaped; a path of only
    those, or the empty value that turns an integration off, is passed as it
    is. A double-quoted plain path reads back as itself, so the quoting never
    changes which program runs.
    """
    if not path or _PLAIN_WORD.match(path):
        return path
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def build_sarif(
    payload: Any, exit_code: int, uri_base: Optional[Path] = None
) -> Dict[str, Any]:
    """Convert actionlint's ``ACTIONLINT_FORMAT`` output into a SARIF 2.1.0 dict.

    An error whose ``line`` is 0 (actionlint writes 0 for an error with no
    position) is kept as a result with no region, so one such workflow never
    drops the findings of every other workflow in the run. The template always
    writes an integer, so any other value that is not a positive integer is the
    output format having changed, and raises (decision 5).

    ``uri_base``, when given, is joined in front of every ``filepath``: actionlint
    writes paths relative to its working directory, and the scan reads a relative
    URI as relative to the source directory. For the converted target the working
    directory is the work directory, so its findings carry absolute URIs under
    it, which is how ASH tells a converted file's finding from a source file's.

    Raises:
        ScannerError: if the payload is not the shape the template produces (a
            ``line`` that is not an integer, or a negative one, included), or if
            the exit code contradicts the findings (1 with none, 0 with some).
    """
    if not isinstance(payload, dict) or "errors" not in payload:
        raise ScannerError(
            "actionlint output is not the expected JSON object with an 'errors' key"
        )
    errors = payload["errors"]
    if errors is None:
        errors = []
    if not isinstance(errors, list):
        raise ScannerError("actionlint output 'errors' is not a JSON array")
    if exit_code == 1 and not errors:
        raise ScannerError(
            "actionlint exited 1, which means it found problems, but reported none"
        )
    if exit_code == 0 and errors:
        raise ScannerError(
            f"actionlint exited 0, which means clean, but reported {len(errors)} "
            "problem(s)"
        )

    results: List[Dict[str, Any]] = []
    kinds_seen: Dict[str, str] = {}
    untrusted_shape_drift_logged = False
    credential_lines = _credential_lines(errors)
    for index, error in enumerate(errors):
        if not isinstance(error, dict):
            raise ScannerError(f"actionlint error #{index} is not a JSON object")
        kind = error.get("kind")
        message = error.get("message")
        filepath = error.get("filepath")
        line = error.get("line")
        column = error.get("column")
        if not (
            isinstance(kind, str)
            and kind
            and isinstance(message, str)
            and isinstance(filepath, str)
            and filepath
        ):
            raise ScannerError(
                f"actionlint error #{index} is missing kind, message or filepath: "
                f"{error!r}"
            )
        if kind not in KIND_SEVERITY and kind not in kinds_seen:
            ASH_LOGGER.warning(
                f"actionlint reported rule kind {kind!r}, which ASH has no severity "
                f"for; reporting it as {UNKNOWN_KIND_SEVERITY}."
            )
        severity = severity_for(kind, message)
        kinds_seen.setdefault(kind, KIND_SEVERITY.get(kind, UNKNOWN_KIND_SEVERITY))
        # The HIGH for an untrusted-input finding is given by the message's
        # shape (severity_for), so workflow-authored text holding the marker
        # words is not raised. The other side of that anchoring: a message that
        # holds the marker in a shape the pinned mapping does not know (a newer
        # actionlint's wording, a prefix) would quietly become LOW, which passes
        # the default gate. The severity stays as the shape decides; the drift
        # is logged once per report so it is seen.
        if (
            not untrusted_shape_drift_logged
            and kind == "expression"
            and severity != "HIGH"
            and UNTRUSTED_INPUT_MARKER in message
        ):
            untrusted_shape_drift_logged = True
            ASH_LOGGER.warning(
                "actionlint reported an expression finding whose message holds "
                f"{UNTRUSTED_INPUT_MARKER!r} in a shape the severity mapping for "
                f"actionlint {PINNED_VERSION} does not recognize; it is classified "
                f"by its kind ({severity}), not HIGH. A newer actionlint may have "
                "reworded the untrusted-input message; check the pinned mapping."
            )

        # actionlint writes the platform's separator. On Windows that is the
        # backslash, rewritten to the SARIF form; on POSIX a backslash is a
        # character of the file's name and stays, or the finding would name a
        # path that does not exist.
        uri = filepath.replace("\\", "/") if os.sep == "\\" else filepath
        if uri_base is not None:
            uri = (uri_base / uri).as_posix()
        physical_location: Dict[str, Any] = {"artifactLocation": {"uri": uri}}
        # actionlint reports line 0 for an error that has no position: an empty
        # file, invalid UTF-8, a YAML error raised before the first line. That is
        # still a finding on the file, so it is kept without a region rather than
        # failing the whole run and dropping every other workflow's findings.
        # Only that 0 goes region-less: the template writes an integer line for
        # every error, so a bool, None, a string or a missing key means the
        # output format changed, and reading it as "no position" would silently
        # drop every region (line-scoped suppressions, line-keyed masking).
        if type(line) is not int:
            raise ScannerError(
                f"actionlint error #{index} has no integer line: {line!r}"
            )
        if line < 0:
            # Not a position actionlint writes; silently giving it the line-0
            # treatment would drop the region.
            raise ScannerError(
                f"actionlint error #{index} has a negative line: {line!r}"
            )
        if line >= 1:
            region: Dict[str, Any] = {"startLine": line, "endLine": line}
            if isinstance(column, int) and not isinstance(column, bool) and column >= 1:
                region["startColumn"] = column
                end_column = error.get("end_column")
                if (
                    isinstance(end_column, int)
                    and not isinstance(end_column, bool)
                    and end_column >= column
                ):
                    # actionlint's end_column is inclusive; SARIF's endColumn is
                    # the column after the last character.
                    region["endColumn"] = end_column + 1
            snippet = error.get("snippet")
            # A credentials finding's snippet is the hard-coded password itself,
            # and so is the snippet of any other finding on that line, so
            # neither is copied into the report.
            if (
                isinstance(snippet, str)
                and snippet
                and (filepath, line) not in credential_lines
            ):
                region["snippet"] = {"text": snippet}
            physical_location["region"] = region

        properties: Dict[str, Any] = {
            "issue_severity": severity,
            "actionlint_kind": kind,
        }
        if kind == "credentials":
            properties["tags"] = list(CREDENTIALS_TAGS)

        results.append(
            {
                "ruleId": kind,
                "level": _SEVERITY_TO_LEVEL[severity],
                "message": {"text": message},
                "locations": [{"physicalLocation": physical_location}],
                "properties": properties,
            }
        )

    rules = []
    for kind, default_severity in sorted(kinds_seen.items()):
        rule: Dict[str, Any] = {
            "id": kind,
            "name": kind,
            "shortDescription": {"text": f"actionlint {kind} check"},
            "helpUri": ACTIONLINT_CHECKS_URL,
            "defaultConfiguration": {"level": _SEVERITY_TO_LEVEL[default_severity]},
        }
        if kind == "credentials":
            rule["properties"] = {"tags": list(CREDENTIALS_TAGS)}
        rules.append(rule)
    version = payload.get("version")
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "actionlint",
                        "version": str(version) if version else "unknown",
                        "informationUri": "https://github.com/rhysd/actionlint",
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


class ActionlintScannerConfigOptions(ScannerOptionsBase):
    config_file: Annotated[
        str | None,
        Field(
            description=(
                "Path to an actionlint config file. A relative path is taken from the "
                "directory of the config file that sets it, or from the working "
                "directory for --config-overrides, not from the source directory. "
                f"{SET_BY_THE_OPERATOR} Otherwise actionlint runs with an empty "
                "config, and a .github/actionlint.yaml in the scanned repository is "
                "not read. A path set here that does not exist fails the scan."
            ),
        ),
    ] = None
    shellcheck: Annotated[
        str | None,
        Field(
            description=(
                "Command name or path of shellcheck, which actionlint runs "
                "on every run: script. Unset (the default) disables the integration so "
                "results do not depend on what is installed on the host. Any config "
                "may set 'shellcheck', looked up on PATH. Another program, or a path "
                f"that resolves outside the scanned tree: {SET_BY_THE_OPERATOR} "
                "From such a config it is ignored with a warning. When set and not "
                "found, the scanner reports MISSING."
            ),
        ),
    ] = None
    pyflakes: Annotated[
        str | None,
        Field(
            description=(
                "Command name or absolute path of pyflakes, which actionlint runs on "
                "'shell: python' steps. Unset (the default) disables the integration. "
                "Any config may set 'pyflakes', looked up on PATH. Another program, or "
                f"a path that resolves outside the scanned tree: {SET_BY_THE_OPERATOR} "
                "From such a config it is ignored with a warning. When set and not "
                "found, the scanner reports MISSING."
            ),
        ),
    ] = None


class ActionlintScannerConfig(ScannerPluginConfigBase):
    name: Literal["actionlint"] = "actionlint"
    enabled: bool = True
    options: Annotated[
        ActionlintScannerConfigOptions,
        Field(description="Configure the actionlint scanner"),
    ] = ActionlintScannerConfigOptions()


class _RefusedIntegration(Exception):
    """A shellcheck/pyflakes value the scanned tree may not choose; see the module.

    ``refusal`` is the ``config_trust`` refusal it stands for, when there is one,
    so the warning ends with that refusal's remedy (``refusal_warning``).
    """

    def __init__(self, reason: str, refusal: Optional[str] = None) -> None:
        super().__init__(reason)
        self.refusal = refusal


@ash_scanner_plugin
class ActionlintScanner(ScannerPluginBase[ActionlintScannerConfig]):
    """Lints GitHub Actions workflow files with actionlint."""

    #: Not Python-only: actionlint is a native binary, installed from its pinned
    #: release asset, so a Python-only scan does not run it.
    python_only: ClassVar[bool | None] = False

    offline_strategy: ClassVar[OfflineStrategy] = OfflineStrategy.BUNDLED
    # The strict default, declared so the choice is visible: actionlint reads the
    # workflows and ASH's config file, and needs no network, cache or variables. An
    # enabled shellcheck or pyflakes is found through PATH, which the baseline mounts.
    sandbox_requirements: ClassVar[SandboxRequirements] = SandboxRequirements()
    # Integrations already reported as refused, so each is logged once per scan.
    _refused_integrations: Set[str] = PrivateAttr(default_factory=set)
    # actionlint's absolute path, from validate_plugin_dependencies; see
    # find_absolute_executable for why it is never looked up by name at run time.
    _executable: Optional[str] = PrivateAttr(default=None)

    def model_post_init(self, context: Any) -> None:
        if self.config is None:
            self.config = ActionlintScannerConfig()
        self.command = "actionlint"
        self.tool_type = ScannerToolType.IAC
        super().model_post_init(context)

    def _options(self) -> ActionlintScannerConfigOptions:
        """The scanner's options, typed. ``model_post_init`` guarantees a config."""
        options = getattr(self.config, "options", None)
        if isinstance(options, ActionlintScannerConfigOptions):
            return options
        return ActionlintScannerConfigOptions.model_validate(
            options.model_dump() if options is not None else {}
        )

    def _source_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("ActionlintScanner has no plugin context")
        return Path(self.context.source_dir)

    def _output_dir(self) -> Path:
        if self.context is None:
            raise ScannerError("ActionlintScanner has no plugin context")
        return Path(self.context.output_dir)

    @model_validator(mode="after")
    def setup_custom_install_commands(self) -> "ActionlintScanner":
        self.custom_install_commands.update(pinned_tool_install_commands("actionlint"))
        return self

    def _integration_executables(self) -> Dict[str, Optional[str]]:
        """Resolved paths for the enabled shellcheck/pyflakes integrations.

        A configured integration that cannot be found maps to None. One whose value
        is refused (see ``_integration_executable``) is left out, so actionlint runs
        with it off.
        """
        options = self._options()
        resolved: Dict[str, Optional[str]] = {}
        for flag in ("shellcheck", "pyflakes"):
            configured = getattr(options, flag, None)
            if configured is None or str(configured).strip() == "":
                continue
            try:
                resolved[flag] = self._integration_executable(
                    flag, str(configured).strip()
                )
            except _RefusedIntegration as refused:
                if flag not in self._refused_integrations:
                    self._refused_integrations.add(flag)
                    self._plugin_log(
                        refusal_warning(
                            f"Ignoring scanners.actionlint.options.{flag} "
                            f"({str(configured).strip()!r}): {refused}. actionlint "
                            f"runs with {flag} off.",
                            refused.refusal,
                        ),
                        level=logging.WARNING,
                    )
        return resolved

    def _integration_executable(self, flag: str, configured: str) -> Optional[str]:
        """The executable actionlint may run for ``flag``, None when it is absent.

        actionlint pipes every ``run:`` script (or ``shell: python`` step) to this
        program, so choosing it is choosing what runs the repository's scripts:
        ``shellcheck: sh`` would execute them. A value from a config inside a git
        checkout or the scanned directory is therefore accepted only when it is the
        flag's own name, looked up on PATH's absolute entries
        (``find_absolute_executable``). The operator (``--config-overrides`` or a
        config file outside every git checkout and the scanned directory) may name
        another program or an absolute path. Either way, the program must not resolve
        inside the scanned tree: an absolute PATH entry inside it would otherwise
        find one the repository committed. actionlint is always handed an absolute
        path, so it never looks the program up itself.

        Raises:
            _RefusedIntegration: the value is not one this config source may set.
        """
        source_dir = self._source_dir()
        context_config = self.context.config if self.context is not None else None
        root = scan_root(context_config, source_dir)
        if configured != flag and not set_by_operator(
            context_config, f"scanners.actionlint.options.{flag}", configured
        ):
            raise _RefusedIntegration(
                "a config file inside a git checkout or the scanned directory, or "
                f"one an MCP client delivered, may set only {flag!r} itself, or an "
                "empty value to keep it off",
                NOT_THE_OPERATORS,
            )
        if not any(sep and sep in configured for sep in ("/", os.sep, os.altsep)):
            found = find_absolute_executable(configured)
            if found is not None and in_scanned_tree(found, root):
                raise _RefusedIntegration(
                    f"it resolves to {found}, inside the scanned tree"
                )
            # A PATH entry inside the tree that is a link out of it: the program
            # resolves outside the tree, but the tree's link chose it.
            if found is not None and leaves_the_tree_through_a_link(
                found, source_dir, root
            ):
                raise _RefusedIntegration(
                    f"it is found at {found}, a path inside the scanned tree that "
                    "resolves outside it through a symbolic link"
                )
            return found
        # A path: the operator's only (checked above), resolved, and never inside
        # the tree, through the rule every option that names a file follows.
        chosen = operator_path(
            context_config,
            f"scanners.actionlint.options.{flag}",
            configured,
            source_dir,
        )
        if chosen.path is None:
            reason = chosen.refusal or INSIDE_THE_TREE
            raise _RefusedIntegration(reason, reason)
        candidate = chosen.path
        # A file that is not executable counts as absent: actionlint would
        # otherwise drop the integration silently.
        usable = candidate.is_file() and os.access(candidate, os.X_OK)
        return candidate.as_posix() if usable else None

    def _missing_integrations(
        self, integrations: Dict[str, Optional[str]]
    ) -> Optional[str]:
        """The MISSING reason for the enabled integrations *integrations* could
        not resolve, or None when every enabled one resolved."""
        options = self._options()
        missing = [
            f"{flag} ({getattr(options, flag)!s})"
            for flag, path in integrations.items()
            if path is None
        ]
        if not missing:
            return None
        return (
            f"actionlint is configured to use {', '.join(missing)}, which was not "
            "found. Install it, or unset the option to run actionlint without "
            "that integration."
        )

    def validate_plugin_dependencies(self) -> bool:
        self.dependency_unavailable_reason = self._missing_integrations(
            self._integration_executables()
        )
        if self.dependency_unavailable_reason:
            self._plugin_log(self.dependency_unavailable_reason, level=logging.WARNING)
            return False
        found = find_absolute_executable(self.command or "actionlint")
        self._executable = found
        if not found:
            ASH_LOGGER.warning(
                "actionlint executable not found. Install it with "
                "`ash dependencies install --tool actionlint`."
            )
        return found is not None

    def nothing_to_scan_reason(self) -> Optional[str]:
        """Why actionlint has nothing to scan in this run, or None.

        A reason only when ``_workflow_files``, the selection ``scan()`` makes,
        finds no workflow in any tree a scan hands this scanner
        (``utils/scan_targets.py``), so a workflow that selection leaves out (a
        link out of the tree, a reference outside it, a vendored copy) is not
        input here either. ``global_settings.ignore_paths`` is applied as
        scan() applies it: the orchestrator hands scan() the config's list
        through ``active_ignore_paths`` and then
        ``ignore_paths_that_skip_scanning`` (``models/core.py``: no entry under
        ``--ignore-suppressions``, and never one a delivered tree's own config
        supplied, which is left to the SARIF step), and this method builds the
        same list from the config and the context's flag, so a workflow the
        operator ignored is neither found nor named, and one only a client
        config ignored, or one ignored under the flag, is found here as scan()
        finds it. Without the first half this method found, refused and named
        a file scan() had passed over in silence, and the reason then said the
        scan log explained a file the log never mentioned; without the second
        it applied more ignore paths than scan() did, so a workflow scan()
        refused read as no workflow file. Logs nothing; scan() logs the
        warnings for the workflows it skips. When every workflow file was left
        out of the lint, the reason names them rather than saying there is no
        workflow file: there is, and the warnings say why each was not linted.
        """
        if self.context is None:
            return None
        settings = getattr(
            getattr(self.context, "config", None), "global_settings", None
        )
        ignore_paths = ignore_paths_that_skip_scanning(
            active_ignore_paths(getattr(settings, "ignore_paths", None)),
            ignore_suppressions=bool(
                getattr(self.context, "ignore_suppressions", False)
            ),
        )
        left_out: List[Dict[str, str]] = []
        for target_type, target in scan_targets(self.context):
            if self._workflow_files(
                target, target_type, ignore_paths, report=False, left_out=left_out
            ):
                return None
        if left_out:
            names = ", ".join(sorted({entry["path"] for entry in left_out}))
            return (
                "every GitHub Actions workflow file in the scanned files was left "
                f"out of the lint ({names}; the scan log says why each one was not "
                "linted), so actionlint evaluated nothing"
            )
        return NO_WORKFLOW_FILE

    def _workflow_files(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
        report: bool = True,
        left_out: Optional[List[Dict[str, str]]] = None,
    ) -> List[str]:
        """Workflow files under *target*, as POSIX paths relative to it, sorted.

        ``report`` False leaves out the warnings for the workflows it skips.
        ``left_out``, when given, collects a ``{path, reason}`` record for each
        workflow file the selection refused (a link out of the tree, a reference
        outside it, a path that is not a regular file); scan() reports them as
        the scanner's ``inputs_not_scanned``. A file the ignore rules leave out
        is not an input and is not recorded.
        """

        def refuse(rel: str, reason: str) -> None:
            if left_out is not None:
                left_out.append({"path": rel, "reason": reason})
            if report:
                self._plugin_log(f"Not linting {rel}: {reason}.", level=logging.WARNING)

        target_abs = Path(target).absolute()
        target_real = Path(target).resolve()
        if target_type == "converted":
            candidates = [str(p) for p in target_abs.rglob("*") if p.is_file()]
        else:
            # In a workspace scan the workspace's output directory holds every
            # project's output, converted archives included; a project at the
            # workspace root holds it, and without naming it the walk would lint
            # other projects' output as this project's source.
            workspace_output = getattr(self.context, "workspace_output_dir", None)
            # The scan set leaves out a file link whose target is outside the
            # tree before any scanner sees it. A workflow among those is still
            # an input this scanner did not lint, so it is recorded as the loop
            # below records the links it refuses itself (the converted walk meets
            # them there), and the nothing-to-scan reason names it instead of
            # saying the tree holds no workflow file. Empty when the scan set was
            # read back from the output directory, whose list left them out.
            links_left_out: List[Dict[str, str]] = []
            candidates = scan_set(
                source=str(self._source_dir()),
                output=str(self._output_dir()),
                honor_ignore_files=honors_ignore_files(
                    getattr(self.context, "config", None)
                ),
                run_id=getattr(self.context, "run_id", None),
                workspace_output_dir=(
                    str(workspace_output) if workspace_output is not None else None
                ),
                links_not_scanned=links_left_out,
            )
            source_abs = Path(self._source_dir()).absolute()
            for entry in links_left_out:
                link = (source_abs / entry["path"]).absolute()
                if not link.is_relative_to(target_abs):
                    continue
                link_rel = link.relative_to(target_abs).as_posix()
                if not is_workflow_file(link_rel, scan_root=target_abs):
                    continue
                if _KNOWN_IGNORED_DIRS.intersection(PurePosixPath(link_rel).parts[:-1]):
                    continue
                if any(
                    ignore_path_matches(link_rel, ignore.path)
                    for ignore in global_ignore_paths
                ):
                    continue
                refuse(link_rel, "it resolves outside the scan root")

        relative: List[str] = []
        for item in candidates:
            # The scan set spells each path from the source directory as it was
            # given, so a relative source directory yields paths relative to the
            # working directory, not to the target: absolute() reads them from
            # there, as zizmor does, where joining them to the target named files
            # that do not exist.
            path = Path(item).absolute()
            if not path.is_relative_to(target_abs):
                continue
            # ASH's own output directory is left out by the scan set, which keeps
            # the files git tracks there (a repository can commit files at that
            # path); no second filter here, or those are never linted.
            rel = path.relative_to(target_abs).as_posix()
            if not is_workflow_file(rel, scan_root=target_abs):
                continue
            # Vendored dependencies and virtualenvs, which zizmor skips too.
            if _KNOWN_IGNORED_DIRS.intersection(PurePosixPath(rel).parts[:-1]):
                continue
            # Before the checks below, which warn and read the file. Matched as
            # every ignore path is, so one ending in "/" names what is inside.
            if any(
                ignore_path_matches(rel, ignore.path) for ignore in global_ignore_paths
            ):
                continue
            # A link whose target is missing, or that loops, is a file actionlint
            # cannot open: it exits 3 and no workflow in the run is linted. Checked
            # before resolve(), which raises on a loop before Python 3.13. The
            # probes read a refused stat as "not that", never as an error that
            # ends the selection.
            if probe_path(path, "is_symlink") and not probe_path(path, "is_file"):
                refuse(rel, "it is a symbolic link that does not resolve to a file")
                continue
            # A FIFO or a device named like a workflow is not one: opening it to
            # read its local references would block ASH itself, outside any scan
            # timeout, and actionlint could not lint it either.
            if not probe_path(path, "is_file"):
                refuse(rel, "it is not a regular file")
                continue
            # A symlinked workflow is followed by actionlint, which copies the
            # target's lines into the SARIF snippet. Only pass files whose real
            # path is inside the real scan root.
            if not path.resolve().is_relative_to(target_real):
                refuse(rel, "it resolves outside the scan root")
                continue
            spec = self._reference_outside_the_tree(path, target_real)
            if spec is not None:
                refuse(
                    rel,
                    f"its local reference 'uses: {spec}' resolves outside the "
                    "scanned tree, and actionlint would read that file and quote "
                    "it in its findings",
                )
                continue
            relative.append(rel)
        return sorted(set(relative))

    def _reference_outside_the_tree(
        self, workflow: Path, target_real: Path
    ) -> Optional[str]:
        """A ``uses: ./...`` in *workflow* that would make actionlint read a file
        outside the scanned tree, or None.

        actionlint resolves ``./`` against its project root: in 1.7.12, the nearest
        ancestor holding ``.github/workflows`` that is also a git root. Every
        ancestor holding ``.github/workflows`` is checked here, so a different
        project rule cannot widen what is read. The ancestors are those of the
        path as given and those of its real path: actionlint computes its root
        from the physical working directory (Go's ``os.Getwd`` falls back to the
        kernel's answer when ``$PWD`` is not the directory it was started in),
        so under a scan root that is itself a symbolic link the roots it may
        pick are the real path's. For each, the reference is joined to the
        ancestor lexically, as actionlint joins it (``..`` taken before any link
        is followed), and the path that names and the
        ``action.yml``/``action.yaml`` inside it are then followed through
        symlinks; one that exists and lands outside both the scanned tree and
        the scan target is reported. A reference that names nothing under an
        ancestor is not one actionlint can read a file through, so it does not
        keep the workflow from being linted: without that test every ancestor
        holding ``.github/workflows`` exempted every workflow with an ordinary
        local action from the lint. An unreadable workflow is left to
        actionlint, which reports it, and an ancestor whose stat is refused is
        read as holding no project root.
        """
        try:
            text = decode_workflow(workflow.read_bytes())
        except OSError:
            return None
        specs = sorted(local_uses_references(text))
        if not specs:
            return None
        context_config = self.context.config if self.context is not None else None
        root = scan_root(context_config, self._source_dir())
        ancestors: List[Path] = list(workflow.parents)
        real_workflow = Path(os.path.realpath(workflow))
        if real_workflow != workflow:
            ancestors.extend(
                directory
                for directory in real_workflow.parents
                if directory not in ancestors
            )
        bases = [
            directory
            for directory in ancestors
            if probe_path(directory / ".github" / "workflows", "is_dir")
        ]
        for base in bases:
            for spec in specs:
                # actionlint joins the reference to its root lexically (Go's
                # filepath.Join cleans the path, so ".." is taken before any
                # link is followed) and opens what that names. Resolving links
                # first would judge a different file: "./link/../x" is
                # <root>/x to actionlint, whatever the link points at.
                named = Path(os.path.normpath(os.path.join(str(base), spec)))
                for candidate in (named, named / "action.yml", named / "action.yaml"):
                    # Nothing there: actionlint reads no file through it.
                    if not (
                        probe_path(candidate, "is_symlink")
                        or probe_path(candidate, "exists")
                    ):
                        continue
                    try:
                        real = Path(os.path.realpath(candidate))
                    except ValueError:
                        # A NUL (a YAML escape can write one), a lone surrogate,
                        # or anything else the operating system takes no path
                        # from: no file is opened through it, by actionlint or
                        # anyone, so it names nothing here.
                        continue
                    if not (
                        real.is_relative_to(target_real) or in_scanned_tree(real, root)
                    ):
                        return spec
        return None

    def _resolve_config_file(self, target: Path) -> Path:
        """The config file actionlint is given, always explicitly. See decision 3."""
        configured = self._options().config_file
        context_config = self.context.config if self.context is not None else None
        if configured:
            # The operator's own findings config may live in the tree, so
            # outside_tree is off; see config_trust.operator_path.
            chosen = operator_path(
                context_config,
                "scanners.actionlint.options.config_file",
                configured,
                self._source_dir(),
                outside_tree=False,
            )
            if chosen.refusal == LEADS_OUT_OF_THE_TREE:
                raise ScannerError(
                    f"scanners.actionlint.options.config_file is {configured!r}, a "
                    "path inside the scanned tree that resolves outside it through a "
                    "symbolic link. The scanned repository decides what is at that "
                    "path, so actionlint is not given it, and actionlint is not run."
                )
            if chosen.path is None:
                self._plugin_log(
                    refusal_warning(
                        f"Ignoring scanners.actionlint.options.config_file "
                        f"({configured!r}): {chosen.refusal}. actionlint runs with "
                        "an empty config; tune findings with ASH suppressions.",
                        chosen.refusal,
                    ),
                    level=logging.WARNING,
                )
            elif not chosen.path.is_file():
                raise ScannerError(
                    f"scanners.actionlint.options.config_file is {configured!r}, "
                    f"which does not exist (resolved to {chosen.path.as_posix()})."
                )
            else:
                return chosen.path
        present = [
            name for name in _DEFAULT_CONFIG_CANDIDATES if (target / name).is_file()
        ]
        if present:
            self._plugin_log(
                f"{', '.join(present)} in the scanned tree is not read: actionlint "
                "runs with an empty config, so its findings are reported and tuned "
                "with ASH suppressions. Set scanners.actionlint.options.config_file "
                "with --config-overrides or a config file outside every git checkout "
                "and the scanned directory to use an actionlint config.",
                level=logging.INFO,
            )
        # Outside the scanned tree, new for this run and removed when it ends
        # (config/tool_config_trust.empty_tool_config). It sets nothing, so
        # where it lives does not change what actionlint reports.
        return empty_tool_config(
            "ash-default-actionlint.yaml",
            "# Written by ASH so actionlint reads no config from the scanned tree.\n",
            context=self.context,
        ).absolute()

    def _stage_workflows(self, target: Path, workflows: List[str]) -> Path:
        """A copy of *workflows* (every selected path, relative to *target*) outside
        the tree, made once before the batches run.

        For a tree whose own actionlint config actionlint must not read (see
        ``config_to_avoid`` and the exit-3 retry in ``scan``): made new for this
        run in the scanner run's directory outside the scanned tree
        (``empty_tool_directory``), removed when the run ends, with the same
        relative layout under it and no ``.git``, so actionlint finds no project
        root there, reads no config of the tree's and reports the same relative
        paths it would have reported in the tree. The copy is root-free only when
        no ancestor of its directory is a project root (``.github/workflows`` and
        ``.git`` together): actionlint would take such an ancestor as the root,
        read ITS config and resolve ``uses: ./../...`` against a directory
        ``_reference_outside_the_tree`` never judged, so a directory under one is
        refused, naming it; the run directory falls back to the output directory
        when the temporary directory is unusable, and the output directory sits
        inside the scanned tree in the default layout. Each file is read from the
        tree (the selection already refused links that leave it) and written
        through the output guard with the copy's directory as its root, so a link
        planted at a copy's name, or at any directory between, is refused rather
        than followed.
        """
        root = empty_tool_directory("actionlint-workflows", context=self.context)
        above = project_root_above(root)
        if above is not None:
            raise ScannerError(
                f"the directory ASH made for a copy of the workflows, "
                f"{root.as_posix()}, lies under {above.as_posix()}, which holds "
                ".github/workflows and .git, so actionlint would take that "
                "directory as the project root, read its config and resolve local "
                "references against it. Set TMPDIR to a directory under no git "
                "checkout, or fix the scanned tree's actionlint config so the run "
                "can stay in the tree."
            )
        source = Path(target).absolute()
        for rel in workflows:
            data = (source / rel).read_bytes()
            with open_for_write(
                root / rel, binary=True, make_parents=True, root=root
            ) as copy:
                copy.write(data)
        return root

    def _execute_scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason],
    ) -> Tuple[List[str], Path, Optional[Dict[str, str]]]:
        """Abstract stub: ActionlintScanner overrides scan() directly."""
        raise NotImplementedError(
            f"{self.__class__.__name__} overrides scan() directly."
        )

    @staticmethod
    def _empty_report() -> SarifReport:
        """A one-run report with no results, for a scan set with no workflow files.

        The executor refuses a SARIF log that holds no run, so ``runs=[]`` would
        grade ERROR and fail the scan as incomplete. ``targets_attempted`` stays 0,
        which grades the row SKIPPED, a complete status.
        """
        return SarifReport.model_validate(
            {
                "version": "2.1.0",
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "actionlint",
                                "version": PINNED_VERSION,
                                "informationUri": "https://github.com/rhysd/actionlint",
                            }
                        },
                        "results": [],
                    }
                ],
            }
        )

    def scan(
        self,
        target: Path,
        target_type: Literal["source", "converted"],
        global_ignore_paths: List[IgnorePathWithReason] | None = None,
        config: ActionlintScannerConfig | ScannerPluginConfigBase | None = None,
        *args: Any,
        **kwargs: Any,
    ) -> SarifReport | bool:
        if global_ignore_paths is None:
            global_ignore_paths = []
        self.targets_attempted = 0
        self.targets_failed = 0
        # ScannerExecutor runs this instance over the source and then the converted
        # target, and the base class keeps the worst exit code across runs. Without
        # this, a source that exits 1 (findings) makes a clean converted target read
        # as "exited 1 but reported none". Reset above every return, as zizmor does.
        self.exit_code = 0
        # Per target too: the list is filled after the workflow selection below,
        # which the early returns never reach, so a converted run that returned
        # early re-reported the source target's refused workflows.
        self.inputs_not_scanned = []

        if not target.exists() or not any(target.iterdir()):
            self._plugin_log(
                f"Target directory {target} is empty or doesn't exist. Skipping scan.",
                target_type=target_type,
                level=logging.INFO,
                append_to_stream="stderr",
            )
            self._post_scan(target=target, target_type=target_type)
            return True

        if not self._pre_scan(target=target, target_type=target_type, config=config):
            self._post_scan(target=target, target_type=target_type)
            return False
        if not self.dependencies_satisfied:
            self._post_scan(target=target, target_type=target_type)
            return False

        # Resolved once more here, with the config scan() was given: the
        # dependency check ran against the config the scanner was built with. An
        # enabled integration that does not resolve now is MISSING, as it is
        # there (decision 2), never run with the integration quietly off.
        integrations = self._integration_executables()
        missing = self._missing_integrations(integrations)
        if missing:
            self.dependency_unavailable_reason = missing
            self._plugin_log(missing, target_type=target_type, level=logging.WARNING)
            self.dependencies_satisfied = False
            self._post_scan(target=target, target_type=target_type)
            return False

        left_out: List[Dict[str, str]] = []
        workflows = self._workflow_files(
            target, target_type, global_ignore_paths, left_out=left_out
        )
        # The workflow files this scan found and did not lint, for the report
        # (scanner_executor reads it as ``inputs_not_scanned``). Per target.
        self.inputs_not_scanned = left_out
        if not workflows:
            if left_out:
                self._plugin_log(
                    f"Every GitHub Actions workflow file in the {target_type} scan "
                    "set was left out of the lint (see the warnings above); "
                    "actionlint evaluated nothing.",
                    target_type=target_type,
                    level=logging.INFO,
                )
            else:
                self._plugin_log(
                    "No GitHub Actions workflow files (.github/workflows/*.yml or "
                    f"*.yaml) in the {target_type} scan set; actionlint evaluated "
                    "nothing.",
                    target_type=target_type,
                    level=logging.INFO,
                )
            self._post_scan(target=target, target_type=target_type)
            # True with targets_attempted left at 0 is what ScannerExecutor grades
            # as SKIPPED, with nothing_to_scan_reason() as the reason, as zizmor
            # does on the same tree. A SARIF report with no run is refused there
            # as "nothing to grade" and reads as ERROR, which fails a scan of a
            # tree without workflows under fail_on_incomplete_scanners.
            return True

        self.targets_attempted = len(workflows)
        if self.results_dir is None:
            raise ScannerError("ActionlintScanner has no results directory")
        results_dir = Path(self.results_dir).joinpath(target_type)
        results_dir.mkdir(parents=True, exist_ok=True)
        post_scanned = False
        # Whether actionlint was started, so a failure before it (a config file
        # that does not exist, one that leads out of the tree) is described as
        # that, and not with an exit code the tool never returned.
        tool_started = False
        # No exit code until a run returns one: the 0 set above is for the clean
        # skips, which the invocation record reads as accepted.
        self.exit_code = None
        # Every run's stdout is appended to self.output as record lines, and
        # those are persisted with the results when a scan fails. Remembered
        # here, outside the try, so the handler below can replace them whatever
        # ends the scan: a later batch's timeout or bad exit code would
        # otherwise leave an earlier batch's raw stdout, a credentials finding's
        # password included, in the records.
        output_before = len(self.output)
        raw_output_note: Optional[str] = None
        # Set once the redacted payload has replaced the raw record lines: a
        # failure after that point must keep it, not replace it with a note
        # saying the scan failed before the output could be redacted.
        redacted_recorded = False

        try:
            config_file = self._resolve_config_file(target)
            try:
                ignore_patterns = config_ignore_patterns(config_file)
            except IgnorePatternsUnlisted as exc:
                ignore_patterns = []
                self._plugin_log(
                    "ASH could not list the findings the actionlint config at "
                    f"{config_file.as_posix()} ignores: {exc}. actionlint still "
                    "reads it, and drops the findings its paths.<glob>.ignore "
                    "patterns match before ASH sees them.",
                    target_type=target_type,
                    level=logging.WARNING,
                )
            if ignore_patterns:
                self._plugin_log(
                    f"The actionlint config at {config_file.as_posix()} ignores "
                    f"findings matching {', '.join(repr(p) for p in ignore_patterns)}. "
                    "actionlint drops those before ASH sees them, so they cannot "
                    "appear in these results or be tracked as suppressions.",
                    target_type=target_type,
                    level=logging.WARNING,
                )

            # Where actionlint runs: the target, whose relative paths the
            # findings carry, unless a repository config actionlint would read
            # while it looks for a workflow's project root must be kept from it
            # (decision 3): then a copy of the workflows outside the tree, laid
            # out the same, so the paths are unchanged. Two cases move the run.
            # Before it starts: a config whose shape ASH will not let actionlint
            # (or itself) read through, a link, a FIFO, a file outside the tree
            # (config_to_avoid; judged by stat, never opened). After a batch:
            # actionlint exited 3 with a repository config present, the code it
            # gives a config it cannot read or parse (a wrong type, a duplicate
            # key, an invalid glob), which no check of ASH's own could tell
            # apart from one it accepts; the batch is run again from the copy.
            run_root: Path = Path(target)
            roots = project_roots(Path(target), workflows)
            avoided = config_to_avoid(Path(target), roots)
            retry_from_copy = avoided is None and config_present(roots)
            if avoided is not None:
                root, name, shape = avoided
                run_root = self._stage_workflows(target, workflows)
                self._plugin_log(
                    f"{name} at {root.as_posix()} is {shape}. actionlint reads a "
                    "project's own config while it looks for the project root, "
                    "before the -config-file it is given is consulted, and ASH "
                    "does not let it read through a file of that shape, so the "
                    "workflows are linted from a copy outside the tree. The "
                    "findings and their paths are the same; local `uses: ./...` "
                    "references are not resolved on this run, since the copy has "
                    "no project root. Replace the file with a regular one inside "
                    "the tree, or remove it, to lint in place.",
                    target_type=target_type,
                    level=logging.WARNING,
                )

            common_args: List[str] = [
                self._executable or self.command or "actionlint",
                "-no-color",
                f"-shellcheck={_command_word(integrations.get('shellcheck') or '')}",
                f"-pyflakes={_command_word(integrations.get('pyflakes') or '')}",
                "-config-file",
                config_file.as_posix(),
                "-format",
                ACTIONLINT_FORMAT,
                "--",
            ]
            effective_timeout = self._effective_scan_timeout()
            # One deadline for the target: scan_timeout is the limit for one
            # target, so each batch below gets the time left under it. Given
            # the whole limit per batch, a target split into N batches could run
            # for N times the limit the operator set.
            deadline = (
                None
                if effective_timeout is None
                else time.monotonic() + effective_timeout
            )
            uri_base = Path(target).absolute() if target_type == "converted" else None
            # The workflows go on the command line in batches that fit the
            # platform's limit (workflow_batches); each run is judged by its own
            # exit code and parsed on its own, then the findings are joined.
            payloads: List[Dict[str, Any]] = []
            sarif_dicts: List[Dict[str, Any]] = []
            final_args: List[str] = common_args
            # The worst code across the batches, folded as the base class folds
            # its runs: the invocation record below describes the whole target,
            # not the last batch. Within the loop self.exit_code is the current
            # batch's own code, which judges that batch.
            worst_exit_code: Optional[int] = None
            for index, batch in enumerate(workflow_batches(workflows)):
                final_args = [*common_args, *batch]
                # The first batch is given the limit as the operator set it (a
                # single-batch target reads its own timeout unchanged, not the
                # limit minus the microseconds since the deadline was set); the
                # batches after it get what the deadline leaves.
                batch_timeout = effective_timeout
                if deadline is not None and index > 0:
                    batch_timeout = deadline - time.monotonic()
                    if batch_timeout <= 0:
                        # The earlier batches used the whole limit; this one
                        # never starts. Worded as the timeout below is, with
                        # the limit through the shared token.
                        limit = self._timeout_limit_token(effective_timeout)
                        raise ScannerError(
                            text_without_values(
                                f"actionlint timed out after {limit}: the runs "
                                "over this target's earlier workflow batches used "
                                "the whole limit before this one could start. "
                                "Raise scanners.actionlint.options.scan_timeout if "
                                "this target legitimately needs longer.",
                                self._values_to_redact(),
                            )
                        )
                tool_started = True
                response = self._run_subprocess(
                    command=final_args,
                    results_dir=results_dir,
                    stdout_preference="return",
                    stderr_preference="write",
                    cwd=run_root,
                    timeout=batch_timeout,
                )
                # This run's code, not the largest of the batches so far.
                self._record_target_exit_code(response)

                if (
                    retry_from_copy
                    and run_root == Path(target)
                    and self.exit_code == 3
                    and not (isinstance(response, dict) and response.get("timed_out"))
                ):
                    # actionlint found a project root for a workflow in this
                    # batch and refused the repository config there (its exit 3
                    # before any file is linted). From here every batch runs
                    # from the copy, where it finds no project root and so reads
                    # no config of the tree's.
                    run_root = self._stage_workflows(target, workflows)
                    self._plugin_log(
                        "actionlint exited 3 with a repository actionlint config "
                        "present at a project root of the scanned tree ("
                        + ", ".join(root.as_posix() for root in roots)
                        + "). It parses that file while it looks for the project "
                        "root, before the -config-file it is given is consulted, "
                        "and exits 3 on one it cannot read or parse (a wrong type, "
                        "a duplicate key, an invalid glob), so the workflows are "
                        "linted from a copy outside the tree. The findings and "
                        "their paths are the same; local `uses: ./...` references "
                        "are not resolved on this run, since the copy has no "
                        "project root. Fix or remove the file to lint in place.",
                        target_type=target_type,
                        level=logging.WARNING,
                    )
                    retry_timeout = effective_timeout
                    if deadline is not None:
                        retry_timeout = deadline - time.monotonic()
                        if retry_timeout <= 0:
                            limit = self._timeout_limit_token(effective_timeout)
                            raise ScannerError(
                                text_without_values(
                                    f"actionlint timed out after {limit}: the run "
                                    "over this target's workflows used the whole "
                                    "limit before it could be run again from a copy "
                                    "outside the tree. Raise "
                                    "scanners.actionlint.options.scan_timeout if "
                                    "this target legitimately needs longer.",
                                    self._values_to_redact(),
                                )
                            )
                    response = self._run_subprocess(
                        command=final_args,
                        results_dir=results_dir,
                        stdout_preference="return",
                        stderr_preference="write",
                        cwd=run_root,
                        timeout=retry_timeout,
                    )
                    self._record_target_exit_code(response)

                if isinstance(response, dict) and response.get("timed_out"):
                    # The limit through the shared token, so an environment-read
                    # number is not printed, and "was killed" only when the stop
                    # worked: a tool ASH could not stop may still be running.
                    limit = self._timeout_limit_token(effective_timeout)
                    ending = (
                        COULD_NOT_STOP_ENDING
                        if self.scan_could_not_stop is not None
                        else WAS_KILLED_ENDING
                    )
                    raise ScannerError(
                        text_without_values(
                            f"actionlint timed out after {limit}{ending}. Raise "
                            "scanners.actionlint.options.scan_timeout if this "
                            "target legitimately needs longer.",
                            self._values_to_redact(),
                        )
                    )
                if self.exit_code not in self.success_exit_codes:
                    raise ScannerError(
                        f"actionlint exited {self.exit_code} (2 is a bad command "
                        "line, 3 a fatal error such as an unreadable file or "
                        "invalid config)"
                    )

                stdout = (response or {}).get("stdout") or ""
                try:
                    payload = json.loads(stdout)
                except json.JSONDecodeError as exc:
                    # Not kept: output that does not parse cannot be redacted,
                    # and a credentials finding's snippet, the password, may be
                    # in it. The record lines hold the same text; the handler
                    # below replaces them with this note of what was dropped.
                    raw_output_note = (
                        f"actionlint wrote {len(stdout)} characters that are not "
                        "JSON; not kept, since they could not be redacted"
                    )
                    raise ScannerError(
                        f"actionlint output is not JSON ({exc}); the output is not "
                        "kept, since it could not be redacted"
                    ) from exc
                # Validated per run: a run that exited 1 with no findings, or 0
                # with some, is a broken run whatever the other runs reported.
                sarif_dicts.append(build_sarif(payload, self.exit_code, uri_base))
                payloads.append(payload)
                if self.exit_code is not None:
                    worst_exit_code = worse_exit_code(worst_exit_code, self.exit_code)

            # One record for the target: every workflow the batches were given,
            # and the worst code any batch returned. Recording the last batch's
            # argv and code put batch-1 findings under an invocation that named
            # none of their files and could say the run was clean.
            if len(sarif_dicts) > 1:
                final_args = [*common_args, *workflows]
                self.exit_code = worst_exit_code

            self._post_scan(target=target, target_type=target_type)
            post_scanned = True

            payload = (
                payloads[0]
                if len(payloads) == 1
                else {
                    **payloads[0],
                    "errors": [
                        error
                        for part in payloads
                        for error in (part.get("errors") or [])
                    ],
                }
            )
            redacted = redact_credentials(payload)
            raw_output = results_dir / "actionlint.json"
            with open_for_write(raw_output) as handle:
                handle.write(json.dumps(redacted, indent=2))
            # The record lines hold the raw stdout, a credentials finding's
            # password included; the redacted payload takes their place so a
            # later failure of this scanner does not persist the password.
            self.output[output_before:] = [json.dumps(redacted)]
            redacted_recorded = True

            # actionlint ran in the target, or in a copy laid out like it (the
            # run_root above), so its paths are relative to the target either
            # way. A source finding stays relative (the scan reads it from the
            # source directory); a converted finding is made absolute under the
            # work directory, which is how the scan recognizes a converted file.
            sarif_dict = _joined_sarif(sarif_dicts)
            self.tool_version = sarif_dict["runs"][0]["tool"]["driver"]["version"]
            if self.tool_version.lstrip("v") != PINNED_VERSION.lstrip("v"):
                self._plugin_log(
                    f"actionlint {self.tool_version} is not the pinned "
                    f"{PINNED_VERSION}. The severity mapping matches rule kinds and "
                    "message text from the pinned version, so findings from this "
                    "version may be classified differently.",
                    target_type=target_type,
                    level=logging.WARNING,
                )
            sarif_report = SarifReport.model_validate(sarif_dict)
            self._inject_invocation(sarif_report, final_args, target)
            with open_for_write(results_dir / "actionlint.sarif") as handle:
                handle.write(
                    sarif_report.model_dump_json(
                        by_alias=True, exclude_none=True, exclude_unset=True, indent=2
                    )
                )
            return sarif_report
        except Exception as exc:
            self.targets_failed = self.targets_attempted
            if not post_scanned:
                self._post_scan(target=target, target_type=target_type)
            # Whatever ended the scan, no run's raw stdout stays in the record
            # lines: when the redacted payload never replaced them, a note does.
            # Once it has, the record lines hold the redacted payload and a
            # failure after that point (the SARIF model, the invocation record,
            # the SARIF file) leaves it there.
            if not redacted_recorded and len(self.output) > output_before:
                self.output[output_before:] = [
                    raw_output_note
                    or (
                        "actionlint's output is not kept: the scan failed before "
                        "the output could be redacted"
                    )
                ]
            raise ScannerError(
                self._describe_scan_failure(
                    exc, results_dir / "actionlint.json", tool_started=tool_started
                )
            ) from exc
