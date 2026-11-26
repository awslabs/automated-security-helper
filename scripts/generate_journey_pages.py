#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Render each journey file in docs/journeys/ to the tutorial page template it owns.

Usage:
    uv run python scripts/generate_journey_pages.py             # rewrite every render
    uv run python scripts/generate_journey_pages.py --check     # exit 1 with a diff if stale
    uv run python scripts/generate_journey_pages.py --journey docs/journeys/<name>.journey.yaml

Why a journey file
------------------
A journey page is an ordered run of commands a reader executes, with claims about
the outcome (an exit code, the number of actionable findings, the file a fix
changes). Those claims used to live in three places: the page's prose, the page's
doctest markers, and the regular expressions a test used to read them back out of
the rendered page. A journey file holds them once. The page is a render of it, and
the twin test (``tests/integration/docs/test_local_tutorial_twin.py``) runs the
journey's structured fields, so the page cannot say one thing and CI check another.

The pipeline composes with the version pinning chain and does not replace it::

    docs/journeys/<name>.journey.yaml      (source, committed)
        | this script
        v
    docs/content/.../<page>.md.template    (render, committed)
        | scripts/version_template_manager.py generate
        v
    docs/content/.../<page>.md             (published page, committed)

This script writes only the template. ``{{VERSION}}`` and ``{{RELEASE}}`` pass
through verbatim; the version manager and the docs build hook stay the only
writers of the page.

Schema v1
---------
A journey is a mapping with exactly these keys::

    schema: 1
    template: docs/content/.../page.md.template   # the file this journey renders
    page: docs/content/.../page.md                # what the template renders to
    twin:                                         # optional; the offline twin's scan
      scan: ash scan fs --scanners bandit --offline
      timeout: 300
    body:                                         # ordered segments
      - prose: |            # Markdown, verbatim
      - block:              # a fenced block
          lang: bash
          marker: {mode: illustrative, reason: "..."}   # optional doctest marker
          twin: {kind: scan, exit: "2", actionable: 2}  # optional, see below
          body: |
      - sample: |           # <!-- doctest: output --> followed by a ``text`` block

Segments render in order, joined by one blank line, and every segment's text is
copied byte for byte. The renderer never reflows, rewraps or rewrites anything. The
one thing it adds is the comment block ``scripts/_reference_docs.py`` writes at the top
of every generated page, naming this script and the journey, so a reader of the
template or the published page knows to edit the journey.

A block's ``marker`` is a run marker (``run``, ``illustrative``) or a config marker.
``{mode: config, kind: github-actions, save-as: <path>}`` is a pipeline file the page
tells the reader to create, and ``{mode: config, kind: github-actions, extends: <path>}``
is a fragment the docs runner merges into it, the way ``ci.md`` adds a second job to
the workflow of its first step. A config marker takes the keys the docs checks read for
its kind; ``extends`` must name a file an earlier block of the journey saved, as the
same kind.

``twin`` kinds, the steps the twin test runs in page order:

* ``project``: a block that writes the tutorial's project with ``cat > <file> <<'EOF'``.
* ``scan``: a block that runs ``ash``; ``exit`` is the code the page says it exits
  with, ``actionable`` (optional) the count in its ``Exiting due to N actionable
  findings`` line.
* ``report``: ``ash results report``; ``rule-id`` is the rule the page's sample shows.
* ``save``: a YAML block the twin writes to ``path``.
* ``fix``: a Python function that replaces ``replaces-function`` in the
  ``project`` file (``file-from: project``).

What the renderer refuses
-------------------------
Each refusal names the segment and is a ``--check`` failure:

* a scan step whose ``exit`` or ``actionable`` disagrees with an ``exit code: N``
  or ``Exiting due to N actionable findings`` line in the samples that follow it
  (up to the next twin step), or whose block echoes ``exit code`` and has no sample
  showing it; a report step whose sample does not show its ``rule-id``;
* a fix step that replaces a function the project's file does not define;
* a save step whose ``path`` does not appear in the prose that introduces the step,
  whose path holds a character outside ``A-Za-z0-9_./-`` or a ``..`` component, or
  a project, save or fix text with a line that is exactly ``EOF`` (the twin writes
  each through a heredoc that line would end);
* a marker key that is not one the docs runner reads, an unknown key anywhere in
  the file, a YAML anchor, alias or merge key;
* a render that does not parse back, through ``scripts/docs_checks.py``, to the
  blocks and markers the journey states, so the static checks and the runner see
  exactly what the journey says.

Pure standard library plus PyYAML. It reads only the journey files and the
templates and never imports ASH, so its output cannot depend on the environment.
"""

from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path, PurePosixPath
from typing import Any

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parent))
from _reference_docs import (  # noqa: E402
    add_docs_root_argument,
    banner,
    write_or_check,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
GENERATOR = "scripts/generate_journey_pages.py"
JOURNEY_DIR = Path("docs") / "journeys"
JOURNEY_SUFFIX = ".journey.yaml"
SCHEMA = 1
REGENERATE = f"uv run python {GENERATOR}"

_TOP_KEYS = frozenset({"schema", "template", "page", "twin", "body"})
_TWIN_KEYS = frozenset({"scan", "timeout"})
_BLOCK_KEYS = frozenset({"lang", "marker", "twin", "body"})
#: The keys each twin kind carries (``kind`` itself is always required).
_TWIN_KINDS: dict[str, frozenset[str]] = {
    "project": frozenset(),
    "scan": frozenset({"exit", "actionable"}),
    "report": frozenset({"rule-id"}),
    "save": frozenset({"path"}),
    "fix": frozenset({"file-from", "replaces-function"}),
}
#: A marker value that needs no quotes in a doctest marker.
_SAFE_VALUE = re.compile(r"[A-Za-z0-9_@%+,./:-]+")
#: A save path is written into a shell script, so it is limited to plain path characters.
_TWIN_PATH = re.compile(r"[A-Za-z0-9_./-]+")
_MODE = re.compile(r"[a-z][a-z-]*")
_LANG = re.compile(r"[A-Za-z0-9_+.-]+")
_EXIT_LINE = re.compile(r"^exit code: (\d+)$", re.MULTILINE)
_ACTIONABLE_LINE = re.compile(r"Exiting due to (\d+) actionable findings")
_RULE_LINE = re.compile(r"Rule ID: (\S+)")

_docs_checks_module = None


class JourneyError(Exception):
    """A journey file the renderer refuses; the message names the segment."""


def load_docs_checks():
    """scripts/docs_checks.py, loaded by path under the name the docs runner uses."""
    global _docs_checks_module
    name = "_ash_docs_checks"
    if _docs_checks_module is None and name in sys.modules:
        _docs_checks_module = sys.modules[name]
    if _docs_checks_module is None:
        path = Path(__file__).resolve().parent / "docs_checks.py"
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise RuntimeError(f"cannot load {path}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
        _docs_checks_module = module
    return _docs_checks_module


# ---------------------------------------------------------------------------
# Loading and validation
# ---------------------------------------------------------------------------


def _where(index: int, segment: dict) -> str:
    kind = next(iter(segment))
    value = segment[kind]
    if kind == "block" and isinstance(value, dict):
        detail = f"block, lang {value.get('lang')}"
        twin = value.get("twin")
        if isinstance(twin, dict) and "kind" in twin:
            detail += f", twin {twin['kind']}"
    elif kind == "block":
        detail = "block"
    else:
        text = value if isinstance(value, str) else ""
        first = next((line for line in text.splitlines() if line.strip()), "")
        detail = f"{kind}, starts {first[:40]!r}"
    return f"body[{index}] ({detail})"


def _refuse_yaml_features(text: str, path: Path) -> None:
    """Schema v1 has no anchors, aliases or merge keys."""
    try:
        for event in yaml.parse(text):
            if isinstance(event, yaml.AliasEvent) or getattr(event, "anchor", None):
                raise JourneyError(
                    f"{path}: YAML anchors and aliases are not part of schema v1"
                )
            if (
                isinstance(event, yaml.ScalarEvent)
                and event.value == "<<"
                and event.style is None
            ):
                raise JourneyError(f"{path}: YAML merge keys are not part of schema v1")
    except yaml.YAMLError as exc:
        raise JourneyError(f"{path}: not valid YAML: {exc}") from exc


def _unknown(keys, allowed, where: str) -> None:
    extra = sorted(str(k) for k in set(keys) - set(allowed))
    if extra:
        raise JourneyError(
            f"{where}: unknown key(s) {extra}; schema v1 allows {sorted(allowed)}"
        )


def _text(value: Any, where: str, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise JourneyError(f"{where}: {field} must be a non-empty string")
    if not value.endswith("\n") or value.endswith("\n\n") or value.startswith("\n"):
        raise JourneyError(
            f"{where}: {field} must end with exactly one newline and start with "
            "text (write it as a `|` block scalar); segments are joined by one "
            "blank line"
        )
    return value


def block_body(block: dict) -> str:
    """The block's text as the docs parser reads it: no trailing newline."""
    return block["body"][:-1]


def heredoc_file(body: str) -> tuple[str, str]:
    """(name, content) of the file a ``cat > name <<'EOF'`` block writes."""
    match = re.search(
        r"^cat > (\S+) <<'EOF'\n(.*?)\nEOF$", body, re.MULTILINE | re.DOTALL
    )
    if not match:
        raise JourneyError("the project block no longer writes its file with a heredoc")
    return match.group(1), match.group(2)


def replace_function(source: str, replacement: str) -> str:
    """source with the top-level function replacement defines swapped for it."""
    name = re.match(r"\s*def (\w+)\(", replacement)
    if not name:
        raise JourneyError("the fix block is not a function definition")
    pattern = re.compile(
        rf"^def {name.group(1)}\(.*?(?=^\S|\Z)", re.MULTILINE | re.DOTALL
    )
    if not pattern.search(source):
        raise JourneyError(f"the project has no {name.group(1)}() to replace")
    return pattern.sub(replacement.strip("\n") + "\n", source, count=1)


def _config_kinds(checks) -> frozenset[str]:
    """The ``kind=`` values of a ``config`` marker the docs checks read."""
    return frozenset(
        set(checks.ASH_CONFIG_KINDS) | set(checks.OTHER_CONFIG_KINDS) | checks.CI_KINDS
    )


def _config_keys(checks, kind: str) -> set[str]:
    """The marker keys a ``config kind=<kind>`` block may carry besides ``mode``."""
    keys = {"kind", "save-as", "reason"}
    keys |= set(checks.ASH_CONFIG_KINDS.get(kind, ()))
    keys |= set(checks.OTHER_KIND_KEYS.get(kind, ()))
    if kind == checks.MCP_RESPONSE_KIND:
        keys.add("of")
    if kind in checks.CI_RUNNERS:
        keys |= set(checks.CI_RUNNER_KEYS)
    return keys


def _check_marker(marker: Any, where: str) -> None:
    checks = load_docs_checks()
    if not isinstance(marker, dict):
        raise JourneyError(f"{where}: marker must be a mapping with a mode")
    mode = marker.get("mode")
    if not isinstance(mode, str) or not _MODE.fullmatch(mode):
        raise JourneyError(f"{where}: marker needs a mode such as run or illustrative")
    if mode == "output":
        raise JourneyError(
            f"{where}: an output marker is not written by hand; use a sample segment"
        )
    if mode == "options":
        raise JourneyError(
            f"{where}: options markers belong to tables, not journey blocks"
        )
    if mode == "config":
        kind = marker.get("kind")
        if not isinstance(kind, str) or not kind:
            raise JourneyError(
                f"{where}: a config marker needs kind=<kind>, such as github-actions"
            )
        if kind not in _config_kinds(checks):
            raise JourneyError(
                f"{where}: config kind {kind} is not one the docs checks read "
                f"({sorted(_config_kinds(checks))})"
            )
        allowed = _config_keys(checks, kind)
    else:
        allowed = set(checks.RUN_KEYS) | {"reason"}
    if mode == "config":
        given = {k: v for k, v in marker.items() if isinstance(v, str)}
        problems = checks._ci_key_problems(marker["kind"], given)
        if problems:
            raise JourneyError(f"{where}: {problems[0]}")
    for key, value in marker.items():
        if key == "mode":
            continue
        if key not in allowed:
            raise JourneyError(
                f"{where}: marker key {key!r} is not one the docs runner reads "
                f"({sorted(allowed)})"
            )
        if not isinstance(value, str):
            raise JourneyError(
                f"{where}: marker value for {key!r} must be a quoted string, "
                f"got {value!r}"
            )
        if any(ch in value for ch in '"\\\n'):
            raise JourneyError(
                f"{where}: marker value for {key!r} holds a quote, backslash or newline"
            )


def _check_twin_fields(twin: Any, block: dict, where: str) -> None:
    if not isinstance(twin, dict) or twin.get("kind") not in _TWIN_KINDS:
        raise JourneyError(f"{where}: twin.kind must be one of {sorted(_TWIN_KINDS)}")
    kind = twin["kind"]
    _unknown(twin, {"kind"} | _TWIN_KINDS[kind], f"{where}: twin")
    lang = block["lang"]
    if kind in {"project", "scan", "report"} and lang != "bash":
        raise JourneyError(f"{where}: a {kind} step is a bash block, not {lang!r}")
    if kind == "scan":
        code = twin.get("exit")
        if not isinstance(code, str) or not code.isdigit():
            raise JourneyError(f"{where}: twin.exit must be a quoted exit code")
        count = twin.get("actionable")
        if count is not None and (
            not isinstance(count, int) or isinstance(count, bool)
        ):
            raise JourneyError(f"{where}: twin.actionable must be a number")
        if count is not None and code == "0":
            raise JourneyError(
                f"{where}: a scan that exits 0 has no actionable findings to count"
            )
    elif kind == "report":
        if not isinstance(twin.get("rule-id"), str) or not twin["rule-id"]:
            raise JourneyError(f"{where}: twin.rule-id must name the rule")
    elif kind == "save":
        path = twin.get("path")
        if (
            not isinstance(path, str)
            or not _TWIN_PATH.fullmatch(path)
            or path.startswith("/")
            or ".." in PurePosixPath(path).parts
        ):
            raise JourneyError(
                f"{where}: twin.path must be a relative file path of letters, "
                f"digits and _ . / - with no '..' component, got {path!r}"
            )
        if lang not in {"yaml", "yml"}:
            raise JourneyError(f"{where}: a save step is a YAML block, not {lang!r}")
    elif kind == "fix":
        if twin.get("file-from") != "project":
            raise JourneyError(f"{where}: twin.file-from must be 'project'")
        function = twin.get("replaces-function")
        if not isinstance(function, str) or not function:
            raise JourneyError(f"{where}: twin.replaces-function must name a function")
        if lang != "python":
            raise JourneyError(f"{where}: a fix step is a Python block, not {lang!r}")


def _samples_after(body: list[dict], index: int) -> list[str]:
    """Text of the output samples after segment ``index``, up to the next twin step."""
    found: list[str] = []
    for segment in body[index + 1 :]:
        if "sample" in segment:
            found.append(segment["sample"])
        elif "block" in segment:
            block = segment["block"]
            if "twin" in block:
                break
            if block["lang"] == "text":
                found.append(block["body"])
    return found


def _check_agreement(body: list[dict], index: int) -> None:
    """A twin step's structured claims must agree with the samples shown after it."""
    block = body[index]["block"]
    twin = block["twin"]
    where = _where(index, body[index])
    samples = _samples_after(body, index)
    joined = "\n".join(samples)
    if twin["kind"] == "scan":
        exit_code = twin["exit"]
        shown = _EXIT_LINE.findall(joined)
        for code in shown:
            if code != exit_code:
                raise JourneyError(
                    f"{where}: twin.exit is {exit_code} but a sample after it says "
                    f"`exit code: {code}`"
                )
        if 'echo "exit code: $?"' in block["body"] and not shown:
            raise JourneyError(
                f"{where}: the block echoes its exit code but no sample after it "
                "shows `exit code: N`"
            )
        counts = _ACTIONABLE_LINE.findall(joined)
        expected = twin.get("actionable")
        for count in counts:
            if expected is None:
                raise JourneyError(
                    f"{where}: a sample after it says `Exiting due to {count} "
                    "actionable findings` but twin.actionable is not set"
                )
            if int(count) != expected:
                raise JourneyError(
                    f"{where}: twin.actionable is {expected} but a sample after it "
                    f"says `Exiting due to {count} actionable findings`"
                )
        if expected is not None and not counts:
            raise JourneyError(
                f"{where}: twin.actionable is {expected} but no sample after it "
                "shows an `Exiting due to N actionable findings` line"
            )
    elif twin["kind"] == "report":
        rule = twin["rule-id"]
        rules = _RULE_LINE.findall(joined)
        if not rules:
            raise JourneyError(f"{where}: no sample after it shows a `Rule ID:` line")
        for found in rules:
            if found != rule:
                raise JourneyError(
                    f"{where}: twin.rule-id is {rule} but a sample after it shows "
                    f"`Rule ID: {found}`"
                )


def _intro_prose(body: list[dict], index: int) -> str:
    """The prose segment that introduces the block at ``index``: the nearest one before
    it, looking back no further than the previous twin step."""
    for segment in reversed(body[:index]):
        if "prose" in segment:
            return segment["prose"]
        if "twin" in segment.get("block", {}):
            break
    return ""


def _refuse_heredoc_terminator(text: str, where: str, what: str) -> None:
    if any(line == "EOF" for line in text.splitlines()):
        raise JourneyError(
            f"{where}: {what} has a line that is exactly EOF, which would end the "
            "heredoc the twin writes it with; change that line"
        )


def _check_twin_steps(body: list[dict]) -> None:
    project: dict | None = None
    for index, segment in enumerate(body):
        block = segment.get("block")
        if not block or "twin" not in block:
            continue
        twin = block["twin"]
        where = _where(index, segment)
        if twin["kind"] == "save":
            _refuse_heredoc_terminator(block["body"], where, "the save text")
            if twin["path"] not in _intro_prose(body, index):
                raise JourneyError(
                    f"{where}: twin.path {twin['path']!r} does not appear in the "
                    "prose that introduces this step, so the twin would write a "
                    "file the page never tells the reader to create; name that "
                    "file in the prose, or change twin.path to the file it names"
                )
        elif twin["kind"] == "fix":
            _refuse_heredoc_terminator(block["body"], where, "the fix text")
        if twin["kind"] == "project":
            if project is not None:
                raise JourneyError(f"{where}: a journey has one project step")
            project = block
            if sum(1 for line in block["body"].splitlines() if line == "EOF") > 1:
                raise JourneyError(
                    f"{where}: the project's file text has a line that is exactly "
                    "EOF, which would end the heredoc early; change that line"
                )
            try:
                heredoc_file(block_body(block))
            except JourneyError as exc:
                raise JourneyError(f"{where}: {exc}") from exc
        elif twin["kind"] == "fix":
            if project is None:
                raise JourneyError(f"{where}: a fix step needs an earlier project step")
            _name, source = heredoc_file(block_body(project))
            function = twin["replaces-function"]
            if not re.search(rf"^def {re.escape(function)}\(", source, re.MULTILINE):
                raise JourneyError(
                    f"{where}: the project file defines no function {function}()"
                )
            if not re.match(rf"\s*def {re.escape(function)}\(", block["body"]):
                raise JourneyError(
                    f"{where}: the block does not define {function}(), "
                    "which twin.replaces-function names"
                )
        _check_agreement(body, index)


def _check_ci_fragments(body: list[dict]) -> None:
    """A fragment step (``config kind=<ci> extends=<path>``) extends a pipeline file an
    earlier step of the same journey saved with ``save-as=<path>``, of the same kind.

    The docs runner merges the fragment into that saved file and runs the result, so a
    fragment with nothing to extend would only fail there, on a CI runner, long after the
    page was written.
    """
    saved: dict[str, str] = {}
    for index, segment in enumerate(body):
        marker = segment.get("block", {}).get("marker")
        if not marker or marker.get("mode") != "config":
            continue
        where = _where(index, segment)
        target = marker.get("extends")
        if target is not None:
            if target not in saved:
                raise JourneyError(
                    f"{where}: extends {target}, which no earlier block of this "
                    "journey saves; add save-as=<path> to the block that writes "
                    "the file, before this one"
                )
            if saved[target] != marker["kind"]:
                raise JourneyError(
                    f"{where}: extends {target}, which is saved as config "
                    f"kind={saved[target]}, not kind={marker['kind']}"
                )
        path = marker.get("save-as")
        if path is not None:
            saved[path] = marker["kind"]


def load_journey(path: Path) -> dict:
    """Parse and validate a journey file; raises JourneyError naming what is wrong."""
    path = Path(path)
    text = path.read_text(encoding="utf-8")
    _refuse_yaml_features(text, path)
    journey = yaml.safe_load(text)
    if not isinstance(journey, dict):
        raise JourneyError(f"{path}: a journey is a mapping")
    _unknown(journey, _TOP_KEYS, str(path))
    if journey.get("schema") != SCHEMA:
        raise JourneyError(f"{path}: schema must be {SCHEMA}")
    for key in ("template", "page"):
        value = journey.get(key)
        if (
            not isinstance(value, str)
            or value.startswith("/")
            or ".." in Path(value).parts
        ):
            raise JourneyError(f"{path}: {key} must be a path inside the docs tree")
    if not journey["template"].endswith(".md.template") or journey["page"] != journey[
        "template"
    ].removesuffix(".template"):
        raise JourneyError(
            f"{path}: template must be the page's .md.template sibling "
            f"(page {journey['page']!r}, template {journey['template']!r})"
        )
    twin = journey.get("twin")
    if twin is not None:
        if not isinstance(twin, dict):
            raise JourneyError(f"{path}: twin is a mapping")
        _unknown(twin, _TWIN_KEYS, f"{path}: twin")
        if not isinstance(twin.get("scan"), str) or not twin["scan"].strip():
            raise JourneyError(f"{path}: twin.scan must be the narrowed scan command")
        timeout = twin.get("timeout")
        if not isinstance(timeout, int) or isinstance(timeout, bool) or timeout < 1:
            raise JourneyError(f"{path}: twin.timeout must be a number of seconds")
    body = journey.get("body")
    if not isinstance(body, list) or not body:
        raise JourneyError(f"{path}: body is a list of segments")
    for index, segment in enumerate(body):
        if (
            not isinstance(segment, dict)
            or len(segment) != 1
            or next(iter(segment)) not in {"prose", "block", "sample"}
        ):
            raise JourneyError(
                f"{path}: body[{index}] is exactly one of prose, block or sample"
            )
        where = f"{path}: {_where(index, segment)}"
        kind = next(iter(segment))
        value = segment[kind]
        if kind in {"prose", "sample"}:
            _text(value, where, kind)
            continue
        if not isinstance(value, dict):
            raise JourneyError(f"{where}: a block is a mapping")
        _unknown(value, _BLOCK_KEYS, where)
        lang = value.get("lang")
        if not isinstance(lang, str) or not _LANG.fullmatch(lang):
            raise JourneyError(f"{where}: a block needs a lang such as bash")
        _text(value.get("body"), where, "body")
        if any(line.strip().startswith("```") for line in value["body"].splitlines()):
            raise JourneyError(f"{where}: a block's text cannot hold a fence line")
        if "marker" in value:
            _check_marker(value["marker"], where)
        if "twin" in value:
            if twin is None:
                raise JourneyError(
                    f"{where}: a twin step needs the top-level twin: key"
                )
            _check_twin_fields(value["twin"], value, where)
    try:
        _check_twin_steps(body)
        _check_ci_fragments(body)
    except JourneyError as exc:
        raise JourneyError(f"{path}: {exc}") from exc
    return journey


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _marker_line(marker: dict) -> str:
    words = [marker["mode"]]
    for key, value in marker.items():
        if key == "mode":
            continue
        if not _SAFE_VALUE.fullmatch(value):
            value = f'"{value}"'
        words.append(f"{key}={value}")
    return f"<!-- doctest: {' '.join(words)} -->"


def _banner(source: str) -> str:
    """The comment block every journey render opens with, so a reader of the template
    or the page knows the journey is the file to edit."""
    extra = [
        "The page is rendered from this template by",
        "scripts/version_template_manager.py generate,",
        "so edit the journey, not the template or the page.",
    ]
    return "\n".join(banner(GENERATOR, source, extra))


def render(journey: dict, source: str) -> str:
    """The template text: the banner naming ``source``, then each segment verbatim, one
    blank line between segments."""
    pieces: list[str] = [_banner(source)]
    for segment in journey["body"]:
        if "prose" in segment:
            pieces.append(segment["prose"])
        elif "sample" in segment:
            pieces.append(
                f"<!-- doctest: output -->\n```text\n{segment['sample']}```\n"
            )
        else:
            block = segment["block"]
            marker = _marker_line(block["marker"]) + "\n" if "marker" in block else ""
            pieces.append(f"{marker}```{block['lang']}\n{block['body']}```\n")
    return "\n".join(pieces)


def _expected_blocks(journey: dict) -> list[tuple[str, str, str | None, dict]]:
    """(lang, body, marker mode, marker keys) for each fenced block the journey states."""
    expected = []
    for segment in journey["body"]:
        if "sample" in segment:
            expected.append(("text", segment["sample"][:-1], "output", {}))
        elif "block" in segment:
            block = segment["block"]
            marker = block.get("marker")
            keys = {k: v for k, v in (marker or {}).items() if k != "mode"}
            expected.append(
                (
                    block["lang"],
                    block["body"][:-1],
                    marker["mode"] if marker else None,
                    keys,
                )
            )
    return expected


def round_trip_problems(journey: dict, text: str, docs_root: Path) -> list[str]:
    """Differences between the journey and what the docs parser reads from its render."""
    checks = load_docs_checks()
    page = checks.parse_page(docs_root / journey["template"], docs_root, text=text)
    version = checks.current_version(str(docs_root))
    problems = [str(finding) for finding in page.structure]
    expected = _expected_blocks(journey)
    if len(page.blocks) != len(expected):
        problems.append(
            f"the render parses to {len(page.blocks)} blocks, the journey states "
            f"{len(expected)}"
        )
        return problems
    for number, (block, want) in enumerate(zip(page.blocks, expected), 1):
        lang, body, mode, keys = want
        body = body.replace(checks.VERSION_PLACEHOLDER, version)
        got_mode = block.marker.mode if block.marker else None
        got_keys = dict(block.marker.keys) if block.marker else {}
        if (block.lang, block.body, got_mode, got_keys) != (lang, body, mode, keys):
            problems.append(
                f"block {number} (line {block.fence_line}) parses to "
                f"lang={block.lang!r} marker={got_mode!r} {got_keys!r}, not the "
                f"journey's lang={lang!r} marker={mode!r} {keys!r}, or its text differs"
            )
    return problems


def render_checked(journey_path: Path, docs_root: Path) -> tuple[dict, str]:
    """Load, render and verify the render parses back to the journey."""
    journey = load_journey(journey_path)
    text = render(journey, _rel(journey_path, docs_root))
    problems = round_trip_problems(journey, text, docs_root)
    if problems:
        raise JourneyError(
            f"{journey_path}: the render does not parse back to the journey:\n  "
            + "\n  ".join(problems)
        )
    return journey, text


# ---------------------------------------------------------------------------
# Finding journeys, checking them, the command line
# ---------------------------------------------------------------------------


def find_journeys(docs_root: Path) -> list[Path]:
    directory = Path(docs_root) / JOURNEY_DIR
    return sorted(directory.glob(f"*{JOURNEY_SUFFIX}")) if directory.is_dir() else []


def _rel(path: Path, docs_root: Path) -> str:
    try:
        return Path(path).resolve().relative_to(Path(docs_root).resolve()).as_posix()
    except ValueError:
        return str(path)


def check_journeys(docs_root: Path, journeys: list[Path] | None = None) -> list[str]:
    """One line per journey that is refused, or whose template or page is not current."""
    docs_root = Path(docs_root)
    failures: list[str] = []
    for path in journeys if journeys is not None else find_journeys(docs_root):
        rel = _rel(path, docs_root)
        try:
            journey, text = render_checked(path, docs_root)
        except JourneyError as exc:
            failures.append(f"{rel} is refused: {exc}")
            continue
        template = docs_root / journey["template"]
        actual = template.read_text(encoding="utf-8") if template.is_file() else None
        if actual != text:
            state = "is not committed" if actual is None else "differs from the render"
            failures.append(
                f"{journey['template']} {state}: it is the render of {rel}, "
                f"so edit the journey and run: {REGENERATE}"
            )
        if not (docs_root / journey["page"]).is_file():
            failures.append(
                f"{rel} names the page {journey['page']}, which is not committed; "
                "render it with scripts/version_template_manager.py generate"
            )
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "--check",
        action="store_true",
        help="Exit 1 with a diff if a render is stale or a journey is refused.",
    )
    parser.add_argument(
        "--journey",
        action="append",
        default=None,
        help="Journey file to render (repeatable). Default: every journey under "
        "<docs root>/docs/journeys/.",
    )
    add_docs_root_argument(parser)
    args = parser.parse_args(argv)
    docs_root = Path(args.docs_root).resolve()
    journeys = (
        [Path(p).resolve() for p in args.journey]
        if args.journey
        else find_journeys(docs_root)
    )
    if not journeys:
        print(f"No journey files under {docs_root / JOURNEY_DIR}.", file=sys.stderr)
        return 0
    status = 0
    for path in journeys:
        if not path.is_file():
            print(f"{path} does not exist.", file=sys.stderr)
            status = 1
            continue
        try:
            journey, text = render_checked(path, docs_root)
        except JourneyError as exc:
            print(f"{_rel(path, docs_root)} is refused: {exc}", file=sys.stderr)
            status = 1
            continue
        summary = (
            f"{len(journey['body'])} segments from {_rel(path, docs_root)}, "
            f"{len(_expected_blocks(journey))} blocks."
        )
        status |= write_or_check(
            docs_root / journey["template"], text, args.check, GENERATOR, summary
        )
        if args.check and not (docs_root / journey["page"]).is_file():
            print(
                f"{journey['page']} is not committed; render it with "
                "scripts/version_template_manager.py generate",
                file=sys.stderr,
            )
            status = 1
    return status


if __name__ == "__main__":
    sys.exit(main())
