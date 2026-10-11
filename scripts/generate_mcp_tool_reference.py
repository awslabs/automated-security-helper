#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate the agentic-plugins MCP tool reference from the live MCP registry.

Why this exists
---------------
``ash-agent-plugins/agentic-coding/transpiler/_base/references/tool-reference.md``
is the source that the transpiler byte-copies into every plugin backend. At the
commit that added this script it documented 8 tools and 2 resources while
``automated_security_helper/cli/mcp_server.py`` registered 21 tools and 5
resources -- 13 tools and 3 resources missing, and a prose sentence on line 3
stating the wrong counts.

The existing ``agentic-plugins check`` gate is sound and is deliberately left
alone: it rebuilds every backend into a tempdir and byte-compares whole output
trees against what is on disk, which proves the copies match ``_base/``. It
cannot notice that ``_base/`` itself is behind ``mcp_server.py``, because it
never inspects content. This script closes that second gap; the byte-compare
then propagates the result to every copy for free.

Why this is a hybrid rather than a pure derivation
--------------------------------------------------
The file carries operational knowledge that exists in no docstring and no
schema. The clearest example:

    **Decide on `status`, not `is_complete`.** ... Polling on `is_complete`
    alone never ends for a cancelled or failed scan that writes no results file.

That is a correction TO the server's own docstring and its ``next_steps`` advice.
A generator that rendered only what the code says about itself would delete it,
making the document cheaper to maintain and worse to read. The cost is that the
notes are claims about behavior that nothing re-derives: each was checked against
the server code (``scan_registry.py``, ``mcp_tools.py``) when written, and a change
to that behavior needs the note changed by hand. So the split is:

* Derived from the registry, because this is what drifted: which tools exist,
  which resources exist, the counts, and each tool's parameter names, types,
  required/default status.
* Editorial, held in ``TOOL_NOTES`` below: the intro override, the ``Returns:``
  example blocks, and the caveats. Per-parameter ``Notes`` text likewise.

A registered tool with no ``TOOL_NOTES`` entry is not an error -- its intro comes
from the docstring's first line, which is accurate and specific enough to publish
(measured across all 21). What *is* an error is a ``TOOL_NOTES`` entry naming a
tool that is not registered, because that is a stale note.

The docs-site page
------------------
The same content is also written to docs/content/reference/mcp-tools.md, under the
reference pages' common banner. Bold is dropped there because the docs' house
style keeps bold out of running prose; the agent-facing file keeps it.

Usage
-----
    uv run python scripts/generate_mcp_tool_reference.py           # rewrite
    uv run python scripts/generate_mcp_tool_reference.py --check   # fail if stale

After a rewrite, propagate to the plugin backends and commit the result:

    uv run --project ash-agent-plugins/agentic-coding/transpiler agentic-plugins build

Note that no pre-commit hook fires the transpiler in this monorepo -- the
``ash-agent-plugins/.pre-commit-config.yaml`` patterns are rooted at
``^agentic-coding/`` and so only match when that directory is checked out as its
own repository. The drift gate runs in CI only, so the build step above is
manual and must not be skipped.
"""

from __future__ import annotations

import argparse
import asyncio
import difflib
import inspect
import sys
from pathlib import Path

#: The two files this script writes, relative to the docs tree (``--docs-root``).
TARGET = Path(
    "ash-agent-plugins/agentic-coding/transpiler/_base/references/tool-reference.md"
)
REFERENCE_PAGE = Path("docs/content/reference/mcp-tools.md")
GENERATOR = "scripts/generate_mcp_tool_reference.py"

NUMBER_WORDS = {
    1: "one",
    2: "two",
    3: "three",
    4: "four",
    5: "five",
    6: "six",
    7: "seven",
    8: "eight",
    9: "nine",
    10: "ten",
    11: "eleven",
    12: "twelve",
    13: "thirteen",
    14: "fourteen",
    15: "fifteen",
    16: "sixteen",
    17: "seventeen",
    18: "eighteen",
    19: "nineteen",
    20: "twenty",
    21: "twenty-one",
    22: "twenty-two",
    23: "twenty-three",
    24: "twenty-four",
    25: "twenty-five",
}


def _spell(n: int) -> str:
    return NUMBER_WORDS.get(n, str(n))


# Editorial content per tool. Every field is optional.
#   intro     -- replaces the docstring's first line.
#   params    -- per-parameter Notes column. The Default column is always the
#                schema's default, because the docs checks compare it with the
#                schema; what an unset parameter means goes in the notes.
#   returns   -- a fenced example response block.
#   caveats   -- paragraphs appended after the returns block, in order.
TOOL_NOTES: dict[str, dict] = {
    "run_ash_scan": {
        "intro": (
            "Starts a scan in the server process and returns a `scan_id` at once. The "
            "scan stops if the server process exits; over stdio, that is when the "
            "client disconnects."
        ),
        "params": {
            "source_dir": {
                "notes": (
                    "Absolute path to scan. When not set: the source delivered to this "
                    "session with `set_source_git` or `set_source_zip_finalize`, or, for "
                    "a client with no session, the server's working directory"
                )
            },
            "severity_threshold": {
                "notes": (
                    "Recorded with the scan and returned by `get_scan_progress`; it "
                    "does not change which findings the scan reports"
                )
            },
            "config_path": {
                "notes": (
                    "Custom config path. When not set: the config this session bound "
                    "with `select_profile`, or else ASH's own discovery in the source "
                    "directory"
                ),
            },
            "clean_output": {"notes": "Wipe stale reports before starting"},
        },
        "pre_returns": (
            "Output reports are written to `<source_dir>/.ash/ash_output/` — there is no "
            "parameter to override this. Scanner selection, mode, and other tuning live in "
            "`.ash/.ash.yaml`, not in tool arguments."
        ),
        "returns": """{
  "success": true,
  "status": "running",
  "scan_id": "<uuid>",
  "progress": 0.0,
  "message": "Scan started, initializing scanners. Use get_scan_progress to track progress.",
  "directory_path": "<absolute path scanned>",
  "important": {
    "connection_management": "<server's polling guidance>",
    "next_steps": ["..."]
  }
}""",
        "caveats": [
            (
                "The `directory_path` field tells you the resolved absolute path the server is "
                "scanning — derive `output_dir` for `get_scan_results` from this value "
                "(`<directory_path>/.ash/ash_output`) rather than constructing it independently."
            ),
            (
                "**Heads-up:** the server's own docstring and the `important.next_steps` array "
                "suggest polling `progress['is_complete']`. Decide on `status` instead: "
                "`is_complete` can stay `False` for a cancelled or failed scan that "
                "writes no results file. (See `get_scan_progress` below.)"
            ),
        ],
    },
    "get_scan_progress": {
        "intro": (
            "Poll progress every 5 seconds until `status` is `completed`, `incomplete`, "
            "`failed`, or `cancelled`."
        ),
        "params": {"scan_id": {"notes": "From `run_ash_scan`"}},
        "returns": """{
  "scan_id": "...",
  "directory_path": "/path/to/scanned/project",
  "output_directory": "/path/to/.ash/ash_output",
  "start_time": "<iso8601>",
  "end_time": "<iso8601 | null>",
  "status": "pending | running | completed | incomplete | failed | cancelled",
  "severity_threshold": "MEDIUM",
  "config_path": "<path | null>",
  "warnings": [...],
  "error_message": "<str | null>",
  "is_complete": bool,
  "coverage_complete": "bool | null",
  "incomplete_scanners": [
    { "scanner": "grype", "status": "MISSING", "reason": "missing_dependencies", "detail": "MISSING" }
  ],
  "no_scanner_ran": bool,
  "incomplete_converters": [{ "converter": "...", "reason": "..." }],
  "unevaluated_rules": ["..."],
  "stale_content_databases": [{ "name": "grype-db", "scanner": "grype", "built": "<iso8601 | null>", "age": "...", "max_age": "...", "refresh": "..." }],
  "completed_scanners": int,
  "total_scanners": int,
  "total_findings": int,
  "severity_counts": { "critical": int, "high": int, "medium": int, "low": int, "info": int, "suppressed": int },
  "scanners": {
    "<scanner_name>": {
      "<target_type>": { ... per-scanner-target progress ... }
    }
  }
}""",
        "caveats": [
            (
                "There is no overall percentage field. To compute progress, use "
                "`completed_scanners / total_scanners` — but **guard against "
                "`total_scanners == 0`** during the pre-flight phase (before any scanner has "
                'registered). Show "initializing" or 0% when `total_scanners` is zero.'
            ),
            (
                "There is no top-level `duration` field — derive elapsed time from "
                "`start_time` and `end_time` (or from current time while running)."
            ),
            (
                "**Decide on `status`, not `is_complete`.** `is_complete` is `True` for "
                "`completed` and `incomplete`, and for `failed` or `cancelled` once a results "
                "file exists in the output directory, which an earlier scan of the same "
                "directory may have left. Stop polling when `status` is `completed`, "
                "`incomplete`, `failed`, or `cancelled`. Polling on `is_complete` alone "
                "never ends for a cancelled or failed scan that writes no results file."
            ),
            (
                "**`incomplete` is terminal, with partial coverage.** The run finished and its "
                "results are readable, but a selected scanner was `MISSING` or `ERROR` (or lost "
                "targets), no scanner reached a verdict, a converter did not run, a rule "
                "could not be evaluated, or a content database was past its declared age "
                "bound. `incomplete_scanners` names each scanner and why, and "
                "`stale_content_databases` each stale database. The "
                "findings are real but partial, so read them, and do not report the target as "
                "clean. `failed` means the run crashed or left no readable results. "
                "`coverage_complete` is `null` while running and for `failed` or `cancelled`; "
                "with `fail_on_incomplete_scanners: false` a scan is `completed` with "
                "`coverage_complete: false` when scanners did not run."
            ),
            (
                "**Status enum:** the documented values are "
                "`pending | running | completed | incomplete | failed | cancelled`. The registry uses "
                "`pending` briefly while a scan is queued, transitions to `running` once "
                "execution begins, and may also expose the legacy `in_progress` string from "
                "older `ScanProgress` instances. Treat `pending`, `running`, and `in_progress` "
                'as equivalent "not done yet" states.'
            ),
        ],
    },
    "get_scan_results": {
        "intro": (
            "Fetch finalized results with filtering. Run only after `get_scan_progress` "
            "reports complete."
        ),
        "params": {
            "output_dir": {
                "notes": (
                    "Absolute path strongly recommended; the server resolves relative paths "
                    "against its own cwd, which usually isn't your project root"
                )
            },
            "filter_level": {"notes": "`full`, `summary`, `minimal`"},
            "scanners": {
                "notes": "Comma-separated subset; not set means every scanner"
            },
            "severities": {
                "notes": (
                    "Comma-separated subset of `critical,high,medium,low,info,suppressed`; "
                    "not set means every severity"
                ),
            },
            "actionable_only": {
                "notes": (
                    "Sets the suppressed counts to zero. The `findings` list it adds is "
                    "always empty, because the response does not carry the SARIF it is "
                    "built from"
                )
            },
        },
        "caveats": [
            (
                "With `filter_level` `full`, `raw_results` is the aggregated results "
                "document without its `sarif`, `cyclonedx` and `ash_config` sections; "
                "`summary` returns the metadata and the counts by severity and by scanner, "
                "and `minimal` the status. Individual findings are in the report files: "
                "`get_scan_result_paths` lists them, and the `flat-json` reporter, which "
                "is enabled by default, writes `reports/ash.flat.json` under "
                "`output_dir`."
            ),
            (
                "`status` is `completed` or `incomplete`, decided by the same rule as the scan's "
                "exit code, with `coverage_complete` and `incomplete_scanners` as in "
                "`get_scan_progress`. An `incomplete` scan's findings are returned in full."
            ),
        ],
    },
    "get_scan_summary": {
        "intro": (
            "Metadata and counts only — no individual findings. Cheap for quick health checks."
        ),
        "params": {"output_dir": {"notes": "Absolute path"}},
        "caveats": ["Returns total count, severity breakdown, scanner statuses."],
    },
    "get_scan_result_paths": {
        "intro": (
            "Returns file paths to all generated reports. Useful when you want to read HTML, "
            "SARIF, CSV, or markdown directly with file tools instead of pulling JSON over MCP."
        ),
        "params": {"output_dir": {"notes": "Absolute path"}},
        "caveats": ["Returns a dict mapping format names to absolute paths."],
    },
    "list_active_scans": {
        "intro": "All scans the server tracks (active + recently completed).",
        "no_params_sentence": "No parameters. Returns a list of scan summaries.",
    },
    "cancel_scan": {
        "intro": (
            "Marks a running scan `cancelled`. It does not stop the scan: the scan keeps "
            "running in the server process and can still write its results, while its "
            "`status` stays `cancelled`."
        ),
        "params": {"scan_id": {"notes": "The scan to mark cancelled"}},
        "caveats": [
            (
                "Returns `success`, `status`, and `message`. A scan that has already "
                "finished is not changed, and the response has `success: false` and the "
                "scan's status."
            ),
        ],
    },
    "check_installation": {
        "intro": (
            "Reports the version of the ASH package the MCP server runs. It does not run "
            "a scan or check that any scanner's tool is installed."
        ),
        "no_params_sentence": (
            "No parameters. Returns `version`, with `installed` and "
            "`ash_command_available` both `true` when the version could be read."
        ),
    },
    "set_source_zip_chunk": {
        "params": {
            "upload_id": {
                "notes": "Caller-chosen id tying the chunks of one upload together"
            },
            "sequence": {
                "notes": "Zero-based chunk index; chunks must arrive in order"
            },
            "data_b64": {"notes": "Base64 of this chunk's bytes"},
            "last": {"notes": "`true` on the final chunk"},
        },
        "caveats": [
            (
                "Pair with `set_source_zip_finalize`, which verifies the reassembled archive "
                "against `expected_sha256` before extracting it. A chunked upload that is never "
                "finalized is not a scan target."
            ),
        ],
    },
    "set_source_git": {
        "params": {
            "url": {"notes": "Repository URL"},
            "ref": {
                "notes": (
                    "Branch, tag, or commit; not set means the remote's default branch"
                )
            },
            "ssh_key_id": {
                "notes": (
                    "Operator-registered key id for private repos; not set means no key"
                ),
            },
            "depth": {"notes": "Clone depth; `0` for a full clone"},
        },
    },
    "list_scanners": {
        "no_params_sentence": (
            "No parameters. Returns one entry per registered scanner with its config name, "
            "detected version, and whether it is enabled."
        ),
    },
    "list_profiles": {
        "no_params_sentence": (
            "No parameters. Returns the config profiles the operator registered at server "
            "startup."
        ),
    },
    "clear_source": {
        "no_params_sentence": (
            "No parameters. Deletes this session's delivered source tree and workspace."
        ),
    },
}


def _type_name(schema: dict) -> str:
    """Render a JSON-schema fragment the way this document spells types.

    Unions are written `string \\| null` with an escaped pipe, because the value
    lands in a markdown table cell where a bare pipe would end the column.
    """
    if "anyOf" in schema:
        parts = [_type_name(s) for s in schema["anyOf"]]
        seen: list[str] = []
        for part in parts:
            if part not in seen:
                seen.append(part)
        return r" \| ".join(seen)
    if "enum" in schema:
        return "string"
    declared = schema.get("type")
    if isinstance(declared, list):
        return r" \| ".join(str(d) for d in declared)
    if declared == "array":
        return "array"
    return str(declared or "any")


def _default_display(schema: dict, required: bool) -> str:
    """The schema's default as the docs checks read it: a phrase or one JSON span."""
    import json

    if required:
        return "*required*"
    if "default" not in schema:
        return ""
    value = schema["default"]
    if value is None:
        return "not set"
    return f"`{json.dumps(value)}`"


#: The docs checks compare each tool's parameter table with the tool's input schema.
def _options_marker(tool: str) -> str:
    return f"<!-- doctest: options of=mcp.{tool} -->"


def _docstring_arg_notes(func) -> dict[str, str]:
    """Per-parameter descriptions parsed out of a Google-style ``Args:`` block.

    Used as the fallback for the Notes column so a tool with no ``TOOL_NOTES``
    entry still gets populated cells rather than blank ones. Continuation lines
    are folded into the preceding parameter, because several of these docstrings
    wrap a long description over two or three lines.
    """
    doc = inspect.getdoc(func) or ""
    if "Args:" not in doc:
        return {}
    section = doc.split("Args:", 1)[1]
    for terminator in ("Returns:", "Raises:", "Example:", "Examples:", "Note:"):
        if terminator in section:
            section = section.split(terminator)[0]

    found: dict[str, str] = {}
    current: str | None = None
    for raw in section.splitlines():
        line = raw.strip()
        if not line:
            continue
        head, sep, tail = line.partition(":")
        candidate = head.strip()
        if (
            sep
            and candidate
            and candidate.replace("_", "").isalnum()
            and " " not in candidate
        ):
            current = candidate
            found[current] = tail.strip()
        elif current:
            found[current] = f"{found[current]} {line}".strip()

    # A pipe would end the markdown table column early.
    return {k: v.replace("|", r"\|") for k, v in found.items()}


def _render_tool(name: str, description: str, schema: dict, func) -> list[str]:
    notes = TOOL_NOTES.get(name, {})
    doc_notes = _docstring_arg_notes(func)
    lines = [f"## {name}", ""]

    intro = notes.get("intro")
    if not intro:
        doc = inspect.getdoc(func) or description or ""
        intro = " ".join(doc.split("\n\n")[0].split()).strip()
    lines += [intro, ""]

    properties: dict = schema.get("properties", {})
    required = set(schema.get("required", []))
    param_notes: dict = notes.get("params", {})

    if not properties:
        lines += [notes.get("no_params_sentence", "No parameters."), ""]
    else:
        # Match the existing convention: a Default column only when at least one
        # parameter has a default worth showing.
        defaults = {
            key: _default_display(spec, key in required)
            for key, spec in properties.items()
        }
        # The document's existing convention: a Default column appears only when
        # some parameter actually has a default. A tool whose parameters are all
        # required renders as a three-column table, so "*required*" alone does not
        # earn the column.
        show_default = any(v for v in defaults.values() if v != "*required*")
        lines.append(_options_marker(name))
        if show_default:
            lines += [
                "| Param | Type | Default | Notes |",
                "|-------|------|---------|-------|",
            ]
        else:
            lines += ["| Param | Type | Notes |", "|-------|------|-------|"]
        for key, spec in properties.items():
            note = param_notes.get(key, {}).get("notes") or doc_notes.get(key, "")
            if show_default:
                lines.append(
                    f"| `{key}` | {_type_name(spec)} | {defaults[key]} | {note} |"
                )
            else:
                lines.append(f"| `{key}` | {_type_name(spec)} | {note} |")
        lines.append("")

    if notes.get("pre_returns"):
        lines += [notes["pre_returns"], ""]

    if notes.get("returns"):
        lines += ["Returns:", "```json", notes["returns"], "```", ""]

    for caveat in notes.get("caveats", []):
        lines += [caveat, ""]

    return lines


def render() -> str:
    """The agent-facing tool-reference.md."""
    header, body = _render_parts()
    return "\n".join(header + _adapt_markdown(body, strip_bold=False))


def render_reference_page() -> str:
    """docs/content/reference/mcp-tools.md: the same body under the reference banner."""

    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _reference_docs import banner, generated_note

    _header, body = _render_parts()
    lines = banner(GENERATOR, "the MCP server's registered tools and resources")
    lines += [
        "# MCP tools reference",
        "",
        generated_note(
            GENERATOR,
            "the tools and resources the ASH MCP server registers, with editorial notes "
            "kept in the generator",
        ),
        "",
    ]
    return "\n".join(_adapt_markdown(lines + body, strip_bold=True))


#: Marker the docs doctest reads on a fenced JSON block that is an example, not an
#: ASH config (see the doctest contract's "Config blocks").
_RESPONSE_EXAMPLE_MARKER = (
    '<!-- doctest: config kind=other reason="example MCP tool response" -->'
)


def _adapt_markdown(lines: list[str], strip_bold: bool) -> list[str]:
    """Make the response examples pass the docs checks, and on the docs site drop bold.

    * A ```json response example that does not parse as JSON (``bool``, ``[...]``
      placeholders) becomes a ```text block, because the docs checks parse every
      JSON block. One that parses keeps its language and gets the marker saying it
      is an example rather than an ASH config. Both files get this: the docs
      checks read the agent-facing file and every copy the transpiler makes of it.
    * With ``strip_bold``, no bold in running prose (the docs site's house style).
      Bold that wraps a code span is unwrapped too; ``**`` inside a code span or a
      fence is left alone. The agent-facing file keeps its bold. Table cells also
      get ``<`` and ``>`` outside code spans escaped there.
    """
    import json
    import re

    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        if line.strip() == "```json":
            end = i + 1
            while end < len(lines) and lines[end].strip() != "```":
                end += 1
            block = lines[i + 1 : end]
            try:
                json.loads("\n".join(block))
                parsed = True
            except ValueError:
                parsed = False
            if out and out[-1] != "":
                out.append("")
            if parsed:
                out += [_RESPONSE_EXAMPLE_MARKER, "```json"]
            else:
                out.append("```text")
            out += block
            out.append("```")
            i = end + 1
            continue
        if line.startswith("```") or not strip_bold:
            out.append(line)
            i += 1
            continue
        spans: list[str] = []

        def hide(match):
            spans.append(match.group(0))
            return f"\x00{len(spans) - 1}\x00"

        hidden = re.sub(r"`[^`]*`", hide, line)
        hidden = hidden.replace("**", "")
        if hidden.startswith("|"):
            # Notes taken from docstrings say things like "Defaults to <cwd>/...",
            # which python-markdown would pass through as an HTML tag and the
            # browser would drop. The agent-facing file is read as text and keeps it.
            hidden = hidden.replace("<", "&lt;").replace(">", "&gt;")
        out.append(re.sub(r"\x00(\d+)\x00", lambda m: spans[int(m.group(1))], hidden))
        i += 1
    return out


def _render_parts() -> tuple[list[str], list[str]]:
    from automated_security_helper.cli import mcp_server

    tools = asyncio.run(mcp_server.mcp.list_tools())
    resources = asyncio.run(mcp_server.mcp.list_resources())

    stale_notes = sorted(set(TOOL_NOTES) - {t.name for t in tools})
    if stale_notes:
        raise SystemExit(
            f"ERROR: TOOL_NOTES has entries for tools that are not registered: "
            f"{stale_notes}. Remove them or fix the tool's registration."
        )

    # Document order: the editorial ordering for the tools that had it, then the
    # rest alphabetically, so a newly registered tool lands in a stable place.
    editorial_order = [
        "run_ash_scan",
        "get_scan_progress",
        "get_scan_results",
        "get_scan_summary",
        "get_scan_result_paths",
        "list_active_scans",
        "cancel_scan",
        "check_installation",
    ]
    by_name = {t.name: t for t in tools}
    ordered = [by_name[n] for n in editorial_order if n in by_name]
    ordered += sorted(
        (t for t in tools if t.name not in editorial_order), key=lambda t: t.name
    )

    lines = [
        "# ASH MCP Tool Reference",
        "",
        "<!-- Generated by scripts/generate_mcp_tool_reference.py from the MCP server's",
        "     registered tools and resources. Do not edit this file directly; edit the",
        "     generator (prose and caveats live in its TOOL_NOTES table) and re-run it,",
        "     then `agentic-plugins build` to propagate to every plugin backend. -->",
        "",
    ]
    header_length = len(lines)
    lines += [
        (
            f"The ASH MCP server exposes {_spell(len(tools))} tools and "
            f"{_spell(len(resources))} resources."
        ),
        "",
    ]

    for tool in ordered:
        lines += _render_tool(
            tool.name,
            tool.description or "",
            tool.input_schema or {},
            getattr(mcp_server, tool.name),
        )

    lines += ["## Resources", ""]
    for resource in sorted(resources, key=lambda r: str(r.uri)):
        summary = " ".join((resource.description or "").split())
        summary = summary.rstrip(".")
        lines.append(f"- `{resource.uri}` — {summary}")
    lines += [
        "",
        "Read these via the standard MCP resource read mechanism for context-free help.",
        "",
        "## Severity levels",
        "",
        "`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO` > `SUPPRESSED`",
        "",
        (
            "`actionable_only=True` on `get_scan_results` sets the `SUPPRESSED` counts "
            "(false positives, accepted risks) to zero; the `findings` list it adds is "
            "always empty."
        ),
        "",
    ]

    return lines[:header_length], lines[header_length:]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not write. Exit non-zero with a diff if either file is stale.",
    )
    parser.add_argument(
        "--output",
        default=None,
        help=(
            "Write only the docs-site page, to this path ('-' for stdout), and leave "
            "the agent-facing file alone. For measuring another tree's MCP surface."
        ),
    )
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _reference_docs import add_docs_root_argument, prepare_environment

    add_docs_root_argument(parser)
    args = parser.parse_args()

    docs_root = Path(args.docs_root).resolve()
    prepare_environment(docs_root)
    if args.output:
        page = render_reference_page()
        if args.output == "-":
            sys.stdout.write(page)
        else:
            with open(args.output, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(page)
        return 0
    status = 0
    for target, expected, after in (
        (
            docs_root / TARGET,
            render(),
            (
                "Then propagate: uv run --project "
                "ash-agent-plugins/agentic-coding/transpiler agentic-plugins build"
            ),
        ),
        (docs_root / REFERENCE_PAGE, render_reference_page(), ""),
    ):
        status |= _write_or_check(target, expected, args.check, after, docs_root)
    return status


def _write_or_check(
    target: Path, expected: str, check: bool, after: str, docs_root: Path
) -> int:
    actual = target.read_text(encoding="utf-8") if target.exists() else ""
    rel = target.relative_to(docs_root)

    if expected == actual:
        if check:
            print(f"{rel} is up to date.", file=sys.stderr)
        return 0

    if check:
        print(
            f"{rel} is stale relative to the MCP registry.\n"
            f"Regenerate with: uv run python scripts/generate_mcp_tool_reference.py\n"
            + (f"{after}\n" if after else ""),
            file=sys.stderr,
        )
        sys.stderr.writelines(
            difflib.unified_diff(
                actual.splitlines(keepends=True),
                expected.splitlines(keepends=True),
                fromfile=f"{rel.name} (on disk)",
                tofile=f"{rel.name} (regenerated)",
                n=1,
            )
        )
        return 1

    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(expected, encoding="utf-8")
    print(f"Wrote {rel}", file=sys.stderr)
    if after:
        print(f"Now run: {after.removeprefix('Then propagate: ')}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
