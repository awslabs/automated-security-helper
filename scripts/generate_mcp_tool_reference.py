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

    **`is_complete` does not flip to `True` for cancelled scans** ... Polling on
    `is_complete` alone will loop forever on a cancelled scan.

That is a correction TO the server's own docstring. A generator that rendered
only what the code says about itself would delete it, making the document
cheaper to maintain and worse to read. So the split is:

* Derived from the registry, because this is what drifted: which tools exist,
  which resources exist, the counts, and each tool's parameter names, types,
  required/default status.
* Editorial, held in ``TOOL_NOTES`` below: the intro override, the ``Returns:``
  example blocks, and the caveats. Per-parameter ``Notes`` text likewise.

A registered tool with no ``TOOL_NOTES`` entry is not an error -- its intro comes
from the docstring's first line, which is accurate and specific enough to publish
(measured across all 21). What *is* an error is a ``TOOL_NOTES`` entry naming a
tool that is not registered, because that is a stale note.

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

REPO_ROOT = Path(__file__).resolve().parent.parent
TARGET = (
    REPO_ROOT
    / "ash-agent-plugins/agentic-coding/transpiler/_base/references/tool-reference.md"
)

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
#   params    -- per-parameter Notes column, and an optional default_display that
#                overrides the schema default when the schema value is uninformative
#                (e.g. `null` where the real behaviour is "current dir").
#   returns   -- a fenced example response block.
#   caveats   -- paragraphs appended after the returns block, in order.
TOOL_NOTES: dict[str, dict] = {
    "run_ash_scan": {
        "intro": (
            "Starts a scan asynchronously. Returns a `scan_id` immediately — the scan "
            "continues in the background regardless of MCP connection state."
        ),
        "params": {
            "source_dir": {"default": "current dir", "notes": "Absolute path to scan"},
            "severity_threshold": {
                "notes": "Findings below this are filtered out at scan time"
            },
            "config_path": {
                "default": "`<source>/.ash/.ash.yaml`",
                "notes": "Custom config path",
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
            "The `directory_path` field tells you the resolved absolute path the server is "
            "scanning — derive `output_dir` for `get_scan_results` from this value "
            "(`<directory_path>/.ash/ash_output`) rather than constructing it independently.",
            "**Heads-up:** the server's own docstring and the `important.next_steps` array "
            "suggest polling `progress['is_complete']`. This is incomplete advice — "
            "`is_complete` stays `False` for cancelled scans. Always check `status` "
            "independently. (See `get_scan_progress` below.)",
        ],
    },
    "get_scan_progress": {
        "intro": (
            "Poll progress every 5 seconds until complete. Keeps the MCP connection alive "
            "while the scan runs."
        ),
        "params": {"scan_id": {"notes": "From `run_ash_scan`"}},
        "returns": """{
  "scan_id": "...",
  "directory_path": "/path/to/scanned/project",
  "output_directory": "/path/to/.ash/ash_output",
  "start_time": "<iso8601>",
  "end_time": "<iso8601 | null>",
  "status": "running | completed | failed | cancelled",
  "severity_threshold": "MEDIUM",
  "config_path": "<path | null>",
  "warnings": [...],
  "error_message": "<str | null>",
  "is_complete": bool,
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
            "There is no overall percentage field. To compute progress, use "
            "`completed_scanners / total_scanners` — but **guard against "
            "`total_scanners == 0`** during the pre-flight phase (before any scanner has "
            'registered). Show "initializing" or 0% when `total_scanners` is zero.',
            "There is no top-level `duration` field — derive elapsed time from "
            "`start_time` and `end_time` (or from current time while running).",
            "**`is_complete` does not flip to `True` for cancelled scans** — it returns "
            "`True` only for `completed` and `failed`. Always check `status` independently: "
            "stop polling when `status` is `completed`, `failed`, or `cancelled`. Polling on "
            "`is_complete` alone will loop forever on a cancelled scan.",
            "**Status enum:** the documented values are "
            "`pending | running | completed | failed | cancelled`. The registry uses "
            "`pending` briefly while a scan is queued, transitions to `running` once "
            "execution begins, and may also expose the legacy `in_progress` string from "
            "older `ScanProgress` instances. Treat `pending`, `running`, and `in_progress` "
            'as equivalent "not done yet" states.',
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
            "scanners": {"default": "all", "notes": "Comma-separated subset"},
            "severities": {
                "default": "all",
                "notes": "`critical,high,medium,low,info`",
            },
            "actionable_only": {"notes": "Drop suppressed findings"},
        },
        "caveats": ["Returns full or filtered findings depending on `filter_level`."],
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
        "intro": "Stop a running scan and free resources.",
        "params": {"scan_id": {"notes": "The scan to stop"}},
        "caveats": ["Returns confirmation."],
    },
    "check_installation": {
        "intro": (
            "Verify ASH is installed and the MCP server can spawn it. Run before the first "
            "scan in a session if you're unsure of the install state."
        ),
        "no_params_sentence": "No parameters. Returns version string and feature flags.",
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
            "Pair with `set_source_zip_finalize`, which verifies the reassembled archive "
            "against `expected_sha256` before extracting it. A chunked upload that is never "
            "finalized is not a scan target.",
        ],
    },
    "set_source_git": {
        "params": {
            "url": {"notes": "Repository URL"},
            "ref": {"default": "default branch", "notes": "Branch, tag, or commit"},
            "ssh_key_id": {
                "default": "none",
                "notes": "Operator-registered key id for private repos",
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


def _default_display(
    name: str, schema: dict, required: bool, override: str | None
) -> str:
    if override is not None:
        return override
    if required:
        return "*required*"
    if "default" not in schema:
        return ""
    value = schema["default"]
    if value is None:
        return "`null`"
    if isinstance(value, bool):
        return f"`{str(value).lower()}`"
    if isinstance(value, str):
        return f'`"{value}"`'
    return f"`{value}`"


def _render_tool(name: str, description: str, schema: dict, func) -> list[str]:
    notes = TOOL_NOTES.get(name, {})
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
            key: _default_display(
                key, spec, key in required, param_notes.get(key, {}).get("default")
            )
            for key, spec in properties.items()
        }
        # The document's existing convention: a Default column appears only when
        # some parameter actually has a default. A tool whose parameters are all
        # required renders as a three-column table, so "*required*" alone does not
        # earn the column.
        show_default = any(v for v in defaults.values() if v != "*required*")
        if show_default:
            lines += [
                "| Param | Type | Default | Notes |",
                "|-------|------|---------|-------|",
            ]
        else:
            lines += ["| Param | Type | Notes |", "|-------|------|-------|"]
        for key, spec in properties.items():
            note = param_notes.get(key, {}).get("notes", "")
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
        f"The ASH MCP server exposes {_spell(len(tools))} tools and "
        f"{_spell(len(resources))} resources.",
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
        "`actionable_only=True` drops `SUPPRESSED` findings (false positives, accepted risks).",
        "",
    ]

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Do not write. Exit non-zero with a diff if the file is stale.",
    )
    args = parser.parse_args()

    expected = render()
    actual = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""

    if expected == actual:
        if args.check:
            print(f"{TARGET.relative_to(REPO_ROOT)} is up to date.", file=sys.stderr)
        return 0

    if args.check:
        print(
            f"{TARGET.relative_to(REPO_ROOT)} is stale relative to the MCP registry.\n"
            f"Regenerate with: uv run python scripts/generate_mcp_tool_reference.py\n"
            f"Then propagate: uv run --project "
            f"ash-agent-plugins/agentic-coding/transpiler agentic-plugins build\n",
            file=sys.stderr,
        )
        sys.stderr.writelines(
            difflib.unified_diff(
                actual.splitlines(keepends=True),
                expected.splitlines(keepends=True),
                fromfile="tool-reference.md (on disk)",
                tofile="tool-reference.md (regenerated)",
                n=1,
            )
        )
        return 1

    TARGET.write_text(expected, encoding="utf-8")
    print(f"Wrote {TARGET.relative_to(REPO_ROOT)}", file=sys.stderr)
    print(
        "Now run: uv run --project ash-agent-plugins/agentic-coding/transpiler "
        "agentic-plugins build",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
