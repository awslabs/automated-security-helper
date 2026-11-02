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

    **`incomplete` is terminal, with partial coverage.** ... `incomplete_scanners`
    names each scanner and why.

That is guidance the docstrings do not carry in this form. A generator that rendered
only what the code says about itself would delete it, making the document
cheaper to maintain and worse to read. So the split is:

* Derived from the registry, because this is what drifted: which tools exist,
  which resources exist, the counts, and each tool's parameter names, types,
  required/default status.
* Derived from the tools' return statements (``scripts/_mcp_contract.py``): the
  ``error_type`` values each tool can return, and the ``type`` of each entry of
  ``validate_config``'s ``errors``. The pages that tell a client which error a
  refusal carries are checked against the same values, and so are the example
  responses, so a renamed literal or key fails the docs checks. Editorial text that
  names a response key or an error type is printed only while the server returns it
  (``returns_fields``, and a caveat given as a dict with ``needs``, ``needs_types``
  or ``error_types``), so the page describes the tools at the commit it is generated
  from and not a server that has more or fewer of them.
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
import re
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
                    "Absolute path to scan. When not set: the tree this session delivered "
                    "with `set_source_git` or `set_source_zip_finalize`. With none "
                    "delivered, a call with no session id (stdio) scans the server's "
                    "working directory, and a call with a session id is refused"
                )
            },
            "severity_threshold": {
                "default": "the config's",
                "notes": (
                    "Least severe finding that counts as actionable, any case; it can make "
                    "the config's `global_settings.severity_threshold` stricter for this "
                    "scan, never looser"
                ),
            },
            "config_path": {
                "notes": (
                    "Custom config path. When not set: the profile this session bound "
                    "with `select_profile`, else the config ASH discovers in the source "
                    "directory, else the file `ASH_CONFIG` names in the server's "
                    "environment, else the built-in defaults"
                ),
            },
            "clean_output": {
                "notes": (
                    "Set the previous scan's results in the output directory aside as "
                    "soon as the scan is registered; with `false`, the scan's own set-up "
                    "does it a moment later. Either way they are deleted once the scan "
                    "has results of its own, and put back if it fails or is canceled. "
                    "A refused call leaves the previous results as they were"
                )
            },
        },
        "pre_returns": (
            "Output reports are written to `<source_dir>/.ash/ash_output/` — there is no "
            "parameter to override this. Scanner selection, mode, and other tuning live in "
            "the project's ASH config, not in tool arguments."
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
                "Poll `get_scan_progress` until `is_complete` is `true`, then read `status`. "
                "`is_complete` is `true` for every ending, including `failed` and "
                "`cancelled`. (See `get_scan_progress` below.)"
            ),
            (
                "**A refused config keeps its own `error_type`.** The scan does not start, "
                "and the response is `success: false` with one of these `error_type` values "
                "and the reason in `error`:"
            ),
            (
                "- `config_input_not_permitted`: `config_path`, or a base its `extends` "
                "chain names, is outside the directories this session may read a config from.\n"
                "- `config_check_failed`: the check of the config sources in the scan "
                "target could not finish (an unreadable entry, a link loop), so the scan "
                "was not started. The config was not found to be outside the permitted "
                "roots -- that case is `config_input_not_permitted` -- so check the "
                "config files in the target for unreadable entries and link loops.\n"
                "- `config_field_denied`: a config file an MCP client delivered or named "
                "sets a field the session's runtime-override policy denies. `error` names "
                "each field and why.\n"
                "- `config_policy_unreadable`: that policy cannot be established, for "
                "example because the profile the session bound is no longer registered. "
                "`error` starts with `A config an MCP client delivered cannot be checked:`.\n"
                "- `config_env_not_resolved`: a file of the config uses an `!ENV` tag, or a "
                "plain value that starts with a `${VAR}` or `${VAR:default}` reference, "
                "where none is resolved. For a remote caller that is any file the "
                "operator did not set aside (outside the directories "
                "`ASH_MCP_ALLOWED_CONFIG_ROOTS` names, other than the profile files "
                "the server writes in the calling session's `config/` directory), the "
                "scan target's own config included, and every base "
                "such a file extends; for a stdio caller, a file a client delivered. The "
                "server's own config, the file `ASH_CONFIG` names outside the MCP "
                "workspace root and each registered profile, is not refused. `error` "
                "names the file and the line or key."
            ),
            (
                "The target and source checks have their own `error_type` values too "
                "(`scan_target_not_permitted`, `output_dir_not_permitted`, "
                "`no_source_delivered`, `session_source_mismatch`, "
                "`delivered_source_missing`, `invalid_session_id`). A directory that "
                "already has a scan is refused with `error_type: MCPResourceError` and "
                "`error_category: resource_exhausted`; `error` says the directory "
                "`already has an active scan`, or, for a scan that was cancelled or "
                "stopped at its timeout and has not finished stopping, "
                "`has a scan that is still stopping`. That `error_type` is the "
                "exception's class name, and an unexpected error while the scan is "
                "being started arrives as `MCPResourceError` too, with `error_category: unexpected_error`, so "
                "`MCPResourceError` alone does not prove a deliberate refusal: branch on "
                "`error_category`. The server's `max_concurrent_scans` limit is refused "
                "the same way (`resource_exhausted`); its `context` holds "
                "`max_concurrent_scans`: wait for a running scan to finish, then retry. "
                "The busy-directory refusal's `context` names the running scan's "
                "`scan_id` only when the scan is this session's: poll `get_scan_progress` "
                "with it, or `cancel_scan` it if it is no longer needed "
                "(`list_active_scans` lists this session's scans). Without a `scan_id`, "
                "another session's scan holds the directory and the server does not name "
                "it: wait and retry, or scan another directory. After a `cancel_scan` of "
                "that directory the refusal repeats until the scan has stopped (see "
                "`cancel_scan`): retry after a few seconds. Four more refusals carry "
                "their own `error_type`: `committed_output_files` (a file git tracks "
                "in `.ash/ash_output` where the scan writes, or that check could not "
                "finish), `session_identity_required` (the caller has no session the "
                "server issued, so a scan it could neither follow nor stop is not "
                "started), `session_scan_limit` (this session is already running "
                "`max_concurrent_scans_per_session` scans: retry once one has "
                "finished, or `cancel_scan` one) and `source_delivery_busy` (the "
                "session's delivered source is being changed: retry after the change "
                "finishes). Any other reason the scan could not be started returns "
                "`error_type: scan_start_failure`, and an unexpected error returns "
                "the exception's class name. Branch on "
                "`error_type` and `error_category`, never on the text of `error`."
            ),
        ],
    },
    "get_scan_progress": {
        "intro": (
            "Poll progress every 5 seconds until `is_complete` is `true`, then read "
            "`status`: `completed`, `incomplete`, `failed`, or `cancelled`. The scan "
            "continues server-side independently of polling."
        ),
        "params": {"scan_id": {"notes": "From `run_ash_scan`"}},
        "returns": """{
  "success": true,
  "scan_id": "...",
  "directory_path": "/path/to/scanned/project",
  "output_directory": "/path/to/.ash/ash_output",
  "start_time": "<iso8601>",
  "end_time": "<iso8601 | null>",
  "status": "pending | running | completed | incomplete | failed | cancelled",
  "severity_threshold": "<the threshold the scan was judged by; null until it finishes when none was named>",
  "requested_severity_threshold": "<the threshold the request named | null>",
  "config_path": "<path | null>",
  "warnings": [...],
  "error_message": "<str | null>",
  "exit_code": "<int | null>",
  "exit_code_meaning": "<str | null>",
  "is_complete": bool,
  "results_available": bool,
  "output_holds_previous_results": bool,
  "output_superseded": bool,
  "superseded_by": ["<scan_id>"],
  "coverage_complete": "bool | null",
  "incomplete_scanners": [
    { "scanner": "grype", "status": "MISSING", "reason": "missing_dependencies", "detail": "MISSING" }
  ],
  "no_scanner_ran": bool,
  "incomplete_converters": [{ "converter": "...", "reason": "...", "failed_input_kinds": ["..."] }],
  "unevaluated_rules": ["..."],
  "stale_content_databases": [{ "name": "grype-db", "scanner": "grype", "built": "<iso8601 | null>", "age": "...", "max_age": "...", "refresh": "..." }],
  "could_not_stop": [{ "scanner": "...", "reason": "..." }],
  "completed_scanners": int,
  "finished_scanners": int,
  "total_scanners": int,
  "scanner_status_counts": { "passed": int, "failed": int, "skipped": int, "running": int, "pending": int },
  "scanner_statuses": { "<scanner_name>": { "status": "PASSED | FAILED | ERROR | MISSING | SKIPPED", "excluded": bool, "dependencies_satisfied": bool } },
  "skipped_scanners": [{ "scanner": "grype", "status": "MISSING", "reason": "missing_dependencies | excluded_by_configuration | skipped" }],
  "total_findings": int,
  "severity_counts": { "critical": int, "high": int, "medium": int, "low": int, "info": int, "suppressed": int, "unknown": int },
  "scanners": {
    "<scanner_name>": {
      "<target_type>": { ... per-scanner-target progress ... }
    }
  },
  "timestamp": "<iso8601>",
  "operation": "get_scan_progress"
}""",
        # A caveat is a string, or a dict that is printed only when the server
        # returns what it describes: "needs" are response keys, "needs_types"
        # error types. "otherwise" is what is printed instead, when there is one.
        "caveats": [
            {
                "needs": ["finished_scanners", "scanner_status_counts"],
                "text": (
                    "There is no overall percentage field. To compute progress, use "
                    "`finished_scanners / total_scanners`: `finished_scanners` counts every "
                    "scanner that has ended, whatever its status, and `completed_scanners` "
                    "only the ones that PASSED. `scanner_status_counts` splits them into "
                    "`passed`, `failed` (FAILED or ERROR), `skipped` (MISSING or SKIPPED), "
                    "`running`, and `pending`. **Guard against `total_scanners == 0`** during "
                    "the pre-flight phase (before any scanner has registered). Show "
                    '"initializing" or 0% when `total_scanners` is zero.'
                ),
                "otherwise": (
                    "There is no overall percentage field. To compute progress, use "
                    "`completed_scanners / total_scanners`: `completed_scanners` counts "
                    "only the scanners whose progress status is completed, so it can "
                    "stay below `total_scanners` when the scan ends with a scanner that "
                    "failed or was skipped. **Guard against `total_scanners == 0`** "
                    "during the pre-flight phase (before any scanner has registered). "
                    'Show "initializing" or 0% when `total_scanners` is zero.'
                ),
            },
            {
                "needs": ["start_time", "end_time"],
                "text": (
                    "There is no top-level `duration` field; derive elapsed time from "
                    "`start_time` and `end_time` (or from current time while running)."
                ),
            },
            (
                "**`is_complete` is `true` once the scan has ended**, whatever the ending: "
                "`completed`, `incomplete`, `failed` or `cancelled`. It is decided by the "
                "scan's state alone, never by a results file on disk, which can be a previous "
                "scan's. `results_available` is `true` for `completed` and `incomplete`, the "
                "scans whose results `get_scan_results` can read, and `false` for one of "
                "them whose results file cannot be read (the scan ended without writing "
                "its final results, or the file is not valid JSON): `error_message` then "
                "names the file and `coverage_complete` is `null`."
            ),
            (
                "**A later scan can take the output tree over.** `output_superseded` is "
                "`true` once a later scan of the same directory has written "
                "`output_directory`; `superseded_by` lists those scans' ids, oldest first, "
                "and is empty otherwise. Nothing below is read from the files then: this "
                "scan's results are gone, and `get_scan_results` on that directory reads "
                "the newest scan's. `exit_code` and `exit_code_meaning` are the ASH exit "
                "code of a run that ended with one and its documented meaning, `null` for "
                "every other ending and while the scan runs."
            ),
            (
                "**A failed or cancelled scan leaves the previous scan's results in place.** "
                "ASH puts them back in `output_directory`, and `output_holds_previous_results` "
                "is then `true` and the scanner fields are empty, because those files are not "
                "this scan's. `get_scan_results` on that directory reads the previous scan's "
                "results."
            ),
            {
                # Printed while the response carries the keys the paragraph names;
                # without one of them the status explanation is kept, with the
                # key-naming sentences left out, so the warning never disappears.
                "needs": [
                    "incomplete_scanners",
                    "stale_content_databases",
                    "coverage_complete",
                ],
                "otherwise": (
                    "**`incomplete` is terminal, with partial coverage.** The run finished and its "
                    "results are readable, but a selected scanner was `MISSING` or `ERROR` (or lost "
                    "targets), no scanner reached a verdict, a converter did not run or could "
                    "not convert some of its inputs, a rule "
                    "could not be evaluated, or a content database was past its declared age "
                    "bound. The findings are real but partial, so read them, and do not report "
                    "the target as clean. `failed` means the run crashed, left no readable "
                    "results, or ran past the server's `scan_timeout_seconds`."
                ),
                "text": (
                    "**`incomplete` is terminal, with partial coverage.** The run finished and its "
                    "results are readable, but a selected scanner was `MISSING` or `ERROR` (or lost "
                    "targets), no scanner reached a verdict, a converter did not run or could "
                    "not convert some of its inputs, a rule "
                    "could not be evaluated, or a content database was past its declared age "
                    "bound. `incomplete_scanners` names each scanner and why, and "
                    "`stale_content_databases` each stale database. The "
                    "findings are real but partial, so read them, and do not report the target as "
                    "clean. `failed` means the run crashed, left no readable results, or "
                    "ran past the server's `scan_timeout_seconds`. "
                    "`coverage_complete` is `null` while running and for `failed` or `cancelled`; "
                    "with `fail_on_incomplete_scanners: false` a scan is `completed` with "
                    "`coverage_complete: false` when scanners did not run."
                ),
            },
            (
                "**Status enum:** the documented values are "
                "`pending | running | completed | incomplete | failed | cancelled`, the "
                "registry entry's own state and nothing else. The registry uses "
                "`pending` briefly while a scan is queued and `running` once execution "
                'begins; treat both as "not done yet", and read `is_complete` rather than '
                "comparing the string."
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
                    "Keep only the actionable findings, the ones behind exit code 2: "
                    "unsuppressed and at or above the severity threshold the scan was "
                    "judged by (a scanner's own where its config sets one). Drop the "
                    "rest and add `findings`, a flat list of them that honors "
                    "`scanners` and `severities` (`full` level only)"
                )
            },
        },
        "caveats": [
            (
                "With `filter_level` `full`, `raw_results` is the aggregated results "
                "document without its `sarif`, `cyclonedx`, and `ash_config` sections; "
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
        "caveats": [
            (
                "Returns `output_dir`, `reports_dir` and `files`, a dict keyed by "
                "format name (`sarif`, `flat_json`, `html`, `csv`, `markdown`, "
                "`text`, `ocsf`, `cyclonedx`, `junit_xml`, `gitlab_sast`, "
                "`aggregated_results`) whose values are objects with the absolute "
                "`path`, whether the file `exists`, and its `size_bytes`; a report "
                "the scan did not write is listed with `exists: false`. When the "
                "output directory holds a `scanners/` tree, `scanners_dir` and "
                "`scanner_results` (per scanner, per target) are added."
            )
        ],
    },
    "list_active_scans": {
        "intro": (
            "This session's scans, active and recently completed. Only scans this "
            "session started are listed; another session's scans are not visible, "
            "and the statistics count only this session's."
        ),
        "no_params_sentence": "No parameters. Returns a list of scan summaries.",
    },
    "cancel_scan": {
        "intro": (
            "Stops a running scan. The scanner tool running at the time is stopped with "
            "every process it started (SIGTERM, then SIGKILL after 10 seconds). The "
            "scan halts at its next cancel check, and no further scanner, phase, or "
            "reporter starts, so a scan canceled before its report phase writes no "
            "reports. Work that is not waiting on a child process, such as a scanner "
            "parsing its tool's output, can still finish and write under `scanners/` "
            "or `converted/`, but `ash_aggregated_results.json` is not written after "
            "the cancel. When the output directory held a previous scan's results, "
            "they are put back in place of every result the canceled scan wrote; its "
            "log, `ash.log`, stays, and an `ash.log.jsonl` already there is left as it "
            "was. With no previous results, what the scan wrote before it stopped "
            "stays, except that a cancel during the report phase removes the reports "
            "that phase wrote and every other file a reporter wrote beside them, "
            "`reports/ash.unused-suppressions.md` included."
        ),
        "params": {"scan_id": {"notes": "The scan to cancel"}},
        "caveats": [
            (
                "Returns `success`, `status`, and `message`. The status is `cancelled` "
                "at once. A running scan stops within about 10 seconds; one still "
                "waiting for another scan of its session stops when that scan ends. "
                "Until it has stopped, `run_ash_scan` refuses another scan of the same "
                "directory as still stopping, and the scan counts against "
                "`max_concurrent_scans`. A scan that has already ended is not changed, "
                "and the response has `success: false` and the scan's status. For a "
                "`run_ash_workspace_scan`, `cancel_scan` takes one project's scan id and "
                "stops that project, which ends `failed`; the other projects carry on."
            ),
        ],
    },
    "check_installation": {
        "intro": (
            "Reports whether ASH can scan: its version and, for each built-in scanner, "
            "whether its tool can run. Enabled means enabled in ASH's defaults: the "
            "call reads no project's config and checks no plugin scanner. It runs each "
            "scanner's dependency check, which can start the tool, so it takes several "
            "seconds, and it installs and downloads nothing. The tool of a scanner "
            "that ASH installs with uv is installed when `uv tool list` lists it, or "
            "when its executable is on `PATH` or in a directory ASH also searches, "
            "such as `~/.ash/bin`. A scanner whose tool is not, when the server is "
            "online and has uv, is listed in `installs_on_first_scan`, because the "
            "first scan installs it with uv, which needs network access. Offline, or "
            "without uv, it is listed in `missing_dependencies`. Offline, semgrep is "
            "also missing when it has no rules cache."
        ),
        "no_params_sentence": (
            "No parameters. Returns `installed` (at least one enabled scanner can run, "
            "or will once the first scan installs its tool), `ready` (every enabled "
            "scanner can run or will), `version`, `scanners` (each scanner's `name`, "
            "`enabled`, `dependencies_satisfied`, `installs_on_first_scan`, and "
            "`version`), `installs_on_first_scan`, `missing_dependencies` and "
            "`undetermined_dependencies` (the enabled scanners whose tool is missing "
            "and that a scan cannot install, or whose check could not run), and "
            "`ash_command_available` (whether an `ash` executable is on `PATH`, which "
            "the server does not need)."
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
            (
                "When the session's workspace directory cannot be created, both upload tools "
                "return `success: false` with `error_type` `session_workspace_unavailable`."
            ),
            (
                "While the server removes the session's workspace for being unused longer "
                "than its time to live, `set_source_zip_chunk` returns `success: false` with "
                "`error_type` `session_workspace_busy`. Send the upload again from its first "
                "chunk."
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
                    "Leave it out: the server registers no SSH keys, so any value is "
                    "refused"
                ),
            },
            "depth": {"notes": "Clone depth, a whole number of commits from 1 to 1000"},
        },
        "caveats": [
            (
                "Refused while a scan of this session is running, because the clone "
                "would replace the tree and config files that scan is reading. The "
                "response is `success: false`, `error_type: source_delivery_busy`, "
                "and `error` set to `a scan of this session is running; change the "
                "delivered source after it finishes`. Deliver the source again once "
                "`get_scan_progress` reports a terminal status."
            ),
            (
                "A refusal or a git failure returns `success: false` with an `error_type`: "
                "`clone_url_not_permitted` (a url beginning with `-` or using the `ext::` "
                "transport, a url holding a control character or a lone surrogate, or a url "
                "whose host cannot be read), `clone_ref_not_permitted` (a ref beginning with "
                "`-` or holding a control character or a lone surrogate), "
                "`invalid_clone_depth` (below 1 or above 1000; the limit is on how much "
                "history is fetched), "
                "`invalid_session_id`, "
                "`local_clone_source_refused` (a local path or `file://` url, which would read "
                "the server's own filesystem), `clone_host_not_permitted` (the host is not in "
                "`ASH_MCP_GIT_ALLOWED_HOSTS`), `ssh_key_not_registered` (an `ssh_key_id` was "
                "named), `clone_timed_out` (git ran past its time limit and was stopped), "
                "`git_clone_failed` or `git_checkout_failed` (git's own message is in "
                "`error`; `git_clone_failed` also covers a git that is not on `PATH` or "
                "cannot be started), or `session_workspace_unavailable` (the session's "
                "workspace could not take the clone: a directory of it could not be created, "
                "the previously delivered source could not be moved aside for it, or the "
                "clone could not be moved into place; each move is tried a few times before "
                "it fails). The clone is made beside the delivered source "
                "and replaces it only once it has worked, so a delivery that fails for any of "
                "these reasons, or is refused, leaves the previously delivered source in "
                "place, and `run_ash_scan` with no `source_dir` scans it. A partial clone "
                "that cannot be fully deleted stays beside the source, logged, for the next "
                "delivery to delete, and the error returned is still git's own. The one "
                "exception is a clone that could not be moved into place after the previous "
                "source had been moved aside and could not be put back: the recorded source "
                "then names a path that is gone, and `run_ash_scan` with no `source_dir` "
                "answers `delivered_source_missing` until a source is delivered again; that "
                "next delivery puts the previous source back first. A "
                "`session_workspace_unavailable` that names a refused rename can be retried "
                "with the same call: the refusal is usually a program holding a handle "
                "inside a tree (a virus scanner, a file indexer), and it passes."
            ),
            (
                "A re-delivery needs room for both trees at once, because the new clone is "
                "made beside the delivered source, which is deleted only after it. When the "
                "disk is short, call `clear_source` first to free the delivered one. A clone, "
                "fetch or checkout that fails for want of space returns `git_clone_failed` or "
                "`git_checkout_failed` with git's own message, and that advice added when "
                "the session has a delivered source to free."
            ),
        ],
    },
    "set_source_zip_finalize": {
        "caveats": [
            (
                "Refused while a scan of this session is running, for the same reason as "
                "`set_source_git`: `success: false`, `error_type: source_delivery_busy`, "
                "and `error` set to `a scan of this session is running; change the "
                "delivered source after it finishes`. "
                "`set_source_zip_chunk` is not refused, so the chunks can be sent while the "
                "scan runs and the upload finalized after it ends."
            ),
            (
                "A finalize that cannot deliver returns `success: false` with an `error`. "
                "Its `error_type` is `session_workspace_unavailable` when the session's "
                "workspace could not take the tree: a directory of it could not be created, "
                "the previous tree could not be renamed aside (nothing is deleted where it "
                "stands), or the extracted one could not be moved into place, whatever the "
                "operating system error was. The previous tree stays delivered and the "
                "uploaded zip is kept, so the same call can be sent again; when the previous "
                "tree could not be put back either, `run_ash_scan` with no `source_dir` "
                "answers `delivered_source_missing`. A checksum mismatch, an "
                "upload that never received its last chunk, or an archive the limits refuse "
                "returns `error` with no `error_type`. An archive that is not a zip returns "
                "`error_type` `BadZipFile`, and a failure on disk while the archive is "
                "read or extracted (no space, no permission, a file that vanished) returns "
                "the class name of the exception, `OSError` or one of its subclasses; both "
                "carry an `error` that starts `Error finalizing source upload:`."
            ),
        ],
    },
    "get_config": {
        "caveats": [
            (
                "A config this session may not read, or one a client delivered that the "
                "server refuses, returns `success: false` with `error_type` "
                "`config_input_not_permitted`, `config_field_denied`, "
                "`config_policy_unreadable` or `config_env_not_resolved`, as `run_ash_scan` "
                "does for the same file."
            ),
        ],
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
            "startup, each with `ash mcp --profile NAME=path/to/ash.yaml` (repeatable). A "
            "client cannot register one; an empty list means the operator registered none."
        ),
    },
    "resolve_ash_workspace": {
        "caveats": [
            (
                "A workspace policy file, named or found in the workspace file's "
                "directory or its `.ash` directory, is used only when it is in a "
                "directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names; any other refuses the "
                "workspace with exit code 4, or with exit code 3 when a client "
                "delivered it and it sets a field the server's policy denies."
            ),
        ],
    },
    "run_ash_workspace_scan": {
        "caveats": [
            (
                "A workspace policy file, named or found in the workspace file's "
                "directory or its `.ash` directory, is used only when it is in a "
                "directory `ASH_MCP_ALLOWED_CONFIG_ROOTS` names; any other refuses the "
                "workspace with exit code 4, or with exit code 3 when a client "
                "delivered it and it sets a field the server's policy denies."
            ),
        ],
    },
    "clear_source": {
        "no_params_sentence": (
            "No parameters. Deletes this session's delivered source tree and workspace."
        ),
        "caveats": [
            (
                "Refused while a scan of this session is running: `success: false`, "
                "`error_type: source_delivery_busy`. Clear again once the scan ends. Entries "
                "the server cannot delete (files another account owns) stay on disk; the "
                "session's delivered source is forgotten either way."
            ),
        ],
    },
    "validate_config": {
        "caveats": [
            (
                "`config_content` counts as the client's config, and so does a "
                "`config_path` that a client delivered or that is outside the "
                "directories `ASH_MCP_ALLOWED_CONFIG_ROOTS` names and its session's "
                "`config/` directory. Each field such a config may not set under the "
                "server's runtime-override policy is an error of type "
                "`denied_by_runtime_policy`, and a policy the server cannot read is one "
                "error of type `config_policy_unreadable`; for `config_content`, both "
                "only when a remote client calls. A `${VAR}` or `${VAR:default}` "
                "reference at the start of a plain value, or an `!ENV` tag, in such a "
                "config is an error of type `config_env_not_resolved`."
            ),
        ],
    },
}


def _cell(text: str) -> str:
    """``text`` with every bare pipe escaped, so it stays in one markdown table column."""
    return text.replace(r"\|", "|").replace("|", r"\|")


def _resolve_ref(ref: str, root: dict | None) -> dict | None:
    """The schema a local ``$ref`` (``#/$defs/Name``) points at in ``root``."""
    if root is None or not ref.startswith("#/"):
        return None
    node: object = root
    for part in ref[2:].split("/"):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node if isinstance(node, dict) else None


def _enum_type_name(values: list) -> str:
    """The type of an enum by its declared type or, failing that, its values.

    Every enum used to render as ``string``, which mislabelled an integer or a
    boolean enum.
    """
    kinds = {type(v) for v in values if v is not None}
    if kinds == {bool}:
        return "boolean"
    if kinds == {int}:
        return "integer"
    if kinds <= {int, float} and kinds:
        return "number"
    return "string"


def _type_name(schema: dict, root: dict | None = None) -> str:
    """Render a JSON-schema fragment the way this document spells types.

    Unions are written `string \\| null` with an escaped pipe, because the value
    lands in a markdown table cell where a bare pipe would end the column.
    ``root`` is the tool's whole input schema, so a ``$ref`` into its ``$defs``
    (an Enum or model parameter) is rendered by what it points at rather than
    as ``any``.
    """
    if "$ref" in schema:
        target = _resolve_ref(str(schema["$ref"]), root)
        if target is not None:
            return _type_name(target, root)
        return "object"
    for union_key in ("anyOf", "oneOf", "allOf"):
        if union_key in schema:
            parts = [_type_name(s, root) for s in schema[union_key]]
            seen: list[str] = []
            for part in parts:
                if part not in seen:
                    seen.append(part)
            return r" \| ".join(seen)
    declared = schema.get("type")
    if "enum" in schema:
        if isinstance(declared, str):
            return declared
        return _enum_type_name(list(schema["enum"]))
    if isinstance(declared, list):
        return r" \| ".join(str(d) for d in declared)
    if declared == "array":
        return "array"
    return str(declared or "any")


def _default_display(schema: dict, required: bool) -> str:
    """The schema's default as the docs checks read it: a phrase or one JSON span.

    A pipe inside the JSON is escaped, as the type names are: the span lands in
    a table column.
    """
    import json

    if required:
        return "*required*"
    if "default" not in schema:
        return ""
    value = schema["default"]
    if value is None:
        return "not set"
    return _cell(f"`{json.dumps(value)}`")


def _plural(count: int, noun: str) -> str:
    """``one tool``, ``two tools``: the spelled count with the noun agreeing."""
    return f"{_spell(count)} {noun}{'' if count == 1 else 's'}"


#: The docs checks compare each tool's parameter table with the tool's input schema.
def _options_marker(tool: str) -> str:
    return f"<!-- doctest: options of=mcp.{tool} -->"


#: A Google-style section header on its own line (``Returns:``, ``Note:``).
_SECTION_HEADER = re.compile(
    r"^\s*(?:Returns?|Raises?|Yields?|Examples?|Notes?|Attributes|See Also|"
    r"Warnings?|Todo)\s*:\s*$"
)
#: A parameter head: an identifier, an optional ``(type)``, a colon.
_PARAM_HEAD = re.compile(
    r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s*(?:\([^)]*\))?\s*:\s*(?P<tail>.*)$"
)


def parse_arg_notes(doc: str) -> dict[str, str]:
    """Per-parameter descriptions parsed out of a Google-style ``Args:`` block.

    The block is the lines after ``Args:`` up to the next section header on a
    line of its own, or the first dedented line (a paragraph after the block). A
    parameter head is an identifier, with an optional ``(type)``, and a colon, at
    the block's parameter indentation; a line indented deeper is a continuation
    of the parameter above it, whatever words or colons it holds.

    The old parser cut the block at the first ``Note:`` or ``Example:`` anywhere
    in the text, so one such word inside a description blanked every later
    parameter's note; it read any ``Word:`` line as a new parameter, so a wrapped
    line that began that way became a phantom parameter; it did not recognize a
    ``name (type):`` head, so such a parameter's text was appended to the one
    before it; and it folded every paragraph between the block and ``Returns:``
    into the last parameter.
    """
    lines = doc.splitlines()
    try:
        start = next(i for i, line in enumerate(lines) if line.strip() == "Args:")
    except StopIteration:
        return {}

    found: dict[str, str] = {}
    current: str | None = None
    param_indent: int | None = None
    for raw in lines[start + 1 :]:
        if not raw.strip():
            # A blank line ends the block unless more parameter lines follow at
            # the parameter indentation; decided by the next non-blank line.
            continue
        if _SECTION_HEADER.match(raw):
            break
        indent = len(raw) - len(raw.lstrip())
        if param_indent is None:
            param_indent = indent
        if indent < param_indent:
            break
        if indent == param_indent:
            head = _PARAM_HEAD.match(raw.strip())
            if head is None:
                # Prose at the parameter indentation after the block: the
                # block is over.
                break
            current = head.group("name")
            found[current] = head.group("tail").strip()
        elif current is not None:
            found[current] = f"{found[current]} {raw.strip()}".strip()

    # A pipe would end the markdown table column early.
    return {k: _cell(v) for k, v in found.items()}


def _docstring_arg_notes(func) -> dict[str, str]:
    """``parse_arg_notes`` of ``func``'s docstring; empty when there is none."""
    if func is None:
        return {}
    return parse_arg_notes(inspect.getdoc(func) or "")


def _response_keys(contract, wanted: set[str]) -> set[str]:
    """The keys of the one response dict the tool's return statements build that
    carries the most of ``wanted``.

    Read by ``scripts/_mcp_contract.py``. One dict rather than the union of all of
    them, because the docs checks hold an example to a single response: an example
    with keys from a refusal and from a success would pass no check. Without a
    contract (a tool the reader did not find) every wanted key counts as present.
    """
    if contract is None:
        return set(wanted)
    best: set[str] = set()
    score = -1
    for variant in contract.response.dicts():
        keys = {key for key, _ in variant.keys}
        hits = len(keys & wanted)
        if hits > score or (hits == score and len(keys) > len(best)):
            best, score = keys, hits
    return best


def _conditional_caveat(
    caveat: dict, have: set[str], types: set[str] | None
) -> str | None:
    """The text of a caveat given as a dict, or None when it is not printed.

    * ``needs``: response keys; all must be in ``have``, else ``otherwise`` is
      printed when there is one.
    * ``needs_types``: error types; all must be among the tool's, else nothing.
    * ``error_types``: (type, note) pairs, a paragraph naming those the tool
      returns, each followed by its note in parentheses; ``untyped`` is added after
      it while none of ``untyped_unless`` is returned. Without a contract every
      type counts as returned, as every key does in ``_response_keys``, so the
      paragraph never names a type and then calls it untyped.
    """
    if not all(key in have for key in caveat.get("needs", [])):
        return caveat.get("otherwise")
    if types is not None and not set(caveat.get("needs_types", [])) <= types:
        return None
    if "error_types" in caveat:
        named = [
            f"`{kind}`" + (f" ({note})" if note else "")
            for kind, note in caveat["error_types"]
            if types is None or kind in types
        ]
        if not named:
            return None
        if len(named) > 1:
            listed = f"{', '.join(named[:-1])}, or {named[-1]}"
        else:
            listed = named[0]
        text = f"{caveat['lead']} {listed}."
        unless = set(caveat.get("untyped_unless", []))
        absent = not unless if types is None else not unless & types
        if caveat.get("untyped") and absent:
            text = f"{text} {caveat['untyped']}"
        return text
    return caveat["text"]


def _render_tool(
    name: str, description: str, schema: dict, func, contract=None
) -> list[str]:
    notes = TOOL_NOTES.get(name, {})
    doc_notes = _docstring_arg_notes(func)
    lines = [f"## {name}", ""]

    intro = notes.get("intro")
    if not intro:
        # A tool registered under a name that is not a module attribute has no
        # function to read; its registered description stands in.
        doc = (inspect.getdoc(func) if func is not None else None) or description or ""
        intro = " ".join(doc.split("\n\n")[0].split()).strip()
    lines += [intro, ""]

    properties: dict = schema.get("properties", {})
    required = set(schema.get("required", []))
    param_notes: dict = notes.get("params", {})

    # A TOOL_NOTES note for a parameter the tool no longer has is as stale as a
    # note for a tool that is gone, which _render_parts refuses; a renamed
    # parameter used to drop its note silently.
    stale_params = sorted(set(param_notes) - set(properties))
    if stale_params:
        raise SystemExit(
            f"ERROR: TOOL_NOTES[{name!r}]['params'] names parameters the tool does "
            f"not have: {stale_params}. Rename them or remove them."
        )

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
            # Editorial notes go through the same pipe escaping as the
            # docstring notes; only the latter were escaped before.
            note = _cell(
                param_notes.get(key, {}).get("notes") or doc_notes.get(key, "")
            )
            type_name = _type_name(spec, schema)
            if show_default:
                lines.append(f"| `{key}` | {type_name} | {defaults[key]} | {note} |")
            else:
                lines.append(f"| `{key}` | {type_name} | {note} |")
        lines.append("")

    if notes.get("pre_returns"):
        lines += [notes["pre_returns"], ""]

    caveats = notes.get("caveats", [])
    fields = notes.get("returns_fields")
    wanted = {key for key, _ in fields or []}
    for caveat in caveats:
        if isinstance(caveat, dict):
            wanted.update(caveat.get("needs", []))
    have = _response_keys(contract, wanted)
    types = None if contract is None else set(contract.error_types)

    returns = notes.get("returns")
    if fields:
        kept = [text for key, text in fields if key in have]
        returns = "{\n" + ",\n".join(kept) + "\n}" if kept else None
    if returns:
        lines += ["Returns:", "```json", returns, "```", ""]

    for caveat in caveats:
        if isinstance(caveat, dict):
            caveat = _conditional_caveat(caveat, have, types)
            if caveat is None:
                continue
        lines += [caveat, ""]

    if contract is not None:
        lines += _error_lines(contract)

    return lines


def _error_lines(contract) -> list[str]:
    """What the tool's return statements say a failure carries.

    Read by ``scripts/_mcp_contract.py``, which records ``type(e).__name__`` as
    "the class name of an exception" rather than as a value.
    """
    lines = []
    for lead, values, class_name in (
        (
            "On failure, `error_type` is",
            contract.error_types,
            contract.error_class_name,
        ),
        (
            "Each entry of `errors` has a `type` that is",
            contract.entry_types,
            contract.entry_class_name,
        ),
    ):
        named = [f"`{value}`" for value in values]
        if len(named) > 1:
            listed = f"one of {', '.join(named[:-1])} and {named[-1]}"
        else:
            listed = "".join(named)
        if class_name:
            other = "the class name of an exception"
            listed = f"{listed}, or {other}" if listed else other
        if listed:
            lines += [f"{lead} {listed}.", ""]
    return lines


def _tool_contracts(tools) -> dict:
    """Each registered tool's contract, read from the source of the package it documents.

    A registered tool with no ``@mcp.tool`` function the reader finds, or an
    ``error_type`` it cannot read, stops the run: the page would otherwise list
    fewer errors than the server returns, with nothing to say so.
    """
    import automated_security_helper

    from _mcp_contract import tool_contracts

    package = Path(automated_security_helper.__file__).resolve().parent
    contracts = tool_contracts(package)
    registered = {t.name for t in tools}
    problems = [
        f"{name} is registered but no @mcp.tool function defines it"
        for name in sorted(registered - set(contracts))
    ]
    for name in sorted(registered & set(contracts)):
        contract = contracts[name]
        for site in (*contract.error_types_unread, *contract.entry_types_unread):
            problems.append(f"{name}: an error type at {site} cannot be read")
    if problems:
        raise SystemExit(
            "ERROR: the MCP tools' error types cannot all be listed:\n  "
            + "\n  ".join(problems)
        )
    return contracts


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


def _response_marker(tool: str) -> str:
    """The marker on a response example: the docs checks compare its keys with the
    keys the tool's return statements build (see the doctest contract's "Config
    blocks")."""
    return f"<!-- doctest: config kind=mcp-response of=mcp.{tool} -->"


def _adapt_markdown(lines: list[str], strip_bold: bool) -> list[str]:
    """Make the response examples pass the docs checks, and on the docs site drop bold.

    * A ```json response example that does not parse as JSON (``bool``, ``[...]``
      placeholders) becomes a ```text block, because the docs checks parse every
      JSON block. Either way it gets the marker naming the tool whose response it
      is, under whose ``## <tool>`` heading it sits. Both files get this: the docs
      checks read the agent-facing file and every copy the transpiler makes of it.
    * With ``strip_bold``, no bold in running prose (the docs site's house style).
      Bold that wraps a code span is unwrapped too; ``**`` inside a code span or a
      fence is left alone. The agent-facing file keeps its bold. Table cells also
      get ``<`` and ``>`` outside code spans escaped there.
    """
    import json
    import re

    out: list[str] = []
    tool = None
    i = 0
    while i < len(lines):
        line = lines[i]
        heading = re.match(r"^## ([a-z][a-z0-9_]*)$", line)
        if heading:
            tool = heading.group(1)
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
            if tool is None:
                raise SystemExit(
                    "ERROR: a response example is not under a '## <tool>' heading, so "
                    "the docs checks could not tell which tool's keys it shows."
                )
            out += [_response_marker(tool), "```json" if parsed else "```text"]
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


def _resource_uri(resource) -> str:
    """A resource's URI, or a template resource's URI template, as text."""
    uri = getattr(resource, "uri", None)
    if uri is None:
        uri = getattr(resource, "uriTemplate", None) or getattr(
            resource, "uri_template", ""
        )
    return str(uri)


def _render_parts() -> tuple[list[str], list[str]]:
    from automated_security_helper.cli import mcp_server

    tools = asyncio.run(mcp_server.mcp.list_tools())
    resources = list(asyncio.run(mcp_server.mcp.list_resources()))
    # list_resources() returns the fixed-URI resources only; a resource
    # registered with a URI template is listed by list_resource_templates(), so
    # without this call the count and the Resources section left those out.
    list_templates = getattr(mcp_server.mcp, "list_resource_templates", None)
    if list_templates is not None:
        resources += list(asyncio.run(list_templates()))

    contracts = _tool_contracts(tools)
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
            f"The ASH MCP server exposes {_plural(len(tools), 'tool')} and "
            f"{_plural(len(resources), 'resource')}."
        ),
        "",
    ]

    for tool in ordered:
        lines += _render_tool(
            tool.name,
            tool.description or "",
            tool.input_schema or {},
            # None for a tool registered under a custom name: _render_tool then
            # reads the registered description instead of a function docstring.
            getattr(mcp_server, tool.name, None),
            contracts[tool.name],
        )

    lines += ["## Resources", ""]
    for resource in sorted(resources, key=_resource_uri):
        summary = " ".join((resource.description or "").split())
        summary = summary.rstrip(".")
        lines.append(f"- `{_resource_uri(resource)}` — {summary}")
    lines += [
        "",
        "Read these via the standard MCP resource read mechanism for context-free help.",
        "",
        "## Severity levels",
        "",
        "`CRITICAL` > `HIGH` > `MEDIUM` > `LOW` > `INFO` > `SUPPRESSED`",
        "",
        (
            "`actionable_only=True` drops `SUPPRESSED` findings (false positives, accepted "
            "risks) and findings below the scan's severity threshold, which are reported "
            "but do not fail the scan."
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
            "Write (or with --check, compare) only the docs-site page, at this path "
            "('-' for stdout), and leave the agent-facing file alone."
        ),
    )
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from _reference_docs import (
        add_docs_root_argument,
        prepare_environment,
        refuse_check_to_stdout,
        write_or_check,
    )

    add_docs_root_argument(parser)
    args = parser.parse_args()
    refuse_check_to_stdout(parser, args)

    docs_root = Path(args.docs_root).resolve()
    prepare_environment(docs_root)
    if args.output:
        page = render_reference_page()
        if args.output == "-":
            sys.stdout.write(page)
            return 0
        return write_or_check(Path(args.output), page, args.check, GENERATOR)
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
