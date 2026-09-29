#!/usr/bin/env python3
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Drive a real MCP handshake with the MCP Inspector and diff the wire surface
against a committed golden copy.

Run with:  python .github/actions/validate-mcp/compare_tool_surface.py
Regenerate: python .github/actions/validate-mcp/compare_tool_surface.py --update

WHY THIS EXISTS
---------------
`.github/actions/validate-mcp/action.yml` used to install
`@modelcontextprotocol/inspector` and then never invoke it. The package name
appeared in the install line and nowhere else in the repository, so the step
asserted nothing while still being able to fail the job: one macOS leg died on
`getaddrinfo ENOTFOUND registry.npmjs.org` after 161 seconds of DNS timeout,
after the two steps that do test something had already passed. A step that can
only fail for reasons unrelated to the code under test is worse than no step --
it spends the reader's trust and teaches them to re-run red legs.

This script makes the install load-bearing. It speaks the protocol the way a
client does: the inspector spawns `ash mcp` over stdio, performs the
initialization handshake, calls `tools/list`, and prints the server's reply.
That reply is compared against `tool_surface.golden.json`.

WHAT THIS COVERS THAT tests/unit/cli/mcp/test_tool_surface_parity.py CANNOT
--------------------------------------------------------------------------
The unit test asks the in-process server object for its registry:
`await mcp.list_tools()`. That is the registration table, one Python call away
from the decorator that filled it. It proves `@mcp.tool()` was applied.

This check asks a separate process, over a pipe, through a real client, after a
real `initialize` exchange. Between the registry and the client sit the
transport, the JSON-RPC framing, the protocol-version negotiation, and the
server's serialization of every Pydantic model into JSON Schema. A defect in any
of those is invisible to the unit test and fatal to a client:

* a console-script entry point that no longer resolves, or an `ash mcp` that
  exits non-zero before serving -- the registry is still correct in-process
* a transport that never completes `initialize`, so `tools/list` never returns
* a model whose JSON Schema serialization changes shape -- the unit test
  compares tool *names*, and says so under "WHAT THIS DOES NOT CHECK"
* a tool whose schema is emitted but is not portable to a real client

The unit test also cannot see the schema at all. It compares name sets against
the docs. This compares the full `inputSchema` and `outputSchema` of every tool,
which is the part a client generates its call sites from. The two checks overlap
on exactly one property -- the set of names -- and diverge on everything else, so
this is not a duplicate.

NORMALIZATION
-------------
Every normalizer below removes a difference that was *measured* to appear
between two honest runs. Nothing is normalized speculatively. Over-normalizing
is how a golden quietly stops detecting anything, so each entry names what was
measured and how to re-measure it.

1. `description` -> `inspect.cleandoc`.

   MEASURED: CPython 3.14 dedents docstrings at compile time; 3.10 through 3.13
   do not. Probe, on any two interpreters:

       def f():
           '''Summary.

           Body.
           '''
       print(repr(f.__doc__))

   3.12.13 prints 'Summary.\\n\\n    Body.\\n    ';
   3.14.6 prints 'Summary.\\n\\nBody.\\n'.

   The `mcp` package hands `__doc__` through unchanged, so all 21 of ASH's tool
   descriptions differ between a 3.13 and a 3.14 capture with byte-identical
   dependency versions (mcp 2.2.0, pydantic 2.13.5, pydantic-core 2.46.5 on
   both). `python-version` in the matrix that runs this action spans 3.10 to
   3.14, so an un-normalized golden is red on five legs out of twenty-five no
   matter which interpreter captured it. `inspect.cleandoc` reconciles all 21.

   What this costs: a pure re-indentation of a docstring no longer registers as a
   change. That is the right trade -- the interpreter already performs that
   re-indentation for us on 3.14 -- and a change to the *words* still fails,
   which is proven by the description mutation in the pull request that added
   this file.

2. Object key order -> canonical, via `json.dumps(sort_keys=True)`.

   Lossless by specification: RFC 8259 defines a JSON object as unordered, so
   two serializations differing only in key order carry the same data. This is
   not a judgement call and removes a whole class of false positive.

3. `required` and `enum` arrays -> sorted.

   Lossless by specification: JSON Schema defines `required` as a set of
   property names and `enum` as a set of permitted values. Neither carries
   ordering semantics, so sorting cannot hide a real change. Sorted by canonical
   JSON text rather than by value, because `enum` may hold mixed types and
   `sorted([1, "a"])` raises.

NOT normalized, deliberately:

* Absolute paths, temp directories, session ids, timestamps and the ASH version
  string. The brief for this check listed these as likely volatile; they are
  not present at all. A scan of a captured payload for `/home`, `/local`, `/tmp`,
  `/var` and `/Users` path prefixes, ISO-8601-shaped tokens, UUID-shaped tokens,
  and the literal version from pyproject.toml returns zero hits -- `tools/list`
  is a declarative surface with no runtime values in it. Two captures from
  different working directories (`--cwd`) are byte-identical. Adding a regex for
  a field that is not there would be dead code that a later reader mistakes for
  evidence that such fields exist and are handled.

* `anyOf` / `oneOf` / `allOf` / `prefixItems` array order. `prefixItems` is
  positional, so sorting it would be lossy; none of the four was measured to
  vary. Leaving them alone keeps a reorder detectable.

FAILING LOUDLY
--------------
A golden comparison that passes when the golden is missing is worse than no
check at all, so:

* a missing golden file is a hard failure and is never auto-created
* a golden that parses but names zero tools is a hard failure
* a live surface with zero tools is a hard failure, so a broken invocation that
  emits `{"tools": []}` cannot match an empty golden
* `--update` is the only code path that writes the golden, and CI never passes it
"""

from __future__ import annotations

import argparse
import difflib
import inspect
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

HERE = Path(__file__).resolve().parent
DEFAULT_GOLDEN = HERE / "tool_surface.golden.json"

# The fields of a `tools/list` entry this check pins. `name` is the dict key.
COMPARED_FIELDS = ("description", "inputSchema", "outputSchema")

# JSON Schema keywords whose array value is a set, so sorting is lossless.
SET_VALUED_ARRAY_KEYS = frozenset({"required", "enum"})

# `--strict` exits 6 when any tool-schema portability problem is error-severity,
# and 0 when the worst is a warning. Both are successful protocol exchanges that
# print the `tools/list` reply, so both are "the call worked" as far as capturing
# goes; the portability verdict is reported separately below.
INSPECTOR_STRICT_FINDINGS_EXIT = 6


def _sort_set_valued(value: Any, key: str | None = None) -> Any:
    """Sort the two schema arrays JSON Schema defines as sets, recursively.

    `key` is the object key the value was found under, which is how `required`
    and `enum` are recognized. Object key order needs no handling here: it is
    canonicalized at serialization time by `sort_keys=True`, and equality on the
    parsed dicts ignores it already.
    """
    if isinstance(value, dict):
        return {k: _sort_set_valued(v, k) for k, v in value.items()}
    if isinstance(value, list):
        items = [_sort_set_valued(v) for v in value]
        if key in SET_VALUED_ARRAY_KEYS:
            items.sort(key=lambda v: json.dumps(v, sort_keys=True))
        return items
    return value


def normalize_tools(tools: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Turn a `tools/list` array into the name-keyed shape the golden stores.

    Keying by name is what makes this a set comparison rather than a byte diff:
    the order the server happens to list its tools in becomes irrelevant, and a
    tool that appears or disappears shows up as a key difference with its own
    message instead of as a shifted array.
    """
    out: Dict[str, Dict[str, Any]] = {}
    for tool in tools:
        name = tool.get("name")
        if not name:
            raise SystemExit(
                f"FAIL: a tools/list entry has no name: {json.dumps(tool)[:200]}"
            )
        if name in out:
            raise SystemExit(
                f"FAIL: the server returned two tools named {name!r}. The wire "
                "surface must have unique names; a client keyed by name would "
                "silently lose one of them."
            )
        entry: Dict[str, Any] = {}
        for field in COMPARED_FIELDS:
            if field not in tool:
                continue
            value = tool[field]
            if field == "description":
                # See NORMALIZATION note 1.
                value = inspect.cleandoc(value or "")
            else:
                value = _sort_set_valued(value)
            entry[field] = value
        out[name] = entry
    return out


def _pretty(value: Any) -> List[str]:
    """Render for a human-readable diff: canonical keys, one token per line."""
    return json.dumps(value, indent=2, sort_keys=True).splitlines()


def capture(
    inspector: str, ash: str, extra_args: List[str] | None = None
) -> Tuple[Dict[str, Any], int, str]:
    """Run one real handshake and return (payload, portability_exit, stderr).

    Argument order is load-bearing and not obvious. The target command must come
    immediately after `--cli`, before `--method`. Moving `--method tools/list`
    ahead of the target makes the inspector ignore the target entirely, fall back
    to its server catalog, and fail with
    `{"error":{"code":"error","message":"No servers found in config file"}}`.
    Measured against inspector 2.8.0.

    stdio is the right transport here: it is what every desktop MCP client uses
    for a locally installed server, the inspector auto-detects it from a command
    target, and it needs no port, no TLS and no auth header, so the check tests
    the protocol rather than a listener configuration.

    Treating exit 6 as a successful capture is measured, not assumed. Against a
    stub server that answers `tools/list` with a property whose schema is the bare
    boolean `true`, inspector 2.8.0 prints the full `tools/list` reply on stdout,
    the per-tool error detail on stderr, and exits 6. So a portability error does
    not cost the golden comparison: both verdicts are reported from one spawn.
    """
    cmd = [inspector, "--cli", ash, "mcp", "--method", "tools/list", "--strict"]
    cmd.extend(extra_args or [])
    print(f"$ {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in (0, INSPECTOR_STRICT_FINDINGS_EXIT):
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit(
            f"FAIL: the MCP Inspector exited {proc.returncode}. That is neither a "
            f"clean run (0) nor a schema-portability finding "
            f"({INSPECTOR_STRICT_FINDINGS_EXIT}), so the handshake itself did not "
            "complete -- the server did not start, did not negotiate, or did not "
            "answer tools/list. The inspector output is above."
        )
    if not proc.stdout.strip():
        sys.stderr.write(proc.stderr)
        raise SystemExit(
            f"FAIL: the MCP Inspector exited {proc.returncode} but printed no "
            "tools/list reply. Nothing was measured, so this cannot be reported "
            "as a pass. The inspector stderr is above."
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        sys.stdout.write(proc.stdout[:4000])
        raise SystemExit(
            f"FAIL: the MCP Inspector's tools/list reply is not JSON: {exc}"
        ) from exc
    return payload, proc.returncode, proc.stderr


def live_surface(payload: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    tools = payload.get("tools")
    if not isinstance(tools, list) or not tools:
        raise SystemExit(
            "FAIL: the server returned no tools. An empty live surface would "
            "compare equal to an empty golden, so it is refused here rather "
            f"than reported as a match. Reply was: {json.dumps(payload)[:400]}"
        )
    return normalize_tools(tools)


def load_golden(path: Path) -> Dict[str, Dict[str, Any]]:
    """Read the golden, refusing every shape that would make the check vacuous."""
    if not path.is_file():
        raise SystemExit(
            f"FAIL: the golden MCP tool surface is missing: {path}\n"
            "\n"
            "This step does not auto-create it. A golden comparison that passes "
            "when the golden is absent asserts nothing while looking green, "
            "which is the single failure mode this file exists to prevent.\n"
            "\n"
            "If the file was deleted by accident, restore it from git:\n"
            f"    git checkout -- {_repo_relative(path)}\n"
            "If the tool surface genuinely changed and the golden needs to be "
            "rewritten, regenerate it deliberately and review the diff:\n"
            "    python .github/actions/validate-mcp/compare_tool_surface.py --update"
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"FAIL: the golden at {path} is not valid JSON: {exc}"
        ) from exc
    tools = raw.get("tools")
    if not isinstance(tools, dict) or not tools:
        raise SystemExit(
            f"FAIL: the golden at {path} names no tools. An empty golden matches "
            "anything, so it is refused. Regenerate it with --update."
        )
    return tools


def _repo_relative(path: Path) -> str:
    """Render `path` relative to the repository root, for a copy-pasteable hint.

    Falls back to the path as given: a message that is slightly less convenient
    beats one that raises while explaining a failure.
    """
    resolved = path.resolve()
    for parent in resolved.parents:
        if (parent / ".git").exists():
            return str(resolved.relative_to(parent))
    return str(path)


def compare(
    live: Dict[str, Dict[str, Any]], golden: Dict[str, Dict[str, Any]]
) -> List[str]:
    """Return one human-readable problem block per difference; empty means match."""
    problems: List[str] = []

    vanished = sorted(set(golden) - set(live))
    appeared = sorted(set(live) - set(golden))

    if vanished:
        problems.append(
            "TOOL(S) GONE FROM THE WIRE SURFACE: "
            + ", ".join(vanished)
            + "\n  The golden says a client can call these and the server no "
            "longer offers them. Every client written against them breaks."
        )
    if appeared:
        problems.append(
            "NEW TOOL(S) ON THE WIRE SURFACE: "
            + ", ".join(appeared)
            + "\n  The server offers these and the golden does not record them. "
            "A new tool is a published API: document it, then regenerate the "
            "golden so the addition is reviewed rather than discovered."
        )

    for name in sorted(set(live) & set(golden)):
        for field in COMPARED_FIELDS:
            want = golden[name].get(field)
            got = live[name].get(field)
            if want == got:
                continue
            if want is None:
                problems.append(f"{name}: gained a {field} the golden does not record.")
                continue
            if got is None:
                problems.append(f"{name}: lost the {field} the golden records.")
                continue
            if field == "description":
                want_lines = str(want).splitlines()
                got_lines = str(got).splitlines()
            else:
                want_lines = _pretty(want)
                got_lines = _pretty(got)
            diff = "\n".join(
                difflib.unified_diff(
                    want_lines,
                    got_lines,
                    fromfile=f"golden/{name}.{field}",
                    tofile=f"live/{name}.{field}",
                    lineterm="",
                )
            )
            problems.append(f"{name}: {field} changed.\n{diff}")

    return problems


def write_golden(path: Path, live: Dict[str, Dict[str, Any]]) -> None:
    """Rewrite the golden from a live capture.

    The leading `_` keys are for the reader, not the comparison -- `load_golden`
    reads only `tools`. They are deliberately static text: a provenance field
    that churned between captures (the interpreter version used, say) would put
    noise in every regeneration and train reviewers to wave the diff through,
    which is the habit this whole check is meant to break.
    """
    document = {
        "_comment": (
            "Golden copy of the ASH MCP server's tools/list reply, as a real "
            "client receives it over stdio. Compared by "
            ".github/actions/validate-mcp/compare_tool_surface.py, which the "
            "validate-mcp composite action runs in CI. Read that script before "
            "editing this file: it explains which fields are normalized and why, "
            "and why regenerating rather than reading a diff is the wrong "
            "instinct. Do not hand-edit -- regenerate."
        ),
        "_regenerate": (
            "python .github/actions/validate-mcp/compare_tool_surface.py --update"
        ),
        "_normalization": [
            "description: inspect.cleandoc (CPython 3.14 dedents docstrings, 3.10-3.13 do not)",
            "object keys: sorted (JSON objects are unordered per RFC 8259)",
            "required/enum arrays: sorted (both are sets per JSON Schema)",
        ],
        "tools": live,
    }
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--golden",
        type=Path,
        default=DEFAULT_GOLDEN,
        help="Path to the golden tool surface (default: %(default)s)",
    )
    parser.add_argument(
        "--inspector",
        default=os.environ.get("MCP_INSPECTOR_BIN", "mcp-inspector"),
        help="MCP Inspector executable (default: mcp-inspector on PATH)",
    )
    parser.add_argument(
        "--ash",
        default=os.environ.get("ASH_BIN", "ash"),
        help="ash executable to serve over stdio (default: ash on PATH)",
    )
    parser.add_argument(
        "--inspector-arg",
        action="append",
        default=[],
        dest="inspector_args",
        help="Extra argument forwarded to the inspector (repeatable)",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Rewrite the golden from the live surface. The only writing path; "
        "never used in CI.",
    )
    parser.add_argument(
        "--gate-portability",
        dest="gate_portability",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Fail when --strict reports an error-severity schema portability "
        "problem (default: enabled)",
    )
    args = parser.parse_args()

    inspector = shutil.which(args.inspector) or args.inspector
    ash = shutil.which(args.ash) or args.ash
    if not Path(inspector).exists():
        raise SystemExit(
            f"FAIL: MCP Inspector not found ({args.inspector!r}). This check "
            "drives the real protocol, so the inspector is required rather than "
            "optional; install it with the pinned version the action uses."
        )
    if not Path(ash).exists():
        raise SystemExit(f"FAIL: ash executable not found ({args.ash!r}).")

    payload, portability_exit, inspector_stderr = capture(
        inspector, ash, args.inspector_args
    )
    live = live_surface(payload)
    sys.stderr.write(inspector_stderr)

    if args.update:
        try:
            before = load_golden(args.golden)
        except SystemExit:
            before = {}
        write_golden(args.golden, live)
        changed = compare(live, before) if before else []
        print(f"\nWrote {args.golden} with {len(live)} tools.")
        if before and not changed:
            print("The surface was already current; the golden is unchanged.")
        elif before:
            print(f"{len(changed)} difference(s) were recorded. Review the git diff.")
        return 0

    golden = load_golden(args.golden)
    problems = compare(live, golden)

    print(
        f"\nCompared {len(live)} live tool(s) against {len(golden)} in "
        f"{args.golden.name}."
    )
    print(f"Fields compared per tool: {', '.join(COMPARED_FIELDS)}.")

    failed = False

    if problems:
        failed = True
        print(f"\nMCP WIRE SURFACE MISMATCH -- {len(problems)} difference(s):\n")
        for block in problems:
            print(block)
            print()
        print(
            "The golden records the tools/list reply a client receives. If this "
            "change is intended, regenerate it and put the diff in the pull "
            "request so a reviewer sees the API change:\n"
            "    python .github/actions/validate-mcp/compare_tool_surface.py --update\n"
            "If it is not intended, the server's published surface just changed "
            "by accident."
        )
    else:
        print("MCP wire surface matches the golden.")

    # Reported whether or not it gates, because the count alone is the signal a
    # reader needs and suppressing it entirely would hide a growing problem.
    if portability_exit == INSPECTOR_STRICT_FINDINGS_EXIT:
        if args.gate_portability:
            failed = True
            print(
                "\nSCHEMA PORTABILITY: the inspector reported at least one "
                "error-severity problem (exit "
                f"{INSPECTOR_STRICT_FINDINGS_EXIT}). Detail is on stderr above. "
                "An error-severity finding means a real client cannot rely on "
                "the schema, and the golden cannot catch it -- a regenerated "
                "golden would simply record the unportable schema as expected."
            )
        else:
            print(
                "\nSCHEMA PORTABILITY: error-severity problem(s) reported; not "
                "gating because --no-gate-portability was passed."
            )
    else:
        print("\nSchema portability: no error-severity problems.")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
