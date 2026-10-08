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
client does: the inspector spawns `ashx mcp` over stdio, performs the
initialization handshake, calls one list method, and prints the server's reply.
That reply is compared against `tool_surface.golden.json`.

WHICH SURFACES
--------------
One spawn per list method, because the inspector CLI runs one method per
invocation. Each surface is a top-level key of the golden, keyed inside by the
field a client addresses the entry by:

* `tools` -- `tools/list`, by `name`: description, inputSchema, outputSchema
* `resources` -- `resources/list`, by `uri`: name, title, description,
  mimeType, annotations, size
* `resourceTemplates` -- `resources/templates/list`, by `uriTemplate`: the same
  fields as a resource. ASH registers no template today, so this is `{}`; it is
  pinned anyway so the first template to appear is a reviewed addition rather
  than an unnoticed one.
* `prompts` -- `prompts/list`, by `name`: title, description, and the
  `arguments` list (each argument's name, description and `required` flag)

`SURFACES` below is the table that drives all four; adding a surface is one row
there and a regeneration. The list replies are declarative, exactly as
`tools/list` is: what a resource *returns* and what a prompt *renders* are
runtime values and are pinned by syrupy snapshots under tests/snapshot/mcp, not
here. tests/unit/cli/mcp/test_mcp_wire_golden_in_process.py asserts the same
golden against the in-process registry with this module's normalization, which
is what covers the Windows legs this step skips.

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

* a console-script entry point that no longer resolves, or an `ashx mcp` that
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

The same three rules apply to every surface. None of them is surface-specific,
which is the point: one normalization, so the four surfaces cannot drift into
four different definitions of "unchanged".

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
* a golden that lacks one of the surface keys is a hard failure, so a golden
  written before a surface was added cannot pass by not mentioning it
* a golden that parses but names zero tools, resources or prompts is a hard
  failure
* a live surface with zero tools, resources or prompts is a hard failure, so a
  broken invocation that emits `{"tools": []}` cannot match an empty golden.
  `resourceTemplates` is the one surface allowed to be empty, because empty is
  what ASH serves; it is captured from the same server that just answered the
  three non-empty methods, so an empty reply there is not a dead handshake.
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Tuple

HERE = Path(__file__).resolve().parent
DEFAULT_GOLDEN = HERE / "tool_surface.golden.json"

# JSON Schema keywords whose array value is a set, so sorting is lossless.
SET_VALUED_ARRAY_KEYS = frozenset({"required", "enum"})

# `--strict` exits 6 when any tool-schema portability problem is error-severity,
# and 0 when the worst is a warning. Both are successful protocol exchanges that
# print the `tools/list` reply, so both are "the call worked" as far as capturing
# goes; the portability verdict is reported separately below.
INSPECTOR_STRICT_FINDINGS_EXIT = 6


@dataclass(frozen=True)
class Surface:
    """One list method of the MCP wire surface, and how the golden stores it.

    `key` is both the array key in the server's reply and the top-level key in
    the golden. `identity` is the field a client addresses an entry by, which is
    what the golden keys entries on. `fields` are the entry fields compared; the
    identity is the dict key and is not repeated inside the entry.
    """

    key: str
    method: str
    identity: str
    fields: Tuple[str, ...]
    noun: str
    may_be_empty: bool = False
    strict: bool = False


TOOLS = Surface(
    key="tools",
    method="tools/list",
    identity="name",
    fields=("description", "inputSchema", "outputSchema"),
    noun="tool",
    # --strict only means something for tools/list: it checks tool schemas.
    strict=True,
)
RESOURCES = Surface(
    key="resources",
    method="resources/list",
    identity="uri",
    fields=("name", "title", "description", "mimeType", "annotations", "size"),
    noun="resource",
)
RESOURCE_TEMPLATES = Surface(
    key="resourceTemplates",
    method="resources/templates/list",
    identity="uriTemplate",
    fields=("name", "title", "description", "mimeType", "annotations"),
    noun="resource template",
    may_be_empty=True,
)
PROMPTS = Surface(
    key="prompts",
    method="prompts/list",
    identity="name",
    fields=("title", "description", "arguments"),
    noun="prompt",
)

#: Every surface the golden pins, in the order they are captured and reported.
SURFACES: Tuple[Surface, ...] = (TOOLS, RESOURCES, RESOURCE_TEMPLATES, PROMPTS)

# The fields of a `tools/list` entry this check pins. Kept as a name because it
# predates the other surfaces and is the tools row of SURFACES.
COMPARED_FIELDS = TOOLS.fields


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


def normalize_entries(
    entries: List[Dict[str, Any]], surface: Surface = TOOLS
) -> Dict[str, Dict[str, Any]]:
    """Turn a list reply into the identity-keyed shape the golden stores.

    Keying by identity is what makes this a set comparison rather than a byte
    diff: the order the server happens to list entries in becomes irrelevant,
    and an entry that appears or disappears shows up as a key difference with
    its own message instead of as a shifted array.
    """
    out: Dict[str, Dict[str, Any]] = {}
    for item in entries:
        ident = item.get(surface.identity)
        if not ident:
            raise SystemExit(
                f"FAIL: a {surface.method} entry has no {surface.identity}: "
                f"{json.dumps(item)[:200]}"
            )
        if ident in out:
            raise SystemExit(
                f"FAIL: the server returned two {surface.noun}s with "
                f"{surface.identity} {ident!r}. The wire surface must have unique "
                f"{surface.identity}s; a client keyed by {surface.identity} would "
                "silently lose one of them."
            )
        entry: Dict[str, Any] = {}
        for field in surface.fields:
            if field not in item:
                continue
            value = item[field]
            if field == "description":
                # See NORMALIZATION note 1.
                value = inspect.cleandoc(value or "")
            else:
                value = _sort_set_valued(value)
            entry[field] = value
        out[ident] = entry
    return out


def normalize_tools(tools: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """`normalize_entries` for `tools/list`, under the name it was written with."""
    return normalize_entries(tools, TOOLS)


def _pretty(value: Any) -> List[str]:
    """Render for a human-readable diff: canonical keys, one token per line."""
    return json.dumps(value, indent=2, sort_keys=True).splitlines()


def capture(
    inspector: str,
    ash: str,
    extra_args: List[str] | None = None,
    surface: Surface = TOOLS,
) -> Tuple[Dict[str, Any], int, str]:
    """Run one real handshake and return (payload, inspector_exit, stderr).

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

    Treating exit 6 as a successful capture is measured, not assumed, and applies
    only to `tools/list`, the one method run with `--strict`. Against a stub
    server that answers `tools/list` with a property whose schema is the bare
    boolean `true`, inspector 2.8.0 prints the full `tools/list` reply on stdout,
    the per-tool error detail on stderr, and exits 6. So a portability error does
    not cost the golden comparison: both verdicts are reported from one spawn.
    The other three methods run without `--strict`, measured to exit 0 against
    `ashx mcp` with inspector 2.8.0, so anything else from them is a failure.

    The pin moved to 2.9.0 because 2.8.0 depends on @modelcontextprotocol/client
    2.0.0-2.1.0 (GHSA-6qxp-vccf-f47h). On that bump this whole comparison was run
    under both versions against the same `ashx mcp`: all four methods exited 0, the
    surface matched the golden, and the output, warnings included, was identical.
    The exit-6 stub measurement above was not repeated.
    """
    cmd = [inspector, "--cli", ash, "mcp", "--method", surface.method]
    if surface.strict:
        cmd.append("--strict")
    cmd.extend(extra_args or [])
    accepted = (0, INSPECTOR_STRICT_FINDINGS_EXIT) if surface.strict else (0,)
    print(f"$ {' '.join(cmd)}", flush=True)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    if proc.returncode not in accepted:
        sys.stdout.write(proc.stdout)
        sys.stderr.write(proc.stderr)
        raise SystemExit(
            f"FAIL: the MCP Inspector exited {proc.returncode} on {surface.method}. "
            f"Accepted exits for this method are {list(accepted)}, so the handshake "
            "itself did not complete -- the server did not start, did not "
            f"negotiate, or did not answer {surface.method}. The inspector output "
            "is above."
        )
    if not proc.stdout.strip():
        sys.stderr.write(proc.stderr)
        raise SystemExit(
            f"FAIL: the MCP Inspector exited {proc.returncode} but printed no "
            f"{surface.method} reply. Nothing was measured, so this cannot be "
            "reported as a pass. The inspector stderr is above."
        )
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        sys.stdout.write(proc.stdout[:4000])
        raise SystemExit(
            f"FAIL: the MCP Inspector's {surface.method} reply is not JSON: {exc}"
        ) from exc
    return payload, proc.returncode, proc.stderr


def live_surface(
    payload: Dict[str, Any], surface: Surface = TOOLS
) -> Dict[str, Dict[str, Any]]:
    entries = payload.get(surface.key)
    if not isinstance(entries, list):
        raise SystemExit(
            f"FAIL: the {surface.method} reply has no {surface.key!r} array. "
            f"Reply was: {json.dumps(payload)[:400]}"
        )
    if not entries and not surface.may_be_empty:
        raise SystemExit(
            f"FAIL: the server returned no {surface.noun}s. An empty live surface "
            "would compare equal to an empty golden, so it is refused here rather "
            f"than reported as a match. Reply was: {json.dumps(payload)[:400]}"
        )
    return normalize_entries(entries, surface)


def load_golden(path: Path) -> Dict[str, Dict[str, Dict[str, Any]]]:
    """Read the golden, refusing every shape that would make the check vacuous.

    Returns one identity-keyed dict per surface, keyed by `Surface.key`.
    """
    if not path.is_file():
        raise SystemExit(
            f"FAIL: the golden MCP wire surface is missing: {path}\n"
            "\n"
            "This step does not auto-create it. A golden comparison that passes "
            "when the golden is absent asserts nothing while looking green, "
            "which is the single failure mode this file exists to prevent.\n"
            "\n"
            "If the file was deleted by accident, restore it from git:\n"
            f"    git checkout -- {_repo_relative(path)}\n"
            "If the wire surface genuinely changed and the golden needs to be "
            "rewritten, regenerate it deliberately and review the diff:\n"
            "    python .github/actions/validate-mcp/compare_tool_surface.py --update"
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(
            f"FAIL: the golden at {path} is not valid JSON: {exc}"
        ) from exc
    golden: Dict[str, Dict[str, Dict[str, Any]]] = {}
    for surface in SURFACES:
        if surface.key not in raw:
            raise SystemExit(
                f"FAIL: the golden at {path} has no {surface.key!r} key, so it "
                f"records nothing about {surface.method}. A surface the golden "
                "does not mention cannot be compared, and passing it would hide "
                "every change to it. Regenerate it with --update and review the "
                "addition."
            )
        entries = raw[surface.key]
        if not isinstance(entries, dict):
            raise SystemExit(
                f"FAIL: the golden at {path} stores {surface.key!r} as "
                f"{type(entries).__name__}, not an object keyed by "
                f"{surface.identity}. Regenerate it with --update."
            )
        if not entries and not surface.may_be_empty:
            raise SystemExit(
                f"FAIL: the golden at {path} names no {surface.noun}s. An empty "
                "golden matches anything, so it is refused. Regenerate it with "
                "--update."
            )
        golden[surface.key] = entries
    return golden


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
    live: Dict[str, Dict[str, Any]],
    golden: Dict[str, Dict[str, Any]],
    surface: Surface = TOOLS,
) -> List[str]:
    """Return one human-readable problem block per difference; empty means match."""
    problems: List[str] = []
    noun = surface.noun.upper()

    vanished = sorted(set(golden) - set(live))
    appeared = sorted(set(live) - set(golden))

    if vanished:
        problems.append(
            f"{noun}(S) GONE FROM THE WIRE SURFACE: "
            + ", ".join(vanished)
            + "\n  The golden says a client can use these and the server no "
            "longer offers them. Every client written against them breaks."
        )
    if appeared:
        problems.append(
            f"NEW {noun}(S) ON THE WIRE SURFACE: "
            + ", ".join(appeared)
            + "\n  The server offers these and the golden does not record them. "
            f"A new {surface.noun} is a published API: document it, then "
            "regenerate the golden so the addition is reviewed rather than "
            "discovered."
        )

    for ident in sorted(set(live) & set(golden)):
        label = ident if surface is TOOLS else f"{surface.noun} {ident}"
        for field in surface.fields:
            want = golden[ident].get(field)
            got = live[ident].get(field)
            if want == got:
                continue
            if want is None:
                problems.append(
                    f"{label}: gained a {field} the golden does not record."
                )
                continue
            if got is None:
                problems.append(f"{label}: lost the {field} the golden records.")
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
                    fromfile=f"golden/{surface.key}/{ident}.{field}",
                    tofile=f"live/{surface.key}/{ident}.{field}",
                    lineterm="",
                )
            )
            problems.append(f"{label}: {field} changed.\n{diff}")

    return problems


def compare_all(
    live: Dict[str, Dict[str, Dict[str, Any]]],
    golden: Dict[str, Dict[str, Dict[str, Any]]],
) -> List[str]:
    """`compare` over every surface, in SURFACES order."""
    problems: List[str] = []
    for surface in SURFACES:
        problems.extend(
            compare(live.get(surface.key, {}), golden.get(surface.key, {}), surface)
        )
    return problems


def golden_document(live: Dict[str, Dict[str, Dict[str, Any]]]) -> Dict[str, Any]:
    """The golden file's content for a live capture of every surface.

    The leading `_` keys are for the reader, not the comparison -- `load_golden`
    reads only the surface keys. They are deliberately static text: a provenance
    field that churned between captures (the interpreter version used, say) would
    put noise in every regeneration and train reviewers to wave the diff through,
    which is the habit this whole check is meant to break.
    """
    document: Dict[str, Any] = {
        "_comment": (
            "Golden copy of the ASH MCP server's tools/list, resources/list, "
            "resources/templates/list and prompts/list replies, as a real client "
            "receives them over stdio. Compared by "
            ".github/actions/validate-mcp/compare_tool_surface.py, which the "
            "validate-mcp composite action runs in CI, and against the "
            "in-process registry by "
            "tests/unit/cli/mcp/test_mcp_wire_golden_in_process.py. Read that "
            "script before editing this file: it explains which fields are "
            "normalized and why, and why regenerating rather than reading a diff "
            "is the wrong instinct. Do not hand-edit -- regenerate."
        ),
        "_regenerate": (
            "python .github/actions/validate-mcp/compare_tool_surface.py --update"
        ),
        "_normalization": [
            "description: inspect.cleandoc (CPython 3.14 dedents docstrings, 3.10-3.13 do not)",
            "object keys: sorted (JSON objects are unordered per RFC 8259)",
            "required/enum arrays: sorted (both are sets per JSON Schema)",
        ],
    }
    for surface in SURFACES:
        document[surface.key] = live[surface.key]
    return document


def write_golden(path: Path, live: Dict[str, Dict[str, Dict[str, Any]]]) -> None:
    """Rewrite the golden from a live capture of every surface."""
    path.write_text(
        json.dumps(golden_document(live), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--golden",
        type=Path,
        default=DEFAULT_GOLDEN,
        help="Path to the golden wire surface (default: %(default)s)",
    )
    parser.add_argument(
        "--inspector",
        default=os.environ.get("MCP_INSPECTOR_BIN", "mcp-inspector"),
        help="MCP Inspector executable (default: mcp-inspector on PATH)",
    )
    parser.add_argument(
        "--ash",
        default=os.environ.get("ASH_BIN", "ashx"),
        help="ASH executable to serve over stdio (default: ashx on PATH)",
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
        raise SystemExit(f"FAIL: ASH executable not found ({args.ash!r}).")

    live: Dict[str, Dict[str, Dict[str, Any]]] = {}
    portability_exit = 0
    for surface in SURFACES:
        payload, exit_code, inspector_stderr = capture(
            inspector, ash, args.inspector_args, surface
        )
        live[surface.key] = live_surface(payload, surface)
        sys.stderr.write(inspector_stderr)
        if surface.strict:
            portability_exit = exit_code

    counts = ", ".join(f"{len(live[s.key])} {s.key}" for s in SURFACES)

    if args.update:
        try:
            before = load_golden(args.golden)
        except SystemExit:
            before = {}
        write_golden(args.golden, live)
        changed = compare_all(live, before) if before else []
        print(f"\nWrote {args.golden} with {counts}.")
        if before and not changed:
            print("The surface was already current; the golden is unchanged.")
        elif before:
            print(f"{len(changed)} difference(s) were recorded. Review the git diff.")
        return 0

    golden = load_golden(args.golden)
    problems = compare_all(live, golden)

    print(f"\nCompared {counts} live against {args.golden.name}.")
    for surface in SURFACES:
        print(f"Fields compared per {surface.noun}: {', '.join(surface.fields)}.")

    failed = False

    if problems:
        failed = True
        print(f"\nMCP WIRE SURFACE MISMATCH -- {len(problems)} difference(s):\n")
        for block in problems:
            print(block)
            print()
        print(
            "The golden records the list replies a client receives. If this "
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
