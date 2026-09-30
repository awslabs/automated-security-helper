# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

"""Derive the gate's contract from the gate, instead of transcribing it.

WHY THIS MODULE EXISTS
----------------------
`expected.json` used to carry its own copy of two things the gate owns: the
exit-code-to-verdict mapping from `_verdict()`, and the scan flag set from
`CODECOMMIT_GATE_HANDLER`. Both copies were hand-transcribed from
`deploy/cdk/lib/ash-container-scripts.ts`, and a transcription of a contract
drifts from the contract. The mapping's copy listed exit codes 0 through 3 and
stopped, so exit code 4 -- `workspace definition or policy error` in
`ASH_EXIT_CODES` -- was absent from the fixture entirely, and a harness reading
the copy would have derived nothing for it.

The pattern followed here is `deploy/cdk/scripts/gen-s3-sync-diff-fixture.sh`,
which extracts a script constant through the app rather than re-typing it.

HOW THE HANDLER IS OBTAINED, AND WHY NOT `npx ts-node`
------------------------------------------------------
`gen-s3-sync-diff-fixture.sh` imports the constant with `npx ts-node`, which is
authoritative but needs a Node toolchain and an installed `deploy/cdk`. This
module is imported by a pytest test that runs in the integration job, where
neither exists -- and a derivation that only runs on a developer's machine gates
nothing, which is the failure this whole fixture is about.

So the template literal is extracted directly. That is safe here, and checked
rather than assumed:

* `CODECOMMIT_GATE_HANDLER` contains no `${...}` interpolation, so it is a plain
  string and extracting it is lossless. `extract_handler_source` asserts that; if
  an interpolation is ever added, this raises instead of silently returning a
  half-rendered script.
* `handler_matches_deployed_template` corroborates the extraction against the
  handler embedded in `deploy/cdk/templates/AshCodeCommitGate.template.json`,
  which is synthesized by the app and is itself gated byte-for-byte against a
  fresh synth by `.github/workflows/ash-iac-drift.yml`. If the extraction were
  wrong, the two would disagree.

WHAT IS DERIVED, AND WHAT THAT BUYS
-----------------------------------
`derive_verdict_mapping` EXECUTES the extracted `_verdict`. It does not read the
function's source and reimplement its branches -- that would be a second
transcription wearing a derivation's clothes. Executing it means the fallback
arm is covered for free, which is what puts exit code 4 in the mapping: the gate
has no branch for 4, so it falls through to `errored`, and the derived mapping
says so because the function said so.

`derive_scan_flags` reads the argv construction out of the syntax tree, so a flag
added to or removed from the handler changes the derived set without anyone
editing a fixture.
"""

from __future__ import annotations

import ast
import json
import re
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
CONTAINER_SCRIPTS_TS = REPO_ROOT / "deploy" / "cdk" / "lib" / "ash-container-scripts.ts"
GATE_TEMPLATE_JSON = (
    REPO_ROOT / "deploy" / "cdk" / "templates" / "AshCodeCommitGate.template.json"
)
CONTRACT_JSON = HERE / "gate-contract.json"

_HANDLER_MARKER = "export const CODECOMMIT_GATE_HANDLER = `"

# The TS template-literal escapes the handler actually uses, plus the ones it
# could grow. Anything else is left alone rather than guessed at.
_TS_ESCAPES = {
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "\\": "\\",
    "`": "`",
    "$": "$",
}


def _closing_backtick(text: str, start: int) -> int:
    """Index of the backtick that ends the template literal opened before `start`.

    A backtick preceded by an odd number of backslashes is escaped and is part of
    the string -- the handler contains several, in the markdown fences it posts
    as pull-request comments.
    """
    index = start
    while True:
        candidate = text.index("`", index)
        backslashes = 0
        cursor = candidate - 1
        while cursor >= 0 and text[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        if backslashes % 2 == 0:
            return candidate
        index = candidate + 1


def extract_handler_source(ts_path: Path | None = None) -> str:
    """Return the Python source of CODECOMMIT_GATE_HANDLER."""
    text = (ts_path or CONTAINER_SCRIPTS_TS).read_text(encoding="utf-8")
    if _HANDLER_MARKER not in text:
        raise AssertionError(
            f"{_HANDLER_MARKER!r} is not in {ts_path or CONTAINER_SCRIPTS_TS}. The "
            f"constant was renamed or moved; this derivation cannot run and must "
            f"not fall back to a transcribed copy."
        )
    start = text.index(_HANDLER_MARKER) + len(_HANDLER_MARKER)
    raw = text[start : _closing_backtick(text, start)]

    # An interpolation would mean the deployed script is not this string.
    without_escaped = raw.replace("\\$", "")
    if "${" in without_escaped:
        raise AssertionError(
            "CODECOMMIT_GATE_HANDLER now contains a ${...} interpolation, so "
            "extracting the literal no longer yields the script the stack emits. "
            "Render it through the app (npx ts-node, as "
            "deploy/cdk/scripts/gen-s3-sync-diff-fixture.sh does) instead."
        )

    out: list[str] = []
    index = 0
    while index < len(raw):
        char = raw[index]
        if char == "\\" and index + 1 < len(raw) and raw[index + 1] in _TS_ESCAPES:
            out.append(_TS_ESCAPES[raw[index + 1]])
            index += 2
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _normalize_for_corroboration(text: str) -> str:
    """Strip what the shell and JSON layers add, leaving comparable content.

    The handler reaches the synthesized template through a heredoc inside a
    buildspec inside a JSON string, and each layer adds escaping: the template's
    copy carries `\\"` for every quote. Removing backslashes and whitespace makes
    the two comparable.

    Only usable on text containing no `\\n` escape of its own. The template
    encodes the handler's LINE BREAKS as a literal backslash-n, so stripping
    backslashes there leaves a stray `n` that has no counterpart on the extracted
    side -- which is why corroboration below is done per-line, on lines that
    contain no escapes, rather than over the whole script.
    """
    return re.sub(r"\s+", "", text.replace("\\", ""))


def corroboration_lines(source: str | None = None) -> list[str]:
    """The handler lines every derived fact is read from.

    Corroborating these rather than the whole script is deliberate. The point of
    checking against the synthesized template is to confirm the values in the
    contract are the values that DEPLOY; a whole-file comparison would answer a
    broader question and, because of the escaping described above, would answer it
    unreliably. These are the lines `derive_verdict_mapping` and
    `derive_scan_flags` actually depend on, and none of them contains an escape.
    """
    code = source if source is not None else extract_handler_source()
    wanted: list[str] = []
    for line in code.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("EXIT_") and "=" in stripped:
            wanted.append(stripped)
        elif stripped.startswith("def _verdict"):
            wanted.append(stripped)
        elif stripped.startswith(('return "passed"', 'return "failed"')):
            wanted.append(stripped)
        elif stripped.startswith("argv") and "--" in stripped:
            wanted.append(stripped)
        elif stripped.startswith('"--'):
            wanted.append(stripped)
    return wanted


def handler_corroboration_failures(template_path: Path | None = None) -> list[str]:
    """Which derived-from lines are absent from the synthesized template.

    Empty means every line the contract is derived from is present in the
    template the app synthesizes -- and that template is itself gated byte-for-byte
    against a fresh synth by .github/workflows/ash-iac-drift.yml, so the
    extraction is reading the script that deploys.
    """
    path = template_path or GATE_TEMPLATE_JSON
    if not path.is_file():
        return [f"{path} is absent, so the extraction cannot be corroborated"]

    haystack = _normalize_for_corroboration(path.read_text(encoding="utf-8"))
    lines = corroboration_lines()
    if not lines:
        return ["no corroboration lines were collected; nothing was compared"]

    return [
        line for line in lines if _normalize_for_corroboration(line) not in haystack
    ]


def handler_matches_deployed_template(template_path: Path | None = None) -> bool:
    """Is the extracted handler the one the synthesized template deploys?"""
    return not handler_corroboration_failures(template_path)


def _handler_namespace(source: str | None = None) -> dict:
    """Execute the handler far enough to get its module-level functions.

    `boto3` is stubbed because importing it is not this derivation's business and
    the module-level import is the only thing that needs it; `handler()` is never
    called, so no AWS client is ever constructed.
    """
    import sys
    import types

    code = source if source is not None else extract_handler_source()

    stub = types.ModuleType("boto3")
    stub.client = lambda *args, **kwargs: None  # pragma: no cover - never called
    injected = "boto3" not in sys.modules
    if injected:
        sys.modules["boto3"] = stub
    try:
        namespace: dict = {"__name__": "_ash_gate_handler"}
        # B102 (exec_used) is correct that this is `exec`, and the `exec` is the
        # point -- see "WHAT IS DERIVED, AND WHAT THAT BUYS" above. Suppressed on
        # this line only, and only for this rule.
        #
        # What is executed: `code` is the CODECOMMIT_GATE_HANDLER template literal
        # read out of the repo-tracked deploy/cdk/lib/ash-container-scripts.ts, and
        # corroborated against the synthesized template by
        # `handler_matches_deployed_template`. No caller supplies it -- the only
        # parameter is `source`, every call site in this module reaches it through
        # `extract_handler_source()`, and nothing outside this module calls
        # `_handler_namespace`. Changing what runs here requires write access to
        # this repository, which is the same access that could edit this file.
        #
        # Rejected: writing `code` to a temporary file and loading it with
        # `importlib`. That runs the identical bytes while no longer matching B102,
        # which hides the fact from the scanner instead of recording it.
        exec(compile(code, "<CODECOMMIT_GATE_HANDLER>", "exec"), namespace)  # nosec B102
    finally:
        if injected:
            del sys.modules["boto3"]
    return namespace


def derive_verdict_mapping(source: str | None = None) -> dict[str, str]:
    """Call the gate's own `_verdict` for every exit code ASH documents.

    Keyed by string, because JSON object keys are strings and the harness looks
    the code up after reading it out of shell output.

    `unknown` records the fallback arm. It is derived by calling `_verdict` with a
    code that is deliberately not in ASH_EXIT_CODES, so if the fallback is ever
    changed the derived value changes with it.
    """
    from automated_security_helper.core.constants import ASH_EXIT_CODES

    namespace = _handler_namespace(source)
    verdict = namespace.get("_verdict")
    if not callable(verdict):
        raise AssertionError(
            "the extracted handler defines no callable _verdict; the gate's "
            "verdict logic was renamed and this derivation is measuring nothing"
        )

    mapping = {str(code): verdict(code)[0] for code in sorted(ASH_EXIT_CODES)}
    sentinel = max(ASH_EXIT_CODES) + 100
    mapping["unknown"] = verdict(sentinel)[0]
    return mapping


def derive_scan_flags(source: str | None = None) -> dict[str, list[str]]:
    """Read the flags out of the handler's argv construction.

    Three groups, matching the three ways the handler builds argv: the
    unconditional base, the changed-files pair added when
    ASH_CHANGED_FILES_ONLY is on, and the severity pair added when
    ASH_MIN_SEVERITY is set. Only literal `--flag` strings are collected; the
    values beside them are runtime data (a temp directory, a commit id) and are
    not part of the contract.
    """
    code = source if source is not None else extract_handler_source()
    tree = ast.parse(code)

    handler = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.FunctionDef) and node.name == "handler"
        ),
        None,
    )
    if handler is None:
        raise AssertionError("the extracted handler defines no handler() function")

    def flags_of(node: ast.AST) -> list[str]:
        found = []
        for child in ast.walk(node):
            if (
                isinstance(child, ast.Constant)
                and isinstance(child.value, str)
                and child.value.startswith("--")
            ):
                found.append(child.value)
        return found

    base: list[str] = []
    changed_files_only: list[str] = []
    min_severity: list[str] = []

    for node in ast.walk(handler):
        # `argv = [...]`
        if isinstance(node, ast.Assign) and any(
            isinstance(t, ast.Name) and t.id == "argv" for t in node.targets
        ):
            base.extend(flags_of(node.value))
        # `argv += [...]`, each inside the `if` that guards it
        if (
            isinstance(node, ast.AugAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == "argv"
        ):
            added = flags_of(node.value)
            if any(flag.startswith("--min-severity") for flag in added):
                min_severity.extend(added)
            else:
                changed_files_only.extend(added)

    if not base:
        raise AssertionError(
            "no argv assignment with literal flags was found in handler(); the "
            "flag set cannot be derived and must not be reported as empty"
        )

    return {
        "base": base,
        "changed_files_only": changed_files_only,
        "min_severity": min_severity,
    }


def derive_min_severity_default(template_path: Path | None = None) -> str | None:
    """The MinSeverity stack parameter's default, from the synthesized template.

    The handler reads ASH_MIN_SEVERITY from the environment and has no default of
    its own, so the value a deployment actually scans with comes from the
    CloudFormation parameter. Read from the synthesized template rather than the
    TypeScript, because the template is what an adopter deploys and is itself
    drift-gated against the app.
    """
    doc = json.loads((template_path or GATE_TEMPLATE_JSON).read_text(encoding="utf-8"))
    parameter = (doc.get("Parameters") or {}).get("MinSeverity")
    if not isinstance(parameter, dict):
        return None
    return parameter.get("Default")


def build_contract() -> dict:
    """Assemble the whole derived contract."""
    source = extract_handler_source()
    flags = derive_scan_flags(source)
    default_severity = derive_min_severity_default()
    return {
        "_comment": [
            "DERIVED FILE -- do not hand-edit. Regenerate with:",
            "  python tests/integration/codecommit_gate_regression/gate_contract.py",
            "",
            "Every value here is read out of the gate itself:",
            "  verdict_mapping     -- by CALLING _verdict() from",
            "                         CODECOMMIT_GATE_HANDLER for each code in",
            "                         ASH_EXIT_CODES, so the fallback arm is",
            "                         covered and exit code 4 appears.",
            "  scan_flags          -- from the argv construction in handler().",
            "  min_severity_default-- from the MinSeverity parameter of the",
            "                         synthesized AshCodeCommitGate template.",
            "",
            "tests/integration/codecommit_gate_regression/",
            "test_codecommit_gate_regression.py re-derives all of it and fails if",
            "this file disagrees, so it cannot drift from the gate unnoticed.",
        ],
        "verdict_mapping": derive_verdict_mapping(source),
        "scan_flags": flags,
        "min_severity_default": default_severity,
        "min_severity_invocation": flags["min_severity"] + [str(default_severity)],
    }


def load_contract() -> dict:
    """Read the committed derived contract, failing closed if it is absent."""
    if not CONTRACT_JSON.is_file():
        raise AssertionError(
            f"{CONTRACT_JSON} is missing. Regenerate it with: python {__file__}"
        )
    return json.loads(CONTRACT_JSON.read_text(encoding="utf-8"))


def render_contract() -> str:
    return json.dumps(build_contract(), indent=2, sort_keys=True) + "\n"


def main() -> int:
    CONTRACT_JSON.write_text(render_contract(), encoding="utf-8")
    contract = load_contract()
    print(f"wrote {CONTRACT_JSON.relative_to(REPO_ROOT)}")
    print(f"  verdict_mapping: {contract['verdict_mapping']}")
    print(f"  scan_flags:      {contract['scan_flags']}")
    print(f"  min_severity:    {contract['min_severity_invocation']}")
    if not handler_matches_deployed_template():
        print(
            "WARNING: the extracted handler does not appear in the synthesized "
            "template. Re-synthesize deploy/cdk/templates and compare."
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
