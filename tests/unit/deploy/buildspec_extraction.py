"""Pull the AWS-touching command strings out of the committed CDK templates.

WHY EXTRACT RATHER THAN RECONSTRUCT
-----------------------------------
The helpers these tests exercise are defined in TypeScript
(`deploy/cdk/lib/ash-container-scripts.ts`) and reach a build container only after
CDK renders them into a buildspec. An adopter runs the RENDERED string, not the
constant. A test that retyped the Python into a fixture would pass while the
rendered template said something else -- which is the exact shape of the bug the
boto3 rewrite fixed, where the template said `aws s3 cp` and the image had no
`aws`. So the subject under test is `deploy/cdk/templates/*.template.json`, which
is committed and reviewable, and every helper here reads from it.

WHY RESOURCES ARE FOUND BY CONTENT AND NOT BY LOGICAL ID
-------------------------------------------------------
CDK logical IDs carry a hash of the construct path -- `Shard0Project06DF6494`,
`MergeProject4EB0C9A5`. Hard-coding those means an unrelated construct rename
turns these tests red for no behavioral reason, and worse, a lookup that stops
matching would have to be repaired by someone who no longer remembers what the
test was for. Selecting by resource type plus a marker in the buildspec keeps
working across re-synth, and the callers assert on the COUNT of matches, so a
template that stops containing the helper fails loudly instead of silently
iterating an empty list.

FAILURE MODES THIS MODULE IS BUILT TO AVOID
-------------------------------------------
Every accessor raises on a miss instead of returning None or "". A helper that
returned an empty string on a bad path would hand the caller something that runs
as a shell no-op and exits 0, and the test would pass having executed nothing.
"""

from __future__ import annotations

import json
import pathlib

# tests/unit/deploy/buildspec_extraction.py -> repository root
REPO_ROOT = pathlib.Path(__file__).resolve().parents[3]

CDK_TEMPLATE_DIR = REPO_ROOT / "deploy" / "cdk" / "templates"

# Deliberately NO per-template constant. There was one -- pointing at
# AshDistributedPipeline -- and it is what made six tests go red when the flavor
# gating moved the MCP entrypoint to the stacks that build the mcp flavor. Naming a
# template hard-codes a deployment decision into a test that does not care which
# stack emits the thing it asserts about. Use the marker constants below with
# templates_with_plain_buildspec_marker / templates_with_joined_buildspec_marker.

# Markers that identify each injected script inside a rendered buildspec.
S3_SYNC_MARKER = "ash-s3-sync.py"
MCP_ENTRYPOINT_MARKER = "ash-mcp-entrypoint.sh"
GATE_HANDLER_MARKER = "ash_gate_handler.py"
SSM_PARAMETER_MARKER = "ASH_BASE_CONFIG_SSM_PARAMETER"
SECRETS_MARKER = "get_secret_value"

TERRAFORM_S3_SYNC = (
    REPO_ROOT
    / "deploy"
    / "terraform"
    / "modules"
    / "codepipeline-executor"
    / "files"
    / "ash_s3_sync.py"
)

CODEBUILD_PROJECT = "AWS::CodeBuild::Project"

# The path the buildspec writes the helper to inside the build container. Tests
# rewrite this to a per-test temporary path; see rewrite_helper_path.
CONTAINER_HELPER_PATH = "/tmp/ash-s3-sync.py"


def all_template_paths() -> list[pathlib.Path]:
    """Every committed CDK template, sorted."""
    paths = sorted(CDK_TEMPLATE_DIR.glob("*.template.json"))
    if not paths:
        raise AssertionError(
            f"no committed CDK templates under {CDK_TEMPLATE_DIR}. These tests "
            f"exercise the rendered templates, so there is nothing to test without "
            f"them."
        )
    return paths


def _joined_buildspec_texts(template: dict) -> list[str]:
    """Every `Fn::Join` CodeBuild buildspec, reassembled into decodable JSON text.

    Non-raising, and deliberately separate from `joined_buildspec_document`: that
    one reports where a marker went when it cannot find it, and building that report
    means walking every template. Having the report call back into a raising lookup
    would recurse forever.
    """
    texts: list[str] = []
    for resource in template.get("Resources", {}).values():
        if resource.get("Type") != CODEBUILD_PROJECT:
            continue
        spec = resource.get("Properties", {}).get("Source", {}).get("BuildSpec")
        if not isinstance(spec, dict) or "Fn::Join" not in spec:
            continue
        delimiter, parts = spec["Fn::Join"]
        texts.append(
            delimiter.join(
                part if isinstance(part, str) else "CFN_SUBSTITUTION_PLACEHOLDER"
                for part in parts
            )
        )
    return texts


def _marker_locations(marker: str) -> dict[str, tuple[int, int]]:
    """For every template, how many plain and Fn::Join buildspecs carry `marker`."""
    found: dict[str, tuple[int, int]] = {}
    for path in all_template_paths():
        template = load_template(path)
        plain = len(projects_containing(template, marker))
        joined = sum(1 for text in _joined_buildspec_texts(template) if marker in text)
        found[path.name.replace(".template.json", "")] = (plain, joined)
    return found


def _marker_report(marker: str) -> str:
    """Human-readable map of where a marker actually lives right now.

    WHY THIS EXISTS: the first time a lane changed which scripts land in which
    template, these tests failed with "no buildspec contains marker X" and no hint
    about where X had gone. Diagnosing that took far longer than it should have.
    Every failure path that cannot find a marker prints this, so the next reader
    sees the answer in the error rather than having to go looking for it.
    """
    lines = [f"where {marker!r} actually appears in the committed templates:"]
    for name, (plain, joined) in sorted(_marker_locations(marker).items()):
        if plain or joined:
            lines.append(
                f"    {name}: plain-string buildspecs={plain}, Fn::Join={joined}"
            )
    if len(lines) == 1:
        lines.append("    nowhere -- no committed template emits it at all")
    return "\n".join(lines)


def templates_with_plain_buildspec_marker(marker: str) -> dict[str, dict]:
    """Templates having a PLAIN-STRING CodeBuild buildspec that carries `marker`.

    Selecting the template by content rather than by filename, for the same reason
    resources are selected by content rather than by logical id. Which template
    emits which script is a deployment decision that changes: the flavor gating
    made each stack receive only the scripts for the flavors it builds, so the MCP
    entrypoint left AshDistributedPipeline and the S3 helper stayed. A test naming
    a file goes red on that change even though nothing it asserts is wrong. A test
    that finds the emitting template follows it.
    """
    found = {
        path.name.replace(".template.json", ""): load_template(path)
        for path in all_template_paths()
    }
    matching = {
        name: template
        for name, template in found.items()
        if projects_containing(template, marker)
    }
    if not matching:
        raise AssertionError(
            f"no committed template has a plain-string CodeBuild buildspec "
            f"containing {marker!r}, so there is nothing for this test to exercise.\n"
            f"{_marker_report(marker)}"
        )
    return matching


def templates_with_joined_buildspec_marker(marker: str) -> dict[str, dict]:
    """Templates having an `Fn::Join` CodeBuild buildspec that carries `marker`.

    The image builds assemble their buildspec from template parameters, so the
    scripts they write into the image live here rather than in a plain string.
    """
    matching: dict[str, dict] = {}
    for path in all_template_paths():
        template = load_template(path)
        if any(marker in text for text in _joined_buildspec_texts(template)):
            matching[path.name.replace(".template.json", "")] = template
    if not matching:
        raise AssertionError(
            f"no committed template has an Fn::Join CodeBuild buildspec containing "
            f"{marker!r}, so there is nothing for this test to exercise.\n"
            f"{_marker_report(marker)}"
        )
    return matching


def load_template(path: pathlib.Path) -> dict:
    """Parse a committed CloudFormation template."""
    if not path.is_file():
        raise AssertionError(
            f"expected a committed CDK template at {path}. These tests exercise the "
            f"rendered template rather than the TypeScript constant, so there is "
            f"nothing to test without it."
        )
    return json.loads(path.read_text(encoding="utf-8"))


def codebuild_buildspecs(template: dict) -> dict[str, dict]:
    """Every CodeBuild project in the template whose BuildSpec is a plain string.

    Returns logical id -> parsed buildspec. Projects whose BuildSpec is a
    `Fn::Join` are skipped: those are the image builds, whose buildspec is
    assembled from template parameters and is not parseable as standalone JSON.
    """
    found: dict[str, dict] = {}
    for logical_id, resource in template.get("Resources", {}).items():
        if resource.get("Type") != CODEBUILD_PROJECT:
            continue
        spec = resource.get("Properties", {}).get("Source", {}).get("BuildSpec")
        if not isinstance(spec, str):
            continue
        found[logical_id] = json.loads(spec)
    return found


def projects_containing(template: dict, marker: str) -> dict[str, dict]:
    """CodeBuild projects whose buildspec mentions `marker`, keyed by logical id."""
    return {
        logical_id: spec
        for logical_id, spec in codebuild_buildspecs(template).items()
        if marker in json.dumps(spec)
    }


def phase_commands(buildspec: dict, phase: str) -> list[str]:
    """The command list for one buildspec phase."""
    phases = buildspec.get("phases", {})
    if phase not in phases:
        raise AssertionError(
            f"buildspec has no {phase!r} phase; it has {sorted(phases)}. "
            f"The command this test executes lives in that phase, so a rename "
            f"means the test is no longer pointed at anything."
        )
    return list(phases[phase].get("commands", []))


def helper_invocation(buildspec: dict, phase: str, subcommand: str) -> str:
    """The command in `phase` that RUNS the helper with `subcommand`.

    The marker includes the container path on purpose. Matching on the bare word
    "download" also matches the materialize command, because the helper's own
    usage docstring names its subcommands -- so a looser marker makes
    `sole_command_containing` see two hits and refuse.
    """
    return sole_command_containing(
        buildspec, phase, f"{CONTAINER_HELPER_PATH} {subcommand}"
    )


def sole_command_containing(buildspec: dict, phase: str, marker: str) -> str:
    """The single command in `phase` that contains `marker`.

    Raises when zero or more than one match. "Zero" would otherwise leave the
    caller executing nothing; "more than one" means the marker stopped
    identifying a unique command and the test would silently exercise whichever
    happened to come first.
    """
    matches = [c for c in phase_commands(buildspec, phase) if marker in c]
    if len(matches) != 1:
        raise AssertionError(
            f"expected exactly one {phase!r} command containing {marker!r}, "
            f"found {len(matches)}. Commands present: "
            f"{[c[:80] for c in phase_commands(buildspec, phase)]}"
        )
    return matches[0]


def heredoc_body(command: str, delimiter: str = "PY") -> str:
    """The body of a quoted heredoc, as the shell would write it to disk.

    The buildspec materializes the helper with `cat > path <<'PY' ... PY`. With a
    QUOTED delimiter the shell expands nothing, so the body reaching the file is
    byte-identical to what sits between the markers -- which is why this can be
    a plain slice rather than a shell invocation.
    """
    opener = f"<<'{delimiter}'\n"
    start = command.find(opener)
    if start < 0:
        raise AssertionError(
            f"no quoted heredoc opener {opener!r} in command: {command[:200]!r}. "
            f"An UNquoted <<{delimiter} would let the shell eat the Python's $, "
            f"backticks and braces, so the distinction is load-bearing."
        )
    body_start = start + len(opener)
    terminator = f"\n{delimiter}"
    end = command.find(terminator, body_start)
    if end < 0:
        raise AssertionError(
            f"heredoc opened with {opener!r} but never terminated by a lone "
            f"{delimiter!r} line"
        )
    # The shell writes a trailing newline for the final body line, which the
    # terminator search consumed.
    return command[body_start:end] + "\n"


def joined_buildspec_text(template: dict, marker: str) -> str:
    """The literal parts of an `Fn::Join` buildspec, concatenated.

    The image-build projects assemble their buildspec from template parameters, so
    it is a `Fn::Join` rather than a plain string and is not parseable as JSON.
    The parts that matter here are the literal strings; the interspersed `Ref` and
    `Fn::GetAtt` objects are dropped, which is fine because nothing this is used
    for asserts across a substitution boundary.
    """
    for logical_id, resource in template.get("Resources", {}).items():
        if resource.get("Type") != CODEBUILD_PROJECT:
            continue
        spec = resource.get("Properties", {}).get("Source", {}).get("BuildSpec")
        if not isinstance(spec, dict) or "Fn::Join" not in spec:
            continue
        parts = spec["Fn::Join"][1]
        text = "".join(p for p in parts if isinstance(p, str))
        if marker in text:
            return text
    raise AssertionError(
        f"no Fn::Join CodeBuild buildspec in this template contains {marker!r}. "
        f"Resources present: {sorted(template.get('Resources', {}))[:20]}"
    )


def joined_buildspec_document(template: dict, marker: str) -> dict:
    """Decode an `Fn::Join` buildspec into the real parsed document.

    The image-build projects assemble their buildspec from template parameters, so
    the BuildSpec is a `Fn::Join` whose parts alternate between literal JSON text
    and `Ref`/`Fn::GetAtt` objects. Concatenating only the literals leaves invalid
    JSON, which is why `joined_buildspec_text` above hands back raw text and its
    callers have to reason about escaping levels.

    Substituting a placeholder string for each non-literal part makes the
    concatenation valid JSON again, so it decodes to real command strings with no
    escaping guesswork. That matters here because the MCP entrypoint is a shell
    script inside a heredoc inside a command inside that JSON -- three nestings,
    each with its own quoting, and getting the level wrong yields a pattern that
    silently matches nothing.

    The placeholder is deliberately not a plausible value. Nothing this is used for
    asserts across a substitution boundary, and a stand-in that looked like a real
    bucket or ARN would let a test appear to check a resolved value.
    """
    for rebuilt in _joined_buildspec_texts(template):
        if marker not in rebuilt:
            continue
        try:
            return json.loads(rebuilt)
        except json.JSONDecodeError as exc:  # pragma: no cover - guard
            raise AssertionError(
                f"an Fn::Join buildspec containing {marker!r} did not decode as JSON "
                f"once its Ref parts were replaced: {exc}"
            ) from exc
    raise AssertionError(
        f"no Fn::Join CodeBuild buildspec in this template contains {marker!r}.\n"
        f"{_marker_report(marker)}"
    )


def rewrite_helper_path(command: str, replacement: str) -> str:
    """Repoint the buildspec's hard-coded helper path at a per-test path.

    The buildspec writes and invokes `/tmp/ash-s3-sync.py`, a fixed absolute
    path. Executing that verbatim would have every xdist worker -- and every
    other job sharing this machine's /tmp -- write and read one file, so a
    passing test could be reading another worker's helper.

    This is the ONLY edit these tests make to a committed command string, and it
    asserts the substitution actually happened. A silent no-op here would leave
    the test running the real /tmp path while believing it was sandboxed.
    """
    if CONTAINER_HELPER_PATH not in command:
        raise AssertionError(
            f"expected the committed command to reference {CONTAINER_HELPER_PATH!r} "
            f"so it could be redirected to a per-test path, but it does not: "
            f"{command[:200]!r}"
        )
    return command.replace(CONTAINER_HELPER_PATH, replacement)
