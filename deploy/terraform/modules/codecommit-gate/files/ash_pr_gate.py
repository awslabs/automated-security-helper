"""Lambda handler: scan a CodeCommit pull request and comment the result.

Triggered by an EventBridge rule on the `CodeCommit Pull Request State Change`
detail-type, scoped to one repository. The handler clones the pull request's
source branch, runs an ASH scan over it, and posts the outcome back to the pull
request with `PostCommentForPullRequest`.

Three outcomes are distinguished, and keeping them apart is the point of reading
the results file rather than trusting the exit code alone:

*   **pass** - the scan completed and reported no actionable findings.
*   **findings** - the scan completed and reported actionable findings.
*   **error** - the scan did not complete, so nothing is known either way.

An exit code on its own conflates the second and third cases: a crashed scan and
a scan that found real problems both exit non-zero. Reporting "no findings" for a
scan that never ran would be the worst failure this handler could have, so the
presence and parseability of the results file is what separates them.
"""

from __future__ import annotations

import json
import logging
import os
import pathlib
import shutil
import subprocess
import sys

import boto3

LOGGER = logging.getLogger()
LOGGER.setLevel(os.environ.get("LOG_LEVEL", "INFO"))

#: Only /tmp is writable in a Lambda execution environment.
WORK_ROOT = pathlib.Path("/tmp/ash-gate")  # noqa: S108 - the only writable path

RESULTS_FILENAME = "ash_aggregated_results.json"

#: Severities that make a pull request fail. Overridable so a repository can gate
#: on CRITICAL only while still reporting the rest.
DEFAULT_BLOCKING_SEVERITIES = ("critical", "high")

#: The PostCommentForPullRequest API reference documents no maximum for the
#: content field, so this is defensive rather than a documented constraint: a
#: full ASH report can be very large, and a rejected comment would lose the
#: result entirely. The link to the full report survives truncation.
DEFAULT_MAX_COMMENT_CHARS = 10000

TRUE_VALUES = {"1", "true", "yes", "on"}


def _env_list(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return tuple(part.strip().lower() for part in raw.replace(",", " ").split() if part)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        return int(raw)
    except ValueError:
        LOGGER.warning("%s=%r is not an integer; using %d", name, raw, default)
        return default


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name, "").strip().lower()
    if not raw:
        return default
    return raw in TRUE_VALUES


def _run(argv: list[str], cwd: pathlib.Path | None = None) -> subprocess.CompletedProcess:
    """Run a subprocess, capturing output, without raising on a non-zero exit."""
    LOGGER.info("running: %s", " ".join(argv))
    return subprocess.run(  # noqa: S603 - argv is a list, never a shell string
        argv,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )


def parse_event(event: dict) -> dict:
    """Pull the fields this handler needs out of the EventBridge event.

    Field names follow the documented `CodeCommit Pull Request State Change`
    detail shape. Note that `repositoryNames` is a list, not a string, and
    `pullRequestId` is a string, not a number.
    """
    detail = event.get("detail") or {}

    repository_names = detail.get("repositoryNames") or []
    if not repository_names:
        raise ValueError("event detail carries no repositoryNames")

    required = ("pullRequestId", "sourceCommit", "destinationCommit", "sourceReference")
    missing = [key for key in required if not detail.get(key)]
    if missing:
        raise ValueError(f"event detail is missing required fields: {', '.join(missing)}")

    source_reference = detail["sourceReference"]
    branch = source_reference.removeprefix("refs/heads/")

    return {
        "event_name": detail.get("event", ""),
        "repository_name": repository_names[0],
        "pull_request_id": str(detail["pullRequestId"]),
        "source_commit": detail["sourceCommit"],
        "destination_commit": detail["destinationCommit"],
        "source_branch": branch,
        "revision_id": detail.get("revisionId"),
        "title": detail.get("title", ""),
    }


def clone_source(repository_name: str, branch: str, commit: str, region: str) -> pathlib.Path:
    """Clone the pull request's source branch and check out its tip commit.

    Uses git-remote-codecommit (the `codecommit::` remote helper), which signs
    requests with the Lambda role's own credentials. That avoids provisioning
    long-lived Git credentials or an AWS CLI credential helper, neither of which
    belongs in a Lambda image.

    The branch is cloned in full rather than shallow: CodeCommit does not
    reliably permit fetching an arbitrary commit SHA directly, so the SHA has to
    arrive as part of the branch history. That makes clone time proportional to
    repository history, which is the main cost driver for this target.
    """
    if WORK_ROOT.exists():
        # A warm Lambda reuses /tmp across invocations, so a previous scan's tree
        # would otherwise be scanned again alongside this one.
        shutil.rmtree(WORK_ROOT, ignore_errors=True)
    WORK_ROOT.mkdir(parents=True, exist_ok=True)

    source_dir = WORK_ROOT / "src"
    remote = f"codecommit::{region}://{repository_name}"

    result = _run(
        [
            "git",
            "clone",
            "--single-branch",
            "--branch",
            branch,
            remote,
            str(source_dir),
        ]
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr.strip()[-2000:]}")

    checkout = _run(["git", "checkout", "--detach", commit], cwd=source_dir)
    if checkout.returncode != 0:
        raise RuntimeError(f"git checkout {commit} failed: {checkout.stderr.strip()[-2000:]}")

    return source_dir


def run_scan(source_dir: pathlib.Path) -> tuple[int, pathlib.Path, str]:
    """Run ASH over the checked-out tree. Returns exit code, output dir, and log tail."""
    output_dir = WORK_ROOT / "out"
    output_dir.mkdir(parents=True, exist_ok=True)

    argv = [
        "ash",
        "scan",
        "--source-dir",
        str(source_dir),
        "--output-dir",
        str(output_dir),
        # The verdict comes from the results file below, not from this exit code,
        # so findings must not abort the run before the report is written.
        "--no-fail-on-findings",
    ]

    extra = os.environ.get("ASH_SCAN_EXTRA_ARGS", "").strip()
    if extra:
        argv.extend(extra.split())

    result = _run(argv)
    log_tail = (result.stderr or result.stdout or "").strip()[-4000:]
    if result.returncode != 0:
        LOGGER.warning("ash scan exited %d", result.returncode)
    return result.returncode, output_dir, log_tail


def read_severity_counts(output_dir: pathlib.Path) -> dict[str, int] | None:
    """Read per-severity counts from the aggregated results file.

    Returns None when the file is absent or unparseable, which the caller treats
    as an error outcome rather than as a clean scan. ASH's results model permits
    extra fields and has carried severity counts both nested under
    severity_counts and flat on summary_stats, so both shapes are accepted.
    """
    results_path = output_dir / RESULTS_FILENAME
    if not results_path.is_file():
        LOGGER.error("no results file at %s", results_path)
        return None

    try:
        document = json.loads(results_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        LOGGER.error("could not parse %s: %s", results_path, exc)
        return None

    summary = ((document.get("metadata") or {}).get("summary_stats")) or {}
    nested = summary.get("severity_counts") or {}

    counts: dict[str, int] = {}
    for severity in ("critical", "high", "medium", "low", "info", "suppressed"):
        value = nested.get(severity, summary.get(severity))
        if isinstance(value, bool) or not isinstance(value, int):
            continue
        counts[severity] = value

    if not counts:
        LOGGER.error("results file at %s carries no recognizable severity counts", results_path)
        return None

    return counts


def build_comment(
    outcome: str,
    counts: dict[str, int] | None,
    blocking: tuple[str, ...],
    source_commit: str,
    log_tail: str,
    max_chars: int,
) -> str:
    lines = ["## ASH security scan", ""]

    if outcome == "error":
        lines += [
            "**The scan did not complete, so this pull request has not been assessed.**",
            "",
            "This is not a pass. Treat it as an unknown result and check the Lambda logs.",
        ]
        if log_tail:
            lines += ["", "<details><summary>Scan log tail</summary>", "", "```", log_tail, "```", "", "</details>"]
    else:
        verdict = "found blocking findings" if outcome == "findings" else "found no blocking findings"
        lines += [f"Scanned `{source_commit[:12]}` and {verdict}.", ""]

        if counts:
            reported = [s for s in ("critical", "high", "medium", "low", "info") if s in counts]
            if reported:
                lines += ["| Severity | Count |", "| --- | --- |"]
                for severity in reported:
                    marker = " (blocking)" if severity in blocking else ""
                    lines.append(f"| {severity.capitalize()}{marker} | {counts[severity]} |")
                lines.append("")
            if counts.get("suppressed"):
                lines += [f"{counts['suppressed']} finding(s) suppressed by configuration.", ""]

        lines.append(f"Severities that block: {', '.join(blocking)}.")

    comment = "\n".join(lines)
    if len(comment) > max_chars:
        keep = max(0, max_chars - 200)
        comment = comment[:keep] + "\n\n_Comment truncated. See the Lambda logs for the full report._"
    return comment


def handler(event: dict, context: object) -> dict:  # noqa: ARG001 - Lambda signature
    region = os.environ["AWS_REGION"]
    blocking = _env_list("ASH_BLOCKING_SEVERITIES", DEFAULT_BLOCKING_SEVERITIES)
    max_chars = _env_int("ASH_MAX_COMMENT_CHARS", DEFAULT_MAX_COMMENT_CHARS)
    manage_approval = _env_bool("ASH_MANAGE_APPROVAL_STATE")

    parsed = parse_event(event)
    LOGGER.info(
        "pull request %s on %s (%s), source %s",
        parsed["pull_request_id"],
        parsed["repository_name"],
        parsed["event_name"],
        parsed["source_commit"],
    )

    codecommit = boto3.client("codecommit")

    log_tail = ""
    counts: dict[str, int] | None = None
    try:
        source_dir = clone_source(
            parsed["repository_name"], parsed["source_branch"], parsed["source_commit"], region
        )
        _, output_dir, log_tail = run_scan(source_dir)
        counts = read_severity_counts(output_dir)
    except Exception as exc:  # noqa: BLE001 - any failure here is an error outcome
        LOGGER.exception("scan failed")
        log_tail = f"{log_tail}\n{exc}".strip()
        counts = None

    if counts is None:
        outcome = "error"
    elif any(counts.get(severity, 0) > 0 for severity in blocking):
        outcome = "findings"
    else:
        outcome = "pass"

    comment = build_comment(
        outcome, counts, blocking, parsed["source_commit"], log_tail, max_chars
    )

    codecommit.post_comment_for_pull_request(
        pullRequestId=parsed["pull_request_id"],
        repositoryName=parsed["repository_name"],
        beforeCommitId=parsed["destination_commit"],
        afterCommitId=parsed["source_commit"],
        content=comment,
    )
    LOGGER.info("posted %s comment on pull request %s", outcome, parsed["pull_request_id"])

    # Approval state is only ever set to APPROVE on a clean scan. An error
    # outcome deliberately leaves the state untouched rather than revoking, so a
    # transient infrastructure failure cannot look like a security judgment.
    if manage_approval and parsed.get("revision_id"):
        if outcome == "pass":
            try:
                codecommit.update_pull_request_approval_state(
                    pullRequestId=parsed["pull_request_id"],
                    revisionId=parsed["revision_id"],
                    approvalState="APPROVE",
                )
                LOGGER.info("approved pull request %s", parsed["pull_request_id"])
            except Exception:  # noqa: BLE001 - approval is advisory, the comment is the record
                LOGGER.exception("could not set approval state")
        else:
            LOGGER.info("outcome %s: leaving approval state unchanged", outcome)

    return {"outcome": outcome, "severityCounts": counts or {}}


if __name__ == "__main__":  # pragma: no cover - local smoke test
    print(json.dumps(handler(json.load(sys.stdin), None), indent=2))
