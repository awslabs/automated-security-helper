"""Lambda handler: scan a CodeCommit pull request and comment the result.

Triggered by an EventBridge rule on the `CodeCommit Pull Request State Change`
detail-type, scoped to one repository. The handler clones the pull request's
source branch, runs an ASH scan over it, and posts the outcome back to the pull
request with `PostCommentForPullRequest`.

The verdict is `ash scan`'s exit code, not a judgment made here:

*   **0 -> pass** - no actionable findings at or above the configured severity.
*   **2 -> findings** - actionable findings at or above it.
*   **anything else -> error** - the scan did not complete, so nothing is known
    either way. ASH returns 1 from ``_compute_exit_code`` when it produced no
    results at all.

Severity counts are read from the results file too, but only to render the comment
table. They are deliberately not compared against a threshold here. ASH routes
that comparison through ``_compute_exit_code``, the same function `ash merge` uses,
so a gate verdict and a scan verdict cannot disagree about identical findings. A
severity table reimplemented in this handler would be another copy of the one that
``automated_security_helper/utils/severity_ladder.py`` exists to consolidate, and
when it drifted this gate would pass pull requests that `ash scan` fails.

Reporting "no findings" for a scan that never ran would be the worst failure this
handler could have, so an unrecognized exit code is reported as unknown rather
than folded into either real outcome.
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

#: Threshold handed to `ash scan --min-severity`, evaluated by ASH; this module
#: never compares against it.
#:
#: A FLOOR on what counts as actionable, so a lower value is a stricter gate --
#: ASH tests `rank(finding) >= rank(min_severity)`, so "low" admits every level
#: and "high" admits only one. Matches ASH's own default for that reason: on a
#: gate, the surprise must run toward a build failing over something unimportant,
#: never toward one passing with findings.
DEFAULT_MIN_SEVERITY = "low"

#: Exit codes `ash scan` uses, via _compute_exit_code.
EXIT_CLEAN = 0
EXIT_FINDINGS = 2

#: The PostCommentForPullRequest API reference documents no maximum for the
#: content field, so this is defensive rather than a documented constraint: a
#: full ASH report can be very large, and a rejected comment would lose the
#: result entirely. The link to the full report survives truncation.
DEFAULT_MAX_COMMENT_CHARS = 10000

TRUE_VALUES = {"1", "true", "yes", "on"}


def _env_str(name: str, default: str) -> str:
    raw = os.environ.get(name, "").strip()
    return raw or default


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


def run_scan(
    source_dir: pathlib.Path, min_severity: str, fail_on_findings: bool
) -> tuple[int, pathlib.Path, str]:
    """Run ASH over the checked-out tree. Returns exit code, output dir, and log tail.

    The threshold is handed to ASH rather than applied afterwards, so the exit code
    that comes back is already the verdict.
    """
    output_dir = WORK_ROOT / "out"
    output_dir.mkdir(parents=True, exist_ok=True)

    argv = [
        "ash",
        "scan",
        "--source-dir",
        str(source_dir),
        "--output-dir",
        str(output_dir),
        "--min-severity",
        min_severity,
        # Passed explicitly rather than left to ASH's default, which falls back to
        # the scan configuration. A base config carrying fail_on_findings: false
        # would otherwise make every pull request pass while findings were still
        # being reported in the comment.
        "--fail-on-findings" if fail_on_findings else "--no-fail-on-findings",
        # Not optional, and not configurable, because this gate can APPROVE.
        #
        # Without it a run where no scanner completed exits 0 -- the same code as a
        # clean scan, since no scanner produced a finding to fail on. That exit 0
        # becomes outcome "pass", and "pass" is the one outcome that calls
        # update_pull_request_approval_state with APPROVE. So an operator who arms
        # ASH_MANAGE_APPROVAL_STATE gets auto-approval of code nothing looked at.
        #
        # That is not hypothetical here. Lambda runs this image on a read-only root
        # filesystem, and ASH's scanners write caches at scan time; deployed without
        # the cache redirection the CDK gate applies, a measured run reported bandit,
        # checkov and semgrep MISSING, opengrep ERROR, and grype PASSED with zero
        # findings. The gate said "passed" over a scan that evaluated almost nothing.
        # See the _scan_env note in deploy/cdk/lib/ash-container-scripts.ts.
        #
        # Hardcoded rather than exposed as an environment variable: a gate whose
        # fail-closed behaviour can be switched off by configuration is a gate whose
        # safety depends on deployment, and the failure is silent when it is wrong.
        "--fail-on-incomplete-scanners",
    ]

    extra = os.environ.get("ASH_SCAN_EXTRA_ARGS", "").strip()
    if extra:
        argv.extend(extra.split())

    result = _run(argv)
    log_tail = (result.stderr or result.stdout or "").strip()[-4000:]
    LOGGER.info("ash scan exited %d", result.returncode)
    return result.returncode, output_dir, log_tail


def read_severity_counts(output_dir: pathlib.Path) -> dict[str, int] | None:
    """Read per-severity counts for the comment table. Display only.

    These counts never decide the outcome — `ash scan`'s exit code does. So None
    here means "no table in the comment", not "error": a scan can legitimately
    exit 0 while this returns None if the report shape changes, and downgrading a
    clean verdict over a missing table would be its own false signal.

    ASH's results model permits extra fields and has carried severity counts both
    nested under severity_counts and flat on summary_stats, so both are accepted.
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
    min_severity: str,
    scan_exit: int,
    source_commit: str,
    log_tail: str,
    max_chars: int,
) -> str:
    lines = ["## ASH security scan", ""]

    if outcome == "error":
        lines += [
            "**The scan did not complete, so this pull request has not been assessed.**",
            "",
            f"This is not a pass. `ash scan` exited {scan_exit}; treat the result as "
            "unknown and check the Lambda logs.",
        ]
        if log_tail:
            lines += ["", "<details><summary>Scan log tail</summary>", "", "```", log_tail, "```", "", "</details>"]
    else:
        verdict = (
            f"found actionable findings at or above {min_severity}"
            if outcome == "findings"
            else f"found no actionable findings at or above {min_severity}"
        )
        lines += [f"Scanned `{source_commit[:12]}` and {verdict}.", ""]

        if counts:
            reported = [s for s in ("critical", "high", "medium", "low", "info") if s in counts]
            if reported:
                lines += ["| Severity | Count |", "| --- | --- |"]
                for severity in reported:
                    lines.append(f"| {severity.capitalize()} | {counts[severity]} |")
                lines.append("")
            if counts.get("suppressed"):
                lines += [f"{counts['suppressed']} finding(s) suppressed by configuration.", ""]

        # The threshold is stated, not applied here: ASH decided the verdict above.
        lines.append(
            f"Threshold: findings ranked at or above `{min_severity}` are "
            "actionable; anything lower is listed but does not fail the gate."
        )

    comment = "\n".join(lines)
    if len(comment) > max_chars:
        keep = max(0, max_chars - 200)
        comment = comment[:keep] + "\n\n_Comment truncated. See the Lambda logs for the full report._"
    return comment


def handler(event: dict, context: object) -> dict:  # noqa: ARG001 - Lambda signature
    region = os.environ["AWS_REGION"]
    min_severity = _env_str("ASH_MIN_SEVERITY", DEFAULT_MIN_SEVERITY)
    fail_on_findings = _env_bool("ASH_FAIL_ON_FINDINGS", default=True)
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
    # Sentinel for "the scan never got far enough to produce an exit code". Not a
    # code ASH uses, so it cannot be mistaken for a real verdict.
    scan_exit = -1
    try:
        source_dir = clone_source(
            parsed["repository_name"], parsed["source_branch"], parsed["source_commit"], region
        )
        scan_exit, output_dir, log_tail = run_scan(source_dir, min_severity, fail_on_findings)
        counts = read_severity_counts(output_dir)
    except Exception as exc:  # noqa: BLE001 - any failure here is an error outcome
        LOGGER.exception("scan failed")
        log_tail = f"{log_tail}\n{exc}".strip()

    # ASH's exit code is the verdict. Note the counts read above are not consulted:
    # comparing them against min_severity here would be a second implementation of
    # a judgment ASH already made, free to drift from it.
    if scan_exit == EXIT_CLEAN:
        outcome = "pass"
    elif scan_exit == EXIT_FINDINGS:
        outcome = "findings"
    else:
        outcome = "error"

    comment = build_comment(
        outcome, counts, min_severity, scan_exit, parsed["source_commit"], log_tail, max_chars
    )

    codecommit.post_comment_for_pull_request(
        pullRequestId=parsed["pull_request_id"],
        repositoryName=parsed["repository_name"],
        beforeCommitId=parsed["destination_commit"],
        afterCommitId=parsed["source_commit"],
        content=comment,
    )
    LOGGER.info("posted %s comment on pull request %s", outcome, parsed["pull_request_id"])

    # APPROVE on a clean scan, REVOKE on anything else. The CDK gate does the same
    # (deploy/cdk/lib/ash-container-scripts.ts), and the two have to agree: an operator
    # choosing an infrastructure flavour is not choosing a security posture.
    #
    # This previously left the state untouched on a non-pass outcome, reasoning that a
    # transient infrastructure failure should not look like a security judgment. The
    # reasoning is real but it points the other way once approvals can already exist. A
    # pull request approved on an earlier clean commit, then pushed to with code that has
    # findings, keeps its approval: the gate declines to withdraw the very approval it
    # granted, on code it has now judged unclean. Leaving a stale APPROVE standing is
    # undetectable to a reviewer reading the pull request, while an over-eager REVOKE is
    # both visible and self-correcting -- the next clean run re-approves.
    #
    # So REVOKE covers "findings" and "error" alike. "error" includes the incomplete-scanner
    # exit that --fail-on-incomplete-scanners produces above, which is exactly the case
    # where an approval must not survive: nothing was scanned, so nothing supports it.
    if manage_approval and parsed.get("revision_id"):
        desired_state = "APPROVE" if outcome == "pass" else "REVOKE"
        try:
            codecommit.update_pull_request_approval_state(
                pullRequestId=parsed["pull_request_id"],
                revisionId=parsed["revision_id"],
                approvalState=desired_state,
            )
            LOGGER.info(
                "set approval state %s on pull request %s (outcome %s)",
                desired_state,
                parsed["pull_request_id"],
                outcome,
            )
        except Exception:  # noqa: BLE001 - approval is advisory, the comment is the record
            LOGGER.exception("could not set approval state to %s", desired_state)

    return {"outcome": outcome, "scanExitCode": scan_exit, "severityCounts": counts or {}}


if __name__ == "__main__":  # pragma: no cover - local smoke test
    print(json.dumps(handler(json.load(sys.stdin), None), indent=2))
