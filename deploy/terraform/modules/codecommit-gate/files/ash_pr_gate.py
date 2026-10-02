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

The scan runs under a rewritten environment; see ``_scan_env``, which is the other
half of that same concern. Lambda gives a container image a read-only root
filesystem and its own PATH, so the scanners ASH shells out to cannot write where
the image points them, and a scan whose tools all failed to start still exits 0.
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

#: Where the gate image recorded the uv tool directory the ASH stage installed
#: into, so ``_scan_env`` can give uv a writable parent without reinstalling the
#: tools. Baked by the ENV block in
#: deploy/terraform/modules/ash-image-pipeline/files/wrapper.Dockerfile.
BAKED_UV_TOOL_DIR_VAR = "ASH_BAKED_UV_TOOL_DIR"

#: Scanner data the image bakes, each paired with the environment variable naming
#: the writable path ``_scan_env`` redirects that scanner to.
#:
#: Both halves are load-bearing and neither is sufficient. The redirect is what
#: lets the scanner write at all on a read-only root filesystem; the seed is what
#: keeps the database and rulesets the image was built to carry reachable through
#: it. Redirecting without seeding aims grype at an empty directory, and grype
#: with no database reports PASSED with zero findings -- a clean verdict over an
#: unscanned tree, which is the worst outcome this gate has.
#:
#: The baked locations are read from the environment rather than written out here
#: because they belong to the image build: ash-image-pipeline's ash_image_target
#: selects which ASH stage is wrapped, and the stages do not agree on HOME.
BAKED_SCANNER_DATA = (
    ("ASH_BAKED_GRYPE_DB_DIR", "GRYPE_DB_CACHE_DIR"),
    ("ASH_BAKED_SEMGREP_RULES_DIR", "SEMGREP_RULES_CACHE_DIR"),
    ("ASH_BAKED_OPENGREP_RULES_DIR", "OPENGREP_RULES_CACHE_DIR"),
)

#: Values ASH itself reads as "offline". Copied from ``is_offline_mode()`` in
#: automated_security_helper/core/constants.py, which is the predicate the
#: scanners consult, so this handler and the scan it launches cannot disagree
#: about whether the run has network access.
OFFLINE_VALUES = {"YES", "TRUE", "1"}

#: Scan options an operator may not set through ASH_SCAN_EXTRA_ARGS. Each one can
#: change this gate's verdict, so the gate decides them and the environment does not.
#:
#: Two kinds are listed together, because they produce the same failure:
#:
#: 1.  Options this gate passes itself, in `run_scan` below. ASH_SCAN_EXTRA_ARGS used
#:     to be appended after the whole argv, and `click` resolves a repeated option to
#:     its LAST occurrence -- so putting --no-fail-on-incomplete-scanners in that
#:     variable turned off the one flag hardcoded precisely so that it could not be
#:     turned off. Measured against the real CLI rather than reasoned about: with the
#:     negation appended, ctx.params["fail_on_incomplete_scanners"] resolves to False.
#:
#: 2.  Options that narrow what gets scanned, or move where the verdict comes from.
#:     These need no repetition to do damage, because the gate never passes them --
#:     and they are the more dangerous half, because --fail-on-incomplete-scanners
#:     covers only scanners that were SELECTED. A scanner left out of the selection is
#:     recorded SKIPPED rather than MISSING, and SKIPPED is on the completeness
#:     allowlist. The help text of --fail-on-incomplete-scanners in
#:     automated_security_helper/cli/scan.py says so, and
#:     automated_security_helper/core/phases/scan_phase.py is where an unselected
#:     scanner is recorded that way.
#:
#:     So `--scanners bandit` switches the completeness gate off more thoroughly than
#:     the negation in (1): checkov, semgrep and cdk-nag are not merely ungated, they
#:     are absent from the severity table this handler comments, and the run exits 0.
#:     Exit 0 is outcome "pass", and "pass" is the one outcome that APPROVEs.
#:
#: Both polarities are listed wherever ASH declares a negation. A redundant
#: --fail-on-incomplete-scanners changes nothing today, but accepting it establishes
#: this variable as a place these values get set, and the next edit to it is a
#: negation nobody re-reviews. "The gate decides these" is also a rule an operator can
#: check by reading; "the gate decides these unless you happen to agree with it" is
#: not.
#:
#: Presentation and diagnostic flags are deliberately absent, so an operator keeps the
#: extra args they have a real use for: --offline, --output-formats and its aliases,
#: --strategy, --cleanup, --inspect, --verbose, --debug, --quiet, --log-level,
#: --progress, --color, --show-summary, --simple, --compact-report. --offline was
#: checked rather than assumed: it does not drop the npm/pnpm/yarn audit scanners, it
#: passes `--offline` through to the tool and keeps going, so those scanners still run
#: and still report a status the completeness gate covers. --ignore-suppressions is
#: absent for the same kind of reason -- it makes suppressed findings actionable, so
#: it can only report more, and its negation is ASH's own default.
#:
#: Every spelling ASH accepts is listed, enumerated from the real click command rather
#: than derived by hand, because a near-miss reads like a closed hole and is not one.
#: `ash scan` sets ignore_unknown_options, so a token this set does not name is
#: collected into ctx.args instead of being refused, and `click` does not accept
#: abbreviated long options -- verified against click 8.3.3 and typer 0.27.2, where
#: --no-fail-on-incomplete leaves the parameter at its default. The --opt=value form
#: is split on the first = in `_is_gate_owned_option`, because `click` accepts it for
#: options that take a value, --min-severity among them.
GATE_OWNED_SCAN_OPTIONS = frozenset(
    {
        # Passed by this gate, so a repeat here would resolve last and win.
        "--source-dir",
        "--output-dir",
        "--min-severity",
        "--fail-on-findings",
        "--no-fail-on-findings",
        "--fail-on-incomplete-scanners",
        "--no-fail-on-incomplete-scanners",
        # Narrow the scanner selection, which is what the completeness gate is scoped
        # to. --mode is here for the same reason and not as a container switch: the
        # 'precommit' preset replaces the selection with a fixed list of fast
        # scanners.
        "--scanners",
        "--exclude-scanners",
        "--python-only",
        "--python-based-scanners-only",
        "--python-based-plugins-only",
        "--full",
        "--all-enabled-scanners",
        "--all-enabled-plugins",
        "--mode",
        # One shard of a split scan runs a disjoint subset of the scanners and records
        # the others as excluded. Sharding is recombinable by `ash merge`; this gate
        # does not merge, so a shard here is just a partial scan reporting itself as a
        # whole one.
        "--shard-index",
        "--shard-count",
        # Replace the configuration that the selection and the thresholds come from. A
        # config file that disables every scanner is the same hole as --scanners with
        # one name, and --config-overrides reaches the same settings key by key.
        "--config",
        "--config-overrides",
        # Skip the scan phase, or answer from a results file rather than from a scan.
        # --use-existing fails closed today only because `clone_source` clears
        # WORK_ROOT on every invocation, so the file it would read cannot exist -- an
        # accident of a cleanup that is there for an unrelated reason.
        "--phases",
        "--use-existing",
        "--no-use-existing",
        # Filter the findings down to a git diff before the exit code is computed, so
        # findings elsewhere in the tree stop counting. The gate clones full branch
        # history, so --base-ref has real refs to point at.
        "--changed-files-only",
        "--base-ref",
    }
)

#: Short aliases of the options above, matched by PREFIX rather than by equality.
#:
#: `click` accepts a short option's value attached with no separator, which the exact
#: match used for the long spellings cannot see: `-c/tmp/none.yaml` resolves --config
#: to /tmp/none.yaml, and splitting that token on = leaves it whole. Measured against
#: the real CLI, not assumed.
#:
#: -c is the only short alias any refused option has. The others ASH declares belong
#: to options that are not refused, and no ASH option spelling other than --config's
#: begins with the two characters "-c" -- so the prefix rule has nothing to collide
#: with, and a long option is unaffected because "--config" does not start with "-c".
GATE_OWNED_SHORT_OPTIONS = frozenset({"-c"})


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


def _run(
    argv: list[str],
    cwd: pathlib.Path | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess:
    """Run a subprocess, capturing output, without raising on a non-zero exit.

    ``env=None`` inherits this process's environment, which is what the git calls
    want. The scan passes a rewritten one; see ``_scan_env``.
    """
    LOGGER.info("running: %s", " ".join(argv))
    return subprocess.run(  # noqa: S603 - argv is a list, never a shell string
        argv,
        cwd=str(cwd) if cwd else None,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


def _seed_from_baked(
    baked: pathlib.Path, writable: pathlib.Path, *, directories_only: bool
) -> None:
    """Make the image's baked content reachable through a writable directory.

    DIRECTORIES ARE SYMLINKED, FILES ARE COPIED. A directory holds content the
    scanner only reads -- grype's vulnerability database lands in a versioned
    subdirectory -- so a link costs no bytes of the function's ephemeral storage,
    which the clone and ASH's output already draw on. A file is the thing a
    scanner is most likely to rewrite in place, and a link to one aims that write
    at the read-only root filesystem: it would look seeded and fail at scan time.
    Copying gives the scan its own writable copy of the small files (the semgrep
    and opengrep rulesets are these) while the bulk stays linked.

    ``directories_only`` skips files entirely instead of copying them, and it
    exists for the uv tool directory. uv's baked tree also holds uv's own ``.lock``
    and a ``.gitignore``; uv needs to create its lock inside UV_TOOL_DIR, and a
    copy of the baked one would be a stale lock rather than an absent one. The
    first version of the CDK flavor of this fix linked ``.lock`` and three scanners
    still ERRORed -- see the ``_scan_env`` note in
    deploy/cdk/lib/ash-container-scripts.ts. Do not turn this off for the tool dir.

    Idempotent: an entry already present is left alone, so a warm invocation
    re-uses what a cold one seeded.
    """
    for entry in sorted(baked.iterdir()):
        link = writable / entry.name
        if link.exists() or link.is_symlink():
            continue
        if entry.is_dir():
            link.symlink_to(entry, target_is_directory=True)
        elif not directories_only and entry.is_file():
            shutil.copy2(entry, link)


def _is_offline_scan() -> bool:
    """Whether this scan has no network, so an empty cache cannot refill itself.

    The distinction decides whether an unreachable baked cache is fatal. Online,
    grype can still fetch a database and the scan is slow rather than blind.
    Offline it cannot, so a zero-finding report says nothing about the code.
    """
    return os.environ.get("ASH_OFFLINE", "NO").strip().upper() in OFFLINE_VALUES


def _scan_env() -> dict[str, str]:
    """The environment `ash scan` runs under. Passing it is not optional.

    WHAT GOES WRONG WITHOUT IT, MEASURED ON THE CDK FLAVOR OF THIS SAME IMAGE
    ------------------------------------------------------------------------
    Lambda runs a container image with a read-only root filesystem -- only /tmp is
    writable -- and replaces PATH with its own. ASH's scanner toolchain writes at
    scan time, and every path the image points it at is on that read-only layer:
    the three caches the base image sets (GRYPE_DB_CACHE_DIR,
    SEMGREP_RULES_CACHE_DIR, OPENGREP_RULES_CACHE_DIR, all under /deps), HOME, and
    uv's cache and tool directory. A real scan of a three-file repository in that
    state reported bandit, checkov and semgrep MISSING, opengrep ERROR, and grype
    PASSED with zero findings, and the gate reported "passed". The measurement is
    recorded next to the CDK gate handler in
    deploy/cdk/lib/ash-container-scripts.ts; this handler had no equivalent, which
    is the defect. It fails visibly rather than silently here only because
    ``--fail-on-incomplete-scanners`` is hardcoded in ``run_scan`` -- that flag is
    what turns a scan of nothing into an error outcome, and it is the reason this
    was a broken deployment target rather than a gate quietly approving.

    Redirecting alone is not the fix. The baked uv tools, vulnerability database
    and rulesets are all on the read-only layer, so a redirect to a fresh /tmp
    directory points every scanner at nothing: uv reinstalls from PyPI, which
    works only where the function has egress, and an image built with
    ash_offline_mode cannot reach the database its own build asserted is
    non-empty. So each redirected path is seeded from the location the image
    recorded; see ``_seed_from_baked`` and BAKED_SCANNER_DATA.

    PATH is restored from ASH_IMAGE_PATH when the image recorded one, and left
    alone when it did not, so running this handler outside the image behaves
    normally.
    """
    env = dict(os.environ)
    home = WORK_ROOT / "home"
    cache = home / "cache"
    tool_dir = home / "uv-tools"
    data_home = home / "share"

    # HOME is assigned last on purpose: several tools derive their own paths from
    # it, and the image's HOME is on the read-only layer.
    env["XDG_CACHE_HOME"] = str(cache)
    env["XDG_DATA_HOME"] = str(data_home)
    env["UV_CACHE_DIR"] = str(cache / "uv")
    env["UV_TOOL_DIR"] = str(tool_dir)
    env["GRYPE_DB_CACHE_DIR"] = str(cache / "grype")
    env["SEMGREP_RULES_CACHE_DIR"] = str(cache / "semgrep")
    env["OPENGREP_RULES_CACHE_DIR"] = str(cache / "opengrep")
    env["HOME"] = str(home)

    image_path = os.environ.get("ASH_IMAGE_PATH")
    if image_path:
        env["PATH"] = image_path

    for path in (cache, tool_dir, data_home):
        path.mkdir(parents=True, exist_ok=True)

    baked_tools = os.environ.get(BAKED_UV_TOOL_DIR_VAR, "").strip()
    if baked_tools and pathlib.Path(baked_tools).is_dir():
        _seed_from_baked(pathlib.Path(baked_tools), tool_dir, directories_only=True)
    else:
        # Not fatal: the affected scanners degrade to MISSING, which
        # --fail-on-incomplete-scanners turns into a visible error outcome.
        LOGGER.warning(
            "%s names no directory, so uv's baked tools were not seeded; the "
            "scanners uv provides will reinstall or report MISSING",
            BAKED_UV_TOOL_DIR_VAR,
        )

    unreachable: list[str] = []
    for baked_var, cache_var in BAKED_SCANNER_DATA:
        writable = pathlib.Path(env[cache_var])
        writable.mkdir(parents=True, exist_ok=True)
        baked = os.environ.get(baked_var, "").strip()
        if baked and pathlib.Path(baked).is_dir():
            _seed_from_baked(pathlib.Path(baked), writable, directories_only=False)
        if not any(writable.iterdir()):
            unreachable.append(f"{cache_var} (from {baked_var}={baked or '<unset>'})")

    # Checked on the OUTCOME rather than on the inputs, deliberately. An assertion
    # that re-tested whether the variables are set would be silenced by whatever
    # silenced the seeding, and the property that matters is that the scan can
    # read a database, not that a variable exists. The root Dockerfile's own
    # offline assertion is written the same way and says why: "Deliberately checks
    # the ARTIFACTS rather than re-testing OFFLINE".
    if unreachable:
        if _is_offline_scan():
            raise RuntimeError(
                "ASH_OFFLINE is set, so this scan cannot fetch what it is missing, "
                "and these redirected scanner caches are empty after seeding: "
                + "; ".join(unreachable)
                + ". Refusing to scan rather than reporting no findings from an "
                "empty vulnerability database and no rulesets. Build the gate's "
                "base image with ash_offline_mode = true so the database and "
                "rulesets are baked in, or set ash_offline_mode = false so the "
                "scanners may fetch them."
            )
        LOGGER.warning(
            "these redirected scanner caches are empty after seeding and will be "
            "fetched at scan time: %s",
            "; ".join(unreachable),
        )

    return env


def _is_gate_owned_option(token: str) -> bool:
    """Whether *token* sets one of the options this gate reserves.

    Long spellings match exactly on the part before the first =, so an option that
    merely shares a prefix with a reserved one is not refused: --min-severity-foo,
    --output-directory and --source-dir-extra each split to themselves and none of
    them is in the set. Short spellings match by prefix, because `click` lets a short
    option's value be attached with no separator; see GATE_OWNED_SHORT_OPTIONS.

    A reserved spelling appearing as another option's VALUE is refused too, since this
    reads tokens rather than parsing them. That errs toward refusing a scan, which on a
    gate is the direction to err in, and no ASH option takes a value that looks like an
    option name.
    """
    if token.split("=", 1)[0] in GATE_OWNED_SCAN_OPTIONS:
        return True
    return any(token.startswith(short) for short in GATE_OWNED_SHORT_OPTIONS)


def _reject_gate_owned_options(tokens: list[str]) -> None:
    """Refuse extra args that set an option this gate owns.

    Refusal rather than dropping the token with a warning. Dropping leaves the gate
    running in a configuration nobody chose, with the operator's intent discarded and
    nothing in the pull request saying so, which looks exactly like a gate doing what
    its deployment asked. Raising is read by `handler` as outcome "error", which
    comments that the pull request has not been assessed and REVOKEs any standing
    approval -- fail-closed, and visible where the decision is read.

    The cost is deliberate: a deployment that has been keeping a noisy gate green
    through this variable stops scanning until someone removes the token. That is the
    point. It was already not gating what it claimed to.
    """
    offending = [token for token in tokens if _is_gate_owned_option(token)]
    if not offending:
        return

    reserved = sorted(GATE_OWNED_SCAN_OPTIONS | GATE_OWNED_SHORT_OPTIONS)
    message = (
        f"ASH_SCAN_EXTRA_ARGS sets options this gate reserves: {' '.join(offending)}. "
        "Refusing to scan rather than letting the environment decide this gate's "
        "verdict: these either repeat an option the gate passes -- which resolves to "
        "its last occurrence -- or narrow what gets scanned, which switches off the "
        "completeness check without switching off the gate's report of a pass. "
        f"Reserved: {' '.join(reserved)}."
    )
    LOGGER.error(message)
    raise RuntimeError(message)


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
        raise ValueError(
            f"event detail is missing required fields: {', '.join(missing)}"
        )

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


def clone_source(
    repository_name: str, branch: str, commit: str, region: str
) -> pathlib.Path:
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
        raise RuntimeError(
            f"git checkout {commit} failed: {checkout.stderr.strip()[-2000:]}"
        )

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

    # Held apart from the operator's extra args below and emitted after them, so that
    # last-occurrence-wins resolution lands on the gate's value.
    #
    # GATE_OWNED_SCAN_OPTIONS is a superset of the spellings in this list, and not a
    # mirror of it: most of what it refuses are options the gate never passes but which
    # narrow the scan, and the ordering below does nothing about those. For them the
    # refusal is the only defence, which is why it refuses rather than warns.
    gate_owned = [
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
        #
        # Hardcoding it here is not by itself enough to make that true, which is what
        # _reject_gate_owned_options and the ordering below are for. This flag was
        # hardcoded and still negatable, because ASH_SCAN_EXTRA_ARGS was appended
        # after it and the CLI resolves a repeated option to its last occurrence.
        "--fail-on-incomplete-scanners",
    ]

    extra = os.environ.get("ASH_SCAN_EXTRA_ARGS", "").strip()
    extra_tokens = extra.split() if extra else []
    _reject_gate_owned_options(extra_tokens)

    # Extras first, the gate's own options last. The refusal above is the guard; this
    # ordering is what still holds if the guard is ever incomplete, since a spelling it
    # does not know about then resolves before the gate's value rather than after it.
    argv = ["ash", "scan", *extra_tokens, *gate_owned]

    # env= is load-bearing, not hygiene: without it the child inherits Lambda's
    # PATH merged with the image's ENVs, which point every scanner's cache at the
    # read-only root filesystem. See _scan_env. It raises when an offline scan's
    # caches are unreachable, which handler reads as outcome "error".
    result = _run(argv, env=_scan_env())
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
        LOGGER.error(
            "results file at %s carries no recognizable severity counts", results_path
        )
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
            (
                f"This is not a pass. `ash scan` exited {scan_exit}; treat the result as "
                "unknown and check the Lambda logs."
            ),
        ]
        if log_tail:
            lines += [
                "",
                "<details><summary>Scan log tail</summary>",
                "",
                "```",
                log_tail,
                "```",
                "",
                "</details>",
            ]
    else:
        verdict = (
            f"found actionable findings at or above {min_severity}"
            if outcome == "findings"
            else f"found no actionable findings at or above {min_severity}"
        )
        lines += [f"Scanned `{source_commit[:12]}` and {verdict}.", ""]

        if counts:
            reported = [
                s for s in ("critical", "high", "medium", "low", "info") if s in counts
            ]
            if reported:
                lines += ["| Severity | Count |", "| --- | --- |"]
                for severity in reported:
                    lines.append(f"| {severity.capitalize()} | {counts[severity]} |")
                lines.append("")
            if counts.get("suppressed"):
                lines += [
                    f"{counts['suppressed']} finding(s) suppressed by configuration.",
                    "",
                ]

        # The threshold is stated, not applied here: ASH decided the verdict above.
        lines.append(
            f"Threshold: findings ranked at or above `{min_severity}` are "
            "actionable; anything lower is listed but does not fail the gate."
        )

    comment = "\n".join(lines)
    if len(comment) > max_chars:
        keep = max(0, max_chars - 200)
        comment = (
            comment[:keep]
            + "\n\n_Comment truncated. See the Lambda logs for the full report._"
        )
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
            parsed["repository_name"],
            parsed["source_branch"],
            parsed["source_commit"],
            region,
        )
        scan_exit, output_dir, log_tail = run_scan(
            source_dir, min_severity, fail_on_findings
        )
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
        outcome,
        counts,
        min_severity,
        scan_exit,
        parsed["source_commit"],
        log_tail,
        max_chars,
    )

    codecommit.post_comment_for_pull_request(
        pullRequestId=parsed["pull_request_id"],
        repositoryName=parsed["repository_name"],
        beforeCommitId=parsed["destination_commit"],
        afterCommitId=parsed["source_commit"],
        content=comment,
    )
    LOGGER.info(
        "posted %s comment on pull request %s", outcome, parsed["pull_request_id"]
    )

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

    return {
        "outcome": outcome,
        "scanExitCode": scan_exit,
        "severityCounts": counts or {},
    }


if __name__ == "__main__":  # pragma: no cover - local smoke test
    print(json.dumps(handler(json.load(sys.stdin), None), indent=2))
