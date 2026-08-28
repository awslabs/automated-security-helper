# ASH pull-request gate regression fixture

A matched pair of pull-request-shaped scans — one carrying bandit HIGH findings,
one clean — plus a checker that requires their verdicts to diverge.

## Why this exists

On 2026-08-28, deploy-validation of the CDK `AshCodeCommitGate` target against a
real AWS account found that the gate commented **"ASH scan passed"** on a pull
request containing three bandit findings, two of them HIGH. It then commented
**"ASH scan passed"** on a clean control too, with a byte-identical scanner
table. Both comments looked plausible in isolation. Only the pair showed that the
gate was returning one verdict for every input.

The cause was not the finding logic. In the Lambda environment only 5 of ASH's 10
scanners appeared and all 5 were `MISSING` or `ERROR` — nothing was scanned — yet
ASH exited 0 and the gate's `_verdict()` maps exit 0 to "passed". The same image,
with the same flags, on the same fixture, run locally with all filesystems
writable, reported bandit `FAILED` with 2 HIGH + 1 MEDIUM and exited 2.

So a security gate reported green because its scanners could not run. That is the
worst failure mode available to a gate, and nothing in the codebase would have
caught it: there was no test that asserted a dangerous input produces a blocking
verdict, and no test that asserted a passing verdict was earned by scanners that
actually ran.

This fixture is that test.

## What it asserts

For each case: ASH's exit code, the verdict the gate would derive from it (using
the gate's own mapping, duplicated in `expected.json` so the two cannot drift
apart silently), and — the part with teeth — that every scanner the case depends
on actually ran.

Then, across the two cases: **the verdicts must differ.** This is the assertion
that fails on the observed-broken build. A single case cannot express it. The
clean case passing is not evidence of a working gate, because a gate that passes
everything also passes the clean case.

## The replay: the defect pinned, with nothing installed

`cases/observed-2026-08-28/` holds the actual artifact — both pull-request
comments verbatim, plus the scanner table transcribed off them — and
`assert_case.py --replay` checks one conjunction against it:

> A passing verdict is legitimate only if no scanner is `MISSING` or `ERROR`.

That is evaluable from a `(verdict, scanner-table)` pair, so the replay needs no
AWS, no Docker, no image and no working scanner set. It runs in a bare CI
container, and `run_regression.sh` runs it first, even with no arguments.

It is distinct from the live-scan assertions. Those say *the scanners must have
run*, which only a real scan can show. The replay says *if they did not run, do
not claim green* — which is the property the gate actually violated, and the one
worth guarding forever.

Today it reports **XFAIL** with three violations: both pull requests claimed
"passed" over five faulted scanners, and PR 1 additionally carried findings that
should have blocked. XFAIL exits 0 deliberately, so a known defect does not sit
in CI as a red test that someone eventually mutes.

**It survives the fix.** Post-fix, the same scanner table must produce a
non-passing verdict, at which point the replay reports **XPASS** and exits
non-zero to tell you to set `known_defect.expected_to_fail` to `false`. Do not
delete the case then — flipping the flag turns it into a guard against
re-regression. Only that one value changes; the recorded table and the harness
stay as they are.

## Running it

```sh
./run_regression.sh <image-ref> [workdir]
```

Use the image the gate's Lambda actually runs, so the test measures the artifact
that ships:

```sh
aws ecr list-images --region <region> --repository-name <gate-ecr-repo>
./run_regression.sh <account>.dkr.ecr.<region>.amazonaws.com/<gate-ecr-repo>:lambda-amd64
```

Exit status is 0 only if both cases meet their expectations and the verdicts
diverge. `KEEP_WORKDIR=1` retains the scratch trees.

The replay alone, with no image:

```sh
python3 assert_case.py --replay
```

To check the checker itself:

```sh
python3 assert_case.py --selftest
```

That replays the 2026-08-28 all-`MISSING` payload and requires a rejection,
replays an empty payload and requires a rejection, and replays a legitimately
sharded payload and requires acceptance. Without the third case a checker could
pass the first two by rejecting everything.

The replay assertion was checked the same three ways, by feeding
`--replay --observed <file>` a constructed record each time: the real broken
record (3 violations, XFAIL), a post-fix record with the same faulted table but
an `errored` verdict (accepted, XPASS, exit 1), and a healthy record with no
faults and one `SKIPPED` scanner (accepted, and `SKIPPED` correctly not counted
as a fault). Without the last two, an assertion that rejected every input would
have looked correct on the first.

## If you are writing the fix, key on `summary_stats.missing`

Not on `validation_summary.*.has_issues`. That field looks like the signal for
this and is not. Measured on 2026-08-28, on a run with four scanner tools absent:

```
summary_stats                   -> missing: 4
execution_completion_validation -> expected_count: 1, completed_count: 1,
                                   missing_count: 0, completion_rate: 1.0,
                                   has_issues: false
```

`false`, with four selected scanners that never ran. `expected` counts only
scanners actually *dispatched*, so a `MISSING` scanner never enters the expected
set and therefore cannot register as missing from it. The field under-reports
precisely the condition it appears to report. A fix keyed on it would review well,
pass a test written against the same assumption, and do nothing.

`assert_case.py` treats `has_issues` as an advisory line only, never as a reason a
case fails, and `--selftest` has a dedicated case that fails if it ever becomes
load-bearing.

Worth knowing *why* this was nearly missed, because the shape recurs: the first
run to examine these two fields had `missing: 0`, so they agreed, and agreeing
data cannot tell you whether two signals are interchangeable. It took a second run
with a different scanner set to separate them. If you find yourself offering two
signals as equivalent, the run where they agree is not evidence.

## Two traps worth knowing before you change anything

**`SKIPPED` is not `MISSING`.** `SKIPPED` means a scanner was deliberately not
selected — it is the mechanism sharding uses to exclude scanners. It must keep
exiting 0. `MISSING` means selected but its dependencies were absent. `ERROR`
means it ran and failed. Only the latter two are faults. A checker that required
`skipped == 0` would fail every sharded run, get disabled as noisy, and protect
nothing. `assert_case.py` asserts on `summary_stats.missing` and never on
`skipped`. An early probe of this defect used a bogus scanner name, which produces
`SKIPPED` rather than `MISSING` and was therefore the wrong experiment.

**bandit grades by argument, not by call.** `subprocess.call("ls", shell=True)` on
a *literal* string is LOW, below the default MEDIUM threshold, and would make the
positive control non-actionable — it would exit 0 legitimately and prove nothing
while looking dangerous. Passing a variable is what makes B602 and B605 HIGH. If
you add a case, verify its severities against real output instead of assuming a
dangerous-looking construct is HIGH.

**Read `scanner_results.<name>.status`, not `additional_reports`.** On the
measured vulnerable run `scanner_results.bandit.status` was `FAILED` while
`additional_reports.bandit.source.status` was `PASSED`. A checker reading the
wrong one would accept a failing scan as clean.

Status of that one: observed once, and **not reproduced** on a second run by a
different agent where bandit passed and both fields read `PASSED` — which is
consistent with the two fields meaning different things (per-scanner gate outcome
versus report-source health) and only diverging when a scanner actually fails, but
that explanation is inferred and untested. Recorded as measured-once,
unreproduced. Reading `scanner_results` is correct either way, so nothing here
depends on settling it.

## What this does and does not cover

Covered: the gate's flag set, ASH's exit code, the exit-code-to-verdict mapping,
whether scanners ran, and the specific bandit rules and severities.

**Not covered** — all of it needs a deployed stack, and a green run here does not
imply any of it works: EventBridge delivery of the pull-request event, the
CodeCommit clone over the `codecommit::` transport, `PostCommentForPullRequest`,
the approval-rule vote (`ApprovalGate`, which defaulted to `false` during
validation and was never exercised), and the 900-second / 4 GB `/tmp` ceilings.

The deployed round trip that produced this fixture was: seed a throwaway
CodeCommit repository, branch, open a pull request with
`aws codecommit create-pull-request`, then read
`aws codecommit get-comments-for-pull-request`. Note the seeding used the
CodeCommit API (`put-file`, `create-branch`) rather than git, because
`git-remote-codecommit` was not installed — so the `codecommit::` transport was
exercised only by the Lambda's own clone, never from the operator side.

## Provenance and known gaps

`expected.json` labels every expectation `measured` or `specified`. `measured`
values are quoted from real 2026-08-28 output. `specified` values are the
required behaviour, not a recording — do not promote one to `measured` without
re-running.

Specifically unmeasured: **the clean case has never been observed passing
locally.** Its local run was blocked by the operator's permission system during
validation. Its Lambda run returned "passed", but so did the vulnerable case with
an identical all-`MISSING` table, so that observation confirms nothing. The first
real run of `run_regression.sh` will record it.

Also unverified: *why* the scanners fail in Lambda. The leading hypothesis was
Lambda's read-only root filesystem, but the experiment that would have tested it
was blocked, so it is a hypothesis and is recorded here as one rather than as a
cause. The bar for closing it is reproducing the exact 5-of-10 `MISSING`/`ERROR`
signature under Lambda-like constraints, not merely producing some failure.

`run_regression.sh` has not been executed end to end against a real image — the
docker runs needed to do so were blocked. Its assertion core (`assert_case.py`)
is verified three ways: it passes on the real measured vulnerable output, it
rejects the reconstructed Lambda-observed state on 14 independent grounds, and
its `--selftest` passes. Its repository construction and its fail-closed path
(no `ASH_EXIT` marker produces a loud failure, never a pass) were exercised
directly. The unexercised part is the single `docker run`.

The replay path has no such gap: it is fully exercised, because it needs nothing
that could be blocked. If you only trust one half of this fixture, trust that
half.

Note on the aggregated-results payload used to prove the live-scan checker
rejects the broken state: it is a *reconstruction* from the observed comment
table, not a capture. The real one lived in the Lambda's ephemeral `/tmp` and is
gone. `cases/observed-2026-08-28/observed.json` labels every field's provenance
for the same reason — the scanner statuses are transcribed, the verdict is
quoted, and the exit code is explicitly marked as inferred rather than observed.

## Where this should live

Standalone here so it did not have to be committed while fix lanes were in
flight. It belongs in the ASH repository near the other deployment tests once
the fixes land — `deploy/cdk/test/` holds the unit tests for this stack, but this
is an integration fixture and needs a home that can run docker.
