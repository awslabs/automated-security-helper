# Adoption record

This fixture was written standalone, outside the repository, so it did not have to
be committed while the fix lanes were in flight. It landed here alongside the
`fail_on_incomplete_scanners` change, which is the fix its `known_defect` block
tracks.

Kept as a separate file rather than folded into `README.md` or `expected.json`
because those belong to the fixture's author and carry its provenance labels. This
file records what a different person measured on adoption; mixing the two would
make it impossible to tell an author's recording from an adopter's.

## What changed on adoption, and what did not

Every provenance label and the `known_defect.expected_to_fail` flag are exactly as
written. Nothing was promoted from `specified` to `measured` here, including the
values measured below — see "Left for the author" at the end.

Two substantive changes, both to correct guidance that measurement showed was
wrong. Neither touches an expectation, a label, or a flag.

**`fix_must_key_on` no longer says `summary_stats.missing`.** It now requires
iterating per-scanner `scanner_results[*].status` and treating both `ERROR` and
`MISSING` as verdict-affecting. The old guidance was wrong for `ERROR` scanners,
and a fix written to it would have passed the exact case this fixture exists to
close. `README.md` gained the same correction. The advisory-only demotion of
`validation_summary.*.has_issues` is untouched and still load-bearing.

**`--selftest` gained a fifth case:** a scanner in `ERROR` while
`summary_stats.missing` is 0, requiring rejection, and additionally requiring that
the rejection reason mention `ERROR` so it must come from the per-scanner branch
rather than the counter check. The four pre-existing cases are unchanged. Without
this case a `summary_stats`-keyed checker passes the whole selftest, because every
other case has `missing` above zero — the same agreeing-signals blind spot that
produced the wrong guidance in the first place.

`assert_case.py` was also run through `ruff format` (v0.11.8, the version pinned in
the repository's `.pre-commit-config.yaml`). The alternative — leaving it
unformatted — was rejected because the repository's `ruff-format` pre-commit hook
would rewrite it on whoever's commit next touched this tree, attributing the churn
to them. Behaviour was verified unchanged after formatting: `--replay` produced
byte-identical output to the pre-format run.

## Why `summary_stats` is not sufficient — measured here

`ERROR` scanners are absent from **every** `summary_stats` counter. Reproduced
locally with `UV_CACHE_DIR=/dev/null/<name>`, which fails uv tool installs with
"Not a directory (os error 20)":

```
scanner_results: bandit=ERROR  checkov=ERROR  detect-secrets=PASSED
                 cdk-nag/cfn-nag/grype/syft=MISSING  npm-audit/opengrep/semgrep=SKIPPED
summary_stats:   passed=1 failed=0 missing=4 skipped=3   -> 8 of 10 scanners
```

The two `ERROR` scanners are in no counter. Then the discriminating case, with the
four tool-less scanners excluded so `missing` is genuinely 0:

```
scanner_results: bandit=ERROR  checkov=ERROR  (8 SKIPPED)
summary_stats:   passed=0 failed=0 missing=0 skipped=8
ash scan default                        -> exit 0   <- false green, with ERROR
ash scan --fail-on-incomplete-scanners  -> exit 1   <- names both ERROR scanners
```

A gate keyed on `summary_stats.missing` reads 0 there and exits 0. This is the same
mechanism the author measured on a 4-shard pipeline (arm A control: merge exit 2,
`actionable=16`, 10 scanners accounted for; arm B broken: merge exit 0,
`actionable=0`, 8 accounted for), so it is confirmed on two independent
infrastructures by two different mechanisms.

`chmod 500` is not a usable mechanism when the process runs as root — root bypasses
ordinary permission bits and the arm silently becomes a no-op, which reads as a
result and is not one.

`.ash/.ash.yaml` gained an `ignore_paths` entry for `cases/**`. Without it the
repository's own ASH scan reports `cases/vulnerable/src/vulnerable.py`'s bandit
findings against this repository — findings that are the entire point of the file.
Scoped to `cases/` so the harness itself is still scanned.

## Measured on adoption

Container runtime was available here, which it was not for the author, so the one
path the README lists as never executed end to end was executed.

`./run_regression.sh <gate-lambda-image>` — **REGRESSION PAIR: PASS**, exit 0:

| case | ash exit | verdict | assertion |
|---|---|---|---|
| vulnerable | 2 | `failed` | PASS |
| clean | 0 | `passed` | PASS |

Verdicts diverge. Image digest
`sha256:5898cea9c3e298dc8dea5638f86a0ee9c13f37768890807987206776bc8abf07`, which is
the same digest `expected.json` records for the vulnerable case's original
measurement — so this is the same artifact, not a near equivalent. Both cases passed
the `summary_stats.missing == 0` integrity check, so that image does have all ten
scanner tools when run locally with writable filesystems, as the README inferred.

This is the first observation of the **clean** case passing anywhere that means
anything. Its Lambda "passed" was worthless as confirmation because the vulnerable
case returned the same verdict over the same all-`MISSING` table.

The pair was also run against a local source build of the fix, outside any
container, with the harness's flag set. Same result: vulnerable exit 2 / `failed`,
clean exit 0 / `passed`, verdicts diverge — once the four scanners whose tools are
absent on that host were excluded (see below).

## The finding that matters for anyone wiring this into the gate

On a host missing `cdk-nag`, `cfn-nag`, `grype` and `syft`, running the pair with
`--fail-on-incomplete-scanners` **collapses both verdicts to `errored`**:

| case | ash exit | verdict |
|---|---|---|
| vulnerable | 1 | `errored` |
| clean | 1 | `errored` |

The fixture's `cross_case_invariant` fails, and it is right to fail. `errored` for
everything is fail-closed and therefore safe, but it is still one verdict for every
input, which is the shape the fixture exists to catch. Enabling the flag does not
substitute for making the scanners available; it converts a silent wrong answer
into a loud absence of an answer.

Two consequences:

1. Do not enable `fail_on_incomplete_scanners` on the gate until the Lambda can
   actually run its scanners. Fix the environment first, then enable the flag to
   keep it fixed.
2. This is the measurement that justifies the flag defaulting to off. Defaulting it
   on would turn every scan on a tool-poor host into exit 1.

Excluding the four absent scanners with `--exclude-scanners` — which records them
`SKIPPED` rather than `MISSING` — restores the diverging pair with the flag still
on. That is the sharding-safety property the fixture's healthy-record control
asserts, confirmed here through a live scan rather than a replay.

## What the fix keys on

The fix reads the **per-scanner status**, via `get_unified_scanner_metrics`. That is
the same function that computes `summary_stats.missing`, so the corroborating
counter cannot disagree with the gate for `MISSING` — and reading one level
upstream additionally covers `ERROR`, which `summary_stats` structurally cannot
express: it carries `passed`/`failed`/`missing`/`skipped` and no error counter.

`tests/unit/interactions/test_fail_on_incomplete_scanners.py` pins four properties
that a plausible-but-wrong implementation would fail: the `scanner_results` versus
`additional_reports` precedence, immunity to a clean `has_issues` block, the absence
of an error counter on `SummaryStats`, and an `ERROR` scanner firing the gate while
every `summary_stats` counter reads clean. That last one was verified to
discriminate: on the same model, a `summary_stats.missing`-keyed gate finds no
faults and the implemented gate returns `[('bandit', 'ERROR')]`.

## Known gaps preserved

Still unmeasured, and deliberately still labelled that way in `expected.json`:

- *Why* the scanners fail in Lambda. The read-only-root hypothesis is untested. The
  bar for closing it is reproducing the exact 5-of-10 signature under Lambda-like
  constraints, not merely producing some failure.
- Everything needing a deployed stack: EventBridge delivery, the `codecommit::`
  clone, `PostCommentForPullRequest`, the approval vote, and the 900 s / 4 GB
  `/tmp` ceilings. The green run above does not imply any of it works.

Not wired into CI. The live pair needs a container runtime and an image reference,
and `--replay` deliberately exits non-zero on XPASS to prompt a flag flip — both
are decisions about CI topology that belong to whoever owns that, not to an
adopting change. `--selftest` and `--replay` are cheap and need nothing installed,
so they are the obvious first candidates if someone does wire it up.

## Left for the author

The clean case's `provenance` is still `specified` and `known_defect.expected_to_fail`
is still `true`, both untouched on purpose. The clean case now has a real local
observation (above) that would support `measured`; recording it is the author's call
because they own the labels. The `expected_to_fail` flag correctly stays `true`:
the replay reads a historical record of what the broken Lambda did, and the fix
changes ASH's behaviour rather than that record, so the recorded table still shows
`verdict='passed'` over a faulted scanner set and still XFAILs. What would prove the
fix in this fixture is a newly recorded post-fix case, not a flag flip.
