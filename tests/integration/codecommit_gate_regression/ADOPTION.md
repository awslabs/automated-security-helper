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

`expected.json` is byte-identical to the standalone original (md5
`533ed34f599cd98d9e6fc36bb5d54234`). Every provenance label, the
`known_defect.expected_to_fail` flag, and the advisory-only demotion of
`validation_summary.*.has_issues` are exactly as written. Nothing was promoted
from `specified` to `measured` here, including the values measured below — see
"Left for the author" at the end.

One file was changed: `assert_case.py` was run through `ruff format` (v0.11.8, the
version pinned in the repository's `.pre-commit-config.yaml`). Whitespace only. The
alternative — leaving it unformatted — was rejected because the repository's
`ruff-format` pre-commit hook would rewrite it on whoever's commit next touched
this tree, attributing the churn to them. Behaviour was verified unchanged after
formatting: `--selftest` still passes all four cases, and `--replay` produces
byte-identical output to the pre-format run.

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

`expected.json` requires `metadata.summary_stats.missing` and/or per-scanner
`scanner_results.<name>.status`, and forbids `validation_summary.*.has_issues`. The
fix reads the **per-scanner status**, via `get_unified_scanner_metrics` — the same
function that computes `summary_stats.missing`, so the two cannot disagree. Reading
the per-scanner status additionally covers `ERROR`, which `summary_stats` cannot
express: it has `passed`/`failed`/`missing`/`skipped` and no error counter.
`tests/unit/interactions/test_fail_on_incomplete_scanners.py` pins both the field
precedence and the immunity to `has_issues`.

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
