# ASH for security reviewers

You read pull requests and answer for what merges. For that, a scanner's
verdict is only useful if you know what it measured, what it skipped, and who
can change the rules. This page covers the three things a reviewer leans on:
an exit code that means what it says, exceptions that live in the diff, and
reports where the review happens.

## A verdict you can trust

A scan's exit code is its verdict, and the order of the checks is designed so
that a broken scan cannot pass as a clean one
([What decides the exit code](../how-to/set-the-gate.md#order)):

- 2 means unsuppressed findings at or above the severity threshold.
- 1 means the scan did not produce a result you can rely on: a selected
  scanner was MISSING or ended in ERROR, no scanner ran, a converter failed,
  or a vulnerability database is past its age bound.
- 0 means the scan completed and nothing actionable remains.

The 1 comes from `fail_on_incomplete_scanners`, which is on by default and
takes precedence over the findings gate when both would fail: a partial scan's
findings are real, but its clean bill of health is not. A scanner that was
deliberately left out with `--exclude-scanners` is recorded SKIPPED and does
not trip it, so the right response to a tool you cannot run is to exclude it
visibly, not to pass `--no-fail-on-incomplete-scanners`
([Incomplete scans](../how-to/set-the-gate.md#incomplete)).

The thresholds are yours to set: a global `severity_threshold`, per-scanner
overrides, and `--min-severity` as a scan-wide floor
([Severity thresholds](../how-to/set-the-gate.md#thresholds)).

## Exceptions are code

A suppression keeps the finding in the results, marked suppressed, with the
author's reason, and it lives in the repository's ASH configuration, so it
arrives in a pull request like any other change:

<!-- doctest: config kind=ash -->
```yaml
global_settings:
  suppressions:
    - path: src/deploy.py
      rule_id: B602
      line_start: 40
      line_end: 48
      reason: The command is a constant; no user input reaches it
      expires: "2027-01-31"
```

Review the entry the way you review code. Is the `path` as narrow as it could
be, or does a pattern cover files the reason does not? Does the `reason` state
a fact you can check, or restate the rule? Is there an `expires` date, so the
question is re-asked instead of settled forever? On its date the suppression
stops matching and the finding fails the next scan; ASH warns about
suppressions expiring within 30 days, and `ash config lint --fix` removes the
expired ones ([Expiration](../how-to/suppress-findings.md#expiration)).

Two companion tools keep the ledger honest. The `unused-suppressions` reporter,
on by default, lists entries that matched nothing in the scan, so dead
exceptions get removed rather than accumulating
([Find suppressions that no longer match](../how-to/suppress-findings.md#unused)).
And `--ignore-suppressions` reports findings as if no suppression existed, for
an audit of what the current set hides:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress --ignore-suppressions \
  --config-overrides 'global_settings.suppressions+=[{"path": "app.py", "rule_id": "SECRET-SECRET-KEYWORD", "reason": "Fixture value, not a real password"}]'
```

The scanners' own inline comments are a different matter: a bandit `# nosec` or
a detect-secrets `pragma: allowlist secret` keeps the finding from ever
reaching ASH, so it leaves no trace in any report.
[The scanners' own comments](../how-to/suppress-findings.md#inline) lists which
comments ASH honors, which it reports as suppressed, and which it turns off so
a repository cannot hide its own findings that way.

## Who can change the gate

The settings above live in configuration, and in a scan of a repository, that
repository's own config file is honored: a pull request can raise the
threshold, add suppressions, or set `fail_on_findings: false`, and none of it
is marked in the results. For repositories whose authors you do not implicitly
trust with the gate, pass your own config with `--config` from a file they
cannot change, and pass the gate flags explicitly
([Who can change the gate](../how-to/set-the-gate.md#who)). The full rollout of
that pattern, with a test that proves the repository's config no longer
changes the verdict, is in
[Roll out across repositories](../getting-started/platform-teams.md).

## The review surface

On GitHub, the [reusable workflows](../getting-started/ci.md) put the results
where the review happens: the scanner summary as a pull request comment, each
actionable finding as a failed test in a check run, and `ash.ghas.sarif`
uploaded to code scanning, which annotates the changed lines and compares the
pull request against the analysis of its base branch
([Upload results to code scanning](../how-to/export-reports.md#github)). On
GitLab, `ash.gl-sast-report.json` feeds the merge request security widget
([GitLab](../how-to/export-reports.md#gitlab)). Suppressed findings stay
visible in `ash.sarif`, `ash.csv`, and `ash.flat.json` with their reasons, so
the exception ledger is part of the record you review.

Two options sharpen what a pull request is judged on:

- `--changed-files-only` drops findings in files the change did not touch, so
  the gate counts the pull request's own debt and not the backlog. Suppressed
  findings and the full reports still record everything
  ([Gate on the files a change touches](../how-to/scale-large-repos.md#changed-files)).
- A scan of `main` after each merge keeps the baseline current, which is what
  code scanning diffs pull requests against
  ([Add ASH to CI](../getting-started/ci.md)).

For comparing two scans directly, `diff_scan_results` over the
[MCP server](../reference/mcp-tools.md#diff_scan_results) returns the resolved,
new, and severity-changed findings between two results files.
