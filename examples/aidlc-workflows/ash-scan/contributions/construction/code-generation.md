---
target: code-generation
plugin: ash-scan
fragments:
  - anchor: before-step:6
    order: 200
---

## fragment: before-step:6

### ash-scan: Scan the Unit's code with ASH

Before the completion handoff, run a fast security scan of the project from its
root: `ash --mode precommit --no-progress`. Precommit mode runs bandit,
detect-secrets, checkov, cdk-nag, and npm-audit, and writes its reports to
`.ash/ash_output/` in the project.

Act on the exit code:

- 0: record "ASH precommit scan: passed" in the code summary and continue.
- 2: the scan found actionable findings. Read them in
  `.ash/ash_output/reports/ash.summary.md`, fix every finding located in this
  Unit's files, and run the scan again. For a finding that is a false positive
  or an accepted risk, do not change the gate: add an entry under
  `global_settings.suppressions` in the project's ASH configuration, with the
  finding's `path` and `rule_id`, its `line_start` and `line_end` (from
  `.ash/ash_output/reports/ash.flat.json`) so later findings of the same rule
  in the file still count, a `reason` a reviewer would accept, and an `expires`
  date, and list that entry in the code summary so the human sees it at the
  next approval gate.
- 1: the scan did not complete, usually because a scanner's tool is missing.
  Install the missing tools with `ash dependencies install` and rerun. If a
  tool cannot run in this environment (cdk-nag and npm-audit need Node.js, so
  in a project with CloudFormation templates or an npm lockfile but no Node.js
  they are MISSING on every Unit), exclude its scanner with
  `--exclude-scanners` and record the exclusion and its reason in the code
  summary: the summary must say what was not measured. Do not pass
  `--no-fail-on-incomplete-scanners`, and do not continue to the completion
  handoff while the scan still exits 1.
- 3: the project's ASH configuration is invalid. Fix the configuration file
  before continuing; `ash config validate` names the field.

Findings in files this Unit did not touch belong to the intent, not the Unit:
note them in the code summary and leave them for Build and Test.
