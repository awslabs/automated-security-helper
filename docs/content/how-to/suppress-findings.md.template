# Suppress findings

When a finding is a false positive or an accepted risk, suppress it so it stops failing the scan. A suppression keeps the finding in the results, marked suppressed, with your reason. An ignore path drops findings in a path from the results entirely. [Suppressions, ignore paths, and scanner exclusions](../concepts/suppressions.md) explains how they differ and how they interact with the gate and the reports.

To write a suppression you need the finding's rule ID and file. Both are in `.ash/ash_output/reports/ash.flat.json` (`rule_id`, `file_path`, `line_start`) and in the SARIF report `ash.sarif` (`ruleId`).

## Suppress a finding in the config {#config}

Add an entry to `global_settings.suppressions`:

```yaml
global_settings:
  suppressions:
    - path: src/deploy.py
      rule_id: B602
      line_start: 40
      line_end: 48
      reason: The command is a constant; no user input reaches it
      expiration: "2027-01-31"
    - path: tests/**
      rule_id: B101
      reason: assert is how the tests check results
```

<!-- doctest: options of=global_settings.suppressions -->
| Field | Required | Meaning |
|---|---|---|
| `path` | yes | The file, or a pattern, relative to the scanned directory |
| `reason` | yes | Why the finding is suppressed. It appears in the reports. |
| `rule_id` | no | The rule to suppress, as ASH reports it. Without it, the entry suppresses every rule in its path. |
| `line_start`, `line_end` | no | Lines the finding must overlap, inclusive. `line_start` alone runs to the end of the file. |
| `expiration` | no | The date, `YYYY-MM-DD`, from which the suppression stops matching |
| `symbol` | no | Only findings inside this function, class, or method; see [Scope a suppression to a symbol](#symbol) |
| `package_name`, `package_version`, `package_path` | no | Only findings about this dependency, for dependency scanners such as grype and npm-audit |

- Paths match case-sensitively: `tests/**` does not match `Tests/`. In a pattern without `**`, `*` also matches across directory separators, so `src/*.py` matches `src/sub/app.py`; `**` matches any depth. A path that starts with `./` matches nothing, and neither does an empty path, `.` or `./`. A trailing slash is literal, unlike in an ignore path: `tests/` matches no finding, and the scan warns that it matched nothing and gives `tests/**/*`, the pattern for the files under the directory. A bare directory name such as `tests` names only the path `tests` itself and matches nothing inside it. When the directory exists in the scanned directory, `ash config validate` and `ash config lint` warn about either one with that pattern and exit 0. They warn in the same way, saying what to write instead, about a path that starts with `./` (`./src/app.py` is `src/app.py`) and about an empty path or `.`. A path whose leading names match the tree only in another case (`tests/**` against `Tests/`) gets a warning that names the tree's spelling and says that patterns match case-sensitively.
- A file whose name is not valid UTF-8 is reported with each such byte written as `\udcNN` (a latin-1 `secr\xe9t.py` as `secr\udce9t.py`). A `path` matches it written that way, since the `\` of a `\udcNN` escape is part of the name and not a separator, or with `?` for that `\` (`secr?udce9t.py`), or by a glob such as `secr*t.py`. An ignore path matches such a file the same way when ASH lists the files to scan. A UTF-8 file name that spells the same `\udcNN` text reads as the same name, so in a tree that holds both files, both are reported under that name, and a path that matches one matches both.
- `rule_id` is a case-insensitive pattern with no scanner prefix. It matches any scanner that reports that rule ID.
- Quote the `expiration` date. YAML reads an unquoted `2027-01-31` as a date, not a string, and ASH then refuses the whole config (exit 3). `ash config lint` and `ash config get` name the problem.
- A key that is not in the table makes the config invalid (exit 3), and when a known key is close, the error names it: `ruleId` fails with `Unknown key 'ruleId' (did you mean 'rule_id'?)`. The same holds for an ignore path.

To try a suppression before you write it into the file, pass it for one run. In a repository where detect-secrets reports `SECRET-SECRET-KEYWORD` in `app.py`, this run passes:

```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress \
  --config-overrides 'global_settings.suppressions+=[{"path": "app.py", "rule_id": "SECRET-SECRET-KEYWORD", "reason": "Fixture value, not a real password"}]'
```

With `rule_id` misspelled, the same run is refused instead of suppressing every rule in `app.py`:

<!-- doctest: run expect-exit=3 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress \
  --config-overrides 'global_settings.suppressions+=[{"path": "app.py", "ruleId": "SECRET-SECRET-KEYWORD", "reason": "Fixture value, not a real password"}]'
```

### Expiration {#expiration}

On its `expiration` date, by the local clock of the machine that runs the scan (UTC in the container image, which sets `TZ=UTC`), a suppression stops matching, and the finding fails the next scan again. At the start of a scan, ASH logs one warning that lists every suppression and ignore path that has expired, including those whose date is today, and then a warning for the ignore paths and one for the suppressions that expire within the next 30 days. With `--ignore-suppressions`, these warnings leave suppressions out. `ash config lint` reports suppressions that have expired, and `ash config lint --fix` removes them.

An expired suppression no longer applies, so this run fails on the finding and names the entry:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress \
  --config-overrides 'global_settings.suppressions+=[{"path": "app.py", "rule_id": "SECRET-SECRET-KEYWORD", "reason": "Fixture value, not a real password", "expiration": "2020-01-01"}]'
```

```text
The following ignore paths and suppressions have expired and no longer apply:
  - Suppression of rule 'SECRET-SECRET-KEYWORD' for 'app.py' expired on 2020-01-01. Reason: Fixture value, not a real password
Remove them, or move their expiration dates, in your ASH configuration file.
```

### Scope a suppression to a symbol {#symbol}

`symbol` limits a suppression to findings inside one definition in the file, named with dots from the top of the file, such as `Deployer.run_hook`. The name is exact and case-sensitive. A suppression with `symbol` keeps matching when the code around the definition moves, where a line range would not.

```yaml
global_settings:
  suppressions:
    - path: src/deploy.py
      rule_id: B602
      symbol: Deployer.run_hook
      reason: run_hook only runs commands from the deploy manifest
```

ASH finds the definition by parsing the file with tree-sitter, for Python, JavaScript, TypeScript, and Java files. The parsers are in the `symbols` extra, which is not installed by default; without it, a suppression with `symbol` matches nothing and the scan logs a warning that names the extra. The container image includes it.

### Installing the extra {#installing-the-extra}

When the extra is missing, the scan warning and `ash config lint` print a command that installs the extra's packages. The command is read from the metadata of the ASH you run, so it fits that ASH whatever its version or source. It runs the `uv` that ASH depends on through the Python interpreter that runs ASH and installs into that interpreter's environment, so it reaches a virtualenv, a `uv tool install` or `pipx install` environment, and a checkout's `uv sync` environment alike. The hint prints the interpreter's full path where this shows `<python>`:

<!-- doctest: illustrative reason="shows the command the warning prints, with a placeholder for the interpreter path" -->
```bash
<python> -m uv pip install --no-config --python <python> 'tree-sitter>=0.26,<0.27' 'tree-sitter-java>=0.23.5,<0.24' 'tree-sitter-javascript>=0.25,<0.26' 'tree-sitter-python>=0.25,<0.26' 'tree-sitter-typescript>=0.23.2,<0.24'
```

A plain `pip install` of those packages does not do the same: environments made by uv have no pip, so `pip` runs whichever pip comes next on `PATH`, usually another Python's.

You can also reinstall ASH with `[symbols]` added to the source you installed it from. For uvx that is the only way that lasts: uvx rebuilds its cached environment from its own arguments, so an extra installed into it is dropped.

The `symbols` extra is available from the next release, the first after v3.7.1. v3.7.1 and earlier define only `cdk`, and asking one of them for `[symbols]` installs it without the extra, with only a warning. Until that release, install from the `main` branch, as [Install from main](install.md#install-from-main) shows, with `[symbols]` after the package name:

<!-- doctest: illustrative reason="installs ASH from GitHub over the network" -->
```bash
uv tool install --force "automated-security-helper[symbols] @ git+https://github.com/awslabs/automated-security-helper.git@main"
```

`main` moves, so this command also replaces the ASH you run with the newest code. To stay on one version, or to use a checkout, put that source after the first `@` instead: a commit SHA from `main`, or `file:///path/to/checkout`. Keep the `@` and the source. ASH is not published on PyPI, and the PyPI project with ASH's name is unrelated and has no `symbols` extra, so asking for the extra by the bare name installs that project instead.

## Suppress a finding in the source {#inline}

An `ash-ignore` comment on the finding's line suppresses it, and `ash-ignore-next-line` suppresses a finding on the line below:

<!-- doctest: illustrative reason="shows where the comments go; running it would call make deploy" -->
```python
import subprocess

DEPLOY_COMMAND = "make deploy"
subprocess.call(DEPLOY_COMMAND, shell=True)  # ash-ignore: B602 fixed command

# ash-ignore-next-line: B108 the build container's own scratch directory
SCRATCH_DIR = "/tmp/ash-build"
```

- Write the comment with `#` or `//`. Other comment styles, such as `/* */` and `<!-- -->`, are not recognized.
- Name exactly one rule ID, as ASH reports it, for example `B602`, `SECRET-SECRET-KEYWORD`, or `zizmor/unpinned-uses`. It is compared without case but is not a pattern. A comment without a rule ID suppresses nothing.
- The comment must be on the line where the finding starts (or the line above it, for `ash-ignore-next-line`). Scanners report different start lines for the same code; check `line_start` in `ash.flat.json`.
- The text after the rule ID is the reason. It is optional, and the reports show it after `(ASH inline)`.

### The scanners' own comments

Most scanners have their own inline syntax. ASH runs bandit, semgrep, opengrep, checkov, cdk-nag, cfn-nag, and detect-secrets in a way that honors it. For cfn-guard, cfn-lint, gitleaks, and zizmor, ASH turns the tools' own ignore comments off unless an operator source turns them on for that scanner, so a repository cannot hide its own findings that way; use ASH's suppressions instead:

| Scanner | Comment | In ASH's results |
|---|---|---|
| bandit | `# nosec`, `# nosec B602` | Not reported. Set `scanners.bandit.options.ignore_nosec: true` to make bandit ignore these comments. |
| semgrep, opengrep | `# nosemgrep`, `# nosemgrep: <rule-id>` | Reported as suppressed |
| checkov | `# checkov:skip=CKV_AWS_18:reason`, or `checkov: skip:` in a CloudFormation resource's `Metadata` | Reported as suppressed, with checkov's reason |
| cdk-nag | `cdk_nag: rules_to_suppress:` in a resource's `Metadata` | Reported as suppressed, with the reason |
| cfn-guard | `guard: SuppressedRules:` in a resource's `Metadata` | Reported, unless an operator turns the comments on; then not reported |
| cfn-lint | `cfn-lint: config: ignore_checks:` in a resource's `Metadata` | Reported, unless an operator turns the comments on; then not reported |
| cfn-nag | `cfn_nag: rules_to_suppress:` in a resource's `Metadata` | Not reported |
| detect-secrets | `pragma: allowlist secret`, `pragma: allowlist nextline secret` | Not reported. Setting `scan_settings.filters_used` replaces detect-secrets' default filters and turns these comments off. |
| gitleaks | `gitleaks:allow` | Reported, unless an operator turns the comments on; then not reported |
| zizmor | `# zizmor: ignore[<rule>]` | Reported, unless an operator turns the comments on; then not reported |

A finding that is not reported never reaches ASH, so it leaves no trace in any report and `--ignore-suppressions` cannot bring it back.

## Ignore a path {#ignore-paths}

An ignore path drops every finding located in a path:

```yaml
global_settings:
  ignore_paths:
    - path: vendor/**
      reason: Third-party code, scanned upstream
    - path: tests/fixtures/**
      reason: Deliberately vulnerable test inputs
```

`path` and `reason` are required, and paths match the way suppression paths do. The findings an ignore path drops include a dependency scanner's findings about a package installed under it: a `node_modules/` ignore path also drops grype's findings located in `node_modules/<package>/package.json`.

An ignore path can also have an `expiration`, which works the way a suppression's does: on that date the ignore path stops applying, so the files it covered are scanned again and their findings count on the next scan. The same holds for the entries of bandit `excluded_paths`, checkov `skip_path`, and syft `exclude`. This expired ignore path no longer drops the finding in `app.py`:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress \
  --config-overrides 'global_settings.ignore_paths+=[{"path": "app.py", "reason": "Fixture value, not a real password", "expiration": "2020-01-01"}]'
```

A trailing slash names the files under a directory. With a copy of `app.py` in `vendor/`, the ignore path `vendor/` drops the copy's finding, and the suppression from the earlier example covers the original, so the run passes:

```bash
mkdir -p vendor && cp app.py vendor/app.py
ash --source-dir . --scanners detect-secrets --offline --no-progress \
  --config-overrides 'global_settings.ignore_paths+=[{"path": "vendor/", "reason": "Third-party code"}]' \
  --config-overrides 'global_settings.suppressions+=[{"path": "app.py", "rule_id": "SECRET-SECRET-KEYWORD", "reason": "Fixture value, not a real password"}]'
rm -r vendor
```

ASH does not read a `.ashignore` file. It does apply the repository's `.gitignore` and `.ignore` files to the files it hands several scanners; see [Coverage](../reference/coverage.md#what-decides-the-files). Several scanners also have their own exclusion options, such as bandit's `excluded_paths`, checkov's `skip_path`, and semgrep's `exclude`; the [scanner reference](../reference/scanners.md) lists them.

## Find suppressions that no longer match {#unused}

The `unused-suppressions` reporter, on by default, writes `.ash/ash_output/reports/ash.unused-suppressions.json` and `ash.unused-suppressions.md`. They list each entry in `global_settings.suppressions` that matched no finding in the scan, including expired ones. They do not cover ignore paths or inline suppressions.

After a scan, `ash config lint --fix-unused` comments out the entries that the report lists, with the date. When it comments out every entry, it leaves `suppressions: []` above them, so the file still loads; remove the `[]` when you turn an entry back on. A suppression can look unused in one environment and still be needed in another, for example when a scanner whose finding it covers is not installed locally but runs in CI. Check the report before you remove entries.

## Add a suppression while you review findings {#inspect}

`ash inspect findings` opens the last scan's findings in your terminal. Select a finding and press `x` to suppress it: ASH asks for a reason and an optional expiration, and adds an entry with the finding's path and rule ID, and its line as `line_start` and `line_end`, to the config file (the `--config` file, else the config ASH discovers, else a new `.ashrc.yaml` in the current directory). It keeps the comments of a YAML file, except one whose `global_settings` is written inline (`global_settings: {...}`), which it rewrites in full, and it writes a JSON config back as JSON. If the file already has an identical entry, nothing is added, and the status bar says so; an entry for another line, reason, or expiration with the same rule ID and path is added. It does not edit TOML files, or a file that uses `extends` but has no suppressions list of its own.

## See every finding {#ignore-suppressions}

`--ignore-suppressions` reports findings as if no suppression existed, so you can review what the suppressions hide. With the suppression from the earlier example, the finding fails the scan again:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress --ignore-suppressions \
  --config-overrides 'global_settings.suppressions+=[{"path": "app.py", "rule_id": "SECRET-SECRET-KEYWORD", "reason": "Fixture value, not a real password"}]'
```

It lifts config suppressions, ignore paths, `ash-ignore` comments, and cdk-nag's `Metadata` suppressions. Every scanner reads the files under an ignore path, and their findings are reported; to drop only the ignore paths for one run, pass `--config-overrides 'global_settings.ignore_paths=[]'` instead. It does not bring back what a scanner never reported (findings hidden by the scanner's own comments or its exclusion options), and findings that semgrep and checkov report as suppressed stay suppressed. The repository's `.gitignore` and `.ignore` files still apply, and findings in ASH's own output directory stay out of the results. In container mode the flag reaches the scan inside the container and works there as in a local scan.

When an MCP client delivers the config, its suppressions, ignore paths, and scanner exclusions are marked client-supplied in the results; see [Configuration trust model](../concepts/trust-model.md#client-supplied). ASH applies all of them itself, so in a local scan with `--ignore-suppressions` none of them applies, and the findings they would have marked are ordinary findings.
