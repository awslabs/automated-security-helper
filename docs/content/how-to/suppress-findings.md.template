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
      expires: "2027-01-31"
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
| `expires` | no | The date, `YYYY-MM-DD`, from which the suppression stops matching. `expiration` is a deprecated alias, removed in ASH v4. |
| `symbol` | no | Only findings inside this function, class, or method; see [Scope a suppression to a symbol](#symbol) |
| `package_name`, `package_version`, `package_path` | no | Only findings about this dependency, for dependency scanners such as grype and npm-audit |
| `image` | no | Only findings inside a container image whose submitted reference or resolved digest matches this case-insensitive glob; see [Scan container images](scan-container-images.md#findings-identity-and-suppressions). A finding that is not inside an image never matches |
| `resource_id` | no | Only findings about this resource, for the scanners that name one: cdk-nag (the construct path) and checkov (for Terraform, a Terraform plan, CloudFormation and Kubernetes; the name checkov gives it, such as `aws_db_instance.this`, `module.db.aws_db_instance.this` or `AWS::S3::Bucket.Bucket`). A finding with no resource never matches |

- Paths match case-sensitively: `tests/**` does not match `Tests/`. In a pattern without `**`, `*` also matches across directory separators, so `src/*.py` matches `src/sub/app.py`; `**` matches any depth. A path that starts with `./` matches nothing, and neither does an empty path, `.` or `./`. A path with no glob character names a file and the directory of that name: `tests` and `tests/` both match every finding below `tests/`, and the bare `tests` also matches a file named `tests`. Both are anchored at the top of the scanned directory, so neither matches anything in `pkg/tests/`; write `**/tests/**` for a `tests` directory at any depth. `ash config validate` and `ash config lint` warn, saying what to write instead, about a path that starts with `./` (`./src/app.py` is `src/app.py`) and about an empty path or `.`, and exit 0. A path whose leading names match the tree only in another case (`tests/**` against `Tests/`) gets a warning that names the tree's spelling and says that patterns match case-sensitively.
- Upgrading changes what an existing entry matches. Before the bare-directory rule (issue #894), a glob-free `tests` matched only a file of exactly that name, `tests/` matched no finding at all, and `ash config validate` flagged both as matching nothing; both now cover every finding below `tests/`, and that warning is gone. A bare-name entry kept from an earlier release therefore widens, silently, into a whole-directory suppression. When you upgrade, check each suppression and ignore path whose `path` has no glob character, once, and name a file or add a glob where the directory was not meant.
- A file whose name is not valid UTF-8 is reported with each such byte written as `\udcNN` (a latin-1 `secr\xe9t.py` as `secr\udce9t.py`). A `path` matches it written that way, since the `\` of a `\udcNN` escape is part of the name and not a separator, or with `?` for that `\` (`secr?udce9t.py`), or by a glob such as `secr*t.py`. An ignore path matches such a file the same way when ASH lists the files to scan. A UTF-8 file name that spells the same `\udcNN` text reads as the same name, so in a tree that holds both files, both are reported under that name, and a path that matches one matches both.
- `rule_id` is a case-insensitive pattern with no scanner prefix. It matches any scanner that reports that rule ID.
- Quote the `expires` date. YAML reads an unquoted `2027-01-31` as a date, not a string, and ASH then refuses the whole config (exit 3). `ash config lint` and `ash config get` name the problem.
- A key that is not in the table warns at config load, and when a known key is close, the warning names it: `ruleId` warns with `Unknown key 'ruleId' (did you mean 'rule_id'?)`, and the entry suppresses nothing until the key is fixed, so a typo can only narrow what is suppressed. Set `fail_on_unknown_keys: true` to make it an error (exit 3) instead; ASH v4 makes that the default. The same holds for an ignore path.

To try a suppression before you write it into the file, pass it for one run. In a repository where detect-secrets reports `SECRET-SECRET-KEYWORD` in `app.py`, this run passes:

```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress \
  --config-overrides 'global_settings.suppressions+=[{"path": "app.py", "rule_id": "SECRET-SECRET-KEYWORD", "reason": "Fixture value, not a real password"}]'
```

With `rule_id` misspelled, the entry suppresses nothing instead of suppressing every rule in `app.py`: the run warns, naming the key, and fails on the finding the entry was meant to suppress (exit 2). Set `fail_on_unknown_keys: true` to refuse the config outright (exit 3); ASH v4 makes that the default.

### Suppress a finding in a harvested lockfile {#harvested}

A finding can sit in a file the scan materialized rather than one in your tree:
the [sdist lockfile harvest](../docs/plugins/builtin/syft.md#the-sdist-lockfile-harvest)
writes a compiled dependency's embedded lockfiles into the converted target at
`sdist-locks/<package>/<version>/<lockfile>`, and grype and trivy report
advisories against them. Such a finding is fixed by upgrading the parent
package, never by an edit, so while no fixed release exists the honest
disposition is a time-boxed suppression whose `path` globs over the harvest
layout -- the version segment is a `*` so the entry survives a version bump,
and `expires` plus the pinned package version force the revisit:

```yaml
global_settings:
  suppressions:
    - rule_id: "GHSA-2mjx-qc3c-rqvc"
      path: "**/sdist-locks/polars-runtime-32/*/Cargo.lock"
      package_name: "rustls"
      package_version: "0.23.43"
      expires: "2026-12-27"
      reason: >-
        rustls 0.23.43 is statically linked into the polars-runtime-32 wheel;
        only a polars release built against rustls 0.23.45 or later removes it.
```

ASH's own `.ash.yaml` carries the worked set of these entries (the rustls
advisories in polars' harvested `Cargo.lock`), one per scanner spelling of the
same GHSA id, each with the evidence in its reason.

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress \
  --config-overrides 'global_settings.suppressions+=[{"path": "app.py", "ruleId": "SECRET-SECRET-KEYWORD", "reason": "Fixture value, not a real password"}]'
```

### Expiration {#expiration}

On its `expires` date, by the local clock of the machine that runs the scan (UTC in the container image, which sets `TZ=UTC`), a suppression stops matching, and the finding fails the next scan again. `expires` is the canonical spelling of the field; `expiration` is accepted as a deprecated alias when a config is read, and the alias is removed in ASH v4. At the start of a scan, ASH logs one warning that lists every suppression and ignore path that has expired, including those whose date is today, and then a warning for the ignore paths and one for the suppressions that expire within the next 30 days. With `--ignore-suppressions`, these warnings leave suppressions out. `ash config lint` reports suppressions that have expired, and `ash config lint --fix` removes them.

An expired suppression no longer applies, so this run fails on the finding and names the entry:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress \
  --config-overrides 'global_settings.suppressions+=[{"path": "app.py", "rule_id": "SECRET-SECRET-KEYWORD", "reason": "Fixture value, not a real password", "expires": "2020-01-01"}]'
```

```text
The following ignore paths and suppressions have expired and no longer apply:
  - Suppression of rule 'SECRET-SECRET-KEYWORD' for 'app.py' expired on 2020-01-01. Reason: Fixture value, not a real password
Remove them, or move their expiration dates, in your ASH configuration file.
```

### Scope a suppression to a symbol {#symbol}

`symbol` limits a suppression to findings inside one definition in the file, named with dots from the top of the file, such as `Deployer.run_hook`. The name is exact and case-sensitive. A suppression with `symbol` keeps matching when the code around the definition moves, where a line range would not.

The examples in this section and the next use this `src/deploy.py`, in which bandit reports B602 (a subprocess call with `shell=True`) inside both methods:

<!-- doctest: save-as=src/deploy.py -->
```python
import subprocess


class Deployer:
    def __init__(self, manifest):
        self.manifest = manifest

    def run_hook(self, name):
        return subprocess.call(self.manifest["hooks"][name], shell=True)

    def clean(self):
        return subprocess.call("make clean", shell=True)
```

This suppression covers the finding in `run_hook`, and the one in `clean` is still reported:

<!-- doctest: save-as=.ash.yaml -->
```yaml
global_settings:
  suppressions:
    - path: src/deploy.py
      rule_id: B602
      symbol: Deployer.run_hook
      reason: run_hook only runs commands from the deploy manifest
```

A symbol suppression also needs an entry for its file in `.ash.lock`; [create both with `ash suppress add`](#lock).

ASH finds the definition by parsing the file with tree-sitter, for Python, JavaScript, TypeScript, and Java files. The parsers are in the `symbols` extra, which is not installed by default; without it, a suppression with `symbol` matches nothing and the scan logs a warning that names the extra. The container image includes it. For the qualified-name grammar, the fail-closed rules, and the resolver's API and limits, see [Symbol resolution](../reference/symbol-resolution.md).

### Lock a symbol suppression to the code you reviewed {#lock}

A symbol suppression follows its definition when the code moves, so a definition that is rewritten would keep a review that no longer describes it. The lock prevents that. `.ash.lock`, a committed JSON file at the top of the scanned directory (`--source-dir`, usually the repository root -- the lock follows the scanned directory, wherever the config file lives), records each file a symbol suppression names as tree-sitter parsed it when the suppression was reviewed: digests of the file's syntax tree, and the `(rule_id, symbol)` scopes reviewed on it, each with an [invalidation scope](#invalidation-scope), `file` or `symbol`, that says which change makes it stop applying:

- A symbol suppression the lock does not record is refused when the config is validated, by `ash scan` and by `ash config validate`: a file with no entry, and equally a `(rule_id, symbol)` the file's entry does not record, so locking a file for one rule does not approve suppressions added to it later. The message names the `ash suppress add` command to run, which records a new scope on an existing entry. The rule id is compared case-insensitively, the symbol exactly.
- A symbol suppression's `path` must name one file. A glob or directory path names no single syntax tree, so it is refused with its own message; lock each file that holds a suppressed definition with its own entry.
- When the code a suppression was reviewed against changes, the suppression stops applying: any change to the code of the file under `file` scope, a change to the code of the definition under `symbol` scope. Its findings are reported again, and the scan prints one notice that names the file, the suppressions, and the refresh command.
- A change to layout alone, such as re-indenting, does not count; [What a change looks like to the lock](#what-counts) lists what does.
- Line-range suppressions are not affected.

Create the suppression and its lock entry together with `ash suppress add`:

```bash
ash suppress add B602 --symbol Deployer.run_hook --file src/deploy.py \
  --reason "run_hook only runs commands from the deploy manifest"
```

This writes the suppression to the config a scan of the current directory uses (`--config` names another YAML file) and the file's digests to `.ash.lock`. A suppression already in the config for the same rule, file, and symbol is not written twice, which is how you bring an existing symbol suppression, such as the one above, under the lock. Pass `--source-dir` to run it from another directory. `add` refuses a file whose recorded suppressions are out of date until you review its change and refresh it.

After you change a locked file, read the change, confirm the suppressions still hold, and record the review:

```bash
ash suppress refresh src/deploy.py   # or --all, after reviewing every change
```

A refresh records every suppression of each file it names again, from the code as it stands, so the whole-lock run is asked for explicitly with `--all`, never by leaving the paths off. A file that changed and does not parse cleanly is left as it was; `refresh` names the error and exits 1. A locked file that no longer exists cannot be recorded; `refresh` reports it and exits 1, and `ash suppress refresh --drop-missing <file>` removes the dead entry (then remove its suppressions from the config). A symbol-scoped suppression whose definition is gone from the file, renamed or deleted, is reported the same way: record it under its new name with `ash suppress add`, or remove it from the config, then refresh the file with `--drop-missing`.

`ash suppress verify` exits 1 and lists every recorded suppression whose code changed, whose file or definition is gone, or whose changed file cannot be parsed, and every symbol suppression the checked configs hold that the lock does not record. Run it in CI. It prints which config files it checked: the named `--config` files (repeatable for a repository with more than one), or the one config a scan of the source directory discovers; suppressions contributed by an `extends` base are not read.

`ash suppress add`, `refresh`, and `migrate` parse the files they record, so they need the `symbols` extra and refuse without it, printing the [install command](#installing-the-extra). `ash suppress verify` needs it only for a file whose bytes changed since it was recorded: an unchanged file is current by its content hash alone. A scan needs it in any case, since without it a symbol suppression matches nothing.

Commit `.ash.lock` with the change it belongs to, so a reviewer sees the new digests, and any change of invalidation scope, beside the edit they cover. The commands are the supported way to write the file. Its keys are sorted, so the same entries produce the same bytes in any order; each entry keeps the `created` stamp of its first review, `refresh` keeps it too, and a refresh that changes nothing rewrites nothing, so two independently created locks differ only in those stamps.

The lock was first written inside the `.ash/` directory. ASH still reads that older file when `.ash.lock` does not exist, with a deprecation warning; move it with `git mv .ash/ash.lock .ash.lock` (any later `ash suppress add`, `refresh`, or `migrate` also writes `.ash.lock` and leaves the old file for `git rm`). Reading it is deprecated since v3.9 and ends in v4.0.

#### Choose what makes a suppression stop applying {#invalidation-scope}

Each suppression the lock records has an invalidation scope:

| Scope | The suppression stops applying when |
|---|---|
| `file`, the default | the code of the file changes, anywhere in it |
| `symbol` | the code of the definition changes: a token on its lines, another definition that bears its name, the header of a definition it sits in (such as a class's name, bases, and decorators), or the top of the file (a byte order mark; in Python the encoding declaration, the `#!` line, and `from __future__` imports; in JavaScript and TypeScript the `#!` line, leading comments, and directives such as `"use strict"`) |

Choose by what the suppression's reason depends on. The reason given for `run_hook` above, that it only runs commands from the deploy manifest, depends on where the manifest comes from, which is code outside `run_hook`, so it keeps file scope. A reason that the definition's own lines prove can take symbol scope, such as the fixed command in `clean`:

```bash
ash suppress add B602 --symbol Deployer.clean --file src/deploy.py \
  --reason "clean runs a fixed command" --invalidation-scope symbol
```

Symbol scope does not cover the rest of the file: imports other than `from __future__`, module-level constants, class attributes, other definitions, the code that calls the definition, and an `if` or `try` around it. A suppression whose reason rests on one of them keeps file scope. For a `subprocess.call(COMMANDS[step], shell=True)` that is safe because of what `COMMANDS` holds at the top of the module, symbol scope would leave the suppression applying after an edit to `COMMANDS`.

Without `--invalidation-scope`, `add` records a new suppression with the `global_settings.suppression_invalidation_scope` of the config it writes to (`file` or `symbol`; an `extends` base is not read), or `file` when the config does not set it. A suppression the lock already records keeps its scope: `add` refuses a different `--invalidation-scope` for it, and when only the config's default differs, it keeps the recorded scope and says so. Change a recorded scope with a refresh, which reviews the file again: `ash suppress refresh --invalidation-scope symbol --symbol Deployer.run_hook src/deploy.py` would move the `run_hook` suppression to symbol scope, and without `--symbol` the option sets the scope of every suppression of the files named. A scan and `ash suppress verify` read the scope from the lock alone, so editing the config's default never changes a suppression that was already reviewed.

#### What a change looks like to the lock {#what-counts}

Only layout is ignored: spaces, tabs, and line breaks between tokens, a backslash that continues a Python line, and line endings (CRLF, CR, and LF read the same). Every other change counts:

- a comment, so an edit that changes only a comment counts;
- the spelling of a literal: its quote style, an f-string's spacing, a re-wrapped docstring, `0x10` written for `16`;
- parentheses, trailing commas, and semicolons that a formatter adds or removes;
- in JavaScript and TypeScript, whether a line break comes before a token, so moving part of a statement onto a new line counts and re-indenting it does not;
- adding or removing a UTF-8 byte order mark.

A formatter that only re-indents keeps every suppression applying; one that rewrites quotes or commas needs a refresh after you review its change. With the two suppressions above, a comment appended to `src/deploy.py` changes the file but not `clean`:

<!-- doctest: run expect-exit=1 -->
```bash
printf '\n# Hooks are defined in the deploy manifest.\n' >> src/deploy.py
ash suppress verify
```

```text
stale: src/deploy.py (B602 in Deployer.run_hook); after review run `ash suppress refresh src/deploy.py`
1 problem(s); a scan does not apply these suppressions.
```

The file-scope suppression of `run_hook` stops applying until the file is refreshed, and the symbol-scope suppression of `clean` still applies. After reviewing the change, record it:

```bash
ash suppress refresh src/deploy.py
```

#### Grammar updates {#grammar-updates}

A digest depends on how the grammar of the file's language parses the file, so each entry records the grammar it was computed under: the grammar's package and version, and a fingerprint of its tables. When an upgrade of ASH or of the `symbols` extra brings a grammar whose tables differ:

- a file whose bytes have not changed since it was recorded stays current;
- a changed file cannot be compared across two grammars, so `verify` and the scan report its suppressions as stale, naming both grammar versions, until a refresh records the review under the new grammar.

A grammar release with the same tables is the same grammar to the lock. Each entry also names the canonical form its digests were computed in (`ash-ast-1`); an ASH that does not compute that form reports a changed file of the entry as one it cannot check, never as current.

#### Upgrading a version 1 lock {#upgrade-lock}

A lock written before syntax-tree digests, a version 1 lock, records a SHA-256 of each file's bytes. ASH still reads it with that meaning: any byte change, line endings included, makes a version 1 entry stale. `ash suppress verify` passes on a version 1 entry whose file is unchanged and prints a line that names `ash suppress migrate`. The first command that writes the lock writes version 2, and leaves the version 1 entries it did not record as they were.

To convert a lock:

1. Run `ash suppress verify`. For each file it lists, review the change and run `ash suppress refresh <file>`, which records the review as syntax-tree digests.
2. Run `ash suppress migrate`. It converts every version 1 entry whose file is unchanged, at file scope, which approves nothing: the bytes it reads are the bytes that were reviewed. It lists every entry it leaves (its file changed, is gone, or does not parse) and exits 0 only when no version 1 entry is left.

```bash
ash suppress migrate
```

`ash suppress add` also converts the entry it records a suppression on, while that file is unchanged. Moving a converted suppression to symbol scope is a separate review, with `refresh --invalidation-scope symbol`.

Every environment that runs `ash scan` or `ash suppress` on the repository has to move together. An ASH built before version 2 locks reads only version 1 and refuses a version 2 lock: its scan stops when the config is validated (exit 3), and its `ash suppress` commands exit 1. To go back to such a build, restore the `.ash.lock` from before the upgrade as well.

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

npm-audit does not work that way. npm, pnpm and yarn name no file in their audit output, so npm-audit locates each advisory at the lockfile it audited (`package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml` or `yarn.lock`), as a path relative to the scanned directory. That file is in your checkout, a `node_modules/` ignore path does not match it, and it is where a fix is made. For an npm lockfile the result also carries the line of the package's entry; for `pnpm-lock.yaml` and `yarn.lock` it has no line. Findings of one lockfile share its location, so the package, its installed version and where it is installed are what tell them apart: they are in the result's `package_name`, `package_version` and `package_path` properties, and in its `partialFingerprints`.

Two ignore paths still silence npm-audit, and neither is a mistake in the scanner. An ignore path that matches a lockfile, such as `**/pnpm-lock.yaml`, drops that lockfile's findings. And a lockfile under an ignore path is skipped rather than audited, so a generic ignore list that names lockfiles leaves those projects out of the audit and the scan has no npm-audit finding for them. Check the ignore list for lockfile names before relying on a clean npm-audit result.

Earlier releases located every npm-audit finding at `node_modules/<package>/package.json`. A suppression whose `path` is that location does not match the finding now, and neither does a baseline keyed on it. Re-key the suppression by setting `path` to the lockfile and keeping `package_name`, `package_version` and `package_path` to name the dependency:

```yaml
global_settings:
  suppressions:
    - rule_id: GHSA-vfj7-8cjw-p6xm
      path: deploy/cdk/package-lock.json
      package_name: braces
      package_path: deploy/cdk/node_modules/braces
      reason: Not reachable from the deployed code
```

Grype's findings in a lockfile are suppressed the same way.

An ignore path can also have an `expires` date, which works the way a suppression's does: on that date the ignore path stops applying, so the files it covered are scanned again and their findings count on the next scan. The same holds for the entries of bandit `excluded_paths`, checkov `skip_path`, and syft `exclude`. This expired ignore path no longer drops the finding in `app.py`:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress \
  --config-overrides 'global_settings.ignore_paths+=[{"path": "app.py", "reason": "Fixture value, not a real password", "expires": "2020-01-01"}]'
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

## Drop one rule under a path (exclusions) {#exclusions}

A suppression keeps the result in SARIF marked suppressed, and an ignore path drops every rule under the path. When one rule is always benign in one place -- bandit B101 (`assert`) under `tests/`, say -- a rule+path exclusion drops just that rule's results there, so they do not pile up as suppressed noise in SARIF consumers while B105 or B108 under `tests/` are still reported:

```yaml
global_settings:
  exclusions:
    - rule_id: B101
      path: "**/tests/**"
      scanner: bandit
      reason: "pytest assert idiom; tests are not shipped"
```

`rule_id`, `path`, and `reason` are required. The rule ID matches the finding's exact ID case-insensitively, or as a glob (`B1*`); the path matches the way a suppression's does, and a result is dropped only when every location that names a file is under the path; `scanner` (optional) bounds the exclusion to one scanner's results by its registered name; `expires` works the way a suppression's does. Each dropped result is logged when the scan runs with `--verbose`. Exclusions are a suppression mechanism: [`--ignore-suppressions`](#ignore-suppressions) brings excluded results back with everything else. An exclusion that matched nothing is not listed by the [unused-suppressions report](#unused), so check stale exclusions by hand. [Suppressions, ignore paths, and scanner exclusions](../concepts/suppressions.md) places exclusions among the other mechanisms.

## Find suppressions that no longer match {#unused}

The `unused-suppressions` reporter, on by default, writes `.ash/ash_output/reports/ash.unused-suppressions.json` and `ash.unused-suppressions.md`. They list each entry in `global_settings.suppressions` that matched no finding in the scan, including expired ones. They do not cover ignore paths, `global_settings.exclusions`, or inline suppressions.

After a scan, `ash config lint --fix-unused` comments out the entries that the report lists, with the date. When it comments out every entry, it leaves `suppressions: []` above them, so the file still loads; remove the `[]` when you turn an entry back on. A suppression can look unused in one environment and still be needed in another, for example when a scanner whose finding it covers is not installed locally but runs in CI. Check the report before you remove entries.

## Add a suppression while you review findings {#inspect}

`ash inspect findings` opens the last scan's findings in your terminal. Select a finding and press `x` to suppress it: ASH asks for a reason and an optional expiration, and adds an entry with the finding's path and rule ID, and its line as `line_start` and `line_end`, to the config file (the `--config` file, else the config ASH discovers, else a new `.ash.yaml` in the current directory). It keeps the comments of a YAML file, except one whose `global_settings` is written inline (`global_settings: {...}`), which it rewrites in full, and it writes a JSON config back as JSON. If the file already has an identical entry, nothing is added, and the status bar says so; an entry for another line, reason, or expiration with the same rule ID and path is added. It does not edit TOML files, or a file that uses `extends` but has no suppressions list of its own.

## See every finding {#ignore-suppressions}

`--ignore-suppressions` reports findings as if no suppression existed, so you can review what the suppressions hide. With the suppression from the earlier example, the finding fails the scan again:

<!-- doctest: run expect-exit=2 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress --ignore-suppressions \
  --config-overrides 'global_settings.suppressions+=[{"path": "app.py", "rule_id": "SECRET-SECRET-KEYWORD", "reason": "Fixture value, not a real password"}]'
```

It lifts config suppressions, ignore paths, rule+path exclusions ([Drop one rule under a path](#exclusions)), `ash-ignore` comments, and cdk-nag's `Metadata` suppressions. Every scanner reads the files under an ignore path, and their findings are reported; to drop only the ignore paths for one run, pass `--config-overrides 'global_settings.ignore_paths=[]'` instead. It does not bring back what a scanner never reported (findings hidden by the scanner's own comments or its exclusion options), and findings that semgrep and checkov report as suppressed stay suppressed. The repository's `.gitignore` and `.ignore` files still apply, and findings in ASH's own output directory stay out of the results. In container mode the flag reaches the scan inside the container and works there as in a local scan.

When an MCP client delivers the config, its suppressions, ignore paths, and scanner exclusions are marked client-supplied in the results; see [Configuration trust model](../concepts/trust-model.md#client-supplied). ASH applies all of them itself, so in a local scan with `--ignore-suppressions` none of them applies, and the findings they would have marked are ordinary findings.
