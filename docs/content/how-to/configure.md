# Configure ASH

ASH runs without a config file. Add one when you want to change a default: the gate, which scanners run, suppressions, or a scanner's options. This page covers creating the file, where ASH looks for it, overriding settings for one run, and checking a file before you rely on it. Every key is listed in the [configuration reference](../reference/configuration.md).

## Create a config file

Run this in the root of the repository you scan:

```bash
ash config init
```

`ash config init` writes `.ashrc.yaml` in the current directory, with `project_name` set to the directory's name and every other setting at its default value, and `.ash/.gitignore`, which keeps ASH's output directory `.ash/ash_output` out of git. It exits 1 if the file already exists; pass `--force` to overwrite it. It also exits 1 when the directory already has another config source, such as `.ash/.ash.yaml` or a `[tool.ash]` table, because ASH never merges sources, and `--force` does not change that. With `--config`, or `ASH_CONFIG` set, it writes to that path instead, and a path that ends in `.json` gets a JSON file. It then does not look for another config source, so a file it writes next to an existing `.ash/.ash.yaml` is one a scan does not read. `project_name` is then the name of the directory that holds the file, and `.ash/.gitignore` is written only when the file is in `.ash/` or has one of the names ASH looks for.

You can delete every key you don't change. A key you keep holds its value when a later ASH release changes the default, and a key you delete follows the new default. A short file also has less to review:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json
project_name: payments-api
global_settings:
  severity_threshold: HIGH
scanners:
  cfn-guard:
    enabled: false
```

`project_name` names the project in the reports. Without it, ASH uses the `ASH_PROJECT_NAME` environment variable, else `ash-scan`.

A config file inside the repository you scan, including the `.ashrc.yaml` that ASH finds on its own, is a repository config: whoever can commit to the repository controls it, so ASH ignores the few settings in it that grant sandbox access, load ASH's plugins that send data off the host, turn on the reporters that send findings off the host, choose where findings are sent, relax the stale content database check, choose which release of a scanner's tool runs, let trivy send usage data to its vendor, or point the scanners listed in [Options only the operator can set](choose-scanners.md#operator-only) at their tool files. Command-line flags, and a config file outside every git checkout and the scanned directory that you name with `--config`, are operator sources and may set everything. A config in a separate ops or dotfiles checkout is held to the same limits as a repository config; [Configuration trust model](../concepts/trust-model.md) has the details.

## Where ASH looks for its config {#discovery}

`ash scan` looks in its source directory (`--source-dir`, by default the current directory), and so do `ash config get`, `ash config validate`, `ash config lint`, `ash config validate-plugin-dependencies`, `ash config update`, and `ash config wizard`, which take `--source-dir` too. `ash config init` writes in the current directory. ASH uses the first source it finds, in this order:

1. `.ash.yml`, `.ash.yaml`, `.ash.json`, `ash.yml`, `ash.yaml`, `ash.json`. ASH tries each name in the directory and then in its `.ash/` subdirectory before it moves to the next name, so `.ash/.ash.yml` wins over `.ash.yaml`.
2. `.ashrc.toml`, `.ashrc.yaml`, `.ashrc.yml`, `.ashrc.json`, `ashrc.toml`, `ashrc.yaml`, `ashrc.yml`, and `ashrc.json`, in the directory only.
3. The `[tool.ash]` table of `pyproject.toml`.

ASH never merges sources and does not look in parent directories. Every other source it finds is ignored, with a warning that names it. The [configuration reference](../reference/configuration.md#where-ash-finds-its-configuration) lists all 21 locations in order.

When a file from the first group is used while an `ashrc` file or a `[tool.ash]` table also exists, the warning adds that the first group's names are deprecated in favor of the other two. The file from the first group is still the one ASH uses. `ash config init` writes `.ashrc.yaml`, and these pages use that name.

The commands that edit a config file (`ash config update`, `ash config wizard`, and `ash inspect findings`) write YAML, and JSON into a file whose name ends in `.json`. They refuse TOML files, and `update` and `wizard` also refuse a file that uses `extends` or `patch` or reads values from the environment, because a rewrite would store what the references resolve to. With no config file, `wizard` and `inspect findings` create `.ashrc.yaml`. `ash config update --set` takes the same `key.path=value` form as [`--config-overrides`](#overrides), including JSON values and `+=`. `update` and `wizard` exit 3 and leave the file unchanged when a scan refuses it, and `update` also when a `--set` leaves a config a scan would refuse. Neither checks the options of plugins loaded from `ash_plugin_modules`, so a scan can still refuse a file they wrote. They write every setting, defaults included, keep top-level keys ASH does not know (a JSON `$schema`, for example), and keep no comment other than the schema line.

In `pyproject.toml`, the same settings go under `[tool.ash]`:

<!-- doctest: config kind=pyproject -->
```toml
[tool.ash]
project_name = "payments-api"

[tool.ash.global_settings]
severity_threshold = "HIGH"
```

### Use a specific file

`--config` (`-c`) or the `ASH_CONFIG` environment variable names the file to use. In a scan of one directory, ASH then skips discovery, so it does not read the repository's own config at all. In workspace mode, the file is layered over each project's own config instead: every setting it makes is final for every project, a project's own config fills only the settings it leaves out, and a project with no config uses the file alone. ASH refuses such a file inside the workspace's tree (exit 3), and one inside another git checkout cannot make the operator-only settings final ([Scan a multi-project workspace](scale-large-repos.md#workspaces)). `--config-overrides` applies to every project as well. A relative path is resolved against the current directory, not the source directory.

<!-- doctest: illustrative reason="names a config file outside the sample project" -->
```bash
ash --source-dir . --config ~/ash/ci.yaml
```

A scan uses the default configuration only when there is no config file at all. A config file that `--config` or `ASH_CONFIG` names, or that discovery finds, stops the scan with exit 3 before anything is scanned when it does not exist, is not a regular file, cannot be read, is not UTF-8, does not parse, or fails validation, and so does an `extends` base that is missing or does not parse. [Check a config](#check) shows how to catch these before a scan.

A scan that names a file that does not exist is refused:

<!-- doctest: run expect-exit=3 -->
```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress --config no-such-config.yaml
```

So is one whose `ASH_CONFIG` names such a file, also when `--config` names a file that loads:

<!-- doctest: run expect-exit=3 -->
```bash
ASH_CONFIG=no-such-config.yaml ash --source-dir . --scanners detect-secrets --offline --no-progress
```

## Share settings with `extends` {#extends}

A config file can build on other files. `extends` names one base file or a list of them, relative to the file that names it:

```yaml
extends: config/ash-base.yaml
project_name: payments-api
scanners:
  trivy:
    enabled: false
patch:
  - op: add
    path: /global_settings/suppressions/-
    value:
      path: app.py
      rule_id: SECRET-SECRET-KEYWORD
      reason: Fixture value, not a real password
```

ASH merges the bases in order and then the file itself. Mappings merge key by key; a list or a single value from the later file replaces the base's. To add to a base's list instead of replacing it, use `patch`, a list of JSON Patch operations (`add`, `remove`, `replace`, and `test`) applied after the merge. A config file that an MCP client chose (a file inside delivered source, or one named as `config_path`) may not use `test`: every `test` operation in such a file is refused before any operation applies, because a `test` against a base the operator owns would reveal, through whether the file loads, a value the client may not read ([What a delivered config cannot set](mcp-server.md#what-a-delivered-config-cannot-set)); the operator's own files keep theirs.

A plugin's section is found by the plugin's name with case, punctuation, and the words Scanner, Reporter, and Converter ignored, so `CSV`, `CsvReporter`, and `csv` name one reporter, and `DetectSecretsScanner` names `detect-secrets`. A child's spelling of a section the base writes another way is that section: the merged config holds it under a built-in plugin's own name (`csv`), and otherwise under the child's spelling. A file that writes two such spellings, such as `detect-secrets` and `DETECT_SECRETS`, is refused with exit 3 by a scan and by `ash config validate`, which name both spellings and none of their values. A config that a results file recorded is read, not refused, by `ash report` and `ash merge`: of two such spellings in it, they read the one that the scan which recorded it read, and when the spelling not read sets a value the read one does not, a warning names the spellings and the one read, never a value.

`patch` works on what the files set, not on ASH's defaults. `add` at `/global_settings/suppressions/-` appends to a list that a file in the chain set; when none did, the operation fails with exit 3, and you add the whole list instead (`path: /global_settings/suppressions` with a list as the `value`), which in turn needs a file in the chain to set `global_settings`. `replace` also fails on a key that no file set; use `add` for those. The error for an operation that fails names the file, the entry's place in `patch`, its op, and its path, and not its value. In a `patch` path, a key spelled with `-` and the same key spelled with `_` are one key, and a plugin's section is matched as its name is: `/reporters/CSV/enabled` and `/scanners/detect_secrets/enabled` reach the `csv` and `detect-secrets` sections.

A base must be inside the scanned directory. For a config file outside the scanned directory, its bases must be in that file's own directory or below it (for a file in `.ash/`, the directory that holds `.ash/`). URLs are refused, and so are cycles, chains more than 10 levels deep, and chains of more than 50 files.

## Override settings for one run {#overrides}

`--config-overrides` sets one key for one run, on top of the config file. Repeat it to set several; when two set the same key, the later one wins.

```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress \
  --config-overrides fail_on_findings=false \
  --config-overrides global_settings.severity_threshold=HIGH
```

The form is `key.path=value`:

- The key is a dotted path into the config, such as `scanners.bandit.options.confidence_level`. Plugin names use their hyphenated config names (`detect-secrets`, `cdk-nag`), and a key reaches a plugin's section by that name, so `reporters.csv.enabled` sets the `csv` section's. There is no list indexing.
- The value is split from the key at the first `=`. `true`, `false`, `null`, and `none`, in any case, become booleans and null; numbers become numbers; and a value wrapped in `[...]` or `{...}` is read as JSON (a `[...]` that is not valid JSON is split at its commas). Anything else is a string. Threshold values are case-sensitive, so `HIGH` is a threshold and `high` is an error.
- `key.path+=value` appends to an existing list instead of replacing it: `--config-overrides 'global_settings.ignore_paths+=[{"path": "vendor/**", "reason": "Third-party code"}]'`. On a key that is not a list yet, it sets the value.

ASH applies the overrides after loading the config file and validates the result again. An override that does not parse or does not validate stops the scan with exit 3, and so does an unknown key in a plugin's `options` or a plugin option set beside `enabled` instead of under `options`. An override of a key the model ignores, such as an unknown top-level key or an unknown plugin name under `scanners`, `reporters`, or `converters`, is accepted and has no effect. Overrides are an operator source, so they can set the settings a repository config cannot.

## Read values from the environment {#environment}

A config value written as `${NAME}` or `${NAME:default}` is replaced by the environment variable `NAME`. With a default, `default` applies when the variable is not set:

```yaml
project_name: ${ASH_SERVICE_NAME:payments-api}
global_settings:
  severity_threshold: ${ASH_GATE_THRESHOLD:HIGH}
```

- Write the reference at the start of the value. In YAML, an unquoted value that starts with `${` is replaced, and a quoted one only when it is tagged `!ENV` (`!ENV '${NAME}'`). In TOML, every string value that starts with `${` is replaced. A JSON config file is never read this way.
- Only names that start with `ASH_`, and `AWS_REGION`, `AWS_DEFAULT_REGION`, and `AWS_PROFILE`, are read. Any other name is left in the value as written, with a warning.
- In container mode, the scan inside the container gets from the host only the variables that your own config files read and that are set, not those a config in the scanned directory or a git checkout reads ([The config file](run-in-a-container.md#config)).
- `${NAME}` without a default needs the variable: when it is not set, ASH refuses the config with exit 3 and names the variable. For a variable that may be unset, write a default. `${NAME:}` and `${NAME:None}` resolve to nothing (null), and so does a variable that is set to an empty string, with or without a default.
- Text after the reference is kept when it contains no `}`: `${ASH_SERVICE_NAME:payments}-api` resolves to the variable's value, or `payments`, followed by `-api`. When the text after the reference does contain a `}`, ASH reads that text as part of the reference. With a default, as in `${ASH_SERVICE_NAME:payments}/{run}`, the default becomes `payments}/{run`, and the whole value is replaced by the variable when it is set. Without a default, as in `${ASH_SERVICE_NAME}/{run}`, the value is left as written. A reference after other text is not replaced, and neither is a second reference in the same value.
- The result is a string. That works for string and threshold values, but a boolean or number key such as `fail_on_findings` fails validation (exit 3).
- The scan runs with the values. What ASH records of the config holds each reference as the file wrote it instead: the `ash_config` in the scan's results (`ash_aggregated_results.json`) and in the merged results, the results' metadata where it names a config value (a `scanners` key in `expected_scanners`), what an off-host reporter sends, and what `ash config get` prints. A reference whose variable is not set is recorded as the default the file wrote, and one that resolves to nothing as null. Debug and info lines name a section's keys, not its values, apart from the plugin modules a scan loads and the settings a scanner, reporter, or converter reports while it runs. In ASH's own log lines, a value that a reference read from the environment is shown as `<value>`, unless the value has no letter or digit, such as `.`; a value the file writes itself is shown as written. Report files are not log lines and keep the values, as the next point says, and output a scanner's tool writes is kept as the tool wrote it.
- The reports the scan writes are built from the values, and the record does not cover them: the reports a scan writes itself, such as `ash.html`, show the values. So do not read secrets into the config.
- `ash merge` and `ash report` read the recorded config and do not read the environment for a reference in it. A text field such as `project_name` keeps the reference as its value. A field that takes a fixed choice, a boolean, or a number, such as `severity_threshold`, cannot hold one: the command warns that the field reads as its default, then exits 3 naming the field and the reference, until you supply the field with `--config-overrides` or in the file `--config` names.
- A config file under the ASH MCP server's workspace root, where delivered source is kept, may not use a reference at all: ASH refuses it, on the CLI too, with exit code 3. Under `ash mcp`, neither may a config file an MCP client names outside the directories `ASH_MCP_ALLOWED_CONFIG_ROOTS` names, and the MCP tools refuse it with `config_env_not_resolved` ([What a delivered config cannot set](mcp-server.md#what-a-delivered-config-cannot-set)).
- An editor that checks the file against ASH's schema marks a reference in a field with fixed values, such as `severity_threshold`, as an error. ASH accepts it.

`ash config get` loads the file with the variable read, and prints the reference, not the value:

```bash
cat > env-example.yaml <<'EOF'
project_name: ${ASH_SERVICE_NAME}
EOF
ASH_SERVICE_NAME=payments-api ash config get --config env-example.yaml
```

<!-- doctest: output -->
```text
project_name: ${ASH_SERVICE_NAME}
```

Without the variable, the same file is refused:

<!-- doctest: run expect-exit=3 -->
```bash
ash config validate --config env-example.yaml
```

## Relative paths in the operator's settings {#relative-paths}

A relative path in one of the operator's settings is taken from where it was set, not from the source directory being scanned:

- In a config file outside the tree (`--config`, `ASH_CONFIG`, a workspace's `--config`, an MCP profile), from that file's directory. In an `extends` base, from the base's directory. In a `patch` operation, from the directory of the file that holds it.
- In `--config-overrides`, in a CLI flag, and in `TRIVY_IGNOREFILE`, `TRIVY_SECRET_CONFIG` or `TRIVY_CONFIG`, from the working directory ASH runs in.

This covers `config_file` of actionlint, bandit, cfn-lint, checkov, ferret-scan, gitleaks, grype, syft, trivy, trivy-repo and zizmor, gitleaks' `baseline_path`, each entry of cfn-guard's `rules_paths`, detect-secrets' `baseline_file` and the `file://` entries of its `scan_settings`, trivy's and trivy-repo's `ignore_file` and `secret_config_file`, trivy-repo's `module_dir`, opengrep's and semgrep's `config` when a file or directory is there (otherwise it is a registry entry such as `p/ci`), and `sandbox.extra_read_paths`. It does not cover actionlint's `shellcheck` and `pyflakes`, which name a program: a bare name there is looked up on `PATH`, and a relative path is taken from the source directory.
A path that starts with `~`, or is absolute, is used as written. In `TRIVY_IGNOREFILE`, `TRIVY_SECRET_CONFIG` and `TRIVY_CONFIG`, any other value is taken from the working directory exactly as written, a `$` or `://` in it included, and a `..` after a symbolic link goes up from where the link points.

A config file inside the scanned tree does not set these options ([How a file's tier is decided](../concepts/trust-model.md#how-the-tier-is-decided)). To name a file in the scanned repository, give its absolute path, or a path relative to where you run ASH with `--config-overrides`.

## Get completion in your editor {#schema}

The first line `ash config init` writes points editors that use the YAML language server (VS Code with the Red Hat YAML extension, for example) at ASH's JSON schema:

```text
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json
```

The editor then completes keys and checks values as you type. ASH itself treats the line as a comment. The URL follows the `main` branch, not the ASH version you have installed, so the schema can list keys your version does not have. The schema flags an unknown key only where ASH itself refuses one (the unknown-key rows of the table in [Which mistakes ASH catches](#typos) that end in exit 3, plus `build` and `mcp-resource-management`), and it does not include the community plugins' sections.

## Check a config {#check}

Three commands check a config file. `ash config validate` and `ash config lint` give the verdict a scan would give: they load the file with the loader and model `ash scan` uses, and exit 3 when a scan would refuse it. The one exception is the options of plugins loaded from `ash_plugin_modules`, which only a scan checks. Each of the three takes `--config` to check a file other than the one ASH finds, and `--source-dir` (or `ASH_SOURCE_DIR`; by default the current directory) for the directory a scan would scan. An `ASH_CONFIG` that names a file that does not exist makes each of them exit 3, also beside a `--config` file that loads, as it stops a scan. Each finds the config there and holds its `extends` chain to the bounds a scan of that directory sets ([Share settings with `extends`](#extends)), and `validate` and `lint` match ignore and suppression paths against it. `validate` and `get` also take `--config-overrides` and check the config with them applied, as a scan given the same overrides does. An override does not make a file that a scan refuses valid: the file is checked on its own before the overrides apply.

| Command | What it checks | What it misses |
|---|---|---|
| `ash config validate` | Loads the file the way a scan does: it parses, its `extends` chain and its environment references resolve, and ASH's config model accepts every key and value, with any `--config-overrides` you pass applied, and a scan accepts the module names in `ash_plugin_modules`. It also warns, without failing, about what a scan accepts but is probably a mistake: an unknown or repeated top-level key, a missing `project_name`, the internal `build` section and a plugin section's internal fields (such as `name` and `extension`). An ignore path that names an existing directory with neither a trailing `/` nor `**`, and a suppression path that names one without `**`, are warnings too, since a scan accepts them; the warning gives the pattern for every file inside, `<dir>/` for an ignore path and `<dir>/**/*` for a suppression path. So is a path that matches nothing because it starts with `./` (`./src` is `src/`) or is empty or `.`, and the warning says what to write instead. A path that matches the tree only in another case (`tests/**` against `Tests/`) gets a warning that names the tree's spelling and says that patterns match case-sensitively | The options of plugins loaded from `ash_plugin_modules`, which only a scan checks (a note names those sections), and keys the model accepts and never reads (see below) |
| `ash config lint` | Everything `validate` checks, marking each problem that makes a scan refuse the file `[blocks the scan]`, plus suppressions (`line_start` without `line_end`, expired entries, multi-line reasons, and `symbol` values), expired ignore paths (also in bandit `excluded_paths`, checkov `skip_path`, and syft `exclude`), and snake_case plugin names. `--fix` repairs what it can; `--fix-unused` comments out suppressions the last scan's [unused-suppressions report](suppress-findings.md#unused) lists | The same as `validate` |
| `ash config get` | Loads the file the same way and prints the resolved config, with each value read from the environment shown as the reference the file wrote. Exits 3 on any value or key the model refuses | The same as `validate`. It does not print `validate`'s warnings. |

Run `ash config validate` and `ash config lint` from the repository root before you commit a change. `ash config get` prints the resolved config, so you can see what ASH read from the file:

```bash
ash config validate
ash config lint
ash config get
```

A missing `project_name` and an unknown top-level key are warnings, which leave the exit code at 0: a scan takes the project's name from the `ASH_PROJECT_NAME` environment variable, else `ash-scan`, and it ignores the unknown key, so a config written for another ASH version still loads. A file that does not parse is invalid for `validate` and `lint` (exit 3), and a scan refuses it the same way.

In the messages of the `ash config` commands, and of a scan that refuses a config, a value that a reference read from the environment is shown as `<value>` where the message quotes it, however short the value is, so the commands do not print what the variable holds. A value that a field taking a fixed choice, a boolean, or a number refuses is not quoted at all: the message names the field and what it takes. `ash config get` prints a valid config with each reference as the file wrote it.

### Which mistakes ASH catches {#typos}

A scan refuses a misspelled key in most of the config. It ignores an unknown top-level key and an unknown plugin name, so a misspelling there does nothing at all, with no error:

| Mistake | Example | What a scan does |
|---|---|---|
| Unknown top-level key | `fail_on_finding: false` | Ignores it. `validate` and `lint` warn about it. |
| Unknown key in `global_settings`, `sandbox`, `workspace`, or a `content_db_staleness_overrides` entry | `severity_treshold: HIGH` | Refuses the config, exit 3 |
| Unknown key in a suppression or an ignore path | `ruleId: B602`, `expiry: "2027-01-31"` | Refuses the config, exit 3 |
| Unknown key directly under a plugin's `options` | `confidance_level: high` | Refuses the config, exit 3. A key inside an option's value, such as an entry of cdk-nag's `nag_packs`, is not checked. |
| Wrong value | `severity_threshold: high`, or an unquoted `expiration: 2027-01-31` | Refuses the config, exit 3 |
| Missing required field | a suppression without `reason` | Refuses the config, exit 3 |
| A plugin option written directly in the plugin's section, beside `enabled` | `severity_threshold: HIGH` beside `enabled: true` under `scanners.bandit` | Refuses the config, exit 3. The error says to move the key under `options`. |
| Misspelled scanner, reporter, or converter name | `detect_secret:` | Ignores the section |

When a known key is close to the unknown one, the error names it. This suppression is refused:

<!-- doctest: config kind=ash-invalid reason="ruleId is not a key of a suppression" -->
```yaml
global_settings:
  suppressions:
    - path: src/deploy.py
      ruleId: B602
      reason: The command is a constant; no user input reaches it
```

```text
Invalid value at 'global_settings.suppressions[0]': Value error, Unknown key 'ruleId' (did you mean 'rule_id'?) in a suppression. Accepted keys: expiration, line_end, line_start, package_name, package_path, package_version, path, reason, rule_id, symbol.
```

`ash config validate`, `ash config lint`, and `ash config get` catch every mistake that ends in exit 3, with one exception: they do not load the plugins named in `ash_plugin_modules`, so only a scan checks those plugins' options, once it has loaded them. `validate` and `lint` also warn about the unknown top-level key. No command catches the last mistake. For that one, compare your keys with the [configuration reference](../reference/configuration.md) and the [scanner reference](../reference/scanners.md), and look for the value you meant to set in the output of `ash config get`.
