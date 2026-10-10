# Configure ASH

ASH runs without a config file. Add one when you want to change a default: the gate, which scanners run, suppressions, or a scanner's options. This page covers creating the file, where ASH looks for it, overriding settings for one run, and checking a file before you rely on it. Every key is listed in the [configuration reference](../reference/configuration.md).

## Create a config file

Run this in the root of the repository you scan:

```bash
ash config init
```

`ash config init` writes `.ash/.ash.yaml`, with every setting at its default value, and `.ash/.gitignore`, which keeps ASH's output directory `.ash/ash_output` out of git. It exits 1 if the file already exists; pass `--force` to overwrite it. With `--config`, or `ASH_CONFIG` set, it writes to that path instead.

You can delete every key you don't change. A key you keep holds its value when a later ASH release changes the default, and a key you delete follows the new default. A short file is also easier to review:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json
project_name: payments-api
global_settings:
  severity_threshold: HIGH
scanners:
  cfn-guard:
    enabled: false
```

A config file inside the repository you scan, including the `.ash/.ash.yaml` that ASH finds on its own, is repository configuration: whoever can commit to the repository controls it, so ASH ignores the few settings in it that grant sandbox access, load ASH's plugins that send data off the host, choose where findings are sent, or point scanners at tool files. Command-line flags, and a config file outside every git checkout and outside the scanned directory that you name with `--config`, are operator configuration and may set everything; [Configuration trust model](../concepts/trust-model.md) has the details.

## Where ASH looks for its config {#discovery}

`ash scan` looks in its source directory (`--source-dir`, by default the current directory). The `ash config` commands look in the current directory. ASH uses the first source it finds, in this order:

1. `.ash.yml`, `.ash.yaml`, `.ash.json`, `ash.yml`, `ash.yaml`, `ash.json`. ASH tries each name in the directory and then in its `.ash/` subdirectory before it moves to the next name, so `.ash/.ash.yml` wins over `.ash.yaml`.
2. `.ashrc.toml`, `.ashrc.yaml`, `.ashrc.yml`, `.ashrc.json`, `ashrc.toml`, `ashrc.yaml`, `ashrc.yml` and `ashrc.json`, in the directory only.
3. The `[tool.ash]` table of `pyproject.toml`.

ASH never merges sources and does not look in parent directories. Every other source it finds is ignored, with a warning that names it. The [configuration reference](../reference/configuration.md#where-ash-finds-its-configuration) lists all 21 locations in order.

When a file from the first group is used while an `ashrc` file or a `[tool.ash]` table also exists, the warning adds that the first group's names are deprecated in favor of the other two. The file from the first group is still the one ASH uses. These pages use `.ash/.ash.yaml` because `ash config init` writes it. The commands that edit a config file (`ash config update`, `ash config wizard` and `ash inspect findings`) write YAML and refuse TOML files.

In `pyproject.toml`, the same settings go under `[tool.ash]`:

<!-- doctest: config kind=pyproject -->
```toml
[tool.ash]
project_name = "payments-api"

[tool.ash.global_settings]
severity_threshold = "HIGH"
```

### Use a specific file

`--config` (`-c`) or the `ASH_CONFIG` environment variable names the file to use. ASH then skips discovery, so it does not read the repository's own config at all. A relative path is resolved against the current directory, not the source directory.

<!-- doctest: illustrative reason="names a config file outside the sample project" -->
```bash
ash --source-dir . --config ~/ash/ci.yaml
```

If the named file does not exist, or a config file does not parse, ASH logs a warning and scans with the default configuration, so none of your thresholds or suppressions apply and the exit code reflects the defaults. A file that parses but fails validation stops the scan with exit 3. [Check a config](#check) shows how to catch both before a scan.

## Share settings with `extends` {#extends}

A config file can build on other files. `extends` names one base file or a list of them, relative to the file that names it:

```yaml
extends: ../config/ash-base.yaml
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

ASH merges the bases in order and then the file itself. Mappings merge key by key; a list or a single value from the later file replaces the base's. To add to a base's list instead of replacing it, use `patch`, a list of JSON Patch operations (`add`, `remove`, `replace` and `test`) applied after the merge. `replace` fails on a key that no file set; use `add` for those.

A base must be inside the scanned directory. For a config file outside the scanned directory, its bases must be in that file's own directory or below it (for a file in `.ash/`, the directory that holds `.ash/`). URLs are refused, and so are cycles, chains more than 10 levels deep and chains of more than 50 files.

## Override settings for one run {#overrides}

`--config-overrides` sets one key for one run, on top of the config file. Repeat it to set several; when two set the same key, the later one wins.

```bash
ash --source-dir . --scanners detect-secrets --offline --no-progress \
  --config-overrides fail_on_findings=false \
  --config-overrides global_settings.severity_threshold=HIGH
```

The form is `key.path=value`:

- The key is a dotted path into the config, such as `scanners.bandit.options.confidence_level`. Plugin names use their hyphenated config names (`detect-secrets`, `cdk-nag`). There is no list indexing.
- The value is split from the key at the first `=`. `true`, `false` and `null` become booleans and null, numbers become numbers, and a value that starts with `[` or `{` is read as JSON. Anything else is a string. Values are case-sensitive, so `HIGH` is a threshold and `high` is an error.
- `key.path+=value` appends to an existing list instead of replacing it: `--config-overrides 'global_settings.ignore_paths+=[{"path": "vendor/**", "reason": "Third-party code"}]'`. On a key that is not a list yet, it sets the value.

ASH applies the overrides after loading the config file and validates the result again. An override that does not validate stops the scan with exit 3. An override of a key the model ignores, such as an unknown top-level key or anything unknown under `scanners`, `reporters` or `converters`, is accepted and has no effect. Overrides count as operator configuration, so they can set the settings a repository's config cannot.

## Read values from the environment {#environment}

A config value written as `${NAME:default}` is replaced by the environment variable `NAME`, or by `default` when the variable is not set:

```yaml
project_name: ${ASH_SERVICE_NAME:payments-api}
global_settings:
  severity_threshold: ${ASH_GATE_THRESHOLD:HIGH}
```

- Write the reference as the whole value. It works in YAML and TOML files, not in JSON.
- Only names that start with `ASH_`, and `AWS_REGION`, `AWS_DEFAULT_REGION` and `AWS_PROFILE`, are read. Any other name is left in the value as written, with a warning.
- Always write the colon. `${NAME}` without one is never replaced, even when the variable is set; write `${NAME:}` for an empty default.
- The result is a string. That works for string and threshold values, but a boolean or number key such as `fail_on_findings` fails validation (exit 3).
- The resolved config is written into the scan's results (`ash_aggregated_results.json`), so do not read secrets into it.
- An editor that checks the file against ASH's schema marks a reference in a field with fixed values, such as `severity_threshold`, as an error. ASH accepts it.

## Get completion in your editor {#schema}

The first line `ash config init` writes points editors that use the YAML language server (VS Code with the Red Hat YAML extension, for example) at ASH's JSON schema:

```text
# yaml-language-server: $schema=https://raw.githubusercontent.com/awslabs/automated-security-helper/refs/heads/main/automated_security_helper/schemas/AshConfig.json
```

The editor then completes keys and checks values as you type. ASH itself treats the line as a comment. The URL follows the `main` branch, not the ASH version you have installed, so the schema can list keys your version does not have. The schema flags an unknown key only in the sections where ASH itself refuses one (the second row of the table in [Which mistakes ASH catches](#typos)), and it does not include the community plugins' sections.

## Check a config {#check}

Three commands check a config file, and they check different things:

| Command | What it checks | What it misses |
|---|---|---|
| `ash config validate` | The file parses; its `extends` chain resolves; `project_name` is set; top-level keys are known and not repeated; no plugin section sets an internal field (`name`, `extension`, `tool_version`, `install_timeout`); no ignore or suppression path names an existing directory without `**` | Values: it never loads the file into ASH's config model, so a wrong value or a misspelled key inside a section passes |
| `ash config lint` | Everything `validate` checks, plus suppressions (`line_start` without `line_end`, expired entries, multi-line reasons, `symbol` values) and snake_case plugin names. `--fix` repairs what it can; `--fix-unused` comments out suppressions the last scan's [unused-suppressions report](suppress-findings.md#unused) lists | The same values `validate` misses |
| `ash config get <file>` | Loads the file through the same model `ash scan` uses and prints the resolved config. Exits 3 on any value or key the model refuses | Keys the model accepts and never reads (see below) |

Run all three from the repository root before you commit a change:

```bash
ash config validate
ash config lint
ash config get .ash/.ash.yaml
```

`validate` and `lint` exit 1 when `project_name` is missing, although a scan works without it and uses `ash-scan`. An unknown top-level key is an error for `validate` (exit 1) and a warning for `lint` (exit 0).

### Which mistakes ASH catches {#typos}

Most of the config model accepts keys it does not know and drops or ignores them, so a misspelled key often does nothing at all, with no error:

| Mistake | Example | What a scan does |
|---|---|---|
| Unknown top-level key | `fail_on_finding: false` | Ignores it. `validate` reports it. |
| Unknown key in `global_settings`, `sandbox`, `workspace` or a `content_db_staleness_overrides` entry | `severity_treshold: HIGH` | Refuses the config, exit 3 |
| Wrong value | `severity_threshold: high`, or an unquoted `expiration: 2027-01-31` | Refuses the config, exit 3 |
| Misspelled scanner, reporter or converter name | `detect_secret:` | Ignores the section |
| Unknown key in a plugin section or its options | `enabeld: false`, `confidance_level: high` | Ignores the key |
| Unknown key in a suppression or ignore path | `ruleId: B602` | Drops the key. A suppression whose `rule_id` is misspelled has no rule ID, so it matches every rule in its path. |

`ash config get` catches the two mistakes that end in exit 3, and `validate` and `lint` catch the unknown top-level key. No command catches the last three. For those, compare your keys with the [configuration reference](../reference/configuration.md) and the [scanner reference](../reference/scanners.md), and look for the value you meant to set in the output of `ash config get`.
